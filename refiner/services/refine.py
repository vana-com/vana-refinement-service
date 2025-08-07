import os
import shutil
import uuid
import tempfile

import vana

from refiner.errors.exceptions import FileDecryptionError, FileDownloadError, RefinementBaseException
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse
from refiner.utils.cryptography import decrypt_file, ecies_encrypt
from refiner.utils.docker import run_signed_container
from refiner.utils.files import download_file, detect_file_type, should_apply_file_type_detection
from refiner.services.health import get_health_service
from refiner.services.refiner_logging import get_refiner_logging_service


def truncate_docker_logs(logs: str, head_lines: int = 30, tail_lines: int = 20, max_chars: int = 1600) -> str:
    """
    Truncate docker logs to a maximum number of lines and characters for database storage.
    Keeps the first and last portions of the logs for debugging.
    
    Args:
        logs: The complete docker logs
        head_lines: Number of lines to keep from the beginning
        tail_lines: Number of lines to keep from the end
        max_chars: Maximum number of characters to keep in total
        
    Returns:
        str: Truncated logs with summary of removed content
    """
    if not logs:
        return logs
    
    # First check character count - if too long, truncate by characters first
    if len(logs) > max_chars:
        # Keep first half and last half of character limit
        head_chars = max_chars // 2
        tail_chars = max_chars // 2
        
        truncated_logs = (
            logs[:head_chars] + 
            f"\n\n... ({len(logs) - max_chars} characters truncated for database storage) ...\n\n" +
            logs[-tail_chars:]
        )
        
        # Now check line count on the character-truncated logs
        logs = truncated_logs
        
    lines = logs.split('\n')
    total_lines = len(lines)
    
    if total_lines <= head_lines + tail_lines:
        return logs
    
    # Keep first and last portions for context
    truncated_lines = (
        lines[:head_lines] +
        [f"... ({total_lines - head_lines - tail_lines} lines truncated for database storage) ..."] +
        lines[-tail_lines:]
    )
    
    return '\n'.join(truncated_lines)

def refine(
        client: vana.Client,
        request: RefinementRequest,
        request_id: str = None
) -> RefinementResponse:
    # Set request ID in context if provided
    if request_id:
        request_id_context.set(request_id)

    # Get health service for tracking metrics
    health_service = get_health_service()
    start_time = health_service.record_refinement_start()
    
    # Log job start to refiner-specific logging
    refiner_logging = get_refiner_logging_service()
    refiner_logging.log_refinement_job(
        refiner_id=request.refiner_id,
        job_id=request_id or "sync",
        level="info",
        message=f"Starting refinement job for file {request.file_id}"
    )

    vana.logging.info(
        f"Starting refinement for file_id={request.file_id}, refiner_id={request.refiner_id}")

    # EARLY VALIDATION: Validate encryption key before expensive processing
    # Can be disabled with SKIP_ENCRYPTION_KEY_VALIDATION=true for debugging
    if not os.getenv('SKIP_ENCRYPTION_KEY_VALIDATION', 'false').lower() == 'true':
        try:
            from refiner.services.validation import validate_encryption_key_comprehensive
            derived_refinement_key = validate_encryption_key_comprehensive(request.encryption_key)
            vana.logging.info(f"Encryption key validation passed for file {request.file_id}")
        except Exception as e:
            # All validation exceptions should be properly typed, but catch any unexpected ones
            if hasattr(e, 'error_code'):
                raise  # Re-raise structured validation exceptions as-is
            else:
                raise RefinementBaseException(
                    status_code=500,
                    message=f"Encryption key validation failed unexpectedly: {str(e)}",
                    error_code="ENCRYPTION_KEY_VALIDATION_ERROR"
                )
    else:
        vana.logging.warning("Encryption key validation SKIPPED due to SKIP_ENCRYPTION_KEY_VALIDATION=true")
        # Still need to derive the key for later use
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'query-engine',
            backend=default_backend()
        )
        master_key_bytes = bytes.fromhex(request.encryption_key.removeprefix('0x'))
        derived_refinement_key = '0x' + hkdf.derive(master_key_bytes).hex()

    # Continue with existing refinement logic...
    # Get file info from client (validation already confirmed it exists)
    file_info = client.get_file(request.file_id)
    if not file_info:
        raise RefinementBaseException(
            status_code=404,
            message=f"File {request.file_id} not found",
            error_code="FILE_NOT_FOUND"
        )

    (id, ownerAddress, url, addedAtBlock) = file_info
    vana.logging.info(f"Processing file ID: {id}, url: {url}, ownerAddress: {ownerAddress}")

    encrypted_file_path = None
    decrypted_file_path = None
    temp_dir = None  # This will store the base temp dir (parent of 'input')

    try:
        # 1. Download the encrypted file
        vana.logging.info("Starting file download...")
        encrypted_file_path = download_file(url)
        temp_dir = os.path.dirname(encrypted_file_path)  # Get the base temporary directory
        encrypted_file_size = os.path.getsize(encrypted_file_path) if os.path.exists(encrypted_file_path) else 0
        vana.logging.info(f"Successfully downloaded encrypted file to: {encrypted_file_path} ({encrypted_file_size} bytes)")
        
        # Check if the downloaded file exists and has content
        if not os.path.exists(encrypted_file_path) or encrypted_file_size == 0:
            raise FileDownloadError(f"Downloaded file is empty or does not exist: {encrypted_file_path}")

        # 2. Decrypt the file (will be placed in temp_dir/input/decrypted_file...)
        vana.logging.info("Starting file decryption...")
        decrypted_file_path = decrypt_file(encrypted_file_path, request.encryption_key)
        decrypted_file_size = os.path.getsize(decrypted_file_path) if os.path.exists(decrypted_file_path) else 0
        # The path to the directory containing the decrypted file is needed for mounting
        input_dir_host_path = os.path.dirname(decrypted_file_path)
        vana.logging.info(f"Host path for input mount: {input_dir_host_path} (decrypted file: {decrypted_file_size} bytes)")
        
        # Check if the decrypted file exists and has content
        if not os.path.exists(decrypted_file_path) or decrypted_file_size == 0:
            raise FileDecryptionError(f"Decrypted file is empty or does not exist: {decrypted_file_path}")
        
        # Only apply file type detection when the current extension is obviously wrong or missing
        # This prevents breaking refiners that expect specific file extensions (e.g., CSV)
        current_extension = os.path.splitext(decrypted_file_path)[1]
        
        if should_apply_file_type_detection(current_extension):
            detected_extension = detect_file_type(decrypted_file_path)
            
            if detected_extension != current_extension:
                new_path = os.path.splitext(decrypted_file_path)[0] + detected_extension
                os.rename(decrypted_file_path, new_path)
                decrypted_file_path = new_path
                vana.logging.info(f"Decrypted file type detected as {detected_extension} based on content (was {current_extension or 'no extension'})")
        else:
            vana.logging.debug(f"Skipping file type detection for {current_extension} extension - trusting original extension")

        if os.getenv('CHAIN_NETWORK') == 'moksha' and os.getenv('DEBUG_FILES_DIR'):
            debug_dir = os.getenv('DEBUG_FILES_DIR')
            os.makedirs(debug_dir, exist_ok=True)
            debug_file_path = os.path.join(debug_dir, os.path.basename(decrypted_file_path)) + uuid.uuid4().hex[:8]
            shutil.copy2(decrypted_file_path, debug_file_path)
            vana.logging.info(f"Copied decrypted file to debug directory: {debug_file_path}")

        # 3. Look up the refiner instructions
        refiner = client.get_refiner(request.refiner_id)
        dlp_id = refiner.get('dlp_id', 0)
        if dlp_id == 0:
            raise RefinementBaseException(
                status_code=404,
                message=f"Refiner with ID {request.refiner_id} not found",
                error_code="REFINER_NOT_FOUND"
            )
        vana.logging.info(f"Refiner for refiner ID {request.refiner_id}: {refiner}")

        dlp_pub_key = client.get_dlp_pub_key(dlp_id)
        if not dlp_pub_key:
            raise RefinementBaseException(
                status_code=404,
                message=f"DLP public key for refiner {request.refiner_id} and DLP ID {dlp_id} not found",
                error_code="REFINER_DLP_PUBLIC_KEY_NOT_FOUND"
            )
        vana.logging.info(f"DLP public key for DLP ID {dlp_id}: {dlp_pub_key}")

        # 4. Use the already-derived Refinement Encryption Key (REK)
        # (Key was already derived and validated during early validation)
        refinement_encryption_key = derived_refinement_key
        encrypted_refinement_encryption_key, ephemeral_sk, nonce = ecies_encrypt(dlp_pub_key,
                                                                                 refinement_encryption_key.encode())
        vana.logging.info(f"Encrypted encryption key: {encrypted_refinement_encryption_key.hex()}")

        # 5. Run the refiner Docker container
        # Ensure environment variables are strings
        environment = {
            **request.env_vars,
            "FILE_ID": request.file_id,
            "FILE_URL": url,
            "FILE_OWNER_ADDRESS": ownerAddress,
            "REFINEMENT_ENCRYPTION_KEY": refinement_encryption_key,
            "INPUT_DIR": "/input",
            "OUTPUT_DIR": "/output"
        }

        docker_run_result = run_signed_container(
            image_url=refiner.get('refinement_instruction_url'),
            environment=environment,
            input_file_path=decrypted_file_path,
            request_id=request_id
        )
        # Truncate logs to first 10 lines for logging
        log_lines = docker_run_result.logs.split('\n', 11)
        truncated_logs = '\n'.join(log_lines[:10])
        if len(log_lines) > 10:
            truncated_logs += f'\n... ({len(log_lines) - 10} more lines truncated)'
        
        vana.logging.info(
            f"Refiner Docker run result (Exit Code: {docker_run_result.exit_code}):\n{truncated_logs}")
        
        # Log to refiner-specific logging system
        refiner_logging = get_refiner_logging_service()
        level = "error" if docker_run_result.exit_code != 0 else "info"
        message = f"Docker container execution completed with exit code {docker_run_result.exit_code}"
        
        refiner_logging.log_refinement_job(
            refiner_id=request.refiner_id,
            job_id=request_id or "sync",
            level=level,
            message=message,
            docker_container=docker_run_result.container_name,
            exit_code=docker_run_result.exit_code,
            full_logs=docker_run_result.logs
        )
        
        # Store docker execution details in database if request_id is provided (background processing)
        if request_id:
            try:
                from refiner.stores import refinement_jobs_store
                # Store truncated docker logs for database storage
                truncated_docker_logs = truncate_docker_logs(docker_run_result.logs)
                
                refinement_jobs_store.update_job_docker_info(
                    job_id=request_id,
                    container_name=docker_run_result.container_name,
                    exit_code=docker_run_result.exit_code,
                    logs=truncated_docker_logs
                )
                vana.logging.debug(f"Stored docker execution info for job {request_id}")
            except Exception as docker_info_error:
                vana.logging.warning(f"Failed to store docker info for job {request_id}: {docker_info_error}")

        if docker_run_result.exit_code != 0:
            # Log the error to refiner-specific logs
            refiner_logging.log_refinement_job(
                refiner_id=request.refiner_id,
                job_id=request_id or "sync",
                level="error",
                message=f"Refiner container failed with exit code {docker_run_result.exit_code}",
                docker_container=docker_run_result.container_name,
                exit_code=docker_run_result.exit_code,
                full_logs=docker_run_result.logs
            )
            
            raise RefinementBaseException(
                status_code=500,
                message=f"Refiner container failed with exit code {docker_run_result.exit_code}",
                error_code="REFINER_CONTAINER_FAILED",
                details={"logs": docker_run_result.logs[-1000:]}  # Include last 1000 chars of logs
            )
        vana.logging.info(f"Refined file URL: {docker_run_result.output_data.refinement_url}")
        
        # Log successful completion
        refiner_logging.log_refinement_job(
            refiner_id=request.refiner_id,
            job_id=request_id or "sync",
            level="info",
            message=f"Refinement completed successfully. Output URL: {docker_run_result.output_data.refinement_url}"
        )

        # 6. Validate refinement output before adding to registry
        # Can be disabled with SKIP_REFINEMENT_OUTPUT_VALIDATION=true for debugging
        if not os.getenv('SKIP_REFINEMENT_OUTPUT_VALIDATION', 'false').lower() == 'true':
            try:
                from refiner.services.validation import validate_refinement_output
                validate_refinement_output(docker_run_result.output_data.refinement_url, refinement_encryption_key)
                vana.logging.info("Refinement output validation passed")
            except Exception as e:
                # All validation exceptions should be properly typed, but catch any unexpected ones
                if hasattr(e, 'error_code'):
                    raise  # Re-raise structured validation exceptions as-is
                else:
                    raise RefinementBaseException(
                        status_code=500,
                        message=f"Refinement output validation failed unexpectedly: {str(e)}",
                        error_code="REFINEMENT_OUTPUT_VALIDATION_ERROR",
                        details={"refinement_url": docker_run_result.output_data.refinement_url}
                    )
        else:
            vana.logging.warning("Refinement output validation SKIPPED due to SKIP_REFINEMENT_OUTPUT_VALIDATION=true")

        # 7. Add refinement to the data registry

        # Write the refinement to the data registry
        transaction_hash, transaction_receipt = client.add_refinement_with_permission(
            file_id=request.file_id,
            refiner_id=request.refiner_id,
            url=docker_run_result.output_data.refinement_url,
            account=os.getenv('QUERY_ENGINE_ACCOUNT'),
            key=encrypted_refinement_encryption_key.hex()
        )
        vana.logging.info(
            f"Refinement added to the data registry with transaction hash: {transaction_hash.hex()} and receipt: {transaction_receipt}")

        # Record successful refinement for health tracking
        health_service.record_refinement_success(start_time)

        return RefinementResponse(
            add_refinement_tx_hash=transaction_hash.hex()
        )

    except FileDownloadError as e:
        vana.logging.error(f"File download failed for file ID {request.file_id}, URL {url}: {e.details.get('error', str(e))}")
        health_service.record_refinement_failure(start_time, "FILE_DOWNLOAD_FAILED")
        raise RefinementBaseException(
            status_code=500,
            message=f"Failed to download file: {e.details.get('error', str(e))}",
            error_code="FILE_DOWNLOAD_FAILED",
            details={"file_id": request.file_id, "url": url}
        )
    except FileDecryptionError as e:
        error_msg = e.details.get('error', 'Invalid encryption key or corrupted file')
        vana.logging.error(f"File decryption failed for file ID {request.file_id}: {error_msg}")
        health_service.record_refinement_failure(start_time, "FILE_DECRYPTION_FAILED")
        raise RefinementBaseException(
            status_code=400,
            message=f"Failed to decrypt file: {error_msg}",
            error_code="FILE_DECRYPTION_FAILED",
            details={"file_id": request.file_id, "reason": "Invalid encryption key or corrupted file"}
        )
    except Exception as e:
        vana.logging.exception(f"An unexpected error occurred during refinement for file ID {request.file_id}: {e}")
        health_service.record_refinement_failure(start_time, "REFINEMENT_PROCESSING_ERROR")
        raise RefinementBaseException(
            status_code=500,
            message=f"An internal error occurred during refinement: {str(e)}",
            error_code="REFINEMENT_PROCESSING_ERROR",
            details={"file_id": request.file_id}
        )
    finally:
        if temp_dir and os.path.isdir(temp_dir):
            vana.logging.info(f"Cleaning up temporary directory: {temp_dir}")
            try:
                shutil.rmtree(temp_dir)
                vana.logging.info(f"Successfully removed temporary directory: {temp_dir}")
            except Exception as e:
                vana.logging.error(f"Failed to clean up temporary directory {temp_dir}: {e}")
