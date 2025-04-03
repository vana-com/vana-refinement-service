import os
import shutil
import vana

from refiner.errors.exceptions import FileDecryptionError, FileDownloadError, RefinementBaseException
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse
from refiner.utils.docker import run_signed_container
from refiner.utils.files import download_file
from refiner.utils.cryptography import decrypt_file, ecies_encrypt

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

def refine(
        client: vana.Client,
        request: RefinementRequest,
        request_id: str = None
) -> RefinementResponse:
    # Set request ID in context if provided
    if request_id:
        request_id_context.set(request_id)

    # Get file info from chain
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
    temp_dir = None

    try:
        # 1. Download the encrypted file
        vana.logging.info("Starting file download...")
        encrypted_file_path = download_file(url)
        temp_dir = os.path.dirname(encrypted_file_path)
        vana.logging.info(f"Successfully downloaded encrypted file to: {encrypted_file_path}")

        # 2. Decrypt the file
        vana.logging.info("Starting file decryption...")
        decrypted_file_path = decrypt_file(encrypted_file_path, request.encryption_key)
        vana.logging.info(f"Successfully decrypted file to: {decrypted_file_path}")

        # 3. Look up the refiner instructions
        refiner = client.get_refiner(request.refiner_id)
        if refiner.get('dlp_id', 0) == 0:
            raise RefinementBaseException(
                status_code=404,
                message=f"Refiner with ID {request.refiner_id} not found",
                error_code="REFINER_NOT_FOUND"
            )
        vana.logging.info(f"Refiner for refiner ID {request.refiner_id}: {refiner}")
        # {'dlp_id': 41, 'owner': '0x2AC93684679a5bdA03C6160def908CdB8D46792f', 'name': 'DLP Example', 'schema_definition_url': 'Qma3dWDFZCQnWFTv1owAXyJjtpxjENGvKizPhFT4fsX8do', 'refinement_instruction_url': 'https://github.com/vana-com/vana-data-refinement-template/releases/download/v1/refiner-1.tar.gz', 'public_key': '0x071a73c96fe828b7c2f342b01a782e83564a8e6c5f40b59a11e0bfb99a2b641a1f77fe46ebf1ec880e8b753561d7c5f6e983973fa50f3d97b5e927c718b302f8'}

        # 4. Generate Refinement Encryption Key (REK) from the user's original encryption key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'query-engine',
            backend=default_backend() # Specify the backend
        )
        master_key_bytes = bytes.fromhex(request.encryption_key.removeprefix('0x'))
        refinement_encryption_key = '0x' + hkdf.derive(master_key_bytes).hex()
        vana.logging.info(f"Original encryption key: {request.encryption_key}")
        vana.logging.info(f"Refined encryption key: {refinement_encryption_key}")
        
        encrypted_message, ephemeral_sk, nonce = ecies_encrypt(refiner.get('public_key'), refinement_encryption_key.encode())
        vana.logging.info(f"Encrypted encryption key: {encrypted_message.hex()}")

        # 5. Run the refiner Docker container, passing decrypted_file_path and REK
        environment = {
            **request.env_vars,
            "FILE_ID": request.file_id,
            "FILE_URL": url,
            "FILE_OWNER_ADDRESS": ownerAddress,
            "REFINEMENT_ENCRYPTION_KEY": refinement_encryption_key
        }
        docker_run_result = run_signed_container(
            refiner.get('refinement_instruction_url'),
            environment,
            request_id=request_id
            #decrypted_file_path,
        )
        vana.logging.info(f"Refiner Docker run result: {docker_run_result}")
                
        # 6. Get IPFS CID from container output

        # 7. Call client.add_refinement_with_permission(...)

        # Placeholder response for now
        add_refinement_tx_hash = "0x1234567890abcdef_placeholder" # Replace with actual hash

        return RefinementResponse(
            add_refinement_tx_hash=add_refinement_tx_hash
        )

    except FileDownloadError as e:
        vana.logging.error(f"File download failed for file ID {request.file_id}, URL {url}: {e.error}")
        # Re-raise the specific error or wrap it if needed
        raise RefinementBaseException(
             status_code=500, # Or appropriate status
             message=f"Failed to download file: {e.error}",
             error_code="FILE_DOWNLOAD_FAILED",
             details={"file_id": request.file_id, "url": url}
        )
    except FileDecryptionError as e:
        vana.logging.error(f"File decryption failed for file ID {request.file_id}: {e.error}")
         # Re-raise the specific error or wrap it
        raise RefinementBaseException(
             status_code=500,
             message=f"Failed to decrypt file: {e.error}",
             error_code="FILE_DECRYPTION_FAILED",
             details={"file_id": request.file_id}
        )
    except Exception as e:
        # Catch any other unexpected errors during the process
        vana.logging.exception(f"An unexpected error occurred during refinement for file ID {request.file_id}: {e}")
        raise RefinementBaseException(
            status_code=500,
            message=f"An internal error occurred during refinement: {str(e)}",
            error_code="REFINEMENT_PROCESSING_ERROR",
            details={"file_id": request.file_id}
        )
    finally:
        # Ensure cleanup happens regardless of success or failure
        if temp_dir and os.path.isdir(temp_dir):
            vana.logging.info(f"Cleaning up temporary directory: {temp_dir}")
            try:
                shutil.rmtree(temp_dir)
                vana.logging.info(f"Successfully removed temporary directory: {temp_dir}")
            except Exception as e:
                # Log error during cleanup but don't prevent function exit
                vana.logging.error(f"Failed to clean up temporary directory {temp_dir}: {e}")
