import os
import uuid
import json
import io
import tarfile
from datetime import datetime

import docker
import requests
import vana

from refiner.errors.exceptions import ContainerTimeoutError, ContainerExecutionError
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import DockerRun, Output
from refiner.utils.docker_cache import DockerImageCache

# Initialize the image cache as a module-level singleton (thread-safe)
import threading
_image_cache = None
_cache_lock = threading.Lock()


def get_image_cache() -> DockerImageCache:
    """Get or create the Docker image cache singleton (thread-safe)."""
    global _image_cache
    if _image_cache is None:
        with _cache_lock:
            # Double-check pattern to avoid race conditions
            if _image_cache is None:
                cache_dir = os.getenv('DOCKER_IMAGE_CACHE_DIR', '/var/cache/vana/docker-images')
                max_cache_size_gb = float(os.getenv('DOCKER_IMAGE_CACHE_SIZE_GB', '20.0'))
                ttl_days = int(os.getenv('DOCKER_IMAGE_CACHE_TTL_DAYS', '7'))
                _image_cache = DockerImageCache(
                    cache_dir=cache_dir,
                    max_cache_size_gb=max_cache_size_gb,
                    ttl_days=ttl_days
                )
    return _image_cache


def get_docker_client():
    client = None
    try:
        client = docker.from_env()
        vana.logging.debug(f"Docker client initialized successfully. {client.version()}")
    except docker.errors.DockerException as e:
        vana.logging.error(f"Error initializing Docker client: {e}")
        raise Exception("Docker client is not initialized")

    if client is None:
        raise Exception("Docker client is not initialized")
    return client


def cleanup_orphaned_volumes(max_age_minutes=60, max_volumes_per_run=50, timeout_seconds=30):
    """
    Clean up orphaned Docker volumes that match the refinement volume naming pattern.
    This is called periodically to prevent disk space leaks from crashed processes.
    
    IMPORTANT: This function is designed to be non-blocking by limiting the number
    of volumes processed per run and using timeouts to prevent blocking the worker loop.

    Args:
        max_age_minutes: Only remove volumes older than this many minutes (default: 60)
        max_volumes_per_run: Maximum number of volumes to process per invocation (default: 50)
        timeout_seconds: Maximum time to spend on cleanup per run (default: 30)

    Returns:
        int: Number of volumes removed
    """
    import time
    start_time = time.time()
    
    try:
        client = get_docker_client()
        removed_count = 0
        processed_count = 0

        # Get all volumes - this should be fast even with many volumes
        try:
            all_volumes = client.volumes.list()
        except Exception as list_error:
            vana.logging.warning(f"Failed to list Docker volumes: {list_error}")
            return 0

        # Current time for age calculation
        current_time = time.time()
        cutoff_time = current_time - (max_age_minutes * 60)

        # Filter to only refinement volumes first (fast, no API calls)
        refinement_volumes = [
            v for v in all_volumes 
            if v.name.startswith('input-') or v.name.startswith('output-')
        ]
        
        if refinement_volumes:
            vana.logging.debug(f"Found {len(refinement_volumes)} refinement volumes to check")

        for volume in refinement_volumes:
            # Check timeout - don't block the worker loop for too long
            if time.time() - start_time > timeout_seconds:
                vana.logging.info(f"Volume cleanup timeout reached after {timeout_seconds}s, processed {processed_count} volumes, removed {removed_count}")
                break
                
            # Check batch limit - process incrementally across multiple runs
            if processed_count >= max_volumes_per_run:
                vana.logging.debug(f"Volume cleanup batch limit reached ({max_volumes_per_run}), removed {removed_count}")
                break

            volume_name = volume.name
            processed_count += 1

            try:
                # Get volume details to check creation time
                volume.reload()
                volume_attrs = volume.attrs

                # Parse creation time
                created_at_str = volume_attrs.get('CreatedAt', '')
                if created_at_str:
                    # Parse ISO format timestamp
                    from dateutil import parser
                    try:
                        created_at = parser.parse(created_at_str).timestamp()
                    except:
                        # If parsing fails, try alternate method
                        created_at = volume_attrs.get('CreatedAt', 0)
                        if isinstance(created_at, str):
                            # Fallback: assume it's old if we can't parse
                            created_at = 0
                else:
                    # If no creation time, assume it's old
                    created_at = 0

                # Only remove if older than cutoff
                if created_at < cutoff_time:
                    vana.logging.info(f"Removing orphaned volume: {volume_name} (age: {(current_time - created_at) / 60:.1f} minutes)")

                    # Try to remove the volume
                    try:
                        volume.remove(force=True)
                        removed_count += 1
                        vana.logging.info(f"Successfully removed orphaned volume: {volume_name}")
                    except docker.errors.APIError as remove_error:
                        # Volume might be in use, skip it
                        vana.logging.debug(f"Could not remove volume {volume_name}: {remove_error}")
                        continue

            except Exception as volume_error:
                vana.logging.debug(f"Error processing volume {volume_name}: {volume_error}")
                continue

        elapsed = time.time() - start_time
        if removed_count > 0:
            vana.logging.info(f"Orphaned volume cleanup: removed {removed_count}/{processed_count} volumes in {elapsed:.1f}s")
        else:
            vana.logging.debug(f"Orphaned volume cleanup: no volumes to remove (checked {processed_count} in {elapsed:.1f}s)")

        return removed_count

    except Exception as e:
        vana.logging.error(f"Error during orphaned volume cleanup: {e}")
        return 0


def run_signed_container(
    image_url: str,
    environment: dict,
    input_file_path: str,
    request_id: str
) -> DockerRun:
    """
    Runs a container with the given image and copies the input file directly into it.
    
    Args:
        image_url: URL of the container image.
        environment: Environment variables to pass to the container.
        input_file_path: Path to the file to copy into the container's /input directory.
        request_id: Request ID for logging context.

    Returns:
        DockerRun: Result of running the container including logs, exit code, and parsed output data.
    """
    if request_id:
        request_id_context.set(request_id)

    client = get_docker_client()
    cache = get_image_cache()

    # Get container timeout from environment variable (default 60 seconds)
    container_timeout = int(os.getenv('CONTAINER_TIMEOUT_SECONDS', '60'))
    vana.logging.debug(f"Container timeout set to {container_timeout} seconds")

    vana.logging.debug(f"Getting image from cache or downloading: {image_url}")
    image_tag = cache.get_image(image_url)

    if not image_tag:
        raise ValueError(f"Failed to get Docker image from {image_url}")

    # Generate a unique container name
    container_name = f"refinement-{request_id}-{image_tag.split('/')[-1].split(':')[0]}-{uuid.uuid4().hex[:8]}"
    docker_run = DockerRun(
        container_name=container_name,
        exit_code=None,
        logs="",
        started_at=datetime.now(),
        terminated_at=None,
        output_data=None
    )

    input_volume_name = f"input-{uuid.uuid4().hex}"
    output_volume_name = f"output-{uuid.uuid4().hex}"
    input_volume = client.volumes.create(input_volume_name)
    output_volume = client.volumes.create(output_volume_name)
    container = None

    try:
        volumes = {
            input_volume_name: {'bind': '/input', 'mode': 'rw'},
            output_volume_name: {'bind': '/output', 'mode': 'rw'},
        }
        vana.logging.info(f"Using volumes: {volumes}")

        container = client.containers.create(
            image=image_tag,
            name=container_name,
            environment=environment,
            volumes=volumes,
            detach=True,
        )

        container.start()
        vana.logging.info(f"Started container {container_name} from image {image_tag}")
        
        # Copy the input file to the container
        with open(input_file_path, 'rb') as file_data:
            file_size = os.path.getsize(input_file_path)
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                file_info = tarfile.TarInfo(name=os.path.basename(input_file_path))
                file_info.size = file_size
                tar.addfile(file_info, file_data)
            tar_buffer.seek(0)
            archive_size = len(tar_buffer.getvalue())
            client.api.put_archive(container.id, '/input', tar_buffer.getvalue())
        vana.logging.info(f"Successfully copied file to container's /input directory ({file_size} bytes, archive size: {archive_size} bytes)")

        try:
            result = container.wait(timeout=container_timeout)
            docker_run.exit_code = result.get('StatusCode', -1)
            vana.logging.info(f"Container {container_name} finished with exit code {docker_run.exit_code}")
        # Catch the broader ConnectionError which wraps ReadTimeout in this context,
        # or the more specific ReadTimeout from requests.
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
            if "Read timed out" in str(e):
                vana.logging.error(f"Container {container_name} timed out after {container_timeout} seconds. Killing container.")
                try:
                    container.kill()
                except docker.errors.APIError as kill_e:
                    vana.logging.error(f"Error killing timed-out container {container_name}: {kill_e}")
                docker_run.exit_code = 137 # Standard exit code for SIGKILL
                raise ContainerTimeoutError(container_name=container_name, timeout=container_timeout)
            else:
                # If it's another type of ConnectionError, re-raise it
                vana.logging.error(f"A connection error occurred while waiting for container {container_name}: {str(e)}")
                raise
        except Exception as e:
            vana.logging.error(f"Unexpected error waiting for container {container_name}: {str(e)}")
            docker_run.exit_code = -1
            raise
        finally:
             docker_run.terminated_at = datetime.now()

        # Retrieve logs after waiting/timeout
        try:
            docker_run.logs = container.logs().decode('utf-8', errors='replace')
            vana.logging.debug(f"Container {container_name} logs retrieved.")
        except docker.errors.APIError as log_e:
            vana.logging.error(f"Failed to retrieve logs for container {container_name}: {log_e}")
            docker_run.logs = "<Failed to retrieve logs>"

        # Retrieve output.json from the output volume
        if docker_run.exit_code == 0:
            vana.logging.info(f"Attempting to retrieve output.json from volume {output_volume_name}")
            output_content = None
            try:
                # Run a temporary alpine container to cat the file from the volume
                output_content_bytes = client.containers.run(
                    image='alpine:latest',
                    command=f'cat /volume_data/output.json',
                    volumes={output_volume_name: {'bind': '/volume_data', 'mode': 'ro'}}, # Mount read-only
                    remove=True, # Automatically remove the container when done
                    stdout=True,
                    stderr=True
                )
                output_content = output_content_bytes.decode('utf-8').strip()
                vana.logging.info(f"Successfully retrieved content from output.json")
                vana.logging.debug(f"output.json content: \n{output_content}")
            except docker.errors.ContainerError as cat_err:
                # This happens if the command fails (e.g., file not found)
                vana.logging.warning(f"Could not retrieve output.json: Command failed in helper container. Stderr: {cat_err.stderr.decode('utf-8', errors='replace')}")
            except Exception as read_err:
                vana.logging.error(f"Unexpected error retrieving output.json: {read_err}")

            # Parse the content if retrieved
            if output_content:
                try:
                    parsed_data = json.loads(output_content)
                    # Validate and store using the Pydantic model
                    docker_run.output_data = Output(**parsed_data)
                    vana.logging.info(f"Successfully parsed output.json into Output model.")
                except json.JSONDecodeError as json_err:
                    vana.logging.error(f"Failed to parse JSON from output.json: {json_err}")
                    docker_run.logs += "\n[REFINER_ERROR] Failed to parse output.json content."
                    # Raise ContainerExecutionError for JSON parsing failures
                    raise ContainerExecutionError(
                        container_name=container_name,
                        exit_code=docker_run.exit_code,
                        logs=docker_run.logs
                    )
                except Exception as pydantic_err: # Catch potential Pydantic validation errors
                     vana.logging.error(f"Failed to validate output.json against Output model: {pydantic_err}")
                     docker_run.logs += f"\n[REFINER_ERROR] Failed to validate output.json content: {pydantic_err}"
                     # Raise ContainerExecutionError for validation failures
                     raise ContainerExecutionError(
                         container_name=container_name,
                         exit_code=docker_run.exit_code,
                         logs=docker_run.logs
                     )
            else:
                # Container succeeded but produced no output - this is an execution error
                vana.logging.error(f"Container {container_name} executed successfully but produced no output.json")
                docker_run.logs += "\n[REFINER_ERROR] Container executed successfully but produced no output.json"
                raise ContainerExecutionError(
                    container_name=container_name,
                    exit_code=docker_run.exit_code,
                    logs=docker_run.logs
                )
        else:
             vana.logging.warning(f"Skipping output.json retrieval as container exit code was {docker_run.exit_code}")

        return docker_run

    except Exception as e:
        vana.logging.error(f"Error in run_signed_container setup/execution for {container_name}: {str(e)}")
        if docker_run.exit_code is None: docker_run.exit_code = -1
        raise

    finally:
        # Clean up main container and volumes
        cleanup_errors = []
        
        # Clean up container
        if container:
            try:
                vana.logging.info(f"Removing container: {container_name}")
                container.remove(force=True)
            except docker.errors.NotFound:
                vana.logging.info(f"Container {container_name} already removed during cleanup.")
            except Exception as e:
                error_msg = f"Error removing container {container_name}: {str(e)}"
                vana.logging.error(error_msg)
                cleanup_errors.append(error_msg)

        # Clean up volumes with retry logic and more aggressive removal
        def cleanup_volume_with_retry(volume_obj, volume_name, max_retries=5):
            """Helper function to cleanup volume with retry logic"""
            if not volume_obj:
                return
                
            for attempt in range(max_retries):
                try:
                    vana.logging.info(f"Removing volume: {volume_name} (attempt {attempt + 1}/{max_retries})")
                    volume_obj.remove(force=True)
                    vana.logging.info(f"Successfully removed volume: {volume_name}")
                    return
                except docker.errors.NotFound:
                    vana.logging.info(f"Volume {volume_name} already removed during cleanup.")
                    return
                except Exception as e:
                    error_msg = f"Error removing volume {volume_name} (attempt {attempt + 1}): {str(e)}"
                    vana.logging.warning(error_msg)
                    if attempt == max_retries - 1:  # Last attempt
                        cleanup_errors.append(error_msg)
                        # Try alternative cleanup methods as last resort
                        try:
                            vana.logging.info(f"Attempting alternative cleanup for volume: {volume_name}")
                            # Method 1: Direct API call with force
                            client.api.remove_volume(volume_name, force=True)
                            vana.logging.info(f"Alternative cleanup (API) successful for volume: {volume_name}")
                            return
                        except Exception as alt_e1:
                            try:
                                # Method 2: Prune volumes (will remove if truly orphaned)
                                vana.logging.info(f"Attempting prune for volume: {volume_name}")
                                client.volumes.prune(filters={'label': f'name={volume_name}'})
                                vana.logging.info(f"Alternative cleanup (prune) attempted for volume: {volume_name}")
                            except Exception as alt_e2:
                                alt_error_msg = f"All cleanup methods failed for volume {volume_name}: API={alt_e1}, Prune={alt_e2}"
                            vana.logging.error(alt_error_msg)
                            cleanup_errors.append(alt_error_msg)
                    else:
                        # Wait progressively longer before retry
                        import time
                        # Exponential backoff: 1s, 2s, 4s, 8s
                        time.sleep(2 ** attempt)

        # Clean up input volume
        cleanup_volume_with_retry(input_volume, input_volume_name)
        
        # Clean up output volume  
        cleanup_volume_with_retry(output_volume, output_volume_name)

        # Log summary of cleanup errors if any
        if cleanup_errors:
            vana.logging.error(f"Cleanup completed with {len(cleanup_errors)} errors:")
            for error in cleanup_errors:
                vana.logging.error(f"  - {error}")
        else:
            vana.logging.info("Container and volume cleanup completed successfully")
