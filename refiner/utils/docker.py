import os
import time
import uuid
from datetime import datetime

import docker
import vana

from refiner.errors.exceptions import ContainerTimeoutError
from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import DockerRun
from refiner.utils.docker_cache import DockerImageCache

# Initialize the image cache as a module-level singleton
_image_cache = None


def get_image_cache() -> DockerImageCache:
    """Get or create the Docker image cache singleton."""
    global _image_cache
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


def run_signed_container(image_url: str, environment: dict, request_id: str = None) -> DockerRun:
    """
    Synchronous version of run_signed_container that runs the container and waits for completion.

    Args:
        job_run: Job run metadata with run uuid, input and output directories, ...
        image_url: URL of the container image
        environment: Environment variables to pass to the container
        request_id: Optional request ID for logging context

    Returns:
        DockerRun: Result of running the container including logs and exit code
    """
    # Set request ID in context if provided
    if request_id:
        request_id_context.set(request_id)

    client = get_docker_client()
    cache = get_image_cache()

    # Get container timeout from environment variable (default 10 seconds)
    container_timeout = int(os.getenv('CONTAINER_TIMEOUT_SECONDS', '10'))
    vana.logging.debug(f"Container timeout set to {container_timeout} seconds")

    # Get image from cache or download
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
    )

    # Generate unique names for input and output volumes
    input_volume_name = f"input-{uuid.uuid4().hex}"
    output_volume_name = f"output-{uuid.uuid4().hex}"
    input_volume = client.volumes.create(input_volume_name)
    output_volume = client.volumes.create(output_volume_name)

    try:
        volumes = {
            input_volume_name: {'bind': '/input', 'mode': 'rw'},
            output_volume_name: {'bind': '/output', 'mode': 'rw'},
        }

        # Create (but don't start) the container
        container = client.containers.create(
            image=image_tag,
            name=container_name,
            environment=environment,
            volumes=volumes,
            detach=True,
        )

        # Start the container
        container.start()
        start_time = time.time()

        # Wait for the container with timeout
        try:
            while True:
                # Check if container is still running
                container.reload()
                if container.status != 'running':
                    break

                # Check if timeout exceeded
                if time.time() - start_time > container_timeout:
                    vana.logging.error(f"Container {container_name} timed out after {container_timeout} seconds")
                    container.kill()
                    raise ContainerTimeoutError(container_name=container_name, timeout=container_timeout)

                time.sleep(1)  # Wait before next check

            result = container.wait()
            docker_run.exit_code = result['StatusCode']

        except ContainerTimeoutError:
            raise
        except Exception as e:
            vana.logging.error(f"Error waiting for container: {str(e)}")
            raise

        # Termination timestamp
        docker_run.terminated_at = datetime.now()

        # Get the logs
        docker_run.logs = container.logs().decode('utf-8')

        vana.logging.info(
            f"[Container {container_name}][Image {image_url}] Finished with exit code {docker_run.exit_code}")

        return docker_run

    except Exception as e:
        vana.logging.error(f"Error in run_signed_container: {str(e)}")
        raise

    finally:
        # Clean up
        try:
            # Remove container
            vana.logging.info(f"[Container {container_name}][Image {image_url}] Removing container and volumes")
            container.remove(force=True)
        except Exception as e:
            vana.logging.error(f"[Container {container_name}][Image {image_url}] Error removing container: {str(e)}")
