import hashlib
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict

import docker
import requests
import vana


class DockerImageCache:
    """
    Manages caching of Docker images with TTL and size limits.
    """

    def __init__(self,
                 cache_dir: str = "/var/cache/vana/docker-images",
                 max_cache_size_gb: float = 20.0,
                 ttl_days: int = 7):
        self.cache_dir = Path(cache_dir)
        self.max_cache_size_bytes = max_cache_size_gb * 1024 * 1024 * 1024  # Convert GB to bytes
        self.ttl = timedelta(days=ttl_days)
        self.metadata_file = self.cache_dir / "metadata.json"
        self.docker_client = docker.from_env()
        self.lock = threading.Lock()

        # Create cache directory if it doesn't exist
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Load or initialize metadata
        self.metadata = self._load_metadata()
        vana.logging.info(
            f"Initialized Docker image cache at {cache_dir} (max size: {max_cache_size_gb}GB, TTL: {ttl_days} days)")

    def _load_metadata(self) -> Dict:
        """Load metadata from file or create new if doesn't exist."""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
                vana.logging.info(f"Loaded cache metadata with {len(metadata['images'])} cached images")
                return metadata
            except json.JSONDecodeError:
                vana.logging.error("Failed to load cache metadata, creating new")
        return {'images': {}}

    def _save_metadata(self):
        """Save metadata to file."""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f)

    def _calculate_url_hash(self, url: str) -> str:
        """Calculate SHA-256 hash of URL."""
        return hashlib.sha256(url.encode()).hexdigest()

    def _get_cache_size(self) -> int:
        """Calculate total size of cached images."""
        total_size = 0
        for image_data in self.metadata['images'].values():
            total_size += image_data['size']
        return total_size

    def _cleanup_expired(self):
        """Remove expired images from cache."""
        now = datetime.now()
        expired = []

        for url_hash, image_data in self.metadata['images'].items():
            last_accessed = datetime.fromtimestamp(image_data['last_accessed'])
            if now - last_accessed > self.ttl:
                expired.append(url_hash)
                vana.logging.info(f"Found expired image: {image_data['url']}, last accessed: {last_accessed}")

        for url_hash in expired:
            self._remove_image(url_hash)

        if expired:
            vana.logging.info(f"Cleaned up {len(expired)} expired images from cache")

    def _cleanup_by_size(self):
        """Remove oldest images until cache size is under limit."""
        current_size = self._get_cache_size()
        removed_count = 0

        while current_size > self.max_cache_size_bytes:
            # Find oldest accessed image
            oldest_hash = min(
                self.metadata['images'].keys(),
                key=lambda k: self.metadata['images'][k]['last_accessed']
            )
            removed_size = self.metadata['images'][oldest_hash]['size']
            self._remove_image(oldest_hash)
            current_size -= removed_size
            removed_count += 1

        if removed_count > 0:
            vana.logging.info(f"Removed {removed_count} images to maintain cache size limit")

    def _remove_image(self, url_hash: str):
        """Remove image from cache and metadata."""
        image_data = self.metadata['images'].get(url_hash, {})
        image_path = self.cache_dir / f"{url_hash}.tar"

        if image_path.exists():
            image_path.unlink()
            vana.logging.info(f"Removed cached image file for {image_data.get('url', url_hash)}")

        # Remove from Docker if loaded
        try:
            image_tag = image_data.get('image_tag')
            if image_tag:
                self.docker_client.images.remove(image_tag, force=True)
                vana.logging.info(f"Removed Docker image {image_tag}")
        except docker.errors.ImageNotFound:
            pass
        except Exception as e:
            vana.logging.error(f"Error removing Docker image: {e}")

        del self.metadata['images'][url_hash]
        self._save_metadata()

    def get_image_sha256(self, url: str) -> Optional[str]:
        # Ensure image exists in cache
        self.get_image(url)

        hash_sha256 = hashlib.sha256()
        url_hash = self._calculate_url_hash(url)
        image_path = self.cache_dir / f"{url_hash}.tar"
        with open(image_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def get_image(self, url: str) -> Optional[str]:
        """
        Get image from cache or download if not present.
        Returns a unique image tag based on the URL if successful, None otherwise.
        """
        url_hash = self._calculate_url_hash(url)
        image_path = self.cache_dir / f"{url_hash}.tar"

        # Generate a unique image tag based on URL
        unique_tag = f"refinement-{url_hash[:12]}:latest"

        with self.lock:
            # Check if image exists in cache and is not expired
            if url_hash in self.metadata['images']:
                image_data = self.metadata['images'][url_hash]
                last_accessed = datetime.fromtimestamp(image_data['last_accessed'])

                if datetime.now() - last_accessed <= self.ttl:
                    # Update last accessed time
                    image_data['last_accessed'] = time.time()
                    self._save_metadata()

                    # Load image if not already in Docker
                    try:
                        self.docker_client.images.get(unique_tag)
                        vana.logging.info(f"[Image {url}] Cache hit: Serving from cache (tag: {unique_tag})")
                        return unique_tag
                    except docker.errors.ImageNotFound:
                        vana.logging.info(f"Cache hit but Docker image not found, reloading from cache file: {url}")
                        with open(image_path, 'rb') as f:
                            images = self.docker_client.images.load(f.read())
                            if images and images[0]:
                                # Tag the loaded image with unique tag
                                images[0].tag(unique_tag)
                                vana.logging.info(f"Successfully reloaded image from cache (tag: {unique_tag})")
                                return unique_tag
                            return None

            # Download and cache new image
            try:
                vana.logging.info(f"[Image {url}] Cache miss: Downloading")
                # Download image
                response = requests.get(url, stream=True)
                response.raise_for_status()

                # Save to cache
                with open(image_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                # Load into Docker
                with open(image_path, 'rb') as f:
                    images = self.docker_client.images.load(f.read())
                    if not images:
                        raise ValueError("No images loaded from tarball")

                    # Tag the image with unique tag
                    images[0].tag(unique_tag)
                    vana.logging.info(f"[Image {url}] Successfully downloaded and cached (tag: {unique_tag})")

                    # Update metadata
                    file_size = image_path.stat().st_size
                    self.metadata['images'][url_hash] = {
                        'url': url,
                        'image_tag': unique_tag,
                        'size': file_size,
                        'last_accessed': time.time()
                    }
                    self._save_metadata()
                    vana.logging.info(f"Added image to cache (size: {file_size / (1024 * 1024):.2f}MB)")

                    # Run cleanup if needed
                    self._cleanup_expired()
                    self._cleanup_by_size()

                    return unique_tag

            except Exception as e:
                vana.logging.error(f"[Image {url}] Error downloading and caching: {e}")
                if image_path.exists():
                    image_path.unlink()
                return None

    def clear_cache(self):
        """Clear all cached images."""
        image_count = len(self.metadata['images'])
        for url_hash in list(self.metadata['images'].keys()):
            self._remove_image(url_hash)
        vana.logging.info(f"Cleared cache: removed {image_count} images")
