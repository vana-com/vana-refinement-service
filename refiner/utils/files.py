import os
import tempfile
from urllib.parse import urlparse

import requests
import vana

from refiner.errors.exceptions import FileDownloadError


def download_file(file_url: str) -> str:
    """
    Downloads a file from a URL into a temporary directory.

    Args:
        file_url (str): URL of the file to download.

    Returns:
        str: Path to the downloaded file in a temporary location.
             The caller is responsible for cleaning up this file and its directory.

    Raises:
        FileDownloadError: If file download fails.
    """
    temp_dir = tempfile.mkdtemp()
    file_extension = '.zip'  # Default extension

    # Attempt to determine file extension
    try:
        response = requests.head(file_url, allow_redirects=True, timeout=10)
        response.raise_for_status()

        # Check Content-Disposition header
        if 'Content-Disposition' in response.headers:
            content_disposition = response.headers['Content-Disposition']
            if 'filename=' in content_disposition:
                filename_start = content_disposition.index('filename=') + 9
                filename_end = content_disposition.find(';', filename_start)
                if filename_end == -1:
                    filename_end = len(content_disposition)
                filename = content_disposition[filename_start:filename_end].strip('"\'')
                _, ext = os.path.splitext(filename)
                if ext:
                    file_extension = ext

        # If no extension from header, try URL path
        if file_extension == '.zip':
            parsed_url = urlparse(file_url)
            _, ext = os.path.splitext(parsed_url.path)
            if ext:
                file_extension = ext

        # If still no extension, check Content-Type header
        if file_extension == '.zip' and 'Content-Type' in response.headers:
            content_type = response.headers['Content-Type'].lower().split(';')[0].strip()
            mime_to_ext = {
                'application/pdf': '.pdf', 'application/zip': '.zip',
                'application/x-gzip': '.gz', 'application/x-tar': '.tar',
                'application/x-compressed': '.zip', 'application/x-7z-compressed': '.7z',
                'application/json': '.json', 'text/csv': '.csv',
                'text/plain': '.txt', 'image/jpeg': '.jpg', 'image/png': '.png'
            }
            file_extension = mime_to_ext.get(content_type, '.zip')

    except requests.exceptions.RequestException as e:
        vana.logging.warning(
            f"Could not reliably determine file extension from URL '{file_url}'. Error: {e}. Using default: {file_extension}")
        # Clean up temp dir if header check fails before download attempt
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass  # Directory might not be empty or already removed
        # Re-raise or handle as appropriate, here we just log and continue with default ext
    except Exception as e:
        vana.logging.warning(f"Error determining file extension for '{file_url}': {e}. Using default: {file_extension}")
        # Clean up temp dir
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass

    encrypted_file_path = os.path.join(temp_dir, f"encrypted_file{file_extension}")

    # Download the actual file
    try:
        response = requests.get(file_url, stream=True, timeout=30)
        response.raise_for_status()
        with open(encrypted_file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        vana.logging.info(f"Successfully downloaded file to: {encrypted_file_path}")
        return encrypted_file_path
    except requests.exceptions.RequestException as e:
        # Clean up temp dir and file if download fails
        try:
            if os.path.exists(encrypted_file_path):
                os.remove(encrypted_file_path)
        except OSError:
            pass
        try:
            os.rmdir(temp_dir)
        except OSError:
            pass
        raise FileDownloadError(file_url=file_url, error=str(e))
