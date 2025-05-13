import os
import tempfile
from urllib.parse import urlparse

import requests
import vana
import json

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
        
        # Content-based file type detection
        detected_extension = detect_file_type(encrypted_file_path)
        if detected_extension != file_extension:
            new_path = os.path.join(temp_dir, f"encrypted_file{detected_extension}")
            os.rename(encrypted_file_path, new_path)
            encrypted_file_path = new_path
            vana.logging.info(f"File type detected as {detected_extension} based on content")
        
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


def detect_file_type(file_path):
    """
    Detect file type based on content analysis.
    
    Args:
        file_path (str): Path to the file to analyze
        
    Returns:
        str: Detected file extension with leading dot (e.g., '.json')
    """
    # Try using python-magic if available (most reliable)
    try:
        import magic
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(file_path)
        
        # Map common MIME types to extensions
        mime_to_ext = {
            'application/json': '.json',
            'application/zip': '.zip',
            'application/x-tar': '.tar',
            'application/gzip': '.gz',
            'application/x-gzip': '.gz',
            'application/x-bzip2': '.bz2',
            'application/x-xz': '.xz',
            'application/x-7z-compressed': '.7z',
            'text/plain': '.txt',
            'text/csv': '.csv',
            'text/html': '.html',
            'application/pdf': '.pdf',
            'image/jpeg': '.jpg',
            'image/png': '.png'
        }
        
        if mime_type in mime_to_ext:
            return mime_to_ext[mime_type]
        
        # For generic types, do more specific detection
        if mime_type == 'text/plain':
            # Check if it's JSON
            if is_json_file(file_path):
                return '.json'
            
    except ImportError:
        vana.logging.debug("python-magic not available, falling back to basic detection")
    
    # Basic detection without dependencies
    
    # Check if it's JSON
    if is_json_file(file_path):
        return '.json'
    
    # Check if it's text
    if is_text_file(file_path):
        return '.txt'
    
    # Check for archive signatures
    with open(file_path, 'rb') as f:
        header = f.read(8)  # Read first 8 bytes
        
        # ZIP files start with PK\x03\x04
        if header.startswith(b'PK\x03\x04'):
            return '.zip'
        
        # gzip files start with 1F 8B
        if header.startswith(b'\x1f\x8b'):
            return '.gz'
        
        # tar files can vary, but common ones start with "ustar" at position 257
        f.seek(257)
        if f.read(5) == b'ustar':
            return '.tar'
    
    # Default if no detection succeeds
    return os.path.splitext(file_path)[1] or '.bin'


def is_json_file(file_path):
    """Check if file contains valid JSON."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # Check for JSON structures
            if (content.strip().startswith('{') and content.strip().endswith('}')) or \
               (content.strip().startswith('[') and content.strip().endswith(']')):
                json.loads(content)
                return True
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        pass
    return False


def is_text_file(file_path, sample_size=8192):
    """
    Check if file appears to be text by examining a sample.
    Binary files typically contain null bytes and many non-printable characters.
    """
    try:
        with open(file_path, 'rb') as f:
            sample = f.read(sample_size)
            # Count null bytes and control characters
            null_count = sample.count(0)
            control_count = sum(1 for b in sample if b < 32 and b not in (9, 10, 13))  # Tab, LF, CR are ok
            
            # If >30% are null or control chars, likely binary
            if (null_count + control_count) / len(sample) > 0.3:
                return False
            
            # Try to decode as utf-8
            try:
                sample.decode('utf-8')
                return True
            except UnicodeDecodeError:
                return False
    except:
        return False
