"""
Validation services for refinement operations.

This module provides structured validation for:
1. Encryption key format and validity 
2. Refinement output accessibility and content
"""

import os
import tempfile
import shutil

import vana
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from refiner.errors.exceptions import (
    EncryptionKeyValidationError,
    RefinementOutputValidationError
)


def validate_encryption_key_format(encryption_key: str) -> None:
    """
    Validate encryption key format without expensive operations.
    
    Args:
        encryption_key: The encryption key to validate
        
    Raises:
        EncryptionKeyValidationError: If the key format is invalid
    """
    if not encryption_key:
        raise EncryptionKeyValidationError(
            message="Encryption key is required",
            guidance="Provide the original file encryption key (EK) used to encrypt the uploaded file"
        )
    
    if not isinstance(encryption_key, str):
        raise EncryptionKeyValidationError(
            message="Encryption key must be a string",
            guidance="Ensure the encryption key is provided as a hex string starting with '0x'"
        )
    
    if not encryption_key.startswith('0x'):
        raise EncryptionKeyValidationError(
            message="Encryption key must start with '0x'",
            guidance="Add '0x' prefix to your hex-encoded encryption key"
        )
    
    # Remove 0x prefix for length validation
    hex_part = encryption_key[2:]
    
    if len(hex_part) == 0:
        raise EncryptionKeyValidationError(
            message="Encryption key cannot be just '0x'",
            guidance="Provide the full hex-encoded encryption key after the '0x' prefix"
        )
    
    # Check if it's valid hex
    try:
        bytes.fromhex(hex_part)
    except ValueError:
        raise EncryptionKeyValidationError(
            message="Encryption key contains invalid hex characters",
            guidance="Ensure the encryption key contains only valid hex characters (0-9, a-f, A-F)"
        )
    
    # Check minimum length (at least 32 bytes = 64 hex chars for AES-256)
    if len(hex_part) < 64:
        raise EncryptionKeyValidationError(
            message=f"Encryption key is too short ({len(hex_part)} hex characters, minimum 64 required)",
            guidance="Provide a full-length encryption key (at least 32 bytes = 64 hex characters)"
        )


def validate_key_derivation(encryption_key: str) -> str:
    """
    Validate that key derivation works and return the derived refinement key.
    
    Args:
        encryption_key: The original encryption key
        
    Returns:
        str: The derived refinement encryption key
        
    Raises:
        EncryptionKeyValidationError: If key derivation fails
    """
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'query-engine',
            backend=default_backend()
        )
        master_key_bytes = bytes.fromhex(encryption_key.removeprefix('0x'))
        refinement_encryption_key = '0x' + hkdf.derive(master_key_bytes).hex()
        
        # Validate the derived key format
        if not refinement_encryption_key.startswith('0x') or len(refinement_encryption_key) != 130:  # 0x + 128 hex chars
            raise ValueError(f"Invalid derived key format: length {len(refinement_encryption_key)}")
        
        vana.logging.debug("Key derivation validation successful")
        return refinement_encryption_key
        
    except Exception as e:
        raise EncryptionKeyValidationError(
            message=f"Key derivation failed: {str(e)}",
            guidance="Ensure the encryption key is properly formatted and contains valid key material",
            error_code="KEY_DERIVATION_FAILED"
        )


def validate_refinement_output(refinement_url: str, expected_refinement_key: str) -> None:
    """
    Validate that the refinement output is accessible and properly encrypted.
    
    Args:
        refinement_url: URL to the refined output file
        expected_refinement_key: The derived refinement encryption key that should decrypt the output
        
    Raises:
        RefinementOutputValidationError: If validation fails
    """
    vana.logging.info(f"Validating refinement output at: {refinement_url}")
    
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="refinement_output_validation_")
        
        # 1. Check if the URL is accessible and download the file
        try:
            # Import here to avoid circular imports
            from refiner.utils.files import download_file
            output_file_path = download_file(refinement_url)
            output_file_size = os.path.getsize(output_file_path) if os.path.exists(output_file_path) else 0
            
            if output_file_size == 0:
                raise RefinementOutputValidationError(
                    message="Refinement output file is empty",
                    refinement_url=refinement_url,
                    error_code="REFINEMENT_OUTPUT_EMPTY"
                )
                
            vana.logging.debug(f"Downloaded refinement output: {output_file_size} bytes")
            
        except RefinementOutputValidationError:
            # Re-raise our own validation errors as-is
            raise
        except Exception as e:
            if "FileDownloadError" in str(type(e)):
                raise RefinementOutputValidationError(
                    message=f"Cannot access refinement output URL: {str(e)}",
                    refinement_url=refinement_url,
                    error_code="REFINEMENT_OUTPUT_INACCESSIBLE"
                )
            else:
                raise RefinementOutputValidationError(
                    message=f"Failed to download refinement output: {str(e)}",
                    refinement_url=refinement_url,
                    error_code="REFINEMENT_OUTPUT_DOWNLOAD_FAILED"
                )
        
        # 2. Test decryption with the expected key
        try:
            # Import here to avoid circular imports and make it clear this is for validation
            from refiner.utils.cryptography import decrypt_file
            
            decrypted_path = decrypt_file(output_file_path, expected_refinement_key)
            decrypted_size = os.path.getsize(decrypted_path) if os.path.exists(decrypted_path) else 0
            
            if decrypted_size == 0:
                raise RefinementOutputValidationError(
                    message="Refinement output decrypts to empty content",
                    refinement_url=refinement_url,
                    error_code="REFINEMENT_OUTPUT_EMPTY_AFTER_DECRYPTION"
                )
            
            vana.logging.debug(f"Successfully decrypted refinement output: {decrypted_size} bytes")
            
        except RefinementOutputValidationError:
            # Re-raise our own validation errors as-is
            raise
        except Exception as e:
            if "FileDecryptionError" in str(type(e)):
                raise RefinementOutputValidationError(
                    message=f"Cannot decrypt refinement output with derived key: {str(e)}",
                    refinement_url=refinement_url,
                    error_code="REFINEMENT_OUTPUT_DECRYPTION_FAILED"
                )
            else:
                raise RefinementOutputValidationError(
                    message=f"Unexpected error during refinement output decryption: {str(e)}",
                    refinement_url=refinement_url,
                    error_code="REFINEMENT_OUTPUT_VALIDATION_ERROR"
                )
        
        vana.logging.info("Refinement output validation successful")
        
    finally:
        # Clean up temporary files
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                vana.logging.warning(f"Failed to clean up validation temp directory: {e}")


def validate_encryption_key_comprehensive(encryption_key: str) -> str:
    """
    Perform comprehensive encryption key validation.
    
    This is a lighter-weight alternative to the previous pre-validation approach.
    It validates format and key derivation without expensive file operations.
    
    Args:
        encryption_key: The encryption key to validate
        
    Returns:
        str: The derived refinement encryption key
        
    Raises:
        EncryptionKeyValidationError: If validation fails
    """
    vana.logging.info("Performing encryption key validation")
    
    # Step 1: Format validation
    validate_encryption_key_format(encryption_key)
    
    # Step 2: Key derivation validation
    refinement_key = validate_key_derivation(encryption_key)
    
    vana.logging.info("Encryption key validation completed successfully")
    return refinement_key 