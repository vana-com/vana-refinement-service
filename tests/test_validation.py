"""
Unit tests for validation services.

Tests cover all edge cases for encryption key validation and refinement output validation.
"""

import os
import tempfile
import shutil
from unittest.mock import patch, MagicMock, mock_open
import pytest

from refiner.services.validation import (
    validate_encryption_key_format,
    validate_key_derivation,
    validate_refinement_output,
    validate_encryption_key_comprehensive,
    EncryptionKeyValidationError,
    RefinementOutputValidationError
)


class TestEncryptionKeyFormatValidation:
    """Test encryption key format validation"""
    
    def test_valid_key_format(self):
        """Test that valid keys pass format validation"""
        valid_keys = [
            "0x" + "a" * 64,  # Minimum length
            "0x" + "1234567890abcdef" * 8,  # 64 hex chars
            "0x" + "A" * 128,  # Longer key, uppercase
            "0x" + "f" * 256,  # Very long key
        ]
        
        for key in valid_keys:
            # Should not raise an exception
            validate_encryption_key_format(key)
    
    def test_empty_key(self):
        """Test that empty key raises appropriate error"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_format("")
        
        error = exc_info.value
        assert "required" in error.detail["error"]["message"].lower()
        assert "original file encryption key" in error.detail["error"]["details"]["guidance"]
    
    def test_none_key(self):
        """Test that None key raises appropriate error"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_format(None)
        
        error = exc_info.value
        assert "required" in error.detail["error"]["message"].lower()
    
    def test_non_string_key(self):
        """Test that non-string keys raise appropriate error"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_format(123)
        
        error = exc_info.value
        assert "must be a string" in error.detail["error"]["message"]
        assert "hex string starting with '0x'" in error.detail["error"]["details"]["guidance"]
    
    def test_missing_0x_prefix(self):
        """Test that keys without 0x prefix raise appropriate error"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_format("1234567890abcdef" * 4)
        
        error = exc_info.value
        assert "must start with '0x'" in error.detail["error"]["message"]
        assert "Add '0x' prefix" in error.detail["error"]["details"]["guidance"]
    
    def test_only_0x(self):
        """Test that '0x' alone raises appropriate error"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_format("0x")
        
        error = exc_info.value
        assert "cannot be just '0x'" in error.detail["error"]["message"]
        assert "full hex-encoded encryption key" in error.detail["error"]["details"]["guidance"]
    
    def test_invalid_hex_characters(self):
        """Test that invalid hex characters raise appropriate error"""
        invalid_keys = [
            "0x123g567890abcdef" * 4,  # 'g' is not hex
            "0x123456789@abcdef" * 4,  # '@' is not hex
            "0x" + "xyz" * 21 + "ab",  # Contains 'xyz'
            "0x" + "b" * 63,  # Odd length hex string (invalid for bytes.fromhex)
        ]
        
        for key in invalid_keys:
            with pytest.raises(EncryptionKeyValidationError) as exc_info:
                validate_encryption_key_format(key)
            
            error = exc_info.value
            assert "invalid hex characters" in error.detail["error"]["message"]
            assert "valid hex characters (0-9, a-f, A-F)" in error.detail["error"]["details"]["guidance"]
    
    def test_too_short_key(self):
        """Test that keys shorter than minimum length raise appropriate error"""
        short_keys = [
            "0x12",  # Way too short (even length)
            "0x" + "a" * 32,  # 32 hex chars = 16 bytes, need at least 32 bytes
            "0x" + "b" * 62,  # 62 hex chars, just under minimum (even length)
        ]
        
        for key in short_keys:
            with pytest.raises(EncryptionKeyValidationError) as exc_info:
                validate_encryption_key_format(key)
            
            error = exc_info.value
            assert "too short" in error.detail["error"]["message"]
            assert "minimum 64 required" in error.detail["error"]["message"]
            assert "at least 32 bytes" in error.detail["error"]["details"]["guidance"]
    
    def test_error_includes_expected_details(self):
        """Test that errors include helpful details"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_format("")
        
        error = exc_info.value
        details = error.detail["error"]["details"]
        
        assert "expected_format" in details
        assert "key_type" in details
        assert "guidance" in details
        assert "Original file encryption key (EK)" in details["key_type"]
        assert "not encrypted encryption key (EEK)" in details["key_type"]


class TestKeyDerivationValidation:
    """Test key derivation validation"""
    
    def test_valid_key_derivation(self):
        """Test that valid keys can be derived successfully"""
        valid_key = "0x" + "1234567890abcdef" * 8  # 64 hex chars
        
        derived_key = validate_key_derivation(valid_key)
        
        assert derived_key.startswith("0x")
        assert len(derived_key) == 130  # 0x + 128 hex chars
        # Verify it's valid hex
        bytes.fromhex(derived_key[2:])
    
    def test_key_derivation_consistency(self):
        """Test that key derivation is consistent"""
        test_key = "0x" + "abcdef1234567890" * 8
        
        derived_key1 = validate_key_derivation(test_key)
        derived_key2 = validate_key_derivation(test_key)
        
        assert derived_key1 == derived_key2
    
    def test_different_keys_produce_different_derivations(self):
        """Test that different keys produce different derived keys"""
        key1 = "0x" + "1111111111111111" * 8
        key2 = "0x" + "2222222222222222" * 8
        
        derived_key1 = validate_key_derivation(key1)
        derived_key2 = validate_key_derivation(key2)
        
        assert derived_key1 != derived_key2
    
    @patch('refiner.services.validation.HKDF')
    def test_hkdf_failure(self, mock_hkdf):
        """Test that HKDF failures are handled appropriately"""
        mock_hkdf_instance = MagicMock()
        mock_hkdf_instance.derive.side_effect = Exception("HKDF derivation failed")
        mock_hkdf.return_value = mock_hkdf_instance
        
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_key_derivation("0x" + "a" * 64)
        
        error = exc_info.value
        assert error.error_code == "KEY_DERIVATION_FAILED"
        assert "Key derivation failed" in error.detail["error"]["message"]
        assert "properly formatted" in error.detail["error"]["details"]["guidance"]


class TestRefinementOutputValidation:
    """Test refinement output validation"""
    
    @patch('refiner.utils.files.download_file')
    @patch('refiner.utils.cryptography.decrypt_file')
    @patch('os.path.getsize')
    @patch('os.path.exists')
    def test_valid_refinement_output(self, mock_exists, mock_getsize, mock_decrypt, mock_download):
        """Test that valid refinement output passes validation"""
        # Setup mocks
        mock_download.return_value = "/tmp/downloaded_file"
        mock_decrypt.return_value = "/tmp/decrypted_file"
        mock_exists.return_value = True
        mock_getsize.side_effect = [1024, 512]  # Downloaded file size, then decrypted size
        
        # Should not raise an exception
        validate_refinement_output("https://ipfs.example.com/file", "0x" + "a" * 128)
        
        mock_download.assert_called_once_with("https://ipfs.example.com/file")
        mock_decrypt.assert_called_once_with("/tmp/downloaded_file", "0x" + "a" * 128)
    
    @patch('refiner.utils.files.download_file')
    def test_download_failure(self, mock_download):
        """Test that download failures raise appropriate error"""
        from refiner.errors.exceptions import FileDownloadError
        mock_download.side_effect = FileDownloadError("https://example.com", "Network error")
        
        with pytest.raises(RefinementOutputValidationError) as exc_info:
            validate_refinement_output("https://ipfs.example.com/file", "0x" + "a" * 128)
        
        error = exc_info.value
        assert error.error_code == "REFINEMENT_OUTPUT_INACCESSIBLE"
        assert "Cannot access refinement output URL" in error.detail["error"]["message"]
        assert error.detail["error"]["details"]["refinement_url"] == "https://ipfs.example.com/file"
    
    @patch('refiner.utils.files.download_file')
    @patch('os.path.getsize')
    @patch('os.path.exists')
    def test_empty_downloaded_file(self, mock_exists, mock_getsize, mock_download):
        """Test that empty downloaded files raise appropriate error"""
        mock_download.return_value = "/tmp/empty_file"
        mock_exists.return_value = True
        mock_getsize.return_value = 0  # Empty file
        
        with pytest.raises(RefinementOutputValidationError) as exc_info:
            validate_refinement_output("https://ipfs.example.com/file", "0x" + "a" * 128)
        
        error = exc_info.value
        assert error.error_code == "REFINEMENT_OUTPUT_EMPTY"
        assert "empty" in error.detail["error"]["message"].lower()
    
    @patch('refiner.utils.files.download_file')
    @patch('refiner.utils.cryptography.decrypt_file')
    @patch('os.path.getsize')
    @patch('os.path.exists')
    def test_decryption_failure(self, mock_exists, mock_getsize, mock_decrypt, mock_download):
        """Test that decryption failures raise appropriate error"""
        from refiner.errors.exceptions import FileDecryptionError
        
        mock_download.return_value = "/tmp/downloaded_file"
        mock_exists.return_value = True
        mock_getsize.return_value = 1024  # Non-empty downloaded file
        mock_decrypt.side_effect = FileDecryptionError("Decryption failed")
        
        with pytest.raises(RefinementOutputValidationError) as exc_info:
            validate_refinement_output("https://ipfs.example.com/file", "0x" + "a" * 128)
        
        error = exc_info.value
        assert error.error_code == "REFINEMENT_OUTPUT_DECRYPTION_FAILED"
        assert "Cannot decrypt refinement output" in error.detail["error"]["message"]
    
    @patch('refiner.utils.files.download_file')
    @patch('refiner.utils.cryptography.decrypt_file')
    @patch('os.path.getsize')
    @patch('os.path.exists')
    def test_empty_after_decryption(self, mock_exists, mock_getsize, mock_decrypt, mock_download):
        """Test that files empty after decryption raise appropriate error"""
        mock_download.return_value = "/tmp/downloaded_file"
        mock_decrypt.return_value = "/tmp/decrypted_file"
        mock_exists.return_value = True
        mock_getsize.side_effect = [1024, 0]  # Downloaded file has content, decrypted is empty
        
        with pytest.raises(RefinementOutputValidationError) as exc_info:
            validate_refinement_output("https://ipfs.example.com/file", "0x" + "a" * 128)
        
        error = exc_info.value
        assert error.error_code == "REFINEMENT_OUTPUT_EMPTY_AFTER_DECRYPTION"
        assert "decrypts to empty content" in error.detail["error"]["message"]
    
    def test_error_includes_troubleshooting(self):
        """Test that errors include troubleshooting information"""
        with patch('refiner.utils.files.download_file') as mock_download:
            mock_download.side_effect = Exception("Network error")
            
            with pytest.raises(RefinementOutputValidationError) as exc_info:
                validate_refinement_output("https://ipfs.example.com/file", "0x" + "a" * 128)
        
        error = exc_info.value
        details = error.detail["error"]["details"]
        
        assert "troubleshooting" in details
        assert "check_ipfs_accessibility" in details["troubleshooting"]
        assert "verify_file_encryption" in details["troubleshooting"]
        assert "check_file_content" in details["troubleshooting"]


class TestComprehensiveValidation:
    """Test the comprehensive validation function"""
    
    def test_successful_comprehensive_validation(self):
        """Test that valid keys pass comprehensive validation"""
        valid_key = "0x" + "1234567890abcdef" * 8
        
        derived_key = validate_encryption_key_comprehensive(valid_key)
        
        assert derived_key.startswith("0x")
        assert len(derived_key) == 130
    
    def test_format_error_in_comprehensive_validation(self):
        """Test that format errors are propagated in comprehensive validation"""
        with pytest.raises(EncryptionKeyValidationError) as exc_info:
            validate_encryption_key_comprehensive("invalid_key")
        
        error = exc_info.value
        assert "must start with '0x'" in error.detail["error"]["message"]
    
    def test_derivation_error_in_comprehensive_validation(self):
        """Test that derivation errors are propagated in comprehensive validation"""
        with patch('refiner.services.validation.validate_key_derivation') as mock_derivation:
            mock_derivation.side_effect = EncryptionKeyValidationError(
                "Derivation failed", "Test guidance", "KEY_DERIVATION_FAILED"
            )
            
            with pytest.raises(EncryptionKeyValidationError) as exc_info:
                validate_encryption_key_comprehensive("0x" + "a" * 64)
            
            error = exc_info.value
            assert error.error_code == "KEY_DERIVATION_FAILED"


class TestIntegrationScenarios:
    """Test realistic integration scenarios"""
    
    def test_typical_api_consumer_errors(self):
        """Test common mistakes API consumers might make"""
        
        # Common mistake 1: Providing encrypted encryption key instead of original
        encrypted_key = "0x" + "e" * 64  # This might be an EEK, not EK
        # This should still pass format validation, but would fail in actual decryption
        validate_encryption_key_format(encrypted_key)
        
        # Common mistake 2: Missing 0x prefix
        with pytest.raises(EncryptionKeyValidationError):
            validate_encryption_key_format("1234567890abcdef" * 4)
        
        # Common mistake 3: Wrong key length
        with pytest.raises(EncryptionKeyValidationError):
            validate_encryption_key_format("0x123456")
        
        # Common mistake 4: Invalid hex characters
        with pytest.raises(EncryptionKeyValidationError):
            validate_encryption_key_format("0x123ghijk")
    
    @patch('refiner.utils.files.download_file')
    @patch('refiner.utils.cryptography.decrypt_file')
    @patch('os.path.getsize')
    @patch('os.path.exists')
    def test_refinement_output_edge_cases(self, mock_exists, mock_getsize, mock_decrypt, mock_download):
        """Test edge cases in refinement output validation"""
        
        # Case 1: IPFS URL is inaccessible
        mock_download.side_effect = Exception("IPFS node unreachable")
        
        with pytest.raises(RefinementOutputValidationError) as exc_info:
            validate_refinement_output("https://ipfs.io/ipfs/QmTest", "0x" + "a" * 128)
        
        assert "REFINEMENT_OUTPUT_DOWNLOAD_FAILED" in str(exc_info.value.error_code)
        
        # Reset for next test
        mock_download.side_effect = None
        mock_download.return_value = "/tmp/file"
        
        # Case 2: File downloads but is corrupted/unreadable
        mock_exists.return_value = True
        mock_getsize.return_value = 1024
        from refiner.errors.exceptions import FileDecryptionError
        mock_decrypt.side_effect = FileDecryptionError("File corrupted")
        
        with pytest.raises(RefinementOutputValidationError) as exc_info:
            validate_refinement_output("https://ipfs.io/ipfs/QmTest", "0x" + "a" * 128)
        
        assert "REFINEMENT_OUTPUT_DECRYPTION_FAILED" in str(exc_info.value.error_code)


# Fixtures for testing
@pytest.fixture
def valid_encryption_key():
    """Fixture providing a valid encryption key"""
    return "0x" + "1234567890abcdef" * 8


@pytest.fixture
def mock_refinement_url():
    """Fixture providing a mock refinement URL"""
    return "https://ipfs.io/ipfs/QmTestRefinementOutput"


@pytest.fixture
def mock_derived_key():
    """Fixture providing a mock derived key"""
    return "0x" + "a" * 128


# Performance tests
class TestValidationPerformance:
    """Test that validation functions perform efficiently"""
    
    def test_format_validation_is_fast(self, valid_encryption_key):
        """Test that format validation completes quickly"""
        import time
        
        start_time = time.time()
        for _ in range(1000):
            validate_encryption_key_format(valid_encryption_key)
        end_time = time.time()
        
        # Should complete 1000 validations in less than 1 second
        assert (end_time - start_time) < 1.0
    
    def test_derivation_validation_is_reasonable(self, valid_encryption_key):
        """Test that key derivation validation completes in reasonable time"""
        import time
        
        start_time = time.time()
        for _ in range(100):
            validate_key_derivation(valid_encryption_key)
        end_time = time.time()
        
        # Should complete 100 derivations in less than 5 seconds
        assert (end_time - start_time) < 5.0 