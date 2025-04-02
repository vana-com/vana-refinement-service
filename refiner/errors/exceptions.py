from typing import Any, Dict, Optional

from fastapi import HTTPException, status


class RefinementServiceBaseException(HTTPException):
    """Base exception class for refinement service errors"""

    def __init__(
            self,
            status_code: int,
            message: str,
            error_code: str,
            details: Optional[Dict[str, Any]] = None
    ):
        self.error_code = error_code
        self.details = details or {}
        super().__init__(
            status_code=status_code,
            detail={
                "error": {
                    "code": error_code,
                    "message": message,
                    "details": self.details
                }
            }
        )


class FileDownloadError(RefinementServiceBaseException):
    def __init__(self, file_url: str, error: str, file_id: Optional[int] = None):
        details = {
            "url": file_url,
            "error": error
        }
        if file_id is not None:
            details["file_id"] = file_id

        super().__init__(
            status_code=status.HTTP_502_BAD_GATEWAY,
            message="Failed to download file",
            error_code="FILE_DOWNLOAD_ERROR",
            details=details
        )


class FileDecryptionError(RefinementServiceBaseException):
    def __init__(self, error: str, file_id: Optional[int] = None):
        details = {"error": error}
        if file_id is not None:
            details["file_id"] = file_id

        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message="Failed to decrypt file",
            error_code="FILE_DECRYPTION_ERROR",
            details=details
        )


class InvalidPermissionError(RefinementServiceBaseException):
    def __init__(self, file_id: int, address: str, reason: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            message="Invalid permission for file access",
            error_code="INVALID_PERMISSION",
            details={
                "file_id": file_id,
                "address": address,
                "reason": reason
            }
        )


class ContainerExecutionError(RefinementServiceBaseException):
    def __init__(self, container_name: str, exit_code: int, logs: str):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="Container execution failed",
            error_code="CONTAINER_EXECUTION_ERROR",
            details={
                "container_name": container_name,
                "exit_code": exit_code,
                "logs": logs
            }
        )


class IPFSUploadError(RefinementServiceBaseException):
    def __init__(self, error_message: str):
        super().__init__(
            status_code=status.HTTP_502_BAD_GATEWAY,
            message="Failed to upload artifacts to IPFS",
            error_code="IPFS_UPLOAD_ERROR",
            details={
                "error": error_message
            }
        )


class CryptographyError(RefinementServiceBaseException):
    def __init__(self, operation: str, error: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=f"Cryptography operation failed: {operation}",
            error_code="CRYPTOGRAPHY_ERROR",
            details={
                "operation": operation,
                "error": error
            }
        )


class ContainerTimeoutError(RefinementServiceBaseException):
    def __init__(self, container_name: str, timeout: int):
        super().__init__(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            message="Container execution timed out",
            error_code="CONTAINER_TIMEOUT_ERROR",
            details={
                "container_name": container_name,
                "timeout_seconds": timeout
            }
        )
