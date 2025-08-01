import os
import json
import logging
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Configuration
REFINER_LOGS_DIR = Path(os.getenv('REFINER_LOGS_DIR', "/app/data/refiner_logs"))
MAX_LOG_FILE_SIZE = int(os.getenv('MAX_REFINER_LOG_FILE_SIZE', '10485760'))  # 10MB
MAX_LOG_FILES_PER_REFINER = int(os.getenv('MAX_LOG_FILES_PER_REFINER', '5'))
LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', '30'))

@dataclass
class RefinerLogEntryInternal:
    """Internal representation of a refiner log entry"""
    timestamp: datetime
    job_id: str
    level: str
    message: str
    docker_container: Optional[str] = None
    exit_code: Optional[int] = None
    full_logs: Optional[str] = None

class RefinerLoggingService:
    """Service for managing per-refiner logging"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._ensure_log_directory()
    
    def _ensure_log_directory(self):
        """Ensure the refiner logs directory exists"""
        REFINER_LOGS_DIR.mkdir(parents=True, exist_ok=True)
        logger.info(f"Refiner logs directory initialized: {REFINER_LOGS_DIR}")
    
    def _get_refiner_log_dir(self, refiner_id: int) -> Path:
        """Get the log directory for a specific refiner"""
        refiner_dir = REFINER_LOGS_DIR / f"refiner_{refiner_id}"
        refiner_dir.mkdir(parents=True, exist_ok=True)
        return refiner_dir
    
    def _get_current_log_file(self, refiner_id: int) -> Path:
        """Get the current log file for a refiner"""
        refiner_dir = self._get_refiner_log_dir(refiner_id)
        return refiner_dir / "current.log"
    
    def _rotate_logs_if_needed(self, refiner_id: int):
        """Rotate logs if the current file is too large"""
        current_log = self._get_current_log_file(refiner_id)
        
        if not current_log.exists():
            return
            
        if current_log.stat().st_size > MAX_LOG_FILE_SIZE:
            # Create rotated filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_file = current_log.parent / f"refiner_{refiner_id}_{timestamp}.log.gz"
            
            # Compress and move the current log
            with open(current_log, 'rb') as f_in:
                with gzip.open(rotated_file, 'wb') as f_out:
                    f_out.writelines(f_in)
            
            # Remove the original file
            current_log.unlink()
            
            logger.info(f"Rotated logs for refiner {refiner_id}: {rotated_file}")
            
            # Clean up old log files
            self._cleanup_old_logs(refiner_id)
    
    def _cleanup_old_logs(self, refiner_id: int):
        """Clean up old log files for a refiner"""
        refiner_dir = self._get_refiner_log_dir(refiner_id)
        
        # Get all compressed log files
        log_files = list(refiner_dir.glob(f"refiner_{refiner_id}_*.log.gz"))
        log_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        # Remove files beyond the limit
        if len(log_files) > MAX_LOG_FILES_PER_REFINER:
            for old_file in log_files[MAX_LOG_FILES_PER_REFINER:]:
                old_file.unlink()
                logger.info(f"Cleaned up old log file: {old_file}")
        
        # Remove files older than retention period
        cutoff_date = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
        for log_file in log_files:
            if datetime.fromtimestamp(log_file.stat().st_mtime) < cutoff_date:
                log_file.unlink()
                logger.info(f"Cleaned up expired log file: {log_file}")
    
    def log_refinement_job(self, refiner_id: int, job_id: str, level: str, message: str, 
                          docker_container: Optional[str] = None, exit_code: Optional[int] = None,
                          full_logs: Optional[str] = None):
        """Log a refinement job event for a specific refiner"""
        # Prepare data outside of lock to minimize lock time
        MAX_MESSAGE_LENGTH = 1000
        MAX_FULL_LOGS_LENGTH = 5000
        
        truncated_message = message[:MAX_MESSAGE_LENGTH]
        if len(message) > MAX_MESSAGE_LENGTH:
            truncated_message += f"... (message truncated, {len(message) - MAX_MESSAGE_LENGTH} chars removed)"
        
        truncated_full_logs = None
        if full_logs:
            truncated_full_logs = full_logs[:MAX_FULL_LOGS_LENGTH]
            if len(full_logs) > MAX_FULL_LOGS_LENGTH:
                truncated_full_logs += f"... (logs truncated, {len(full_logs) - MAX_FULL_LOGS_LENGTH} chars removed)"
        
        log_entry = RefinerLogEntryInternal(
            timestamp=datetime.now(),
            job_id=job_id[:100],  # Limit job_id length
            level=level[:20],     # Limit level length
            message=truncated_message,
            docker_container=docker_container[:100] if docker_container else None,
            exit_code=exit_code,
            full_logs=truncated_full_logs
        )
        
        # Prepare JSON data
        log_data = {
            "timestamp": log_entry.timestamp.isoformat(),
            "job_id": log_entry.job_id,
            "level": log_entry.level,
            "message": log_entry.message,
            "docker_container": log_entry.docker_container,
            "exit_code": log_entry.exit_code,
            "full_logs": log_entry.full_logs
        }
        json_line = json.dumps(log_data) + '\n'
        
        # Only hold lock for file path determination and rotation check
        with self._lock:
            try:
                self._rotate_logs_if_needed(refiner_id)
                current_log = self._get_current_log_file(refiner_id)
            except Exception as e:
                logger.error(f"Failed to prepare log file for refiner {refiner_id}: {e}")
                return
        
        # Write to file outside of lock to avoid blocking other refiners
        try:
            with open(current_log, 'a', encoding='utf-8') as f:
                f.write(json_line)
            logger.debug(f"Logged entry for refiner {refiner_id}, job {job_id}: {truncated_message[:100]}")
        except Exception as e:
            logger.error(f"Failed to write log entry for refiner {refiner_id}: {e}")
    
    def get_refiner_logs(self, refiner_id: int, limit: int = 100, 
                        start_date: Optional[datetime] = None,
                        end_date: Optional[datetime] = None,
                        job_id: Optional[str] = None) -> List[Dict]:
        """Get logs for a specific refiner with optional filtering"""
        logs = []
        
        try:
            refiner_dir = self._get_refiner_log_dir(refiner_id)
            
            # Get all log files (current + compressed)
            log_files = []
            current_log = self._get_current_log_file(refiner_id)
            if current_log.exists():
                log_files.append(current_log)
            
            # Add compressed files, sorted by modification time (newest first)
            compressed_files = list(refiner_dir.glob(f"refiner_{refiner_id}_*.log.gz"))
            compressed_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            log_files.extend(compressed_files)
            
            # Read logs from files
            for log_file in log_files:
                if len(logs) >= limit:
                    break
                    
                file_logs = self._read_log_file(log_file, limit - len(logs), 
                                              start_date, end_date, job_id)
                logs.extend(file_logs)
            
            # Sort by timestamp (newest first)
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return logs[:limit]
            
        except Exception as e:
            logger.error(f"Failed to get logs for refiner {refiner_id}: {e}")
            return []
    
    def _read_log_file(self, log_file: Path, limit: int,
                      start_date: Optional[datetime] = None,
                      end_date: Optional[datetime] = None,
                      job_id: Optional[str] = None) -> List[Dict]:
        """Read and filter logs from a single log file"""
        logs = []
        
        try:
            # Determine if file is compressed
            if log_file.suffix == '.gz':
                open_func = gzip.open
                mode = 'rt'
            else:
                open_func = open
                mode = 'r'
            
            with open_func(log_file, mode, encoding='utf-8') as f:
                for line in f:
                    if len(logs) >= limit:
                        break
                    
                    try:
                        log_entry = json.loads(line.strip())
                        
                        # Parse timestamp
                        entry_time = datetime.fromisoformat(log_entry['timestamp'])
                        
                        # Apply filters
                        if start_date and entry_time < start_date:
                            continue
                        if end_date and entry_time > end_date:
                            continue
                        if job_id and log_entry.get('job_id') != job_id:
                            continue
                        
                        logs.append(log_entry)
                        
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        logger.warning(f"Failed to parse log line in {log_file}: {e}")
                        continue
            
            return logs
            
        except Exception as e:
            logger.error(f"Failed to read log file {log_file}: {e}")
            return []
    
    def get_refiner_stats(self, refiner_id: int, days: int = 7) -> Dict:
        """Get statistics for a refiner over the specified number of days"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            logs = self.get_refiner_logs(refiner_id, limit=10000, start_date=start_date)
            
            stats = {
                "refiner_id": refiner_id,
                "period_days": days,
                "total_jobs": 0,
                "successful_jobs": 0,
                "failed_jobs": 0,
                "error_rate": 0.0,
                "last_activity": None,
                "common_errors": {}
            }
            
            job_results = {}
            error_counts = {}
            
            for log_entry in logs:
                job_id = log_entry.get('job_id')
                level = log_entry.get('level', '').lower()
                message = log_entry.get('message', '')
                exit_code = log_entry.get('exit_code')
                
                if job_id:
                    if job_id not in job_results:
                        job_results[job_id] = {'started': True, 'completed': False, 'failed': False}
                    
                    if level == 'error' or (exit_code is not None and exit_code != 0):
                        job_results[job_id]['failed'] = True
                        # Count error types
                        error_key = message[:100]  # First 100 chars as error type
                        error_counts[error_key] = error_counts.get(error_key, 0) + 1
                    elif 'completed' in message.lower() or 'success' in message.lower():
                        job_results[job_id]['completed'] = True
                
                # Track last activity
                if not stats["last_activity"]:
                    stats["last_activity"] = log_entry['timestamp']
            
            # Calculate statistics
            stats["total_jobs"] = len(job_results)
            stats["successful_jobs"] = sum(1 for job in job_results.values() 
                                         if job['completed'] and not job['failed'])
            stats["failed_jobs"] = sum(1 for job in job_results.values() if job['failed'])
            
            if stats["total_jobs"] > 0:
                stats["error_rate"] = stats["failed_jobs"] / stats["total_jobs"]
            
            # Get top 5 common errors
            sorted_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)
            stats["common_errors"] = dict(sorted_errors[:5])
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get stats for refiner {refiner_id}: {e}")
            return {"refiner_id": refiner_id, "error": str(e)}

# Global instance with thread-safe initialization
_refiner_logging_service = None
_service_lock = threading.Lock()

def get_refiner_logging_service() -> RefinerLoggingService:
    """Get the global refiner logging service instance (thread-safe)"""
    global _refiner_logging_service
    if _refiner_logging_service is None:
        with _service_lock:
            # Double-check pattern to avoid race conditions
            if _refiner_logging_service is None:
                _refiner_logging_service = RefinerLoggingService()
    return _refiner_logging_service 