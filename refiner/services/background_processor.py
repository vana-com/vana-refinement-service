import asyncio
import threading
import time
from datetime import datetime
from typing import Optional
import logging

import vana

from refiner.stores import refinement_jobs_store
from refiner.services.refine import refine
from refiner.models.models import RefinementRequest, JobStatus, RefinementJob
from refiner.middleware.log_request_id_handler import request_id_context

logger = logging.getLogger(__name__)

class BackgroundRefinementProcessor:
    """
    Background service that processes refinement jobs asynchronously
    """
    
    def __init__(self, vana_client: vana.Client, poll_interval: int = 5, max_concurrent_jobs: int = 10):
        """
        Initialize the background processor
        
        Args:
            vana_client: Vana client for blockchain operations
            poll_interval: How often to check for new jobs (seconds)
            max_concurrent_jobs: Maximum number of jobs to process concurrently
        """
        self.vana_client = vana_client
        self.poll_interval = poll_interval
        self.max_concurrent_jobs = max_concurrent_jobs
        self.is_running = False
        self.stop_event = threading.Event()
        self.worker_thread: Optional[threading.Thread] = None
        self.current_jobs = {}  # Track currently processing jobs
        self._jobs_lock = threading.RLock()  # Lock for thread-safe access to current_jobs
        
        logger.info(f"Initialized background processor (poll_interval={poll_interval}s, max_concurrent={max_concurrent_jobs})")

    def start(self):
        """Start the background processor"""
        if self.is_running:
            logger.warning("Background processor is already running")
            return
            
        self.is_running = True
        self.stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        logger.info("Background refinement processor started")

    def stop(self):
        """Stop the background processor"""
        if not self.is_running:
            return
            
        logger.info("Stopping background refinement processor...")
        self.is_running = False
        self.stop_event.set()
        
        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=10)
            
        logger.info("Background refinement processor stopped")

    def _worker_loop(self):
        """Main worker loop that processes jobs"""
        logger.info("Background processor worker loop started")
        
        last_cleanup = time.time()
        cleanup_interval = 300  # Run cleanup every 5 minutes
        
        while not self.stop_event.is_set():
            try:
                # Clean up completed jobs from tracking
                self._cleanup_completed_jobs()
                
                # Periodically clean up orphaned jobs (every 5 minutes)
                current_time = time.time()
                if current_time - last_cleanup > cleanup_interval:
                    try:
                        orphaned_count = refinement_jobs_store.cleanup_orphaned_jobs(timeout_minutes=60)
                        if orphaned_count > 0:
                            logger.info(f"Cleaned up {orphaned_count} orphaned jobs")
                        last_cleanup = current_time
                    except Exception as cleanup_error:
                        logger.error(f"Error during orphaned job cleanup: {cleanup_error}")
                
                # Check if we can process more jobs
                with self._jobs_lock:
                    current_job_count = len(self.current_jobs)
                    
                if current_job_count < self.max_concurrent_jobs:
                    # Atomically claim pending jobs to prevent race conditions
                    claimed_jobs = refinement_jobs_store.claim_pending_jobs(
                        limit=self.max_concurrent_jobs - current_job_count
                    )
                    
                    # Start processing claimed jobs
                    for job in claimed_jobs:
                        with self._jobs_lock:
                            # Double-check the job isn't already being processed
                            if job.job_id not in self.current_jobs:
                                self._start_job_processing(job)
                            else:
                                # This shouldn't happen with atomic claiming, but handle it gracefully
                                logger.warning(f"Job {job.job_id} was claimed but already in current_jobs")
                
                # Wait before next poll
                self.stop_event.wait(self.poll_interval)
                
            except Exception as e:
                logger.error(f"Error in background processor worker loop: {e}")
                self.stop_event.wait(self.poll_interval)
        
        logger.info("Background processor worker loop ended")

    def _cleanup_completed_jobs(self):
        """Remove completed jobs from tracking"""
        completed_job_ids = []
        
        with self._jobs_lock:
            for job_id, job_thread in self.current_jobs.items():
                if not job_thread.is_alive():
                    completed_job_ids.append(job_id)
            
            for job_id in completed_job_ids:
                del self.current_jobs[job_id]

    def _start_job_processing(self, job: RefinementJob):
        """Start processing a refinement job in a separate thread
        
        Note: This method assumes the caller already holds self._jobs_lock
        and that the job status has already been atomically set to PROCESSING
        """
        logger.info(f"Starting processing for job {job.job_id} (file_id: {job.file_id})")
        
        # Job status is already set to PROCESSING by claim_pending_jobs
        # Start processing thread
        job_thread = threading.Thread(
            target=self._process_job,
            args=(job,),
            daemon=True
        )
        job_thread.start()
        self.current_jobs[job.job_id] = job_thread

    def _process_job(self, job: RefinementJob):
        """Process a single refinement job"""
        job_id = job.job_id
        
        try:
            # Set request ID context for logging
            request_id_context.set(job_id)
            
            logger.info(f"Processing refinement job {job_id} for file {job.file_id}")
            
            # Create a RefinementRequest from the job
            request = RefinementRequest(
                file_id=job.file_id,
                refiner_id=job.refiner_id,
                encryption_key=job.encryption_key,
                env_vars=job.env_vars
            )
            
            # Process the refinement
            response = refine(
                client=self.vana_client,
                request=request,
                request_id=job_id
            )
            
            # Update job with successful result
            refinement_jobs_store.update_job_result(
                job_id=job_id,
                transaction_hash=response.add_refinement_tx_hash
            )
            
            refinement_jobs_store.update_job_status(
                job_id=job_id,
                status=JobStatus.COMPLETED,
                completed_at=datetime.now()
            )
            
            logger.info(f"Successfully completed refinement job {job_id} with tx hash {response.add_refinement_tx_hash}")
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to process refinement job {job_id}: {error_msg}")
            
            try:
                # Update job with failure status
                refinement_jobs_store.update_job_status(
                    job_id=job_id,
                    status=JobStatus.FAILED,
                    error=error_msg,
                    completed_at=datetime.now()
                )
            except Exception as update_error:
                logger.error(f"Failed to update job {job_id} failure status: {update_error}")
                # If we can't update the status, the job will be stuck in PROCESSING
                # This will be handled by a separate cleanup process for orphaned jobs
        
        finally:
            # Clear request ID context
            request_id_context.set(None)
            
            # Ensure job is removed from tracking even if database updates fail
            with self._jobs_lock:
                if job_id in self.current_jobs:
                    del self.current_jobs[job_id]
                    logger.debug(f"Removed job {job_id} from current_jobs tracking")

    def get_status(self) -> dict:
        """Get the current status of the background processor"""
        with self._jobs_lock:
            current_job_count = len(self.current_jobs)
            active_job_ids = list(self.current_jobs.keys())
        
        return {
            "is_running": self.is_running,
            "current_jobs": current_job_count,
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "poll_interval": self.poll_interval,
            "active_job_ids": active_job_ids
        }

# Global processor instance
_processor: Optional[BackgroundRefinementProcessor] = None

def get_background_processor() -> Optional[BackgroundRefinementProcessor]:
    """Get the global background processor instance"""
    return _processor

def initialize_background_processor(vana_client: vana.Client, **kwargs) -> BackgroundRefinementProcessor:
    """Initialize the global background processor instance"""
    global _processor
    if _processor is None:
        _processor = BackgroundRefinementProcessor(vana_client, **kwargs)
    return _processor

def start_background_processor():
    """Start the global background processor"""
    if _processor:
        _processor.start()
    else:
        logger.error("Background processor not initialized")

def stop_background_processor():
    """Stop the global background processor"""
    if _processor:
        _processor.stop() 