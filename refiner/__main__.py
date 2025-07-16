import asyncio
import copy
import logging
import os
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import vana
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from fastapi import Request, Header

from refiner.middleware.error_handler import error_handler_middleware
from refiner.middleware.log_request_id_handler import add_request_id_middleware, request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse, RefinementJobResponse, RefinementJobStatus, JobStatus, HealthMetrics, RefinerExecutionStatusResponse
from typing import Union
from refiner.services.refine import refine
from refiner.utils.config import add_args, check_config, default_config
from refiner.utils.logfilter import RequestIdFilter
from refiner.services.health import get_health_service
from refiner.services.background_processor import initialize_background_processor, start_background_processor, stop_background_processor, get_background_processor
from refiner.services.execution_stats_service import get_execution_stats_service
from refiner.services.auth_service import verify_refiner_access
from refiner.stores import refinement_jobs_store
from refiner.errors.exceptions import RefinementBaseException

load_dotenv()

from vana.logging import _logging
from vana.logging import logging as vana_logging

SHORT_LOG_FORMAT = "[%(request_id)s] | %(message)s"
LONG_LOG_FORMAT = "%(asctime)s | %(levelname)s | [%(request_id)s] | %(message)s"
formatter = _logging.Formatter(fmt=SHORT_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
long_formatter = _logging.Formatter(fmt=LONG_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

for handler in vana_logging._logger.handlers:
    handler.setFormatter(formatter)

original_logger = vana.logging._logger
original_logger.addFilter(RequestIdFilter())
vana.logging._logger = original_logger

logging.getLogger().addFilter(RequestIdFilter())
for handler in logging.getLogger().handlers:
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(long_formatter)

thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() * 2)


class Refiner:
    """
    Represents the Refiner service
    """

    @classmethod
    def check_config(cls, config: vana.Config):
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        add_args(cls, parser)

    @classmethod
    def config(cls):
        return default_config(cls)

    def __init__(self, config=None):
        self.config = self.config()
        if config:
            base_config = copy.deepcopy(config)
            self.config.merge(base_config)
        self.check_config(self.config)

        # Set up logging with the provided configuration and directory.
        vana.logging(config=self.config, logging_dir=self.config.full_path)

        self.wallet = vana.Wallet(config=self.config)
        self.chain_manager = vana.ChainManager(config=self.config)
        self.vana_client = vana.Client(config=self.config)

        # Serve NodeServer to enable external connections.
        max_workers = os.cpu_count() * 2 + 1
        self.config.node_server.verify_body_integrity = False
        self.node_server = ((vana.NodeServer(
            wallet=self.wallet,
            config=self.config,
            max_workers=max_workers
        ).serve(chain_manager=self.chain_manager)).start())

        # Refinement endpoint with header-based versioning
        self.node_server.router.add_api_route(
            f"/refine",
            self.handle_refinement_request,
            methods=["POST"],
            response_model=Union[RefinementResponse, RefinementJobResponse],
        )
        
        # Job status endpoint
        self.node_server.router.add_api_route(
            f"/refine/{{job_id}}",
            self.get_refinement_job_status,
            methods=["GET"],
            response_model=RefinementJobStatus,
        )
        
        # Background processor status endpoint
        self.node_server.router.add_api_route(
            f"/processor/status",
            self.get_processor_status,
            methods=["GET"],
        )
        
        # Refiner execution stats endpoint
        self.node_server.router.add_api_route(
            f"/stats/refiner/{{refiner_id}}",
            self.get_refiner_execution_stats,
            methods=["GET"],
            response_model=RefinerExecutionStatusResponse,
        )
        
        self.node_server.app.include_router(self.node_server.router)

        # Basic health check for docker container monitoring
        self.node_server.router.add_api_route(
            f"/",
            lambda: {"status": "ok"},
            methods=["GET"]
        )
        self.node_server.app.include_router(self.node_server.router)

        # Comprehensive health endpoint for monitoring systems like Datadog
        self.node_server.router.add_api_route(
            f"/health",
            self.get_health_status,
            methods=["GET"],
            response_model=HealthMetrics,
        )
        self.node_server.app.include_router(self.node_server.router)

        # Enable CORS
        self.node_server.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["OPTIONS", "GET", "POST"],
            allow_headers=["*"],
        )

        # Add error handling middleware
        self.node_server.app.middleware("http")(error_handler_middleware)
        self.node_server.app.middleware("http")(add_request_id_middleware)

        # Create asyncio event loop to manage async tasks.
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        # Instantiate runners
        self.should_exit: bool = False
        self.is_running: bool = False
        self.thread: threading.Thread = None
        self.lock = asyncio.Lock()

        # Check balance
        balance = self.chain_manager.get_balance(self.wallet.hotkey.address)
        if balance < 0.1 and self.config.environment == "production":
            vana.logging.error(
                f"Insufficient balance: {balance} VANA, please top up the wallet {self.wallet.hotkey.address}")
            exit(1)

        vana.logging.info(f"Running refiner on network: {self.config.chain.chain_endpoint}")
        
        # Initialize and start background processor
        poll_interval = int(os.getenv('BACKGROUND_PROCESSOR_POLL_INTERVAL', '5'))
        max_concurrent_jobs = int(os.getenv('BACKGROUND_PROCESSOR_MAX_CONCURRENT_JOBS', '3'))
        initialize_background_processor(self.vana_client, poll_interval=poll_interval, max_concurrent_jobs=max_concurrent_jobs)
        start_background_processor()
        vana.logging.info(f"Background refinement processor initialized and started (poll_interval={poll_interval}s, max_concurrent={max_concurrent_jobs})")

    async def handle_refinement_request(self, refinement_request: RefinementRequest, request: Request) -> Union[RefinementResponse, RefinementJobResponse]:
        """Handle refinement requests with header-based API versioning"""
        version = self._check_api_version(request)
        
        if version == "v2":
            # Use async background processing for v2
            return await self.submit_refinement_job(refinement_request)
        else:
            # Use synchronous processing for v1 (default)
            return await self.forward_refinement_sync(refinement_request)
    
    async def forward_refinement_sync(self, request: RefinementRequest) -> RefinementResponse:
        """Synchronous refinement processing (v1 API) - uses background processor internally"""
        
        job = None
        try:
            # Submit job to background processor for controlled concurrency
            job = refinement_jobs_store.create_job_from_request(request)
            vana.logging.info(f"V1 API: Created background job {job.job_id} for synchronous processing")
            
            # Poll for completion and return traditional response
            poll_interval = int(os.getenv('V1_API_POLL_INTERVAL', '2'))  # Poll every 2 seconds for v1 API
            max_wait_time = int(os.getenv('V1_API_MAX_WAIT_TIME', '900'))  # Maximum 15 minutes wait
            start_time = time.time()
            
            while (time.time() - start_time) < max_wait_time:
                # Wait between polls without blocking the event loop
                await asyncio.sleep(poll_interval)
                
                # Check job status
                current_job = refinement_jobs_store.get_job(job.job_id)
                if not current_job:
                    raise RefinementBaseException(
                        status_code=500,
                        message=f"Job {job.job_id} disappeared during processing",
                        error_code="JOB_LOST"
                    )
                
                if current_job.status == JobStatus.COMPLETED:
                    vana.logging.info(f"V1 API: Job {job.job_id} completed successfully")
                    response = RefinementResponse(
                        add_refinement_tx_hash=current_job.transaction_hash
                    )
                    return response
                elif current_job.status == JobStatus.FAILED:
                    vana.logging.error(f"V1 API: Job {job.job_id} failed: {current_job.error}")
                    raise RefinementBaseException(
                        status_code=500,
                        message=f"Refinement failed: {current_job.error}",
                        error_code="REFINEMENT_PROCESSING_ERROR"
                    )
                # If still submitted or processing, continue polling
            
            # Timeout reached
            vana.logging.error(f"V1 API: Job {job.job_id} timed out after {max_wait_time} seconds")
            raise RefinementBaseException(
                status_code=504,
                message=f"Refinement timed out after {max_wait_time} seconds",
                error_code="REFINEMENT_TIMEOUT"
            )
        
        finally:
            # Clean up job status if it was created but something went wrong
            if job and job.job_id:
                try:
                    current_job = refinement_jobs_store.get_job(job.job_id)
                    if current_job and current_job.status in [JobStatus.SUBMITTED, JobStatus.PROCESSING]:
                        # Mark job as failed due to API timeout/error
                        refinement_jobs_store.update_job_status(
                            job_id=job.job_id,
                            status=JobStatus.FAILED,
                            error="V1 API cleanup: job abandoned due to timeout or error",
                            completed_at=datetime.now()
                        )
                        vana.logging.info(f"V1 API: Cleaned up abandoned job {job.job_id}")
                except Exception as cleanup_error:
                    vana.logging.error(f"V1 API: Failed to clean up job {job.job_id}: {cleanup_error}")
    
    def _check_api_version(self, request: Request) -> str:
        """Check API version from headers and return appropriate version"""
        # Check for Vana-Accept-Version header
        vana_version = request.headers.get("vana-accept-version", "v1")
        
        # Also check standard Accept-Version header as fallback
        accept_version = request.headers.get("accept-version", "v1")
        
        # Prioritize Vana-Accept-Version
        version = vana_version if vana_version != "v1" else accept_version
        
        return version.lower()

    async def submit_refinement_job(self, request: RefinementRequest) -> RefinementJobResponse:
        """Submit a refinement job for background processing (v2 API)"""
        try:
            # Create job in database
            job = refinement_jobs_store.create_job_from_request(request)
            
            vana.logging.info(f"Created refinement job {job.job_id} for file {request.file_id}")
            
            response = RefinementJobResponse(
                job_id=job.job_id,
                status=job.status,
                message="Refinement job submitted successfully"
            )
            return response
            
        except Exception as e:
            vana.logging.error(f"Failed to create refinement job: {e}")
            raise

    async def get_refinement_job_status(self, job_id: str) -> RefinementJobStatus:
        """Get the status of a refinement job"""
        try:
            job = refinement_jobs_store.get_job(job_id)
            
            if not job:
                from fastapi import HTTPException
                raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
            
            # Calculate processing duration if applicable
            processing_duration_seconds = None
            if job.started_at and job.completed_at:
                processing_duration_seconds = (job.completed_at - job.started_at).total_seconds()
            
            response = RefinementJobStatus(
                job_id=job.job_id,
                status=job.status,
                file_id=job.file_id,
                refiner_id=job.refiner_id,
                error=job.error,
                transaction_hash=job.transaction_hash,
                submitted_at=job.submitted_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
                processing_duration_seconds=processing_duration_seconds
            )
            return response
            
        except Exception as e:
            if "HTTPException" in str(type(e)):
                raise  # Re-raise HTTP exceptions
            vana.logging.error(f"Failed to get job status for {job_id}: {e}")
            raise
    
    async def get_processor_status(self) -> dict:
        """Get the status of the background processor"""
        try:
            processor = get_background_processor()
            if processor:
                return processor.get_status()
            else:
                return {"error": "Background processor not initialized"}
        except Exception as e:
            vana.logging.error(f"Failed to get processor status: {e}")
            return {"error": str(e)}
    
    async def get_refiner_execution_stats(self, refiner_id: int, x_refiner_signature: str = Header(...)) -> RefinerExecutionStatusResponse:
        """
        Get comprehensive execution statistics for a specific refiner.
        
        Access is restricted to:
        1. The owner of the refiner (verified by signature on refiner_id)
        2. Admin wallets from the configured whitelist
        
        The signature should be on the refiner_id as a string.
        
        Args:
            refiner_id: The ID of the refiner to get statistics for
            x_refiner_signature: Signature of the refiner_id as a string
            
        Returns:
            RefinerExecutionStatusResponse with comprehensive statistics
            
        Raises:
            HTTPException: For authentication failures or server errors
        """
        try:
            vana.logging.info(f"Fetching execution stats for refiner {refiner_id}")
            
            # Verify signature and check permissions
            verified_address = verify_refiner_access(refiner_id, x_refiner_signature)
            
            # Get comprehensive execution statistics
            stats_service = get_execution_stats_service()
            status = stats_service.get_refiner_execution_status(refiner_id)
            
            vana.logging.info(f"Successfully retrieved execution stats for refiner {refiner_id}: "
                           f"{status.total_jobs} total jobs, "
                           f"{status.successful_jobs} successful, "
                           f"{status.failed_jobs} failed")
            
            return status
            
        except Exception as e:
            # If it's already an HTTPException, re-raise it
            if hasattr(e, 'status_code'):
                raise
            vana.logging.error(f"Error retrieving execution stats for refiner {refiner_id}: {str(e)}", exc_info=True)
            from fastapi import HTTPException
            raise HTTPException(
                status_code=500, 
                detail=f"Failed to retrieve execution stats for refiner {refiner_id}: {str(e)}"
            )

    def get_health_status(self) -> HealthMetrics:
        """
        Get comprehensive health status for monitoring systems.
        Returns detailed metrics about refinement processing, system resources, and service health.
        """
        try:
            health_service = get_health_service()
            health_metrics = health_service.get_health_status(
                wallet=getattr(self, 'wallet', None),
                config=getattr(self, 'config', None), 
                node_server=getattr(self, 'node_server', None)
            )
            
            return health_metrics
            
        except Exception as e:
            vana.logging.error(f"Error generating health status: {str(e)}")
            # Return a minimal HealthMetrics object for error cases
            from refiner.models.models import HealthStatus, SystemMetrics, RefinementMetrics, RecentActivity, ServiceHealth
            return HealthMetrics(
                status=HealthStatus.UNHEALTHY,
                timestamp=time.time(),
                uptime_seconds=0,
                uptime_hours=0,
                refinement_metrics=RefinementMetrics(),
                recent_activity=RecentActivity(),
                system_metrics=SystemMetrics(
                    cpu_percent=0.0,
                    memory_percent=0.0,
                    memory_available_gb=0.0,
                    disk_percent=0.0,
                    disk_free_gb=0.0,
                    docker_healthy=False,
                    error=f"Failed to generate health status: {str(e)}"
                ),
                service_health=ServiceHealth(
                    docker_healthy=False,
                    node_server_running=False
                )
            )

    async def run(self):
        """
        Initiates and manages the main loop for the refiner on the network.
        """
        self.sync()

        # This loop maintains the refiner's operations until intentionally stopped.
        try:
            while True:
                if self.should_exit:
                    break

                time.sleep(8)
                self.sync()

        # If someone intentionally stops the refiner, it'll safely terminate operations.
        except KeyboardInterrupt:
            if hasattr(self, 'node_server') and self.node_server:
                self.node_server.stop()
                self.node_server.unserve(dlp_uid=self.config.dlpuid, chain_manager=self.chain_manager)
            vana.logging.success("Refiner killed by keyboard interrupt.")
            exit()

        # In case of unforeseen errors, the refiner will log the error and continue operations.
        except Exception as err:
            vana.logging.error("Error during refinement", str(err))
            vana.logging.debug(traceback.print_exception(type(err), err, err.__traceback__))

    def sync(self):
        pass

    def run_in_background_thread(self):
        """
        Starts the refiner's operations in a background thread upon entering the context.
        This method facilitates the use of the refiner in a 'with' statement.
        """
        if not self.is_running:
            vana.logging.debug("Starting refiner in background thread.")
            self.should_exit = False
            self.thread = threading.Thread(target=self.run, daemon=True)
            self.thread.start()
            self.is_running = True
            vana.logging.debug("Started")

    def stop_run_thread(self):
        """
        Stops the refiner's operations that are running in the background thread.
        """
        if self.is_running:
            vana.logging.debug("Stopping refiner in background thread.")
            # Stop background processor
            stop_background_processor()
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            vana.logging.debug("Stopped")

    def __enter__(self):
        self.run_in_background_thread()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Stops the validator's background operations upon exiting the context.
        This method facilitates the use of the validator in a 'with' statement.

        Args:
            exc_type: The type of the exception that caused the context to be exited.
                      None if the context was exited without an exception.
            exc_value: The instance of the exception that caused the context to be exited.
                       None if the context was exited without an exception.
            traceback: A traceback object encoding the stack trace.
                       None if the context was exited without an exception.
        """
        if self.is_running:
            vana.logging.debug("Stopping validator in background thread.")
            # Stop background processor
            stop_background_processor()
            self.should_exit = True
            self.thread.join(5)
            self.is_running = False
            vana.logging.debug("Stopped")


# poetry run python -m app
if __name__ == "__main__":
    # vana.trace()
    try:
        while True:
            try:
                refiner = Refiner()
                asyncio.run(refiner.run())
            except Exception as e:
                vana.logging.error(f"An error occurred: {str(e)}")
                vana.logging.error(traceback.format_exc())
                vana.logging.error("Restarting the refiner in 5 seconds...")
                time.sleep(5)
    finally:
        vana.logging.info("Refiner stopped.")
        sys.exit(0)
