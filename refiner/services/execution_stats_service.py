import logging
from datetime import datetime
from typing import Dict, Any

from refiner.stores import refinement_jobs_store
from refiner.models.models import RefinerExecutionStatusResponse

logger = logging.getLogger(__name__)


class ExecutionStatsService:
    """Service for generating refinement execution statistics"""
    
    def __init__(self):
        logger.info("Execution stats service initialized")
    
    def get_refiner_execution_status(self, refiner_id: int) -> RefinerExecutionStatusResponse:
        """
        Get comprehensive execution statistics for a specific refiner.
        
        Args:
            refiner_id: The ID of the refiner
            
        Returns:
            RefinerExecutionStatusResponse with all statistics
        """
        try:
            logger.info(f"Generating execution statistics for refiner {refiner_id}")
            
            # Get raw statistics from the store
            stats = refinement_jobs_store.get_refiner_job_stats(refiner_id)
            
            # Transform the raw stats into the response model
            response = RefinerExecutionStatusResponse(
                refiner_id=refiner_id,
                total_jobs=stats["total_jobs"],
                successful_jobs=stats["successful_jobs"],
                failed_jobs=stats["failed_jobs"],
                processing_jobs=stats["processing_jobs"],
                submitted_jobs=stats["submitted_jobs"],
                first_job_at=stats["first_job_at"],
                last_job_at=stats["last_job_at"],
                average_processing_time_seconds=stats["average_processing_time_seconds"],
                success_rate=stats["success_rate"],
                jobs_per_hour=stats["jobs_per_hour"],
                processing_period_days=stats["processing_period_days"],
                error_types=stats["error_types"],
                recent_errors=stats["recent_errors"]
            )
            
            logger.info(f"Generated execution statistics for refiner {refiner_id}: "
                       f"{response.total_jobs} total jobs, "
                       f"{response.successful_jobs} successful, "
                       f"{response.failed_jobs} failed, "
                       f"{response.success_rate:.2%} success rate")
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating execution statistics for refiner {refiner_id}: {e}", exc_info=True)
            # Return a minimal response with error state
            return RefinerExecutionStatusResponse(
                refiner_id=refiner_id,
                total_jobs=0,
                successful_jobs=0,
                failed_jobs=0,
                processing_jobs=0,
                submitted_jobs=0,
                first_job_at=None,
                last_job_at=None,
                average_processing_time_seconds=0.0,
                success_rate=0.0,
                jobs_per_hour=0.0,
                processing_period_days=None,
                error_types={},
                recent_errors=[]
            )


# Global instance for the service
_execution_stats_service = ExecutionStatsService()


def get_execution_stats_service() -> ExecutionStatsService:
    """Get the global execution stats service instance"""
    return _execution_stats_service 