import json
import uuid
from typing import Dict, List, Optional
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text

from refiner.stores import db
from refiner.models.models import RefinementRequest, JobStatus, RefinementJob

logger = logging.getLogger(__name__)

def _job_orm_to_model(orm_job: db.RefinementJobORM) -> RefinementJob:
    """Convert an ORM job object to a RefinementJob model"""
    env_vars = {}
    if orm_job.env_vars:
        try:
            env_vars = json.loads(orm_job.env_vars)
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding stored env_vars for job ID '{orm_job.job_id}': {e}")

    return RefinementJob(
        job_id=orm_job.job_id,
        file_id=orm_job.file_id,
        refiner_id=orm_job.refiner_id,
        encryption_key=orm_job.encryption_key,
        env_vars=env_vars,
        status=orm_job.status,
        error=orm_job.error,
        transaction_hash=orm_job.transaction_hash,
        docker_container_name=orm_job.docker_container_name,
        docker_exit_code=orm_job.docker_exit_code,
        docker_logs=orm_job.docker_logs,
        submitted_at=orm_job.submitted_at,
        started_at=orm_job.started_at,
        completed_at=orm_job.completed_at
    )

def _job_to_orm_dict(job: RefinementJob) -> Dict:
    """Convert a RefinementJob model to a dictionary for ORM operations"""
    # Use Pydantic's model_dump for better serialization
    job_dict = job.model_dump()
    
    # Handle env_vars JSON serialization
    if job_dict["env_vars"]:
        try:
            job_dict["env_vars"] = json.dumps(job_dict["env_vars"])
        except TypeError as e:
            logger.error(f"Error encoding env_vars for job ID '{job.job_id}': {e}")
            job_dict["env_vars"] = None
    else:
        job_dict["env_vars"] = None

    return job_dict

@db.session_scope
def create_job_from_request(session: Session, request: RefinementRequest) -> RefinementJob:
    """
    Create a new refinement job from a request
    
    Args:
        session: SQLAlchemy session
        request: The refinement request
        
    Returns:
        RefinementJob: The created job
    """
    job_id = str(uuid.uuid4())
    
    job = RefinementJob(
        job_id=job_id,
        file_id=request.file_id,
        refiner_id=request.refiner_id,
        encryption_key=request.encryption_key,
        env_vars=request.env_vars,
        status=JobStatus.SUBMITTED
    )
    
    try:
        orm_dict = _job_to_orm_dict(job)
        new_job = db.RefinementJobORM(**orm_dict)
        session.add(new_job)
        session.flush()  # Flush to get the ID without committing
        
        logger.info(f"Created new refinement job {job_id} for file {request.file_id}")
        return job
    except Exception as e:
        logger.error(f"Error creating refinement job: {e}")
        raise

@db.session_scope
def get_job(session: Session, job_id: str) -> Optional[RefinementJob]:
    """
    Get a refinement job by ID
    
    Args:
        session: SQLAlchemy session
        job_id: ID of the job
        
    Returns:
        Optional[RefinementJob]: The job if found, None otherwise
    """
    try:
        job_orm = session.query(db.RefinementJobORM).filter(db.RefinementJobORM.job_id == job_id).first()
        
        if not job_orm:
            return None
        
        return _job_orm_to_model(job_orm)
    except Exception as e:
        logger.error(f"Error retrieving job {job_id}: {e}")
        return None

@db.session_scope
def update_job_status(session: Session, job_id: str, status: str, error: str = None, 
                      started_at: datetime = None, completed_at: datetime = None) -> bool:
    """
    Update the status of a refinement job
    
    Args:
        session: SQLAlchemy session
        job_id: ID of the job
        status: New status
        error: Optional error message
        started_at: Optional start time
        completed_at: Optional completion time
        
    Returns:
        bool: True if the job was updated, False if it wasn't found
    """
    try:
        job = session.query(db.RefinementJobORM).filter(db.RefinementJobORM.job_id == job_id).first()
        
        if not job:
            return False
        
        update_values = {"status": status}
        if error is not None:
            update_values["error"] = error
        if started_at is not None:
            update_values["started_at"] = started_at
        if completed_at is not None:
            update_values["completed_at"] = completed_at
            
        session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.job_id == job_id
        ).update(
            update_values,
            synchronize_session='fetch'
        )
        
        logger.debug(f"Updated job {job_id} status to {status}")
        return True
    except Exception as e:
        logger.error(f"Error updating job {job_id} status: {e}")
        return False

@db.session_scope
def update_job_docker_info(session: Session, job_id: str, container_name: str = None, 
                          exit_code: int = None, logs: str = None) -> bool:
    """
    Update Docker execution information for a job
    
    Args:
        session: SQLAlchemy session
        job_id: ID of the job
        container_name: Docker container name
        exit_code: Container exit code
        logs: Container logs
        
    Returns:
        bool: True if the job was updated, False if it wasn't found
    """
    try:
        job = session.query(db.RefinementJobORM).filter(db.RefinementJobORM.job_id == job_id).first()
        
        if not job:
            return False
        
        update_values = {}
        if container_name is not None:
            update_values["docker_container_name"] = container_name
        if exit_code is not None:
            update_values["docker_exit_code"] = exit_code
        if logs is not None:
            update_values["docker_logs"] = logs
            
        if update_values:
            session.query(db.RefinementJobORM).filter(
                db.RefinementJobORM.job_id == job_id
            ).update(
                update_values,
                synchronize_session='fetch'
            )
            
        logger.debug(f"Updated job {job_id} Docker info")
        return True
    except Exception as e:
        logger.error(f"Error updating job {job_id} Docker info: {e}")
        return False

@db.session_scope
def update_job_result(session: Session, job_id: str, transaction_hash: str) -> bool:
    """
    Update the transaction hash result for a job
    
    Args:
        session: SQLAlchemy session
        job_id: ID of the job
        transaction_hash: Transaction hash from blockchain
        
    Returns:
        bool: True if the job was updated, False if it wasn't found
    """
    try:
        job = session.query(db.RefinementJobORM).filter(db.RefinementJobORM.job_id == job_id).first()
        
        if not job:
            return False
        
        session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.job_id == job_id
        ).update(
            {"transaction_hash": transaction_hash},
            synchronize_session='fetch'
        )
        
        logger.debug(f"Updated job {job_id} transaction hash")
        return True
    except Exception as e:
        logger.error(f"Error updating job {job_id} transaction hash: {e}")
        return False

@db.session_scope
def get_pending_jobs(session: Session, limit: int = 10) -> List[RefinementJob]:
    """
    Get pending jobs (submitted status) for processing
    
    Args:
        session: SQLAlchemy session
        limit: Maximum number of jobs to return
        
    Returns:
        List[RefinementJob]: List of pending jobs
    """
    try:
        orm_jobs = session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.status == JobStatus.SUBMITTED
        ).order_by(
            db.RefinementJobORM.submitted_at.asc()
        ).limit(limit).all()
        
        return [_job_orm_to_model(job) for job in orm_jobs]
    except Exception as e:
        logger.error(f"Error retrieving pending jobs: {e}")
        return []

@db.session_scope
def get_jobs_by_status(session: Session, status: str, limit: int = 100) -> List[RefinementJob]:
    """
    Get jobs by status
    
    Args:
        session: SQLAlchemy session
        status: Job status to filter by
        limit: Maximum number of jobs to return
        
    Returns:
        List[RefinementJob]: List of jobs with the specified status
    """
    try:
        orm_jobs = session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.status == status
        ).order_by(
            db.RefinementJobORM.submitted_at.desc()
        ).limit(limit).all()
        
        return [_job_orm_to_model(job) for job in orm_jobs]
    except Exception as e:
        logger.error(f"Error retrieving jobs by status {status}: {e}")
        return []

@db.session_scope
def claim_pending_jobs(session: Session, limit: int = 10) -> List[RefinementJob]:
    """
    Atomically claim pending jobs for processing by updating their status to PROCESSING.
    This prevents race conditions where multiple workers try to process the same job.
    
    Args:
        session: SQLAlchemy session
        limit: Maximum number of jobs to claim
        
    Returns:
        List[RefinementJob]: List of claimed jobs
    """
    try:
        from datetime import datetime
        
        # Use a raw SQL update with WHERE clause to atomically claim jobs
        # This ensures only one worker can claim each job
        result = session.execute(
            text("""
            UPDATE refinement_jobs 
            SET status = :processing_status, started_at = :started_at
            WHERE job_id IN (
                SELECT job_id FROM refinement_jobs 
                WHERE status = :submitted_status 
                ORDER BY submitted_at ASC 
                LIMIT :limit
            )
            """),
            {
                "processing_status": JobStatus.PROCESSING,
                "submitted_status": JobStatus.SUBMITTED,
                "started_at": datetime.now(),
                "limit": limit
            }
        )
        
        # Commit the claim operation immediately
        session.commit()
        
        # Now fetch the claimed jobs
        if result.rowcount > 0:
            claimed_jobs = session.query(db.RefinementJobORM).filter(
                db.RefinementJobORM.status == JobStatus.PROCESSING,
                db.RefinementJobORM.started_at >= datetime.now().replace(microsecond=0)
            ).order_by(
                db.RefinementJobORM.started_at.desc()
            ).limit(limit).all()
            
            logger.info(f"Successfully claimed {len(claimed_jobs)} jobs for processing")
            return [_job_orm_to_model(job) for job in claimed_jobs]
        else:
            logger.debug("No pending jobs available to claim")
            return []
            
    except Exception as e:
        logger.error(f"Error claiming pending jobs: {e}")
        session.rollback()
        return []

@db.session_scope
def cleanup_orphaned_jobs(session: Session, timeout_minutes: int = 60) -> int:
    """
    Clean up jobs that have been stuck in PROCESSING state for too long.
    This handles cases where jobs were claimed but the worker died or crashed.
    
    Args:
        session: SQLAlchemy session
        timeout_minutes: Jobs older than this in PROCESSING state will be reset to SUBMITTED
        
    Returns:
        int: Number of jobs cleaned up
    """
    try:
        from datetime import datetime, timedelta
        
        # Calculate the cutoff time
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        
        # Find jobs that have been in PROCESSING state for too long
        orphaned_jobs = session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.status == JobStatus.PROCESSING,
            db.RefinementJobORM.started_at < cutoff_time
        ).all()
        
        if not orphaned_jobs:
            return 0
        
        # Reset these jobs back to SUBMITTED status
        job_ids = [job.job_id for job in orphaned_jobs]
        
        session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.job_id.in_(job_ids)
        ).update(
            {
                "status": JobStatus.SUBMITTED,
                "started_at": None,
                "error": f"Reset from orphaned PROCESSING state after {timeout_minutes} minutes"
            },
            synchronize_session='fetch'
        )
        
        logger.info(f"Cleaned up {len(orphaned_jobs)} orphaned jobs that were stuck in PROCESSING state")
        return len(orphaned_jobs)
        
    except Exception as e:
        logger.error(f"Error cleaning up orphaned jobs: {e}")
        session.rollback()
        return 0

@db.session_scope
def get_refiner_job_stats(session: Session, refiner_id: int) -> Dict:
    """
    Get comprehensive job statistics for a specific refiner.
    
    Args:
        session: SQLAlchemy session
        refiner_id: ID of the refiner to get stats for
        
    Returns:
        Dict: Dictionary containing comprehensive statistics
    """
    try:
        from datetime import datetime, timedelta
        from collections import Counter
        
        # Get all jobs for this refiner
        all_jobs = session.query(db.RefinementJobORM).filter(
            db.RefinementJobORM.refiner_id == refiner_id
        ).all()
        
        if not all_jobs:
            return {
                "total_jobs": 0,
                "successful_jobs": 0,
                "failed_jobs": 0,
                "processing_jobs": 0,
                "submitted_jobs": 0,
                "first_job_at": None,
                "last_job_at": None,
                "average_processing_time_seconds": 0.0,
                "success_rate": 0.0,
                "jobs_per_hour": 0.0,
                "processing_period_days": None,
                "error_types": {},
                "recent_errors": []
            }
        
        # Count jobs by status
        status_counts = Counter(job.status for job in all_jobs)
        total_jobs = len(all_jobs)
        successful_jobs = status_counts.get(JobStatus.COMPLETED, 0)
        failed_jobs = status_counts.get(JobStatus.FAILED, 0)
        processing_jobs = status_counts.get(JobStatus.PROCESSING, 0)
        submitted_jobs = status_counts.get(JobStatus.SUBMITTED, 0)
        
        # Calculate success rate
        success_rate = successful_jobs / total_jobs if total_jobs > 0 else 0.0
        
        # Get time range
        timestamps = [job.submitted_at for job in all_jobs if job.submitted_at]
        first_job_at = min(timestamps) if timestamps else None
        last_job_at = max(timestamps) if timestamps else None
        
        # Calculate processing period
        processing_period_days = None
        if first_job_at and last_job_at:
            processing_period_days = (last_job_at - first_job_at).total_seconds() / (24 * 3600)
        
        # Calculate jobs per hour
        jobs_per_hour = 0.0
        if processing_period_days and processing_period_days > 0:
            jobs_per_hour = total_jobs / (processing_period_days * 24)
        
        # Calculate average processing time
        completed_jobs = [job for job in all_jobs if job.status == JobStatus.COMPLETED and job.started_at and job.completed_at]
        average_processing_time_seconds = 0.0
        if completed_jobs:
            processing_times = [(job.completed_at - job.started_at).total_seconds() for job in completed_jobs]
            average_processing_time_seconds = sum(processing_times) / len(processing_times)
        
        # Get error types (top 10)
        failed_jobs_with_errors = [job for job in all_jobs if job.status == JobStatus.FAILED and job.error]
        error_types = {}
        if failed_jobs_with_errors:
            # Extract error types from error messages based on actual error codes used in the codebase
            error_type_counts = Counter()
            for job in failed_jobs_with_errors:
                error_msg = job.error or ""
                # Check for specific error codes that are actually used in the refinement service
                if "FILE_DOWNLOAD_FAILED" in error_msg or "FILE_DOWNLOAD_ERROR" in error_msg:
                    error_type_counts["FILE_DOWNLOAD_FAILED"] += 1
                elif "FILE_DECRYPTION_FAILED" in error_msg or "FILE_DECRYPTION_ERROR" in error_msg:
                    error_type_counts["FILE_DECRYPTION_FAILED"] += 1
                elif "CONTAINER_EXECUTION_ERROR" in error_msg or "REFINER_CONTAINER_FAILED" in error_msg:
                    error_type_counts["CONTAINER_EXECUTION_ERROR"] += 1
                elif "CONTAINER_TIMEOUT_ERROR" in error_msg:
                    error_type_counts["CONTAINER_TIMEOUT_ERROR"] += 1
                elif "REFINEMENT_PROCESSING_ERROR" in error_msg:
                    error_type_counts["REFINEMENT_PROCESSING_ERROR"] += 1
                elif "REFINEMENT_TIMEOUT" in error_msg:
                    error_type_counts["REFINEMENT_TIMEOUT"] += 1
                elif "REFINER_NOT_FOUND" in error_msg:
                    error_type_counts["REFINER_NOT_FOUND"] += 1
                elif "FILE_NOT_FOUND" in error_msg:
                    error_type_counts["FILE_NOT_FOUND"] += 1
                elif "JOB_LOST" in error_msg:
                    error_type_counts["JOB_LOST"] += 1
                elif "REFINER_CONTAINER_NO_OUTPUT" in error_msg:
                    error_type_counts["REFINER_CONTAINER_NO_OUTPUT"] += 1
                elif "REFINEMENT_URL_INVALID" in error_msg or "REFINEMENT_URL_VALIDATION_ERROR" in error_msg:
                    error_type_counts["REFINEMENT_URL_ERROR"] += 1
                elif "IPFS_UPLOAD_ERROR" in error_msg:
                    error_type_counts["IPFS_UPLOAD_ERROR"] += 1
                elif "CRYPTOGRAPHY_ERROR" in error_msg:
                    error_type_counts["CRYPTOGRAPHY_ERROR"] += 1
                elif "INVALID_PERMISSION" in error_msg:
                    error_type_counts["INVALID_PERMISSION"] += 1
                else:
                    error_type_counts["OTHER_ERROR"] += 1
            
            # Get top 10 error types
            error_types = dict(error_type_counts.most_common(10))
        
        # Get recent errors (last 10 failed jobs)
        recent_failed_jobs = [job for job in all_jobs if job.status == JobStatus.FAILED and job.error]
        recent_failed_jobs.sort(key=lambda x: x.completed_at or x.submitted_at, reverse=True)
        recent_errors = []
        for job in recent_failed_jobs[:10]:
            recent_errors.append({
                "job_id": job.job_id,
                "error": job.error[:200] + "..." if len(job.error) > 200 else job.error,  # Truncate long errors
                "timestamp": (job.completed_at or job.submitted_at).isoformat()
            })
        
        return {
            "total_jobs": total_jobs,
            "successful_jobs": successful_jobs,
            "failed_jobs": failed_jobs,
            "processing_jobs": processing_jobs,
            "submitted_jobs": submitted_jobs,
            "first_job_at": first_job_at,
            "last_job_at": last_job_at,
            "average_processing_time_seconds": average_processing_time_seconds,
            "success_rate": success_rate,
            "jobs_per_hour": jobs_per_hour,
            "processing_period_days": processing_period_days,
            "error_types": error_types,
            "recent_errors": recent_errors
        }
        
    except Exception as e:
        logger.error(f"Error getting refiner job stats for refiner {refiner_id}: {e}")
        return {
            "total_jobs": 0,
            "successful_jobs": 0,
            "failed_jobs": 0,
            "processing_jobs": 0,
            "submitted_jobs": 0,
            "first_job_at": None,
            "last_job_at": None,
            "average_processing_time_seconds": 0.0,
            "success_rate": 0.0,
            "jobs_per_hour": 0.0,
            "processing_period_days": None,
            "error_types": {},
            "recent_errors": []
        } 