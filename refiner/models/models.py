from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field, field_validator
from enum import Enum

# Job status enums
class JobStatus:
    SUBMITTED = "submitted"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class RefinementJob(BaseModel):
    """Pydantic model for refinement jobs"""
    job_id: str = Field(..., description="Unique job identifier")
    file_id: int = Field(..., description="File ID being refined") 
    refiner_id: int = Field(..., description="Refiner ID to use")
    encryption_key: str = Field(..., description="Encryption key for the file")
    env_vars: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    status: str = Field(default=JobStatus.SUBMITTED, description="Current job status")
    error: Optional[str] = Field(None, description="Error message if failed")
    transaction_hash: Optional[str] = Field(None, description="Blockchain transaction hash when completed")
    docker_container_name: Optional[str] = Field(None, description="Docker container name used")
    docker_exit_code: Optional[int] = Field(None, description="Docker container exit code")
    docker_logs: Optional[str] = Field(None, description="Docker container logs")
    submitted_at: datetime = Field(default_factory=datetime.now, description="When job was submitted")
    started_at: Optional[datetime] = Field(None, description="When job processing started")
    completed_at: Optional[datetime] = Field(None, description="When job processing completed")
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        """Validate that status is one of the allowed values"""
        valid_statuses = {JobStatus.SUBMITTED, JobStatus.PROCESSING, JobStatus.COMPLETED, JobStatus.FAILED}
        if v not in valid_statuses:
            raise ValueError(f"Status must be one of: {', '.join(valid_statuses)}")
        return v


class RefinementRequest(BaseModel):
    file_id: int = Field(..., description="File ID of the file in the Data Registry to be refined")
    encryption_key: str = Field(...,
                                description="Symmetric encryption key for the file so it can be decrypted and refined")
    refiner_id: int = Field(...,
                            description="Refiner ID in the Data Refiner Registry containing the instructions for refinement")
    env_vars: dict = Field(...,
                          description="Environment variables to inject into the refinement docker container")

class RefinementResponse(BaseModel):
    add_refinement_tx_hash: str = Field(...,
                                        description="Transaction hash for the refinement being added to the Data Registry")

# New async response models
class RefinementJobResponse(BaseModel):
    job_id: str = Field(..., description="Unique job ID for tracking the refinement")
    status: str = Field(..., description="Current status of the job")
    message: str = Field(default="Refinement job submitted successfully")

class RefinementJobStatus(BaseModel):
    job_id: str = Field(..., description="Unique job ID")
    status: str = Field(..., description="Current status: submitted, processing, completed, failed")
    file_id: int = Field(..., description="File ID being refined")
    refiner_id: int = Field(..., description="Refiner ID used")
    error: Optional[str] = Field(None, description="Error message if job failed")
    transaction_hash: Optional[str] = Field(None, description="Transaction hash if completed successfully")
    submitted_at: datetime = Field(..., description="When the job was submitted")
    started_at: Optional[datetime] = Field(None, description="When processing started")
    completed_at: Optional[datetime] = Field(None, description="When processing completed")
    processing_duration_seconds: Optional[float] = Field(None, description="How long processing took")

class OffChainSchema(BaseModel):
    name: str
    version: str
    description: str
    dialect: str
    schema_definition: str
    
class Output(BaseModel):
    refinement_url: Optional[str] = None
    schema_info: Optional[OffChainSchema] = None
    
class DockerRun(BaseModel):
    container_name: str
    exit_code: Optional[int] = None
    logs: str = ""
    started_at: datetime
    terminated_at: Optional[datetime] = None
    output_data: Optional[Output] = None


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class SystemMetrics(BaseModel):
    cpu_percent: float = Field(..., description="CPU usage percentage")
    memory_percent: float = Field(..., description="Memory usage percentage")
    memory_available_gb: float = Field(..., description="Available memory in GB")
    disk_percent: float = Field(..., description="Disk usage percentage")
    disk_free_gb: float = Field(..., description="Free disk space in GB")
    load_average: Optional[List[float]] = Field(None, description="System load average")
    docker_healthy: bool = Field(..., description="Docker daemon health status")
    error: Optional[str] = Field(None, description="Error message if metrics collection failed")


class RefinementMetrics(BaseModel):
    total_refinements: int = Field(0, description="Total number of refinement attempts")
    successful_refinements: int = Field(0, description="Number of successful refinements")
    failed_refinements: int = Field(0, description="Number of failed refinements")
    success_rate: float = Field(0.0, description="Success rate as a decimal (0.0 to 1.0)")
    last_successful_refinement: Optional[float] = Field(None, description="Timestamp of last successful refinement")
    last_failed_refinement: Optional[float] = Field(None, description="Timestamp of last failed refinement")
    avg_processing_time_seconds: float = Field(0.0, description="Average processing time in seconds")
    seconds_since_last_success: Optional[int] = Field(None, description="Seconds since last successful refinement")
    seconds_since_last_failure: Optional[int] = Field(None, description="Seconds since last failed refinement")


class RecentActivity(BaseModel):
    errors_in_last_hour: int = Field(0, description="Number of errors in the last hour")
    successes_in_last_hour: int = Field(0, description="Number of successes in the last hour")


class ServiceHealth(BaseModel):
    docker_healthy: bool = Field(..., description="Docker service health status")
    wallet_address: Optional[str] = Field(None, description="Wallet address if available")
    chain_endpoint: Optional[str] = Field(None, description="Blockchain endpoint if available")
    node_server_running: bool = Field(..., description="Node server running status")


class HealthMetrics(BaseModel):
    status: HealthStatus = Field(..., description="Overall health status")
    timestamp: float = Field(..., description="Timestamp when metrics were collected")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")
    uptime_hours: float = Field(..., description="Service uptime in hours")
    refinement_metrics: RefinementMetrics = Field(..., description="Refinement processing metrics")
    recent_activity: RecentActivity = Field(..., description="Recent activity metrics")
    system_metrics: SystemMetrics = Field(..., description="System resource metrics")
    service_health: ServiceHealth = Field(..., description="Service health indicators")


