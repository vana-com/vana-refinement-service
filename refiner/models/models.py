from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from enum import Enum


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

class OffChainSchema(BaseModel):
    name: str
    version: str
    description: str
    dialect: str
    schema: str
    
class Output(BaseModel):
    refinement_url: Optional[str] = None
    schema: Optional[OffChainSchema] = None
    
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


