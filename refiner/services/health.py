import time
import threading
import psutil
import os
from collections import deque
from typing import Dict, Any, Optional, Tuple

import vana

from refiner.models.models import (
    HealthMetrics, HealthStatus, SystemMetrics, RefinementMetrics, 
    RecentActivity, ServiceHealth
)


class HealthService:
    """
    Thread-safe health tracking service for the refiner that monitors:
    - Refinement success/failure rates
    - System resource usage
    - Recent error patterns
    - Docker service health
    - Service component status
    """
    
    def __init__(self, max_recent_events: int = 100):
        """
        Initialize the health service with thread-safe data structures.
        
        Args:
            max_recent_events: Maximum number of recent events to track
        """
        # Thread safety lock - all operations on shared state must use this lock
        self._lock = threading.RLock()  # Use RLock to allow recursive locking
        
        # Service metadata
        self._start_time = time.time()
        self._max_recent_events = max_recent_events
        
        # Refinement counters (protected by lock)
        self._total_refinements = 0
        self._successful_refinements = 0
        self._failed_refinements = 0
        
        # Recent events tracking: (timestamp, success/failure, processing_time)
        self._recent_events = deque(maxlen=max_recent_events)
        
        # Timestamps for last events (protected by lock)
        self._last_successful_refinement: Optional[float] = None
        self._last_failed_refinement: Optional[float] = None
        
        # Processing times for average calculation (protected by lock)
        self._processing_times = deque(maxlen=50)
        
        vana.logging.info("Health service initialized with thread-safe tracking")
        
    def record_refinement_start(self) -> float:
        """
        Record the start of a refinement operation.
        
        Returns:
            float: Start timestamp for tracking processing time
        """
        return time.time()
        
    def record_refinement_success(self, start_time: float) -> None:
        """
        Thread-safely record a successful refinement.
        
        Args:
            start_time: The timestamp when refinement started
        """
        end_time = time.time()
        processing_time = end_time - start_time
        
        with self._lock:
            self._total_refinements += 1
            self._successful_refinements += 1
            self._last_successful_refinement = end_time
            self._recent_events.append((end_time, True, processing_time))
            self._processing_times.append(processing_time)
            
        vana.logging.debug(f"Recorded successful refinement (processing time: {processing_time:.2f}s)")
            
    def record_refinement_failure(self, start_time: float, error_type: str = "unknown") -> None:
        """
        Thread-safely record a failed refinement.
        
        Args:
            start_time: The timestamp when refinement started
            error_type: Type of error that occurred
        """
        end_time = time.time()
        processing_time = end_time - start_time
        
        with self._lock:
            self._total_refinements += 1
            self._failed_refinements += 1
            self._last_failed_refinement = end_time
            self._recent_events.append((end_time, False, processing_time))
            
        vana.logging.debug(f"Recorded failed refinement: {error_type} (processing time: {processing_time:.2f}s)")
            
    def _get_system_metrics(self) -> SystemMetrics:
        """
        Get current system metrics safely.
        
        Returns:
            SystemMetrics: Current system resource usage and health status
        """
        try:
            # CPU and Memory metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Docker health check
            docker_healthy = self._check_docker_health()
            
            # Load average (Unix systems only)
            load_avg = None
            if hasattr(os, 'getloadavg'):
                try:
                    load_avg = list(os.getloadavg())
                except OSError:
                    load_avg = None
            
            return SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_available_gb=round(memory.available / (1024**3), 2),
                disk_percent=disk.percent,
                disk_free_gb=round(disk.free / (1024**3), 2),
                load_average=load_avg,
                docker_healthy=docker_healthy
            )
            
        except Exception as e:
            vana.logging.error(f"Failed to collect system metrics: {e}")
            return SystemMetrics(
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_available_gb=0.0,
                disk_percent=0.0,
                disk_free_gb=0.0,
                load_average=None,
                docker_healthy=False,
                error=f"Failed to collect system metrics: {str(e)}"
            )
            
    def _check_docker_health(self) -> bool:
        """
        Check if Docker daemon is accessible and healthy.
        
        Returns:
            bool: True if Docker is accessible, False otherwise
        """
        try:
            import docker
            client = docker.from_env()
            client.ping()
            return True
        except Exception as e:
            vana.logging.debug(f"Docker health check failed: {e}")
            return False
            
    def _calculate_recent_stats(self, hours: int = 1) -> Tuple[int, int]:
        """
        Thread-safely calculate recent success/failure counts.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Tuple[int, int]: (recent_successes, recent_failures)
        """
        current_time = time.time()
        cutoff_time = current_time - (hours * 3600)
        
        recent_successes = 0
        recent_failures = 0
        
        with self._lock:
            for timestamp, success, _ in self._recent_events:
                if timestamp >= cutoff_time:
                    if success:
                        recent_successes += 1
                    else:
                        recent_failures += 1
                        
        return recent_successes, recent_failures
        
    def _determine_health_status(
        self, 
        system_metrics: SystemMetrics,
        refinement_metrics: RefinementMetrics,
        recent_activity: RecentActivity
    ) -> HealthStatus:
        """
        Determine overall health status based on various metrics.
        
        Args:
            system_metrics: Current system resource metrics
            refinement_metrics: Refinement processing metrics
            recent_activity: Recent activity metrics
            
        Returns:
            HealthStatus: Overall health status
        """
        current_time = time.time()
        
        # Check for critical system issues
        if not system_metrics.docker_healthy:
            vana.logging.warning("Health status: UNHEALTHY - Docker not healthy")
            return HealthStatus.UNHEALTHY
            
        # Check system resources for critical levels
        if (system_metrics.cpu_percent > 95 or 
            system_metrics.memory_percent > 95 or 
            system_metrics.disk_percent > 95):
            vana.logging.warning("Health status: UNHEALTHY - Critical resource usage")
            return HealthStatus.UNHEALTHY
            
        # Check recent error rate
        if (refinement_metrics.total_refinements > 50 and 
            refinement_metrics.success_rate < 0.2):
            vana.logging.warning("Health status: UNHEALTHY - High error rate")
            return HealthStatus.UNHEALTHY
            
        # Check success rate for services that have processed refinements
        if (refinement_metrics.total_refinements > 20 and 
            refinement_metrics.success_rate < 0.5):
            vana.logging.warning("Health status: DEGRADED - Low success rate")
            return HealthStatus.DEGRADED
            
        # Check for high resource usage (degraded performance)
        if (system_metrics.cpu_percent > 80 or 
            system_metrics.memory_percent > 80 or 
            system_metrics.disk_percent > 80):
            vana.logging.info("Health status: DEGRADED - High resource usage")
            return HealthStatus.DEGRADED
            
        return HealthStatus.HEALTHY
        
    def get_health_status(self, wallet=None, config=None, node_server=None) -> HealthMetrics:
        """
        Get comprehensive health status with thread-safe data access.
        
        Args:
            wallet: Optional wallet instance for service health
            config: Optional config instance for service health  
            node_server: Optional node server instance for service health
            
        Returns:
            HealthMetrics: Complete health metrics
        """
        current_time = time.time()
        
        # Safely collect refinement metrics
        with self._lock:
            # Calculate success rate
            success_rate = (
                self._successful_refinements / self._total_refinements 
                if self._total_refinements > 0 else 0.0
            )
            
            # Calculate average processing time
            avg_processing_time = (
                sum(self._processing_times) / len(self._processing_times)
                if self._processing_times else 0.0
            )
            
            # Create refinement metrics
            refinement_metrics = RefinementMetrics(
                total_refinements=self._total_refinements,
                successful_refinements=self._successful_refinements,
                failed_refinements=self._failed_refinements,
                success_rate=round(success_rate, 3),
                last_successful_refinement=self._last_successful_refinement,
                last_failed_refinement=self._last_failed_refinement,
                avg_processing_time_seconds=round(avg_processing_time, 2)
            )
            
            # Add time since last activity
            if self._last_successful_refinement:
                refinement_metrics.seconds_since_last_success = int(
                    current_time - self._last_successful_refinement
                )
            if self._last_failed_refinement:
                refinement_metrics.seconds_since_last_failure = int(
                    current_time - self._last_failed_refinement
                )
        
        # Get recent stats
        recent_successes, recent_failures = self._calculate_recent_stats(1)
        recent_activity = RecentActivity(
            errors_in_last_hour=recent_failures,
            successes_in_last_hour=recent_successes
        )
        
        # Get system metrics
        system_metrics = self._get_system_metrics()
        
        # Create service health metrics
        service_health = ServiceHealth(
            docker_healthy=system_metrics.docker_healthy,
            wallet_address=wallet.hotkey.address if wallet and hasattr(wallet, 'hotkey') else None,
            chain_endpoint=config.chain.chain_endpoint if config and hasattr(config, 'chain') else None,
            node_server_running=node_server is not None
        )
        
        # Determine overall health status
        health_status = self._determine_health_status(
            system_metrics, refinement_metrics, recent_activity
        )
        
        # Calculate uptime
        uptime_seconds = current_time - self._start_time
        uptime_hours = round(uptime_seconds / 3600, 2)
        
        return HealthMetrics(
            status=health_status,
            timestamp=current_time,
            uptime_seconds=uptime_seconds,
            uptime_hours=uptime_hours,
            refinement_metrics=refinement_metrics,
            recent_activity=recent_activity,
            system_metrics=system_metrics,
            service_health=service_health
        )


# Global health service instance with thread-safe singleton pattern
_health_service_lock = threading.Lock()
_health_service: Optional[HealthService] = None


def get_health_service() -> HealthService:
    """
    Get the global thread-safe health service instance (singleton pattern).
    
    Returns:
        HealthService: The global health service instance
    """
    global _health_service
    
    # Double-checked locking pattern for thread-safe singleton
    if _health_service is None:
        with _health_service_lock:
            if _health_service is None:
                _health_service = HealthService()
                vana.logging.info("Global health service instance created")
    
    return _health_service 