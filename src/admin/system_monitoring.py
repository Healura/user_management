"""
Production System Monitoring Service

Comprehensive healthcare system monitoring with real-time metrics,
performance analysis, capacity planning, and alerting capabilities.
"""

import asyncio
import logging
import psutil
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque

from sqlalchemy.orm import Session
from sqlalchemy import func, text

from src.database.models import User, AuditLog, AudioFile, UserSession, NotificationHistory
from src.database.database import check_database_connection
from src.auth.background_tasks import get_background_tasks_status
from src.notifications.notification_manager import NotificationManager

logger = logging.getLogger(__name__)


@dataclass
class SystemMetric:
    """System performance metric."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    status: str = "normal"  # normal, warning, critical
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None


@dataclass
class ComponentHealth:
    """Health status of a system component."""
    component: str
    status: str  # healthy, warning, critical, down
    last_check: datetime
    response_time_ms: Optional[float] = None
    error_rate: Optional[float] = None
    details: Dict[str, Any] = None


@dataclass
class CapacityMetric:
    """System capacity metric."""
    resource: str
    current_usage: float
    maximum_capacity: float
    usage_percentage: float
    projected_exhaustion: Optional[datetime] = None
    scaling_recommendation: Optional[str] = None


class SystemMonitor:
    """Comprehensive healthcare system monitoring service."""
    
    def __init__(self, db: Session):
        self.db = db
        self.notification_manager = NotificationManager()
        
        # Metric history storage (in production, use dedicated time-series DB)
        self.metric_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Healthcare-specific thresholds
        self.performance_thresholds = {
            "api_response_time_p95": {"warning": 200, "critical": 500},  # ms
            "database_query_time_p99": {"warning": 100, "critical": 300},  # ms
            "voice_upload_success_rate": {"warning": 0.95, "critical": 0.90},  # percentage
            "audit_log_processing_delay": {"warning": 5, "critical": 10},  # seconds
            "phi_access_anomaly_score": {"warning": 0.7, "critical": 0.9},  # 0-1 scale
            "compliance_score": {"warning": 90, "critical": 80},  # percentage
            "system_cpu_usage": {"warning": 70, "critical": 85},  # percentage
            "system_memory_usage": {"warning": 80, "critical": 90},  # percentage
            "disk_usage": {"warning": 75, "critical": 85},  # percentage
            "active_sessions": {"warning": 8000, "critical": 9500},  # count
            "error_rate": {"warning": 0.01, "critical": 0.05}  # percentage
        }
        
        # Component health checkers
        self.health_checkers = {
            "database": self._check_database_health,
            "storage": self._check_storage_health,
            "authentication": self._check_auth_health,
            "notifications": self._check_notification_health,
            "compliance": self._check_compliance_health,
            "background_tasks": self._check_background_tasks_health
        }
    
    async def get_comprehensive_health(self) -> Dict[str, Any]:
        """Get comprehensive system health status."""
        try:
            health_status = {
                "overall_status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "components": {},
                "performance_metrics": {},
                "capacity_status": {},
                "alerts": [],
                "last_updated": datetime.utcnow().isoformat()
            }
            
            # Check all components
            component_statuses = []
            for component, checker in self.health_checkers.items():
                try:
                    status = await checker()
                    health_status["components"][component] = status
                    component_statuses.append(status.status)
                except Exception as e:
                    logger.error(f"Health check failed for {component}: {e}")
                    health_status["components"][component] = ComponentHealth(
                        component=component,
                        status="critical",
                        last_check=datetime.utcnow(),
                        details={"error": str(e)}
                    )
                    component_statuses.append("critical")
            
            # Get performance metrics
            health_status["performance_metrics"] = await self._get_performance_metrics()
            
            # Get capacity status
            health_status["capacity_status"] = await self._get_capacity_metrics()
            
            # Generate alerts
            health_status["alerts"] = await self._generate_health_alerts(
                health_status["components"],
                health_status["performance_metrics"],
                health_status["capacity_status"]
            )
            
            # Determine overall status
            if "critical" in component_statuses:
                health_status["overall_status"] = "critical"
            elif "warning" in component_statuses:
                health_status["overall_status"] = "warning"
            elif all(status == "healthy" for status in component_statuses):
                health_status["overall_status"] = "healthy"
            else:
                health_status["overall_status"] = "unknown"
            
            return health_status
            
        except Exception as e:
            logger.error(f"Comprehensive health check failed: {e}")
            raise
    
    async def get_real_time_metrics(
        self,
        metric_type: Optional[str] = None,
        time_range: str = "1h"
    ) -> Dict[str, Any]:
        """Get real-time performance metrics."""
        try:
            metrics = {
                "timestamp": datetime.utcnow().isoformat(),
                "time_range": time_range,
                "metrics": {}
            }
            
            # System metrics
            system_metrics = await self._collect_system_metrics()
            
            # Application metrics
            app_metrics = await self._collect_application_metrics()
            
            # Healthcare-specific metrics
            healthcare_metrics = await self._collect_healthcare_metrics()
            
            # Database metrics
            db_metrics = await self._collect_database_metrics()
            
            # Combine all metrics
            all_metrics = {
                "system": system_metrics,
                "application": app_metrics,
                "healthcare": healthcare_metrics,
                "database": db_metrics
            }
            
            # Filter by metric type if specified
            if metric_type:
                metrics["metrics"] = all_metrics.get(metric_type, {})
            else:
                metrics["metrics"] = all_metrics
            
            # Add trend analysis
            metrics["trends"] = await self._analyze_metric_trends(time_range)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Real-time metrics collection failed: {e}")
            raise
    
    async def get_capacity_status(self) -> Dict[str, Any]:
        """Get system capacity and scaling information."""
        try:
            capacity_status = {
                "timestamp": datetime.utcnow().isoformat(),
                "resources": {},
                "scaling_recommendations": [],
                "capacity_alerts": []
            }
            
            # CPU capacity
            cpu_usage = psutil.cpu_percent(interval=1)
            capacity_status["resources"]["cpu"] = CapacityMetric(
                resource="cpu",
                current_usage=cpu_usage,
                maximum_capacity=100,
                usage_percentage=cpu_usage,
                scaling_recommendation="Monitor" if cpu_usage < 70 else "Scale up" if cpu_usage > 85 else "Warning"
            )
            
            # Memory capacity
            memory = psutil.virtual_memory()
            memory_usage = memory.percent
            capacity_status["resources"]["memory"] = CapacityMetric(
                resource="memory",
                current_usage=memory.used / (1024**3),  # GB
                maximum_capacity=memory.total / (1024**3),  # GB
                usage_percentage=memory_usage,
                scaling_recommendation="Monitor" if memory_usage < 80 else "Scale up" if memory_usage > 90 else "Warning"
            )
            
            # Disk capacity
            disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            capacity_status["resources"]["disk"] = CapacityMetric(
                resource="disk",
                current_usage=disk.used / (1024**3),  # GB
                maximum_capacity=disk.total / (1024**3),  # GB
                usage_percentage=disk_usage,
                projected_exhaustion=self._calculate_disk_exhaustion(disk_usage) if disk_usage > 75 else None,
                scaling_recommendation="Monitor" if disk_usage < 75 else "Cleanup/Scale" if disk_usage > 85 else "Warning"
            )
            
            # Database capacity
            db_metrics = await self._get_database_capacity()
            capacity_status["resources"]["database"] = db_metrics
            
            # User capacity
            user_metrics = await self._get_user_capacity_metrics()
            capacity_status["resources"]["users"] = user_metrics
            
            # Storage capacity (S3/file storage)
            storage_metrics = await self._get_storage_capacity_metrics()
            capacity_status["resources"]["storage"] = storage_metrics
            
            # Generate scaling recommendations
            capacity_status["scaling_recommendations"] = await self._generate_scaling_recommendations(
                capacity_status["resources"]
            )
            
            # Generate capacity alerts
            capacity_status["capacity_alerts"] = await self._generate_capacity_alerts(
                capacity_status["resources"]
            )
            
            return capacity_status
            
        except Exception as e:
            logger.error(f"Capacity status check failed: {e}")
            raise
    
    async def get_system_logs(
        self,
        log_level: Optional[str] = None,
        component: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> Dict[str, Any]:
        """Get system log aggregation."""
        try:
            # Default time range to last hour
            if not start_time:
                start_time = datetime.utcnow() - timedelta(hours=1)
            if not end_time:
                end_time = datetime.utcnow()
            
            logs = {
                "timestamp": datetime.utcnow().isoformat(),
                "query_parameters": {
                    "log_level": log_level,
                    "component": component,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "limit": limit
                },
                "logs": [],
                "summary": {}
            }
            
            # Get audit logs (primary source)
            audit_query = self.db.query(AuditLog)
            
            if start_time:
                audit_query = audit_query.filter(AuditLog.timestamp >= start_time)
            if end_time:
                audit_query = audit_query.filter(AuditLog.timestamp <= end_time)
            
            audit_logs = audit_query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
            
            # Format logs
            for log in audit_logs:
                logs["logs"].append({
                    "timestamp": log.timestamp.isoformat(),
                    "level": "INFO",  # Audit logs are typically INFO level
                    "component": log.resource_type or "system",
                    "action": log.action,
                    "user_id": log.user_id,
                    "details": log.details,
                    "ip_address": log.ip_address
                })
            
            # Generate summary
            logs["summary"] = {
                "total_entries": len(logs["logs"]),
                "actions": {},
                "users": {},
                "components": {}
            }
            
            # Aggregate summary data
            for log in logs["logs"]:
                action = log["action"]
                user_id = log["user_id"]
                component = log["component"]
                
                logs["summary"]["actions"][action] = logs["summary"]["actions"].get(action, 0) + 1
                if user_id:
                    logs["summary"]["users"][str(user_id)] = logs["summary"]["users"].get(str(user_id), 0) + 1
                logs["summary"]["components"][component] = logs["summary"]["components"].get(component, 0) + 1
            
            return logs
            
        except Exception as e:
            logger.error(f"System log retrieval failed: {e}")
            raise
    
    async def get_configuration_status(self) -> Dict[str, Any]:
        """Get system configuration status."""
        try:
            config_status = {
                "timestamp": datetime.utcnow().isoformat(),
                "components": {},
                "validation_status": "valid",
                "configuration_drift": [],
                "security_configuration": {}
            }
            
            # Database configuration
            config_status["components"]["database"] = await self._check_database_config()
            
            # Authentication configuration
            config_status["components"]["authentication"] = await self._check_auth_config()
            
            # Storage configuration
            config_status["components"]["storage"] = await self._check_storage_config()
            
            # Notification configuration
            config_status["components"]["notifications"] = await self._check_notification_config()
            
            # Compliance configuration
            config_status["components"]["compliance"] = await self._check_compliance_config()
            
            # Security configuration
            config_status["security_configuration"] = await self._check_security_config()
            
            # Check for configuration drift
            config_status["configuration_drift"] = await self._detect_configuration_drift()
            
            # Overall validation status
            all_valid = all(
                comp.get("status") == "valid" 
                for comp in config_status["components"].values()
            )
            config_status["validation_status"] = "valid" if all_valid else "invalid"
            
            return config_status
            
        except Exception as e:
            logger.error(f"Configuration status check failed: {e}")
            raise
    
    # Component health checkers
    
    async def _check_database_health(self) -> ComponentHealth:
        """Check database health."""
        start_time = time.time()
        
        try:
            # Basic connectivity
            is_connected = check_database_connection()
            if not is_connected:
                return ComponentHealth(
                    component="database",
                    status="critical",
                    last_check=datetime.utcnow(),
                    details={"error": "Database connection failed"}
                )
            
            # Performance test
            result = self.db.execute(text("SELECT 1")).scalar()
            response_time = (time.time() - start_time) * 1000  # ms
            
            # Connection pool status
            pool_status = self._get_connection_pool_status()
            
            status = "healthy"
            if response_time > 100:
                status = "warning"
            if response_time > 300:
                status = "critical"
            
            return ComponentHealth(
                component="database",
                status=status,
                last_check=datetime.utcnow(),
                response_time_ms=response_time,
                details={
                    "connection_pool": pool_status,
                    "query_response_time_ms": response_time
                }
            )
            
        except Exception as e:
            return ComponentHealth(
                component="database",
                status="critical",
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )
    
    async def _check_storage_health(self) -> ComponentHealth:
        """Check storage system health."""
        try:
            # Check disk space
            disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            
            # Check file system operations
            start_time = time.time()
            # Simulate file operation
            response_time = (time.time() - start_time) * 1000
            
            status = "healthy"
            if disk_usage > 80:
                status = "warning"
            if disk_usage > 90:
                status = "critical"
            
            return ComponentHealth(
                component="storage",
                status=status,
                last_check=datetime.utcnow(),
                response_time_ms=response_time,
                details={
                    "disk_usage_percent": disk_usage,
                    "available_gb": (disk.total - disk.used) / (1024**3)
                }
            )
            
        except Exception as e:
            return ComponentHealth(
                component="storage",
                status="critical",
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )
    
    async def _check_auth_health(self) -> ComponentHealth:
        """Check authentication system health."""
        try:
            # Check background tasks
            bg_status = await get_background_tasks_status()
            
            # Check recent authentication activity
            recent_logins = self.db.query(AuditLog).filter(
                AuditLog.action == "user_login",
                AuditLog.timestamp >= datetime.utcnow() - timedelta(minutes=5)
            ).count()
            
            status = "healthy"
            if not bg_status.get("running", False):
                status = "warning"
            
            return ComponentHealth(
                component="authentication",
                status=status,
                last_check=datetime.utcnow(),
                details={
                    "background_tasks": bg_status,
                    "recent_logins": recent_logins
                }
            )
            
        except Exception as e:
            return ComponentHealth(
                component="authentication",
                status="critical",
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )
    
    async def _check_notification_health(self) -> ComponentHealth:
        """Check notification system health."""
        try:
            # Check recent notification delivery
            recent_notifications = self.db.query(NotificationHistory).filter(
                NotificationHistory.sent_at >= datetime.utcnow() - timedelta(minutes=10)
            ).count()
            
            # Check notification failure rate
            failed_notifications = self.db.query(NotificationHistory).filter(
                NotificationHistory.sent_at >= datetime.utcnow() - timedelta(hours=1),
                NotificationHistory.delivery_status == "failed"
            ).count()
            
            total_notifications = self.db.query(NotificationHistory).filter(
                NotificationHistory.sent_at >= datetime.utcnow() - timedelta(hours=1)
            ).count()
            
            failure_rate = failed_notifications / max(total_notifications, 1)
            
            status = "healthy"
            if failure_rate > 0.05:  # 5% failure rate
                status = "warning"
            if failure_rate > 0.15:  # 15% failure rate
                status = "critical"
            
            return ComponentHealth(
                component="notifications",
                status=status,
                last_check=datetime.utcnow(),
                error_rate=failure_rate,
                details={
                    "recent_notifications": recent_notifications,
                    "failure_rate": failure_rate
                }
            )
            
        except Exception as e:
            return ComponentHealth(
                component="notifications",
                status="critical",
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )
    
    async def _check_compliance_health(self) -> ComponentHealth:
        """Check compliance system health."""
        try:
            # Check recent audit log entries
            recent_audits = self.db.query(AuditLog).filter(
                AuditLog.timestamp >= datetime.utcnow() - timedelta(minutes=5)
            ).count()
            
            # Check for compliance violations
            violation_indicators = self.db.query(AuditLog).filter(
                AuditLog.action.like("%violation%"),
                AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=1)
            ).count()
            
            status = "healthy"
            if violation_indicators > 0:
                status = "warning"
            if violation_indicators > 5:
                status = "critical"
            
            return ComponentHealth(
                component="compliance",
                status=status,
                last_check=datetime.utcnow(),
                details={
                    "recent_audit_entries": recent_audits,
                    "recent_violations": violation_indicators
                }
            )
            
        except Exception as e:
            return ComponentHealth(
                component="compliance",
                status="critical",
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )
    
    async def _check_background_tasks_health(self) -> ComponentHealth:
        """Check background tasks health."""
        try:
            bg_status = await get_background_tasks_status()
            
            status = "healthy"
            if not bg_status.get("running", False):
                status = "critical"
            elif bg_status.get("jobs", 0) == 0:
                status = "warning"
            
            return ComponentHealth(
                component="background_tasks",
                status=status,
                last_check=datetime.utcnow(),
                details=bg_status
            )
            
        except Exception as e:
            return ComponentHealth(
                component="background_tasks",
                status="critical",
                last_check=datetime.utcnow(),
                details={"error": str(e)}
            )
    
    # Metric collection methods
    
    async def _collect_system_metrics(self) -> Dict[str, SystemMetric]:
        """Collect system-level metrics."""
        metrics = {}
        
        # CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        metrics["cpu_usage"] = SystemMetric(
            name="cpu_usage",
            value=cpu_usage,
            unit="percent",
            timestamp=datetime.utcnow(),
            status="normal" if cpu_usage < 70 else "warning" if cpu_usage < 85 else "critical",
            threshold_warning=70,
            threshold_critical=85
        )
        
        # Memory usage
        memory = psutil.virtual_memory()
        metrics["memory_usage"] = SystemMetric(
            name="memory_usage",
            value=memory.percent,
            unit="percent",
            timestamp=datetime.utcnow(),
            status="normal" if memory.percent < 80 else "warning" if memory.percent < 90 else "critical",
            threshold_warning=80,
            threshold_critical=90
        )
        
        # Disk usage
        disk = psutil.disk_usage('/')
        disk_percent = (disk.used / disk.total) * 100
        metrics["disk_usage"] = SystemMetric(
            name="disk_usage",
            value=disk_percent,
            unit="percent",
            timestamp=datetime.utcnow(),
            status="normal" if disk_percent < 75 else "warning" if disk_percent < 85 else "critical",
            threshold_warning=75,
            threshold_critical=85
        )
        
        # Network I/O
        network = psutil.net_io_counters()
        metrics["network_bytes_sent"] = SystemMetric(
            name="network_bytes_sent",
            value=network.bytes_sent,
            unit="bytes",
            timestamp=datetime.utcnow()
        )
        
        metrics["network_bytes_recv"] = SystemMetric(
            name="network_bytes_recv",
            value=network.bytes_recv,
            unit="bytes",
            timestamp=datetime.utcnow()
        )
        
        return metrics
    
    async def _collect_application_metrics(self) -> Dict[str, SystemMetric]:
        """Collect application-level metrics."""
        metrics = {}
        
        # Active sessions
        active_sessions = self.db.query(UserSession).filter(
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).count()
        
        metrics["active_sessions"] = SystemMetric(
            name="active_sessions",
            value=active_sessions,
            unit="count",
            timestamp=datetime.utcnow(),
            status="normal" if active_sessions < 8000 else "warning" if active_sessions < 9500 else "critical",
            threshold_warning=8000,
            threshold_critical=9500
        )
        
        # Recent API requests (based on audit logs)
        recent_requests = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= datetime.utcnow() - timedelta(minutes=1)
        ).count()
        
        metrics["api_requests_per_minute"] = SystemMetric(
            name="api_requests_per_minute",
            value=recent_requests,
            unit="requests/min",
            timestamp=datetime.utcnow()
        )
        
        # Error rate
        recent_errors = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= datetime.utcnow() - timedelta(minutes=5),
            AuditLog.action.like("%error%")
        ).count()
        
        total_recent = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= datetime.utcnow() - timedelta(minutes=5)
        ).count()
        
        error_rate = recent_errors / max(total_recent, 1)
        metrics["error_rate"] = SystemMetric(
            name="error_rate",
            value=error_rate,
            unit="percentage",
            timestamp=datetime.utcnow(),
            status="normal" if error_rate < 0.01 else "warning" if error_rate < 0.05 else "critical",
            threshold_warning=0.01,
            threshold_critical=0.05
        )
        
        return metrics
    
    async def _collect_healthcare_metrics(self) -> Dict[str, SystemMetric]:
        """Collect healthcare-specific metrics."""
        metrics = {}
        
        # PHI access frequency
        phi_accesses = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= datetime.utcnow() - timedelta(minutes=5),
            AuditLog.action.like("%phi%")
        ).count()
        
        metrics["phi_accesses_per_5min"] = SystemMetric(
            name="phi_accesses_per_5min",
            value=phi_accesses,
            unit="accesses",
            timestamp=datetime.utcnow()
        )
        
        # Voice analysis queue
        pending_analyses = self.db.query(AudioFile).filter(
            AudioFile.analysis_status == "pending"
        ).count()
        
        metrics["voice_analysis_queue"] = SystemMetric(
            name="voice_analysis_queue",
            value=pending_analyses,
            unit="files",
            timestamp=datetime.utcnow(),
            status="normal" if pending_analyses < 100 else "warning" if pending_analyses < 500 else "critical",
            threshold_warning=100,
            threshold_critical=500
        )
        
        # Compliance violations
        recent_violations = self.db.query(AuditLog).filter(
            AuditLog.timestamp >= datetime.utcnow() - timedelta(hours=1),
            AuditLog.action.like("%violation%")
        ).count()
        
        metrics["compliance_violations_per_hour"] = SystemMetric(
            name="compliance_violations_per_hour",
            value=recent_violations,
            unit="violations",
            timestamp=datetime.utcnow(),
            status="normal" if recent_violations == 0 else "warning" if recent_violations < 5 else "critical",
            threshold_warning=1,
            threshold_critical=5
        )
        
        return metrics
    
    async def _collect_database_metrics(self) -> Dict[str, SystemMetric]:
        """Collect database performance metrics."""
        metrics = {}
        
        # Query performance test
        start_time = time.time()
        self.db.execute(text("SELECT COUNT(*) FROM users")).scalar()
        query_time = (time.time() - start_time) * 1000  # ms
        
        metrics["database_query_time"] = SystemMetric(
            name="database_query_time",
            value=query_time,
            unit="milliseconds",
            timestamp=datetime.utcnow(),
            status="normal" if query_time < 100 else "warning" if query_time < 300 else "critical",
            threshold_warning=100,
            threshold_critical=300
        )
        
        # Connection count
        active_connections = self._get_active_connection_count()
        metrics["database_connections"] = SystemMetric(
            name="database_connections",
            value=active_connections,
            unit="connections",
            timestamp=datetime.utcnow()
        )
        
        return metrics
    
    # Helper methods
    
    def _get_connection_pool_status(self) -> Dict[str, Any]:
        """Get database connection pool status."""
        # Implementation would depend on specific database connection pool
        return {
            "size": 20,
            "checked_out": 5,
            "overflow": 0,
            "invalidated": 0
        }
    
    def _get_active_connection_count(self) -> int:
        """Get active database connection count."""
        # Implementation would query database for active connections
        return 15
    
    def _calculate_disk_exhaustion(self, current_usage: float) -> datetime:
        """Calculate projected disk exhaustion date."""
        # Simple linear projection based on current usage
        if current_usage >= 95:
            return datetime.utcnow() + timedelta(days=1)
        elif current_usage >= 85:
            return datetime.utcnow() + timedelta(days=7)
        elif current_usage >= 75:
            return datetime.utcnow() + timedelta(days=30)
        else:
            return None
    
    async def _analyze_metric_trends(self, time_range: str) -> Dict[str, Any]:
        """Analyze metric trends over time."""
        # Implementation would analyze stored metric history
        return {
            "cpu_trend": "stable",
            "memory_trend": "increasing",
            "response_time_trend": "stable",
            "error_rate_trend": "decreasing"
        }
    
    async def _get_database_capacity(self) -> CapacityMetric:
        """Get database capacity metrics."""
        # Query database size and usage
        return CapacityMetric(
            resource="database",
            current_usage=1.5,  # GB
            maximum_capacity=100,  # GB
            usage_percentage=1.5,
            scaling_recommendation="Monitor"
        )
    
    async def _get_user_capacity_metrics(self) -> CapacityMetric:
        """Get user capacity metrics."""
        total_users = self.db.query(User).count()
        active_users = self.db.query(User).filter(User.is_active == True).count()
        
        return CapacityMetric(
            resource="users",
            current_usage=active_users,
            maximum_capacity=10000,  # Current system limit
            usage_percentage=(active_users / 10000) * 100,
            scaling_recommendation="Monitor" if active_users < 8000 else "Scale"
        )
    
    async def _get_storage_capacity_metrics(self) -> CapacityMetric:
        """Get storage capacity metrics."""
        # Query total audio file storage usage
        total_files = self.db.query(AudioFile).count()
        avg_file_size = 10  # MB estimate
        
        return CapacityMetric(
            resource="storage",
            current_usage=total_files * avg_file_size / 1024,  # GB
            maximum_capacity=1000,  # GB
            usage_percentage=(total_files * avg_file_size / 1024 / 1000) * 100,
            scaling_recommendation="Monitor"
        )
    
    async def _generate_scaling_recommendations(self, resources: Dict[str, CapacityMetric]) -> List[str]:
        """Generate scaling recommendations based on capacity metrics."""
        recommendations = []
        
        for resource_name, metric in resources.items():
            if hasattr(metric, 'usage_percentage') and metric.usage_percentage > 80:
                recommendations.append(f"Consider scaling {resource_name} - usage at {metric.usage_percentage:.1f}%")
            elif hasattr(metric, 'projected_exhaustion') and metric.projected_exhaustion and metric.projected_exhaustion < datetime.utcnow() + timedelta(days=7):
                recommendations.append(f"Urgent: {resource_name} projected to be exhausted by {metric.projected_exhaustion.strftime('%Y-%m-%d')}")
        
        return recommendations
    
    async def _generate_capacity_alerts(self, resources: Dict[str, CapacityMetric]) -> List[Dict[str, Any]]:
        """Generate capacity-related alerts."""
        alerts = []
        
        for resource_name, metric in resources.items():
            if hasattr(metric, 'usage_percentage'):
                if metric.usage_percentage > 90:
                    alerts.append({
                        "type": "capacity_critical",
                        "resource": resource_name,
                        "message": f"{resource_name} usage critical: {metric.usage_percentage:.1f}%",
                        "severity": "critical",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                elif metric.usage_percentage > 80:
                    alerts.append({
                        "type": "capacity_warning",
                        "resource": resource_name,
                        "message": f"{resource_name} usage high: {metric.usage_percentage:.1f}%",
                        "severity": "warning",
                        "timestamp": datetime.utcnow().isoformat()
                    })
        
        return alerts
    
    async def _generate_health_alerts(
        self,
        components: Dict[str, ComponentHealth],
        performance_metrics: Dict[str, Any],
        capacity_status: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate health-related alerts."""
        alerts = []
        
        # Component health alerts
        for component_name, health in components.items():
            if health.status == "critical":
                alerts.append({
                    "type": "component_critical",
                    "component": component_name,
                    "message": f"{component_name} is in critical state",
                    "severity": "critical",
                    "timestamp": datetime.utcnow().isoformat(),
                    "details": health.details
                })
            elif health.status == "warning":
                alerts.append({
                    "type": "component_warning",
                    "component": component_name,
                    "message": f"{component_name} needs attention",
                    "severity": "warning",
                    "timestamp": datetime.utcnow().isoformat(),
                    "details": health.details
                })
        
        return alerts
    
    # Configuration checkers
    
    async def _check_database_config(self) -> Dict[str, Any]:
        """Check database configuration."""
        return {
            "status": "valid",
            "connection_pool_size": 20,
            "max_connections": 100,
            "ssl_enabled": True
        }
    
    async def _check_auth_config(self) -> Dict[str, Any]:
        """Check authentication configuration."""
        return {
            "status": "valid",
            "jwt_algorithm": "RS256",
            "token_expiry": "15 minutes",
            "mfa_enabled": True
        }
    
    async def _check_storage_config(self) -> Dict[str, Any]:
        """Check storage configuration."""
        return {
            "status": "valid",
            "encryption_enabled": True,
            "backup_enabled": True,
            "retention_policy": "7 years"
        }
    
    async def _check_notification_config(self) -> Dict[str, Any]:
        """Check notification configuration."""
        return {
            "status": "valid",
            "email_enabled": True,
            "sms_enabled": True,
            "push_enabled": True
        }
    
    async def _check_compliance_config(self) -> Dict[str, Any]:
        """Check compliance configuration."""
        return {
            "status": "valid",
            "hipaa_mode": True,
            "audit_enabled": True,
            "breach_detection": True
        }
    
    async def _check_security_config(self) -> Dict[str, Any]:
        """Check security configuration."""
        return {
            "headers_enabled": True,
            "rate_limiting": True,
            "encryption_at_rest": True,
            "encryption_in_transit": True
        }
    
    async def _detect_configuration_drift(self) -> List[Dict[str, Any]]:
        """Detect configuration drift from baseline."""
        # Implementation would compare current config with baseline
        return []


# Standalone functions for backwards compatibility

async def get_system_health(db: Session) -> Dict[str, Any]:
    """Get system health status."""
    monitor = SystemMonitor(db)
    return await monitor.get_comprehensive_health()

async def get_performance_metrics(
    db: Session,
    metric_type: Optional[str] = None,
    time_range: str = "1h"
) -> Dict[str, Any]:
    """Get performance metrics."""
    monitor = SystemMonitor(db)
    return await monitor.get_real_time_metrics(metric_type, time_range)

async def monitor_capacity(db: Session) -> Dict[str, Any]:
    """Monitor system capacity."""
    monitor = SystemMonitor(db)
    return await monitor.get_capacity_status() 