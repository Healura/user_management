import logging
import os
import psutil
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from ..database.database import get_db, check_database_connection, engine
from ..database.repositories import UserRepository, UserSessionRepository, AuditLogRepository
from config.database_config import database_config
from config.auth_settings import auth_settings
from ..utils.rate_limiting import _rate_limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=Dict[str, Any])
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "user-management-service",
        "version": "1.0.0",
        "uptime": get_uptime()
    }


@router.get("/live", response_model=Dict[str, Any])
async def liveness_check():
    """
    Kubernetes liveness probe endpoint.
    Returns 200 if the service is alive.
    """
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/ready", response_model=Dict[str, Any])
async def readiness_check(db: Session = Depends(get_db)):
    """
    Kubernetes readiness probe endpoint.
    Checks if the service is ready to accept traffic.
    """
    health_status = await get_health_status(db)
    
    # Determine if service is ready
    is_ready = (
        health_status["database"]["connected"] and
        health_status["authentication"]["jwt_keys_loaded"] and
        health_status["rate_limiting"]["status"] == "operational"
    )
    
    if not is_ready:
        return {
            "status": "not_ready",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": health_status
        }
    
    return {
        "status": "ready",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": health_status
    }


@router.get("/database", response_model=Dict[str, Any])
async def database_health(db: Session = Depends(get_db)):
    """Check database connectivity and performance."""
    status = {
        "connected": False,
        "latency_ms": None,
        "pool_size": database_config.db_pool_size,
        "endpoint": database_config.rds_endpoint,
        "active_connections": 0,
        "tables_accessible": False
    }
    
    try:
        # Test basic connectivity
        start_time = datetime.utcnow()
        result = db.execute(text("SELECT 1"))
        end_time = datetime.utcnow()
        
        status["connected"] = True
        status["latency_ms"] = (end_time - start_time).total_seconds() * 1000
        
        # Get database version
        db_info = db.execute(text("SELECT version()")).scalar()
        status["version"] = db_info
        
        # Check connection pool status
        pool = engine.pool
        status["active_connections"] = pool.checkedout()
        status["pool_overflow"] = pool.overflow()
        
        # Test table accessibility
        user_count = db.execute(text("SELECT COUNT(*) FROM users")).scalar()
        status["tables_accessible"] = True
        status["user_count"] = user_count
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        status["error"] = str(e)
    
    return status


@router.get("/auth", response_model=Dict[str, Any])
async def auth_health(db: Session = Depends(get_db)):
    """Check authentication service health."""
    status = {
        "jwt_service": {
            "keys_loaded": False,
            "algorithm": auth_settings.algorithm,
            "token_expiry": {
                "access_minutes": auth_settings.access_token_expire_minutes,
                "refresh_days": auth_settings.refresh_token_expire_days
            }
        },
        "password_policy": {
            "min_length": auth_settings.password_min_length,
            "complexity_enabled": True
        },
        "session_management": {
            "active_sessions": 0,
            "max_sessions_per_user": auth_settings.max_sessions_per_user
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": auth_settings.rate_limit_requests_per_minute
        }
    }
    
    try:
        # Check JWT keys
        from src.utils.jwt_utils import _load_or_create_keys
        private_key, public_key = _load_or_create_keys()
        status["jwt_service"]["keys_loaded"] = bool(private_key and public_key)
        
        # Get active session count
        session_repo = UserSessionRepository(db)
        active_sessions = db.execute(
            text("SELECT COUNT(*) FROM user_sessions WHERE is_active = true AND expires_at > NOW()")
        ).scalar()
        status["session_management"]["active_sessions"] = active_sessions
        
        # Check email service
        status["email_service"] = {
            "configured": bool(auth_settings.smtp_username and auth_settings.smtp_password),
            "smtp_host": auth_settings.smtp_host
        }
        
    except Exception as e:
        logger.error(f"Auth health check failed: {e}")
        status["error"] = str(e)
    
    return status


@router.get("/rate-limiting", response_model=Dict[str, Any])
async def rate_limiting_health():
    """Check rate limiting service health."""
    status = {
        "status": "operational",
        "backend": "memory",
        "redis_available": False,
        "configuration": {
            "requests_per_minute": auth_settings.rate_limit_requests_per_minute,
            "burst_requests": auth_settings.rate_limit_burst_requests
        }
    }
    
    try:
        # Check Redis availability
        if _rate_limiter.redis_client:
            _rate_limiter.redis_client.ping()
            status["redis_available"] = True
            status["backend"] = "redis"
            status["redis_info"] = {
                "connected": True,
                "url": auth_settings.redis_url.split('@')[-1] if auth_settings.redis_url else None
            }
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")
        status["redis_error"] = str(e)
    
    # Check memory store status
    if not status["redis_available"]:
        status["memory_store"] = {
            "active_keys": len(_rate_limiter.memory_store),
            "backend": "in-memory"
        }
    
    return status


@router.get("/system", response_model=Dict[str, Any])
async def system_health():
    """Get system resource information."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        
        # Disk usage
        disk = psutil.disk_usage('/')
        
        return {
            "cpu": {
                "usage_percent": cpu_percent,
                "count": psutil.cpu_count()
            },
            "memory": {
                "total_mb": memory.total // (1024 * 1024),
                "available_mb": memory.available // (1024 * 1024),
                "used_percent": memory.percent
            },
            "disk": {
                "total_gb": disk.total // (1024 * 1024 * 1024),
                "free_gb": disk.free // (1024 * 1024 * 1024),
                "used_percent": disk.percent
            },
            "environment": os.environ.get("ENVIRONMENT", "unknown")
        }
    except Exception as e:
        logger.error(f"System health check failed: {e}")
        return {"error": str(e)}


@router.get("/detailed", response_model=Dict[str, Any])
async def detailed_health_check(db: Session = Depends(get_db)):
    """
    Detailed health check with all component statuses.
    This endpoint should be protected in production.
    """
    health_status = await get_health_status(db)
    
    # Overall health determination
    overall_health = "healthy"
    
    # Check critical components
    if not health_status["database"]["connected"]:
        overall_health = "unhealthy"
    elif health_status["database"].get("latency_ms", 0) > 1000:
        overall_health = "degraded"
    elif not health_status["authentication"]["jwt_keys_loaded"]:
        overall_health = "degraded"
    elif health_status["rate_limiting"]["status"] != "operational":
        overall_health = "degraded"
    
    # Add system metrics
    system_metrics = await system_health()
    
    return {
        "status": overall_health,
        "timestamp": datetime.utcnow().isoformat(),
        "service": "user-management-service",
        "version": "1.0.0",
        "environment": os.environ.get("ENVIRONMENT", "production"),
        "uptime": get_uptime(),
        "components": health_status,
        "system": system_metrics
    }


async def get_health_status(db: Session) -> Dict[str, Any]:
    """
    Get detailed health status of all components.
    
    Args:
        db: Database session
        
    Returns:
        Dictionary with health status of each component
    """
    status = {
        "database": {
            "connected": False,
            "latency_ms": None,
            "pool_size": database_config.db_pool_size,
            "endpoint": database_config.rds_endpoint
        },
        "authentication": {
            "jwt_keys_loaded": False,
            "session_cleanup_active": True,
            "mfa_enabled": True
        },
        "rate_limiting": {
            "status": "unknown",
            "backend": None
        },
        "audit_logging": {
            "enabled": True,
            "recent_logs": 0
        }
    }
    
    # Check database connection
    try:
        start_time = datetime.utcnow()
        result = db.execute(text("SELECT 1"))
        end_time = datetime.utcnow()
        
        status["database"]["connected"] = True
        status["database"]["latency_ms"] = (end_time - start_time).total_seconds() * 1000
        
        # Get additional database info
        db_info = db.execute(text("SELECT version()")).scalar()
        status["database"]["version"] = db_info
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        status["database"]["error"] = str(e)
    
    # Check JWT key availability
    try:
        from src.utils.jwt_utils import _load_or_create_keys
        private_key, public_key = _load_or_create_keys()
        status["authentication"]["jwt_keys_loaded"] = bool(private_key and public_key)
    except Exception as e:
        logger.error(f"JWT key check failed: {e}")
        status["authentication"]["jwt_keys_loaded"] = False
        status["authentication"]["error"] = str(e)
    
    # Check rate limiting
    try:
        if _rate_limiter.redis_client:
            _rate_limiter.redis_client.ping()
            status["rate_limiting"]["status"] = "operational"
            status["rate_limiting"]["backend"] = "redis"
        else:
            status["rate_limiting"]["status"] = "operational"
            status["rate_limiting"]["backend"] = "memory"
    except Exception as e:
        status["rate_limiting"]["status"] = "degraded"
        status["rate_limiting"]["backend"] = "memory"
        status["rate_limiting"]["error"] = str(e)
    
    # Check audit logging
    try:
        audit_repo = AuditLogRepository(db)
        recent_count = db.execute(
            text("SELECT COUNT(*) FROM audit_logs WHERE timestamp > NOW() - INTERVAL '1 hour'")
        ).scalar()
        status["audit_logging"]["recent_logs"] = recent_count
    except Exception as e:
        status["audit_logging"]["error"] = str(e)
    
    return status


def get_uptime() -> str:
    """Get service uptime."""
    try:
        # Get process start time
        process = psutil.Process(os.getpid())
        start_time = datetime.fromtimestamp(process.create_time())
        uptime = datetime.now() - start_time
        
        days = uptime.days
        hours, remainder = divmod(uptime.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return f"{days}d {hours}h {minutes}m {seconds}s"
    except Exception:
        return "unknown"