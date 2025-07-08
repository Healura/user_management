"""Health check endpoints and utilities."""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import text

from src.database.database import get_db, check_database_connection
from config.database_config import database_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=Dict[str, Any])
async def health_check():
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "user-management-service",
        "version": "1.0.0"
    }


@router.get("/live", response_model=Dict[str, Any])
async def liveness_check():
    """Kubernetes liveness probe endpoint."""
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
    
    if not health_status["database"]["connected"]:
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
    
    return status


@router.get("/detailed", response_model=Dict[str, Any])
async def detailed_health_check(db: Session = Depends(get_db)):
    """
    Detailed health check with all component statuses.
    This endpoint should be protected in production.
    """
    health_status = await get_health_status(db)
    
    # Overall health determination
    overall_health = "healthy"
    if not health_status["database"]["connected"]:
        overall_health = "unhealthy"
    elif health_status["database"].get("latency_ms", 0) > 1000:
        overall_health = "degraded"
    
    return {
        "status": overall_health,
        "timestamp": datetime.utcnow().isoformat(),
        "service": "user-management-service",
        "version": "1.0.0",
        "environment": database_config.db_echo,  # This will be from ENVIRONMENT var in real impl
        "components": health_status
    }