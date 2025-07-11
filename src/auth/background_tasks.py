"""
Authentication Background Tasks Manager

Manages background tasks for authentication and session management
including periodic cleanup of expired sessions.
"""

import asyncio
import logging
from typing import Optional
from datetime import datetime, timedelta

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session

from .session_manager import SessionManager
from ..database.database import get_db
from config.auth_settings import auth_settings

logger = logging.getLogger(__name__)


class AuthBackgroundTaskManager:
    """Manages background tasks for authentication and session management."""
    
    def __init__(self):
        self.scheduler: Optional[AsyncIOScheduler] = None
        self.running = False
        
        # Task configuration
        self.session_cleanup_interval_minutes = getattr(
            auth_settings, 
            'session_cleanup_interval_minutes', 
            60  # Default to 1 hour
        )
        
    async def start(self):
        """Start the background task scheduler."""
        if self.running:
            logger.warning("Background task manager is already running")
            return
            
        try:
            # Initialize scheduler
            self.scheduler = AsyncIOScheduler(
                timezone='UTC',
                job_defaults={
                    'coalesce': True,
                    'max_instances': 1,
                    'misfire_grace_time': 300  # 5 minutes
                }
            )
            
            # Add session cleanup task
            self.scheduler.add_job(
                func=self._cleanup_expired_sessions,
                trigger=IntervalTrigger(minutes=self.session_cleanup_interval_minutes),
                id='session_cleanup',
                name='Session Cleanup Task',
                replace_existing=True
            )
            
            # Start scheduler
            self.scheduler.start()
            self.running = True
            
            logger.info(f"Authentication background tasks started (session cleanup every {self.session_cleanup_interval_minutes} minutes)")
            
        except Exception as e:
            logger.error(f"Failed to start background tasks: {e}")
            raise
    
    async def stop(self):
        """Stop the background task scheduler."""
        if not self.running:
            logger.warning("Background task manager is not running")
            return
            
        try:
            if self.scheduler:
                self.scheduler.shutdown(wait=True)
                self.scheduler = None
                
            self.running = False
            logger.info("Authentication background tasks stopped")
            
        except Exception as e:
            logger.error(f"Error stopping background tasks: {e}")
            raise
    
    async def _cleanup_expired_sessions(self):
        """Clean up expired user sessions."""
        try:
            logger.debug("Starting session cleanup task")
            
            # Get database session
            db = next(get_db())
            
            try:
                # Initialize session manager
                session_manager = SessionManager(db)
                
                # Clean up expired sessions
                cleaned_count = await session_manager.cleanup_expired_sessions()
                
                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired sessions")
                else:
                    logger.debug("No expired sessions to clean up")
                    
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Session cleanup task failed: {e}")
    
    def get_status(self) -> dict:
        """Get status of background tasks."""
        status = {
            "running": self.running,
            "scheduler_state": None,
            "jobs": []
        }
        
        if self.scheduler:
            status["scheduler_state"] = "running" if self.scheduler.running else "stopped"
            
            for job in self.scheduler.get_jobs():
                status["jobs"].append({
                    "id": job.id,
                    "name": job.name,
                    "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                    "trigger": str(job.trigger)
                })
        
        return status


# Global instance
_task_manager: Optional[AuthBackgroundTaskManager] = None


async def get_task_manager() -> AuthBackgroundTaskManager:
    """Get the global background task manager instance."""
    global _task_manager
    if _task_manager is None:
        _task_manager = AuthBackgroundTaskManager()
    return _task_manager


async def start_background_tasks():
    """Start authentication background tasks."""
    task_manager = await get_task_manager()
    await task_manager.start()


async def stop_background_tasks():
    """Stop authentication background tasks."""
    task_manager = await get_task_manager()
    await task_manager.stop()


async def get_background_tasks_status() -> dict:
    """Get status of background tasks."""
    task_manager = await get_task_manager()
    return task_manager.get_status() 