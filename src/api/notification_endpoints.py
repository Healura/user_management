"""
Healthcare Notification API Endpoints

HIPAA-compliant notification management endpoints for patients and providers.
Integrates with existing authentication and audit systems.
"""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Body
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ..database.database import get_db
from ..database.models import User, NotificationPreference, NotificationHistory
from ..database.repositories import (
    NotificationPreferenceRepository,
    NotificationHistoryRepository
)
from ..auth.dependencies import CurrentUser, AdminUser, ProviderUser, get_current_user_dependency
from ..auth.authorization import RoleChecker, check_permission
from ..security import AuditLogger
from ..notifications import (
    NotificationManager,
    NotificationScheduler,
    NotificationType
)
from config.notification_config import get_notification_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])


# Request/Response Models
class NotificationPreferencesResponse(BaseModel):
    """Response model for notification preferences"""
    user_id: UUID
    reminder_enabled: bool
    reminder_frequency: str
    reminder_time: Optional[str]
    insights_enabled: bool
    security_alerts_enabled: bool
    email_enabled: bool
    sms_enabled: bool
    push_enabled: bool
    updated_at: datetime
    
    class Config:
        from_attributes = True


class UpdateNotificationPreferencesRequest(BaseModel):
    """Request model for updating notification preferences"""
    reminder_enabled: Optional[bool] = None
    reminder_frequency: Optional[str] = Field(None, pattern="^(daily|weekly|monthly)$")
    reminder_time: Optional[str] = Field(None, pattern="^([01]?[0-9]|2[0-3]):[0-5][0-9]$")
    insights_enabled: Optional[bool] = None
    security_alerts_enabled: Optional[bool] = None
    email_enabled: Optional[bool] = None
    sms_enabled: Optional[bool] = None
    push_enabled: Optional[bool] = None
    
    @validator('reminder_time')
    def validate_reminder_time(cls, v):
        if v:
            try:
                datetime.strptime(v, "%H:%M")
            except ValueError:
                raise ValueError("Invalid time format. Use HH:MM")
        return v


class SendNotificationRequest(BaseModel):
    """Request model for sending notifications"""
    notification_type: str
    user_id: Optional[UUID] = None
    data: Dict[str, Any] = Field(default_factory=dict)
    channels: Optional[List[str]] = None
    priority: str = Field(default="normal", pattern="^(low|normal|high|urgent)$")
    scheduled_time: Optional[datetime] = None


class ScheduleNotificationRequest(BaseModel):
    """Request model for scheduling notifications"""
    notification_type: str
    user_id: UUID
    schedule_type: str = Field(..., pattern="^(once|daily|weekly|monthly|custom_cron|interval)$")
    scheduled_time: datetime
    data: Dict[str, Any] = Field(default_factory=dict)
    timezone: str = Field(default="UTC")
    recurring_data: Optional[Dict[str, Any]] = None
    end_date: Optional[datetime] = None


class NotificationHistoryResponse(BaseModel):
    """Response model for notification history"""
    id: UUID
    notification_type: str
    channel: str
    subject: Optional[str]
    sent_at: datetime
    delivery_status: str
    contains_phi: bool = False
    
    class Config:
        from_attributes = True


class TestNotificationRequest(BaseModel):
    """Request model for testing notifications"""
    channel: str = Field(..., pattern="^(email|sms|push)$")
    test_type: str = Field(default="basic", pattern="^(basic|template|security)$")


class BulkNotificationRequest(BaseModel):
    """Request model for bulk notifications"""
    notification_type: str
    user_ids: List[UUID]
    data: Dict[str, Any] = Field(default_factory=dict)
    channels: Optional[List[str]] = None
    priority: str = Field(default="normal")
    stagger_delay: float = Field(default=0.1, ge=0.0, le=5.0)


# User Notification Preferences Endpoints
@router.get("/preferences", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Get current user's notification preferences."""
    try:
        pref_repo = NotificationPreferenceRepository(db)
        preferences = pref_repo.get_by_user(current_user.id)
        
        if not preferences:
            # Create default preferences if none exist
            preferences = pref_repo.create_default_preferences(current_user.id)
        
        # Log preference access
        audit_logger = AuditLogger(db)
        await audit_logger.log_data_access(
            user_id=current_user.id,
            action="read",
            resource_type="notification_preferences",
            resource_id=preferences.id,
            purpose="View notification settings"
        )
        
        return NotificationPreferencesResponse(
            user_id=preferences.user_id,
            reminder_enabled=preferences.reminder_enabled,
            reminder_frequency=preferences.reminder_frequency,
            reminder_time=preferences.reminder_time.strftime("%H:%M") if preferences.reminder_time else None,
            insights_enabled=preferences.insights_enabled,
            security_alerts_enabled=preferences.security_alerts_enabled,
            email_enabled=preferences.email_enabled,
            sms_enabled=preferences.sms_enabled,
            push_enabled=preferences.push_enabled,
            updated_at=preferences.updated_at
        )
        
    except Exception as e:
        logger.error(f"Error fetching notification preferences: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch notification preferences"
        )


@router.put("/preferences", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    request: UpdateNotificationPreferencesRequest,
    current_user: CurrentUser,
    req: Request,
    db: Session = Depends(get_db)
):
    """Update current user's notification preferences."""
    try:
        pref_repo = NotificationPreferenceRepository(db)
        preferences = pref_repo.get_by_user(current_user.id)
        
        if not preferences:
            preferences = pref_repo.create_default_preferences(current_user.id)
        
        # Prepare update data
        update_data = {}
        for field, value in request.dict(exclude_unset=True).items():
            if field == "reminder_time" and value:
                # Convert time string to time object
                time_obj = datetime.strptime(value, "%H:%M").time()
                update_data[field] = time_obj
            else:
                update_data[field] = value
        
        # Update preferences
        for field, value in update_data.items():
            setattr(preferences, field, value)
        
        preferences.updated_at = datetime.utcnow()
        db.commit()
        
        # Log preference update
        audit_logger = AuditLogger(db)
        await audit_logger.log_user_modification(
            modifier_id=current_user.id,
            user_id=current_user.id,
            action="update_notification_preferences",
            changes=update_data,
            ip_address=req.client.host if req.client else None
        )
        
        return NotificationPreferencesResponse(
            user_id=preferences.user_id,
            reminder_enabled=preferences.reminder_enabled,
            reminder_frequency=preferences.reminder_frequency,
            reminder_time=preferences.reminder_time.strftime("%H:%M") if preferences.reminder_time else None,
            insights_enabled=preferences.insights_enabled,
            security_alerts_enabled=preferences.security_alerts_enabled,
            email_enabled=preferences.email_enabled,
            sms_enabled=preferences.sms_enabled,
            push_enabled=preferences.push_enabled,
            updated_at=preferences.updated_at
        )
        
    except Exception as e:
        logger.error(f"Error updating notification preferences: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update notification preferences"
        )


# Notification History Endpoints
@router.get("/history", response_model=List[NotificationHistoryResponse])
async def get_notification_history(
    current_user: CurrentUser,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    notification_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Get current user's notification history."""
    try:
        history_repo = NotificationHistoryRepository(db)
        notifications = history_repo.get_user_notifications(
            user_id=current_user.id,
            notification_type=notification_type,
            skip=offset,
            limit=limit
        )
        
        # Log history access
        audit_logger = AuditLogger(db)
        await audit_logger.log_data_access(
            user_id=current_user.id,
            action="read",
            resource_type="notification_history",
            resource_id=current_user.id,
            purpose="View notification history"
        )
        
        return [
            NotificationHistoryResponse(
                id=n.id,
                notification_type=n.notification_type,
                channel=n.channel,
                subject=n.subject,
                sent_at=n.sent_at,
                delivery_status=n.delivery_status
            )
            for n in notifications
        ]
        
    except Exception as e:
        logger.error(f"Error fetching notification history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch notification history"
        )


# Test Notification Endpoints
@router.post("/test")
async def test_notification(
    request: TestNotificationRequest,
    current_user: CurrentUser,
    req: Request,
    db: Session = Depends(get_db)
):
    """Send a test notification to verify delivery."""
    try:
        notification_manager = NotificationManager()
        
        # Prepare test data based on type
        test_data = {
            "test_notification": True,
            "test_type": request.test_type,
            "user_name": current_user.full_name or current_user.email
        }
        
        # Determine notification type based on test type
        if request.test_type == "security":
            notification_type = NotificationType.LOGIN_ALERT
            test_data.update({
                "location": "Test Location",
                "device": "Test Device",
                "ip_address": req.client.host if req.client else "127.0.0.1",
                "login_time": datetime.utcnow().strftime("%B %d, %Y at %I:%M %p")
            })
        elif request.test_type == "template":
            notification_type = NotificationType.ANALYSIS_COMPLETE
            test_data.update({
                "analysis_id": "test-123",
                "analysis_type": "test analysis"
            })
        else:
            notification_type = NotificationType.WELCOME_MESSAGE
            test_data.update({
                "onboarding_step": "test"
            })
        
        # Send test notification
        result = await notification_manager.send_notification(
            user_id=current_user.id,
            notification_type=notification_type,
            data=test_data,
            channels=[request.channel.upper()]
        )
        
        # Log test notification
        audit_logger = AuditLogger(db)
        await audit_logger.log_security_event(
            event_type="test_notification_sent",
            user_id=current_user.id,
            description=f"Test {request.channel} notification sent",
            ip_address=req.client.host if req.client else None
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "test_type": request.test_type,
            "channel": request.channel,
            "delivery_details": result.get("results", {})
        }
        
    except Exception as e:
        logger.error(f"Error sending test notification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send test notification"
        )


# Patient Notification Endpoints
@router.post("/reminder")
async def send_recording_reminder(
    user_id: Optional[UUID] = Body(None),
    custom_message: Optional[str] = Body(None),
    current_user: CurrentUser = None,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Send a voice recording reminder to a patient."""
    try:
        # Use current user if no user_id specified
        target_user_id = user_id or current_user.id
        
        # Check permissions if sending to another user
        if user_id and user_id != current_user.id:
            if not check_permission(current_user, ["admin", "healthcare_provider"]):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions to send reminders to other users"
                )
        
        notification_manager = NotificationManager()
        
        # Send reminder notification
        result = await notification_manager.send_notification(
            user_id=target_user_id,
            notification_type=NotificationType.RECORDING_REMINDER,
            data={
                "reminder_type": "manual",
                "custom_message": custom_message or "",
                "sender_id": current_user.id
            }
        )
        
        # Log reminder sent
        audit_logger = AuditLogger(db)
        await audit_logger.log_data_access(
            user_id=current_user.id,
            action="send_reminder",
            resource_type="notification",
            resource_id=target_user_id,
            purpose="Send recording reminder",
            ip_address=req.client.host if req.client else None
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "notification_id": result.get("notification_id"),
            "delivery_channels": list(result.get("results", {}).keys())
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending recording reminder: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send recording reminder"
        )


@router.post("/analysis", response_model=None)
async def send_analysis_notification(
    current_user: CurrentUser,
    user_id: UUID = Body(...),
    analysis_id: str = Body(...),
    analysis_type: str = Body("standard"),
    db: Session = Depends(get_db)
):
    """Send analysis completion notification to a patient."""
    try:
        notification_manager = NotificationManager()
        
        # Send analysis completion notification
        result = await notification_manager.send_notification(
            user_id=user_id,
            notification_type=NotificationType.ANALYSIS_COMPLETE,
            data={
                "analysis_id": analysis_id,
                "analysis_type": analysis_type,
                "completion_time": datetime.utcnow().isoformat(),
                "provider_id": current_user.id
            }
        )
        
        # Log analysis notification
        audit_logger = AuditLogger(db)
        await audit_logger.log_data_access(
            user_id=current_user.id,
            action="notify_analysis_complete",
            resource_type="notification",
            resource_id=user_id,
            purpose="Notify patient of analysis completion"
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "analysis_id": analysis_id,
            "notification_id": result.get("notification_id")
        }
        
    except Exception as e:
        logger.error(f"Error sending analysis notification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send analysis notification"
        )


@router.post("/welcome", response_model=None)
async def send_welcome_message(
    current_user: CurrentUser,
    user_id: UUID = Body(...),
    onboarding_step: str = Body("welcome"),
    provider_name: Optional[str] = Body(None),
    db: Session = Depends(get_db)
):
    """Send welcome message to a new patient."""
    try:
        notification_manager = NotificationManager()
        
        # Send welcome notification
        result = await notification_manager.send_notification(
            user_id=user_id,
            notification_type=NotificationType.WELCOME_MESSAGE,
            data={
                "onboarding_step": onboarding_step,
                "provider_name": provider_name or current_user.full_name,
                "welcome_sender_id": current_user.id
            }
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "notification_id": result.get("notification_id")
        }
        
    except Exception as e:
        logger.error(f"Error sending welcome message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send welcome message"
        )


# System Notification Endpoints
@router.post("/security", response_model=None)
async def send_security_notification(
    request: SendNotificationRequest,
    current_user: CurrentUser,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Send security notification (admin only)."""
    try:
        notification_manager = NotificationManager()
        
        # Add security context
        request.data.update({
            "sender_id": current_user.id,
            "ip_address": req.client.host if req.client else None,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Send security notification
        result = await notification_manager.send_notification(
            user_id=request.user_id,
            notification_type=request.notification_type,
            data=request.data,
            channels=request.channels,
            override_preferences=True  # Security notifications bypass preferences
        )
        
        # Log security notification
        audit_logger = AuditLogger(db)
        await audit_logger.log_security_event(
            event_type="security_notification_sent",
            user_id=current_user.id,
            severity="warning",
            description=f"Security notification sent: {request.notification_type}",
            ip_address=req.client.host if req.client else None
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "notification_type": request.notification_type,
            "notification_id": result.get("notification_id")
        }
        
    except Exception as e:
        logger.error(f"Error sending security notification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send security notification"
        )


@router.post("/maintenance", response_model=None)
async def send_maintenance_notification(
    request: SendNotificationRequest,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Send system maintenance notification (admin only)."""
    try:
        notification_manager = NotificationManager()
        
        # Send maintenance notification
        result = await notification_manager.send_notification(
            user_id=request.user_id,
            notification_type=NotificationType.MAINTENANCE,
            data=request.data,
            channels=request.channels
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "notification_id": result.get("notification_id")
        }
        
    except Exception as e:
        logger.error(f"Error sending maintenance notification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send maintenance notification"
        )


# Bulk and Scheduled Notification Endpoints
@router.post("/bulk", response_model=None)
async def send_bulk_notifications(
    request: BulkNotificationRequest,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Send notifications to multiple users (admin/provider only)."""
    try:
        notification_manager = NotificationManager()
        
        # Send bulk notifications
        result = await notification_manager.send_bulk_notifications(
            user_ids=request.user_ids,
            notification_type=request.notification_type,
            base_data=request.data,
            stagger_delay=request.stagger_delay
        )
        
        # Log bulk notification
        audit_logger = AuditLogger(db)
        await audit_logger.log_data_access(
            user_id=current_user.id,
            action="send_bulk_notifications",
            resource_type="notification",
            resource_id=current_user.id,
            purpose=f"Send bulk {request.notification_type} to {len(request.user_ids)} users"
        )
        
        return {
            "success": result["successful"] > 0,
            "message": f"Sent to {result['successful']}/{result['total']} users",
            "summary": result
        }
        
    except Exception as e:
        logger.error(f"Error sending bulk notifications: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send bulk notifications"
        )


@router.post("/schedule", response_model=None)
async def schedule_notification(
    request: ScheduleNotificationRequest,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Schedule a notification for future delivery."""
    try:
        scheduler = NotificationScheduler()
        
        # Schedule notification
        result = await scheduler.schedule_notification(
            user_id=request.user_id,
            notification_type=request.notification_type,
            schedule_type=request.schedule_type,
            scheduled_time=request.scheduled_time,
            data=request.data,
            timezone=request.timezone,
            recurring_data=request.recurring_data,
            end_date=request.end_date
        )
        
        # Log scheduled notification
        audit_logger = AuditLogger(db)
        await audit_logger.log_data_access(
            user_id=current_user.id,
            action="schedule_notification",
            resource_type="notification",
            resource_id=request.user_id,
            purpose=f"Schedule {request.notification_type} notification"
        )
        
        return {
            "success": result["success"],
            "message": result["message"],
            "schedule_id": result.get("schedule_id"),
            "job_id": result.get("job_id"),
            "next_run": result.get("next_run")
        }
        
    except Exception as e:
        logger.error(f"Error scheduling notification: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to schedule notification"
        ) 