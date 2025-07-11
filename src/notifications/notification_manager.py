"""
Central Notification Manager for Healthcare System

Orchestrates notification delivery across channels (email, SMS, push),
handles channel preferences, fallback mechanisms, and audit trails.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum

from .email_service import EmailService
from .sms_service import SMSService
from .push_notifications import PushNotificationService
from .notif_templates import (
    patient_templates,
    provider_templates,
    security_templates
)
from ..database.models import (
    NotificationPreference,
    NotificationHistory,
    User,
    AuditLog
)
from ..database.database import SessionLocal
from config.notification_config import NotificationConfig

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """Available notification channels"""
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"


class NotificationType(Enum):
    """Types of notifications in the healthcare system"""
    # Patient notifications
    RECORDING_REMINDER = "recording_reminder"
    ANALYSIS_COMPLETE = "analysis_complete"
    WELCOME_MESSAGE = "welcome_message"
    APPOINTMENT_REMINDER = "appointment_reminder"
    
    # Provider notifications
    FILE_SHARED = "file_shared"
    PATIENT_ALERT = "patient_alert"
    NEW_PATIENT = "new_patient"
    
    # Security notifications
    LOGIN_ALERT = "login_alert"
    PASSWORD_CHANGED = "password_changed"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    
    # System notifications
    MAINTENANCE = "maintenance"
    FEATURE_UPDATE = "feature_update"
    COMPLIANCE_UPDATE = "compliance_update"


class NotificationManager:
    """Central orchestrator for all notifications"""
    
    def __init__(self):
        self.config = NotificationConfig()
        self.email_service = EmailService()
        self.sms_service = SMSService()
        self.push_service = PushNotificationService()
        
        # Rate limiting configuration
        self.rate_limit = self.config.NOTIFICATION_RATE_LIMIT
        self.retry_attempts = self.config.NOTIFICATION_RETRY_ATTEMPTS
        
        # Channel priority order for fallback
        self.channel_priority = [
            NotificationChannel.PUSH,
            NotificationChannel.EMAIL,
            NotificationChannel.SMS
        ]
    
    async def send_notification(
        self,
        user_id: int,
        notification_type: Union[str, NotificationType],
        data: Dict[str, Any],
        override_preferences: bool = False,
        channels: Optional[List[NotificationChannel]] = None,
        priority: str = "normal"
    ) -> Dict[str, Any]:
        """
        Send notification through appropriate channels
        
        Args:
            user_id: Target user ID
            notification_type: Type of notification
            data: Notification data and template variables
            override_preferences: Bypass user preferences (for critical notifications)
            channels: Specific channels to use (overrides preferences)
            priority: Notification priority (high, normal, low)
        
        Returns:
            Dictionary with send results for each channel
        """
        try:
            # Convert string to enum if needed
            if isinstance(notification_type, str):
                notification_type = NotificationType(notification_type)
            
            # Get user and preferences
            user = await self._get_user(user_id)
            if not user:
                return {
                    "success": False,
                    "message": "User not found",
                    "results": {}
                }
            
            # Check rate limiting
            if not await self._check_rate_limit(user_id):
                return {
                    "success": False,
                    "message": "Rate limit exceeded",
                    "results": {}
                }
            
            # Determine channels to use
            if channels:
                selected_channels = channels
            else:
                selected_channels = await self._get_user_channels(
                    user_id,
                    notification_type,
                    override_preferences
                )
            
            # Get notification content
            content = await self._get_notification_content(
                notification_type,
                data,
                user
            )
            
            # Send through each channel
            results = {}
            success_count = 0
            
            for channel in selected_channels:
                result = await self._send_through_channel(
                    channel=channel,
                    user=user,
                    content=content,
                    notification_type=notification_type,
                    priority=priority
                )
                
                results[channel.value] = result
                if result.get("success"):
                    success_count += 1
                    
                    # If successful, no need for fallback
                    if not self.config.SEND_TO_ALL_CHANNELS:
                        break
            
            # Try fallback channels if all failed
            if success_count == 0 and not override_preferences:
                fallback_result = await self._try_fallback_channels(
                    user=user,
                    content=content,
                    notification_type=notification_type,
                    tried_channels=selected_channels
                )
                if fallback_result:
                    results.update(fallback_result)
                    success_count = sum(1 for r in results.values() if r.get("success"))
            
            # Create comprehensive audit log
            await self._create_notification_audit(
                user_id=user_id,
                notification_type=notification_type,
                results=results,
                data=data
            )
            
            return {
                "success": success_count > 0,
                "message": f"Sent to {success_count} channel(s)",
                "results": results,
                "notification_id": await self._generate_notification_id()
            }
            
        except Exception as e:
            logger.error(f"Notification error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to send notification: {str(e)}",
                "results": {}
            }
    
    async def _send_through_channel(
        self,
        channel: NotificationChannel,
        user: User,
        content: Dict[str, Any],
        notification_type: NotificationType,
        priority: str
    ) -> Dict[str, Any]:
        """Send notification through specific channel"""
        try:
            if channel == NotificationChannel.EMAIL:
                return await self.email_service.send_email(
                    to_email=user.email,
                    subject=content["subject"],
                    body=content["body"],
                    template_name=content.get("template"),
                    template_data=content.get("template_data"),
                    contains_phi=content.get("contains_phi", False),
                    user_id=user.id,
                    notification_type=notification_type.value
                )
                
            elif channel == NotificationChannel.SMS:
                return await self.sms_service.send_sms(
                    to_phone=user.phone_number,
                    message=content["sms_body"],
                    user_id=user.id,
                    notification_type=notification_type.value,
                    contains_phi=content.get("contains_phi", False)
                )
                
            elif channel == NotificationChannel.PUSH:
                return await self.push_service.send_push_notification(
                    user_id=user.id,
                    title=content["push_title"],
                    body=content["push_body"],
                    data=content.get("push_data"),
                    notification_type=notification_type.value,
                    priority=priority,
                    contains_phi=content.get("contains_phi", False),
                    action_url=content.get("action_url")
                )
                
            elif channel == NotificationChannel.IN_APP:
                # In-app notifications would be stored in database
                # and retrieved by the app
                return await self._create_in_app_notification(
                    user_id=user.id,
                    content=content,
                    notification_type=notification_type
                )
                
            else:
                return {
                    "success": False,
                    "message": f"Unknown channel: {channel}"
                }
                
        except Exception as e:
            logger.error(f"Channel send error ({channel}): {str(e)}")
            return {
                "success": False,
                "message": str(e),
                "channel": channel.value
            }
    
    async def _get_notification_content(
        self,
        notification_type: NotificationType,
        data: Dict[str, Any],
        user: User
    ) -> Dict[str, Any]:
        """Get notification content from templates"""
        
        # Determine which template module to use
        if notification_type.value.startswith(("recording_", "analysis_", "welcome_", "appointment_")):
            template_module = patient_templates
        elif notification_type.value.startswith(("file_", "patient_alert", "new_patient")):
            template_module = provider_templates
        elif notification_type.value.startswith(("login_", "password_", "suspicious_")):
            template_module = security_templates
        else:
            # System notifications
            template_module = patient_templates
        
        # Get template
        template_func = getattr(template_module, f"get_{notification_type.value}_template", None)
        if not template_func:
            raise ValueError(f"No template found for {notification_type.value}")
        
        # Generate content
        content = template_func(user, data)
        
        # Add common fields
        content.update({
            "user_name": user.full_name or user.username,
            "notification_type": notification_type.value,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return content
    
    async def _get_user_channels(
        self,
        user_id: int,
        notification_type: NotificationType,
        override_preferences: bool
    ) -> List[NotificationChannel]:
        """Determine which channels to use for notification"""
        
        # Critical notifications always use all available channels
        critical_types = [
            NotificationType.SUSPICIOUS_ACTIVITY,
            NotificationType.PASSWORD_CHANGED,
            NotificationType.LOGIN_ALERT
        ]
        
        if notification_type in critical_types or override_preferences:
            return [
                NotificationChannel.EMAIL,
                NotificationChannel.SMS,
                NotificationChannel.PUSH
            ]
        
        # Get user preferences
        preferences = db_session.query(NotificationPreference).filter_by(
            user_id=user_id
        ).first()
        
        if not preferences:
            # Default to email only
            return [NotificationChannel.EMAIL]
        
        # Build channel list based on preferences
        channels = []
        
        if preferences.email_enabled:
            channels.append(NotificationChannel.EMAIL)
        if preferences.sms_enabled:
            channels.append(NotificationChannel.SMS)
        if preferences.push_enabled:
            channels.append(NotificationChannel.PUSH)
        if preferences.in_app_enabled:
            channels.append(NotificationChannel.IN_APP)
        
        # Check notification-specific preferences
        type_preferences = json.loads(preferences.notification_types or '{}')
        if notification_type.value in type_preferences:
            type_channels = type_preferences[notification_type.value].get("channels", [])
            if type_channels:
                channels = [NotificationChannel(ch) for ch in type_channels]
        
        return channels if channels else [NotificationChannel.EMAIL]
    
    async def _try_fallback_channels(
        self,
        user: User,
        content: Dict[str, Any],
        notification_type: NotificationType,
        tried_channels: List[NotificationChannel]
    ) -> Dict[str, Any]:
        """Try fallback channels if primary channels failed"""
        results = {}
        
        for channel in self.channel_priority:
            if channel not in tried_channels:
                # Check if user has this channel configured
                if channel == NotificationChannel.EMAIL and user.email:
                    result = await self._send_through_channel(
                        channel=channel,
                        user=user,
                        content=content,
                        notification_type=notification_type,
                        priority="normal"
                    )
                    results[channel.value] = result
                    if result.get("success"):
                        break
                        
                elif channel == NotificationChannel.SMS and user.phone_number:
                    result = await self._send_through_channel(
                        channel=channel,
                        user=user,
                        content=content,
                        notification_type=notification_type,
                        priority="normal"
                    )
                    results[channel.value] = result
                    if result.get("success"):
                        break
        
        return results
    
    async def _check_rate_limit(self, user_id: int) -> bool:
        """Check if user has exceeded notification rate limit"""
        try:
            # Count recent notifications
            cutoff_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
            
            recent_count = db_session.query(NotificationHistory).filter(
                NotificationHistory.user_id == user_id,
                NotificationHistory.sent_at >= cutoff_time
            ).count()
            
            return recent_count < self.rate_limit
            
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return True  # Allow on error
    
    async def _create_in_app_notification(
        self,
        user_id: int,
        content: Dict[str, Any],
        notification_type: NotificationType
    ) -> Dict[str, Any]:
        """Create in-app notification record"""
        try:
            # This would create a record in an in_app_notifications table
            # For now, we'll just log it
            notification = NotificationHistory(
                user_id=user_id,
                notification_type=notification_type.value,
                channel='in_app',
                recipient=str(user_id),
                status='delivered',
                sent_at=datetime.utcnow(),
                delivered_at=datetime.utcnow(),
                contains_phi=content.get("contains_phi", False),
                metadata=json.dumps({
                    'title': content.get("subject"),
                    'body': content.get("body"),
                    'read': False
                })
            )
            db_session.add(notification)
            db_session.commit()
            
            return {
                "success": True,
                "message": "In-app notification created",
                "notification_id": notification.id
            }
            
        except Exception as e:
            logger.error(f"In-app notification error: {str(e)}")
            return {
                "success": False,
                "message": str(e)
            }
    
    async def _get_user(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        try:
            return db_session.query(User).get(user_id)
        except Exception as e:
            logger.error(f"Error fetching user: {str(e)}")
            return None
    
    async def _generate_notification_id(self) -> str:
        """Generate unique notification ID"""
        import uuid
        return str(uuid.uuid4())
    
    async def _create_notification_audit(
        self,
        user_id: int,
        notification_type: NotificationType,
        results: Dict[str, Any],
        data: Dict[str, Any]
    ):
        """Create comprehensive audit log for notification"""
        try:
            # Count successful channels
            successful_channels = [
                channel for channel, result in results.items()
                if result.get("success")
            ]
            
            audit = AuditLog(
                user_id=user_id,
                action="notification_sent",
                resource_type='notification',
                resource_id=notification_type.value,
                ip_address=None,
                user_agent='NotificationManager',
                details=json.dumps({
                    'notification_type': notification_type.value,
                    'channels_attempted': list(results.keys()),
                    'channels_successful': successful_channels,
                    'contains_phi': data.get('contains_phi', False),
                    'results': results
                }),
                created_at=datetime.utcnow()
            )
            db_session.add(audit)
            db_session.commit()
            
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")
    
    async def send_bulk_notifications(
        self,
        user_ids: List[int],
        notification_type: Union[str, NotificationType],
        base_data: Dict[str, Any],
        user_specific_data: Optional[Dict[int, Dict[str, Any]]] = None,
        stagger_delay: float = 0.1
    ) -> Dict[str, Any]:
        """
        Send notifications to multiple users
        
        Args:
            user_ids: List of user IDs
            notification_type: Type of notification
            base_data: Common data for all notifications
            user_specific_data: User-specific data overrides
            stagger_delay: Delay between sends (seconds)
        
        Returns:
            Summary of bulk send results
        """
        results = {
            "total": len(user_ids),
            "successful": 0,
            "failed": 0,
            "details": []
        }
        
        for user_id in user_ids:
            # Merge base data with user-specific data
            data = base_data.copy()
            if user_specific_data and user_id in user_specific_data:
                data.update(user_specific_data[user_id])
            
            # Send notification
            result = await self.send_notification(
                user_id=user_id,
                notification_type=notification_type,
                data=data
            )
            
            if result["success"]:
                results["successful"] += 1
            else:
                results["failed"] += 1
            
            results["details"].append({
                "user_id": user_id,
                "success": result["success"],
                "channels": result.get("results", {})
            })
            
            # Stagger sends to avoid overload
            if stagger_delay > 0:
                await asyncio.sleep(stagger_delay)
        
        return results
    
    async def get_notification_status(
        self,
        notification_id: Optional[str] = None,
        user_id: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get notification status and history"""
        try:
            query = db_session.query(NotificationHistory)
            
            if notification_id:
                # Search by notification ID in metadata
                query = query.filter(
                    NotificationHistory.metadata.like(f'%{notification_id}%')
                )
            
            if user_id:
                query = query.filter(NotificationHistory.user_id == user_id)
            
            if start_date:
                query = query.filter(NotificationHistory.sent_at >= start_date)
            
            if end_date:
                query = query.filter(NotificationHistory.sent_at <= end_date)
            
            notifications = query.order_by(NotificationHistory.sent_at.desc()).limit(100).all()
            
            return [
                {
                    "id": n.id,
                    "user_id": n.user_id,
                    "type": n.notification_type,
                    "channel": n.channel,
                    "status": n.status,
                    "sent_at": n.sent_at.isoformat() if n.sent_at else None,
                    "delivered_at": n.delivered_at.isoformat() if n.delivered_at else None,
                    "contains_phi": n.contains_phi,
                    "metadata": json.loads(n.metadata) if n.metadata else {}
                }
                for n in notifications
            ]
            
        except Exception as e:
            logger.error(f"Error fetching notification status: {str(e)}")
            return []
    
    async def retry_failed_notifications(
        self,
        time_window_hours: int = 24,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """Retry recently failed notifications"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            # Find failed notifications
            failed_notifications = db_session.query(NotificationHistory).filter(
                NotificationHistory.status == 'failed',
                NotificationHistory.sent_at >= cutoff_time
            ).all()
            
            results = {
                "total_failed": len(failed_notifications),
                "retried": 0,
                "successful": 0
            }
            
            for notification in failed_notifications:
                # Check retry count
                metadata = json.loads(notification.metadata or '{}')
                retry_count = metadata.get('retry_count', 0)
                
                if retry_count >= max_retries:
                    continue
                
                # Attempt retry
                user = await self._get_user(notification.user_id)
                if not user:
                    continue
                
                # Recreate notification data
                data = {
                    "retry": True,
                    "original_id": notification.id,
                    "retry_count": retry_count + 1
                }
                
                result = await self.send_notification(
                    user_id=notification.user_id,
                    notification_type=notification.notification_type,
                    data=data,
                    channels=[NotificationChannel(notification.channel)]
                )
                
                results["retried"] += 1
                if result["success"]:
                    results["successful"] += 1
                
                # Update original notification metadata
                metadata['retry_count'] = retry_count + 1
                metadata['last_retry'] = datetime.utcnow().isoformat()
                notification.metadata = json.dumps(metadata)
                db_session.commit()
            
            return results
            
        except Exception as e:
            logger.error(f"Error retrying notifications: {str(e)}")
            return {
                "error": str(e),
                "retried": 0,
                "successful": 0
            }