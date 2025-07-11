"""
Secure Push Notification Service for Healthcare Mobile Apps

Implements Firebase Cloud Messaging (FCM) for HIPAA-compliant push notifications
with PHI filtering and secure message delivery.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, messaging
from google.auth.transport.requests import Request
from google.oauth2 import service_account

from ..database.models import NotificationHistory, NotificationPreference, UserDevice, AuditLog
from ..database.database import SessionLocal
from config.notification_config import PushNotificationConfig

logger = logging.getLogger(__name__)


class PushNotificationService:
    """Firebase-based push notification service with healthcare compliance"""
    
    def __init__(self):
        self.config = PushNotificationConfig()
        self.project_id = self.config.FIREBASE_PROJECT_ID
        self.private_key_path = self.config.FIREBASE_PRIVATE_KEY_PATH
        self.phi_filtering = self.config.PUSH_PHI_FILTERING
        
        # Initialize Firebase Admin SDK
        self._initialize_firebase()
    
    def _initialize_firebase(self):
        """Initialize Firebase Admin SDK with service account"""
        try:
            if not firebase_admin._apps:
                cred = credentials.Certificate(self.private_key_path)
                firebase_admin.initialize_app(cred, {
                    'projectId': self.project_id,
                })
            logger.info("Firebase Admin SDK initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {str(e)}")
            raise
    
    async def send_push_notification(
        self,
        user_id: int,
        title: str,
        body: str,
        data: Optional[Dict[str, str]] = None,
        notification_type: str = "general",
        priority: str = "normal",
        contains_phi: bool = False,
        action_url: Optional[str] = None,
        badge_count: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Send push notification with PHI filtering
        
        Args:
            user_id: Target user ID
            title: Notification title
            body: Notification body
            data: Additional data payload
            notification_type: Type of notification
            priority: high or normal
            contains_phi: Whether content contains PHI
            action_url: Deep link URL
            badge_count: iOS badge count
        
        Returns:
            Dictionary with send status
        """
        try:
            # Check user preferences
            preferences = await self._get_user_preferences(user_id)
            if not preferences or not preferences.push_enabled:
                return {
                    "success": False,
                    "message": "Push notifications disabled by user",
                    "status": "blocked_by_preferences"
                }
            
            # Get user devices
            devices = await self._get_user_devices(user_id)
            if not devices:
                return {
                    "success": False,
                    "message": "No registered devices found",
                    "status": "no_devices"
                }
            
            # Filter PHI if required
            if contains_phi and self.phi_filtering:
                title, body = self._filter_phi_content(title, body)
            
            # Prepare notification
            notification = messaging.Notification(
                title=title,
                body=body
            )
            
            # Prepare data payload
            if data is None:
                data = {}
            
            data.update({
                'notification_type': notification_type,
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': str(user_id)
            })
            
            if action_url:
                data['action_url'] = action_url
            
            # Platform-specific configurations
            android_config = messaging.AndroidConfig(
                priority='high' if priority == 'high' else 'normal',
                notification=messaging.AndroidNotification(
                    icon='notification_icon',
                    color='#1976D2',
                    sound='default',
                    click_action='FLUTTER_NOTIFICATION_CLICK'
                )
            )
            
            apns_payload = {
                'aps': {
                    'alert': {
                        'title': title,
                        'body': body
                    },
                    'sound': 'default',
                    'content-available': 1
                }
            }
            
            if badge_count is not None:
                apns_payload['aps']['badge'] = badge_count
            
            apns_config = messaging.APNSConfig(
                payload=messaging.APNSPayload(apns_payload)
            )
            
            # Send to all user devices
            results = []
            for device in devices:
                result = await self._send_to_device(
                    device_token=device.device_token,
                    notification=notification,
                    data=data,
                    android_config=android_config,
                    apns_config=apns_config,
                    device_id=device.id
                )
                results.append(result)
            
            # Log notification
            successful_sends = [r for r in results if r['success']]
            await self._log_notification(
                user_id=user_id,
                notification_type=notification_type,
                status='delivered' if successful_sends else 'failed',
                device_count=len(devices),
                successful_count=len(successful_sends),
                contains_phi=contains_phi
            )
            
            # Audit log for PHI notifications
            if contains_phi:
                await self._create_audit_log(
                    user_id=user_id,
                    action="phi_push_notification",
                    details={
                        "type": notification_type,
                        "filtered": self.phi_filtering,
                        "devices": len(devices)
                    }
                )
            
            return {
                "success": len(successful_sends) > 0,
                "message": f"Sent to {len(successful_sends)}/{len(devices)} devices",
                "results": results,
                "total_devices": len(devices),
                "successful_sends": len(successful_sends)
            }
            
        except Exception as e:
            logger.error(f"Push notification error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to send push notification: {str(e)}",
                "status": "error"
            }
    
    async def _send_to_device(
        self,
        device_token: str,
        notification: messaging.Notification,
        data: Dict[str, str],
        android_config: messaging.AndroidConfig,
        apns_config: messaging.APNSConfig,
        device_id: int
    ) -> Dict[str, Any]:
        """Send notification to specific device"""
        try:
            message = messaging.Message(
                notification=notification,
                data=data,
                android=android_config,
                apns=apns_config,
                token=device_token
            )
            
            # Send message
            response = messaging.send(message)
            
            # Update device last_used timestamp
            await self._update_device_activity(device_id)
            
            return {
                "success": True,
                "device_id": device_id,
                "message_id": response,
                "device_token": device_token[:10] + "..."  # Partial token for privacy
            }
            
        except messaging.UnregisteredError:
            # Device token is invalid, mark as inactive
            await self._mark_device_inactive(device_id)
            return {
                "success": False,
                "device_id": device_id,
                "error": "unregistered_device"
            }
        except Exception as e:
            logger.error(f"Device send error: {str(e)}")
            return {
                "success": False,
                "device_id": device_id,
                "error": str(e)
            }
    
    def _filter_phi_content(self, title: str, body: str) -> tuple:
        """Filter PHI content from push notifications"""
        # Generic messages that don't expose PHI
        filtered_messages = {
            "analysis_complete": ("Voice Analysis Ready", "Your analysis is complete. Open the app to view results."),
            "recording_reminder": ("Recording Reminder", "It's time for your scheduled recording."),
            "provider_message": ("New Message", "You have a new message from your provider."),
            "appointment_reminder": ("Appointment Reminder", "You have an upcoming appointment."),
            "file_shared": ("File Shared", "A file has been shared with you."),
            "default": ("Healthcare Update", "You have a new update. Open the app for details.")
        }
        
        # Check if we have a predefined filtered message
        for key, (filtered_title, filtered_body) in filtered_messages.items():
            if key in title.lower() or key in body.lower():
                return filtered_title, filtered_body
        
        # Default filtering
        return filtered_messages["default"]
    
    async def send_topic_notification(
        self,
        topic: str,
        title: str,
        body: str,
        data: Optional[Dict[str, str]] = None,
        notification_type: str = "broadcast"
    ) -> Dict[str, Any]:
        """Send notification to all subscribers of a topic"""
        try:
            # Ensure no PHI in broadcast messages
            if self._contains_potential_phi(title + " " + body):
                return {
                    "success": False,
                    "message": "Broadcast messages cannot contain PHI",
                    "status": "phi_violation"
                }
            
            notification = messaging.Notification(
                title=title,
                body=body
            )
            
            if data is None:
                data = {}
            
            data.update({
                'notification_type': notification_type,
                'timestamp': datetime.utcnow().isoformat(),
                'topic': topic
            })
            
            message = messaging.Message(
                notification=notification,
                data=data,
                topic=topic
            )
            
            response = messaging.send(message)
            
            # Log broadcast notification
            await self._log_broadcast_notification(
                topic=topic,
                notification_type=notification_type,
                message_id=response
            )
            
            return {
                "success": True,
                "message": f"Broadcast sent to topic: {topic}",
                "message_id": response,
                "topic": topic
            }
            
        except Exception as e:
            logger.error(f"Topic notification error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to send topic notification: {str(e)}",
                "status": "error"
            }
    
    async def subscribe_to_topic(self, user_id: int, topic: str) -> Dict[str, Any]:
        """Subscribe user devices to a topic"""
        try:
            devices = await self._get_user_devices(user_id)
            if not devices:
                return {
                    "success": False,
                    "message": "No registered devices found"
                }
            
            tokens = [device.device_token for device in devices]
            response = messaging.subscribe_to_topic(tokens, topic)
            
            return {
                "success": True,
                "message": f"Subscribed {response.success_count} devices to {topic}",
                "success_count": response.success_count,
                "failure_count": response.failure_count
            }
            
        except Exception as e:
            logger.error(f"Topic subscription error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to subscribe to topic: {str(e)}"
            }
    
    async def unsubscribe_from_topic(self, user_id: int, topic: str) -> Dict[str, Any]:
        """Unsubscribe user devices from a topic"""
        try:
            devices = await self._get_user_devices(user_id)
            if not devices:
                return {
                    "success": False,
                    "message": "No registered devices found"
                }
            
            tokens = [device.device_token for device in devices]
            response = messaging.unsubscribe_from_topic(tokens, topic)
            
            return {
                "success": True,
                "message": f"Unsubscribed {response.success_count} devices from {topic}",
                "success_count": response.success_count,
                "failure_count": response.failure_count
            }
            
        except Exception as e:
            logger.error(f"Topic unsubscription error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to unsubscribe from topic: {str(e)}"
            }
    
    def _contains_potential_phi(self, text: str) -> bool:
        """Check if text potentially contains PHI"""
        phi_indicators = [
            'diagnosis', 'treatment', 'medication', 'prescription',
            'blood', 'pressure', 'glucose', 'test result', 'lab',
            'symptom', 'condition', 'disease', 'disorder'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in phi_indicators)
    
    async def _get_user_preferences(self, user_id: int) -> Optional[NotificationPreference]:
        """Get user notification preferences"""
        try:
            return db_session.query(NotificationPreference).filter_by(
                user_id=user_id
            ).first()
        except Exception as e:
            logger.error(f"Error fetching preferences: {str(e)}")
            return None
    
    async def _get_user_devices(self, user_id: int) -> List[UserDevice]:
        """Get active user devices"""
        try:
            return db_session.query(UserDevice).filter_by(
                user_id=user_id,
                is_active=True
            ).all()
        except Exception as e:
            logger.error(f"Error fetching devices: {str(e)}")
            return []
    
    async def _update_device_activity(self, device_id: int):
        """Update device last activity timestamp"""
        try:
            device = db_session.query(UserDevice).get(device_id)
            if device:
                device.last_used_at = datetime.utcnow()
                db_session.commit()
        except Exception as e:
            logger.error(f"Error updating device activity: {str(e)}")
    
    async def _mark_device_inactive(self, device_id: int):
        """Mark device as inactive"""
        try:
            device = db_session.query(UserDevice).get(device_id)
            if device:
                device.is_active = False
                device.updated_at = datetime.utcnow()
                db_session.commit()
        except Exception as e:
            logger.error(f"Error marking device inactive: {str(e)}")
    
    async def _log_notification(
        self,
        user_id: int,
        notification_type: str,
        status: str,
        device_count: int,
        successful_count: int,
        contains_phi: bool
    ):
        """Log push notification in history"""
        try:
            notification = NotificationHistory(
                user_id=user_id,
                notification_type=notification_type,
                channel='push',
                recipient=f"{device_count} devices",
                status=status,
                sent_at=datetime.utcnow(),
                delivered_at=datetime.utcnow() if status == 'delivered' else None,
                contains_phi=contains_phi,
                metadata=json.dumps({
                    'device_count': device_count,
                    'successful_count': successful_count,
                    'phi_filtered': contains_phi and self.phi_filtering
                })
            )
            db_session.add(notification)
            db_session.commit()
        except Exception as e:
            logger.error(f"Error logging notification: {str(e)}")
    
    async def _log_broadcast_notification(
        self,
        topic: str,
        notification_type: str,
        message_id: str
    ):
        """Log broadcast notification"""
        try:
            notification = NotificationHistory(
                user_id=None,  # Broadcast has no specific user
                notification_type=notification_type,
                channel='push',
                recipient=f"topic:{topic}",
                status='delivered',
                sent_at=datetime.utcnow(),
                delivered_at=datetime.utcnow(),
                contains_phi=False,  # Broadcasts never contain PHI
                metadata=json.dumps({
                    'topic': topic,
                    'message_id': message_id,
                    'broadcast': True
                })
            )
            db_session.add(notification)
            db_session.commit()
        except Exception as e:
            logger.error(f"Error logging broadcast: {str(e)}")
    
    async def _create_audit_log(self, user_id: int, action: str, details: Dict[str, Any]):
        """Create audit log entry for compliance"""
        try:
            audit = AuditLog(
                user_id=user_id,
                action=action,
                resource_type='notification',
                resource_id=None,
                ip_address=None,
                user_agent='PushNotificationService',
                details=json.dumps(details),
                created_at=datetime.utcnow()
            )
            db_session.add(audit)
            db_session.commit()
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")