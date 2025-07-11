"""
HIPAA-compliant SMS Service for Healthcare Notifications

Implements Twilio SMS API with encryption for sensitive content,
opt-in/opt-out management, and delivery tracking.
"""

import os
import json
import logging
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import hashlib
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
from cryptography.fernet import Fernet

from ..database.models import NotificationHistory, NotificationPreference, SMSOptInOut, AuditLog
from ..database.database import SessionLocal
from config.notification_config import SMSConfig

logger = logging.getLogger(__name__)


class SMSService:
    """HIPAA-compliant SMS service for healthcare notifications"""
    
    # SMS keywords for opt-in/opt-out
    OPT_IN_KEYWORDS = ['START', 'YES', 'UNSTOP', 'SUBSCRIBE', 'OPTIN']
    OPT_OUT_KEYWORDS = ['STOP', 'END', 'CANCEL', 'UNSUBSCRIBE', 'QUIT', 'OPTOUT']
    HELP_KEYWORDS = ['HELP', 'INFO']
    
    def __init__(self):
        self.config = SMSConfig()
        self.account_sid = self.config.SMS_ACCOUNT_SID
        self.auth_token = self.config.SMS_AUTH_TOKEN
        self.from_number = self.config.SMS_FROM_NUMBER
        self.encryption_required = self.config.SMS_ENCRYPTION_REQUIRED
        
        # Initialize Twilio client
        self.client = Client(self.account_sid, self.auth_token)
        
        # Initialize encryption for sensitive content
        self.encryption_key = self.config.SMS_ENCRYPTION_KEY
        self.cipher_suite = Fernet(self.encryption_key.encode()) if self.encryption_key else None
        
        # SMS settings
        self.max_length = 160  # Standard SMS length
        self.secure_link_base = self.config.SECURE_LINK_BASE_URL
    
    async def send_sms(
        self,
        to_phone: str,
        message: str,
        user_id: Optional[int] = None,
        notification_type: str = "general",
        contains_phi: bool = False,
        requires_consent: bool = True
    ) -> Dict[str, Any]:
        """
        Send HIPAA-compliant SMS with encryption for sensitive content
        
        Args:
            to_phone: Recipient phone number (E.164 format)
            message: SMS message content
            user_id: User ID for tracking
            notification_type: Type of notification
            contains_phi: Whether message contains PHI
            requires_consent: Whether to check for opt-in consent
        
        Returns:
            Dictionary with send status
        """
        try:
            # Validate phone number
            if not self._validate_phone_number(to_phone):
                return {
                    "success": False,
                    "message": "Invalid phone number format",
                    "status": "invalid_number"
                }
            
            # Check user preferences if user_id provided
            if user_id:
                preferences = await self._get_user_preferences(user_id)
                if not preferences or not preferences.sms_enabled:
                    return {
                        "success": False,
                        "message": "SMS notifications disabled by user",
                        "status": "blocked_by_preferences"
                    }
            
            # Check opt-in status if consent required
            if requires_consent:
                opt_in_status = await self._check_opt_in_status(to_phone)
                if not opt_in_status:
                    return {
                        "success": False,
                        "message": "User has not opted in to SMS notifications",
                        "status": "no_consent"
                    }
            
            # Handle PHI content
            if contains_phi and self.encryption_required:
                message = await self._create_secure_message(message, user_id)
            
            # Ensure message fits SMS limits
            message = self._truncate_message(message)
            
            # Add compliance footer
            message = self._add_compliance_footer(message, notification_type)
            
            # Send SMS via Twilio
            result = await self._send_twilio_sms(to_phone, message)
            
            # Log notification
            await self._log_notification(
                user_id=user_id,
                to_phone=to_phone,
                notification_type=notification_type,
                status=result['status'],
                contains_phi=contains_phi,
                message_sid=result.get('sid')
            )
            
            # Audit log for PHI messages
            if contains_phi:
                await self._create_audit_log(
                    user_id=user_id,
                    action="phi_sms_sent",
                    details={
                        "to": self._mask_phone_number(to_phone),
                        "type": notification_type,
                        "encrypted": self.encryption_required
                    }
                )
            
            return {
                "success": result['status'] in ['delivered', 'sent', 'queued'],
                "message": "SMS sent successfully",
                "status": result['status'],
                "message_sid": result.get('sid')
            }
            
        except Exception as e:
            logger.error(f"SMS send error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to send SMS: {str(e)}",
                "status": "error"
            }
    
    async def _send_twilio_sms(self, to_phone: str, message: str) -> Dict[str, Any]:
        """Send SMS via Twilio API"""
        try:
            message_obj = self.client.messages.create(
                body=message,
                from_=self.from_number,
                to=to_phone,
                status_callback=self.config.SMS_STATUS_CALLBACK_URL
            )
            
            return {
                "status": message_obj.status,
                "sid": message_obj.sid,
                "price": message_obj.price,
                "price_unit": message_obj.price_unit
            }
            
        except TwilioRestException as e:
            logger.error(f"Twilio error: {e.msg}")
            return {
                "status": "failed",
                "error": e.msg,
                "code": e.code
            }
    
    async def _create_secure_message(self, original_message: str, user_id: Optional[int]) -> str:
        """Create secure message for PHI content"""
        # Generate secure token
        token = self._generate_secure_token(user_id)
        
        # Store encrypted message
        encrypted_content = self.cipher_suite.encrypt(original_message.encode())
        
        # Store in secure message store (implementation depends on your storage solution)
        await self._store_secure_message(token, encrypted_content, user_id)
        
        # Return link to secure content
        secure_url = f"{self.secure_link_base}/secure/{token}"
        return f"Voice Biomarker: You have a secure message. View it at: {secure_url}"
    
    def _generate_secure_token(self, user_id: Optional[int]) -> str:
        """Generate secure token for message retrieval"""
        data = f"{user_id}:{datetime.utcnow().isoformat()}:{os.urandom(16).hex()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    async def _store_secure_message(self, token: str, encrypted_content: bytes, user_id: Optional[int]):
        """Store encrypted message for secure retrieval"""
        # This would typically store in a secure database or cache
        # Implementation depends on your storage solution
        pass
    
    def _truncate_message(self, message: str) -> str:
        """Truncate message to fit SMS limits"""
        if len(message) <= self.max_length:
            return message
        
        # Leave room for "..." at the end
        return message[:self.max_length - 3] + "..."
    
    def _add_compliance_footer(self, message: str, notification_type: str) -> str:
        """Add required compliance footer to messages"""
        footers = {
            "marketing": "\nReply STOP to unsubscribe",
            "appointment": "\nReply STOP to opt out",
            "general": "\nReply HELP for info"
        }
        
        footer = footers.get(notification_type, footers["general"])
        
        # Check if adding footer would exceed limit
        if len(message) + len(footer) > self.max_length:
            # Truncate message to make room for footer
            message = message[:self.max_length - len(footer) - 3] + "..."
        
        return message + footer
    
    async def process_incoming_sms(self, from_phone: str, body: str) -> Dict[str, Any]:
        """Process incoming SMS for opt-in/opt-out keywords"""
        try:
            keyword = body.strip().upper().split()[0] if body else ""
            
            if keyword in self.OPT_OUT_KEYWORDS:
                return await self._process_opt_out(from_phone)
            elif keyword in self.OPT_IN_KEYWORDS:
                return await self._process_opt_in(from_phone)
            elif keyword in self.HELP_KEYWORDS:
                return await self._send_help_message(from_phone)
            else:
                # Log unrecognized message
                logger.info(f"Unrecognized SMS from {from_phone}: {body}")
                return {"success": True, "action": "logged"}
                
        except Exception as e:
            logger.error(f"Error processing incoming SMS: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _process_opt_out(self, phone_number: str) -> Dict[str, Any]:
        """Process opt-out request"""
        try:
            # Record opt-out
            opt_out = SMSOptInOut(
                phone_number=phone_number,
                status='opted_out',
                timestamp=datetime.utcnow(),
                source='sms_keyword'
            )
            db_session.add(opt_out)
            
            # Update user preferences if user exists
            user = await self._get_user_by_phone(phone_number)
            if user:
                preferences = await self._get_user_preferences(user.id)
                if preferences:
                    preferences.sms_enabled = False
                    preferences.updated_at = datetime.utcnow()
            
            db_session.commit()
            
            # Send confirmation
            await self.send_sms(
                to_phone=phone_number,
                message="You've been unsubscribed from Voice Biomarker SMS. Reply START to resubscribe.",
                requires_consent=False
            )
            
            return {"success": True, "action": "opted_out"}
            
        except Exception as e:
            logger.error(f"Error processing opt-out: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _process_opt_in(self, phone_number: str) -> Dict[str, Any]:
        """Process opt-in request"""
        try:
            # Record opt-in
            opt_in = SMSOptInOut(
                phone_number=phone_number,
                status='opted_in',
                timestamp=datetime.utcnow(),
                source='sms_keyword'
            )
            db_session.add(opt_in)
            
            # Update user preferences if user exists
            user = await self._get_user_by_phone(phone_number)
            if user:
                preferences = await self._get_user_preferences(user.id)
                if preferences:
                    preferences.sms_enabled = True
                    preferences.updated_at = datetime.utcnow()
            
            db_session.commit()
            
            # Send confirmation
            await self.send_sms(
                to_phone=phone_number,
                message="Welcome to Voice Biomarker SMS notifications. You'll receive important updates about your health. Reply STOP to unsubscribe anytime.",
                requires_consent=False
            )
            
            return {"success": True, "action": "opted_in"}
            
        except Exception as e:
            logger.error(f"Error processing opt-in: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _send_help_message(self, phone_number: str) -> Dict[str, Any]:
        """Send help message"""
        try:
            await self.send_sms(
                to_phone=phone_number,
                message="Voice Biomarker: Reply STOP to unsubscribe, START to subscribe. Msg&data rates may apply. Privacy: voicebiomarker.com/privacy",
                requires_consent=False
            )
            return {"success": True, "action": "help_sent"}
        except Exception as e:
            logger.error(f"Error sending help message: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _validate_phone_number(self, phone_number: str) -> bool:
        """Validate phone number format (E.164)"""
        pattern = re.compile(r'^\+[1-9]\d{1,14}$')
        return bool(pattern.match(phone_number))
    
    def _mask_phone_number(self, phone_number: str) -> str:
        """Mask phone number for privacy in logs"""
        if len(phone_number) > 6:
            return phone_number[:3] + "****" + phone_number[-3:]
        return "****"
    
    async def _check_opt_in_status(self, phone_number: str) -> bool:
        """Check if phone number has opted in"""
        try:
            # Get latest opt-in/out record
            latest = db_session.query(SMSOptInOut).filter_by(
                phone_number=phone_number
            ).order_by(SMSOptInOut.timestamp.desc()).first()
            
            return latest and latest.status == 'opted_in'
        except Exception as e:
            logger.error(f"Error checking opt-in status: {str(e)}")
            return False
    
    async def _get_user_preferences(self, user_id: int) -> Optional[NotificationPreference]:
        """Get user notification preferences"""
        try:
            return db_session.query(NotificationPreference).filter_by(
                user_id=user_id
            ).first()
        except Exception as e:
            logger.error(f"Error fetching preferences: {str(e)}")
            return None
    
    async def _get_user_by_phone(self, phone_number: str):
        """Get user by phone number"""
        # This would query your User model by phone number
        # Implementation depends on your User model structure
        pass
    
    async def _log_notification(
        self,
        user_id: Optional[int],
        to_phone: str,
        notification_type: str,
        status: str,
        contains_phi: bool,
        message_sid: Optional[str]
    ):
        """Log SMS notification in history"""
        try:
            notification = NotificationHistory(
                user_id=user_id,
                notification_type=notification_type,
                channel='sms',
                recipient=self._mask_phone_number(to_phone),
                status=status,
                sent_at=datetime.utcnow(),
                delivered_at=datetime.utcnow() if status == 'delivered' else None,
                contains_phi=contains_phi,
                metadata=json.dumps({
                    'message_sid': message_sid,
                    'encrypted': contains_phi and self.encryption_required
                })
            )
            db_session.add(notification)
            db_session.commit()
        except Exception as e:
            logger.error(f"Error logging notification: {str(e)}")
    
    async def _create_audit_log(self, user_id: Optional[int], action: str, details: Dict[str, Any]):
        """Create audit log entry for compliance"""
        try:
            audit = AuditLog(
                user_id=user_id,
                action=action,
                resource_type='notification',
                resource_id=None,
                ip_address=None,
                user_agent='SMSService',
                details=json.dumps(details),
                created_at=datetime.utcnow()
            )
            db_session.add(audit)
            db_session.commit()
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")
    
    async def update_delivery_status(self, message_sid: str, status: str):
        """Update SMS delivery status from Twilio callback"""
        try:
            notification = db_session.query(NotificationHistory).filter(
                NotificationHistory.metadata.like(f'%{message_sid}%')
            ).first()
            
            if notification:
                notification.status = status
                if status == 'delivered':
                    notification.delivered_at = datetime.utcnow()
                
                # Update metadata
                metadata = json.loads(notification.metadata)
                metadata['final_status'] = status
                metadata['status_updated_at'] = datetime.utcnow().isoformat()
                notification.metadata = json.dumps(metadata)
                
                db_session.commit()
                
        except Exception as e:
            logger.error(f"Error updating delivery status: {str(e)}")