"""
HIPAA-compliant Email Service for Healthcare Notifications

Provides secure email delivery with encryption for PHI content,
template rendering, and delivery tracking.
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
import base64
from cryptography.fernet import Fernet
from jinja2 import Template, Environment, FileSystemLoader
import logging

from ..database.models import NotificationHistory, NotificationPreference, AuditLog
from ..database.database import SessionLocal
from config.notification_config import EmailConfig

logger = logging.getLogger(__name__)


class EmailService:
    """HIPAA-compliant email service for healthcare notifications"""
    
    def __init__(self):
        self.config = EmailConfig()
        self.smtp_host = self.config.SMTP_HOST
        self.smtp_port = self.config.SMTP_PORT
        self.smtp_username = self.config.SMTP_USERNAME
        self.smtp_password = self.config.SMTP_PASSWORD
        self.use_tls = self.config.SMTP_TLS
        self.encryption_required = self.config.EMAIL_ENCRYPTION_REQUIRED
        self.from_email = self.config.FROM_EMAIL
        self.from_name = self.config.FROM_NAME
        
        # Initialize encryption for PHI content
        self.encryption_key = self.config.EMAIL_ENCRYPTION_KEY
        self.cipher_suite = Fernet(self.encryption_key.encode()) if self.encryption_key else None
        
        # Initialize template environment
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.template_env = Environment(loader=FileSystemLoader(template_dir))
    
    async def send_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        template_name: Optional[str] = None,
        template_data: Optional[Dict[str, Any]] = None,
        contains_phi: bool = False,
        attachments: Optional[List[Dict[str, Any]]] = None,
        user_id: Optional[int] = None,
        notification_type: str = "general"
    ) -> Dict[str, Any]:
        """
        Send HIPAA-compliant email with optional encryption for PHI
        
        Args:
            to_email: Recipient email address
            subject: Email subject
            body: Email body (plain text or HTML)
            template_name: Optional template name to use
            template_data: Data for template rendering
            contains_phi: Whether email contains PHI (triggers encryption)
            attachments: List of attachments
            user_id: User ID for audit logging
            notification_type: Type of notification for tracking
        
        Returns:
            Dictionary with send status and details
        """
        try:
            # Check user preferences if user_id provided
            if user_id:
                preferences = await self._get_user_preferences(user_id)
                if not preferences or not preferences.email_enabled:
                    return {
                        "success": False,
                        "message": "Email notifications disabled by user",
                        "delivery_status": "blocked_by_preferences"
                    }
            
            # Render template if specified
            if template_name and template_data:
                body = await self._render_template(template_name, template_data)
            
            # Encrypt body if contains PHI
            if contains_phi and self.encryption_required:
                body = await self._encrypt_content(body)
                subject = f"[ENCRYPTED] {subject}"
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['X-Healthcare-Notification'] = 'true'
            msg['X-PHI-Content'] = str(contains_phi).lower()
            
            # Add body
            if contains_phi and self.encryption_required:
                # Add encrypted content with instructions
                encrypted_body = self._create_encrypted_email_body(body)
                msg.attach(MIMEText(encrypted_body, 'html'))
            else:
                msg.attach(MIMEText(body, 'html'))
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    await self._add_attachment(msg, attachment, contains_phi)
            
            # Send email
            delivery_status = await self._send_smtp(msg, to_email)
            
            # Log notification
            await self._log_notification(
                user_id=user_id,
                to_email=to_email,
                notification_type=notification_type,
                delivery_status=delivery_status,
                contains_phi=contains_phi
            )
            
            # Audit log for compliance
            if contains_phi:
                await self._create_audit_log(
                    user_id=user_id,
                    action="phi_email_sent",
                    details={"to": to_email, "type": notification_type}
                )
            
            return {
                "success": True,
                "message": "Email sent successfully",
                "delivery_status": delivery_status,
                "message_id": delivery_status.get("message_id")
            }
            
        except Exception as e:
            logger.error(f"Email send error: {str(e)}")
            return {
                "success": False,
                "message": f"Failed to send email: {str(e)}",
                "delivery_status": "failed"
            }
    
    async def _render_template(self, template_name: str, data: Dict[str, Any]) -> str:
        """Render email template with provided data"""
        try:
            template = self.template_env.get_template(f"{template_name}.html")
            
            # Add default template data
            data.update({
                "app_name": "Voice Biomarker",
                "support_email": "support@voicebiomarker.com",
                "privacy_url": "https://voicebiomarker.com/privacy",
                "unsubscribe_url": "https://voicebiomarker.com/unsubscribe",
                "current_year": datetime.now().year
            })
            
            return template.render(**data)
        except Exception as e:
            logger.error(f"Template rendering error: {str(e)}")
            raise
    
    async def _encrypt_content(self, content: str) -> str:
        """Encrypt content containing PHI"""
        if not self.cipher_suite:
            raise ValueError("Encryption key not configured")
        
        encrypted = self.cipher_suite.encrypt(content.encode())
        return base64.b64encode(encrypted).decode()
    
    def _create_encrypted_email_body(self, encrypted_content: str) -> str:
        """Create email body for encrypted content with instructions"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background-color: #f0f0f0; padding: 20px; border-radius: 5px;">
                <h2 style="color: #d32f2f;">🔒 Encrypted Healthcare Information</h2>
                <p>This email contains protected health information (PHI) that has been encrypted for security.</p>
                
                <div style="background-color: #fff; padding: 15px; margin: 20px 0; border-left: 4px solid #d32f2f;">
                    <p><strong>To view this message:</strong></p>
                    <ol>
                        <li>Log in to your Voice Biomarker account</li>
                        <li>Navigate to Messages > Encrypted</li>
                        <li>Use this reference code: <code>{encrypted_content[:16]}...</code></li>
                    </ol>
                </div>
                
                <p style="color: #666; font-size: 12px;">
                    This encryption is required by HIPAA to protect your health information during transmission.
                    Never share your login credentials with anyone.
                </p>
                
                <hr style="margin: 20px 0;">
                <p style="font-size: 11px; color: #999;">
                    Voice Biomarker Healthcare Platform<br>
                    This message contains confidential information and is intended only for the addressee.
                </p>
            </div>
        </body>
        </html>
        """
    
    async def _send_smtp(self, msg: MIMEMultipart, to_email: str) -> Dict[str, Any]:
        """Send email via SMTP with retry logic"""
        context = ssl.create_default_context()
        retry_count = 0
        max_retries = 3
        
        while retry_count < max_retries:
            try:
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls(context=context)
                    
                    server.login(self.smtp_username, self.smtp_password)
                    
                    # Send email and get response
                    send_response = server.send_message(msg)
                    
                    return {
                        "status": "delivered",
                        "timestamp": datetime.utcnow().isoformat(),
                        "message_id": msg.get('Message-ID'),
                        "attempt": retry_count + 1
                    }
                    
            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    raise
                logger.warning(f"SMTP send attempt {retry_count} failed: {str(e)}")
    
    async def _add_attachment(
        self,
        msg: MIMEMultipart,
        attachment: Dict[str, Any],
        encrypt: bool = False
    ):
        """Add attachment to email with optional encryption"""
        try:
            content = attachment.get('content', b'')
            filename = attachment.get('filename', 'attachment')
            content_type = attachment.get('content_type', 'application/octet-stream')
            
            # Encrypt attachment if required
            if encrypt and self.cipher_suite:
                content = self.cipher_suite.encrypt(content)
                filename = f"{filename}.encrypted"
            
            part = MIMEApplication(content, Name=filename)
            part['Content-Disposition'] = f'attachment; filename="{filename}"'
            msg.attach(part)
            
        except Exception as e:
            logger.error(f"Attachment error: {str(e)}")
            raise
    
    async def _get_user_preferences(self, user_id: int) -> Optional[NotificationPreference]:
        """Get user notification preferences"""
        try:
            return db_session.query(NotificationPreference).filter_by(
                user_id=user_id
            ).first()
        except Exception as e:
            logger.error(f"Error fetching preferences: {str(e)}")
            return None
    
    async def _log_notification(
        self,
        user_id: Optional[int],
        to_email: str,
        notification_type: str,
        delivery_status: Dict[str, Any],
        contains_phi: bool
    ):
        """Log notification in history table"""
        try:
            notification = NotificationHistory(
                user_id=user_id,
                notification_type=notification_type,
                channel='email',
                recipient=to_email,
                status=delivery_status.get('status', 'failed'),
                sent_at=datetime.utcnow(),
                delivered_at=datetime.utcnow() if delivery_status.get('status') == 'delivered' else None,
                contains_phi=contains_phi,
                metadata=json.dumps({
                    'delivery_status': delivery_status,
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
                ip_address=None,  # Not applicable for system-generated emails
                user_agent='EmailService',
                details=json.dumps(details),
                created_at=datetime.utcnow()
            )
            db_session.add(audit)
            db_session.commit()
        except Exception as e:
            logger.error(f"Error creating audit log: {str(e)}")
    
    async def send_bulk_emails(
        self,
        recipients: List[Dict[str, Any]],
        subject: str,
        template_name: str,
        base_template_data: Dict[str, Any],
        notification_type: str = "bulk"
    ) -> Dict[str, Any]:
        """Send bulk emails with rate limiting and compliance"""
        results = {
            "total": len(recipients),
            "sent": 0,
            "failed": 0,
            "details": []
        }
        
        for recipient in recipients:
            # Merge recipient-specific data with base template data
            template_data = {**base_template_data, **recipient.get('data', {})}
            
            result = await self.send_email(
                to_email=recipient['email'],
                subject=subject,
                body="",
                template_name=template_name,
                template_data=template_data,
                contains_phi=recipient.get('contains_phi', False),
                user_id=recipient.get('user_id'),
                notification_type=notification_type
            )
            
            if result['success']:
                results['sent'] += 1
            else:
                results['failed'] += 1
            
            results['details'].append({
                'email': recipient['email'],
                'success': result['success'],
                'message': result.get('message')
            })
            
            # Rate limiting
            await self._apply_rate_limit()
        
        return results
    
    async def _apply_rate_limit(self):
        """Apply rate limiting between sends"""
        import asyncio
        await asyncio.sleep(0.1)  # 10 emails per second max