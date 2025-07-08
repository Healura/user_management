import logging
from typing import Optional, List, Dict, Any
import asyncio

import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config.auth_settings import auth_settings

logger = logging.getLogger(__name__)


class EmailError(Exception):
    """Base exception for email errors."""
    pass


async def send_email(
    to_email: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
    from_email: Optional[str] = None
) -> bool:
    """
    Send an email asynchronously.
    
    Args:
        to_email: Recipient email address
        subject: Email subject
        body: Plain text body
        html_body: Optional HTML body
        from_email: Sender email address
        
    Returns:
        True if email sent successfully
        
    Raises:
        EmailError: If email sending fails
    """
    if not auth_settings.smtp_username or not auth_settings.smtp_password:
        logger.warning("Email configuration missing, skipping email send")
        return False
    
    try:
        # Create message
        message = MIMEMultipart('alternative')
        message['Subject'] = subject
        message['From'] = from_email or auth_settings.email_from
        message['To'] = to_email
        
        # Add text part
        text_part = MIMEText(body, 'plain')
        message.attach(text_part)
        
        # Add HTML part if provided
        if html_body:
            html_part = MIMEText(html_body, 'html')
            message.attach(html_part)
        
        # Send email
        async with aiosmtplib.SMTP(
            hostname=auth_settings.smtp_host,
            port=auth_settings.smtp_port,
            use_tls=True
        ) as smtp:
            await smtp.login(
                auth_settings.smtp_username,
                auth_settings.smtp_password.get_secret_value()
            )
            await smtp.send_message(message)
        
        logger.info(f"Email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {e}")
        raise EmailError(f"Failed to send email: {str(e)}")


async def send_verification_email(
    to_email: str,
    verification_url: str,
    user_name: Optional[str] = None
) -> bool:
    """
    Send email verification message.
    
    Args:
        to_email: Recipient email
        verification_url: Verification URL with token
        user_name: Optional user name for personalization
        
    Returns:
        True if sent successfully
    """
    subject = "Verify Your Email - Voice Biomarker"
    
    body = f"""
Hello{f' {user_name}' if user_name else ''},

Thank you for registering with Voice Biomarker Healthcare Application.

Please verify your email address by clicking the link below:

{verification_url}

This link will expire in {auth_settings.email_verification_expire_hours} hours.

If you did not create an account, please ignore this email.

Best regards,
Voice Biomarker Team
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #4CAF50; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background-color: #f9f9f9; }}
        .button {{ display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 10px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Voice Biomarker</h1>
        </div>
        <div class="content">
            <h2>Hello{f' {user_name}' if user_name else ''},</h2>
            <p>Thank you for registering with Voice Biomarker Healthcare Application.</p>
            <p>Please verify your email address by clicking the button below:</p>
            <center>
                <a href="{verification_url}" class="button">Verify Email</a>
            </center>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all;">{verification_url}</p>
            <p><strong>This link will expire in {auth_settings.email_verification_expire_hours} hours.</strong></p>
            <p>If you did not create an account, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>© 2024 Voice Biomarker Healthcare Application. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""

    return await send_email(to_email, subject, body, html_body)


async def send_password_reset_email(
    to_email: str,
    reset_url: str,
    user_name: Optional[str] = None
) -> bool:
    """
    Send password reset email.
    
    Args:
        to_email: Recipient email
        reset_url: Password reset URL with token
        user_name: Optional user name
        
    Returns:
        True if sent successfully
    """
    subject = "Password Reset Request - Voice Biomarker"
    
    body = f"""
Hello{f' {user_name}' if user_name else ''},

We received a request to reset your password for your Voice Biomarker account.

To reset your password, click the link below:

{reset_url}

This link will expire in 1 hour for security reasons.

If you did not request a password reset, please ignore this email. Your password will remain unchanged.

Best regards,
Voice Biomarker Team
"""

    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #f44336; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background-color: #f9f9f9; }}
        .button {{ display: inline-block; padding: 10px 20px; background-color: #f44336; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .footer {{ text-align: center; padding: 10px; color: #666; font-size: 12px; }}
        .warning {{ background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 10px 0; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Hello{f' {user_name}' if user_name else ''},</h2>
            <p>We received a request to reset your password for your Voice Biomarker account.</p>
            <p>To reset your password, click the button below:</p>
            <center>
                <a href="{reset_url}" class="button">Reset Password</a>
            </center>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all;">{reset_url}</p>
            <div class="warning">
                <strong>⚠️ This link will expire in 1 hour for security reasons.</strong>
            </div>
            <p>If you did not request a password reset, please ignore this email. Your password will remain unchanged.</p>
        </div>
        <div class="footer">
            <p>© 2024 Voice Biomarker Healthcare Application. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""

    return await send_email(to_email, subject, body, html_body)


async def send_login_notification(
    to_email: str,
    user_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    device_info: Optional[str] = None,
    timestamp: Optional[str] = None
) -> bool:
    """
    Send login notification for security.
    
    Args:
        to_email: Recipient email
        user_name: User name
        ip_address: Login IP address
        device_info: Device/browser information
        timestamp: Login timestamp
        
    Returns:
        True if sent successfully
    """
    subject = "New Login to Your Account - Voice Biomarker"
    
    body = f"""
Hello{f' {user_name}' if user_name else ''},

We noticed a new login to your Voice Biomarker account.

Login Details:
- Time: {timestamp or 'Unknown'}
- IP Address: {ip_address or 'Unknown'}
- Device: {device_info or 'Unknown'}

If this was you, no action is needed.

If you did not log in, please:
1. Change your password immediately
2. Review your account activity
3. Contact support if you notice any suspicious activity

Best regards,
Voice Biomarker Security Team
"""

    return await send_email(to_email, subject, body)