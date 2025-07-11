"""
Security Notification Templates

HIPAA-compliant templates for security alerts, login notifications,
and suspicious activity warnings.
"""

from typing import Dict, Any
from datetime import datetime

__all__ = [
    'get_login_alert_template',
    'get_password_changed_template',
    'get_suspicious_activity_template',
    'get_account_locked_template',
    'get_mfa_enabled_template',
    'get_data_breach_notification_template'
]


def get_login_alert_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for login security alerts"""
    login_location = data.get("location", "Unknown location")
    login_device = data.get("device", "Unknown device")
    login_ip = data.get("ip_address", "")
    login_time = data.get("login_time", datetime.utcnow().strftime("%B %d, %Y at %I:%M %p"))
    
    return {
        "subject": "Security Alert: New Login to Your Voice Biomarker Account",
        "template": "login_alert",
        "template_data": {
            "user_name": user.full_name or user.username,
            "login_location": login_location,
            "login_device": login_device,
            "login_ip": login_ip,
            "login_time": login_time
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>We detected a new login to your Voice Biomarker account and wanted to make sure it was you.</p>
        
        <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ffc107;">
            <h3 style="margin-top: 0;">🔐 Login Details</h3>
            <p><strong>Time:</strong> {login_time}</p>
            <p><strong>Location:</strong> {login_location}</p>
            <p><strong>Device:</strong> {login_device}</p>
            <p><strong>IP Address:</strong> {login_ip}</p>
        </div>
        
        <p><strong>Was this you?</strong></p>
        <p>If you recognize this activity, no further action is needed.</p>
        
        <p><strong>Don't recognize this login?</strong></p>
        <ul>
            <li>Change your password immediately</li>
            <li>Review your account activity</li>
            <li>Contact our security team</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/security/review" 
               style="background-color: #d32f2f; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Secure My Account
            </a>
        </div>
        
        <p style="font-size: 12px; color: #666;">
            For your security, we recommend enabling two-factor authentication. 
            This notification is sent for all new device logins.
        </p>
        """,
        "sms_body": f"Voice Biomarker Security: New login detected from {login_location} at {login_time}. If this wasn't you, secure your account immediately.",
        "push_title": "Security Alert",
        "push_body": f"New login detected from {login_location}",
        "push_data": {
            "action": "security_review",
            "alert_type": "login"
        },
        "action_url": "voicebiomarker://security/review",
        "contains_phi": False,
        "urgent": True
    }


def get_password_changed_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for password change notifications"""
    change_time = data.get("change_time", datetime.utcnow().strftime("%B %d, %Y at %I:%M %p"))
    change_location = data.get("location", "Unknown location")
    change_device = data.get("device", "Unknown device")
    
    return {
        "subject": "Password Changed - Voice Biomarker Account",
        "template": "password_changed",
        "template_data": {
            "user_name": user.full_name or user.username,
            "change_time": change_time,
            "change_location": change_location,
            "change_device": change_device
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>Your Voice Biomarker account password was successfully changed.</p>
        
        <div style="background-color: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4caf50;">
            <h3 style="margin-top: 0;">✅ Password Change Confirmed</h3>
            <p><strong>Changed:</strong> {change_time}</p>
            <p><strong>Location:</strong> {change_location}</p>
            <p><strong>Device:</strong> {change_device}</p>
        </div>
        
        <p><strong>Was this you?</strong></p>
        <p>If you made this change, your account is secure and no further action is needed.</p>
        
        <p><strong>Didn't change your password?</strong></p>
        <p>If you didn't make this change, your account may be compromised. Take these steps immediately:</p>
        <ul>
            <li>Reset your password using the "Forgot Password" option</li>
            <li>Review your account for unauthorized activity</li>
            <li>Contact our security team immediately</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/security/emergency" 
               style="background-color: #d32f2f; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Report Unauthorized Access
            </a>
        </div>
        
        <p style="font-size: 12px; color: #666;">
            This notification is sent whenever your password is changed. 
            If you have questions, contact security@voicebiomarker.com
        </p>
        """,
        "sms_body": f"Voice Biomarker: Your password was changed at {change_time}. If this wasn't you, contact security immediately.",
        "push_title": "Password Changed",
        "push_body": "Your account password was successfully changed",
        "push_data": {
            "action": "security_review",
            "alert_type": "password_change"
        },
        "action_url": "voicebiomarker://security/review",
        "contains_phi": False,
        "urgent": True
    }


def get_suspicious_activity_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for suspicious activity alerts"""
    activity_type = data.get("activity_type", "Multiple failed login attempts")
    activity_time = data.get("activity_time", datetime.utcnow().strftime("%B %d, %Y at %I:%M %p"))
    activity_details = data.get("details", "Unusual account access patterns detected")
    risk_level = data.get("risk_level", "medium")
    
    risk_colors = {
        "low": "#2196F3",
        "medium": "#FF9800", 
        "high": "#d32f2f"
    }
    
    risk_emoji = {
        "low": "ℹ️",
        "medium": "⚠️",
        "high": "🚨"
    }
    
    return {
        "subject": f"{risk_emoji[risk_level]} Security Alert: Suspicious Activity Detected",
        "template": "suspicious_activity",
        "template_data": {
            "user_name": user.full_name or user.username,
            "activity_type": activity_type,
            "activity_time": activity_time,
            "activity_details": activity_details,
            "risk_level": risk_level
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>We detected suspicious activity on your Voice Biomarker account and have temporarily secured it as a precaution.</p>
        
        <div style="background-color: {risk_colors[risk_level]}20; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid {risk_colors[risk_level]};">
            <h3 style="margin-top: 0;">{risk_emoji[risk_level]} Security Alert</h3>
            <p><strong>Activity:</strong> {activity_type}</p>
            <p><strong>Detected:</strong> {activity_time}</p>
            <p><strong>Risk Level:</strong> {risk_level.upper()}</p>
            <p><strong>Details:</strong> {activity_details}</p>
        </div>
        
        <p><strong>Immediate Actions Required:</strong></p>
        <ol>
            <li><strong>Verify Your Identity:</strong> Log in with your current password</li>
            <li><strong>Change Your Password:</strong> Create a new, strong password</li>
            <li><strong>Review Account Activity:</strong> Check for unauthorized access</li>
            <li><strong>Enable Two-Factor Authentication:</strong> Add extra security to your account</li>
        </ol>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/security/verification" 
               style="background-color: {risk_colors[risk_level]}; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Verify & Secure Account
            </a>
        </div>
        
        <p><strong>What We're Doing:</strong></p>
        <ul>
            <li>Your account has been temporarily restricted</li>
            <li>We're monitoring for additional suspicious activity</li>
            <li>Our security team has been notified</li>
        </ul>
        
        <p style="font-size: 12px; color: #666;">
            This is an automated security alert. If you need assistance, contact our security team 
            immediately at security@voicebiomarker.com or call our emergency line.
        </p>
        """,
        "sms_body": f"URGENT - Voice Biomarker Security: Suspicious activity detected. Your account is temporarily secured. Verify immediately to restore access.",
        "push_title": "🚨 Security Alert",
        "push_body": f"Suspicious activity detected: {activity_type}",
        "push_data": {
            "action": "security_verification",
            "alert_type": "suspicious_activity",
            "risk_level": risk_level
        },
        "action_url": "voicebiomarker://security/verification",
        "contains_phi": False,
        "urgent": True,
        "high_priority": True
    }


def get_account_locked_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for account lockout notifications"""
    lockout_reason = data.get("reason", "Multiple failed login attempts")
    lockout_time = data.get("lockout_time", datetime.utcnow().strftime("%B %d, %Y at %I:%M %p"))
    unlock_time = data.get("unlock_time", "30 minutes")
    attempts_count = data.get("attempts_count", 5)
    
    return {
        "subject": "Account Temporarily Locked - Voice Biomarker",
        "template": "account_locked",
        "template_data": {
            "user_name": user.full_name or user.username,
            "lockout_reason": lockout_reason,
            "lockout_time": lockout_time,
            "unlock_time": unlock_time,
            "attempts_count": attempts_count
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>Your Voice Biomarker account has been temporarily locked for security reasons.</p>
        
        <div style="background-color: #ffebee; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f44336;">
            <h3 style="margin-top: 0;">🔒 Account Locked</h3>
            <p><strong>Reason:</strong> {lockout_reason}</p>
            <p><strong>Locked At:</strong> {lockout_time}</p>
            <p><strong>Failed Attempts:</strong> {attempts_count}</p>
            <p><strong>Auto-Unlock In:</strong> {unlock_time}</p>
        </div>
        
        <p><strong>What Happened?</strong></p>
        <p>Your account was automatically locked after {attempts_count} consecutive failed login attempts. 
        This is a security measure to protect your healthcare information.</p>
        
        <p><strong>What You Can Do:</strong></p>
        <ul>
            <li><strong>Wait:</strong> Your account will unlock automatically in {unlock_time}</li>
            <li><strong>Reset Password:</strong> If you forgot your password, reset it now</li>
            <li><strong>Contact Support:</strong> If you need immediate access, contact our team</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/auth/reset-password" 
               style="background-color: #1976D2; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Reset Password
            </a>
        </div>
        
        <p><strong>Didn't try to log in?</strong></p>
        <p>If you weren't trying to access your account, someone else may have been attempting 
        to gain unauthorized access. Contact our security team immediately.</p>
        
        <p style="font-size: 12px; color: #666;">
            For your security, we lock accounts after multiple failed login attempts. 
            Contact security@voicebiomarker.com if you need assistance.
        </p>
        """,
        "sms_body": f"Voice Biomarker: Your account is temporarily locked due to {attempts_count} failed login attempts. It will unlock automatically in {unlock_time}.",
        "push_title": "Account Locked",
        "push_body": f"Account locked due to failed login attempts. Unlocks in {unlock_time}",
        "push_data": {
            "action": "reset_password",
            "alert_type": "account_locked"
        },
        "action_url": "voicebiomarker://auth/reset-password",
        "contains_phi": False,
        "urgent": True
    }


def get_mfa_enabled_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for MFA enablement confirmation"""
    enable_time = data.get("enable_time", datetime.utcnow().strftime("%B %d, %Y at %I:%M %p"))
    device_name = data.get("device_name", "your device")
    
    return {
        "subject": "Two-Factor Authentication Enabled - Voice Biomarker",
        "template": "mfa_enabled",
        "template_data": {
            "user_name": user.full_name or user.username,
            "enable_time": enable_time,
            "device_name": device_name
        },
        "body": f"""
        <h2>Hi {user.full_name or user.username},</h2>
        
        <p>Two-factor authentication has been successfully enabled on your Voice Biomarker account.</p>
        
        <div style="background-color: #e8f5e9; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4caf50;">
            <h3 style="margin-top: 0;">🛡️ Enhanced Security Active</h3>
            <p><strong>Enabled:</strong> {enable_time}</p>
            <p><strong>Authenticator:</strong> {device_name}</p>
            <p><strong>Status:</strong> ✅ Active</p>
        </div>
        
        <p><strong>What This Means:</strong></p>
        <ul>
            <li>Your account now has an extra layer of security</li>
            <li>You'll need your phone or authenticator app to log in</li>
            <li>Your healthcare data is better protected</li>
            <li>Unauthorized access is significantly more difficult</li>
        </ul>
        
        <p><strong>Important Reminders:</strong></p>
        <ul>
            <li>Save your backup codes in a secure location</li>
            <li>Keep your authenticator device accessible</li>
            <li>Update your recovery information if needed</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/security/mfa" 
               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Manage 2FA Settings
            </a>
        </div>
        
        <p>Thank you for taking this important step to protect your healthcare information.</p>
        
        <p style="font-size: 12px; color: #666;">
            If you didn't enable two-factor authentication, contact our security team immediately 
            at security@voicebiomarker.com
        </p>
        """,
        "sms_body": f"Voice Biomarker: Two-factor authentication has been enabled on your account at {enable_time}. Your account is now more secure.",
        "push_title": "2FA Enabled",
        "push_body": "Two-factor authentication is now active on your account",
        "push_data": {
            "action": "view_security",
            "alert_type": "mfa_enabled"
        },
        "action_url": "voicebiomarker://security/mfa",
        "contains_phi": False
    }


def get_data_breach_notification_template(user: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    """Template for data breach notifications (HIPAA compliant)"""
    incident_date = data.get("incident_date", "")
    discovery_date = data.get("discovery_date", "")
    data_types = data.get("data_types", ["Account information"])
    mitigation_steps = data.get("mitigation_steps", [])
    
    return {
        "subject": "Important Security Notice - Voice Biomarker",
        "template": "data_breach_notification",
        "template_data": {
            "user_name": user.full_name or user.username,
            "incident_date": incident_date,
            "discovery_date": discovery_date,
            "data_types": data_types,
            "mitigation_steps": mitigation_steps
        },
        "body": f"""
        <h2>Dear {user.full_name or user.username},</h2>
        
        <p>We are writing to inform you of a security incident that may have affected your personal information.</p>
        
        <div style="background-color: #ffebee; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f44336;">
            <h3 style="margin-top: 0;">🔒 Security Incident Notice</h3>
            <p><strong>Incident Date:</strong> {incident_date}</p>
            <p><strong>Discovery Date:</strong> {discovery_date}</p>
            <p><strong>Status:</strong> Contained and Under Investigation</p>
        </div>
        
        <p><strong>What Happened:</strong></p>
        <p>We discovered unauthorized access to some of our systems. We immediately took steps to 
        secure our systems and are working with cybersecurity experts and law enforcement.</p>
        
        <p><strong>Information Involved:</strong></p>
        <ul>
            {chr(10).join([f'<li>{data_type}</li>' for data_type in data_types])}
        </ul>
        
        <p><strong>What We're Doing:</strong></p>
        <ul>
            <li>Secured the affected systems immediately</li>
            <li>Conducted a thorough security review</li>
            <li>Implemented additional security measures</li>
            <li>Notified appropriate authorities</li>
            <li>Engaged cybersecurity experts</li>
        </ul>
        
        <p><strong>What You Should Do:</strong></p>
        <ol>
            <li><strong>Change Your Password:</strong> Create a new, strong password immediately</li>
            <li><strong>Monitor Your Accounts:</strong> Watch for any suspicious activity</li>
            <li><strong>Enable Two-Factor Authentication:</strong> Add extra security</li>
            <li><strong>Review Your Information:</strong> Check your account for any changes</li>
        </ol>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="https://app.voicebiomarker.com/security/incident-response" 
               style="background-color: #d32f2f; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Secure My Account
            </a>
        </div>
        
        <p><strong>More Information:</strong></p>
        <p>We take the security of your information very seriously and sincerely apologize for this incident. 
        A dedicated support team is available to answer your questions.</p>
        
        <p><strong>Contact Information:</strong></p>
        <ul>
            <li>Email: security-incident@voicebiomarker.com</li>
            <li>Phone: 1-800-XXX-XXXX (24/7 hotline)</li>
            <li>Website: voicebiomarker.com/security-incident</li>
        </ul>
        
        <p style="font-size: 12px; color: #666;">
            This notice is being sent in accordance with applicable data protection laws. 
            We will continue to provide updates as our investigation progresses.
        </p>
        """,
        "sms_body": "URGENT - Voice Biomarker Security: We experienced a security incident that may have affected your information. Please check your email and secure your account immediately.",
        "push_title": "🚨 Security Incident",
        "push_body": "Important security notice - action required to protect your account",
        "push_data": {
            "action": "security_incident",
            "alert_type": "data_breach"
        },
        "action_url": "voicebiomarker://security/incident-response",
        "contains_phi": False,
        "urgent": True,
        "high_priority": True,
        "breach_notification": True
    } 