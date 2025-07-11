"""
Healthcare Notification Configuration

HIPAA-compliant notification settings for email, SMS, and push notifications
with security and compliance requirements.
"""

import os
from typing import List, Optional
from pydantic import Field, SecretStr, ConfigDict
from pydantic_settings import BaseSettings


class EmailConfig(BaseSettings):
    """Email notification configuration with HIPAA compliance."""
    
    # SMTP Configuration
    SMTP_HOST: str = Field(default="smtp.office365.com", env="SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_TLS: bool = Field(default=True, env="SMTP_TLS")
    SMTP_USERNAME: str = Field(default="notifications@voicebiomarker.com", env="SMTP_USERNAME")
    SMTP_PASSWORD: Optional[SecretStr] = Field(default=None, env="SMTP_PASSWORD")
    
    # Email Settings
    FROM_EMAIL: str = Field(default="notifications@voicebiomarker.com", env="FROM_EMAIL")
    FROM_NAME: str = Field(default="Voice Biomarker", env="FROM_NAME")
    REPLY_TO_EMAIL: str = Field(default="support@voicebiomarker.com", env="REPLY_TO_EMAIL")
    
    # HIPAA Compliance
    EMAIL_ENCRYPTION_REQUIRED: bool = Field(default=True, env="EMAIL_ENCRYPTION_REQUIRED")
    EMAIL_ENCRYPTION_KEY: Optional[str] = Field(default=None, env="EMAIL_ENCRYPTION_KEY")
    PHI_EMAIL_FILTERING: bool = Field(default=True, env="PHI_EMAIL_FILTERING")
    
    # Delivery Settings
    EMAIL_RETRY_ATTEMPTS: int = Field(default=3, env="EMAIL_RETRY_ATTEMPTS")
    EMAIL_RETRY_DELAY_SECONDS: int = Field(default=60, env="EMAIL_RETRY_DELAY_SECONDS")
    EMAIL_TIMEOUT_SECONDS: int = Field(default=30, env="EMAIL_TIMEOUT_SECONDS")
    
    # Rate Limiting
    EMAIL_RATE_LIMIT_PER_HOUR: int = Field(default=100, env="EMAIL_RATE_LIMIT_PER_HOUR")
    EMAIL_RATE_LIMIT_PER_DAY: int = Field(default=1000, env="EMAIL_RATE_LIMIT_PER_DAY")
    
    # Security
    EMAIL_DOMAIN_VALIDATION: bool = Field(default=True, env="EMAIL_DOMAIN_VALIDATION")
    ALLOWED_EMAIL_DOMAINS: List[str] = Field(default=[], env="ALLOWED_EMAIL_DOMAINS")
    BLOCK_DISPOSABLE_EMAILS: bool = Field(default=True, env="BLOCK_DISPOSABLE_EMAILS")

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )


class SMSConfig(BaseSettings):
    """SMS notification configuration with healthcare compliance."""
    
    # SMS Provider Configuration (Twilio)
    SMS_PROVIDER: str = Field(default="twilio", env="SMS_PROVIDER")
    SMS_ACCOUNT_SID: Optional[str] = Field(default=None, env="SMS_ACCOUNT_SID")
    SMS_AUTH_TOKEN: Optional[SecretStr] = Field(default=None, env="SMS_AUTH_TOKEN")
    SMS_FROM_NUMBER: Optional[str] = Field(default=None, env="SMS_FROM_NUMBER")
    
    # Healthcare Compliance
    SMS_ENCRYPTION_REQUIRED: bool = Field(default=True, env="SMS_ENCRYPTION_REQUIRED")
    SMS_ENCRYPTION_KEY: Optional[str] = Field(default=None, env="SMS_ENCRYPTION_KEY")
    SMS_PHI_FILTERING: bool = Field(default=True, env="SMS_PHI_FILTERING")
    SMS_CONSENT_REQUIRED: bool = Field(default=True, env="SMS_CONSENT_REQUIRED")
    
    # Message Settings
    SMS_CHARACTER_LIMIT: int = Field(default=160, env="SMS_CHARACTER_LIMIT")
    SMS_TRUNCATE_LONG_MESSAGES: bool = Field(default=True, env="SMS_TRUNCATE_LONG_MESSAGES")
    SECURE_LINK_BASE_URL: str = Field(default="https://secure.voicebiomarker.com", env="SECURE_LINK_BASE_URL")
    
    # Delivery Settings
    SMS_RETRY_ATTEMPTS: int = Field(default=3, env="SMS_RETRY_ATTEMPTS")
    SMS_RETRY_DELAY_SECONDS: int = Field(default=30, env="SMS_RETRY_DELAY_SECONDS")
    SMS_STATUS_CALLBACK_URL: Optional[str] = Field(default=None, env="SMS_STATUS_CALLBACK_URL")
    
    # Rate Limiting
    SMS_RATE_LIMIT_PER_HOUR: int = Field(default=50, env="SMS_RATE_LIMIT_PER_HOUR")
    SMS_RATE_LIMIT_PER_DAY: int = Field(default=200, env="SMS_RATE_LIMIT_PER_DAY")
    
    # Opt-in/Opt-out Management
    AUTO_OPT_OUT_KEYWORDS: List[str] = Field(
        default=["STOP", "END", "CANCEL", "UNSUBSCRIBE", "QUIT", "OPTOUT"],
        env="AUTO_OPT_OUT_KEYWORDS"
    )
    AUTO_OPT_IN_KEYWORDS: List[str] = Field(
        default=["START", "YES", "UNSTOP", "SUBSCRIBE", "OPTIN"],
        env="AUTO_OPT_IN_KEYWORDS"
    )

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )


class PushNotificationConfig(BaseSettings):
    """Push notification configuration with security features."""
    
    # Firebase Configuration
    PUSH_SERVICE: str = Field(default="firebase", env="PUSH_SERVICE")
    FIREBASE_PROJECT_ID: Optional[str] = Field(default=None, env="FIREBASE_PROJECT_ID")
    FIREBASE_PRIVATE_KEY_PATH: Optional[str] = Field(default=None, env="FIREBASE_PRIVATE_KEY_PATH")
    FIREBASE_CLIENT_EMAIL: Optional[str] = Field(default=None, env="FIREBASE_CLIENT_EMAIL")
    
    # Healthcare Compliance
    PUSH_PHI_FILTERING: bool = Field(default=True, env="PUSH_PHI_FILTERING")
    PUSH_CONTENT_SANITIZATION: bool = Field(default=True, env="PUSH_CONTENT_SANITIZATION")
    PUSH_ANONYMIZE_PATIENT_DATA: bool = Field(default=True, env="PUSH_ANONYMIZE_PATIENT_DATA")
    
    # Message Settings
    PUSH_TITLE_MAX_LENGTH: int = Field(default=65, env="PUSH_TITLE_MAX_LENGTH")
    PUSH_BODY_MAX_LENGTH: int = Field(default=240, env="PUSH_BODY_MAX_LENGTH")
    PUSH_DATA_MAX_SIZE: int = Field(default=4096, env="PUSH_DATA_MAX_SIZE")  # 4KB
    
    # Delivery Settings
    PUSH_RETRY_ATTEMPTS: int = Field(default=3, env="PUSH_RETRY_ATTEMPTS")
    PUSH_RETRY_DELAY_SECONDS: int = Field(default=30, env="PUSH_RETRY_DELAY_SECONDS")
    PUSH_TTL_SECONDS: int = Field(default=86400, env="PUSH_TTL_SECONDS")  # 24 hours
    
    # Rate Limiting
    PUSH_RATE_LIMIT_PER_HOUR: int = Field(default=200, env="PUSH_RATE_LIMIT_PER_HOUR")
    PUSH_RATE_LIMIT_PER_DAY: int = Field(default=2000, env="PUSH_RATE_LIMIT_PER_DAY")
    
    # Device Management
    PUSH_DEVICE_TOKEN_EXPIRY_DAYS: int = Field(default=90, env="PUSH_DEVICE_TOKEN_EXPIRY_DAYS")
    PUSH_CLEANUP_INACTIVE_TOKENS: bool = Field(default=True, env="PUSH_CLEANUP_INACTIVE_TOKENS")
    
    # Topic Management
    PUSH_ALLOW_TOPIC_SUBSCRIPTIONS: bool = Field(default=True, env="PUSH_ALLOW_TOPIC_SUBSCRIPTIONS")
    PUSH_MAX_TOPIC_SUBSCRIPTIONS: int = Field(default=10, env="PUSH_MAX_TOPIC_SUBSCRIPTIONS")

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )


class SchedulerConfig(BaseSettings):
    """Notification scheduler configuration."""
    
    # Scheduler Settings
    SCHEDULER_TIMEZONE: str = Field(default="UTC", env="SCHEDULER_TIMEZONE")
    SCHEDULER_MAX_INSTANCES: int = Field(default=3, env="SCHEDULER_MAX_INSTANCES")
    SCHEDULER_COALESCE: bool = Field(default=True, env="SCHEDULER_COALESCE")
    SCHEDULER_MISFIRE_GRACE_TIME: int = Field(default=300, env="SCHEDULER_MISFIRE_GRACE_TIME")  # 5 minutes
    
    # Healthcare Scheduling
    BUSINESS_HOURS_START: str = Field(default="08:00", env="BUSINESS_HOURS_START")
    BUSINESS_HOURS_END: str = Field(default="18:00", env="BUSINESS_HOURS_END")
    BUSINESS_DAYS: List[int] = Field(default=[1, 2, 3, 4, 5], env="BUSINESS_DAYS")  # Mon-Fri
    RESPECT_BUSINESS_HOURS: bool = Field(default=True, env="RESPECT_BUSINESS_HOURS")
    
    # Reminder Settings
    DEFAULT_REMINDER_TIME: str = Field(default="09:00", env="DEFAULT_REMINDER_TIME")
    REMINDER_ADVANCE_HOURS: List[int] = Field(default=[24, 2], env="REMINDER_ADVANCE_HOURS")
    MAX_REMINDERS_PER_EVENT: int = Field(default=3, env="MAX_REMINDERS_PER_EVENT")
    
    # Cleanup Settings
    CLEANUP_COMPLETED_JOBS_DAYS: int = Field(default=30, env="CLEANUP_COMPLETED_JOBS_DAYS")
    CLEANUP_FAILED_JOBS_DAYS: int = Field(default=7, env="CLEANUP_FAILED_JOBS_DAYS")

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )


class NotificationConfig(BaseSettings):
    """Core notification system configuration."""
    
    # General Settings
    NOTIFICATION_ENABLED: bool = Field(default=True, env="NOTIFICATION_ENABLED")
    NOTIFICATION_DEBUG_MODE: bool = Field(default=False, env="NOTIFICATION_DEBUG_MODE")
    NOTIFICATION_TEST_MODE: bool = Field(default=False, env="NOTIFICATION_TEST_MODE")
    
    # Healthcare Compliance
    PATIENT_CONSENT_REQUIRED: bool = Field(default=True, env="PATIENT_CONSENT_REQUIRED")
    HIPAA_COMPLIANT_MODE: bool = Field(default=True, env="HIPAA_COMPLIANT_MODE")
    NOTIFICATION_AUDIT_REQUIRED: bool = Field(default=True, env="NOTIFICATION_AUDIT_REQUIRED")
    PHI_DETECTION_ENABLED: bool = Field(default=True, env="PHI_DETECTION_ENABLED")
    
    # Rate Limiting
    NOTIFICATION_RATE_LIMIT: int = Field(default=10, env="NOTIFICATION_RATE_LIMIT")
    NOTIFICATION_RATE_LIMIT_WINDOW: int = Field(default=3600, env="NOTIFICATION_RATE_LIMIT_WINDOW")  # 1 hour
    NOTIFICATION_RETRY_ATTEMPTS: int = Field(default=3, env="NOTIFICATION_RETRY_ATTEMPTS")
    NOTIFICATION_RETRY_DELAY: int = Field(default=60, env="NOTIFICATION_RETRY_DELAY")  # seconds
    
    # Channel Settings
    SEND_TO_ALL_CHANNELS: bool = Field(default=False, env="SEND_TO_ALL_CHANNELS")
    FALLBACK_CHANNELS_ENABLED: bool = Field(default=True, env="FALLBACK_CHANNELS_ENABLED")
    PREFERRED_CHANNEL_ORDER: List[str] = Field(
        default=["push", "email", "sms"],
        env="PREFERRED_CHANNEL_ORDER"
    )
    
    # Template Settings
    TEMPLATE_CACHE_ENABLED: bool = Field(default=True, env="TEMPLATE_CACHE_ENABLED")
    TEMPLATE_CACHE_TTL_SECONDS: int = Field(default=3600, env="TEMPLATE_CACHE_TTL_SECONDS")
    CUSTOM_TEMPLATES_ENABLED: bool = Field(default=False, env="CUSTOM_TEMPLATES_ENABLED")
    
    # Security Settings
    NOTIFICATION_ENCRYPTION_ENABLED: bool = Field(default=True, env="NOTIFICATION_ENCRYPTION_ENABLED")
    NOTIFICATION_SIGNING_ENABLED: bool = Field(default=True, env="NOTIFICATION_SIGNING_ENABLED")
    SECURE_LINK_EXPIRY_MINUTES: int = Field(default=15, env="SECURE_LINK_EXPIRY_MINUTES")
    
    # Monitoring & Logging
    NOTIFICATION_METRICS_ENABLED: bool = Field(default=True, env="NOTIFICATION_METRICS_ENABLED")
    DELIVERY_TRACKING_ENABLED: bool = Field(default=True, env="DELIVERY_TRACKING_ENABLED")
    NOTIFICATION_ANALYTICS_ENABLED: bool = Field(default=True, env="NOTIFICATION_ANALYTICS_ENABLED")
    
    # Emergency Settings
    EMERGENCY_NOTIFICATION_BYPASS: bool = Field(default=True, env="EMERGENCY_NOTIFICATION_BYPASS")
    EMERGENCY_CONTACT_EMAIL: str = Field(default="security@voicebiomarker.com", env="EMERGENCY_CONTACT_EMAIL")
    EMERGENCY_CONTACT_PHONE: str = Field(default="+1-800-XXX-XXXX", env="EMERGENCY_CONTACT_PHONE")

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )


# Global configuration instances
email_config = EmailConfig()
sms_config = SMSConfig()
push_config = PushNotificationConfig()
scheduler_config = SchedulerConfig()
notification_config = NotificationConfig()


def get_notification_config() -> NotificationConfig:
    """Get the global notification configuration."""
    return notification_config


def get_email_config() -> EmailConfig:
    """Get the email configuration."""
    return email_config


def get_sms_config() -> SMSConfig:
    """Get the SMS configuration."""
    return sms_config


def get_push_config() -> PushNotificationConfig:
    """Get the push notification configuration."""
    return push_config


def get_scheduler_config() -> SchedulerConfig:
    """Get the scheduler configuration."""
    return scheduler_config


def validate_notification_config() -> bool:
    """Validate all notification configurations."""
    try:
        # Validate required configurations
        required_configs = [
            notification_config.NOTIFICATION_ENABLED,
            email_config.SMTP_HOST,
            email_config.SMTP_USERNAME,
        ]
        
        # Check if critical settings are configured
        if notification_config.HIPAA_COMPLIANT_MODE:
            if not email_config.EMAIL_ENCRYPTION_REQUIRED:
                raise ValueError("Email encryption required in HIPAA compliant mode")
            if not sms_config.SMS_ENCRYPTION_REQUIRED:
                raise ValueError("SMS encryption required in HIPAA compliant mode")
            if not push_config.PUSH_PHI_FILTERING:
                raise ValueError("Push PHI filtering required in HIPAA compliant mode")
        
        return True
    except Exception as e:
        print(f"Notification configuration validation failed: {e}")
        return False


# Validate configuration on import
if not validate_notification_config():
    print("Warning: Notification configuration validation failed. Some features may not work correctly.") 