"""Security configuration for HIPAA compliance and data protection."""

from pydantic_settings import BaseSettings
from pydantic import Field


class SecurityConfig(BaseSettings):
    """Security and compliance configuration."""
    
    # Encryption
    encryption_algorithm: str = Field(default="AES-256-GCM", env="ENCRYPTION_ALGORITHM")
    key_rotation_days: int = Field(default=90, env="KEY_ROTATION_DAYS")
    
    # Data Retention
    default_data_retention_days: int = Field(default=365, env="DEFAULT_DATA_RETENTION_DAYS")
    audit_log_retention_days: int = Field(default=2555, env="AUDIT_LOG_RETENTION_DAYS")  # 7 years
    
    # Rate Limiting
    rate_limit_requests: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, env="RATE_LIMIT_WINDOW_SECONDS")
    
    # Security Features
    enable_audit_logging: bool = Field(default=True, env="ENABLE_AUDIT_LOGGING")
    enable_encryption_at_rest: bool = Field(default=True, env="ENABLE_ENCRYPTION_AT_REST")
    enable_ip_whitelist: bool = Field(default=False, env="ENABLE_IP_WHITELIST")
    ip_whitelist: list[str] = Field(default=[], env="IP_WHITELIST")
    
    # HIPAA Compliance
    hipaa_compliant_mode: bool = Field(default=True, env="HIPAA_COMPLIANT_MODE")
    require_privacy_consent: bool = Field(default=True, env="REQUIRE_PRIVACY_CONSENT")
    
    # Session Security
    secure_cookies: bool = Field(default=True, env="SECURE_COOKIES")
    samesite_cookies: str = Field(default="strict", env="SAMESITE_COOKIES")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Create a singleton instance
security_config = SecurityConfig()