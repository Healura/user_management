"""Authentication settings for JWT and security configuration."""

from datetime import timedelta
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class AuthSettings(BaseSettings):
    """Authentication configuration settings."""
    
    # JWT Configuration
    secret_key: SecretStr = Field(..., env="SECRET_KEY")
    jwt_private_key_path: str = Field(default="./keys/jwt_private_key.pem", env="JWT_PRIVATE_KEY_PATH")
    jwt_public_key_path: str = Field(default="./keys/jwt_public_key.pem", env="JWT_PUBLIC_KEY_PATH")
    algorithm: str = Field(default="RS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=15, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    
    # Password Policy
    password_min_length: int = Field(default=12, env="PASSWORD_MIN_LENGTH")
    password_require_uppercase: bool = Field(default=True, env="PASSWORD_REQUIRE_UPPERCASE")
    password_require_lowercase: bool = Field(default=True, env="PASSWORD_REQUIRE_LOWERCASE")
    password_require_numbers: bool = Field(default=True, env="PASSWORD_REQUIRE_NUMBERS")
    password_require_special: bool = Field(default=True, env="PASSWORD_REQUIRE_SPECIAL")
    password_history_count: int = Field(default=5, env="PASSWORD_HISTORY_COUNT")
    password_expiry_days: int = Field(default=90, env="PASSWORD_EXPIRY_DAYS")
    
    # Session Configuration
    max_sessions_per_user: int = Field(default=5, env="MAX_SESSIONS_PER_USER")
    session_timeout_minutes: int = Field(default=60, env="SESSION_TIMEOUT_MINUTES")
    
    # Security Settings
    max_login_attempts: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS")
    lockout_duration_minutes: int = Field(default=30, env="LOCKOUT_DURATION_MINUTES")
    bcrypt_rounds: int = Field(default=12, env="BCRYPT_ROUNDS")
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = Field(default=100, env="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_burst_requests: int = Field(default=20, env="RATE_LIMIT_BURST_REQUESTS")
    
    # Email Configuration
    smtp_host: str = Field(default="smtp.gmail.com", env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_username: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    smtp_password: Optional[SecretStr] = Field(default=None, env="SMTP_PASSWORD")
    email_from: str = Field(default="noreply@voicebiomarker.com", env="EMAIL_FROM")
    email_verification_expire_hours: int = Field(default=24, env="EMAIL_VERIFICATION_EXPIRE_HOURS")
    
    # MFA Configuration
    mfa_issuer_name: str = Field(default="Voice Biomarker", env="MFA_ISSUER_NAME")
    mfa_qr_code_size: int = Field(default=200, env="MFA_QR_CODE_SIZE")
    mfa_backup_codes_count: int = Field(default=10, env="MFA_BACKUP_CODES_COUNT")
    
    # Security Headers
    cors_origins: list[str] = Field(
        default=["http://localhost:3000"],
        env="CORS_ORIGINS"
    )
    cors_allow_credentials: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")
    
    # Redis Configuration (for rate limiting)
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")
    
    @property
    def access_token_expire_timedelta(self) -> timedelta:
        return timedelta(minutes=self.access_token_expire_minutes)
    
    @property
    def refresh_token_expire_timedelta(self) -> timedelta:
        return timedelta(days=self.refresh_token_expire_days)
    
    @property
    def lockout_duration_timedelta(self) -> timedelta:
        return timedelta(minutes=self.lockout_duration_minutes)
    
    @property
    def email_verification_expire_timedelta(self) -> timedelta:
        return timedelta(hours=self.email_verification_expire_hours)
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Allow extra fields in .env file


# Create a singleton instance
auth_settings = AuthSettings()