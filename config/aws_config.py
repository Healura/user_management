"""AWS configuration for RDS, S3, and other services."""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class AWSConfig(BaseSettings):
    """AWS service configuration."""
    
    # AWS Credentials
    aws_access_key_id: Optional[str] = Field(default=None, env="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[SecretStr] = Field(default=None, env="AWS_SECRET_ACCESS_KEY")
    aws_region: str = Field(default="eu-central-1", env="AWS_REGION")
    
    # RDS Configuration
    rds_ca_bundle_path: Optional[str] = Field(
        default="/opt/aws/rds-ca-2019-root.pem",
        env="RDS_CA_BUNDLE_PATH"
    )
    
    # S3 Configuration (for future audio file storage)
    s3_bucket_name: Optional[str] = Field(default=None, env="S3_BUCKET_NAME")
    s3_audio_prefix: str = Field(default="audio-files/", env="S3_AUDIO_PREFIX")
    s3_presigned_url_expiry: int = Field(default=3600, env="S3_PRESIGNED_URL_EXPIRY")
    
    # CloudWatch Configuration
    cloudwatch_log_group: str = Field(
        default="/aws/ecs/voice-biomarker/user-management",
        env="CLOUDWATCH_LOG_GROUP"
    )
    cloudwatch_log_stream: Optional[str] = Field(default=None, env="CLOUDWATCH_LOG_STREAM")
    
    # Secrets Manager Configuration
    use_secrets_manager: bool = Field(default=False, env="USE_SECRETS_MANAGER")
    secrets_manager_db_secret: Optional[str] = Field(
        default="voice-biomarker/rds/credentials",
        env="SECRETS_MANAGER_DB_SECRET"
    )
    
    # KMS Configuration (for encryption)
    kms_key_id: Optional[str] = Field(default=None, env="KMS_KEY_ID")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Allow extra fields in .env file


# Create a singleton instance
aws_config = AWSConfig()