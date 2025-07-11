from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class StorageConfig(BaseSettings):
    """Storage configuration with healthcare compliance settings."""
    
    # Storage Provider
    storage_provider: str = Field(default="s3", env="STORAGE_PROVIDER")
    local_storage_path: str = Field(default="./uploads", env="LOCAL_STORAGE_PATH")
    
    # S3 Healthcare Configuration
    aws_s3_bucket: str = Field(
        default="voice-biomarker-audio-files-eu-central-1",
        env="AWS_S3_BUCKET"
    )
    aws_s3_region: str = Field(default="eu-central-1", env="AWS_S3_REGION")
    aws_s3_use_vpc_endpoint: bool = Field(default=True, env="AWS_S3_USE_VPC_ENDPOINT")
    s3_vpc_endpoint_url: Optional[str] = Field(default=None, env="S3_VPC_ENDPOINT_URL")
    
    # Healthcare Encryption
    aws_kms_key_id: str = Field(
        default="alias/voice-biomarker-file-encryption",
        env="AWS_KMS_KEY_ID"
    )
    enable_double_encryption: bool = Field(default=True, env="ENABLE_DOUBLE_ENCRYPTION")
    file_integrity_verification: bool = Field(default=True, env="FILE_INTEGRITY_VERIFICATION")
    encryption_at_rest_required: bool = Field(default=True, env="ENCRYPTION_AT_REST_REQUIRED")
    
    # HIPAA Compliance Settings
    phi_classification_required: bool = Field(default=True, env="PHI_CLASSIFICATION_REQUIRED")
    minimum_necessary_access: bool = Field(default=True, env="MINIMUM_NECESSARY_ACCESS")
    audit_all_operations: bool = Field(default=True, env="AUDIT_ALL_OPERATIONS")
    breach_notification_enabled: bool = Field(default=True, env="BREACH_NOTIFICATION_ENABLED")
    compliance_reporting_enabled: bool = Field(default=True, env="COMPLIANCE_REPORTING_ENABLED")
    
    # Healthcare Retention Policies (in years)
    healthcare_retention_years: int = Field(default=7, env="HEALTHCARE_RETENTION_YEARS")
    patient_retention_years: int = Field(default=10, env="PATIENT_RETENTION_YEARS")
    research_retention_years: int = Field(default=25, env="RESEARCH_RETENTION_YEARS")
    auto_retention_enforcement: bool = Field(default=True, env="AUTO_RETENTION_ENFORCEMENT")
    retention_warning_days: int = Field(default=30, env="RETENTION_WARNING_DAYS")
    
    # Secure File Access
    presigned_url_expiry_minutes: int = Field(default=5, env="PRESIGNED_URL_EXPIRY_MINUTES")
    max_download_attempts: int = Field(default=3, env="MAX_DOWNLOAD_ATTEMPTS")
    file_access_session_timeout: int = Field(default=15, env="FILE_ACCESS_SESSION_TIMEOUT")
    require_mfa_for_download: bool = Field(default=True, env="REQUIRE_MFA_FOR_DOWNLOAD")
    
    # CloudTrail Integration
    cloudtrail_log_group: str = Field(
        default="voice-biomarker-audit-logs",
        env="CLOUDTRAIL_LOG_GROUP"
    )
    cloudtrail_s3_bucket: str = Field(
        default="voice-biomarker-cloudtrail-logs",
        env="CLOUDTRAIL_S3_BUCKET"
    )
    real_time_audit_processing: bool = Field(default=True, env="REAL_TIME_AUDIT_PROCESSING")
    suspicious_activity_alerts: bool = Field(default=True, env="SUSPICIOUS_ACTIVITY_ALERTS")
    
    # Healthcare File Validation
    validate_phi_content: bool = Field(default=True, env="VALIDATE_PHI_CONTENT")
    malware_scanning_required: bool = Field(default=True, env="MALWARE_SCANNING_REQUIRED")
    file_content_analysis: bool = Field(default=True, env="FILE_CONTENT_ANALYSIS")
    healthcare_metadata_required: bool = Field(default=True, env="HEALTHCARE_METADATA_REQUIRED")
    
    # Network Security
    require_vpc_access: bool = Field(default=True, env="REQUIRE_VPC_ACCESS")
    block_public_internet: bool = Field(default=True, env="BLOCK_PUBLIC_INTERNET")
    network_segmentation: bool = Field(default=True, env="NETWORK_SEGMENTATION")
    
    # File Size and Type Limits
    max_file_size_mb: int = Field(default=500, env="MAX_FILE_SIZE_MB")
    allowed_file_types: List[str] = Field(
        default=["audio/wav", "audio/mp3", "audio/mpeg", "audio/m4a", "audio/aac"],
        env="ALLOWED_FILE_TYPES"
    )
    allowed_extensions: List[str] = Field(
        default=[".wav", ".mp3", ".m4a", ".aac"],
        env="ALLOWED_EXTENSIONS"
    )
    
    # Storage Quotas (in GB)
    patient_storage_quota_gb: int = Field(default=10, env="PATIENT_STORAGE_QUOTA_GB")
    provider_storage_quota_gb: int = Field(default=100, env="PROVIDER_STORAGE_QUOTA_GB")
    organization_storage_quota_gb: int = Field(default=1000, env="ORGANIZATION_STORAGE_QUOTA_GB")
    
    # Backup and Recovery
    enable_versioning: bool = Field(default=True, env="ENABLE_VERSIONING")
    backup_retention_days: int = Field(default=90, env="BACKUP_RETENTION_DAYS")
    cross_region_replication: bool = Field(default=True, env="CROSS_REGION_REPLICATION")
    
    # Performance Settings
    multipart_threshold_mb: int = Field(default=100, env="MULTIPART_THRESHOLD_MB")
    multipart_chunk_size_mb: int = Field(default=10, env="MULTIPART_CHUNK_SIZE_MB")
    concurrent_uploads: int = Field(default=5, env="CONCURRENT_UPLOADS")
    
    # PHI Classification Levels
    phi_classification_levels: List[str] = Field(
        default=["HIGH", "MEDIUM", "LOW", "PUBLIC"],
        env="PHI_CLASSIFICATION_LEVELS"
    )
    default_phi_classification: str = Field(default="HIGH", env="DEFAULT_PHI_CLASSIFICATION")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        extra = "ignore"  # Allow extra fields in .env file


# Create singleton instance
storage_config = StorageConfig()


# S3 client configuration for healthcare
def get_s3_client_config() -> dict:
    """Get S3 client configuration with VPC endpoint support."""
    config = {
        'region_name': storage_config.aws_s3_region,
        'use_ssl': True,
        'verify': True
    }
    
    if storage_config.aws_s3_use_vpc_endpoint and storage_config.s3_vpc_endpoint_url:
        config['endpoint_url'] = storage_config.s3_vpc_endpoint_url
    
    return config


# KMS encryption configuration
def get_encryption_config() -> dict:
    """Get KMS encryption configuration for healthcare."""
    return {
        'algorithm': 'AES256',
        'kms_key_id': storage_config.aws_kms_key_id,
        'key_rotation': True,
        'audit_enabled': True,
        'compliance_mode': 'HIPAA',
        'double_encryption': storage_config.enable_double_encryption
    }


# Retention policy configuration
def get_retention_config(file_type: str = "healthcare") -> dict:
    """Get retention configuration based on file type."""
    retention_map = {
        "healthcare": storage_config.healthcare_retention_years,
        "patient": storage_config.patient_retention_years,
        "research": storage_config.research_retention_years
    }
    
    return {
        "retention_years": retention_map.get(file_type, storage_config.healthcare_retention_years),
        "auto_enforcement": storage_config.auto_retention_enforcement,
        "warning_days": storage_config.retention_warning_days,
        "deletion_grace_period_days": 30
    }