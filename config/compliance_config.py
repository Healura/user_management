"""
HIPAA Compliance Configuration

Advanced HIPAA compliance settings for real-time monitoring, breach detection,
risk assessment, and automated data governance.
"""

import os
from typing import List, Optional, Dict, Any
from pydantic import BaseSettings, Field, SecretStr


class ComplianceMonitoringConfig(BaseSettings):
    """Real-time HIPAA compliance monitoring configuration."""
    
    # Core Compliance Settings
    HIPAA_COMPLIANCE_MODE: str = Field(default="strict", env="HIPAA_COMPLIANCE_MODE")
    REAL_TIME_MONITORING: bool = Field(default=True, env="REAL_TIME_MONITORING")
    COMPLIANCE_SCORE_THRESHOLD: int = Field(default=95, env="COMPLIANCE_SCORE_THRESHOLD")
    AUTOMATIC_REMEDIATION: bool = Field(default=True, env="AUTOMATIC_REMEDIATION")
    
    # Monitoring Intervals
    REAL_TIME_SCAN_INTERVAL_SECONDS: int = Field(default=30, env="REAL_TIME_SCAN_INTERVAL_SECONDS")
    COMPLIANCE_CHECK_INTERVAL_MINUTES: int = Field(default=5, env="COMPLIANCE_CHECK_INTERVAL_MINUTES")
    POLICY_VALIDATION_INTERVAL_HOURS: int = Field(default=1, env="POLICY_VALIDATION_INTERVAL_HOURS")
    
    # Violation Thresholds
    CRITICAL_VIOLATION_THRESHOLD: int = Field(default=1, env="CRITICAL_VIOLATION_THRESHOLD")
    HIGH_VIOLATION_THRESHOLD: int = Field(default=3, env="HIGH_VIOLATION_THRESHOLD")
    MEDIUM_VIOLATION_THRESHOLD: int = Field(default=10, env="MEDIUM_VIOLATION_THRESHOLD")
    
    # Automated Response
    AUTO_DISABLE_VIOLATING_ACCOUNTS: bool = Field(default=True, env="AUTO_DISABLE_VIOLATING_ACCOUNTS")
    AUTO_REVOKE_EXCESSIVE_PERMISSIONS: bool = Field(default=True, env="AUTO_REVOKE_EXCESSIVE_PERMISSIONS")
    AUTO_ENCRYPT_UNENCRYPTED_DATA: bool = Field(default=True, env="AUTO_ENCRYPT_UNENCRYPTED_DATA")

    class Config:
        env_file = ".env"
        case_sensitive = False


class BreachDetectionConfig(BaseSettings):
    """Healthcare-specific breach detection configuration."""
    
    # Detection Settings
    BREACH_DETECTION_ENABLED: bool = Field(default=True, env="BREACH_DETECTION_ENABLED")
    SUSPICIOUS_ACCESS_THRESHOLD: int = Field(default=5, env="SUSPICIOUS_ACCESS_THRESHOLD")
    BULK_DOWNLOAD_ALERT_THRESHOLD: int = Field(default=10, env="BULK_DOWNLOAD_ALERT_THRESHOLD")
    OFF_HOURS_ACCESS_MONITORING: bool = Field(default=True, env="OFF_HOURS_ACCESS_MONITORING")
    GEOGRAPHIC_ANOMALY_DETECTION: bool = Field(default=True, env="GEOGRAPHIC_ANOMALY_DETECTION")
    
    # Behavioral Analytics
    ENABLE_BEHAVIORAL_ANALYTICS: bool = Field(default=True, env="ENABLE_BEHAVIORAL_ANALYTICS")
    BEHAVIORAL_BASELINE_DAYS: int = Field(default=30, env="BEHAVIORAL_BASELINE_DAYS")
    ANOMALY_DETECTION_SENSITIVITY: str = Field(default="medium", env="ANOMALY_DETECTION_SENSITIVITY")
    
    # Insider Threat Detection
    INSIDER_THREAT_MONITORING: bool = Field(default=True, env="INSIDER_THREAT_MONITORING")
    PRIVILEGED_USER_MONITORING: bool = Field(default=True, env="PRIVILEGED_USER_MONITORING")
    DATA_EXFILTRATION_DETECTION: bool = Field(default=True, env="DATA_EXFILTRATION_DETECTION")
    
    # Time-based Detection
    BUSINESS_HOURS_START: str = Field(default="08:00", env="BUSINESS_HOURS_START")
    BUSINESS_HOURS_END: str = Field(default="18:00", env="BUSINESS_HOURS_END")
    BUSINESS_DAYS: List[int] = Field(default=[1, 2, 3, 4, 5], env="BUSINESS_DAYS")  # Mon-Fri
    WEEKEND_ACCESS_ALERT: bool = Field(default=True, env="WEEKEND_ACCESS_ALERT")
    
    # Device and Location
    UNKNOWN_DEVICE_ALERT: bool = Field(default=True, env="UNKNOWN_DEVICE_ALERT")
    NEW_LOCATION_ALERT: bool = Field(default=True, env="NEW_LOCATION_ALERT")
    VPN_REQUIREMENT_ENFORCEMENT: bool = Field(default=True, env="VPN_REQUIREMENT_ENFORCEMENT")
    
    # File Access Patterns
    MULTIPLE_FILE_DOWNLOAD_THRESHOLD: int = Field(default=20, env="MULTIPLE_FILE_DOWNLOAD_THRESHOLD")
    RAPID_ACCESS_THRESHOLD_MINUTES: int = Field(default=10, env="RAPID_ACCESS_THRESHOLD_MINUTES")
    UNUSUAL_FILE_TYPE_ACCESS: bool = Field(default=True, env="UNUSUAL_FILE_TYPE_ACCESS")

    class Config:
        env_file = ".env"
        case_sensitive = False


class RiskAssessmentConfig(BaseSettings):
    """Automated risk assessment configuration."""
    
    # Assessment Settings
    RISK_ASSESSMENT_ENABLED: bool = Field(default=True, env="RISK_ASSESSMENT_ENABLED")
    RISK_ASSESSMENT_FREQUENCY_HOURS: int = Field(default=24, env="RISK_ASSESSMENT_FREQUENCY_HOURS")
    REAL_TIME_RISK_CALCULATION: bool = Field(default=True, env="REAL_TIME_RISK_CALCULATION")
    
    # Risk Thresholds (0-100)
    LOW_RISK_THRESHOLD: int = Field(default=30, env="LOW_RISK_THRESHOLD")
    MEDIUM_RISK_THRESHOLD: int = Field(default=60, env="MEDIUM_RISK_THRESHOLD")
    HIGH_RISK_THRESHOLD: int = Field(default=80, env="HIGH_RISK_THRESHOLD")
    CRITICAL_RISK_THRESHOLD: int = Field(default=95, env="CRITICAL_RISK_THRESHOLD")
    
    # Risk Factors
    RISK_FACTORS: List[str] = Field(
        default=["access_patterns", "data_volume", "user_behavior", "system_vulnerabilities", "compliance_violations"],
        env="RISK_FACTORS"
    )
    
    # Risk Factor Weights (must sum to 100)
    ACCESS_PATTERN_WEIGHT: int = Field(default=25, env="ACCESS_PATTERN_WEIGHT")
    DATA_VOLUME_WEIGHT: int = Field(default=20, env="DATA_VOLUME_WEIGHT")
    USER_BEHAVIOR_WEIGHT: int = Field(default=25, env="USER_BEHAVIOR_WEIGHT")
    VULNERABILITY_WEIGHT: int = Field(default=15, env="VULNERABILITY_WEIGHT")
    COMPLIANCE_WEIGHT: int = Field(default=15, env="COMPLIANCE_WEIGHT")
    
    # Escalation Settings
    RISK_ESCALATION_ENABLED: bool = Field(default=True, env="RISK_ESCALATION_ENABLED")
    AUTOMATIC_RISK_MITIGATION: bool = Field(default=True, env="AUTOMATIC_RISK_MITIGATION")
    RISK_TRENDING_ANALYSIS: bool = Field(default=True, env="RISK_TRENDING_ANALYSIS")

    class Config:
        env_file = ".env"
        case_sensitive = False


class DataRetentionConfig(BaseSettings):
    """Healthcare data retention policy configuration."""
    
    # Retention Periods (in years)
    PATIENT_DATA_RETENTION_YEARS: int = Field(default=7, env="PATIENT_DATA_RETENTION_YEARS")
    PROVIDER_DATA_RETENTION_YEARS: int = Field(default=10, env="PROVIDER_DATA_RETENTION_YEARS")
    AUDIT_LOG_RETENTION_YEARS: int = Field(default=6, env="AUDIT_LOG_RETENTION_YEARS")
    RESEARCH_DATA_RETENTION_YEARS: int = Field(default=25, env="RESEARCH_DATA_RETENTION_YEARS")
    
    # Automated Retention
    AUTOMATED_DELETION_ENABLED: bool = Field(default=True, env="AUTOMATED_DELETION_ENABLED")
    SECURE_DELETION_VERIFICATION: bool = Field(default=True, env="SECURE_DELETION_VERIFICATION")
    RETENTION_WARNING_DAYS: int = Field(default=30, env="RETENTION_WARNING_DAYS")
    
    # Grace Periods
    DELETION_GRACE_PERIOD_DAYS: int = Field(default=90, env="DELETION_GRACE_PERIOD_DAYS")
    LEGAL_HOLD_OVERRIDE: bool = Field(default=True, env="LEGAL_HOLD_OVERRIDE")
    
    # Verification
    CRYPTOGRAPHIC_DELETION_PROOF: bool = Field(default=True, env="CRYPTOGRAPHIC_DELETION_PROOF")
    DELETION_AUDIT_TRAIL: bool = Field(default=True, env="DELETION_AUDIT_TRAIL")
    THIRD_PARTY_DELETION_VERIFICATION: bool = Field(default=False, env="THIRD_PARTY_DELETION_VERIFICATION")

    class Config:
        env_file = ".env"
        case_sensitive = False


class IncidentResponseConfig(BaseSettings):
    """Healthcare incident response automation configuration."""
    
    # Response Settings
    INCIDENT_AUTO_RESPONSE: bool = Field(default=True, env="INCIDENT_AUTO_RESPONSE")
    BREACH_NOTIFICATION_DEADLINE_HOURS: int = Field(default=72, env="BREACH_NOTIFICATION_DEADLINE_HOURS")
    AUTOMATED_CONTAINMENT: bool = Field(default=True, env="AUTOMATED_CONTAINMENT")
    
    # Escalation Chain
    INCIDENT_ESCALATION_CHAIN: List[str] = Field(
        default=["security", "admin", "legal", "compliance"],
        env="INCIDENT_ESCALATION_CHAIN"
    )
    
    # Severity Levels
    INCIDENT_SEVERITY_LEVELS: List[str] = Field(
        default=["low", "medium", "high", "critical"],
        env="INCIDENT_SEVERITY_LEVELS"
    )
    
    # Automated Actions
    AUTO_DISABLE_COMPROMISED_ACCOUNTS: bool = Field(default=True, env="AUTO_DISABLE_COMPROMISED_ACCOUNTS")
    AUTO_REVOKE_SUSPICIOUS_SESSIONS: bool = Field(default=True, env="AUTO_REVOKE_SUSPICIOUS_SESSIONS")
    AUTO_QUARANTINE_AFFECTED_DATA: bool = Field(default=True, env="AUTO_QUARANTINE_AFFECTED_DATA")
    
    # Notification Settings
    REGULATORY_NOTIFICATION_REQUIRED: bool = Field(default=True, env="REGULATORY_NOTIFICATION_REQUIRED")
    PATIENT_NOTIFICATION_REQUIRED: bool = Field(default=True, env="PATIENT_NOTIFICATION_REQUIRED")
    MEDIA_NOTIFICATION_THRESHOLD: int = Field(default=500, env="MEDIA_NOTIFICATION_THRESHOLD")  # Affected individuals
    
    # Evidence Collection
    AUTOMATED_EVIDENCE_COLLECTION: bool = Field(default=True, env="AUTOMATED_EVIDENCE_COLLECTION")
    FORENSIC_IMAGING_ENABLED: bool = Field(default=True, env="FORENSIC_IMAGING_ENABLED")
    CHAIN_OF_CUSTODY_TRACKING: bool = Field(default=True, env="CHAIN_OF_CUSTODY_TRACKING")

    class Config:
        env_file = ".env"
        case_sensitive = False


class DataGovernanceConfig(BaseSettings):
    """Healthcare data governance automation configuration."""
    
    # PHI Classification
    AUTOMATED_PHI_CLASSIFICATION: bool = Field(default=True, env="AUTOMATED_PHI_CLASSIFICATION")
    PHI_CLASSIFICATION_CONFIDENCE_THRESHOLD: float = Field(default=0.8, env="PHI_CLASSIFICATION_CONFIDENCE_THRESHOLD")
    PHI_RECLASSIFICATION_INTERVAL_DAYS: int = Field(default=30, env="PHI_RECLASSIFICATION_INTERVAL_DAYS")
    
    # Data Minimization
    DATA_MINIMIZATION_ENFORCEMENT: bool = Field(default=True, env="DATA_MINIMIZATION_ENFORCEMENT")
    PURPOSE_LIMITATION_VALIDATION: bool = Field(default=True, env="PURPOSE_LIMITATION_VALIDATION")
    ACCESS_JUSTIFICATION_REQUIRED: bool = Field(default=True, env="ACCESS_JUSTIFICATION_REQUIRED")
    
    # Consent Management
    CONSENT_EXPIRATION_TRACKING: bool = Field(default=True, env="CONSENT_EXPIRATION_TRACKING")
    AUTOMATED_CONSENT_RENEWAL: bool = Field(default=True, env="AUTOMATED_CONSENT_RENEWAL")
    CONSENT_WITHDRAWAL_PROCESSING: bool = Field(default=True, env="CONSENT_WITHDRAWAL_PROCESSING")
    
    # Cross-Border Controls
    CROSS_BORDER_TRANSFER_CONTROLS: bool = Field(default=True, env="CROSS_BORDER_TRANSFER_CONTROLS")
    ADEQUACY_DECISION_VALIDATION: bool = Field(default=True, env="ADEQUACY_DECISION_VALIDATION")
    INTERNATIONAL_TRANSFER_LOGGING: bool = Field(default=True, env="INTERNATIONAL_TRANSFER_LOGGING")
    
    # Data Lineage
    DATA_LINEAGE_TRACKING: bool = Field(default=True, env="DATA_LINEAGE_TRACKING")
    DATA_FLOW_VISUALIZATION: bool = Field(default=True, env="DATA_FLOW_VISUALIZATION")
    THIRD_PARTY_DATA_SHARING_TRACKING: bool = Field(default=True, env="THIRD_PARTY_DATA_SHARING_TRACKING")

    class Config:
        env_file = ".env"
        case_sensitive = False


class BAAComplianceConfig(BaseSettings):
    """Business Associate Agreement compliance configuration."""
    
    # BAA Requirements
    BAA_COMPLIANCE_MONITORING: bool = Field(default=True, env="BAA_COMPLIANCE_MONITORING")
    BAA_VALIDATION_FREQUENCY_DAYS: int = Field(default=30, env="BAA_VALIDATION_FREQUENCY_DAYS")
    BAA_RENEWAL_REMINDER_DAYS: int = Field(default=90, env="BAA_RENEWAL_REMINDER_DAYS")
    
    # Vendor Management
    VENDOR_COMPLIANCE_TRACKING: bool = Field(default=True, env="VENDOR_COMPLIANCE_TRACKING")
    VENDOR_RISK_ASSESSMENT_REQUIRED: bool = Field(default=True, env="VENDOR_RISK_ASSESSMENT_REQUIRED")
    VENDOR_AUDIT_FREQUENCY_MONTHS: int = Field(default=12, env="VENDOR_AUDIT_FREQUENCY_MONTHS")
    
    # Subcontractor Controls
    SUBCONTRACTOR_BAA_REQUIRED: bool = Field(default=True, env="SUBCONTRACTOR_BAA_REQUIRED")
    SUBCONTRACTOR_MONITORING: bool = Field(default=True, env="SUBCONTRACTOR_MONITORING")
    SUBCONTRACTOR_APPROVAL_REQUIRED: bool = Field(default=True, env="SUBCONTRACTOR_APPROVAL_REQUIRED")
    
    # Security Requirements
    MINIMUM_ENCRYPTION_STANDARD: str = Field(default="AES-256", env="MINIMUM_ENCRYPTION_STANDARD")
    PENETRATION_TESTING_REQUIRED: bool = Field(default=True, env="PENETRATION_TESTING_REQUIRED")
    VULNERABILITY_SCANNING_FREQUENCY_DAYS: int = Field(default=7, env="VULNERABILITY_SCANNING_FREQUENCY_DAYS")
    
    # Incident Response Requirements
    INCIDENT_NOTIFICATION_HOURS: int = Field(default=24, env="INCIDENT_NOTIFICATION_HOURS")
    BREACH_NOTIFICATION_HOURS: int = Field(default=6, env="BREACH_NOTIFICATION_HOURS")
    POST_INCIDENT_REPORTING_REQUIRED: bool = Field(default=True, env="POST_INCIDENT_REPORTING_REQUIRED")

    class Config:
        env_file = ".env"
        case_sensitive = False


class ComplianceConfig(BaseSettings):
    """Main compliance configuration container."""
    
    # Global Settings
    COMPLIANCE_FRAMEWORK: str = Field(default="HIPAA", env="COMPLIANCE_FRAMEWORK")
    COMPLIANCE_ENVIRONMENT: str = Field(default="production", env="COMPLIANCE_ENVIRONMENT")
    COMPLIANCE_OFFICER_EMAIL: str = Field(default="compliance@voicebiomarker.com", env="COMPLIANCE_OFFICER_EMAIL")
    
    # Reporting
    COMPLIANCE_REPORTING_ENABLED: bool = Field(default=True, env="COMPLIANCE_REPORTING_ENABLED")
    COMPLIANCE_REPORT_SCHEDULE: str = Field(default="daily", env="COMPLIANCE_REPORT_SCHEDULE")
    COMPLIANCE_DASHBOARD_ENABLED: bool = Field(default=True, env="COMPLIANCE_DASHBOARD_ENABLED")
    
    # Integration
    CLOUDTRAIL_INTEGRATION: bool = Field(default=True, env="CLOUDTRAIL_INTEGRATION")
    SIEM_INTEGRATION: bool = Field(default=True, env="SIEM_INTEGRATION")
    NOTIFICATION_INTEGRATION: bool = Field(default=True, env="NOTIFICATION_INTEGRATION")
    
    # Emergency Settings
    EMERGENCY_OVERRIDE_ENABLED: bool = Field(default=True, env="EMERGENCY_OVERRIDE_ENABLED")
    EMERGENCY_CONTACT_LIST: List[str] = Field(
        default=["security@voicebiomarker.com", "legal@voicebiomarker.com"],
        env="EMERGENCY_CONTACT_LIST"
    )

    class Config:
        env_file = ".env"
        case_sensitive = False


# Global configuration instances
monitoring_config = ComplianceMonitoringConfig()
breach_detection_config = BreachDetectionConfig()
risk_assessment_config = RiskAssessmentConfig()
data_retention_config = DataRetentionConfig()
incident_response_config = IncidentResponseConfig()
data_governance_config = DataGovernanceConfig()
baa_compliance_config = BAAComplianceConfig()
compliance_config = ComplianceConfig()


def get_compliance_config() -> ComplianceConfig:
    """Get the main compliance configuration."""
    return compliance_config


def get_monitoring_config() -> ComplianceMonitoringConfig:
    """Get the compliance monitoring configuration."""
    return monitoring_config


def get_breach_detection_config() -> BreachDetectionConfig:
    """Get the breach detection configuration."""
    return breach_detection_config


def get_risk_assessment_config() -> RiskAssessmentConfig:
    """Get the risk assessment configuration."""
    return risk_assessment_config


def get_data_retention_config() -> DataRetentionConfig:
    """Get the data retention configuration."""
    return data_retention_config


def get_incident_response_config() -> IncidentResponseConfig:
    """Get the incident response configuration."""
    return incident_response_config


def get_data_governance_config() -> DataGovernanceConfig:
    """Get the data governance configuration."""
    return data_governance_config


def get_baa_compliance_config() -> BAAComplianceConfig:
    """Get the BAA compliance configuration."""
    return baa_compliance_config


def validate_compliance_config() -> bool:
    """Validate all compliance configurations."""
    try:
        # Validate risk factor weights sum to 100
        total_weight = (
            risk_assessment_config.ACCESS_PATTERN_WEIGHT +
            risk_assessment_config.DATA_VOLUME_WEIGHT +
            risk_assessment_config.USER_BEHAVIOR_WEIGHT +
            risk_assessment_config.VULNERABILITY_WEIGHT +
            risk_assessment_config.COMPLIANCE_WEIGHT
        )
        
        if total_weight != 100:
            raise ValueError(f"Risk factor weights must sum to 100, got {total_weight}")
        
        # Validate thresholds are in correct order
        if not (
            risk_assessment_config.LOW_RISK_THRESHOLD < 
            risk_assessment_config.MEDIUM_RISK_THRESHOLD < 
            risk_assessment_config.HIGH_RISK_THRESHOLD < 
            risk_assessment_config.CRITICAL_RISK_THRESHOLD
        ):
            raise ValueError("Risk thresholds must be in ascending order")
        
        # Validate business hours format
        import re
        time_pattern = r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$'
        if not (re.match(time_pattern, breach_detection_config.BUSINESS_HOURS_START) and
                re.match(time_pattern, breach_detection_config.BUSINESS_HOURS_END)):
            raise ValueError("Business hours must be in HH:MM format")
        
        return True
        
    except Exception as e:
        print(f"Compliance configuration validation failed: {e}")
        return False


# Validate configuration on import
if not validate_compliance_config():
    print("Warning: Compliance configuration validation failed. Some features may not work correctly.") 