"""
Real-time HIPAA Compliance Validation

Monitors system state and detects HIPAA compliance violations in real-time.
Provides automated compliance scoring and remediation recommendations.
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from src.database.models import User, AuditLog, AudioFile, NotificationHistory, UserSession
from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from src.utils.cloudtrail_parser import CloudTrailParser
from config.compliance_config import (
    get_monitoring_config, 
    get_compliance_config,
    get_data_governance_config,
    get_baa_compliance_config
)

logger = logging.getLogger(__name__)


class ComplianceViolationType(Enum):
    """Types of HIPAA compliance violations."""
    ACCESS_CONTROL = "access_control"
    DATA_ENCRYPTION = "data_encryption"
    AUDIT_LOGGING = "audit_logging"
    DATA_RETENTION = "data_retention"
    MINIMUM_NECESSARY = "minimum_necessary"
    USER_AUTHENTICATION = "user_authentication"
    BUSINESS_ASSOCIATE = "business_associate"
    BREACH_NOTIFICATION = "breach_notification"
    ADMINISTRATIVE_SAFEGUARDS = "administrative_safeguards"
    PHYSICAL_SAFEGUARDS = "physical_safeguards"
    TECHNICAL_SAFEGUARDS = "technical_safeguards"


class ViolationSeverity(Enum):
    """Severity levels for compliance violations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ComplianceViolation:
    """Represents a specific compliance violation."""
    id: str
    violation_type: ComplianceViolationType
    severity: ViolationSeverity
    title: str
    description: str
    affected_resource: Optional[str] = None
    user_id: Optional[UUID] = None
    timestamp: datetime = None
    remediation_steps: List[str] = None
    auto_remediable: bool = False
    regulatory_reference: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.remediation_steps is None:
            self.remediation_steps = []


@dataclass
class ComplianceScore:
    """Overall compliance scoring."""
    total_score: int  # 0-100
    category_scores: Dict[str, int]
    violations_count: int
    last_assessment: datetime
    trending: str  # improving, declining, stable
    risk_level: str  # low, medium, high, critical


class HIPAAComplianceChecker:
    """Real-time HIPAA compliance validation engine."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.monitoring_config = get_monitoring_config()
        self.compliance_config = get_compliance_config()
        self.data_governance_config = get_data_governance_config()
        self.baa_config = get_baa_compliance_config()
        
        # CloudTrail integration
        self.cloudtrail_parser = CloudTrailParser()
        
        # Violation cache for performance
        self.violation_cache = {}
        self.last_check_time = {}
        
    async def perform_comprehensive_compliance_check(
        self,
        user_id: Optional[UUID] = None,
        resource_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive HIPAA compliance check.
        
        Args:
            user_id: Specific user to check (optional)
            resource_id: Specific resource to check (optional)
            
        Returns:
            Comprehensive compliance assessment
        """
        try:
            logger.info("Starting comprehensive HIPAA compliance check")
            
            # Run all compliance checks
            check_results = await asyncio.gather(
                self._check_access_controls(user_id),
                self._check_data_encryption(),
                self._check_audit_logging(),
                self._check_data_retention(),
                self._check_minimum_necessary_access(user_id),
                self._check_user_authentication(),
                self._check_business_associate_compliance(),
                self._check_administrative_safeguards(),
                self._check_physical_safeguards(),
                self._check_technical_safeguards(),
                return_exceptions=True
            )
            
            # Collect all violations
            all_violations = []
            check_names = [
                "access_controls", "data_encryption", "audit_logging",
                "data_retention", "minimum_necessary", "user_authentication",
                "business_associate", "administrative_safeguards",
                "physical_safeguards", "technical_safeguards"
            ]
            
            detailed_results = {}
            for i, result in enumerate(check_results):
                check_name = check_names[i]
                if isinstance(result, Exception):
                    logger.error(f"Check {check_name} failed: {result}")
                    detailed_results[check_name] = {"error": str(result)}
                else:
                    detailed_results[check_name] = result
                    all_violations.extend(result.get("violations", []))
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(all_violations)
            
            # Generate remediation plan
            remediation_plan = self._generate_remediation_plan(all_violations)
            
            # Create summary
            summary = {
                "assessment_timestamp": datetime.utcnow().isoformat(),
                "compliance_score": asdict(compliance_score),
                "total_violations": len(all_violations),
                "violations_by_severity": self._count_violations_by_severity(all_violations),
                "violations_by_type": self._count_violations_by_type(all_violations),
                "critical_violations": [v for v in all_violations if v.severity == ViolationSeverity.CRITICAL],
                "remediation_plan": remediation_plan,
                "detailed_results": detailed_results,
                "recommendations": self._generate_compliance_recommendations(compliance_score, all_violations)
            }
            
            # Log compliance assessment
            await self._log_compliance_assessment(summary, user_id)
            
            return summary
            
        except Exception as e:
            logger.error(f"Comprehensive compliance check failed: {e}")
            raise
    
    async def _check_access_controls(self, user_id: Optional[UUID] = None) -> Dict[str, Any]:
        """Check HIPAA access control requirements."""
        violations = []
        
        try:
            # Check 1: Users must have appropriate role assignments
            users_query = self.db.query(User)
            if user_id:
                users_query = users_query.filter(User.id == user_id)
            
            users = users_query.all()
            
            for user in users:
                if not user.role_assignments:
                    violations.append(ComplianceViolation(
                        id=f"access_control_no_role_{user.id}",
                        violation_type=ComplianceViolationType.ACCESS_CONTROL,
                        severity=ViolationSeverity.HIGH,
                        title="User without assigned role",
                        description=f"User {user.email} has no assigned roles",
                        user_id=user.id,
                        remediation_steps=[
                            "Assign appropriate role to user",
                            "Review user access requirements",
                            "Implement principle of least privilege"
                        ],
                        auto_remediable=False,
                        regulatory_reference="45 CFR 164.312(a)(1)"
                    ))
            
            # Check 2: Inactive users should not have active sessions
            inactive_users_with_sessions = self.db.query(User).join(UserSession).filter(
                and_(
                    User.is_active == False,
                    UserSession.is_active == True
                )
            ).all()
            
            for user in inactive_users_with_sessions:
                violations.append(ComplianceViolation(
                    id=f"access_control_inactive_user_session_{user.id}",
                    violation_type=ComplianceViolationType.ACCESS_CONTROL,
                    severity=ViolationSeverity.HIGH,
                    title="Inactive user with active sessions",
                    description=f"Inactive user {user.email} has active sessions",
                    user_id=user.id,
                    remediation_steps=[
                        "Terminate all sessions for inactive user",
                        "Review user deactivation procedures",
                        "Implement automated session cleanup"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.308(a)(3)(ii)(C)"
                ))
            
            # Check 3: Sessions should not exceed maximum duration
            long_sessions = self.db.query(UserSession).filter(
                and_(
                    UserSession.is_active == True,
                    UserSession.created_at < datetime.utcnow() - timedelta(hours=24)
                )
            ).all()
            
            for session in long_sessions:
                violations.append(ComplianceViolation(
                    id=f"access_control_long_session_{session.id}",
                    violation_type=ComplianceViolationType.ACCESS_CONTROL,
                    severity=ViolationSeverity.MEDIUM,
                    title="Session exceeds maximum duration",
                    description=f"Session {session.id} has been active for over 24 hours",
                    user_id=session.user_id,
                    remediation_steps=[
                        "Terminate long-running session",
                        "Implement session timeout policies",
                        "Review session management configuration"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.312(a)(2)(iii)"
                ))
            
            return {
                "check_type": "access_controls",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "checked_users": len(users),
                "checked_sessions": self.db.query(UserSession).filter(UserSession.is_active == True).count()
            }
            
        except Exception as e:
            logger.error(f"Access control check failed: {e}")
            return {"check_type": "access_controls", "error": str(e)}
    
    async def _check_data_encryption(self) -> Dict[str, Any]:
        """Check data encryption compliance."""
        violations = []
        
        try:
            # Check 1: All audio files should have encryption key IDs
            unencrypted_files = self.db.query(AudioFile).filter(
                or_(
                    AudioFile.encryption_key_id.is_(None),
                    AudioFile.encryption_key_id == ""
                )
            ).all()
            
            for file in unencrypted_files:
                violations.append(ComplianceViolation(
                    id=f"encryption_unencrypted_file_{file.id}",
                    violation_type=ComplianceViolationType.DATA_ENCRYPTION,
                    severity=ViolationSeverity.CRITICAL,
                    title="Unencrypted PHI file",
                    description=f"Audio file {file.filename} is not encrypted",
                    affected_resource=str(file.id),
                    user_id=file.user_id,
                    remediation_steps=[
                        "Encrypt the file immediately",
                        "Review file upload encryption process",
                        "Implement mandatory encryption checks"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.312(a)(2)(iv)"
                ))
            
            # Check 2: Check for files uploaded without proper encryption metadata
            recent_files = self.db.query(AudioFile).filter(
                AudioFile.uploaded_at > datetime.utcnow() - timedelta(hours=24)
            ).all()
            
            for file in recent_files:
                if not file.encryption_key_id:
                    violations.append(ComplianceViolation(
                        id=f"encryption_recent_unencrypted_{file.id}",
                        violation_type=ComplianceViolationType.DATA_ENCRYPTION,
                        severity=ViolationSeverity.HIGH,
                        title="Recently uploaded file without encryption",
                        description=f"File {file.filename} uploaded in last 24 hours without encryption",
                        affected_resource=str(file.id),
                        user_id=file.user_id,
                        remediation_steps=[
                            "Immediately encrypt the file",
                            "Review upload process",
                            "Implement encryption validation at upload"
                        ],
                        auto_remediable=True,
                        regulatory_reference="45 CFR 164.312(a)(2)(iv)"
                    ))
            
            return {
                "check_type": "data_encryption",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "total_files_checked": self.db.query(AudioFile).count(),
                "unencrypted_files": len(unencrypted_files)
            }
            
        except Exception as e:
            logger.error(f"Data encryption check failed: {e}")
            return {"check_type": "data_encryption", "error": str(e)}
    
    async def _check_audit_logging(self) -> Dict[str, Any]:
        """Check audit logging compliance."""
        violations = []
        
        try:
            # Check 1: Ensure audit logs are being generated
            recent_audit_count = self.db.query(AuditLog).filter(
                AuditLog.timestamp > datetime.utcnow() - timedelta(hours=1)
            ).count()
            
            if recent_audit_count == 0:
                violations.append(ComplianceViolation(
                    id="audit_no_recent_logs",
                    violation_type=ComplianceViolationType.AUDIT_LOGGING,
                    severity=ViolationSeverity.CRITICAL,
                    title="No recent audit logs",
                    description="No audit logs generated in the last hour",
                    remediation_steps=[
                        "Check audit logging service status",
                        "Verify audit log configuration",
                        "Review application audit integration"
                    ],
                    auto_remediable=False,
                    regulatory_reference="45 CFR 164.312(b)"
                ))
            
            # Check 2: Critical actions should have audit logs
            critical_actions = ["login", "logout", "file_upload", "file_download", "user_create"]
            
            for action in critical_actions:
                action_count = self.db.query(AuditLog).filter(
                    and_(
                        AuditLog.action.like(f"%{action}%"),
                        AuditLog.timestamp > datetime.utcnow() - timedelta(days=1)
                    )
                ).count()
                
                if action_count == 0:
                    violations.append(ComplianceViolation(
                        id=f"audit_missing_action_{action}",
                        violation_type=ComplianceViolationType.AUDIT_LOGGING,
                        severity=ViolationSeverity.MEDIUM,
                        title=f"No audit logs for {action} actions",
                        description=f"No {action} actions logged in the last 24 hours",
                        remediation_steps=[
                            f"Review {action} action logging",
                            "Verify audit log coverage",
                            "Check application instrumentation"
                        ],
                        auto_remediable=False,
                        regulatory_reference="45 CFR 164.312(b)"
                    ))
            
            # Check 3: Audit logs should have required fields
            incomplete_logs = self.db.query(AuditLog).filter(
                or_(
                    AuditLog.user_id.is_(None),
                    AuditLog.action.is_(None),
                    AuditLog.timestamp.is_(None)
                )
            ).limit(100).all()
            
            for log in incomplete_logs:
                violations.append(ComplianceViolation(
                    id=f"audit_incomplete_log_{log.id}",
                    violation_type=ComplianceViolationType.AUDIT_LOGGING,
                    severity=ViolationSeverity.MEDIUM,
                    title="Incomplete audit log entry",
                    description=f"Audit log {log.id} missing required fields",
                    remediation_steps=[
                        "Review audit log generation process",
                        "Ensure all required fields are captured",
                        "Implement audit log validation"
                    ],
                    auto_remediable=False,
                    regulatory_reference="45 CFR 164.312(b)"
                ))
            
            return {
                "check_type": "audit_logging",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "total_logs": self.db.query(AuditLog).count(),
                "recent_logs": recent_audit_count
            }
            
        except Exception as e:
            logger.error(f"Audit logging check failed: {e}")
            return {"check_type": "audit_logging", "error": str(e)}
    
    async def _check_data_retention(self) -> Dict[str, Any]:
        """Check data retention policy compliance."""
        violations = []
        
        try:
            # Check 1: Files past retention period should be marked for deletion
            retention_cutoff = datetime.utcnow() - timedelta(days=365 * 7)  # 7 years default
            
            old_files = self.db.query(AudioFile).filter(
                and_(
                    AudioFile.uploaded_at < retention_cutoff,
                    AudioFile.scheduled_deletion_at.is_(None),
                    AudioFile.is_deleted == False
                )
            ).all()
            
            for file in old_files:
                violations.append(ComplianceViolation(
                    id=f"retention_old_file_{file.id}",
                    violation_type=ComplianceViolationType.DATA_RETENTION,
                    severity=ViolationSeverity.HIGH,
                    title="File past retention period",
                    description=f"File {file.filename} is past retention period but not scheduled for deletion",
                    affected_resource=str(file.id),
                    user_id=file.user_id,
                    remediation_steps=[
                        "Schedule file for deletion",
                        "Review retention policy implementation",
                        "Implement automated retention enforcement"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.316(b)(2)"
                ))
            
            # Check 2: Audit logs should be retained for required period
            audit_retention_cutoff = datetime.utcnow() - timedelta(days=365 * 6)  # 6 years
            
            old_audit_count = self.db.query(AuditLog).filter(
                AuditLog.timestamp < audit_retention_cutoff
            ).count()
            
            if old_audit_count > 1000:  # Threshold for concern
                violations.append(ComplianceViolation(
                    id="retention_old_audit_logs",
                    violation_type=ComplianceViolationType.DATA_RETENTION,
                    severity=ViolationSeverity.MEDIUM,
                    title="Excessive old audit logs",
                    description=f"{old_audit_count} audit logs older than retention period",
                    remediation_steps=[
                        "Review audit log retention policy",
                        "Archive old audit logs",
                        "Implement automated audit log cleanup"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.316(b)(2)"
                ))
            
            return {
                "check_type": "data_retention",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "files_past_retention": len(old_files),
                "old_audit_logs": old_audit_count
            }
            
        except Exception as e:
            logger.error(f"Data retention check failed: {e}")
            return {"check_type": "data_retention", "error": str(e)}
    
    async def _check_minimum_necessary_access(self, user_id: Optional[UUID] = None) -> Dict[str, Any]:
        """Check minimum necessary access principle."""
        violations = []
        
        try:
            # Check 1: Users should only access their own data (patients)
            # or data they're authorized to access (providers)
            
            # Get recent file access logs
            recent_access = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.action.like("%file%"),
                    AuditLog.timestamp > datetime.utcnow() - timedelta(days=7)
                )
            )
            
            if user_id:
                recent_access = recent_access.filter(AuditLog.user_id == user_id)
            
            access_logs = recent_access.all()
            
            for log in access_logs:
                # Check if user accessed files they shouldn't have access to
                # This is a simplified check - in practice, you'd implement more sophisticated logic
                if log.resource_type == "audio_file" and log.resource_id:
                    file = self.db.query(AudioFile).get(log.resource_id)
                    if file and file.user_id != log.user_id:
                        # Check if user is authorized provider for this patient
                        user = self.db.query(User).get(log.user_id)
                        patient = self.db.query(User).get(file.user_id)
                        
                        # Simplified authorization check
                        is_authorized = (
                            user and 
                            any(role.role.name in ["admin", "healthcare_provider"] 
                                for role in user.role_assignments)
                        )
                        
                        if not is_authorized:
                            violations.append(ComplianceViolation(
                                id=f"minimum_necessary_unauthorized_access_{log.id}",
                                violation_type=ComplianceViolationType.MINIMUM_NECESSARY,
                                severity=ViolationSeverity.HIGH,
                                title="Unauthorized data access",
                                description=f"User {user.email if user else 'Unknown'} accessed file not belonging to them",
                                user_id=log.user_id,
                                affected_resource=str(log.resource_id),
                                remediation_steps=[
                                    "Review user access permissions",
                                    "Investigate unauthorized access",
                                    "Implement stricter access controls"
                                ],
                                auto_remediable=False,
                                regulatory_reference="45 CFR 164.502(b)"
                            ))
            
            return {
                "check_type": "minimum_necessary",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "access_logs_reviewed": len(access_logs)
            }
            
        except Exception as e:
            logger.error(f"Minimum necessary access check failed: {e}")
            return {"check_type": "minimum_necessary", "error": str(e)}
    
    async def _check_user_authentication(self) -> Dict[str, Any]:
        """Check user authentication requirements."""
        violations = []
        
        try:
            # Check 1: Users should have strong passwords (this would integrate with password policy)
            
            # Check 2: No users should have default passwords (placeholder check)
            
            # Check 3: Failed login attempts should be monitored
            failed_logins = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.action.like("%login_failed%"),
                    AuditLog.timestamp > datetime.utcnow() - timedelta(hours=1)
                )
            ).count()
            
            if failed_logins > 10:  # Threshold
                violations.append(ComplianceViolation(
                    id="auth_excessive_failed_logins",
                    violation_type=ComplianceViolationType.USER_AUTHENTICATION,
                    severity=ViolationSeverity.MEDIUM,
                    title="Excessive failed login attempts",
                    description=f"{failed_logins} failed login attempts in the last hour",
                    remediation_steps=[
                        "Review failed login patterns",
                        "Check for brute force attacks",
                        "Implement account lockout policies"
                    ],
                    auto_remediable=False,
                    regulatory_reference="45 CFR 164.308(a)(5)(ii)(D)"
                ))
            
            return {
                "check_type": "user_authentication",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "failed_logins": failed_logins
            }
            
        except Exception as e:
            logger.error(f"User authentication check failed: {e}")
            return {"check_type": "user_authentication", "error": str(e)}
    
    async def _check_business_associate_compliance(self) -> Dict[str, Any]:
        """Check Business Associate Agreement compliance."""
        violations = []
        
        try:
            # Check 1: BAA compliance monitoring (placeholder implementation)
            if not self.baa_config.BAA_COMPLIANCE_MONITORING:
                violations.append(ComplianceViolation(
                    id="baa_monitoring_disabled",
                    violation_type=ComplianceViolationType.BUSINESS_ASSOCIATE,
                    severity=ViolationSeverity.HIGH,
                    title="BAA compliance monitoring disabled",
                    description="Business Associate Agreement compliance monitoring is not enabled",
                    remediation_steps=[
                        "Enable BAA compliance monitoring",
                        "Review BAA requirements",
                        "Implement vendor compliance tracking"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.308(b)(1)"
                ))
            
            return {
                "check_type": "business_associate",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant"
            }
            
        except Exception as e:
            logger.error(f"Business associate compliance check failed: {e}")
            return {"check_type": "business_associate", "error": str(e)}
    
    async def _check_administrative_safeguards(self) -> Dict[str, Any]:
        """Check HIPAA administrative safeguards."""
        violations = []
        
        try:
            # Check 1: Security officer assignment (configuration check)
            if not self.compliance_config.COMPLIANCE_OFFICER_EMAIL:
                violations.append(ComplianceViolation(
                    id="admin_no_security_officer",
                    violation_type=ComplianceViolationType.ADMINISTRATIVE_SAFEGUARDS,
                    severity=ViolationSeverity.HIGH,
                    title="No security officer assigned",
                    description="No security officer email configured",
                    remediation_steps=[
                        "Assign security officer",
                        "Configure compliance officer contact",
                        "Establish security governance"
                    ],
                    auto_remediable=False,
                    regulatory_reference="45 CFR 164.308(a)(2)"
                ))
            
            return {
                "check_type": "administrative_safeguards",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant"
            }
            
        except Exception as e:
            logger.error(f"Administrative safeguards check failed: {e}")
            return {"check_type": "administrative_safeguards", "error": str(e)}
    
    async def _check_physical_safeguards(self) -> Dict[str, Any]:
        """Check HIPAA physical safeguards."""
        violations = []
        
        try:
            # Physical safeguards are primarily infrastructure-related
            # These would be checked through other means (facility audits, etc.)
            
            return {
                "check_type": "physical_safeguards",
                "violations": violations,
                "status": "compliant",
                "note": "Physical safeguards require manual verification"
            }
            
        except Exception as e:
            logger.error(f"Physical safeguards check failed: {e}")
            return {"check_type": "physical_safeguards", "error": str(e)}
    
    async def _check_technical_safeguards(self) -> Dict[str, Any]:
        """Check HIPAA technical safeguards."""
        violations = []
        
        try:
            # Check 1: Transmission security (HTTPS enforcement)
            # This would typically be checked at infrastructure level
            
            # Check 2: Data integrity controls
            files_without_integrity = self.db.query(AudioFile).filter(
                AudioFile.encryption_key_id.is_(None)
            ).count()
            
            if files_without_integrity > 0:
                violations.append(ComplianceViolation(
                    id="technical_data_integrity",
                    violation_type=ComplianceViolationType.TECHNICAL_SAFEGUARDS,
                    severity=ViolationSeverity.HIGH,
                    title="Files without integrity protection",
                    description=f"{files_without_integrity} files lack integrity protection",
                    remediation_steps=[
                        "Implement file integrity verification",
                        "Enable encryption for all files",
                        "Add checksums or digital signatures"
                    ],
                    auto_remediable=True,
                    regulatory_reference="45 CFR 164.312(c)(1)"
                ))
            
            return {
                "check_type": "technical_safeguards",
                "violations": violations,
                "status": "compliant" if len(violations) == 0 else "non_compliant",
                "files_without_integrity": files_without_integrity
            }
            
        except Exception as e:
            logger.error(f"Technical safeguards check failed: {e}")
            return {"check_type": "technical_safeguards", "error": str(e)}
    
    def _calculate_compliance_score(self, violations: List[ComplianceViolation]) -> ComplianceScore:
        """Calculate overall compliance score."""
        # Base score is 100
        total_score = 100
        
        # Deduct points based on violation severity
        severity_penalties = {
            ViolationSeverity.CRITICAL: 20,
            ViolationSeverity.HIGH: 10,
            ViolationSeverity.MEDIUM: 5,
            ViolationSeverity.LOW: 2
        }
        
        category_scores = {}
        violations_by_category = {}
        
        for violation in violations:
            category = violation.violation_type.value
            if category not in violations_by_category:
                violations_by_category[category] = []
            violations_by_category[category].append(violation)
            
            penalty = severity_penalties.get(violation.severity, 0)
            total_score -= penalty
        
        # Calculate category-specific scores
        for category, category_violations in violations_by_category.items():
            category_score = 100
            for violation in category_violations:
                penalty = severity_penalties.get(violation.severity, 0)
                category_score -= penalty
            category_scores[category] = max(0, category_score)
        
        # Determine trending (simplified - would use historical data)
        trending = "stable"
        
        # Determine risk level
        if total_score >= 95:
            risk_level = "low"
        elif total_score >= 80:
            risk_level = "medium"
        elif total_score >= 60:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        return ComplianceScore(
            total_score=max(0, total_score),
            category_scores=category_scores,
            violations_count=len(violations),
            last_assessment=datetime.utcnow(),
            trending=trending,
            risk_level=risk_level
        )
    
    def _count_violations_by_severity(self, violations: List[ComplianceViolation]) -> Dict[str, int]:
        """Count violations by severity level."""
        counts = {severity.value: 0 for severity in ViolationSeverity}
        for violation in violations:
            counts[violation.severity.value] += 1
        return counts
    
    def _count_violations_by_type(self, violations: List[ComplianceViolation]) -> Dict[str, int]:
        """Count violations by type."""
        counts = {}
        for violation in violations:
            violation_type = violation.violation_type.value
            counts[violation_type] = counts.get(violation_type, 0) + 1
        return counts
    
    def _generate_remediation_plan(self, violations: List[ComplianceViolation]) -> Dict[str, Any]:
        """Generate prioritized remediation plan."""
        # Sort violations by severity (critical first)
        severity_order = [
            ViolationSeverity.CRITICAL,
            ViolationSeverity.HIGH,
            ViolationSeverity.MEDIUM,
            ViolationSeverity.LOW
        ]
        
        sorted_violations = sorted(
            violations,
            key=lambda v: severity_order.index(v.severity)
        )
        
        # Group auto-remediable vs manual violations
        auto_remediable = [v for v in sorted_violations if v.auto_remediable]
        manual_remediable = [v for v in sorted_violations if not v.auto_remediable]
        
        return {
            "total_violations": len(violations),
            "immediate_actions": [v.id for v in sorted_violations[:5]],  # Top 5 priority
            "auto_remediable": len(auto_remediable),
            "manual_remediable": len(manual_remediable),
            "estimated_completion_hours": len(manual_remediable) * 2 + len(auto_remediable) * 0.5,
            "priority_order": [
                {
                    "violation_id": v.id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "auto_remediable": v.auto_remediable,
                    "steps": v.remediation_steps
                }
                for v in sorted_violations
            ]
        }
    
    def _generate_compliance_recommendations(
        self,
        compliance_score: ComplianceScore,
        violations: List[ComplianceViolation]
    ) -> List[str]:
        """Generate high-level compliance recommendations."""
        recommendations = []
        
        if compliance_score.total_score < 60:
            recommendations.append("URGENT: Compliance score is critically low. Immediate action required.")
        
        critical_violations = [v for v in violations if v.severity == ViolationSeverity.CRITICAL]
        if critical_violations:
            recommendations.append(f"Address {len(critical_violations)} critical violations immediately.")
        
        if compliance_score.category_scores.get("data_encryption", 100) < 80:
            recommendations.append("Improve data encryption practices and coverage.")
        
        if compliance_score.category_scores.get("access_control", 100) < 80:
            recommendations.append("Strengthen access control mechanisms and monitoring.")
        
        if compliance_score.category_scores.get("audit_logging", 100) < 80:
            recommendations.append("Enhance audit logging coverage and retention.")
        
        auto_remediable_count = len([v for v in violations if v.auto_remediable])
        if auto_remediable_count > 0:
            recommendations.append(f"Enable automatic remediation for {auto_remediable_count} violations.")
        
        return recommendations
    
    async def _log_compliance_assessment(
        self,
        assessment: Dict[str, Any],
        user_id: Optional[UUID] = None
    ):
        """Log compliance assessment for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="compliance_assessment",
                user_id=user_id,
                severity="info" if assessment["compliance_score"]["total_score"] >= 80 else "warning",
                description=f"HIPAA compliance assessment completed. Score: {assessment['compliance_score']['total_score']}",
                details={
                    "total_score": assessment["compliance_score"]["total_score"],
                    "violations_count": assessment["total_violations"],
                    "risk_level": assessment["compliance_score"]["risk_level"]
                }
            )
        except Exception as e:
            logger.error(f"Failed to log compliance assessment: {e}")


async def run_compliance_check(
    db: Session,
    user_id: Optional[UUID] = None,
    check_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level function to run compliance checks.
    
    Args:
        db: Database session
        user_id: Specific user to check (optional)
        check_type: Specific check type to run (optional)
        
    Returns:
        Compliance check results
    """
    checker = HIPAAComplianceChecker(db)
    
    if check_type:
        # Run specific check type
        check_methods = {
            "access_controls": checker._check_access_controls,
            "data_encryption": checker._check_data_encryption,
            "audit_logging": checker._check_audit_logging,
            "data_retention": checker._check_data_retention,
            "minimum_necessary": checker._check_minimum_necessary_access,
            "user_authentication": checker._check_user_authentication,
            "business_associate": checker._check_business_associate_compliance,
            "administrative_safeguards": checker._check_administrative_safeguards,
            "physical_safeguards": checker._check_physical_safeguards,
            "technical_safeguards": checker._check_technical_safeguards
        }
        
        if check_type in check_methods:
            if check_type == "minimum_necessary":
                return await check_methods[check_type](user_id)
            else:
                return await check_methods[check_type]()
        else:
            raise ValueError(f"Unknown check type: {check_type}")
    else:
        # Run comprehensive check
        return await checker.perform_comprehensive_compliance_check(user_id) 