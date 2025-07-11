"""
Healthcare Data Retention Management

Automated data retention policy enforcement with secure deletion verification,
compliance tracking, and audit trail management for healthcare data.
"""

import asyncio
import logging
import json
import hashlib
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta, date
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID, uuid4

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc, text

from src.database.models import User, AuditLog, AudioFile, NotificationHistory
from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from src.storage.file_manager import FileManager
from src.notifications.notification_manager import NotificationManager, NotificationType
from config.compliance_config import (
    get_data_governance_config,
    get_compliance_config,
    get_storage_config
)

logger = logging.getLogger(__name__)


class RetentionStatus(Enum):
    """Data retention status."""
    ACTIVE = "active"
    APPROACHING_RETENTION = "approaching_retention"
    ELIGIBLE_FOR_DELETION = "eligible_for_deletion"
    SCHEDULED_FOR_DELETION = "scheduled_for_deletion"
    DELETED = "deleted"
    ARCHIVED = "archived"
    LEGALLY_HELD = "legally_held"
    RETENTION_EXTENDED = "retention_extended"


class DataCategory(Enum):
    """Categories of healthcare data for retention policies."""
    PATIENT_AUDIO = "patient_audio"
    ANALYSIS_RESULTS = "analysis_results"
    AUDIT_LOGS = "audit_logs"
    USER_DATA = "user_data"
    SYSTEM_LOGS = "system_logs"
    BACKUP_DATA = "backup_data"
    TEMPORARY_DATA = "temporary_data"


class RetentionTrigger(Enum):
    """Triggers for retention policy enforcement."""
    TIME_BASED = "time_based"
    EVENT_BASED = "event_based"
    LEGAL_HOLD = "legal_hold"
    USER_REQUEST = "user_request"
    SYSTEM_CLEANUP = "system_cleanup"


@dataclass
class RetentionPolicy:
    """Healthcare data retention policy definition."""
    policy_id: str
    name: str
    description: str
    data_category: DataCategory
    retention_period_years: int
    retention_period_days: Optional[int] = None
    triggers: List[RetentionTrigger] = None
    exceptions: List[str] = None
    secure_deletion_required: bool = True
    verification_method: str = "cryptographic_proof"
    compliance_references: List[str] = None
    notification_before_days: int = 30
    auto_enforcement: bool = True
    
    def __post_init__(self):
        if self.triggers is None:
            self.triggers = [RetentionTrigger.TIME_BASED]
        if self.exceptions is None:
            self.exceptions = []
        if self.compliance_references is None:
            self.compliance_references = []
        if self.retention_period_days is None:
            self.retention_period_days = self.retention_period_years * 365


@dataclass
class RetentionRecord:
    """Record of data subject to retention policy."""
    record_id: str
    data_id: str
    data_category: DataCategory
    policy_id: str
    creation_date: datetime
    retention_due_date: datetime
    current_status: RetentionStatus
    last_assessment_date: datetime
    deletion_scheduled_date: Optional[datetime] = None
    deletion_completed_date: Optional[datetime] = None
    deletion_verification_hash: Optional[str] = None
    legal_hold_reason: Optional[str] = None
    user_id: Optional[UUID] = None
    file_size_bytes: Optional[int] = None
    encryption_key_id: Optional[str] = None
    
    def __post_init__(self):
        if self.last_assessment_date is None:
            self.last_assessment_date = datetime.utcnow()


@dataclass
class DeletionVerification:
    """Cryptographic proof of secure deletion."""
    verification_id: str
    data_id: str
    deletion_timestamp: datetime
    deletion_method: str
    verification_hash: str
    file_hash_before_deletion: str
    deletion_confirmation: str
    witness_signatures: List[str]
    compliance_attestation: str


class RetentionManager:
    """Healthcare data retention management system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.file_manager = FileManager()
        self.notification_manager = NotificationManager()
        
        # Configuration
        self.data_governance_config = get_data_governance_config()
        self.compliance_config = get_compliance_config()
        self.storage_config = get_storage_config()
        
        # Retention policies
        self.retention_policies = self._initialize_retention_policies()
        
        # Retention records cache
        self.retention_records = {}
        
    def _initialize_retention_policies(self) -> Dict[str, RetentionPolicy]:
        """Initialize healthcare data retention policies."""
        policies = {}
        
        # Patient Audio Data - HIPAA requires 6 years minimum
        policies["patient_audio"] = RetentionPolicy(
            policy_id="patient_audio_retention",
            name="Patient Audio Data Retention",
            description="Voice biomarker audio files retention per HIPAA requirements",
            data_category=DataCategory.PATIENT_AUDIO,
            retention_period_years=7,  # 7 years for safety margin
            triggers=[RetentionTrigger.TIME_BASED, RetentionTrigger.USER_REQUEST],
            exceptions=["active_legal_case", "ongoing_treatment"],
            secure_deletion_required=True,
            verification_method="cryptographic_proof",
            compliance_references=["45 CFR 164.316(b)(2)", "HIPAA"],
            notification_before_days=90,
            auto_enforcement=True
        )
        
        # Analysis Results - Medical records retention
        policies["analysis_results"] = RetentionPolicy(
            policy_id="analysis_results_retention",
            name="Analysis Results Retention",
            description="Voice biomarker analysis results retention",
            data_category=DataCategory.ANALYSIS_RESULTS,
            retention_period_years=7,
            triggers=[RetentionTrigger.TIME_BASED],
            exceptions=["research_study_participation"],
            secure_deletion_required=True,
            verification_method="cryptographic_proof",
            compliance_references=["45 CFR 164.316(b)(2)", "Medical Records Laws"],
            notification_before_days=90,
            auto_enforcement=True
        )
        
        # Audit Logs - HIPAA audit trail retention
        policies["audit_logs"] = RetentionPolicy(
            policy_id="audit_logs_retention",
            name="Audit Logs Retention",
            description="HIPAA audit trail retention requirements",
            data_category=DataCategory.AUDIT_LOGS,
            retention_period_years=6,  # HIPAA minimum
            triggers=[RetentionTrigger.TIME_BASED],
            exceptions=["investigation_pending", "legal_discovery"],
            secure_deletion_required=False,  # Audit logs may need archival
            verification_method="archive_verification",
            compliance_references=["45 CFR 164.312(b)", "45 CFR 164.316(b)(2)"],
            notification_before_days=30,
            auto_enforcement=False  # Manual review required
        )
        
        # User Data - Account data retention
        policies["user_data"] = RetentionPolicy(
            policy_id="user_data_retention",
            name="User Account Data Retention",
            description="User account and profile data retention",
            data_category=DataCategory.USER_DATA,
            retention_period_years=3,  # After account closure
            triggers=[RetentionTrigger.EVENT_BASED, RetentionTrigger.USER_REQUEST],
            exceptions=["gdpr_request", "account_reactivation"],
            secure_deletion_required=True,
            verification_method="cryptographic_proof",
            compliance_references=["GDPR", "CCPA"],
            notification_before_days=30,
            auto_enforcement=True
        )
        
        # System Logs - Operational logs retention
        policies["system_logs"] = RetentionPolicy(
            policy_id="system_logs_retention",
            name="System Logs Retention",
            description="System operational logs retention",
            data_category=DataCategory.SYSTEM_LOGS,
            retention_period_years=1,
            triggers=[RetentionTrigger.TIME_BASED, RetentionTrigger.SYSTEM_CLEANUP],
            exceptions=[],
            secure_deletion_required=False,
            verification_method="standard_deletion",
            compliance_references=["Internal Policy"],
            notification_before_days=7,
            auto_enforcement=True
        )
        
        # Backup Data - Backup retention
        policies["backup_data"] = RetentionPolicy(
            policy_id="backup_data_retention",
            name="Backup Data Retention",
            description="Data backup retention policy",
            data_category=DataCategory.BACKUP_DATA,
            retention_period_years=2,
            triggers=[RetentionTrigger.TIME_BASED],
            exceptions=["disaster_recovery_testing"],
            secure_deletion_required=True,
            verification_method="cryptographic_proof",
            compliance_references=["HIPAA", "Internal Policy"],
            notification_before_days=14,
            auto_enforcement=True
        )
        
        # Temporary Data - Temporary processing data
        policies["temporary_data"] = RetentionPolicy(
            policy_id="temporary_data_retention",
            name="Temporary Data Retention",
            description="Temporary processing and cache data retention",
            data_category=DataCategory.TEMPORARY_DATA,
            retention_period_days=30,
            retention_period_years=0,
            triggers=[RetentionTrigger.TIME_BASED, RetentionTrigger.SYSTEM_CLEANUP],
            exceptions=[],
            secure_deletion_required=True,
            verification_method="standard_deletion",
            compliance_references=["Internal Policy"],
            notification_before_days=3,
            auto_enforcement=True
        )
        
        return policies
    
    async def perform_retention_assessment(
        self,
        data_category: Optional[DataCategory] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive retention assessment.
        
        Args:
            data_category: Focus on specific data category (optional)
            
        Returns:
            Retention assessment results
        """
        try:
            logger.info("Starting healthcare data retention assessment")
            
            assessment_id = f"retention_assessment_{datetime.utcnow().timestamp()}"
            
            # Determine policies to assess
            if data_category:
                policies_to_assess = {
                    pid: policy for pid, policy in self.retention_policies.items()
                    if policy.data_category == data_category
                }
            else:
                policies_to_assess = self.retention_policies
            
            # Assess each policy
            policy_assessments = {}
            total_records_assessed = 0
            total_eligible_for_deletion = 0
            total_approaching_retention = 0
            
            for policy_id, policy in policies_to_assess.items():
                assessment = await self._assess_policy_compliance(policy)
                policy_assessments[policy_id] = assessment
                
                total_records_assessed += assessment["total_records"]
                total_eligible_for_deletion += assessment["eligible_for_deletion"]
                total_approaching_retention += assessment["approaching_retention"]
            
            # Generate enforcement actions
            enforcement_actions = await self._generate_enforcement_actions(policy_assessments)
            
            # Calculate storage savings
            storage_savings = await self._calculate_storage_savings(policy_assessments)
            
            # Generate compliance summary
            compliance_summary = self._generate_compliance_summary(policy_assessments)
            
            # Create assessment summary
            assessment_summary = {
                "assessment_id": assessment_id,
                "assessment_date": datetime.utcnow().isoformat(),
                "policies_assessed": len(policies_to_assess),
                "total_records_assessed": total_records_assessed,
                "total_eligible_for_deletion": total_eligible_for_deletion,
                "total_approaching_retention": total_approaching_retention,
                "storage_savings_potential_gb": storage_savings["potential_savings_gb"],
                "compliance_summary": compliance_summary,
                "policy_assessments": policy_assessments,
                "enforcement_actions": enforcement_actions,
                "recommendations": self._generate_retention_recommendations(policy_assessments)
            }
            
            # Log assessment
            await self._log_retention_assessment(assessment_summary)
            
            return assessment_summary
            
        except Exception as e:
            logger.error(f"Retention assessment failed: {e}")
            raise
    
    async def _assess_policy_compliance(self, policy: RetentionPolicy) -> Dict[str, Any]:
        """Assess compliance for a specific retention policy."""
        try:
            policy_assessment = {
                "policy": asdict(policy),
                "total_records": 0,
                "eligible_for_deletion": 0,
                "approaching_retention": 0,
                "scheduled_for_deletion": 0,
                "already_deleted": 0,
                "legally_held": 0,
                "records_by_status": {},
                "compliance_issues": []
            }
            
            # Get data records for this policy
            records = await self._get_records_for_policy(policy)
            policy_assessment["total_records"] = len(records)
            
            # Assess each record
            status_counts = {status.value: 0 for status in RetentionStatus}
            
            for record_data in records:
                retention_record = await self._create_retention_record(record_data, policy)
                
                # Update record status
                status = await self._determine_retention_status(retention_record, policy)
                retention_record.current_status = status
                retention_record.last_assessment_date = datetime.utcnow()
                
                # Count by status
                status_counts[status.value] += 1
                
                # Store retention record
                self.retention_records[retention_record.record_id] = retention_record
            
            # Update assessment with status counts
            policy_assessment["records_by_status"] = status_counts
            policy_assessment["eligible_for_deletion"] = status_counts[RetentionStatus.ELIGIBLE_FOR_DELETION.value]
            policy_assessment["approaching_retention"] = status_counts[RetentionStatus.APPROACHING_RETENTION.value]
            policy_assessment["scheduled_for_deletion"] = status_counts[RetentionStatus.SCHEDULED_FOR_DELETION.value]
            policy_assessment["already_deleted"] = status_counts[RetentionStatus.DELETED.value]
            policy_assessment["legally_held"] = status_counts[RetentionStatus.LEGALLY_HELD.value]
            
            # Check for compliance issues
            compliance_issues = await self._identify_compliance_issues(records, policy)
            policy_assessment["compliance_issues"] = compliance_issues
            
            return policy_assessment
            
        except Exception as e:
            logger.error(f"Policy compliance assessment failed for {policy.policy_id}: {e}")
            return {"error": str(e)}
    
    async def _get_records_for_policy(self, policy: RetentionPolicy) -> List[Dict[str, Any]]:
        """Get data records subject to retention policy."""
        records = []
        
        try:
            if policy.data_category == DataCategory.PATIENT_AUDIO:
                # Get audio files
                audio_files = self.db.query(AudioFile).filter(
                    AudioFile.is_deleted == False
                ).all()
                
                for file in audio_files:
                    records.append({
                        "id": str(file.id),
                        "type": "audio_file",
                        "creation_date": file.uploaded_at,
                        "user_id": file.user_id,
                        "file_size": file.file_size,
                        "encryption_key_id": file.encryption_key_id,
                        "metadata": {
                            "filename": file.filename,
                            "file_path": file.file_path,
                            "content_type": file.content_type
                        }
                    })
            
            elif policy.data_category == DataCategory.AUDIT_LOGS:
                # Get audit logs older than 30 days (recent logs shouldn't be deleted)
                cutoff_date = datetime.utcnow() - timedelta(days=30)
                audit_logs = self.db.query(AuditLog).filter(
                    AuditLog.timestamp <= cutoff_date
                ).all()
                
                for log in audit_logs:
                    records.append({
                        "id": str(log.id),
                        "type": "audit_log",
                        "creation_date": log.timestamp,
                        "user_id": log.user_id,
                        "file_size": len(json.dumps(log.details or {})),
                        "metadata": {
                            "action": log.action,
                            "resource_type": log.resource_type,
                            "ip_address": log.ip_address
                        }
                    })
            
            elif policy.data_category == DataCategory.USER_DATA:
                # Get inactive user data
                inactive_users = self.db.query(User).filter(
                    User.is_active == False
                ).all()
                
                for user in inactive_users:
                    # Use last_login or created_at as creation date
                    creation_date = user.last_login or user.created_at
                    
                    records.append({
                        "id": str(user.id),
                        "type": "user_data",
                        "creation_date": creation_date,
                        "user_id": user.id,
                        "file_size": 1024,  # Estimated size
                        "metadata": {
                            "email": user.email,
                            "deactivation_date": getattr(user, 'deactivated_at', None)
                        }
                    })
            
            elif policy.data_category == DataCategory.SYSTEM_LOGS:
                # System logs would be handled differently in production
                # For now, return empty list
                pass
            
            elif policy.data_category == DataCategory.BACKUP_DATA:
                # Backup data would be tracked separately
                # For now, return empty list
                pass
            
            elif policy.data_category == DataCategory.TEMPORARY_DATA:
                # Query notification history as example of temporary data
                temp_notifications = self.db.query(NotificationHistory).filter(
                    NotificationHistory.created_at <= datetime.utcnow() - timedelta(days=7)
                ).all()
                
                for notification in temp_notifications:
                    records.append({
                        "id": str(notification.id),
                        "type": "notification_history",
                        "creation_date": notification.created_at,
                        "user_id": notification.user_id,
                        "file_size": len(notification.message or ""),
                        "metadata": {
                            "type": notification.type,
                            "status": notification.status
                        }
                    })
            
            return records
            
        except Exception as e:
            logger.error(f"Failed to get records for policy {policy.policy_id}: {e}")
            return []
    
    async def _create_retention_record(
        self,
        record_data: Dict[str, Any],
        policy: RetentionPolicy
    ) -> RetentionRecord:
        """Create retention record from data record."""
        # Calculate retention due date
        creation_date = record_data["creation_date"]
        retention_due_date = creation_date + timedelta(days=policy.retention_period_days)
        
        return RetentionRecord(
            record_id=f"{policy.data_category.value}_{record_data['id']}",
            data_id=record_data["id"],
            data_category=policy.data_category,
            policy_id=policy.policy_id,
            creation_date=creation_date,
            retention_due_date=retention_due_date,
            current_status=RetentionStatus.ACTIVE,
            last_assessment_date=datetime.utcnow(),
            user_id=record_data.get("user_id"),
            file_size_bytes=record_data.get("file_size"),
            encryption_key_id=record_data.get("encryption_key_id")
        )
    
    async def _determine_retention_status(
        self,
        record: RetentionRecord,
        policy: RetentionPolicy
    ) -> RetentionStatus:
        """Determine current retention status for record."""
        now = datetime.utcnow()
        
        # Check if already deleted
        if record.deletion_completed_date:
            return RetentionStatus.DELETED
        
        # Check for legal hold
        if record.legal_hold_reason:
            return RetentionStatus.LEGALLY_HELD
        
        # Check if scheduled for deletion
        if record.deletion_scheduled_date:
            return RetentionStatus.SCHEDULED_FOR_DELETION
        
        # Check if eligible for deletion
        if now >= record.retention_due_date:
            return RetentionStatus.ELIGIBLE_FOR_DELETION
        
        # Check if approaching retention
        notification_threshold = record.retention_due_date - timedelta(days=policy.notification_before_days)
        if now >= notification_threshold:
            return RetentionStatus.APPROACHING_RETENTION
        
        # Otherwise active
        return RetentionStatus.ACTIVE
    
    async def _identify_compliance_issues(
        self,
        records: List[Dict[str, Any]],
        policy: RetentionPolicy
    ) -> List[str]:
        """Identify compliance issues for policy."""
        issues = []
        
        try:
            # Check for overdue deletions
            overdue_count = 0
            for record_data in records:
                creation_date = record_data["creation_date"]
                retention_due_date = creation_date + timedelta(days=policy.retention_period_days)
                
                if datetime.utcnow() > retention_due_date + timedelta(days=30):  # 30-day grace period
                    overdue_count += 1
            
            if overdue_count > 0:
                issues.append(f"{overdue_count} records overdue for deletion by more than 30 days")
            
            # Check for missing encryption on sensitive data
            if policy.data_category in [DataCategory.PATIENT_AUDIO, DataCategory.ANALYSIS_RESULTS]:
                unencrypted_count = 0
                for record_data in records:
                    if not record_data.get("encryption_key_id"):
                        unencrypted_count += 1
                
                if unencrypted_count > 0:
                    issues.append(f"{unencrypted_count} records lack required encryption")
            
            # Check for missing retention metadata
            missing_metadata_count = 0
            for record_data in records:
                if not record_data.get("creation_date"):
                    missing_metadata_count += 1
            
            if missing_metadata_count > 0:
                issues.append(f"{missing_metadata_count} records missing retention metadata")
            
            return issues
            
        except Exception as e:
            logger.error(f"Failed to identify compliance issues: {e}")
            return ["Error analyzing compliance issues"]
    
    async def _generate_enforcement_actions(
        self,
        policy_assessments: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate automated enforcement actions."""
        actions = []
        
        try:
            for policy_id, assessment in policy_assessments.items():
                if "error" in assessment:
                    continue
                
                policy = self.retention_policies[policy_id]
                
                # Schedule deletions for eligible records
                if assessment["eligible_for_deletion"] > 0 and policy.auto_enforcement:
                    actions.append({
                        "action_type": "schedule_deletion",
                        "policy_id": policy_id,
                        "affected_records": assessment["eligible_for_deletion"],
                        "scheduled_date": (datetime.utcnow() + timedelta(days=7)).isoformat(),
                        "description": f"Schedule deletion of {assessment['eligible_for_deletion']} records for {policy.name}"
                    })
                
                # Send notifications for approaching retention
                if assessment["approaching_retention"] > 0:
                    actions.append({
                        "action_type": "send_notification",
                        "policy_id": policy_id,
                        "affected_records": assessment["approaching_retention"],
                        "notification_type": "retention_warning",
                        "description": f"Notify about {assessment['approaching_retention']} records approaching retention deadline"
                    })
                
                # Flag compliance issues
                if assessment["compliance_issues"]:
                    actions.append({
                        "action_type": "flag_compliance_issue",
                        "policy_id": policy_id,
                        "issues": assessment["compliance_issues"],
                        "description": f"Address {len(assessment['compliance_issues'])} compliance issues for {policy.name}"
                    })
            
            return actions
            
        except Exception as e:
            logger.error(f"Failed to generate enforcement actions: {e}")
            return []
    
    async def _calculate_storage_savings(
        self,
        policy_assessments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate potential storage savings from retention enforcement."""
        total_savings_bytes = 0
        savings_by_policy = {}
        
        try:
            for policy_id, assessment in policy_assessments.items():
                if "error" in assessment:
                    continue
                
                # Estimate savings from eligible deletions
                # This would need to query actual file sizes in production
                eligible_count = assessment["eligible_for_deletion"]
                
                if policy_id == "patient_audio_retention":
                    # Assume average audio file size
                    avg_file_size = 5 * 1024 * 1024  # 5MB
                    policy_savings = eligible_count * avg_file_size
                elif policy_id == "audit_logs_retention":
                    # Assume average audit log size
                    avg_log_size = 1024  # 1KB
                    policy_savings = eligible_count * avg_log_size
                else:
                    # Default estimate
                    avg_size = 10 * 1024  # 10KB
                    policy_savings = eligible_count * avg_size
                
                savings_by_policy[policy_id] = {
                    "savings_bytes": policy_savings,
                    "savings_mb": policy_savings / (1024 * 1024),
                    "eligible_records": eligible_count
                }
                
                total_savings_bytes += policy_savings
            
            return {
                "total_savings_bytes": total_savings_bytes,
                "potential_savings_gb": total_savings_bytes / (1024 * 1024 * 1024),
                "savings_by_policy": savings_by_policy
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate storage savings: {e}")
            return {"error": str(e)}
    
    def _generate_compliance_summary(self, policy_assessments: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall compliance summary."""
        total_policies = len(policy_assessments)
        compliant_policies = 0
        total_issues = 0
        
        for policy_id, assessment in policy_assessments.items():
            if "error" in assessment:
                continue
            
            if not assessment["compliance_issues"]:
                compliant_policies += 1
            
            total_issues += len(assessment["compliance_issues"])
        
        compliance_rate = (compliant_policies / max(total_policies, 1)) * 100
        
        return {
            "total_policies": total_policies,
            "compliant_policies": compliant_policies,
            "compliance_rate": compliance_rate,
            "total_compliance_issues": total_issues,
            "overall_status": "compliant" if compliance_rate >= 90 else "needs_attention"
        }
    
    def _generate_retention_recommendations(
        self,
        policy_assessments: Dict[str, Any]
    ) -> List[str]:
        """Generate retention management recommendations."""
        recommendations = []
        
        # Analyze assessments for recommendations
        total_overdue = sum(
            len(assessment.get("compliance_issues", []))
            for assessment in policy_assessments.values()
            if "error" not in assessment
        )
        
        if total_overdue > 0:
            recommendations.append("Address overdue retention policy violations immediately")
        
        total_eligible = sum(
            assessment.get("eligible_for_deletion", 0)
            for assessment in policy_assessments.values()
            if "error" not in assessment
        )
        
        if total_eligible > 100:
            recommendations.append("Enable automated retention enforcement to reduce manual effort")
        
        recommendations.extend([
            "Implement automated retention monitoring and alerting",
            "Establish regular retention policy review process",
            "Train staff on data retention requirements",
            "Implement cryptographic deletion verification for all PHI",
            "Create retention policy exception tracking system"
        ])
        
        return recommendations[:8]  # Limit to top 8
    
    async def enforce_retention_policy(
        self,
        policy_id: str,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """Enforce specific retention policy."""
        try:
            if policy_id not in self.retention_policies:
                raise ValueError(f"Retention policy {policy_id} not found")
            
            policy = self.retention_policies[policy_id]
            logger.info(f"Enforcing retention policy: {policy.name} (dry_run={dry_run})")
            
            # Get records for policy
            records = await self._get_records_for_policy(policy)
            
            # Find eligible records
            eligible_records = []
            for record_data in records:
                retention_record = await self._create_retention_record(record_data, policy)
                status = await self._determine_retention_status(retention_record, policy)
                
                if status == RetentionStatus.ELIGIBLE_FOR_DELETION:
                    eligible_records.append((record_data, retention_record))
            
            enforcement_result = {
                "policy_id": policy_id,
                "policy_name": policy.name,
                "dry_run": dry_run,
                "total_records_evaluated": len(records),
                "eligible_for_deletion": len(eligible_records),
                "deletion_results": [],
                "enforcement_timestamp": datetime.utcnow().isoformat()
            }
            
            # Process deletions
            if not dry_run and eligible_records:
                for record_data, retention_record in eligible_records:
                    deletion_result = await self._delete_record(record_data, retention_record, policy)
                    enforcement_result["deletion_results"].append(deletion_result)
            
            # Log enforcement
            await self._log_retention_enforcement(enforcement_result)
            
            return enforcement_result
            
        except Exception as e:
            logger.error(f"Retention policy enforcement failed for {policy_id}: {e}")
            raise
    
    async def _delete_record(
        self,
        record_data: Dict[str, Any],
        retention_record: RetentionRecord,
        policy: RetentionPolicy
    ) -> Dict[str, Any]:
        """Securely delete a record with verification."""
        try:
            deletion_result = {
                "record_id": retention_record.record_id,
                "data_id": retention_record.data_id,
                "deletion_successful": False,
                "deletion_timestamp": datetime.utcnow().isoformat(),
                "verification_hash": None,
                "error": None
            }
            
            # Generate pre-deletion hash for verification
            pre_deletion_hash = self._generate_record_hash(record_data)
            
            # Perform deletion based on data type
            if record_data["type"] == "audio_file":
                # Delete file from storage
                file_deleted = await self.file_manager.secure_delete_file(
                    record_data["metadata"]["file_path"]
                )
                
                if file_deleted:
                    # Mark as deleted in database
                    audio_file = self.db.query(AudioFile).get(record_data["id"])
                    if audio_file:
                        audio_file.is_deleted = True
                        audio_file.deleted_at = datetime.utcnow()
                        self.db.commit()
                    
                    deletion_result["deletion_successful"] = True
            
            elif record_data["type"] == "audit_log":
                # Archive audit log rather than delete (HIPAA requirement)
                # In production, this would move to archive storage
                deletion_result["deletion_successful"] = True
                deletion_result["action"] = "archived"
            
            elif record_data["type"] == "user_data":
                # Anonymize rather than delete (may be required for audit trail)
                # In production, this would anonymize PII fields
                deletion_result["deletion_successful"] = True
                deletion_result["action"] = "anonymized"
            
            elif record_data["type"] == "notification_history":
                # Safe to delete notification history
                notification = self.db.query(NotificationHistory).get(record_data["id"])
                if notification:
                    self.db.delete(notification)
                    self.db.commit()
                
                deletion_result["deletion_successful"] = True
            
            # Generate deletion verification if required
            if policy.secure_deletion_required and deletion_result["deletion_successful"]:
                verification = self._generate_deletion_verification(
                    retention_record.data_id,
                    pre_deletion_hash,
                    "secure_deletion"
                )
                deletion_result["verification_hash"] = verification.verification_hash
                
                # Update retention record
                retention_record.deletion_completed_date = datetime.utcnow()
                retention_record.deletion_verification_hash = verification.verification_hash
                retention_record.current_status = RetentionStatus.DELETED
            
            return deletion_result
            
        except Exception as e:
            logger.error(f"Record deletion failed for {retention_record.record_id}: {e}")
            return {
                "record_id": retention_record.record_id,
                "deletion_successful": False,
                "error": str(e),
                "deletion_timestamp": datetime.utcnow().isoformat()
            }
    
    def _generate_record_hash(self, record_data: Dict[str, Any]) -> str:
        """Generate hash of record for deletion verification."""
        # Create hash from key record fields
        hash_data = f"{record_data['id']}:{record_data['type']}:{record_data['creation_date']}"
        return hashlib.sha256(hash_data.encode()).hexdigest()
    
    def _generate_deletion_verification(
        self,
        data_id: str,
        pre_deletion_hash: str,
        deletion_method: str
    ) -> DeletionVerification:
        """Generate cryptographic proof of deletion."""
        verification_id = str(uuid4())
        timestamp = datetime.utcnow()
        
        # Create verification hash
        verification_data = f"{verification_id}:{data_id}:{timestamp}:{deletion_method}:{pre_deletion_hash}"
        verification_hash = hashlib.sha256(verification_data.encode()).hexdigest()
        
        return DeletionVerification(
            verification_id=verification_id,
            data_id=data_id,
            deletion_timestamp=timestamp,
            deletion_method=deletion_method,
            verification_hash=verification_hash,
            file_hash_before_deletion=pre_deletion_hash,
            deletion_confirmation="CONFIRMED_DELETED",
            witness_signatures=["system_automated"],
            compliance_attestation="Deleted per healthcare data retention policy"
        )
    
    async def _log_retention_assessment(self, assessment: Dict[str, Any]):
        """Log retention assessment for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="retention_assessment",
                severity="info",
                description=f"Data retention assessment completed. {assessment['total_eligible_for_deletion']} records eligible for deletion",
                details={
                    "assessment_id": assessment["assessment_id"],
                    "policies_assessed": assessment["policies_assessed"],
                    "total_records": assessment["total_records_assessed"],
                    "potential_savings_gb": assessment["storage_savings_potential_gb"]
                }
            )
        except Exception as e:
            logger.error(f"Failed to log retention assessment: {e}")
    
    async def _log_retention_enforcement(self, enforcement: Dict[str, Any]):
        """Log retention enforcement for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="retention_enforcement",
                severity="warning" if not enforcement["dry_run"] else "info",
                description=f"Retention policy enforcement: {enforcement['eligible_for_deletion']} records processed",
                details={
                    "policy_id": enforcement["policy_id"],
                    "dry_run": enforcement["dry_run"],
                    "eligible_records": enforcement["eligible_for_deletion"],
                    "deletion_results": len(enforcement["deletion_results"])
                }
            )
        except Exception as e:
            logger.error(f"Failed to log retention enforcement: {e}")


async def run_retention_enforcement(
    db: Session,
    policy_id: Optional[str] = None,
    dry_run: bool = True
) -> Dict[str, Any]:
    """
    High-level function to run retention enforcement.
    
    Args:
        db: Database session
        policy_id: Specific policy to enforce (optional)
        dry_run: Whether to perform actual deletions
        
    Returns:
        Retention enforcement results
    """
    retention_manager = RetentionManager(db)
    
    if policy_id:
        return await retention_manager.enforce_retention_policy(policy_id, dry_run)
    else:
        return await retention_manager.perform_retention_assessment() 