"""
HIPAA Audit Trail Management

Comprehensive HIPAA audit trail management with cross-system correlation,
immutable audit verification, and automated compliance reporting.
"""

import asyncio
import logging
import json
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID, uuid4
from collections import defaultdict

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc, text

from src.database.models import User, AuditLog, AudioFile, UserSession
from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from src.utils.cloudtrail_parser import CloudTrailParser, CloudTrailEvent
from config.compliance_config import (
    get_compliance_config,
    get_data_governance_config,
    get_monitoring_config
)

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events required by HIPAA."""
    PHI_ACCESS = "phi_access"
    PHI_MODIFICATION = "phi_modification"
    PHI_DISCLOSURE = "phi_disclosure"
    PHI_CREATION = "phi_creation"
    PHI_DELETION = "phi_deletion"
    USER_AUTHENTICATION = "user_authentication"
    AUTHORIZATION_FAILURE = "authorization_failure"
    SYSTEM_ACCESS = "system_access"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EVENT = "security_event"
    BACKUP_OPERATION = "backup_operation"
    DATA_EXPORT = "data_export"
    ADMINISTRATIVE_ACTION = "administrative_action"


class AuditCompliance(Enum):
    """HIPAA audit compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL_COMPLIANCE = "partial_compliance"
    PENDING_REVIEW = "pending_review"


@dataclass
class AuditRequirement:
    """HIPAA audit requirement definition."""
    requirement_id: str
    description: str
    event_types: List[AuditEventType]
    retention_years: int
    required_fields: List[str]
    verification_method: str
    compliance_weight: float


@dataclass
class AuditReport:
    """Comprehensive audit report."""
    report_id: str
    generated_date: datetime
    report_period_start: datetime
    report_period_end: datetime
    total_events: int
    events_by_type: Dict[str, int]
    events_by_user: Dict[str, int]
    compliance_status: AuditCompliance
    compliance_score: int
    missing_events: List[str]
    integrity_verification: Dict[str, Any]
    recommendations: List[str]
    detailed_findings: Dict[str, Any]


@dataclass
class IntegrityCheckResult:
    """Audit log integrity verification result."""
    check_id: str
    timestamp: datetime
    total_logs_checked: int
    integrity_violations: List[Dict[str, Any]]
    hash_verification_passed: bool
    sequential_verification_passed: bool
    cross_system_correlation_passed: bool
    overall_integrity_score: int


class HIPAAAuditManager:
    """Comprehensive HIPAA audit trail management system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.cloudtrail_parser = CloudTrailParser()
        
        # Configuration
        self.compliance_config = get_compliance_config()
        self.data_governance_config = get_data_governance_config()
        self.monitoring_config = get_monitoring_config()
        
        # HIPAA audit requirements
        self.audit_requirements = self._initialize_audit_requirements()
        
        # Integrity verification keys
        self.integrity_secret = self.compliance_config.AUDIT_INTEGRITY_SECRET
        
    def _initialize_audit_requirements(self) -> Dict[str, AuditRequirement]:
        """Initialize HIPAA audit requirements."""
        requirements = {}
        
        # PHI Access Logging
        requirements["phi_access"] = AuditRequirement(
            requirement_id="hipaa_164_312_b",
            description="Log all PHI access events per 45 CFR 164.312(b)",
            event_types=[AuditEventType.PHI_ACCESS, AuditEventType.PHI_DISCLOSURE],
            retention_years=6,
            required_fields=["user_id", "timestamp", "resource_id", "action", "ip_address"],
            verification_method="hash_chain",
            compliance_weight=1.0
        )
        
        # User Authentication
        requirements["user_authentication"] = AuditRequirement(
            requirement_id="hipaa_164_312_d",
            description="Log user authentication events per 45 CFR 164.312(d)",
            event_types=[AuditEventType.USER_AUTHENTICATION, AuditEventType.AUTHORIZATION_FAILURE],
            retention_years=6,
            required_fields=["user_id", "timestamp", "action", "ip_address", "success"],
            verification_method="hash_chain",
            compliance_weight=0.8
        )
        
        # PHI Modifications
        requirements["phi_modifications"] = AuditRequirement(
            requirement_id="hipaa_164_312_c_2",
            description="Log PHI modifications per 45 CFR 164.312(c)(2)",
            event_types=[AuditEventType.PHI_MODIFICATION, AuditEventType.PHI_CREATION, AuditEventType.PHI_DELETION],
            retention_years=6,
            required_fields=["user_id", "timestamp", "resource_id", "action", "changes"],
            verification_method="hash_chain",
            compliance_weight=1.0
        )
        
        # Administrative Actions
        requirements["administrative_actions"] = AuditRequirement(
            requirement_id="hipaa_164_308_a_1_ii_d",
            description="Log administrative actions per 45 CFR 164.308(a)(1)(ii)(D)",
            event_types=[AuditEventType.ADMINISTRATIVE_ACTION, AuditEventType.CONFIGURATION_CHANGE],
            retention_years=6,
            required_fields=["user_id", "timestamp", "action", "resource_type", "details"],
            verification_method="hash_chain",
            compliance_weight=0.6
        )
        
        return requirements
    
    async def perform_comprehensive_audit_analysis(
        self,
        start_date: datetime,
        end_date: datetime,
        user_id: Optional[UUID] = None
    ) -> AuditReport:
        """
        Perform comprehensive HIPAA audit analysis.
        
        Args:
            start_date: Analysis period start
            end_date: Analysis period end
            user_id: Focus on specific user (optional)
            
        Returns:
            Comprehensive audit report
        """
        try:
            logger.info(f"Starting HIPAA audit analysis from {start_date} to {end_date}")
            
            report_id = f"hipaa_audit_{datetime.utcnow().timestamp()}"
            
            # Gather audit events
            audit_events = await self._gather_audit_events(start_date, end_date, user_id)
            
            # Perform compliance analysis
            compliance_analysis = await self._analyze_compliance(audit_events, start_date, end_date)
            
            # Verify audit integrity
            integrity_result = await self._verify_audit_integrity(audit_events)
            
            # Cross-correlate with CloudTrail
            cloudtrail_correlation = await self._correlate_with_cloudtrail(audit_events, start_date, end_date)
            
            # Generate compliance score
            compliance_score = self._calculate_compliance_score(compliance_analysis, integrity_result)
            
            # Determine compliance status
            compliance_status = self._determine_compliance_status(compliance_score, integrity_result)
            
            # Identify missing events
            missing_events = await self._identify_missing_events(audit_events, start_date, end_date)
            
            # Generate recommendations
            recommendations = self._generate_audit_recommendations(
                compliance_analysis, 
                integrity_result, 
                missing_events
            )
            
            # Create detailed findings
            detailed_findings = {
                "compliance_analysis": compliance_analysis,
                "integrity_verification": asdict(integrity_result),
                "cloudtrail_correlation": cloudtrail_correlation,
                "event_distribution": self._analyze_event_distribution(audit_events),
                "user_activity_patterns": self._analyze_user_patterns(audit_events),
                "system_health_indicators": self._analyze_system_health(audit_events)
            }
            
            # Create audit report
            report = AuditReport(
                report_id=report_id,
                generated_date=datetime.utcnow(),
                report_period_start=start_date,
                report_period_end=end_date,
                total_events=len(audit_events),
                events_by_type=self._count_events_by_type(audit_events),
                events_by_user=self._count_events_by_user(audit_events),
                compliance_status=compliance_status,
                compliance_score=compliance_score,
                missing_events=missing_events,
                integrity_verification=asdict(integrity_result),
                recommendations=recommendations,
                detailed_findings=detailed_findings
            )
            
            # Log audit analysis
            await self._log_audit_analysis(report)
            
            return report
            
        except Exception as e:
            logger.error(f"HIPAA audit analysis failed: {e}")
            raise
    
    async def _gather_audit_events(
        self,
        start_date: datetime,
        end_date: datetime,
        user_id: Optional[UUID] = None
    ) -> List[AuditLog]:
        """Gather audit events for analysis."""
        try:
            query = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= start_date,
                    AuditLog.timestamp <= end_date
                )
            )
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            audit_events = query.order_by(AuditLog.timestamp).all()
            
            logger.info(f"Gathered {len(audit_events)} audit events for analysis")
            return audit_events
            
        except Exception as e:
            logger.error(f"Failed to gather audit events: {e}")
            return []
    
    async def _analyze_compliance(
        self,
        audit_events: List[AuditLog],
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Analyze HIPAA compliance for audit events."""
        compliance_analysis = {}
        
        try:
            for req_id, requirement in self.audit_requirements.items():
                # Check if required event types are present
                required_events = []
                for event in audit_events:
                    event_type = self._classify_audit_event(event)
                    if event_type in requirement.event_types:
                        required_events.append(event)
                
                # Analyze completeness
                completeness_score = self._analyze_completeness(required_events, requirement)
                
                # Analyze field compliance
                field_compliance = self._analyze_field_compliance(required_events, requirement)
                
                # Analyze retention compliance
                retention_compliance = self._analyze_retention_compliance(requirement)
                
                compliance_analysis[req_id] = {
                    "requirement": asdict(requirement),
                    "events_found": len(required_events),
                    "completeness_score": completeness_score,
                    "field_compliance": field_compliance,
                    "retention_compliance": retention_compliance,
                    "overall_compliance": (completeness_score + field_compliance + retention_compliance) / 3
                }
            
            return compliance_analysis
            
        except Exception as e:
            logger.error(f"Compliance analysis failed: {e}")
            return {}
    
    async def _verify_audit_integrity(self, audit_events: List[AuditLog]) -> IntegrityCheckResult:
        """Verify integrity of audit log entries."""
        try:
            check_id = f"integrity_check_{datetime.utcnow().timestamp()}"
            violations = []
            
            # Hash verification
            hash_verification_passed = True
            for event in audit_events:
                if hasattr(event, 'integrity_hash') and event.integrity_hash:
                    calculated_hash = self._calculate_event_hash(event)
                    if calculated_hash != event.integrity_hash:
                        hash_verification_passed = False
                        violations.append({
                            "type": "hash_mismatch",
                            "event_id": str(event.id),
                            "timestamp": event.timestamp.isoformat(),
                            "expected_hash": event.integrity_hash,
                            "calculated_hash": calculated_hash
                        })
            
            # Sequential verification
            sequential_verification_passed = True
            for i, event in enumerate(audit_events[1:], 1):
                prev_event = audit_events[i-1]
                if event.timestamp < prev_event.timestamp:
                    sequential_verification_passed = False
                    violations.append({
                        "type": "sequential_order",
                        "event_id": str(event.id),
                        "timestamp": event.timestamp.isoformat(),
                        "issue": "Event timestamp earlier than previous event"
                    })
            
            # Cross-system correlation verification
            cross_system_correlation_passed = await self._verify_cross_system_correlation(audit_events)
            
            # Calculate overall integrity score
            integrity_score = 100
            if not hash_verification_passed:
                integrity_score -= 30
            if not sequential_verification_passed:
                integrity_score -= 20
            if not cross_system_correlation_passed:
                integrity_score -= 25
            
            integrity_score -= min(25, len(violations) * 5)  # Deduct for violations
            
            return IntegrityCheckResult(
                check_id=check_id,
                timestamp=datetime.utcnow(),
                total_logs_checked=len(audit_events),
                integrity_violations=violations,
                hash_verification_passed=hash_verification_passed,
                sequential_verification_passed=sequential_verification_passed,
                cross_system_correlation_passed=cross_system_correlation_passed,
                overall_integrity_score=max(0, integrity_score)
            )
            
        except Exception as e:
            logger.error(f"Audit integrity verification failed: {e}")
            return IntegrityCheckResult(
                check_id="failed_check",
                timestamp=datetime.utcnow(),
                total_logs_checked=0,
                integrity_violations=[],
                hash_verification_passed=False,
                sequential_verification_passed=False,
                cross_system_correlation_passed=False,
                overall_integrity_score=0
            )
    
    async def _correlate_with_cloudtrail(
        self,
        audit_events: List[AuditLog],
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Correlate application audit events with CloudTrail logs."""
        try:
            # Get CloudTrail events for the same period
            cloudtrail_events = await self.cloudtrail_parser.parse_events_for_period(
                start_date, end_date
            )
            
            correlation_results = {
                "cloudtrail_events_found": len(cloudtrail_events),
                "app_events_found": len(audit_events),
                "correlated_events": 0,
                "missing_correlations": [],
                "correlation_score": 0
            }
            
            # Try to correlate critical events
            critical_app_events = [
                event for event in audit_events 
                if "login" in event.action or "file" in event.action
            ]
            
            correlated_count = 0
            for app_event in critical_app_events:
                # Look for corresponding CloudTrail event
                correlation_found = False
                for ct_event in cloudtrail_events:
                    if self._events_correlate(app_event, ct_event):
                        correlation_found = True
                        correlated_count += 1
                        break
                
                if not correlation_found:
                    correlation_results["missing_correlations"].append({
                        "app_event_id": str(app_event.id),
                        "timestamp": app_event.timestamp.isoformat(),
                        "action": app_event.action,
                        "user_id": str(app_event.user_id) if app_event.user_id else None
                    })
            
            correlation_results["correlated_events"] = correlated_count
            correlation_results["correlation_score"] = (
                correlated_count / max(len(critical_app_events), 1)
            ) * 100
            
            return correlation_results
            
        except Exception as e:
            logger.error(f"CloudTrail correlation failed: {e}")
            return {"error": str(e)}
    
    def _classify_audit_event(self, event: AuditLog) -> Optional[AuditEventType]:
        """Classify audit event into HIPAA event type."""
        action = event.action.lower()
        
        if "login" in action or "authenticate" in action:
            return AuditEventType.USER_AUTHENTICATION
        elif "access" in action or "view" in action or "download" in action:
            return AuditEventType.PHI_ACCESS
        elif "create" in action or "upload" in action:
            return AuditEventType.PHI_CREATION
        elif "update" in action or "modify" in action or "edit" in action:
            return AuditEventType.PHI_MODIFICATION
        elif "delete" in action or "remove" in action:
            return AuditEventType.PHI_DELETION
        elif "export" in action or "share" in action:
            return AuditEventType.PHI_DISCLOSURE
        elif "backup" in action:
            return AuditEventType.BACKUP_OPERATION
        elif "admin" in action or "config" in action:
            return AuditEventType.ADMINISTRATIVE_ACTION
        elif "security" in action or "breach" in action:
            return AuditEventType.SECURITY_EVENT
        else:
            return AuditEventType.SYSTEM_ACCESS
    
    def _analyze_completeness(self, events: List[AuditLog], requirement: AuditRequirement) -> int:
        """Analyze completeness of audit events for requirement."""
        if not events:
            return 0
        
        # Check for gaps in critical activities
        # This is simplified - in production you'd have more sophisticated gap analysis
        expected_frequency = 1  # Expected events per day
        actual_frequency = len(events) / 7  # Events per day over a week
        
        completeness_ratio = min(1.0, actual_frequency / expected_frequency)
        return int(completeness_ratio * 100)
    
    def _analyze_field_compliance(self, events: List[AuditLog], requirement: AuditRequirement) -> int:
        """Analyze field compliance for audit events."""
        if not events:
            return 100  # No events, so no field violations
        
        compliant_events = 0
        for event in events:
            event_dict = self._audit_log_to_dict(event)
            
            # Check if all required fields are present and non-empty
            fields_present = all(
                field in event_dict and event_dict[field] is not None
                for field in requirement.required_fields
            )
            
            if fields_present:
                compliant_events += 1
        
        return int((compliant_events / len(events)) * 100)
    
    def _analyze_retention_compliance(self, requirement: AuditRequirement) -> int:
        """Analyze retention compliance for requirement."""
        try:
            # Check if we have logs going back the required retention period
            retention_cutoff = datetime.utcnow() - timedelta(days=requirement.retention_years * 365)
            
            old_logs_count = self.db.query(AuditLog).filter(
                AuditLog.timestamp <= retention_cutoff
            ).count()
            
            # If we have logs older than retention period, we're compliant with retention
            # If not, check if the system is newer than retention period
            system_age_days = (datetime.utcnow() - datetime(2024, 1, 1)).days  # Assuming system started in 2024
            required_retention_days = requirement.retention_years * 365
            
            if system_age_days < required_retention_days:
                return 100  # System is newer than required retention period
            elif old_logs_count > 0:
                return 100  # We have old logs, retention is working
            else:
                return 50   # No old logs when we should have them
            
        except Exception as e:
            logger.error(f"Retention compliance analysis failed: {e}")
            return 0
    
    def _calculate_event_hash(self, event: AuditLog) -> str:
        """Calculate integrity hash for audit event."""
        # Create hash from critical event fields
        hash_data = f"{event.id}:{event.timestamp}:{event.user_id}:{event.action}:{event.resource_id}"
        
        if self.integrity_secret:
            return hmac.new(
                self.integrity_secret.encode(),
                hash_data.encode(),
                hashlib.sha256
            ).hexdigest()
        else:
            return hashlib.sha256(hash_data.encode()).hexdigest()
    
    async def _verify_cross_system_correlation(self, audit_events: List[AuditLog]) -> bool:
        """Verify cross-system correlation of audit events."""
        # Simplified verification - in production would be more comprehensive
        try:
            # Check if we have corresponding system events for user actions
            user_events = [e for e in audit_events if e.user_id and "login" in e.action]
            
            # For each login, we should have corresponding session creation
            for login_event in user_events:
                session_exists = self.db.query(UserSession).filter(
                    and_(
                        UserSession.user_id == login_event.user_id,
                        UserSession.created_at >= login_event.timestamp - timedelta(minutes=5),
                        UserSession.created_at <= login_event.timestamp + timedelta(minutes=5)
                    )
                ).first()
                
                if not session_exists:
                    return False  # Login without session creation
            
            return True
            
        except Exception as e:
            logger.error(f"Cross-system correlation verification failed: {e}")
            return False
    
    def _events_correlate(self, app_event: AuditLog, cloudtrail_event: CloudTrailEvent) -> bool:
        """Check if application event correlates with CloudTrail event."""
        # Simplified correlation logic
        time_diff = abs((app_event.timestamp - cloudtrail_event.timestamp).total_seconds())
        
        # Events should be within 5 minutes of each other
        if time_diff > 300:
            return False
        
        # Check for related actions
        app_action = app_event.action.lower()
        ct_action = cloudtrail_event.event_name.lower()
        
        correlation_patterns = {
            "login": ["assumerolewithwebidentity", "getuser", "getsessiontoken"],
            "file_upload": ["putobject", "uploadpart"],
            "file_download": ["getobject", "headobject"],
            "user_create": ["createuser", "putuser"]
        }
        
        for app_pattern, ct_patterns in correlation_patterns.items():
            if app_pattern in app_action:
                return any(pattern in ct_action for pattern in ct_patterns)
        
        return False
    
    def _calculate_compliance_score(
        self,
        compliance_analysis: Dict[str, Any],
        integrity_result: IntegrityCheckResult
    ) -> int:
        """Calculate overall compliance score."""
        if not compliance_analysis:
            return 0
        
        # Calculate weighted average of requirement compliance scores
        total_weight = 0
        weighted_score = 0
        
        for req_id, analysis in compliance_analysis.items():
            requirement = self.audit_requirements[req_id]
            req_score = analysis["overall_compliance"]
            weight = requirement.compliance_weight
            
            weighted_score += req_score * weight
            total_weight += weight
        
        base_score = weighted_score / max(total_weight, 1)
        
        # Adjust for integrity score
        integrity_adjustment = (integrity_result.overall_integrity_score - 80) * 0.2
        
        final_score = base_score + integrity_adjustment
        return int(max(0, min(100, final_score)))
    
    def _determine_compliance_status(
        self,
        compliance_score: int,
        integrity_result: IntegrityCheckResult
    ) -> AuditCompliance:
        """Determine overall compliance status."""
        if integrity_result.overall_integrity_score < 70:
            return AuditCompliance.NON_COMPLIANT
        
        if compliance_score >= 90:
            return AuditCompliance.COMPLIANT
        elif compliance_score >= 70:
            return AuditCompliance.PARTIAL_COMPLIANCE
        else:
            return AuditCompliance.NON_COMPLIANT
    
    async def _identify_missing_events(
        self,
        audit_events: List[AuditLog],
        start_date: datetime,
        end_date: datetime
    ) -> List[str]:
        """Identify potentially missing audit events."""
        missing_events = []
        
        try:
            # Check for expected events that might be missing
            
            # 1. Check for logins without corresponding logouts
            login_events = [e for e in audit_events if "login_success" in e.action]
            logout_events = [e for e in audit_events if "logout" in e.action]
            
            if len(login_events) > len(logout_events) * 1.5:  # Allow some tolerance
                missing_events.append("Potential missing logout events detected")
            
            # 2. Check for file access without authentication
            file_events = [e for e in audit_events if "file" in e.action]
            auth_events = [e for e in audit_events if "login" in e.action or "auth" in e.action]
            
            if file_events and not auth_events:
                missing_events.append("File access events without authentication events")
            
            # 3. Check for administrative actions
            admin_events = [e for e in audit_events if "admin" in e.action or "config" in e.action]
            
            # Query database for potential admin activities
            user_creations = self.db.query(User).filter(
                and_(
                    User.created_at >= start_date,
                    User.created_at <= end_date
                )
            ).count()
            
            if user_creations > 0 and len(admin_events) == 0:
                missing_events.append("User creation activities not reflected in audit logs")
            
            # 4. Check for regular system activities
            days_in_period = (end_date - start_date).days
            if days_in_period > 0:
                events_per_day = len(audit_events) / days_in_period
                if events_per_day < 1:  # Less than 1 event per day seems low
                    missing_events.append("Unusually low audit event frequency detected")
            
            return missing_events
            
        except Exception as e:
            logger.error(f"Missing events identification failed: {e}")
            return ["Error analyzing missing events"]
    
    def _generate_audit_recommendations(
        self,
        compliance_analysis: Dict[str, Any],
        integrity_result: IntegrityCheckResult,
        missing_events: List[str]
    ) -> List[str]:
        """Generate audit improvement recommendations."""
        recommendations = []
        
        # Integrity recommendations
        if integrity_result.overall_integrity_score < 80:
            recommendations.append("URGENT: Address audit log integrity violations")
        
        if not integrity_result.hash_verification_passed:
            recommendations.append("Implement or repair audit log hash verification")
        
        if not integrity_result.sequential_verification_passed:
            recommendations.append("Fix audit log timestamp sequencing issues")
        
        # Compliance recommendations
        low_compliance_reqs = [
            req_id for req_id, analysis in compliance_analysis.items()
            if analysis["overall_compliance"] < 70
        ]
        
        if low_compliance_reqs:
            recommendations.append(f"Improve compliance for requirements: {', '.join(low_compliance_reqs)}")
        
        # Missing events recommendations
        if missing_events:
            recommendations.append("Investigate and address potentially missing audit events")
        
        # General recommendations
        recommendations.extend([
            "Implement automated audit log monitoring",
            "Establish regular audit log integrity verification",
            "Create automated compliance reporting",
            "Train staff on audit log requirements"
        ])
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    # Helper methods for analysis
    def _count_events_by_type(self, events: List[AuditLog]) -> Dict[str, int]:
        """Count events by classified type."""
        type_counts = defaultdict(int)
        for event in events:
            event_type = self._classify_audit_event(event)
            if event_type:
                type_counts[event_type.value] += 1
        return dict(type_counts)
    
    def _count_events_by_user(self, events: List[AuditLog]) -> Dict[str, int]:
        """Count events by user."""
        user_counts = defaultdict(int)
        for event in events:
            user_key = str(event.user_id) if event.user_id else "system"
            user_counts[user_key] += 1
        return dict(user_counts)
    
    def _analyze_event_distribution(self, events: List[AuditLog]) -> Dict[str, Any]:
        """Analyze distribution of audit events."""
        if not events:
            return {}
        
        # Time distribution
        hourly_dist = defaultdict(int)
        daily_dist = defaultdict(int)
        
        for event in events:
            hourly_dist[event.timestamp.hour] += 1
            daily_dist[event.timestamp.date().isoformat()] += 1
        
        return {
            "hourly_distribution": dict(hourly_dist),
            "daily_distribution": dict(daily_dist),
            "peak_hour": max(hourly_dist, key=hourly_dist.get) if hourly_dist else None,
            "total_days": len(daily_dist),
            "average_events_per_day": sum(daily_dist.values()) / max(len(daily_dist), 1)
        }
    
    def _analyze_user_patterns(self, events: List[AuditLog]) -> Dict[str, Any]:
        """Analyze user activity patterns."""
        user_patterns = {}
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            if event.user_id:
                user_events[str(event.user_id)].append(event)
        
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) > 0:
                user_patterns[user_id] = {
                    "total_events": len(user_event_list),
                    "event_types": list(set(e.action for e in user_event_list)),
                    "first_activity": user_event_list[0].timestamp.isoformat(),
                    "last_activity": user_event_list[-1].timestamp.isoformat(),
                    "average_daily_events": len(user_event_list) / max(7, 1)  # Assuming 7-day period
                }
        
        return user_patterns
    
    def _analyze_system_health(self, events: List[AuditLog]) -> Dict[str, Any]:
        """Analyze system health indicators from audit logs."""
        health_indicators = {
            "error_events": len([e for e in events if "error" in e.action.lower() or "fail" in e.action.lower()]),
            "success_events": len([e for e in events if "success" in e.action.lower()]),
            "security_events": len([e for e in events if "security" in e.action.lower() or "breach" in e.action.lower()]),
            "total_events": len(events)
        }
        
        if health_indicators["total_events"] > 0:
            health_indicators["error_rate"] = health_indicators["error_events"] / health_indicators["total_events"]
            health_indicators["security_event_rate"] = health_indicators["security_events"] / health_indicators["total_events"]
        else:
            health_indicators["error_rate"] = 0
            health_indicators["security_event_rate"] = 0
        
        return health_indicators
    
    def _audit_log_to_dict(self, event: AuditLog) -> Dict[str, Any]:
        """Convert audit log to dictionary for field analysis."""
        return {
            "user_id": event.user_id,
            "timestamp": event.timestamp,
            "action": event.action,
            "resource_id": event.resource_id,
            "resource_type": event.resource_type,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "success": getattr(event, 'success', None),
            "details": event.details,
            "changes": getattr(event, 'changes', None)
        }
    
    async def _log_audit_analysis(self, report: AuditReport):
        """Log audit analysis for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="hipaa_audit_analysis",
                severity="warning" if report.compliance_status != AuditCompliance.COMPLIANT else "info",
                description=f"HIPAA audit analysis completed. Compliance: {report.compliance_status.value}",
                details={
                    "report_id": report.report_id,
                    "compliance_score": report.compliance_score,
                    "total_events": report.total_events,
                    "integrity_score": report.integrity_verification.get("overall_integrity_score", 0)
                }
            )
        except Exception as e:
            logger.error(f"Failed to log audit analysis: {e}")


async def run_hipaa_audit(
    db: Session,
    start_date: datetime,
    end_date: datetime,
    user_id: Optional[UUID] = None
) -> AuditReport:
    """
    High-level function to run HIPAA audit analysis.
    
    Args:
        db: Database session
        start_date: Analysis period start
        end_date: Analysis period end
        user_id: Focus on specific user (optional)
        
    Returns:
        HIPAA audit report
    """
    audit_manager = HIPAAAuditManager(db)
    return await audit_manager.perform_comprehensive_audit_analysis(start_date, end_date, user_id) 