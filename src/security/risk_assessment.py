"""
Automated Healthcare Risk Assessment

Real-time risk assessment engine for healthcare systems with trending analysis,
risk factor weighting, and automated mitigation recommendations.
"""

import asyncio
import logging
import json
import math
import statistics
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID
from collections import defaultdict, deque

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, desc

from src.database.models import User, AuditLog, AudioFile, UserSession, NotificationHistory
from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from src.security.compliance_checker import HIPAAComplianceChecker, ComplianceViolation
from src.security.breach_detection import HealthcareThreatDetector, SecurityIncident
from config.compliance_config import (
    get_risk_assessment_config,
    get_compliance_config,
    get_monitoring_config
)

logger = logging.getLogger(__name__)


class RiskCategory(Enum):
    """Categories of risk in healthcare systems."""
    ACCESS_PATTERNS = "access_patterns"
    DATA_VOLUME = "data_volume"
    USER_BEHAVIOR = "user_behavior"
    SYSTEM_VULNERABILITIES = "system_vulnerabilities"
    COMPLIANCE_VIOLATIONS = "compliance_violations"
    SECURITY_INCIDENTS = "security_incidents"
    OPERATIONAL_RISK = "operational_risk"


class RiskLevel(Enum):
    """Risk severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskFactor:
    """Individual risk factor assessment."""
    category: RiskCategory
    name: str
    description: str
    current_value: float
    baseline_value: float
    risk_score: int  # 0-100
    weight: float  # 0-1
    trend: str  # increasing, decreasing, stable
    last_assessment: datetime
    mitigation_actions: List[str]
    severity: RiskLevel
    evidence: List[Dict[str, Any]]


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result."""
    assessment_id: str
    timestamp: datetime
    overall_risk_score: int  # 0-100
    risk_level: RiskLevel
    trend: str  # improving, deteriorating, stable
    risk_factors: List[RiskFactor]
    category_scores: Dict[str, int]
    high_risk_areas: List[str]
    mitigation_recommendations: List[str]
    next_assessment_due: datetime
    confidence_score: float
    assessment_duration_seconds: float


class HealthcareRiskAssessment:
    """Automated risk assessment engine for healthcare systems."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        
        # Configuration
        self.risk_config = get_risk_assessment_config()
        self.compliance_config = get_compliance_config()
        self.monitoring_config = get_monitoring_config()
        
        # Risk factor weights (from configuration)
        self.risk_weights = {
            RiskCategory.ACCESS_PATTERNS: self.risk_config.ACCESS_PATTERN_WEIGHT / 100,
            RiskCategory.DATA_VOLUME: self.risk_config.DATA_VOLUME_WEIGHT / 100,
            RiskCategory.USER_BEHAVIOR: self.risk_config.USER_BEHAVIOR_WEIGHT / 100,
            RiskCategory.SYSTEM_VULNERABILITIES: self.risk_config.VULNERABILITY_WEIGHT / 100,
            RiskCategory.COMPLIANCE_VIOLATIONS: self.risk_config.COMPLIANCE_WEIGHT / 100
        }
        
        # Thresholds
        self.low_threshold = self.risk_config.LOW_RISK_THRESHOLD
        self.medium_threshold = self.risk_config.MEDIUM_RISK_THRESHOLD
        self.high_threshold = self.risk_config.HIGH_RISK_THRESHOLD
        self.critical_threshold = self.risk_config.CRITICAL_RISK_THRESHOLD
        
        # Components
        self.compliance_checker = HIPAAComplianceChecker(db)
        self.threat_detector = HealthcareThreatDetector(db)
        
        # Risk history for trending
        self.risk_history = deque(maxlen=100)
    
    async def perform_comprehensive_risk_assessment(
        self,
        user_id: Optional[UUID] = None,
        include_historical_analysis: bool = True
    ) -> RiskAssessment:
        """
        Perform comprehensive risk assessment.
        
        Args:
            user_id: Focus on specific user (optional)
            include_historical_analysis: Include historical trend analysis
            
        Returns:
            Comprehensive risk assessment
        """
        try:
            assessment_start = datetime.utcnow()
            logger.info("Starting comprehensive healthcare risk assessment")
            
            # Generate unique assessment ID
            assessment_id = f"risk_assessment_{datetime.utcnow().timestamp()}"
            
            # Run all risk factor assessments concurrently
            risk_factor_results = await asyncio.gather(
                self._assess_access_pattern_risk(user_id),
                self._assess_data_volume_risk(user_id),
                self._assess_user_behavior_risk(user_id),
                self._assess_system_vulnerability_risk(),
                self._assess_compliance_violation_risk(),
                self._assess_security_incident_risk(),
                return_exceptions=True
            )
            
            # Process risk factors
            risk_factors = []
            for i, result in enumerate(risk_factor_results):
                if isinstance(result, Exception):
                    logger.error(f"Risk factor assessment {i} failed: {result}")
                else:
                    risk_factors.extend(result)
            
            # Calculate overall risk score
            overall_risk_score = self._calculate_overall_risk_score(risk_factors)
            
            # Determine risk level
            risk_level = self._determine_risk_level(overall_risk_score)
            
            # Calculate category scores
            category_scores = self._calculate_category_scores(risk_factors)
            
            # Determine trend
            trend = await self._determine_risk_trend(overall_risk_score, include_historical_analysis)
            
            # Identify high-risk areas
            high_risk_areas = self._identify_high_risk_areas(risk_factors)
            
            # Generate mitigation recommendations
            mitigation_recommendations = self._generate_mitigation_recommendations(risk_factors, risk_level)
            
            # Calculate next assessment due date
            next_assessment_due = self._calculate_next_assessment_date(risk_level)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(risk_factors)
            
            # Create assessment result
            assessment = RiskAssessment(
                assessment_id=assessment_id,
                timestamp=datetime.utcnow(),
                overall_risk_score=overall_risk_score,
                risk_level=risk_level,
                trend=trend,
                risk_factors=risk_factors,
                category_scores=category_scores,
                high_risk_areas=high_risk_areas,
                mitigation_recommendations=mitigation_recommendations,
                next_assessment_due=next_assessment_due,
                confidence_score=confidence_score,
                assessment_duration_seconds=(datetime.utcnow() - assessment_start).total_seconds()
            )
            
            # Store in risk history for trending
            self.risk_history.append({
                "timestamp": assessment.timestamp,
                "overall_score": overall_risk_score,
                "risk_level": risk_level.value,
                "category_scores": category_scores
            })
            
            # Log assessment
            await self._log_risk_assessment(assessment)
            
            # Trigger automated mitigation if enabled
            if self.risk_config.AUTOMATIC_RISK_MITIGATION:
                await self._trigger_automated_mitigation(assessment)
            
            return assessment
            
        except Exception as e:
            logger.error(f"Comprehensive risk assessment failed: {e}")
            raise
    
    async def _assess_access_pattern_risk(self, user_id: Optional[UUID] = None) -> List[RiskFactor]:
        """Assess risk related to data access patterns."""
        risk_factors = []
        
        try:
            # Analyze recent access patterns
            lookback_period = datetime.utcnow() - timedelta(days=7)
            
            # Query access activities
            query = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= lookback_period,
                    or_(
                        AuditLog.action.like("%file%"),
                        AuditLog.action.like("%data%")
                    )
                )
            )
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            access_logs = query.all()
            
            # Risk Factor 1: Access frequency anomalies
            access_frequency = len(access_logs) / 7  # per day
            baseline_frequency = await self._get_baseline_access_frequency()
            
            frequency_deviation = abs(access_frequency - baseline_frequency) / max(baseline_frequency, 1)
            frequency_risk_score = min(100, int(frequency_deviation * 50))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.ACCESS_PATTERNS,
                name="access_frequency_anomaly",
                description="Deviation from normal data access frequency patterns",
                current_value=access_frequency,
                baseline_value=baseline_frequency,
                risk_score=frequency_risk_score,
                weight=self.risk_weights[RiskCategory.ACCESS_PATTERNS],
                trend=self._calculate_trend(access_frequency, baseline_frequency),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Review user access permissions",
                    "Implement access pattern monitoring",
                    "Establish access baselines"
                ],
                severity=self._score_to_severity(frequency_risk_score),
                evidence=[{"access_count": len(access_logs), "baseline": baseline_frequency}]
            ))
            
            # Risk Factor 2: Off-hours access patterns
            off_hours_access = await self._count_off_hours_access(access_logs)
            total_access = len(access_logs)
            off_hours_ratio = off_hours_access / max(total_access, 1)
            
            off_hours_risk_score = min(100, int(off_hours_ratio * 100))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.ACCESS_PATTERNS,
                name="off_hours_access_risk",
                description="Risk from excessive off-hours data access",
                current_value=off_hours_ratio,
                baseline_value=0.1,  # 10% baseline
                risk_score=off_hours_risk_score,
                weight=self.risk_weights[RiskCategory.ACCESS_PATTERNS],
                trend=self._calculate_trend(off_hours_ratio, 0.1),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Implement time-based access controls",
                    "Monitor off-hours activity",
                    "Require justification for off-hours access"
                ],
                severity=self._score_to_severity(off_hours_risk_score),
                evidence=[{"off_hours_count": off_hours_access, "total_access": total_access}]
            ))
            
            # Risk Factor 3: Cross-user data access
            cross_user_access = await self._count_cross_user_access(access_logs)
            cross_user_ratio = cross_user_access / max(total_access, 1)
            
            cross_user_risk_score = min(100, int(cross_user_ratio * 150))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.ACCESS_PATTERNS,
                name="cross_user_access_risk",
                description="Risk from users accessing data not belonging to them",
                current_value=cross_user_ratio,
                baseline_value=0.05,  # 5% baseline for authorized cross-access
                risk_score=cross_user_risk_score,
                weight=self.risk_weights[RiskCategory.ACCESS_PATTERNS],
                trend=self._calculate_trend(cross_user_ratio, 0.05),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Review data sharing authorizations",
                    "Implement stricter access controls",
                    "Audit cross-user access patterns"
                ],
                severity=self._score_to_severity(cross_user_risk_score),
                evidence=[{"cross_user_count": cross_user_access, "total_access": total_access}]
            ))
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Access pattern risk assessment failed: {e}")
            return []
    
    async def _assess_data_volume_risk(self, user_id: Optional[UUID] = None) -> List[RiskFactor]:
        """Assess risk related to data volume and growth."""
        risk_factors = []
        
        try:
            # Query file storage data
            query = self.db.query(AudioFile).filter(AudioFile.is_deleted == False)
            if user_id:
                query = query.filter(AudioFile.user_id == user_id)
            
            files = query.all()
            
            # Risk Factor 1: Total data volume
            total_size = sum(file.file_size or 0 for file in files)
            total_gb = total_size / (1024**3)
            
            # Compare against baseline (would be configurable)
            baseline_gb = 100.0  # 100GB baseline
            volume_ratio = total_gb / baseline_gb
            
            volume_risk_score = min(100, int(volume_ratio * 30))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.DATA_VOLUME,
                name="total_data_volume",
                description="Risk from excessive total data volume",
                current_value=total_gb,
                baseline_value=baseline_gb,
                risk_score=volume_risk_score,
                weight=self.risk_weights[RiskCategory.DATA_VOLUME],
                trend=self._calculate_trend(total_gb, baseline_gb),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Implement data retention policies",
                    "Archive old data",
                    "Monitor storage growth"
                ],
                severity=self._score_to_severity(volume_risk_score),
                evidence=[{"total_files": len(files), "total_gb": total_gb}]
            ))
            
            # Risk Factor 2: Data growth rate
            recent_files = [f for f in files if f.uploaded_at >= datetime.utcnow() - timedelta(days=30)]
            recent_growth = sum(file.file_size or 0 for file in recent_files) / (1024**3)
            monthly_growth_rate = recent_growth  # GB per month
            
            # Compare against expected growth rate
            expected_growth_rate = 10.0  # 10GB per month baseline
            growth_deviation = abs(monthly_growth_rate - expected_growth_rate) / max(expected_growth_rate, 1)
            
            growth_risk_score = min(100, int(growth_deviation * 40))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.DATA_VOLUME,
                name="data_growth_rate",
                description="Risk from abnormal data growth patterns",
                current_value=monthly_growth_rate,
                baseline_value=expected_growth_rate,
                risk_score=growth_risk_score,
                weight=self.risk_weights[RiskCategory.DATA_VOLUME],
                trend=self._calculate_trend(monthly_growth_rate, expected_growth_rate),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Monitor data upload patterns",
                    "Implement upload quotas",
                    "Review data growth trends"
                ],
                severity=self._score_to_severity(growth_risk_score),
                evidence=[{"recent_files": len(recent_files), "monthly_growth_gb": monthly_growth_rate}]
            ))
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Data volume risk assessment failed: {e}")
            return []
    
    async def _assess_user_behavior_risk(self, user_id: Optional[UUID] = None) -> List[RiskFactor]:
        """Assess risk related to user behavior patterns."""
        risk_factors = []
        
        try:
            # Query user activities
            lookback_period = datetime.utcnow() - timedelta(days=7)
            
            query = self.db.query(AuditLog).filter(AuditLog.timestamp >= lookback_period)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            activities = query.all()
            
            # Group by user
            user_activities = defaultdict(list)
            for activity in activities:
                if activity.user_id:
                    user_activities[activity.user_id].append(activity)
            
            # Risk Factor 1: User activity anomalies
            anomalous_users = 0
            total_users = len(user_activities)
            
            for uid, user_acts in user_activities.items():
                activity_count = len(user_acts)
                baseline_activity = await self._get_baseline_user_activity(uid)
                
                if activity_count > baseline_activity * 3:  # 3x normal activity
                    anomalous_users += 1
            
            anomaly_ratio = anomalous_users / max(total_users, 1)
            anomaly_risk_score = min(100, int(anomaly_ratio * 80))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.USER_BEHAVIOR,
                name="user_activity_anomalies",
                description="Risk from users with anomalous activity patterns",
                current_value=anomaly_ratio,
                baseline_value=0.05,  # 5% baseline anomaly rate
                risk_score=anomaly_risk_score,
                weight=self.risk_weights[RiskCategory.USER_BEHAVIOR],
                trend=self._calculate_trend(anomaly_ratio, 0.05),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Investigate anomalous user behavior",
                    "Implement behavioral monitoring",
                    "Review user access patterns"
                ],
                severity=self._score_to_severity(anomaly_risk_score),
                evidence=[{"anomalous_users": anomalous_users, "total_users": total_users}]
            ))
            
            # Risk Factor 2: Failed authentication attempts
            failed_logins = [a for a in activities if "login_failed" in a.action]
            total_logins = [a for a in activities if "login" in a.action]
            
            failure_rate = len(failed_logins) / max(len(total_logins), 1)
            failure_risk_score = min(100, int(failure_rate * 200))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.USER_BEHAVIOR,
                name="authentication_failure_rate",
                description="Risk from high authentication failure rates",
                current_value=failure_rate,
                baseline_value=0.1,  # 10% baseline failure rate
                risk_score=failure_risk_score,
                weight=self.risk_weights[RiskCategory.USER_BEHAVIOR],
                trend=self._calculate_trend(failure_rate, 0.1),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Investigate failed login patterns",
                    "Implement account lockout policies",
                    "Monitor brute force attempts"
                ],
                severity=self._score_to_severity(failure_risk_score),
                evidence=[{"failed_logins": len(failed_logins), "total_logins": len(total_logins)}]
            ))
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"User behavior risk assessment failed: {e}")
            return []
    
    async def _assess_system_vulnerability_risk(self) -> List[RiskFactor]:
        """Assess risk from system vulnerabilities."""
        risk_factors = []
        
        try:
            # Risk Factor 1: Unencrypted data
            total_files = self.db.query(AudioFile).count()
            unencrypted_files = self.db.query(AudioFile).filter(
                or_(
                    AudioFile.encryption_key_id.is_(None),
                    AudioFile.encryption_key_id == ""
                )
            ).count()
            
            encryption_compliance = 1 - (unencrypted_files / max(total_files, 1))
            encryption_risk_score = int((1 - encryption_compliance) * 100)
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.SYSTEM_VULNERABILITIES,
                name="data_encryption_coverage",
                description="Risk from unencrypted sensitive data",
                current_value=encryption_compliance,
                baseline_value=1.0,  # 100% encryption expected
                risk_score=encryption_risk_score,
                weight=self.risk_weights[RiskCategory.SYSTEM_VULNERABILITIES],
                trend=self._calculate_trend(encryption_compliance, 1.0),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Encrypt all unencrypted files",
                    "Implement mandatory encryption policies",
                    "Monitor encryption compliance"
                ],
                severity=self._score_to_severity(encryption_risk_score),
                evidence=[{"total_files": total_files, "unencrypted_files": unencrypted_files}]
            ))
            
            # Risk Factor 2: Session management vulnerabilities
            active_sessions = self.db.query(UserSession).filter(UserSession.is_active == True).count()
            long_sessions = self.db.query(UserSession).filter(
                and_(
                    UserSession.is_active == True,
                    UserSession.created_at < datetime.utcnow() - timedelta(hours=24)
                )
            ).count()
            
            session_risk_ratio = long_sessions / max(active_sessions, 1)
            session_risk_score = min(100, int(session_risk_ratio * 80))
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.SYSTEM_VULNERABILITIES,
                name="session_management_risk",
                description="Risk from poor session management practices",
                current_value=session_risk_ratio,
                baseline_value=0.05,  # 5% baseline for long sessions
                risk_score=session_risk_score,
                weight=self.risk_weights[RiskCategory.SYSTEM_VULNERABILITIES],
                trend=self._calculate_trend(session_risk_ratio, 0.05),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Implement session timeout policies",
                    "Terminate long-running sessions",
                    "Monitor session durations"
                ],
                severity=self._score_to_severity(session_risk_score),
                evidence=[{"active_sessions": active_sessions, "long_sessions": long_sessions}]
            ))
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"System vulnerability risk assessment failed: {e}")
            return []
    
    async def _assess_compliance_violation_risk(self) -> List[RiskFactor]:
        """Assess risk from HIPAA compliance violations."""
        risk_factors = []
        
        try:
            # Run compliance check
            compliance_result = await self.compliance_checker.perform_comprehensive_compliance_check()
            
            total_violations = compliance_result["total_violations"]
            compliance_score = compliance_result["compliance_score"]["total_score"]
            
            # Risk Factor 1: Overall compliance score
            compliance_risk_score = 100 - compliance_score
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.COMPLIANCE_VIOLATIONS,
                name="hipaa_compliance_score",
                description="Risk from HIPAA compliance violations",
                current_value=compliance_score,
                baseline_value=100.0,  # Perfect compliance expected
                risk_score=compliance_risk_score,
                weight=self.risk_weights[RiskCategory.COMPLIANCE_VIOLATIONS],
                trend=self._calculate_trend(compliance_score, 100.0),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Address compliance violations immediately",
                    "Implement compliance monitoring",
                    "Review HIPAA requirements"
                ],
                severity=self._score_to_severity(compliance_risk_score),
                evidence=[{"total_violations": total_violations, "compliance_score": compliance_score}]
            ))
            
            # Risk Factor 2: Critical violations
            critical_violations = len(compliance_result["critical_violations"])
            critical_risk_score = min(100, critical_violations * 25)  # 25 points per critical violation
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.COMPLIANCE_VIOLATIONS,
                name="critical_violations",
                description="Risk from critical HIPAA compliance violations",
                current_value=critical_violations,
                baseline_value=0.0,  # No critical violations expected
                risk_score=critical_risk_score,
                weight=self.risk_weights[RiskCategory.COMPLIANCE_VIOLATIONS],
                trend=self._calculate_trend(critical_violations, 0.0),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Immediately address critical violations",
                    "Implement emergency compliance measures",
                    "Escalate to compliance officer"
                ],
                severity=self._score_to_severity(critical_risk_score),
                evidence=[{"critical_violations": critical_violations}]
            ))
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Compliance violation risk assessment failed: {e}")
            return []
    
    async def _assess_security_incident_risk(self) -> List[RiskFactor]:
        """Assess risk from security incidents."""
        risk_factors = []
        
        try:
            # Run threat detection
            threat_result = await self.threat_detector.run_threat_detection_scan(lookback_hours=24)
            
            total_incidents = threat_result["total_incidents"]
            high_priority_incidents = len(threat_result["high_priority_incidents"])
            
            # Risk Factor 1: Total security incidents
            incident_risk_score = min(100, total_incidents * 10)  # 10 points per incident
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.SECURITY_INCIDENTS,
                name="security_incident_count",
                description="Risk from detected security incidents",
                current_value=total_incidents,
                baseline_value=0.0,  # No incidents expected
                risk_score=incident_risk_score,
                weight=0.1,  # Additional weight for security incidents
                trend=self._calculate_trend(total_incidents, 0.0),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Investigate and resolve security incidents",
                    "Implement incident response procedures",
                    "Enhance security monitoring"
                ],
                severity=self._score_to_severity(incident_risk_score),
                evidence=[{"total_incidents": total_incidents}]
            ))
            
            # Risk Factor 2: High-priority incidents
            high_priority_risk_score = min(100, high_priority_incidents * 20)  # 20 points per high-priority incident
            
            risk_factors.append(RiskFactor(
                category=RiskCategory.SECURITY_INCIDENTS,
                name="high_priority_incidents",
                description="Risk from high-priority security incidents",
                current_value=high_priority_incidents,
                baseline_value=0.0,  # No high-priority incidents expected
                risk_score=high_priority_risk_score,
                weight=0.15,  # Higher weight for high-priority incidents
                trend=self._calculate_trend(high_priority_incidents, 0.0),
                last_assessment=datetime.utcnow(),
                mitigation_actions=[
                    "Immediately address high-priority incidents",
                    "Implement emergency response procedures",
                    "Escalate to security team"
                ],
                severity=self._score_to_severity(high_priority_risk_score),
                evidence=[{"high_priority_incidents": high_priority_incidents}]
            ))
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Security incident risk assessment failed: {e}")
            return []
    
    def _calculate_overall_risk_score(self, risk_factors: List[RiskFactor]) -> int:
        """Calculate overall weighted risk score."""
        if not risk_factors:
            return 0
        
        total_weighted_score = 0
        total_weight = 0
        
        for factor in risk_factors:
            weighted_score = factor.risk_score * factor.weight
            total_weighted_score += weighted_score
            total_weight += factor.weight
        
        # Normalize to 0-100 scale
        overall_score = int(total_weighted_score / max(total_weight, 1))
        return min(100, max(0, overall_score))
    
    def _determine_risk_level(self, risk_score: int) -> RiskLevel:
        """Determine risk level from score."""
        if risk_score >= self.critical_threshold:
            return RiskLevel.CRITICAL
        elif risk_score >= self.high_threshold:
            return RiskLevel.HIGH
        elif risk_score >= self.medium_threshold:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_category_scores(self, risk_factors: List[RiskFactor]) -> Dict[str, int]:
        """Calculate risk scores by category."""
        category_scores = {}
        category_factors = defaultdict(list)
        
        # Group factors by category
        for factor in risk_factors:
            category_factors[factor.category.value].append(factor)
        
        # Calculate average score for each category
        for category, factors in category_factors.items():
            if factors:
                avg_score = sum(f.risk_score for f in factors) / len(factors)
                category_scores[category] = int(avg_score)
        
        return category_scores
    
    async def _determine_risk_trend(self, current_score: int, include_historical: bool) -> str:
        """Determine risk trend from historical data."""
        if not include_historical or len(self.risk_history) < 2:
            return "stable"
        
        # Compare with recent history
        recent_scores = [entry["overall_score"] for entry in list(self.risk_history)[-5:]]
        
        if len(recent_scores) < 2:
            return "stable"
        
        # Calculate trend
        trend_slope = (recent_scores[-1] - recent_scores[0]) / len(recent_scores)
        
        if trend_slope > 5:
            return "deteriorating"
        elif trend_slope < -5:
            return "improving"
        else:
            return "stable"
    
    def _identify_high_risk_areas(self, risk_factors: List[RiskFactor]) -> List[str]:
        """Identify areas with highest risk."""
        high_risk_areas = []
        
        for factor in risk_factors:
            if factor.risk_score >= self.high_threshold:
                high_risk_areas.append(f"{factor.category.value}: {factor.name}")
        
        # Sort by risk score
        high_risk_areas.sort(
            key=lambda area: next(
                f.risk_score for f in risk_factors 
                if f"{f.category.value}: {f.name}" == area
            ),
            reverse=True
        )
        
        return high_risk_areas[:10]  # Top 10 high-risk areas
    
    def _generate_mitigation_recommendations(self, risk_factors: List[RiskFactor], risk_level: RiskLevel) -> List[str]:
        """Generate prioritized mitigation recommendations."""
        recommendations = []
        
        # Add level-specific recommendations
        if risk_level == RiskLevel.CRITICAL:
            recommendations.append("URGENT: Implement immediate risk mitigation measures")
            recommendations.append("Activate incident response procedures")
            recommendations.append("Notify senior management and compliance officer")
        
        elif risk_level == RiskLevel.HIGH:
            recommendations.append("Implement high-priority risk mitigation measures")
            recommendations.append("Increase monitoring and security controls")
        
        # Add factor-specific recommendations
        high_risk_factors = [f for f in risk_factors if f.risk_score >= self.high_threshold]
        high_risk_factors.sort(key=lambda x: x.risk_score, reverse=True)
        
        for factor in high_risk_factors[:5]:  # Top 5 factors
            recommendations.extend(factor.mitigation_actions)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Limit to 10 recommendations
    
    def _calculate_next_assessment_date(self, risk_level: RiskLevel) -> datetime:
        """Calculate when next assessment should be performed."""
        hours_map = {
            RiskLevel.CRITICAL: 6,   # Every 6 hours
            RiskLevel.HIGH: 12,      # Every 12 hours
            RiskLevel.MEDIUM: 24,    # Daily
            RiskLevel.LOW: 168       # Weekly
        }
        
        hours = hours_map.get(risk_level, 24)
        return datetime.utcnow() + timedelta(hours=hours)
    
    def _calculate_confidence_score(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate confidence in risk assessment."""
        if not risk_factors:
            return 0.0
        
        # Base confidence on data availability and quality
        confidence_scores = []
        
        for factor in risk_factors:
            # Factor-specific confidence calculation
            if factor.evidence:
                evidence_score = min(1.0, len(factor.evidence) * 0.2)
            else:
                evidence_score = 0.5
            
            # Baseline vs current value confidence
            if factor.baseline_value > 0:
                baseline_confidence = 0.8
            else:
                baseline_confidence = 0.6
            
            factor_confidence = (evidence_score + baseline_confidence) / 2
            confidence_scores.append(factor_confidence)
        
        return sum(confidence_scores) / len(confidence_scores)
    
    # Helper methods
    def _calculate_trend(self, current: float, baseline: float) -> str:
        """Calculate trend direction."""
        if current > baseline * 1.1:
            return "increasing"
        elif current < baseline * 0.9:
            return "decreasing"
        else:
            return "stable"
    
    def _score_to_severity(self, score: int) -> RiskLevel:
        """Convert risk score to severity level."""
        if score >= self.critical_threshold:
            return RiskLevel.CRITICAL
        elif score >= self.high_threshold:
            return RiskLevel.HIGH
        elif score >= self.medium_threshold:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    async def _get_baseline_access_frequency(self) -> float:
        """Get baseline access frequency from historical data."""
        # In production, this would calculate from historical data
        # For now, return a reasonable default
        return 50.0  # 50 accesses per day baseline
    
    async def _count_off_hours_access(self, access_logs: List[AuditLog]) -> int:
        """Count access activities during off-hours."""
        # Simplified implementation
        off_hours_count = 0
        
        for log in access_logs:
            hour = log.timestamp.hour
            weekday = log.timestamp.weekday()
            
            # Outside 8 AM - 6 PM or weekends
            if hour < 8 or hour > 18 or weekday >= 5:
                off_hours_count += 1
        
        return off_hours_count
    
    async def _count_cross_user_access(self, access_logs: List[AuditLog]) -> int:
        """Count accesses to data not belonging to the accessing user."""
        cross_user_count = 0
        
        for log in access_logs:
            if log.resource_type == "audio_file" and log.resource_id and log.user_id:
                file = self.db.query(AudioFile).get(log.resource_id)
                if file and file.user_id != log.user_id:
                    # Check if this is authorized cross-access (simplified)
                    user = self.db.query(User).get(log.user_id)
                    is_authorized = (
                        user and 
                        any(role.role.name in ["admin", "healthcare_provider"] 
                            for role in user.role_assignments)
                    )
                    if not is_authorized:
                        cross_user_count += 1
        
        return cross_user_count
    
    async def _get_baseline_user_activity(self, user_id: UUID) -> float:
        """Get baseline activity level for a user."""
        # In production, this would calculate from historical data
        # For now, return a reasonable default
        return 20.0  # 20 activities per week baseline
    
    async def _trigger_automated_mitigation(self, assessment: RiskAssessment):
        """Trigger automated risk mitigation actions."""
        try:
            if assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                # Log high-risk assessment
                await self.audit_logger.log_security_event(
                    event_type="high_risk_assessment",
                    severity="critical" if assessment.risk_level == RiskLevel.CRITICAL else "high",
                    description=f"High risk assessment detected: {assessment.overall_risk_score}",
                    details={
                        "assessment_id": assessment.assessment_id,
                        "risk_score": assessment.overall_risk_score,
                        "risk_level": assessment.risk_level.value,
                        "high_risk_areas": assessment.high_risk_areas
                    }
                )
                
                # Additional automated actions could be implemented here
                # e.g., trigger notifications, disable accounts, etc.
                
        except Exception as e:
            logger.error(f"Failed to trigger automated mitigation: {e}")
    
    async def _log_risk_assessment(self, assessment: RiskAssessment):
        """Log risk assessment for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="risk_assessment_completed",
                severity="info" if assessment.risk_level == RiskLevel.LOW else "warning",
                description=f"Risk assessment completed. Overall score: {assessment.overall_risk_score}",
                details={
                    "assessment_id": assessment.assessment_id,
                    "overall_score": assessment.overall_risk_score,
                    "risk_level": assessment.risk_level.value,
                    "confidence_score": assessment.confidence_score,
                    "duration_seconds": assessment.assessment_duration_seconds
                }
            )
        except Exception as e:
            logger.error(f"Failed to log risk assessment: {e}")


async def run_risk_assessment(
    db: Session,
    user_id: Optional[UUID] = None,
    include_historical: bool = True
) -> RiskAssessment:
    """
    High-level function to run risk assessment.
    
    Args:
        db: Database session
        user_id: Focus on specific user (optional)
        include_historical: Include historical trend analysis
        
    Returns:
        Risk assessment results
    """
    assessor = HealthcareRiskAssessment(db)
    return await assessor.perform_comprehensive_risk_assessment(user_id, include_historical) 