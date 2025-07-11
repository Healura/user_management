"""
Business Associate Agreement (BAA) Compliance Monitoring

Monitors and enforces compliance with Business Associate Agreements
for healthcare vendor relationships and third-party integrations.
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID, uuid4

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func

from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from config.compliance_config import get_baa_compliance_config, get_compliance_config

logger = logging.getLogger(__name__)


class BAAComplianceStatus(Enum):
    """BAA compliance status levels."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PENDING_REVIEW = "pending_review"
    EXPIRED = "expired"
    NOT_APPLICABLE = "not_applicable"


class VendorType(Enum):
    """Types of business associates/vendors."""
    CLOUD_PROVIDER = "cloud_provider"
    SaaS_VENDOR = "saas_vendor"
    IT_SUPPORT = "it_support"
    ANALYTICS_PROVIDER = "analytics_provider"
    BACKUP_SERVICE = "backup_service"
    COMMUNICATION_PROVIDER = "communication_provider"
    OTHER = "other"


class BAARequirement(Enum):
    """Required BAA compliance elements."""
    SIGNED_BAA = "signed_baa"
    PHI_SAFEGUARDS = "phi_safeguards"
    INCIDENT_NOTIFICATION = "incident_notification"
    DATA_RETURN_DESTRUCTION = "data_return_destruction"
    PERMITTED_USES = "permitted_uses"
    MINIMUM_NECESSARY = "minimum_necessary"
    SAFEGUARD_REPORTING = "safeguard_reporting"
    SUBCONTRACTOR_AGREEMENTS = "subcontractor_agreements"


@dataclass
class BusinessAssociate:
    """Represents a business associate/vendor."""
    id: str
    name: str
    vendor_type: VendorType
    contact_email: str
    baa_signed_date: Optional[datetime] = None
    baa_expiration_date: Optional[datetime] = None
    compliance_status: BAAComplianceStatus = BAAComplianceStatus.PENDING_REVIEW
    phi_access_level: str = "none"  # none, limited, full
    services_provided: List[str] = None
    compliance_requirements: Dict[str, bool] = None
    last_assessment_date: Optional[datetime] = None
    risk_level: str = "medium"  # low, medium, high, critical
    monitoring_frequency: str = "monthly"  # daily, weekly, monthly, quarterly
    contract_details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.services_provided is None:
            self.services_provided = []
        if self.compliance_requirements is None:
            self.compliance_requirements = {req.value: False for req in BAARequirement}
        if self.contract_details is None:
            self.contract_details = {}


@dataclass
class BAAViolation:
    """Represents a BAA compliance violation."""
    id: str
    business_associate_id: str
    violation_type: BAARequirement
    severity: str  # low, medium, high, critical
    description: str
    detected_date: datetime
    resolution_deadline: datetime
    status: str = "open"  # open, acknowledged, resolved, overdue
    remediation_actions: List[str] = None
    responsible_party: Optional[str] = None
    evidence: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.remediation_actions is None:
            self.remediation_actions = []
        if self.evidence is None:
            self.evidence = {}


@dataclass
class BAAAssessment:
    """BAA compliance assessment result."""
    assessment_id: str
    timestamp: datetime
    business_associate_id: str
    overall_compliance_score: int  # 0-100
    compliance_status: BAAComplianceStatus
    requirement_compliance: Dict[str, bool]
    violations: List[BAAViolation]
    recommendations: List[str]
    next_assessment_due: datetime
    assessment_notes: str = ""


class BAAComplianceMonitor:
    """Business Associate Agreement compliance monitoring system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        
        # Configuration
        self.baa_config = get_baa_compliance_config()
        self.compliance_config = get_compliance_config()
        
        # Business associates registry
        self.business_associates = {}
        self.load_business_associates()
        
        # Compliance thresholds
        self.high_risk_threshold = 70
        self.medium_risk_threshold = 85
        self.compliance_threshold = 90
    
    def load_business_associates(self):
        """Load business associates from configuration or database."""
        # In production, this would load from database
        # For now, initialize with common healthcare vendors
        
        default_associates = [
            {
                "id": "aws",
                "name": "Amazon Web Services",
                "vendor_type": VendorType.CLOUD_PROVIDER,
                "contact_email": "hipaa-compliance@aws.amazon.com",
                "phi_access_level": "full",
                "services_provided": ["cloud_hosting", "storage", "computing"],
                "risk_level": "high"
            },
            {
                "id": "google_cloud",
                "name": "Google Cloud Platform",
                "vendor_type": VendorType.CLOUD_PROVIDER,
                "contact_email": "compliance@google.com",
                "phi_access_level": "full",
                "services_provided": ["cloud_hosting", "analytics", "ai_services"],
                "risk_level": "high"
            },
            {
                "id": "microsoft_azure",
                "name": "Microsoft Azure",
                "vendor_type": VendorType.CLOUD_PROVIDER,
                "contact_email": "compliance@microsoft.com",
                "phi_access_level": "full",
                "services_provided": ["cloud_hosting", "productivity_tools"],
                "risk_level": "high"
            },
            {
                "id": "twilio",
                "name": "Twilio",
                "vendor_type": VendorType.COMMUNICATION_PROVIDER,
                "contact_email": "security@twilio.com",
                "phi_access_level": "limited",
                "services_provided": ["sms_messaging", "voice_calls"],
                "risk_level": "medium"
            }
        ]
        
        for ba_data in default_associates:
            ba = BusinessAssociate(**ba_data)
            self.business_associates[ba.id] = ba
    
    async def perform_comprehensive_baa_assessment(
        self,
        business_associate_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive BAA compliance assessment.
        
        Args:
            business_associate_id: Specific associate to assess (optional)
            
        Returns:
            BAA compliance assessment results
        """
        try:
            logger.info("Starting comprehensive BAA compliance assessment")
            
            assessments = []
            violations = []
            
            # Determine which associates to assess
            if business_associate_id:
                if business_associate_id in self.business_associates:
                    associates_to_assess = [self.business_associates[business_associate_id]]
                else:
                    raise ValueError(f"Business associate {business_associate_id} not found")
            else:
                associates_to_assess = list(self.business_associates.values())
            
            # Assess each business associate
            for ba in associates_to_assess:
                assessment = await self._assess_business_associate(ba)
                assessments.append(assessment)
                violations.extend(assessment.violations)
            
            # Generate summary
            summary = {
                "assessment_timestamp": datetime.utcnow().isoformat(),
                "total_associates_assessed": len(assessments),
                "compliant_associates": len([a for a in assessments if a.compliance_status == BAAComplianceStatus.COMPLIANT]),
                "non_compliant_associates": len([a for a in assessments if a.compliance_status == BAAComplianceStatus.NON_COMPLIANT]),
                "pending_review": len([a for a in assessments if a.compliance_status == BAAComplianceStatus.PENDING_REVIEW]),
                "expired_baas": len([a for a in assessments if a.compliance_status == BAAComplianceStatus.EXPIRED]),
                "total_violations": len(violations),
                "critical_violations": len([v for v in violations if v.severity == "critical"]),
                "high_risk_associates": [a for a in assessments if a.overall_compliance_score < self.high_risk_threshold],
                "assessments": assessments,
                "violations": violations,
                "recommendations": self._generate_overall_recommendations(assessments, violations)
            }
            
            # Log assessment
            await self._log_baa_assessment(summary)
            
            return summary
            
        except Exception as e:
            logger.error(f"BAA compliance assessment failed: {e}")
            raise
    
    async def _assess_business_associate(self, ba: BusinessAssociate) -> BAAAssessment:
        """Assess compliance for a specific business associate."""
        try:
            assessment_id = f"baa_assessment_{ba.id}_{datetime.utcnow().timestamp()}"
            
            # Check each BAA requirement
            requirement_compliance = {}
            violations = []
            
            for requirement in BAARequirement:
                is_compliant, violation = await self._check_baa_requirement(ba, requirement)
                requirement_compliance[requirement.value] = is_compliant
                
                if violation:
                    violations.append(violation)
            
            # Calculate overall compliance score
            compliance_score = self._calculate_compliance_score(requirement_compliance)
            
            # Determine compliance status
            compliance_status = self._determine_compliance_status(ba, compliance_score)
            
            # Generate recommendations
            recommendations = self._generate_ba_recommendations(ba, requirement_compliance, violations)
            
            # Calculate next assessment date
            next_assessment_due = self._calculate_next_assessment_date(ba)
            
            # Create assessment
            assessment = BAAAssessment(
                assessment_id=assessment_id,
                timestamp=datetime.utcnow(),
                business_associate_id=ba.id,
                overall_compliance_score=compliance_score,
                compliance_status=compliance_status,
                requirement_compliance=requirement_compliance,
                violations=violations,
                recommendations=recommendations,
                next_assessment_due=next_assessment_due,
                assessment_notes=f"Assessment for {ba.name} - {ba.vendor_type.value}"
            )
            
            # Update business associate record
            ba.last_assessment_date = datetime.utcnow()
            ba.compliance_status = compliance_status
            ba.compliance_requirements = requirement_compliance
            
            return assessment
            
        except Exception as e:
            logger.error(f"Business associate assessment failed for {ba.id}: {e}")
            raise
    
    async def _check_baa_requirement(
        self,
        ba: BusinessAssociate,
        requirement: BAARequirement
    ) -> Tuple[bool, Optional[BAAViolation]]:
        """Check a specific BAA requirement for compliance."""
        violation = None
        
        try:
            if requirement == BAARequirement.SIGNED_BAA:
                is_compliant = ba.baa_signed_date is not None
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="critical",
                        description=f"No signed BAA on file for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=30),
                        remediation_actions=["Obtain signed BAA", "Suspend PHI access until BAA signed"]
                    )
            
            elif requirement == BAARequirement.PHI_SAFEGUARDS:
                # Check if appropriate safeguards are documented
                is_compliant = ba.phi_access_level != "full" or self._has_documented_safeguards(ba)
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="high",
                        description=f"Insufficient PHI safeguards documentation for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=60),
                        remediation_actions=["Document PHI safeguards", "Review security controls", "Conduct security assessment"]
                    )
            
            elif requirement == BAARequirement.INCIDENT_NOTIFICATION:
                # Check incident notification procedures
                is_compliant = self._has_incident_notification_procedures(ba)
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="high",
                        description=f"No incident notification procedures documented for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=45),
                        remediation_actions=["Establish incident notification procedures", "Test notification channels"]
                    )
            
            elif requirement == BAARequirement.DATA_RETURN_DESTRUCTION:
                # Check data return/destruction procedures
                is_compliant = self._has_data_return_procedures(ba)
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="medium",
                        description=f"No data return/destruction procedures for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=90),
                        remediation_actions=["Document data return procedures", "Establish secure destruction methods"]
                    )
            
            elif requirement == BAARequirement.PERMITTED_USES:
                # Check permitted uses are documented
                is_compliant = len(ba.services_provided) > 0
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="medium",
                        description=f"Permitted uses not documented for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=30),
                        remediation_actions=["Document permitted uses", "Update BAA with specific uses"]
                    )
            
            elif requirement == BAARequirement.MINIMUM_NECESSARY:
                # Check minimum necessary principle compliance
                is_compliant = ba.phi_access_level != "full" or self._follows_minimum_necessary(ba)
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="medium",
                        description=f"Minimum necessary principle not enforced for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=60),
                        remediation_actions=["Review data access scope", "Implement data minimization", "Audit data usage"]
                    )
            
            elif requirement == BAARequirement.SAFEGUARD_REPORTING:
                # Check safeguard reporting compliance
                is_compliant = self._has_safeguard_reporting(ba)
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="low",
                        description=f"No safeguard reporting mechanism for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=120),
                        remediation_actions=["Establish reporting procedures", "Schedule regular reviews"]
                    )
            
            elif requirement == BAARequirement.SUBCONTRACTOR_AGREEMENTS:
                # Check subcontractor agreements
                is_compliant = self._has_subcontractor_agreements(ba)
                if not is_compliant:
                    violation = BAAViolation(
                        id=f"violation_{ba.id}_{requirement.value}_{datetime.utcnow().timestamp()}",
                        business_associate_id=ba.id,
                        violation_type=requirement,
                        severity="medium",
                        description=f"Subcontractor BAA agreements not verified for {ba.name}",
                        detected_date=datetime.utcnow(),
                        resolution_deadline=datetime.utcnow() + timedelta(days=90),
                        remediation_actions=["Verify subcontractor BAAs", "Obtain subcontractor compliance documentation"]
                    )
            
            else:
                is_compliant = True  # Unknown requirement, assume compliant
            
            return is_compliant, violation
            
        except Exception as e:
            logger.error(f"BAA requirement check failed for {ba.id}, {requirement.value}: {e}")
            return False, None
    
    def _has_documented_safeguards(self, ba: BusinessAssociate) -> bool:
        """Check if business associate has documented safeguards."""
        # In production, this would check actual documentation
        # For now, return based on contract details
        return "security_controls" in ba.contract_details and "encryption" in ba.contract_details
    
    def _has_incident_notification_procedures(self, ba: BusinessAssociate) -> bool:
        """Check if incident notification procedures are in place."""
        return "incident_notification" in ba.contract_details and ba.contact_email is not None
    
    def _has_data_return_procedures(self, ba: BusinessAssociate) -> bool:
        """Check if data return/destruction procedures are documented."""
        return "data_return_procedures" in ba.contract_details
    
    def _follows_minimum_necessary(self, ba: BusinessAssociate) -> bool:
        """Check if minimum necessary principle is followed."""
        # High-risk vendors with full PHI access should have documented justification
        return ba.risk_level != "critical" or "minimum_necessary_justification" in ba.contract_details
    
    def _has_safeguard_reporting(self, ba: BusinessAssociate) -> bool:
        """Check if safeguard reporting is in place."""
        return "reporting_schedule" in ba.contract_details
    
    def _has_subcontractor_agreements(self, ba: BusinessAssociate) -> bool:
        """Check if subcontractor agreements are in place."""
        return "subcontractor_compliance" in ba.contract_details or ba.vendor_type == VendorType.IT_SUPPORT
    
    def _calculate_compliance_score(self, requirement_compliance: Dict[str, bool]) -> int:
        """Calculate overall compliance score."""
        if not requirement_compliance:
            return 0
        
        # Weight requirements by importance
        requirement_weights = {
            BAARequirement.SIGNED_BAA.value: 0.25,
            BAARequirement.PHI_SAFEGUARDS.value: 0.20,
            BAARequirement.INCIDENT_NOTIFICATION.value: 0.15,
            BAARequirement.DATA_RETURN_DESTRUCTION.value: 0.10,
            BAARequirement.PERMITTED_USES.value: 0.10,
            BAARequirement.MINIMUM_NECESSARY.value: 0.10,
            BAARequirement.SAFEGUARD_REPORTING.value: 0.05,
            BAARequirement.SUBCONTRACTOR_AGREEMENTS.value: 0.05
        }
        
        weighted_score = 0
        for requirement, is_compliant in requirement_compliance.items():
            weight = requirement_weights.get(requirement, 0.1)
            if is_compliant:
                weighted_score += weight
        
        return int(weighted_score * 100)
    
    def _determine_compliance_status(self, ba: BusinessAssociate, compliance_score: int) -> BAAComplianceStatus:
        """Determine compliance status based on score and other factors."""
        # Check for expired BAA
        if ba.baa_expiration_date and ba.baa_expiration_date < datetime.utcnow():
            return BAAComplianceStatus.EXPIRED
        
        # Check if BAA is signed
        if not ba.baa_signed_date:
            return BAAComplianceStatus.NON_COMPLIANT
        
        # Check compliance score
        if compliance_score >= self.compliance_threshold:
            return BAAComplianceStatus.COMPLIANT
        elif compliance_score >= self.medium_risk_threshold:
            return BAAComplianceStatus.PENDING_REVIEW
        else:
            return BAAComplianceStatus.NON_COMPLIANT
    
    def _generate_ba_recommendations(
        self,
        ba: BusinessAssociate,
        requirement_compliance: Dict[str, bool],
        violations: List[BAAViolation]
    ) -> List[str]:
        """Generate recommendations for a business associate."""
        recommendations = []
        
        # Critical violations first
        critical_violations = [v for v in violations if v.severity == "critical"]
        if critical_violations:
            recommendations.append("URGENT: Address critical BAA violations immediately")
        
        # Specific requirement recommendations
        if not requirement_compliance.get(BAARequirement.SIGNED_BAA.value, False):
            recommendations.append("Obtain signed Business Associate Agreement")
        
        if not requirement_compliance.get(BAARequirement.PHI_SAFEGUARDS.value, False):
            recommendations.append("Document and verify PHI safeguards implementation")
        
        if not requirement_compliance.get(BAARequirement.INCIDENT_NOTIFICATION.value, False):
            recommendations.append("Establish incident notification procedures and test them")
        
        # Risk-based recommendations
        if ba.risk_level == "high" and ba.phi_access_level == "full":
            recommendations.append("Conduct enhanced due diligence for high-risk vendor with full PHI access")
        
        # Monitoring recommendations
        if ba.monitoring_frequency == "quarterly" and ba.risk_level in ["high", "critical"]:
            recommendations.append("Increase monitoring frequency for high-risk vendor")
        
        return recommendations[:5]  # Limit to top 5
    
    def _calculate_next_assessment_date(self, ba: BusinessAssociate) -> datetime:
        """Calculate when next assessment should be performed."""
        frequency_map = {
            "daily": 1,
            "weekly": 7,
            "monthly": 30,
            "quarterly": 90
        }
        
        # Adjust frequency based on risk level
        base_days = frequency_map.get(ba.monitoring_frequency, 30)
        
        if ba.risk_level == "critical":
            days = base_days // 2  # More frequent for critical risk
        elif ba.risk_level == "low":
            days = base_days * 2  # Less frequent for low risk
        else:
            days = base_days
        
        return datetime.utcnow() + timedelta(days=days)
    
    def _generate_overall_recommendations(
        self,
        assessments: List[BAAAssessment],
        violations: List[BAAViolation]
    ) -> List[str]:
        """Generate overall BAA compliance recommendations."""
        recommendations = []
        
        # Count violations by severity
        critical_count = len([v for v in violations if v.severity == "critical"])
        high_count = len([v for v in violations if v.severity == "high"])
        
        if critical_count > 0:
            recommendations.append(f"URGENT: Address {critical_count} critical BAA violations immediately")
        
        if high_count > 0:
            recommendations.append(f"Address {high_count} high-severity BAA violations within 60 days")
        
        # Compliance status recommendations
        non_compliant = len([a for a in assessments if a.compliance_status == BAAComplianceStatus.NON_COMPLIANT])
        if non_compliant > 0:
            recommendations.append(f"Bring {non_compliant} non-compliant business associates into compliance")
        
        expired = len([a for a in assessments if a.compliance_status == BAAComplianceStatus.EXPIRED])
        if expired > 0:
            recommendations.append(f"Renew {expired} expired BAA agreements")
        
        # General recommendations
        if len(assessments) > 5:
            recommendations.append("Implement automated BAA compliance monitoring")
        
        recommendations.append("Conduct regular BAA compliance training for staff")
        recommendations.append("Establish vendor risk assessment procedures")
        
        return recommendations[:8]  # Limit to top 8
    
    async def monitor_vendor_activities(self, vendor_id: str, lookback_hours: int = 24) -> Dict[str, Any]:
        """Monitor activities for a specific vendor/business associate."""
        try:
            if vendor_id not in self.business_associates:
                raise ValueError(f"Vendor {vendor_id} not found")
            
            ba = self.business_associates[vendor_id]
            
            # For this implementation, we'll analyze general system activities
            # In production, this would integrate with vendor-specific monitoring
            
            since = datetime.utcnow() - timedelta(hours=lookback_hours)
            
            # Analyze activities that might be related to this vendor
            # This is simplified - in production you'd have vendor-specific tracking
            
            monitoring_result = {
                "vendor_id": vendor_id,
                "vendor_name": ba.name,
                "monitoring_period_hours": lookback_hours,
                "compliance_status": ba.compliance_status.value,
                "risk_level": ba.risk_level,
                "phi_access_level": ba.phi_access_level,
                "monitoring_summary": {
                    "data_access_events": 0,  # Would be tracked in production
                    "security_events": 0,
                    "compliance_violations": 0,
                    "system_interactions": 0
                },
                "recommendations": [
                    "Implement vendor-specific activity tracking",
                    "Establish baseline behavior patterns",
                    "Monitor data transfer volumes"
                ]
            }
            
            await self.audit_logger.log_security_event(
                event_type="vendor_monitoring",
                severity="info",
                description=f"Vendor monitoring completed for {ba.name}",
                details=monitoring_result
            )
            
            return monitoring_result
            
        except Exception as e:
            logger.error(f"Vendor monitoring failed for {vendor_id}: {e}")
            raise
    
    async def generate_baa_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive BAA compliance report."""
        try:
            # Run comprehensive assessment
            assessment_result = await self.perform_comprehensive_baa_assessment()
            
            # Generate detailed report
            report = {
                "report_id": f"baa_report_{datetime.utcnow().timestamp()}",
                "generated_date": datetime.utcnow().isoformat(),
                "report_type": "BAA_Compliance_Report",
                "executive_summary": {
                    "total_business_associates": assessment_result["total_associates_assessed"],
                    "compliance_rate": (assessment_result["compliant_associates"] / max(assessment_result["total_associates_assessed"], 1)) * 100,
                    "critical_issues": assessment_result["critical_violations"],
                    "immediate_actions_required": len([a for a in assessment_result["high_risk_associates"]]),
                    "overall_risk_level": self._calculate_overall_baa_risk(assessment_result)
                },
                "detailed_findings": assessment_result,
                "compliance_matrix": self._generate_compliance_matrix(assessment_result["assessments"]),
                "risk_analysis": self._generate_risk_analysis(assessment_result["assessments"]),
                "action_plan": self._generate_action_plan(assessment_result["violations"]),
                "regulatory_references": {
                    "hipaa_section": "45 CFR 164.308(b)",
                    "requirements": [req.value for req in BAARequirement]
                }
            }
            
            return report
            
        except Exception as e:
            logger.error(f"BAA compliance report generation failed: {e}")
            raise
    
    def _calculate_overall_baa_risk(self, assessment_result: Dict[str, Any]) -> str:
        """Calculate overall BAA risk level."""
        total_associates = assessment_result["total_associates_assessed"]
        critical_violations = assessment_result["critical_violations"]
        high_risk_associates = len(assessment_result["high_risk_associates"])
        
        if critical_violations > 0 or high_risk_associates > total_associates * 0.3:
            return "critical"
        elif high_risk_associates > total_associates * 0.1:
            return "high"
        elif assessment_result["non_compliant_associates"] > 0:
            return "medium"
        else:
            return "low"
    
    def _generate_compliance_matrix(self, assessments: List[BAAAssessment]) -> Dict[str, Any]:
        """Generate compliance matrix showing requirement compliance across vendors."""
        matrix = {}
        
        for requirement in BAARequirement:
            req_name = requirement.value
            compliant_count = sum(1 for a in assessments if a.requirement_compliance.get(req_name, False))
            matrix[req_name] = {
                "total_assessed": len(assessments),
                "compliant": compliant_count,
                "non_compliant": len(assessments) - compliant_count,
                "compliance_rate": (compliant_count / max(len(assessments), 1)) * 100
            }
        
        return matrix
    
    def _generate_risk_analysis(self, assessments: List[BAAAssessment]) -> Dict[str, Any]:
        """Generate risk analysis from assessments."""
        risk_analysis = {
            "risk_distribution": {
                "critical": len([a for a in assessments if a.overall_compliance_score < 50]),
                "high": len([a for a in assessments if 50 <= a.overall_compliance_score < 70]),
                "medium": len([a for a in assessments if 70 <= a.overall_compliance_score < 90]),
                "low": len([a for a in assessments if a.overall_compliance_score >= 90])
            },
            "average_compliance_score": sum(a.overall_compliance_score for a in assessments) / max(len(assessments), 1),
            "trends": "stable",  # Would calculate from historical data
            "top_risk_factors": [
                "Unsigned BAA agreements",
                "Insufficient PHI safeguards documentation",
                "Missing incident notification procedures"
            ]
        }
        
        return risk_analysis
    
    def _generate_action_plan(self, violations: List[BAAViolation]) -> Dict[str, Any]:
        """Generate prioritized action plan for violations."""
        # Sort violations by severity and deadline
        sorted_violations = sorted(
            violations,
            key=lambda v: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[v.severity],
                v.resolution_deadline
            )
        )
        
        action_plan = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": []
        }
        
        now = datetime.utcnow()
        
        for violation in sorted_violations:
            days_to_deadline = (violation.resolution_deadline - now).days
            
            action_item = {
                "violation_id": violation.id,
                "business_associate": violation.business_associate_id,
                "requirement": violation.violation_type.value,
                "severity": violation.severity,
                "deadline": violation.resolution_deadline.isoformat(),
                "actions": violation.remediation_actions
            }
            
            if days_to_deadline <= 7 or violation.severity == "critical":
                action_plan["immediate_actions"].append(action_item)
            elif days_to_deadline <= 30:
                action_plan["short_term_actions"].append(action_item)
            else:
                action_plan["long_term_actions"].append(action_item)
        
        return action_plan
    
    async def _log_baa_assessment(self, assessment_summary: Dict[str, Any]):
        """Log BAA assessment for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="baa_compliance_assessment",
                severity="warning" if assessment_summary["critical_violations"] > 0 else "info",
                description=f"BAA compliance assessment completed. {assessment_summary['compliant_associates']}/{assessment_summary['total_associates_assessed']} associates compliant",
                details={
                    "total_associates": assessment_summary["total_associates_assessed"],
                    "compliant_count": assessment_summary["compliant_associates"],
                    "critical_violations": assessment_summary["critical_violations"],
                    "compliance_rate": (assessment_summary["compliant_associates"] / max(assessment_summary["total_associates_assessed"], 1)) * 100
                }
            )
        except Exception as e:
            logger.error(f"Failed to log BAA assessment: {e}")


async def run_baa_compliance_check(
    db: Session,
    business_associate_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level function to run BAA compliance check.
    
    Args:
        db: Database session
        business_associate_id: Specific associate to check (optional)
        
    Returns:
        BAA compliance check results
    """
    monitor = BAAComplianceMonitor(db)
    return await monitor.perform_comprehensive_baa_assessment(business_associate_id) 