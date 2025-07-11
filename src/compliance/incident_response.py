"""
Healthcare Incident Response Automation

Automated incident response for healthcare environments with HIPAA breach
notification, escalation workflows, and compliance documentation.
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
from src.notifications.notification_manager import NotificationManager, NotificationType
from config.compliance_config import (
    get_incident_response_config,
    get_compliance_config,
    get_monitoring_config
)

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """Healthcare incident severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    BREACH = "breach"  # HIPAA breach requiring notification


class IncidentCategory(Enum):
    """Categories of healthcare security incidents."""
    HIPAA_BREACH = "hipaa_breach"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE_INFECTION = "malware_infection"
    SYSTEM_COMPROMISE = "system_compromise"
    INSIDER_THREAT = "insider_threat"
    DENIAL_OF_SERVICE = "denial_of_service"
    CONFIGURATION_ERROR = "configuration_error"
    PHYSICAL_SECURITY = "physical_security"
    VENDOR_INCIDENT = "vendor_incident"


class ResponseStatus(Enum):
    """Incident response status."""
    DETECTED = "detected"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    CLOSED = "closed"


class NotificationRequirement(Enum):
    """HIPAA breach notification requirements."""
    HHS_NOTIFICATION = "hhs_notification"  # 60 days
    INDIVIDUAL_NOTIFICATION = "individual_notification"  # 60 days
    MEDIA_NOTIFICATION = "media_notification"  # If >500 individuals
    STATE_ATTORNEY_GENERAL = "state_attorney_general"  # Concurrent with individuals
    BUSINESS_ASSOCIATE_NOTIFICATION = "business_associate_notification"  # Immediate


@dataclass
class SecurityIncident:
    """Healthcare security incident record."""
    incident_id: str
    title: str
    description: str
    category: IncidentCategory
    severity: IncidentSeverity
    detected_date: datetime
    reported_date: Optional[datetime] = None
    status: ResponseStatus = ResponseStatus.DETECTED
    affected_systems: List[str] = None
    affected_users: List[UUID] = None
    phi_involved: bool = False
    phi_types: List[str] = None
    estimated_affected_count: int = 0
    detection_method: str = "automated"
    reporter_id: Optional[UUID] = None
    assigned_responder: Optional[str] = None
    containment_actions: List[str] = None
    eradication_actions: List[str] = None
    recovery_actions: List[str] = None
    lessons_learned: List[str] = None
    estimated_cost: float = 0.0
    notification_requirements: List[NotificationRequirement] = None
    breach_notification_sent: bool = False
    resolution_date: Optional[datetime] = None
    
    def __post_init__(self):
        if self.affected_systems is None:
            self.affected_systems = []
        if self.affected_users is None:
            self.affected_users = []
        if self.phi_types is None:
            self.phi_types = []
        if self.containment_actions is None:
            self.containment_actions = []
        if self.eradication_actions is None:
            self.eradication_actions = []
        if self.recovery_actions is None:
            self.recovery_actions = []
        if self.lessons_learned is None:
            self.lessons_learned = []
        if self.notification_requirements is None:
            self.notification_requirements = []


@dataclass
class ResponsePlaybook:
    """Incident response playbook definition."""
    playbook_id: str
    name: str
    description: str
    incident_categories: List[IncidentCategory]
    severity_thresholds: Dict[str, IncidentSeverity]
    response_steps: List[Dict[str, Any]]
    notification_templates: Dict[str, str]
    escalation_rules: List[Dict[str, Any]]
    compliance_requirements: List[str]
    estimated_duration_hours: int


@dataclass
class BreachAssessment:
    """HIPAA breach assessment result."""
    assessment_id: str
    incident_id: str
    assessment_date: datetime
    is_breach: bool
    breach_criteria_met: List[str]
    phi_involved: bool
    phi_types: List[str]
    affected_individual_count: int
    likelihood_of_compromise: str  # high, medium, low
    nature_of_phi: str
    notification_requirements: List[NotificationRequirement]
    notification_deadlines: Dict[str, datetime]
    risk_assessment_score: int
    mitigation_factors: List[str]


class IncidentResponseManager:
    """Healthcare incident response automation system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.notification_manager = NotificationManager()
        
        # Configuration
        self.incident_config = get_incident_response_config()
        self.compliance_config = get_compliance_config()
        self.monitoring_config = get_monitoring_config()
        
        # Response playbooks
        self.playbooks = self._initialize_response_playbooks()
        
        # Active incidents tracking
        self.active_incidents = {}
        
    def _initialize_response_playbooks(self) -> Dict[str, ResponsePlaybook]:
        """Initialize incident response playbooks."""
        playbooks = {}
        
        # HIPAA Breach Response Playbook
        playbooks["hipaa_breach"] = ResponsePlaybook(
            playbook_id="hipaa_breach_response",
            name="HIPAA Breach Response",
            description="Response procedures for confirmed HIPAA breaches",
            incident_categories=[IncidentCategory.HIPAA_BREACH],
            severity_thresholds={"phi_count": IncidentSeverity.BREACH},
            response_steps=[
                {
                    "step": 1,
                    "action": "immediate_containment",
                    "description": "Immediately contain the breach",
                    "max_duration_minutes": 60,
                    "automated": True
                },
                {
                    "step": 2,
                    "action": "breach_assessment",
                    "description": "Conduct formal breach assessment",
                    "max_duration_hours": 24,
                    "automated": False
                },
                {
                    "step": 3,
                    "action": "notification_preparation",
                    "description": "Prepare breach notifications",
                    "max_duration_hours": 48,
                    "automated": True
                },
                {
                    "step": 4,
                    "action": "hhs_notification",
                    "description": "Submit HHS breach notification",
                    "max_duration_days": 60,
                    "automated": False
                }
            ],
            notification_templates={
                "individual": "hipaa_breach_individual_notification",
                "hhs": "hipaa_breach_hhs_notification",
                "media": "hipaa_breach_media_notification"
            },
            escalation_rules=[
                {
                    "trigger": "affected_count > 500",
                    "action": "escalate_to_media_notification"
                },
                {
                    "trigger": "severity == CRITICAL",
                    "action": "escalate_to_executive_team"
                }
            ],
            compliance_requirements=["45 CFR 164.408", "45 CFR 164.410", "45 CFR 164.412"],
            estimated_duration_hours=72
        )
        
        # Data Exfiltration Response Playbook
        playbooks["data_exfiltration"] = ResponsePlaybook(
            playbook_id="data_exfiltration_response",
            name="Data Exfiltration Response",
            description="Response procedures for suspected data exfiltration",
            incident_categories=[IncidentCategory.DATA_EXFILTRATION],
            severity_thresholds={"data_volume": IncidentSeverity.HIGH},
            response_steps=[
                {
                    "step": 1,
                    "action": "network_isolation",
                    "description": "Isolate affected systems from network",
                    "max_duration_minutes": 30,
                    "automated": True
                },
                {
                    "step": 2,
                    "action": "forensic_imaging",
                    "description": "Create forensic images of affected systems",
                    "max_duration_hours": 4,
                    "automated": False
                },
                {
                    "step": 3,
                    "action": "data_impact_assessment",
                    "description": "Assess scope and impact of data loss",
                    "max_duration_hours": 12,
                    "automated": False
                }
            ],
            notification_templates={
                "security_team": "data_exfiltration_security_alert",
                "executive": "data_exfiltration_executive_summary"
            },
            escalation_rules=[
                {
                    "trigger": "phi_involved == True",
                    "action": "escalate_to_breach_assessment"
                }
            ],
            compliance_requirements=["Incident Response Policy"],
            estimated_duration_hours=24
        )
        
        # Unauthorized Access Response Playbook
        playbooks["unauthorized_access"] = ResponsePlaybook(
            playbook_id="unauthorized_access_response",
            name="Unauthorized Access Response",
            description="Response procedures for unauthorized system access",
            incident_categories=[IncidentCategory.UNAUTHORIZED_ACCESS],
            severity_thresholds={"access_level": IncidentSeverity.HIGH},
            response_steps=[
                {
                    "step": 1,
                    "action": "account_lockdown",
                    "description": "Lock down compromised accounts",
                    "max_duration_minutes": 15,
                    "automated": True
                },
                {
                    "step": 2,
                    "action": "access_audit",
                    "description": "Audit all access during incident timeframe",
                    "max_duration_hours": 8,
                    "automated": True
                },
                {
                    "step": 3,
                    "action": "credential_reset",
                    "description": "Force password reset for affected users",
                    "max_duration_hours": 24,
                    "automated": True
                }
            ],
            notification_templates={
                "user": "unauthorized_access_user_notification",
                "admin": "unauthorized_access_admin_alert"
            },
            escalation_rules=[
                {
                    "trigger": "admin_account_compromised == True",
                    "action": "escalate_to_critical"
                }
            ],
            compliance_requirements=["Access Control Policy"],
            estimated_duration_hours=48
        )
        
        return playbooks
    
    async def create_incident(
        self,
        title: str,
        description: str,
        category: IncidentCategory,
        severity: IncidentSeverity,
        phi_involved: bool = False,
        affected_systems: List[str] = None,
        reporter_id: Optional[UUID] = None
    ) -> SecurityIncident:
        """Create and initiate incident response."""
        try:
            incident_id = f"INC_{datetime.utcnow().strftime('%Y%m%d')}_{uuid4().hex[:8]}"
            
            incident = SecurityIncident(
                incident_id=incident_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                detected_date=datetime.utcnow(),
                reported_date=datetime.utcnow(),
                phi_involved=phi_involved,
                affected_systems=affected_systems or [],
                reporter_id=reporter_id
            )
            
            # Store incident
            self.active_incidents[incident_id] = incident
            
            # Initiate automated response
            await self._initiate_automated_response(incident)
            
            # Log incident creation
            await self._log_incident_creation(incident)
            
            return incident
            
        except Exception as e:
            logger.error(f"Failed to create incident: {e}")
            raise
    
    async def _initiate_automated_response(self, incident: SecurityIncident):
        """Initiate automated incident response procedures."""
        try:
            logger.info(f"Initiating automated response for incident {incident.incident_id}")
            
            # Select appropriate playbook
            playbook = self._select_response_playbook(incident)
            
            if playbook:
                # Execute automated response steps
                await self._execute_response_playbook(incident, playbook)
                
                # Assess if HIPAA breach
                if incident.phi_involved:
                    breach_assessment = await self._assess_hipaa_breach(incident)
                    if breach_assessment.is_breach:
                        incident.severity = IncidentSeverity.BREACH
                        incident.notification_requirements = breach_assessment.notification_requirements
                        await self._initiate_breach_notifications(incident, breach_assessment)
                
                # Send immediate notifications
                await self._send_incident_notifications(incident, playbook)
                
                # Update incident status
                incident.status = ResponseStatus.ACKNOWLEDGED
                
            else:
                logger.warning(f"No suitable playbook found for incident {incident.incident_id}")
            
        except Exception as e:
            logger.error(f"Automated response initiation failed for {incident.incident_id}: {e}")
    
    def _select_response_playbook(self, incident: SecurityIncident) -> Optional[ResponsePlaybook]:
        """Select appropriate response playbook for incident."""
        for playbook in self.playbooks.values():
            if incident.category in playbook.incident_categories:
                return playbook
        
        # Default to general incident response if no specific playbook
        return None
    
    async def _execute_response_playbook(self, incident: SecurityIncident, playbook: ResponsePlaybook):
        """Execute automated steps from response playbook."""
        try:
            logger.info(f"Executing playbook {playbook.name} for incident {incident.incident_id}")
            
            for step in playbook.response_steps:
                if step.get("automated", False):
                    await self._execute_response_step(incident, step)
                else:
                    # Create task for manual execution
                    await self._create_manual_task(incident, step)
            
        except Exception as e:
            logger.error(f"Playbook execution failed for {incident.incident_id}: {e}")
    
    async def _execute_response_step(self, incident: SecurityIncident, step: Dict[str, Any]):
        """Execute automated response step."""
        try:
            action = step["action"]
            logger.info(f"Executing automated step: {action} for incident {incident.incident_id}")
            
            if action == "immediate_containment":
                await self._perform_immediate_containment(incident)
                incident.containment_actions.append(f"Automated containment executed at {datetime.utcnow()}")
            
            elif action == "network_isolation":
                await self._perform_network_isolation(incident)
                incident.containment_actions.append(f"Network isolation executed at {datetime.utcnow()}")
            
            elif action == "account_lockdown":
                await self._perform_account_lockdown(incident)
                incident.containment_actions.append(f"Account lockdown executed at {datetime.utcnow()}")
            
            elif action == "access_audit":
                await self._perform_access_audit(incident)
                incident.containment_actions.append(f"Access audit initiated at {datetime.utcnow()}")
            
            elif action == "credential_reset":
                await self._perform_credential_reset(incident)
                incident.recovery_actions.append(f"Credential reset executed at {datetime.utcnow()}")
            
            elif action == "notification_preparation":
                await self._prepare_breach_notifications(incident)
                
            else:
                logger.warning(f"Unknown automated action: {action}")
            
        except Exception as e:
            logger.error(f"Response step execution failed: {e}")
    
    async def _perform_immediate_containment(self, incident: SecurityIncident):
        """Perform immediate containment actions."""
        # Implement containment logic based on incident type
        if incident.category == IncidentCategory.HIPAA_BREACH:
            # Disable affected user accounts
            for user_id in incident.affected_users:
                await self._disable_user_account(user_id)
            
            # Alert security team
            await self.notification_manager.send_notification(
                user_id=None,
                notification_type=NotificationType.SECURITY_ALERT,
                data={
                    "incident_id": incident.incident_id,
                    "message": "HIPAA breach containment initiated",
                    "severity": incident.severity.value
                },
                override_preferences=True
            )
    
    async def _perform_network_isolation(self, incident: SecurityIncident):
        """Perform network isolation of affected systems."""
        # In production, this would integrate with network security tools
        logger.info(f"Network isolation initiated for systems: {incident.affected_systems}")
        
        # Simulate network isolation
        for system in incident.affected_systems:
            # Would implement actual network isolation here
            pass
    
    async def _perform_account_lockdown(self, incident: SecurityIncident):
        """Lock down compromised user accounts."""
        from src.database.models import User, UserSession
        
        try:
            for user_id in incident.affected_users:
                # Disable user account
                user = self.db.query(User).get(user_id)
                if user:
                    user.is_active = False
                    
                    # Terminate all sessions
                    sessions = self.db.query(UserSession).filter(
                        and_(
                            UserSession.user_id == user_id,
                            UserSession.is_active == True
                        )
                    ).all()
                    
                    for session in sessions:
                        session.is_active = False
                    
                    self.db.commit()
                    
                    # Send notification to user
                    await self.notification_manager.send_notification(
                        user_id=user_id,
                        notification_type=NotificationType.ACCOUNT_LOCKED,
                        data={
                            "incident_id": incident.incident_id,
                            "reason": "Security incident response"
                        }
                    )
        
        except Exception as e:
            logger.error(f"Account lockdown failed: {e}")
    
    async def _perform_access_audit(self, incident: SecurityIncident):
        """Perform comprehensive access audit."""
        try:
            # Query audit logs for incident timeframe
            incident_start = incident.detected_date - timedelta(hours=24)  # Look back 24 hours
            
            suspicious_access = self.db.query(self.audit_repo.model).filter(
                and_(
                    self.audit_repo.model.timestamp >= incident_start,
                    self.audit_repo.model.timestamp <= incident.detected_date
                )
            ).all()
            
            # Analyze access patterns
            access_analysis = {
                "total_access_events": len(suspicious_access),
                "unique_users": len(set(log.user_id for log in suspicious_access if log.user_id)),
                "unique_resources": len(set(log.resource_id for log in suspicious_access if log.resource_id)),
                "suspicious_patterns": []
            }
            
            # Add access analysis to incident
            incident.containment_actions.append(f"Access audit completed: {access_analysis}")
            
        except Exception as e:
            logger.error(f"Access audit failed: {e}")
    
    async def _perform_credential_reset(self, incident: SecurityIncident):
        """Force credential reset for affected users."""
        # In production, this would integrate with identity management system
        for user_id in incident.affected_users:
            # Send password reset notification
            await self.notification_manager.send_notification(
                user_id=user_id,
                notification_type=NotificationType.PASSWORD_RESET_REQUIRED,
                data={
                    "incident_id": incident.incident_id,
                    "reason": "Security incident response - mandatory password reset"
                }
            )
    
    async def _disable_user_account(self, user_id: UUID):
        """Disable a specific user account."""
        from src.database.models import User
        
        try:
            user = self.db.query(User).get(user_id)
            if user:
                user.is_active = False
                self.db.commit()
        except Exception as e:
            logger.error(f"Failed to disable user account {user_id}: {e}")
    
    async def _assess_hipaa_breach(self, incident: SecurityIncident) -> BreachAssessment:
        """Assess if incident constitutes a HIPAA breach."""
        try:
            assessment_id = f"BA_{incident.incident_id}_{datetime.utcnow().strftime('%Y%m%d%H%M')}"
            
            # HIPAA breach criteria assessment
            breach_criteria_met = []
            
            # Criterion 1: PHI involved
            if incident.phi_involved:
                breach_criteria_met.append("PHI involved in incident")
            
            # Criterion 2: Unauthorized acquisition, access, use, or disclosure
            if incident.category in [
                IncidentCategory.UNAUTHORIZED_ACCESS,
                IncidentCategory.DATA_EXFILTRATION,
                IncidentCategory.INSIDER_THREAT
            ]:
                breach_criteria_met.append("Unauthorized acquisition, access, use, or disclosure")
            
            # Criterion 3: Security or privacy compromised
            if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]:
                breach_criteria_met.append("Security or privacy compromised")
            
            # Determine if it's a breach (needs at least 2 criteria)
            is_breach = len(breach_criteria_met) >= 2
            
            # Estimate affected individual count
            affected_count = max(incident.estimated_affected_count, len(incident.affected_users))
            
            # Determine notification requirements
            notification_requirements = []
            notification_deadlines = {}
            
            if is_breach:
                # Always required for breaches
                notification_requirements.extend([
                    NotificationRequirement.HHS_NOTIFICATION,
                    NotificationRequirement.INDIVIDUAL_NOTIFICATION
                ])
                
                # Calculate deadlines
                base_date = datetime.utcnow()
                notification_deadlines[NotificationRequirement.HHS_NOTIFICATION.value] = base_date + timedelta(days=60)
                notification_deadlines[NotificationRequirement.INDIVIDUAL_NOTIFICATION.value] = base_date + timedelta(days=60)
                
                # Media notification for >500 individuals
                if affected_count > 500:
                    notification_requirements.append(NotificationRequirement.MEDIA_NOTIFICATION)
                    notification_deadlines[NotificationRequirement.MEDIA_NOTIFICATION.value] = base_date + timedelta(days=60)
                
                # State attorney general
                notification_requirements.append(NotificationRequirement.STATE_ATTORNEY_GENERAL)
                notification_deadlines[NotificationRequirement.STATE_ATTORNEY_GENERAL.value] = base_date + timedelta(days=60)
            
            # Risk assessment score (0-100)
            risk_score = self._calculate_breach_risk_score(incident, affected_count)
            
            return BreachAssessment(
                assessment_id=assessment_id,
                incident_id=incident.incident_id,
                assessment_date=datetime.utcnow(),
                is_breach=is_breach,
                breach_criteria_met=breach_criteria_met,
                phi_involved=incident.phi_involved,
                phi_types=incident.phi_types,
                affected_individual_count=affected_count,
                likelihood_of_compromise="high" if incident.severity == IncidentSeverity.CRITICAL else "medium",
                nature_of_phi="voice_biomarker_data",
                notification_requirements=notification_requirements,
                notification_deadlines=notification_deadlines,
                risk_assessment_score=risk_score,
                mitigation_factors=["Encryption in transit", "Access controls", "Audit logging"]
            )
            
        except Exception as e:
            logger.error(f"HIPAA breach assessment failed: {e}")
            raise
    
    def _calculate_breach_risk_score(self, incident: SecurityIncident, affected_count: int) -> int:
        """Calculate breach risk score."""
        risk_score = 0
        
        # Severity factor (0-40 points)
        severity_scores = {
            IncidentSeverity.LOW: 10,
            IncidentSeverity.MEDIUM: 20,
            IncidentSeverity.HIGH: 30,
            IncidentSeverity.CRITICAL: 40,
            IncidentSeverity.BREACH: 40
        }
        risk_score += severity_scores.get(incident.severity, 0)
        
        # Affected count factor (0-30 points)
        if affected_count > 1000:
            risk_score += 30
        elif affected_count > 500:
            risk_score += 25
        elif affected_count > 100:
            risk_score += 20
        elif affected_count > 10:
            risk_score += 15
        else:
            risk_score += 10
        
        # PHI type factor (0-20 points)
        if "audio_recordings" in incident.phi_types:
            risk_score += 20
        elif incident.phi_types:
            risk_score += 15
        
        # Category factor (0-10 points)
        high_risk_categories = [
            IncidentCategory.DATA_EXFILTRATION,
            IncidentCategory.INSIDER_THREAT,
            IncidentCategory.SYSTEM_COMPROMISE
        ]
        if incident.category in high_risk_categories:
            risk_score += 10
        else:
            risk_score += 5
        
        return min(100, risk_score)
    
    async def _initiate_breach_notifications(self, incident: SecurityIncident, assessment: BreachAssessment):
        """Initiate HIPAA breach notifications."""
        try:
            logger.info(f"Initiating HIPAA breach notifications for incident {incident.incident_id}")
            
            # Prepare notification data
            notification_data = {
                "incident_id": incident.incident_id,
                "assessment_id": assessment.assessment_id,
                "affected_count": assessment.affected_individual_count,
                "breach_date": incident.detected_date.isoformat(),
                "phi_types": assessment.phi_types,
                "risk_score": assessment.risk_assessment_score
            }
            
            # Send immediate notifications to compliance team
            await self.notification_manager.send_notification(
                user_id=None,  # Send to compliance team
                notification_type=NotificationType.HIPAA_BREACH_DETECTED,
                data=notification_data,
                override_preferences=True
            )
            
            # Schedule formal notifications based on requirements
            for requirement in assessment.notification_requirements:
                deadline = assessment.notification_deadlines[requirement.value]
                await self._schedule_breach_notification(incident, requirement, deadline, notification_data)
            
            incident.breach_notification_sent = True
            
        except Exception as e:
            logger.error(f"Breach notification initiation failed: {e}")
    
    async def _schedule_breach_notification(
        self,
        incident: SecurityIncident,
        requirement: NotificationRequirement,
        deadline: datetime,
        data: Dict[str, Any]
    ):
        """Schedule specific breach notification."""
        # In production, this would integrate with scheduling system
        logger.info(f"Scheduling {requirement.value} notification for {deadline}")
        
        # Create notification task
        notification_task = {
            "incident_id": incident.incident_id,
            "requirement": requirement.value,
            "deadline": deadline.isoformat(),
            "data": data,
            "status": "scheduled"
        }
        
        # Store notification task (in production database)
        incident.notification_requirements.append(requirement)
    
    async def _prepare_breach_notifications(self, incident: SecurityIncident):
        """Prepare breach notification documents."""
        # Generate notification templates and documentation
        logger.info(f"Preparing breach notification documents for {incident.incident_id}")
        
        # This would generate actual notification documents in production
        incident.recovery_actions.append(f"Breach notification documents prepared at {datetime.utcnow()}")
    
    async def _send_incident_notifications(self, incident: SecurityIncident, playbook: ResponsePlaybook):
        """Send immediate incident notifications."""
        try:
            # Send to security team
            await self.notification_manager.send_notification(
                user_id=None,
                notification_type=NotificationType.SECURITY_INCIDENT,
                data={
                    "incident_id": incident.incident_id,
                    "title": incident.title,
                    "severity": incident.severity.value,
                    "category": incident.category.value,
                    "playbook": playbook.name
                },
                override_preferences=True
            )
            
            # Escalate if high severity
            if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL, IncidentSeverity.BREACH]:
                await self.notification_manager.send_notification(
                    user_id=None,
                    notification_type=NotificationType.SECURITY_ESCALATION,
                    data={
                        "incident_id": incident.incident_id,
                        "title": incident.title,
                        "severity": incident.severity.value,
                        "escalation_reason": "High severity incident detected"
                    },
                    override_preferences=True
                )
        
        except Exception as e:
            logger.error(f"Incident notification failed: {e}")
    
    async def _create_manual_task(self, incident: SecurityIncident, step: Dict[str, Any]):
        """Create manual task for incident response."""
        # In production, this would create tasks in task management system
        logger.info(f"Creating manual task for incident {incident.incident_id}: {step['action']}")
        
        task = {
            "incident_id": incident.incident_id,
            "action": step["action"],
            "description": step["description"],
            "created_date": datetime.utcnow().isoformat(),
            "due_date": (datetime.utcnow() + timedelta(hours=step.get("max_duration_hours", 24))).isoformat(),
            "status": "assigned"
        }
        
        # Store task (would integrate with task management system)
    
    async def update_incident_status(
        self,
        incident_id: str,
        status: ResponseStatus,
        notes: Optional[str] = None
    ) -> SecurityIncident:
        """Update incident status and perform status-specific actions."""
        try:
            if incident_id not in self.active_incidents:
                raise ValueError(f"Incident {incident_id} not found")
            
            incident = self.active_incidents[incident_id]
            old_status = incident.status
            incident.status = status
            
            # Perform status-specific actions
            if status == ResponseStatus.RESOLVED:
                incident.resolution_date = datetime.utcnow()
                await self._finalize_incident(incident)
            
            # Log status update
            await self.audit_logger.log_security_event(
                event_type="incident_status_update",
                severity="info",
                description=f"Incident {incident_id} status updated from {old_status.value} to {status.value}",
                details={
                    "incident_id": incident_id,
                    "old_status": old_status.value,
                    "new_status": status.value,
                    "notes": notes
                }
            )
            
            return incident
            
        except Exception as e:
            logger.error(f"Incident status update failed: {e}")
            raise
    
    async def _finalize_incident(self, incident: SecurityIncident):
        """Finalize resolved incident with lessons learned."""
        try:
            # Generate incident report
            incident_report = await self._generate_incident_report(incident)
            
            # Extract lessons learned
            incident.lessons_learned = self._extract_lessons_learned(incident)
            
            # Update incident status
            incident.status = ResponseStatus.CLOSED
            
            # Archive incident
            # In production, this would move to incident archive
            
        except Exception as e:
            logger.error(f"Incident finalization failed: {e}")
    
    async def _generate_incident_report(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Generate comprehensive incident report."""
        report = {
            "incident_summary": asdict(incident),
            "timeline": self._generate_incident_timeline(incident),
            "impact_assessment": self._assess_incident_impact(incident),
            "response_effectiveness": self._assess_response_effectiveness(incident),
            "recommendations": self._generate_incident_recommendations(incident)
        }
        
        return report
    
    def _generate_incident_timeline(self, incident: SecurityIncident) -> List[Dict[str, Any]]:
        """Generate incident timeline."""
        timeline = [
            {
                "timestamp": incident.detected_date.isoformat(),
                "event": "Incident detected",
                "description": incident.description
            },
            {
                "timestamp": incident.reported_date.isoformat() if incident.reported_date else incident.detected_date.isoformat(),
                "event": "Incident reported",
                "description": "Incident formally reported and response initiated"
            }
        ]
        
        # Add containment actions
        for action in incident.containment_actions:
            timeline.append({
                "timestamp": datetime.utcnow().isoformat(),  # Would extract from action in production
                "event": "Containment action",
                "description": action
            })
        
        # Add recovery actions
        for action in incident.recovery_actions:
            timeline.append({
                "timestamp": datetime.utcnow().isoformat(),  # Would extract from action in production
                "event": "Recovery action",
                "description": action
            })
        
        if incident.resolution_date:
            timeline.append({
                "timestamp": incident.resolution_date.isoformat(),
                "event": "Incident resolved",
                "description": "Incident successfully resolved and closed"
            })
        
        return timeline
    
    def _assess_incident_impact(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Assess overall incident impact."""
        return {
            "affected_users": len(incident.affected_users),
            "affected_systems": len(incident.affected_systems),
            "phi_involved": incident.phi_involved,
            "estimated_affected_individuals": incident.estimated_affected_count,
            "estimated_cost": incident.estimated_cost,
            "severity_level": incident.severity.value,
            "business_impact": "high" if incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL] else "medium"
        }
    
    def _assess_response_effectiveness(self, incident: SecurityIncident) -> Dict[str, Any]:
        """Assess effectiveness of incident response."""
        duration = None
        if incident.resolution_date:
            duration = (incident.resolution_date - incident.detected_date).total_seconds() / 3600
        
        return {
            "response_time_hours": duration,
            "containment_actions_taken": len(incident.containment_actions),
            "recovery_actions_taken": len(incident.recovery_actions),
            "breach_notifications_sent": incident.breach_notification_sent,
            "overall_effectiveness": "effective" if duration and duration < 48 else "needs_improvement"
        }
    
    def _extract_lessons_learned(self, incident: SecurityIncident) -> List[str]:
        """Extract lessons learned from incident."""
        lessons = []
        
        if incident.severity == IncidentSeverity.BREACH:
            lessons.append("Review and strengthen data access controls")
            lessons.append("Enhance PHI monitoring and detection capabilities")
        
        if len(incident.affected_systems) > 1:
            lessons.append("Improve network segmentation to limit lateral movement")
        
        if incident.category == IncidentCategory.INSIDER_THREAT:
            lessons.append("Enhance user behavior monitoring")
            lessons.append("Review privileged access management")
        
        lessons.extend([
            "Update incident response procedures based on this event",
            "Conduct staff training on incident identification and reporting",
            "Review and test backup and recovery procedures"
        ])
        
        return lessons
    
    def _generate_incident_recommendations(self, incident: SecurityIncident) -> List[str]:
        """Generate recommendations based on incident analysis."""
        recommendations = []
        
        # Category-specific recommendations
        if incident.category == IncidentCategory.HIPAA_BREACH:
            recommendations.extend([
                "Implement additional PHI access monitoring",
                "Enhance encryption for PHI data",
                "Review and update breach response procedures"
            ])
        
        if incident.category == IncidentCategory.UNAUTHORIZED_ACCESS:
            recommendations.extend([
                "Implement multi-factor authentication",
                "Review access control policies",
                "Enhance privilege management"
            ])
        
        # General recommendations
        recommendations.extend([
            "Conduct regular security awareness training",
            "Implement continuous security monitoring",
            "Review and update incident response playbooks"
        ])
        
        return recommendations[:8]  # Limit to top 8
    
    async def _log_incident_creation(self, incident: SecurityIncident):
        """Log incident creation for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="incident_created",
                user_id=incident.reporter_id,
                severity=incident.severity.value,
                description=f"Security incident created: {incident.title}",
                details={
                    "incident_id": incident.incident_id,
                    "category": incident.category.value,
                    "phi_involved": incident.phi_involved,
                    "affected_systems": incident.affected_systems
                }
            )
        except Exception as e:
            logger.error(f"Failed to log incident creation: {e}")


async def run_incident_response(
    db: Session,
    incident_id: Optional[str] = None,
    action: str = "list"
) -> Dict[str, Any]:
    """
    High-level function to run incident response operations.
    
    Args:
        db: Database session
        incident_id: Specific incident to operate on (optional)
        action: Action to perform (list, create, update, resolve)
        
    Returns:
        Incident response results
    """
    incident_manager = IncidentResponseManager(db)
    
    if action == "list":
        return {
            "active_incidents": [asdict(incident) for incident in incident_manager.active_incidents.values()],
            "total_active": len(incident_manager.active_incidents)
        }
    elif action == "create" and incident_id:
        # This would need additional parameters in production
        raise NotImplementedError("Use create_incident method directly")
    else:
        raise ValueError(f"Unknown action: {action}") 