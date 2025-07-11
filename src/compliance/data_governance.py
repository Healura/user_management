"""
Healthcare Data Governance Automation

Automated data governance for healthcare systems with PHI classification,
consent management, data lineage tracking, and policy enforcement.
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

from src.database.models import User, AudioFile, AuditLog
from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from src.notifications.notification_manager import NotificationManager, NotificationType
from config.compliance_config import (
    get_data_governance_config,
    get_compliance_config
)

logger = logging.getLogger(__name__)


class DataClassification(Enum):
    """Data classification levels for healthcare data."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PHI = "phi"
    SENSITIVE_PHI = "sensitive_phi"
    RESEARCH_DATA = "research_data"
    DE_IDENTIFIED = "de_identified"


class ConsentType(Enum):
    """Types of data processing consent."""
    TREATMENT = "treatment"
    RESEARCH = "research"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    QUALITY_IMPROVEMENT = "quality_improvement"
    CARE_COORDINATION = "care_coordination"
    EMERGENCY_CARE = "emergency_care"


class ConsentStatus(Enum):
    """Status of user consent."""
    ACTIVE = "active"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"
    PENDING = "pending"
    DECLINED = "declined"


class DataRetentionReason(Enum):
    """Reasons for data retention beyond standard period."""
    LEGAL_HOLD = "legal_hold"
    ONGOING_TREATMENT = "ongoing_treatment"
    RESEARCH_PARTICIPATION = "research_participation"
    REGULATORY_REQUIREMENT = "regulatory_requirement"
    PATIENT_REQUEST = "patient_request"


@dataclass
class DataAsset:
    """Represents a data asset in the system."""
    asset_id: str
    asset_type: str  # audio_file, user_profile, analysis_result, etc.
    classification: DataClassification
    owner_id: Optional[UUID] = None
    created_date: datetime = None
    last_accessed: datetime = None
    phi_elements: List[str] = None
    consent_required: bool = True
    retention_period_years: int = 7
    scheduled_deletion_date: Optional[datetime] = None
    data_lineage: List[str] = None
    processing_purposes: List[ConsentType] = None
    geographic_restrictions: List[str] = None
    
    def __post_init__(self):
        if self.created_date is None:
            self.created_date = datetime.utcnow()
        if self.phi_elements is None:
            self.phi_elements = []
        if self.data_lineage is None:
            self.data_lineage = []
        if self.processing_purposes is None:
            self.processing_purposes = []
        if self.geographic_restrictions is None:
            self.geographic_restrictions = []


@dataclass
class ConsentRecord:
    """User consent record for data processing."""
    consent_id: str
    user_id: UUID
    consent_type: ConsentType
    status: ConsentStatus
    granted_date: datetime
    expiration_date: Optional[datetime] = None
    withdrawn_date: Optional[datetime] = None
    purpose_description: str = ""
    data_categories: List[str] = None
    third_party_sharing: bool = False
    withdrawal_method: Optional[str] = None
    consent_version: str = "1.0"
    
    def __post_init__(self):
        if self.data_categories is None:
            self.data_categories = []


@dataclass
class GovernancePolicy:
    """Data governance policy definition."""
    policy_id: str
    name: str
    description: str
    policy_type: str  # classification, retention, access, consent
    applicable_data_types: List[str]
    rules: List[Dict[str, Any]]
    enforcement_level: str  # advisory, warning, blocking
    created_date: datetime
    last_updated: datetime
    owner: str
    approval_status: str = "active"
    
    def __post_init__(self):
        if self.created_date is None:
            self.created_date = datetime.utcnow()
        if self.last_updated is None:
            self.last_updated = datetime.utcnow()


class DataGovernanceManager:
    """Healthcare data governance automation system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.notification_manager = NotificationManager()
        
        # Configuration
        self.data_governance_config = get_data_governance_config()
        self.compliance_config = get_compliance_config()
        
        # Governance policies
        self.governance_policies = self._initialize_governance_policies()
        
        # Data assets registry
        self.data_assets = {}
        
        # Consent records
        self.consent_records = {}
        
    def _initialize_governance_policies(self) -> Dict[str, GovernancePolicy]:
        """Initialize default data governance policies."""
        policies = {}
        
        # PHI Classification Policy
        policies["phi_classification"] = GovernancePolicy(
            policy_id="phi_classification_policy",
            name="PHI Data Classification Policy",
            description="Automated classification of PHI data elements",
            policy_type="classification",
            applicable_data_types=["audio_file", "analysis_result", "user_profile"],
            rules=[
                {
                    "condition": "contains_voice_data",
                    "action": "classify_as_phi",
                    "parameters": {"classification": DataClassification.PHI.value}
                },
                {
                    "condition": "contains_health_analysis",
                    "action": "classify_as_sensitive_phi",
                    "parameters": {"classification": DataClassification.SENSITIVE_PHI.value}
                }
            ],
            enforcement_level="blocking",
            created_date=datetime.utcnow(),
            last_updated=datetime.utcnow(),
            owner="system"
        )
        
        # Data Retention Policy
        policies["data_retention"] = GovernancePolicy(
            policy_id="healthcare_data_retention",
            name="Healthcare Data Retention Policy",
            description="HIPAA-compliant data retention periods",
            policy_type="retention",
            applicable_data_types=["audio_file", "analysis_result", "audit_log"],
            rules=[
                {
                    "condition": "data_type == 'audio_file'",
                    "action": "set_retention_period",
                    "parameters": {"retention_years": 7}
                },
                {
                    "condition": "data_type == 'audit_log'",
                    "action": "set_retention_period",
                    "parameters": {"retention_years": 6}
                }
            ],
            enforcement_level="blocking",
            created_date=datetime.utcnow(),
            last_updated=datetime.utcnow(),
            owner="compliance"
        )
        
        # Consent Management Policy
        policies["consent_management"] = GovernancePolicy(
            policy_id="consent_management_policy",
            name="Patient Consent Management Policy",
            description="Automated consent validation and management",
            policy_type="consent",
            applicable_data_types=["audio_file", "analysis_result"],
            rules=[
                {
                    "condition": "processing_purpose == 'research'",
                    "action": "require_explicit_consent",
                    "parameters": {"consent_type": ConsentType.RESEARCH.value}
                },
                {
                    "condition": "third_party_sharing == true",
                    "action": "require_explicit_consent",
                    "parameters": {"consent_type": ConsentType.ANALYTICS.value}
                }
            ],
            enforcement_level="blocking",
            created_date=datetime.utcnow(),
            last_updated=datetime.utcnow(),
            owner="privacy"
        )
        
        # Data Minimization Policy
        policies["data_minimization"] = GovernancePolicy(
            policy_id="data_minimization_policy",
            name="Data Minimization Policy",
            description="Ensure only necessary data is collected and processed",
            policy_type="access",
            applicable_data_types=["all"],
            rules=[
                {
                    "condition": "access_purpose != processing_purpose",
                    "action": "deny_access",
                    "parameters": {"reason": "purpose_limitation"}
                },
                {
                    "condition": "data_age > retention_period",
                    "action": "schedule_deletion",
                    "parameters": {"grace_period_days": 30}
                }
            ],
            enforcement_level="warning",
            created_date=datetime.utcnow(),
            last_updated=datetime.utcnow(),
            owner="privacy"
        )
        
        return policies
    
    async def perform_data_governance_scan(
        self,
        scan_scope: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive data governance scan.
        
        Args:
            scan_scope: Scope of scan (all, classification, consent, retention)
            
        Returns:
            Data governance scan results
        """
        try:
            logger.info("Starting comprehensive data governance scan")
            
            scan_id = f"dg_scan_{datetime.utcnow().timestamp()}"
            
            # Initialize scan results
            scan_results = {
                "scan_id": scan_id,
                "scan_timestamp": datetime.utcnow().isoformat(),
                "scan_scope": scan_scope or "all",
                "data_assets_scanned": 0,
                "classification_results": {},
                "consent_compliance": {},
                "retention_compliance": {},
                "policy_violations": [],
                "recommendations": []
            }
            
            # Discover and catalog data assets
            data_assets = await self._discover_data_assets()
            scan_results["data_assets_scanned"] = len(data_assets)
            
            # Run governance checks based on scope
            if scan_scope in [None, "all", "classification"]:
                classification_results = await self._perform_classification_scan(data_assets)
                scan_results["classification_results"] = classification_results
            
            if scan_scope in [None, "all", "consent"]:
                consent_results = await self._perform_consent_compliance_scan(data_assets)
                scan_results["consent_compliance"] = consent_results
            
            if scan_scope in [None, "all", "retention"]:
                retention_results = await self._perform_retention_compliance_scan(data_assets)
                scan_results["retention_compliance"] = retention_results
            
            # Check policy compliance
            policy_violations = await self._check_policy_compliance(data_assets)
            scan_results["policy_violations"] = policy_violations
            
            # Generate recommendations
            recommendations = self._generate_governance_recommendations(scan_results)
            scan_results["recommendations"] = recommendations
            
            # Log scan completion
            await self._log_governance_scan(scan_results)
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Data governance scan failed: {e}")
            raise
    
    async def _discover_data_assets(self) -> List[DataAsset]:
        """Discover and catalog data assets in the system."""
        data_assets = []
        
        try:
            # Discover audio files
            audio_files = self.db.query(AudioFile).filter(AudioFile.is_deleted == False).all()
            
            for file in audio_files:
                asset = DataAsset(
                    asset_id=f"audio_{file.id}",
                    asset_type="audio_file",
                    classification=DataClassification.PHI,  # Default for audio files
                    owner_id=file.user_id,
                    created_date=file.uploaded_at,
                    last_accessed=file.last_accessed_at,
                    phi_elements=["voice_data", "patient_identifier"],
                    consent_required=True,
                    retention_period_years=7,
                    processing_purposes=[ConsentType.TREATMENT]
                )
                
                # Set scheduled deletion date
                asset.scheduled_deletion_date = asset.created_date + timedelta(days=asset.retention_period_years * 365)
                
                data_assets.append(asset)
                self.data_assets[asset.asset_id] = asset
            
            # Discover user profiles
            users = self.db.query(User).all()
            
            for user in users:
                asset = DataAsset(
                    asset_id=f"user_{user.id}",
                    asset_type="user_profile",
                    classification=DataClassification.PHI,
                    owner_id=user.id,
                    created_date=user.created_at,
                    last_accessed=user.last_login,
                    phi_elements=["name", "email", "demographic_data"],
                    consent_required=True,
                    retention_period_years=7,
                    processing_purposes=[ConsentType.TREATMENT, ConsentType.CARE_COORDINATION]
                )
                
                data_assets.append(asset)
                self.data_assets[asset.asset_id] = asset
            
            # Discover audit logs (non-PHI but governed)
            recent_audit_cutoff = datetime.utcnow() - timedelta(days=30)
            audit_logs = self.db.query(AuditLog).filter(
                AuditLog.timestamp >= recent_audit_cutoff
            ).limit(1000).all()  # Sample for performance
            
            if audit_logs:
                asset = DataAsset(
                    asset_id="audit_logs_recent",
                    asset_type="audit_log",
                    classification=DataClassification.CONFIDENTIAL,
                    owner_id=None,
                    created_date=min(log.timestamp for log in audit_logs),
                    phi_elements=[],
                    consent_required=False,
                    retention_period_years=6,
                    processing_purposes=[ConsentType.QUALITY_IMPROVEMENT]
                )
                
                data_assets.append(asset)
                self.data_assets[asset.asset_id] = asset
            
            logger.info(f"Discovered {len(data_assets)} data assets")
            return data_assets
            
        except Exception as e:
            logger.error(f"Data asset discovery failed: {e}")
            return []
    
    async def _perform_classification_scan(self, data_assets: List[DataAsset]) -> Dict[str, Any]:
        """Perform automated data classification scan."""
        try:
            classification_results = {
                "total_assets": len(data_assets),
                "classification_distribution": {},
                "phi_assets": 0,
                "unclassified_assets": 0,
                "reclassification_needed": 0,
                "classification_confidence": {}
            }
            
            # Count assets by classification
            for asset in data_assets:
                classification = asset.classification.value
                classification_results["classification_distribution"][classification] = \
                    classification_results["classification_distribution"].get(classification, 0) + 1
                
                if asset.classification in [DataClassification.PHI, DataClassification.SENSITIVE_PHI]:
                    classification_results["phi_assets"] += 1
                
                # Check if reclassification is needed
                if await self._needs_reclassification(asset):
                    classification_results["reclassification_needed"] += 1
                
                # Calculate classification confidence
                confidence = await self._calculate_classification_confidence(asset)
                classification_results["classification_confidence"][asset.asset_id] = confidence
            
            # Identify PHI elements
            phi_elements = await self._identify_phi_elements(data_assets)
            classification_results["phi_elements_found"] = phi_elements
            
            return classification_results
            
        except Exception as e:
            logger.error(f"Classification scan failed: {e}")
            return {"error": str(e)}
    
    async def _perform_consent_compliance_scan(self, data_assets: List[DataAsset]) -> Dict[str, Any]:
        """Perform consent compliance scan."""
        try:
            consent_results = {
                "total_assets_requiring_consent": 0,
                "assets_with_valid_consent": 0,
                "assets_with_expired_consent": 0,
                "assets_without_consent": 0,
                "consent_gaps": [],
                "consent_expiring_soon": []
            }
            
            for asset in data_assets:
                if not asset.consent_required:
                    continue
                
                consent_results["total_assets_requiring_consent"] += 1
                
                # Check consent status for asset owner
                if asset.owner_id:
                    consent_status = await self._check_user_consent(asset.owner_id, asset.processing_purposes)
                    
                    if consent_status["valid"]:
                        consent_results["assets_with_valid_consent"] += 1
                    elif consent_status["expired"]:
                        consent_results["assets_with_expired_consent"] += 1
                        consent_results["consent_gaps"].append({
                            "asset_id": asset.asset_id,
                            "owner_id": str(asset.owner_id),
                            "issue": "expired_consent",
                            "processing_purposes": [p.value for p in asset.processing_purposes]
                        })
                    else:
                        consent_results["assets_without_consent"] += 1
                        consent_results["consent_gaps"].append({
                            "asset_id": asset.asset_id,
                            "owner_id": str(asset.owner_id),
                            "issue": "missing_consent",
                            "processing_purposes": [p.value for p in asset.processing_purposes]
                        })
                    
                    # Check for consent expiring soon
                    if consent_status.get("expiring_soon"):
                        consent_results["consent_expiring_soon"].append({
                            "asset_id": asset.asset_id,
                            "owner_id": str(asset.owner_id),
                            "expiration_date": consent_status.get("expiration_date")
                        })
            
            return consent_results
            
        except Exception as e:
            logger.error(f"Consent compliance scan failed: {e}")
            return {"error": str(e)}
    
    async def _perform_retention_compliance_scan(self, data_assets: List[DataAsset]) -> Dict[str, Any]:
        """Perform data retention compliance scan."""
        try:
            retention_results = {
                "total_assets": len(data_assets),
                "assets_within_retention": 0,
                "assets_approaching_retention": 0,
                "assets_past_retention": 0,
                "retention_violations": [],
                "scheduled_deletions": 0
            }
            
            now = datetime.utcnow()
            
            for asset in data_assets:
                # Calculate asset age
                asset_age_days = (now - asset.created_date).days
                retention_days = asset.retention_period_years * 365
                
                if asset_age_days < retention_days - 90:  # More than 90 days before retention
                    retention_results["assets_within_retention"] += 1
                elif asset_age_days < retention_days:  # Within 90 days of retention
                    retention_results["assets_approaching_retention"] += 1
                else:  # Past retention period
                    retention_results["assets_past_retention"] += 1
                    
                    # Check if there's a valid reason for extended retention
                    extended_reason = await self._check_retention_extension(asset)
                    if not extended_reason:
                        retention_results["retention_violations"].append({
                            "asset_id": asset.asset_id,
                            "asset_type": asset.asset_type,
                            "age_days": asset_age_days,
                            "retention_days": retention_days,
                            "overdue_days": asset_age_days - retention_days
                        })
                
                # Count scheduled deletions
                if asset.scheduled_deletion_date:
                    retention_results["scheduled_deletions"] += 1
            
            return retention_results
            
        except Exception as e:
            logger.error(f"Retention compliance scan failed: {e}")
            return {"error": str(e)}
    
    async def _check_policy_compliance(self, data_assets: List[DataAsset]) -> List[Dict[str, Any]]:
        """Check compliance with governance policies."""
        violations = []
        
        try:
            for policy_id, policy in self.governance_policies.items():
                for asset in data_assets:
                    # Check if policy applies to this asset
                    if self._policy_applies_to_asset(policy, asset):
                        # Check each rule in the policy
                        for rule in policy.rules:
                            violation = await self._check_policy_rule(policy, rule, asset)
                            if violation:
                                violations.append(violation)
            
            return violations
            
        except Exception as e:
            logger.error(f"Policy compliance check failed: {e}")
            return []
    
    def _policy_applies_to_asset(self, policy: GovernancePolicy, asset: DataAsset) -> bool:
        """Check if governance policy applies to data asset."""
        # Check if asset type is covered by policy
        if "all" in policy.applicable_data_types:
            return True
        
        return asset.asset_type in policy.applicable_data_types
    
    async def _check_policy_rule(
        self,
        policy: GovernancePolicy,
        rule: Dict[str, Any],
        asset: DataAsset
    ) -> Optional[Dict[str, Any]]:
        """Check specific policy rule against data asset."""
        try:
            condition = rule.get("condition", "")
            action = rule.get("action", "")
            parameters = rule.get("parameters", {})
            
            # Evaluate condition
            condition_met = await self._evaluate_rule_condition(condition, asset)
            
            if condition_met:
                # Determine if this constitutes a violation
                if action in ["deny_access", "require_explicit_consent", "schedule_deletion"]:
                    # Check if the required action has been taken
                    action_taken = await self._check_action_taken(action, asset, parameters)
                    
                    if not action_taken:
                        return {
                            "policy_id": policy.policy_id,
                            "policy_name": policy.name,
                            "asset_id": asset.asset_id,
                            "rule_condition": condition,
                            "required_action": action,
                            "violation_type": "missing_required_action",
                            "severity": "high" if policy.enforcement_level == "blocking" else "medium",
                            "parameters": parameters
                        }
            
            return None
            
        except Exception as e:
            logger.error(f"Policy rule check failed: {e}")
            return None
    
    async def _evaluate_rule_condition(self, condition: str, asset: DataAsset) -> bool:
        """Evaluate rule condition against data asset."""
        # Simplified condition evaluation
        # In production, this would use a proper rule engine
        
        if "contains_voice_data" in condition:
            return "voice_data" in asset.phi_elements
        
        if "contains_health_analysis" in condition:
            return asset.asset_type == "analysis_result"
        
        if "data_type ==" in condition:
            expected_type = condition.split("==")[1].strip().strip("'\"")
            return asset.asset_type == expected_type
        
        if "processing_purpose ==" in condition:
            expected_purpose = condition.split("==")[1].strip().strip("'\"")
            return any(p.value == expected_purpose for p in asset.processing_purposes)
        
        if "third_party_sharing == true" in condition:
            # Check if asset involves third-party sharing
            return "third_party" in asset.data_lineage
        
        if "access_purpose != processing_purpose" in condition:
            # This would require access context, simplified for now
            return False
        
        if "data_age > retention_period" in condition:
            asset_age_days = (datetime.utcnow() - asset.created_date).days
            return asset_age_days > (asset.retention_period_years * 365)
        
        return False
    
    async def _check_action_taken(self, action: str, asset: DataAsset, parameters: Dict[str, Any]) -> bool:
        """Check if required action has been taken for asset."""
        if action == "classify_as_phi":
            expected_classification = parameters.get("classification", "")
            return asset.classification.value == expected_classification
        
        if action == "set_retention_period":
            expected_years = parameters.get("retention_years", 0)
            return asset.retention_period_years == expected_years
        
        if action == "require_explicit_consent":
            consent_type = parameters.get("consent_type", "")
            if asset.owner_id:
                consent_status = await self._check_user_consent(asset.owner_id, [ConsentType(consent_type)])
                return consent_status.get("valid", False)
        
        if action == "schedule_deletion":
            return asset.scheduled_deletion_date is not None
        
        return True  # Default to compliant for unknown actions
    
    async def _needs_reclassification(self, asset: DataAsset) -> bool:
        """Check if data asset needs reclassification."""
        # Check if classification is outdated
        if self.data_governance_config.PHI_RECLASSIFICATION_INTERVAL_DAYS:
            days_since_creation = (datetime.utcnow() - asset.created_date).days
            return days_since_creation > self.data_governance_config.PHI_RECLASSIFICATION_INTERVAL_DAYS
        
        return False
    
    async def _calculate_classification_confidence(self, asset: DataAsset) -> float:
        """Calculate confidence score for data classification."""
        confidence = 0.8  # Base confidence
        
        # Increase confidence for well-defined asset types
        if asset.asset_type in ["audio_file", "user_profile"]:
            confidence += 0.1
        
        # Increase confidence if PHI elements are identified
        if asset.phi_elements:
            confidence += 0.1
        
        # Decrease confidence for older assets (may have changed)
        asset_age_days = (datetime.utcnow() - asset.created_date).days
        if asset_age_days > 365:
            confidence -= 0.1
        
        return min(1.0, max(0.0, confidence))
    
    async def _identify_phi_elements(self, data_assets: List[DataAsset]) -> Dict[str, int]:
        """Identify PHI elements across all data assets."""
        phi_elements = {}
        
        for asset in data_assets:
            for element in asset.phi_elements:
                phi_elements[element] = phi_elements.get(element, 0) + 1
        
        return phi_elements
    
    async def _check_user_consent(self, user_id: UUID, purposes: List[ConsentType]) -> Dict[str, Any]:
        """Check user consent status for specific purposes."""
        # In production, this would query actual consent records
        # For now, simulate consent checking
        
        consent_status = {
            "valid": True,
            "expired": False,
            "expiring_soon": False,
            "expiration_date": None
        }
        
        # Check if any purposes require explicit consent
        explicit_consent_purposes = [ConsentType.RESEARCH, ConsentType.MARKETING]
        requires_explicit = any(purpose in explicit_consent_purposes for purpose in purposes)
        
        if requires_explicit:
            # Simulate consent record lookup
            consent_record = self.consent_records.get(f"{user_id}_research")
            if not consent_record:
                consent_status["valid"] = False
            else:
                # Check expiration
                if consent_record.expiration_date and consent_record.expiration_date < datetime.utcnow():
                    consent_status["valid"] = False
                    consent_status["expired"] = True
                elif consent_record.expiration_date and consent_record.expiration_date < datetime.utcnow() + timedelta(days=30):
                    consent_status["expiring_soon"] = True
                    consent_status["expiration_date"] = consent_record.expiration_date.isoformat()
        
        return consent_status
    
    async def _check_retention_extension(self, asset: DataAsset) -> Optional[DataRetentionReason]:
        """Check if asset has valid reason for extended retention."""
        # In production, this would check actual retention extension records
        # For now, return None (no extension reason)
        return None
    
    def _generate_governance_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate data governance recommendations based on scan results."""
        recommendations = []
        
        # Classification recommendations
        if "classification_results" in scan_results:
            unclassified = scan_results["classification_results"].get("unclassified_assets", 0)
            if unclassified > 0:
                recommendations.append(f"Classify {unclassified} unclassified data assets")
            
            reclassification_needed = scan_results["classification_results"].get("reclassification_needed", 0)
            if reclassification_needed > 0:
                recommendations.append(f"Review and update classification for {reclassification_needed} assets")
        
        # Consent recommendations
        if "consent_compliance" in scan_results:
            consent_gaps = len(scan_results["consent_compliance"].get("consent_gaps", []))
            if consent_gaps > 0:
                recommendations.append(f"Address {consent_gaps} consent compliance gaps")
            
            expiring_soon = len(scan_results["consent_compliance"].get("consent_expiring_soon", []))
            if expiring_soon > 0:
                recommendations.append(f"Renew consent for {expiring_soon} assets with expiring consent")
        
        # Retention recommendations
        if "retention_compliance" in scan_results:
            retention_violations = len(scan_results["retention_compliance"].get("retention_violations", []))
            if retention_violations > 0:
                recommendations.append(f"Address {retention_violations} data retention violations")
        
        # Policy recommendations
        policy_violations = len(scan_results.get("policy_violations", []))
        if policy_violations > 0:
            recommendations.append(f"Resolve {policy_violations} governance policy violations")
        
        # General recommendations
        recommendations.extend([
            "Implement automated data classification",
            "Establish regular consent renewal processes",
            "Automate data retention enforcement",
            "Enhance data lineage tracking"
        ])
        
        return recommendations[:8]  # Limit to top 8
    
    async def classify_data_asset(
        self,
        asset_id: str,
        classification: DataClassification,
        phi_elements: List[str] = None
    ) -> Dict[str, Any]:
        """Manually classify or reclassify a data asset."""
        try:
            if asset_id not in self.data_assets:
                raise ValueError(f"Data asset {asset_id} not found")
            
            asset = self.data_assets[asset_id]
            old_classification = asset.classification
            
            # Update classification
            asset.classification = classification
            if phi_elements:
                asset.phi_elements = phi_elements
            
            # Log classification change
            await self.audit_logger.log_security_event(
                event_type="data_classification_change",
                severity="info",
                description=f"Data asset {asset_id} reclassified from {old_classification.value} to {classification.value}",
                details={
                    "asset_id": asset_id,
                    "old_classification": old_classification.value,
                    "new_classification": classification.value,
                    "phi_elements": phi_elements or asset.phi_elements
                }
            )
            
            return {
                "asset_id": asset_id,
                "old_classification": old_classification.value,
                "new_classification": classification.value,
                "classification_timestamp": datetime.utcnow().isoformat(),
                "phi_elements": asset.phi_elements
            }
            
        except Exception as e:
            logger.error(f"Data asset classification failed: {e}")
            raise
    
    async def manage_user_consent(
        self,
        user_id: UUID,
        consent_type: ConsentType,
        action: str,  # grant, withdraw, renew
        expiration_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Manage user consent for data processing."""
        try:
            consent_id = f"{user_id}_{consent_type.value}"
            
            if action == "grant":
                consent_record = ConsentRecord(
                    consent_id=consent_id,
                    user_id=user_id,
                    consent_type=consent_type,
                    status=ConsentStatus.ACTIVE,
                    granted_date=datetime.utcnow(),
                    expiration_date=expiration_date,
                    purpose_description=f"Consent for {consent_type.value} purposes"
                )
                
                self.consent_records[consent_id] = consent_record
                
                # Send confirmation notification
                await self.notification_manager.send_notification(
                    user_id=user_id,
                    notification_type=NotificationType.CONSENT_CONFIRMED,
                    data={
                        "consent_type": consent_type.value,
                        "granted_date": consent_record.granted_date.isoformat(),
                        "expiration_date": expiration_date.isoformat() if expiration_date else None
                    }
                )
                
            elif action == "withdraw":
                if consent_id in self.consent_records:
                    consent_record = self.consent_records[consent_id]
                    consent_record.status = ConsentStatus.WITHDRAWN
                    consent_record.withdrawn_date = datetime.utcnow()
                    consent_record.withdrawal_method = "user_request"
                
            elif action == "renew":
                if consent_id in self.consent_records:
                    consent_record = self.consent_records[consent_id]
                    consent_record.granted_date = datetime.utcnow()
                    consent_record.expiration_date = expiration_date
                    consent_record.status = ConsentStatus.ACTIVE
            
            # Log consent action
            await self.audit_logger.log_security_event(
                event_type="consent_management",
                user_id=user_id,
                severity="info",
                description=f"User consent {action} for {consent_type.value}",
                details={
                    "consent_id": consent_id,
                    "action": action,
                    "expiration_date": expiration_date.isoformat() if expiration_date else None
                }
            )
            
            return {
                "consent_id": consent_id,
                "user_id": str(user_id),
                "consent_type": consent_type.value,
                "action": action,
                "status": self.consent_records.get(consent_id, {}).status.value if consent_id in self.consent_records else "unknown",
                "action_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Consent management failed: {e}")
            raise
    
    async def _log_governance_scan(self, scan_results: Dict[str, Any]):
        """Log data governance scan for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="data_governance_scan",
                severity="info",
                description=f"Data governance scan completed. {scan_results['data_assets_scanned']} assets scanned",
                details={
                    "scan_id": scan_results["scan_id"],
                    "assets_scanned": scan_results["data_assets_scanned"],
                    "policy_violations": len(scan_results["policy_violations"]),
                    "scan_scope": scan_results["scan_scope"]
                }
            )
        except Exception as e:
            logger.error(f"Failed to log governance scan: {e}")


async def run_data_governance_scan(
    db: Session,
    scan_scope: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level function to run data governance scan.
    
    Args:
        db: Database session
        scan_scope: Scope of scan (all, classification, consent, retention)
        
    Returns:
        Data governance scan results
    """
    governance_manager = DataGovernanceManager(db)
    return await governance_manager.perform_data_governance_scan(scan_scope) 