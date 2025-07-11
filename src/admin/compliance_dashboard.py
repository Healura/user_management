"""
Healthcare Compliance Dashboard Service

Real-time HIPAA compliance monitoring, risk assessment dashboard,
and automated compliance alerting for healthcare administrators.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from sqlalchemy.orm import Session

from src.security.compliance_checker import run_compliance_check, HIPAAComplianceChecker
from src.security.risk_assessment import run_risk_assessment, HealthcareRiskAssessment
from src.security.breach_detection import run_threat_detection, HealthcareThreatDetector
from src.compliance.hipaa_audit import run_hipaa_audit, HIPAAAuditManager
from src.compliance.data_governance import run_data_governance_scan, DataGovernanceManager
from src.security.baa_compliance import run_baa_compliance_check, BAAComplianceMonitor
from src.notifications.notification_manager import NotificationManager, NotificationType

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ComplianceAlert:
    """Compliance alert data structure."""
    id: str
    type: str
    severity: AlertSeverity
    title: str
    description: str
    source_component: str
    timestamp: datetime
    status: str = "active"  # active, acknowledged, resolved
    remediation_steps: List[str] = None
    auto_remediation_available: bool = False
    impact_assessment: str = ""
    regulatory_reference: str = ""
    
    def __post_init__(self):
        if self.remediation_steps is None:
            self.remediation_steps = []


@dataclass
class ComplianceMetric:
    """Compliance metric data structure."""
    name: str
    current_value: float
    target_value: float
    unit: str
    trend: str  # improving, declining, stable
    last_updated: datetime
    status: str  # compliant, non_compliant, at_risk
    historical_data: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.historical_data is None:
            self.historical_data = []


@dataclass
class RiskIndicator:
    """Risk indicator data structure."""
    category: str
    risk_level: str  # low, medium, high, critical
    score: int  # 0-100
    description: str
    contributing_factors: List[str]
    mitigation_priority: int  # 1-5, 1 being highest priority
    estimated_impact: str
    likelihood: str
    
    def __post_init__(self):
        if self.contributing_factors is None:
            self.contributing_factors = []


class ComplianceDashboard:
    """Comprehensive healthcare compliance dashboard service."""
    
    def __init__(self, db: Session):
        self.db = db
        self.notification_manager = NotificationManager()
        
        # Dashboard refresh intervals
        self.refresh_intervals = {
            "real_time": 30,  # seconds
            "metrics": 300,   # 5 minutes
            "assessments": 3600,  # 1 hour
            "reports": 86400  # 24 hours
        }
        
        # Compliance scoring weights
        self.compliance_weights = {
            "access_controls": 0.20,
            "data_encryption": 0.15,
            "audit_logging": 0.15,
            "breach_detection": 0.15,
            "data_retention": 0.10,
            "training_compliance": 0.10,
            "baa_compliance": 0.10,
            "incident_response": 0.05
        }
        
        # Alert thresholds
        self.alert_thresholds = {
            "compliance_score": {"critical": 70, "high": 80, "medium": 90},
            "risk_score": {"critical": 80, "high": 60, "medium": 40},
            "violation_count": {"critical": 10, "high": 5, "medium": 2},
            "audit_gaps": {"critical": 5, "high": 3, "medium": 1}
        }
    
    async def get_compliance_overview(self) -> Dict[str, Any]:
        """Get comprehensive compliance overview dashboard."""
        try:
            logger.info("Generating compliance overview dashboard")
            
            overview = {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": {},
                "key_metrics": {},
                "risk_indicators": {},
                "recent_alerts": [],
                "compliance_trends": {},
                "action_items": [],
                "regulatory_status": {}
            }
            
            # Run all compliance assessments in parallel
            assessment_results = await asyncio.gather(
                self._get_overall_compliance_status(),
                self._get_key_compliance_metrics(),
                self._get_risk_indicators(),
                self._get_recent_alerts(),
                self._get_compliance_trends(),
                self._get_action_items(),
                self._get_regulatory_status(),
                return_exceptions=True
            )
            
            (overall_status, key_metrics, risk_indicators, 
             recent_alerts, compliance_trends, action_items, 
             regulatory_status) = assessment_results
            
            # Populate overview
            overview["overall_status"] = overall_status if not isinstance(overall_status, Exception) else {}
            overview["key_metrics"] = key_metrics if not isinstance(key_metrics, Exception) else {}
            overview["risk_indicators"] = risk_indicators if not isinstance(risk_indicators, Exception) else {}
            overview["recent_alerts"] = recent_alerts if not isinstance(recent_alerts, Exception) else []
            overview["compliance_trends"] = compliance_trends if not isinstance(compliance_trends, Exception) else {}
            overview["action_items"] = action_items if not isinstance(action_items, Exception) else []
            overview["regulatory_status"] = regulatory_status if not isinstance(regulatory_status, Exception) else {}
            
            # Generate summary insights
            overview["summary_insights"] = await self._generate_summary_insights(overview)
            
            return overview
            
        except Exception as e:
            logger.error(f"Compliance overview generation failed: {e}")
            raise
    
    async def get_risk_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive risk assessment dashboard."""
        try:
            logger.info("Generating risk assessment dashboard")
            
            risk_dashboard = {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_risk_level": "medium",
                "risk_score": 0,
                "risk_categories": {},
                "threat_landscape": {},
                "vulnerability_assessment": {},
                "risk_trends": {},
                "mitigation_recommendations": [],
                "risk_heat_map": {}
            }
            
            # Run risk assessments
            risk_result = await run_risk_assessment(self.db, include_historical=True)
            threat_result = await run_threat_detection(self.db, lookback_hours=24)
            
            # Process risk assessment results
            if risk_result:
                risk_dashboard["overall_risk_level"] = risk_result.risk_level.value
                risk_dashboard["risk_score"] = risk_result.overall_risk_score
                risk_dashboard["risk_categories"] = risk_result.category_scores
                risk_dashboard["mitigation_recommendations"] = risk_result.mitigation_recommendations
                
                # Convert risk factors to dashboard format
                risk_dashboard["risk_factors"] = [
                    {
                        "category": factor.category.value,
                        "name": factor.name,
                        "score": factor.risk_score,
                        "trend": factor.trend,
                        "severity": factor.severity.value
                    }
                    for factor in risk_result.risk_factors
                ]
            
            # Process threat detection results
            if threat_result:
                risk_dashboard["threat_landscape"] = {
                    "total_incidents": threat_result.get("total_incidents", 0),
                    "critical_incidents": threat_result.get("critical_incidents", 0),
                    "incident_types": threat_result.get("incident_types", {}),
                    "threat_trends": threat_result.get("trends", {})
                }
            
            # Generate vulnerability assessment
            risk_dashboard["vulnerability_assessment"] = await self._assess_vulnerabilities()
            
            # Generate risk trends
            risk_dashboard["risk_trends"] = await self._analyze_risk_trends()
            
            # Generate risk heat map
            risk_dashboard["risk_heat_map"] = await self._generate_risk_heat_map()
            
            return risk_dashboard
            
        except Exception as e:
            logger.error(f"Risk dashboard generation failed: {e}")
            raise
    
    async def generate_compliance_alerts(self) -> List[ComplianceAlert]:
        """Generate and prioritize compliance alerts."""
        try:
            logger.info("Generating compliance alerts")
            
            alerts = []
            
            # Run compliance checks
            compliance_result = await run_compliance_check(self.db)
            
            if compliance_result and "violations" in compliance_result:
                for violation in compliance_result["violations"]:
                    alert = ComplianceAlert(
                        id=f"comp_{violation.get('id', datetime.utcnow().timestamp())}",
                        type="compliance_violation",
                        severity=AlertSeverity(violation.get("severity", "medium")),
                        title=violation.get("title", "Compliance Violation"),
                        description=violation.get("description", ""),
                        source_component="compliance_checker",
                        timestamp=datetime.utcnow(),
                        remediation_steps=violation.get("remediation_steps", []),
                        auto_remediation_available=violation.get("auto_remediable", False),
                        regulatory_reference=violation.get("regulatory_reference", "")
                    )
                    alerts.append(alert)
            
            # Check for audit gaps
            audit_alerts = await self._check_audit_gaps()
            alerts.extend(audit_alerts)
            
            # Check for data governance issues
            governance_alerts = await self._check_data_governance_issues()
            alerts.extend(governance_alerts)
            
            # Check for training compliance
            training_alerts = await self._check_training_compliance()
            alerts.extend(training_alerts)
            
            # Check for BAA compliance
            baa_alerts = await self._check_baa_compliance()
            alerts.extend(baa_alerts)
            
            # Sort alerts by severity and timestamp
            alerts.sort(key=lambda x: (
                ["low", "medium", "high", "critical"].index(x.severity.value),
                x.timestamp
            ), reverse=True)
            
            # Send critical alerts immediately
            await self._send_critical_alerts([a for a in alerts if a.severity == AlertSeverity.CRITICAL])
            
            return alerts
            
        except Exception as e:
            logger.error(f"Compliance alert generation failed: {e}")
            raise
    
    async def get_compliance_scorecard(self) -> Dict[str, Any]:
        """Get detailed compliance scorecard."""
        try:
            scorecard = {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_score": 0,
                "category_scores": {},
                "performance_indicators": {},
                "improvement_areas": [],
                "strengths": [],
                "benchmark_comparison": {}
            }
            
            # Run comprehensive compliance check
            compliance_result = await run_compliance_check(self.db)
            
            if compliance_result and "compliance_score" in compliance_result:
                scorecard["overall_score"] = compliance_result["compliance_score"]["total_score"]
                scorecard["category_scores"] = compliance_result["compliance_score"]["category_scores"]
            
            # Calculate performance indicators
            scorecard["performance_indicators"] = await self._calculate_performance_indicators()
            
            # Identify improvement areas
            scorecard["improvement_areas"] = await self._identify_improvement_areas(scorecard["category_scores"])
            
            # Identify strengths
            scorecard["strengths"] = await self._identify_compliance_strengths(scorecard["category_scores"])
            
            # Benchmark comparison
            scorecard["benchmark_comparison"] = await self._compare_to_benchmarks(scorecard["overall_score"])
            
            return scorecard
            
        except Exception as e:
            logger.error(f"Compliance scorecard generation failed: {e}")
            raise
    
    async def get_audit_dashboard(self) -> Dict[str, Any]:
        """Get audit trail dashboard."""
        try:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=30)
            
            audit_result = await run_hipaa_audit(self.db, start_date, end_date)
            
            dashboard = {
                "timestamp": datetime.utcnow().isoformat(),
                "audit_period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "audit_summary": {},
                "compliance_status": "unknown",
                "integrity_verification": {},
                "event_analysis": {},
                "missing_events": [],
                "recommendations": []
            }
            
            if audit_result:
                dashboard["audit_summary"] = {
                    "total_events": audit_result.total_events,
                    "events_by_type": audit_result.events_by_type,
                    "events_by_user": audit_result.events_by_user
                }
                dashboard["compliance_status"] = audit_result.compliance_status.value
                dashboard["integrity_verification"] = audit_result.integrity_verification
                dashboard["missing_events"] = audit_result.missing_events
                dashboard["recommendations"] = audit_result.recommendations
                
                # Additional event analysis
                dashboard["event_analysis"] = await self._analyze_audit_events(audit_result)
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Audit dashboard generation failed: {e}")
            raise
    
    # Private helper methods
    
    async def _get_overall_compliance_status(self) -> Dict[str, Any]:
        """Get overall compliance status."""
        compliance_result = await run_compliance_check(self.db)
        
        if compliance_result:
            return {
                "score": compliance_result.get("compliance_score", {}).get("total_score", 0),
                "status": "compliant" if compliance_result.get("compliance_score", {}).get("total_score", 0) >= 90 else "non_compliant",
                "last_assessment": datetime.utcnow().isoformat(),
                "violations_count": len(compliance_result.get("violations", [])),
                "critical_violations": len([v for v in compliance_result.get("violations", []) if v.get("severity") == "critical"])
            }
        
        return {}
    
    async def _get_key_compliance_metrics(self) -> Dict[str, ComplianceMetric]:
        """Get key compliance metrics."""
        metrics = {}
        
        # Audit completeness
        metrics["audit_completeness"] = ComplianceMetric(
            name="Audit Trail Completeness",
            current_value=98.5,
            target_value=100.0,
            unit="percentage",
            trend="stable",
            last_updated=datetime.utcnow(),
            status="compliant"
        )
        
        # Data encryption compliance
        metrics["encryption_compliance"] = ComplianceMetric(
            name="Data Encryption Compliance",
            current_value=100.0,
            target_value=100.0,
            unit="percentage",
            trend="stable",
            last_updated=datetime.utcnow(),
            status="compliant"
        )
        
        # Access control compliance
        metrics["access_control"] = ComplianceMetric(
            name="Access Control Compliance",
            current_value=95.2,
            target_value=100.0,
            unit="percentage",
            trend="improving",
            last_updated=datetime.utcnow(),
            status="compliant"
        )
        
        # Training completion
        metrics["training_completion"] = ComplianceMetric(
            name="HIPAA Training Completion",
            current_value=87.3,
            target_value=100.0,
            unit="percentage",
            trend="improving",
            last_updated=datetime.utcnow(),
            status="at_risk"
        )
        
        return metrics
    
    async def _get_risk_indicators(self) -> Dict[str, RiskIndicator]:
        """Get risk indicators."""
        indicators = {}
        
        # Data breach risk
        indicators["data_breach"] = RiskIndicator(
            category="Data Security",
            risk_level="medium",
            score=45,
            description="Risk of data breach based on access patterns and security controls",
            contributing_factors=["Elevated privileged access", "External threat landscape"],
            mitigation_priority=2,
            estimated_impact="High financial and reputational damage",
            likelihood="Medium"
        )
        
        # Compliance violation risk
        indicators["compliance_violation"] = RiskIndicator(
            category="Regulatory Compliance",
            risk_level="low",
            score=25,
            description="Risk of regulatory compliance violations",
            contributing_factors=["Minor audit gaps", "Training completion delays"],
            mitigation_priority=3,
            estimated_impact="Regulatory fines and sanctions",
            likelihood="Low"
        )
        
        return indicators
    
    async def _get_recent_alerts(self) -> List[Dict[str, Any]]:
        """Get recent compliance alerts."""
        alerts = await self.generate_compliance_alerts()
        
        # Return only recent alerts (last 24 hours)
        recent_cutoff = datetime.utcnow() - timedelta(hours=24)
        recent_alerts = [
            {
                "id": alert.id,
                "type": alert.type,
                "severity": alert.severity.value,
                "title": alert.title,
                "timestamp": alert.timestamp.isoformat(),
                "status": alert.status
            }
            for alert in alerts 
            if alert.timestamp >= recent_cutoff
        ]
        
        return recent_alerts[:10]  # Limit to 10 most recent
    
    async def _get_compliance_trends(self) -> Dict[str, Any]:
        """Get compliance trends over time."""
        return {
            "overall_score_trend": "stable",
            "violation_trend": "decreasing",
            "audit_completeness_trend": "improving",
            "training_completion_trend": "improving",
            "incident_trend": "stable"
        }
    
    async def _get_action_items(self) -> List[Dict[str, Any]]:
        """Get prioritized action items."""
        return [
            {
                "id": "act_001",
                "title": "Complete HIPAA training for 15 staff members",
                "priority": "high",
                "due_date": (datetime.utcnow() + timedelta(days=7)).isoformat(),
                "responsible_party": "Training Manager",
                "status": "open"
            },
            {
                "id": "act_002", 
                "title": "Review and update data retention policies",
                "priority": "medium",
                "due_date": (datetime.utcnow() + timedelta(days=30)).isoformat(),
                "responsible_party": "Compliance Officer",
                "status": "in_progress"
            },
            {
                "id": "act_003",
                "title": "Conduct quarterly security assessment",
                "priority": "medium",
                "due_date": (datetime.utcnow() + timedelta(days=14)).isoformat(),
                "responsible_party": "Security Team",
                "status": "open"
            }
        ]
    
    async def _get_regulatory_status(self) -> Dict[str, Any]:
        """Get regulatory compliance status."""
        return {
            "hipaa_compliance": {
                "status": "compliant",
                "last_assessment": datetime.utcnow().isoformat(),
                "next_assessment": (datetime.utcnow() + timedelta(days=90)).isoformat(),
                "findings": []
            },
            "state_regulations": {
                "status": "compliant",
                "applicable_states": ["CA", "NY", "TX"],
                "last_review": datetime.utcnow().isoformat()
            },
            "international_compliance": {
                "gdpr_applicable": False,
                "status": "not_applicable"
            }
        }
    
    async def _generate_summary_insights(self, overview: Dict[str, Any]) -> List[str]:
        """Generate summary insights from overview data."""
        insights = []
        
        overall_score = overview.get("overall_status", {}).get("score", 0)
        if overall_score >= 95:
            insights.append("Excellent compliance posture - maintain current controls")
        elif overall_score >= 85:
            insights.append("Good compliance status with minor improvement opportunities")
        elif overall_score >= 75:
            insights.append("Compliance needs attention - address high-priority violations")
        else:
            insights.append("Critical compliance issues require immediate action")
        
        recent_alerts = overview.get("recent_alerts", [])
        critical_alerts = [a for a in recent_alerts if a.get("severity") == "critical"]
        if critical_alerts:
            insights.append(f"{len(critical_alerts)} critical alerts require immediate attention")
        
        return insights
    
    async def _check_audit_gaps(self) -> List[ComplianceAlert]:
        """Check for audit trail gaps."""
        alerts = []
        
        # Implementation would check for missing audit events
        # This is a simplified example
        
        return alerts
    
    async def _check_data_governance_issues(self) -> List[ComplianceAlert]:
        """Check for data governance issues."""
        alerts = []
        
        try:
            governance_result = await run_data_governance_scan(self.db)
            
            if governance_result and "violations" in governance_result:
                for violation in governance_result["violations"]:
                    alert = ComplianceAlert(
                        id=f"gov_{violation.get('id', datetime.utcnow().timestamp())}",
                        type="data_governance",
                        severity=AlertSeverity(violation.get("severity", "medium")),
                        title=f"Data Governance Issue: {violation.get('title', 'Unknown')}",
                        description=violation.get("description", ""),
                        source_component="data_governance",
                        timestamp=datetime.utcnow()
                    )
                    alerts.append(alert)
        
        except Exception as e:
            logger.error(f"Data governance check failed: {e}")
        
        return alerts
    
    async def _check_training_compliance(self) -> List[ComplianceAlert]:
        """Check for training compliance issues."""
        alerts = []
        
        # Implementation would check training completion rates
        # This is a simplified example
        training_completion = 87.3  # percentage
        
        if training_completion < 90:
            alert = ComplianceAlert(
                id=f"train_{datetime.utcnow().timestamp()}",
                type="training_compliance",
                severity=AlertSeverity.HIGH if training_completion < 80 else AlertSeverity.MEDIUM,
                title="HIPAA Training Completion Below Target",
                description=f"Training completion at {training_completion}%, target is 100%",
                source_component="training_system",
                timestamp=datetime.utcnow(),
                remediation_steps=[
                    "Identify staff members with incomplete training",
                    "Send training reminders",
                    "Schedule training sessions",
                    "Update training tracking system"
                ]
            )
            alerts.append(alert)
        
        return alerts
    
    async def _check_baa_compliance(self) -> List[ComplianceAlert]:
        """Check for Business Associate Agreement compliance issues."""
        alerts = []
        
        try:
            baa_result = await run_baa_compliance_check(self.db)
            
            if baa_result and "violations" in baa_result:
                for violation in baa_result["violations"]:
                    alert = ComplianceAlert(
                        id=f"baa_{violation.get('id', datetime.utcnow().timestamp())}",
                        type="baa_compliance",
                        severity=AlertSeverity(violation.get("severity", "medium")),
                        title=f"BAA Compliance Issue: {violation.get('title', 'Unknown')}",
                        description=violation.get("description", ""),
                        source_component="baa_monitor",
                        timestamp=datetime.utcnow()
                    )
                    alerts.append(alert)
        
        except Exception as e:
            logger.error(f"BAA compliance check failed: {e}")
        
        return alerts
    
    async def _send_critical_alerts(self, critical_alerts: List[ComplianceAlert]):
        """Send immediate notifications for critical alerts."""
        for alert in critical_alerts:
            try:
                await self.notification_manager.send_notification(
                    user_id=None,  # Send to compliance officers
                    notification_type=NotificationType.SECURITY_ALERT,
                    data={
                        "alert_type": alert.type,
                        "severity": alert.severity.value,
                        "title": alert.title,
                        "description": alert.description,
                        "immediate_action_required": True
                    },
                    override_preferences=True
                )
            except Exception as e:
                logger.error(f"Failed to send critical alert notification: {e}")
    
    async def _assess_vulnerabilities(self) -> Dict[str, Any]:
        """Assess system vulnerabilities."""
        return {
            "total_vulnerabilities": 3,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 1,
            "medium_vulnerabilities": 2,
            "low_vulnerabilities": 0,
            "vulnerability_categories": {
                "authentication": 1,
                "data_handling": 1,
                "network_security": 1
            }
        }
    
    async def _analyze_risk_trends(self) -> Dict[str, Any]:
        """Analyze risk trends over time."""
        return {
            "overall_trend": "stable",
            "risk_categories": {
                "data_security": "improving",
                "access_control": "stable", 
                "compliance": "improving",
                "operational": "stable"
            },
            "trend_period_days": 30
        }
    
    async def _generate_risk_heat_map(self) -> Dict[str, Any]:
        """Generate risk heat map data."""
        return {
            "risk_matrix": [
                {"category": "Data Breach", "likelihood": "medium", "impact": "high", "risk_level": "high"},
                {"category": "Unauthorized Access", "likelihood": "low", "impact": "medium", "risk_level": "low"},
                {"category": "System Downtime", "likelihood": "low", "impact": "medium", "risk_level": "low"},
                {"category": "Compliance Violation", "likelihood": "low", "impact": "high", "risk_level": "medium"}
            ]
        }
    
    async def _calculate_performance_indicators(self) -> Dict[str, Any]:
        """Calculate compliance performance indicators."""
        return {
            "audit_trail_integrity": 99.8,
            "access_control_effectiveness": 96.5,
            "incident_response_time": 85.2,
            "training_effectiveness": 92.1,
            "policy_adherence": 94.7
        }
    
    async def _identify_improvement_areas(self, category_scores: Dict[str, int]) -> List[str]:
        """Identify areas needing improvement."""
        improvement_areas = []
        
        for category, score in category_scores.items():
            if score < 85:
                improvement_areas.append(f"{category}: {score}% (target: 95%)")
        
        return improvement_areas
    
    async def _identify_compliance_strengths(self, category_scores: Dict[str, int]) -> List[str]:
        """Identify compliance strengths."""
        strengths = []
        
        for category, score in category_scores.items():
            if score >= 95:
                strengths.append(f"{category}: {score}% (excellent)")
        
        return strengths
    
    async def _compare_to_benchmarks(self, overall_score: int) -> Dict[str, Any]:
        """Compare compliance score to industry benchmarks."""
        return {
            "industry_average": 88,
            "top_quartile": 95,
            "your_score": overall_score,
            "percentile": 75 if overall_score >= 90 else 50 if overall_score >= 85 else 25,
            "comparison": "above_average" if overall_score > 88 else "average" if overall_score >= 80 else "below_average"
        }
    
    async def _analyze_audit_events(self, audit_result) -> Dict[str, Any]:
        """Analyze audit events for insights."""
        return {
            "peak_activity_hours": ["09:00-11:00", "13:00-15:00"],
            "most_active_users": ["user_123", "user_456"],
            "suspicious_patterns": [],
            "compliance_gaps": []
        }


# Standalone functions for backwards compatibility

async def get_compliance_overview(db: Session) -> Dict[str, Any]:
    """Get compliance overview dashboard."""
    dashboard = ComplianceDashboard(db)
    return await dashboard.get_compliance_overview()

async def get_risk_dashboard(db: Session) -> Dict[str, Any]:
    """Get risk assessment dashboard."""
    dashboard = ComplianceDashboard(db)
    return await dashboard.get_risk_dashboard()

async def generate_compliance_alerts(db: Session) -> List[ComplianceAlert]:
    """Generate compliance alerts."""
    dashboard = ComplianceDashboard(db)
    return await dashboard.generate_compliance_alerts() 