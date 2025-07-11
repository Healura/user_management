"""
HIPAA Compliance API Endpoints

REST API endpoints for HIPAA compliance monitoring, risk assessment,
incident response, and automated reporting functionality.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Path
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_user_dependency, CurrentUser
from src.auth.authorization import RoleChecker
from src.database.database import get_db
from src.database.models import User

# Import compliance modules
from src.security.compliance_checker import run_compliance_check, HIPAAComplianceChecker
from src.security.breach_detection import run_threat_detection, HealthcareThreatDetector
from src.security.risk_assessment import run_risk_assessment, HealthcareRiskAssessment
from src.security.baa_compliance import run_baa_compliance_check, BAAComplianceMonitor
from src.compliance.hipaa_audit import run_hipaa_audit, HIPAAAuditManager
from src.compliance.retention_manager import run_retention_enforcement, RetentionManager
from src.compliance.incident_response import run_incident_response, IncidentResponseManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/compliance", tags=["HIPAA Compliance"])


# Request/Response Models
class ComplianceStatusResponse(BaseModel):
    overall_compliance_score: int
    compliance_status: str
    total_violations: int
    violations_by_severity: Dict[str, int]
    last_assessment: str
    risk_level: str
    next_assessment_due: str


class ViolationResponse(BaseModel):
    violation_id: str
    violation_type: str
    severity: str
    title: str
    description: str
    affected_resource: Optional[str]
    remediation_steps: List[str]
    auto_remediable: bool


class RiskAssessmentResponse(BaseModel):
    assessment_id: str
    overall_risk_score: int
    risk_level: str
    trend: str
    high_risk_areas: List[str]
    mitigation_recommendations: List[str]
    confidence_score: float
    assessment_duration_seconds: float


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Incident description")
    category: str = Field(..., description="Incident category")
    severity: str = Field(..., description="Incident severity")
    phi_involved: bool = Field(False, description="Whether PHI is involved")
    affected_systems: List[str] = Field(default_factory=list, description="Affected systems")


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    description: str
    category: str
    severity: str
    status: str
    detected_date: str
    phi_involved: bool
    affected_systems: List[str]


class RemediationRequest(BaseModel):
    violation_ids: List[str] = Field(..., description="Violation IDs to remediate")
    action_type: str = Field(..., description="Type of remediation action")
    approval_required: bool = Field(True, description="Whether approval is required")


# HIPAA Compliance Monitoring Endpoints

@router.get("/status", response_model=ComplianceStatusResponse)
async def get_compliance_status(
    user_id: Optional[UUID] = Query(None, description="Filter by specific user"),
    current_user: User = Depends(require_role(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Get current HIPAA compliance status."""
    try:
        logger.info(f"Compliance status requested by user {current_user.id}")
        
        # Run comprehensive compliance check
        compliance_result = await run_compliance_check(db, user_id)
        
        return ComplianceStatusResponse(
            overall_compliance_score=compliance_result["compliance_score"]["total_score"],
            compliance_status=compliance_result["compliance_score"]["risk_level"],
            total_violations=compliance_result["total_violations"],
            violations_by_severity=compliance_result["violations_by_severity"],
            last_assessment=compliance_result["assessment_timestamp"],
            risk_level=compliance_result["compliance_score"]["risk_level"],
            next_assessment_due=(datetime.utcnow() + timedelta(hours=24)).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Compliance status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Compliance status check failed: {str(e)}")


@router.get("/score", response_model=Dict[str, Any])
async def get_compliance_score(
    detailed: bool = Query(False, description="Include detailed scoring breakdown"),
    current_user: User = Depends(require_role(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Get real-time compliance score with optional detailed breakdown."""
    try:
        compliance_checker = HIPAAComplianceChecker(db)
        compliance_result = await compliance_checker.perform_comprehensive_compliance_check()
        
        response = {
            "total_score": compliance_result["compliance_score"]["total_score"],
            "risk_level": compliance_result["compliance_score"]["risk_level"],
            "trending": compliance_result["compliance_score"]["trending"],
            "last_updated": datetime.utcnow().isoformat()
        }
        
        if detailed:
            response.update({
                "category_scores": compliance_result["compliance_score"]["category_scores"],
                "violations_count": compliance_result["total_violations"],
                "detailed_results": compliance_result["detailed_results"]
            })
        
        return response
        
    except Exception as e:
        logger.error(f"Compliance score retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Compliance score retrieval failed: {str(e)}")


@router.get("/violations", response_model=List[ViolationResponse])
async def get_compliance_violations(
    severity: Optional[str] = Query(None, description="Filter by violation severity"),
    violation_type: Optional[str] = Query(None, description="Filter by violation type"),
    auto_remediable_only: bool = Query(False, description="Show only auto-remediable violations"),
    current_user: User = Depends(require_role(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Get active compliance violations with filtering options."""
    try:
        compliance_result = await run_compliance_check(db)
        violations = []
        
        for result in compliance_result["detailed_results"].values():
            if "violations" in result:
                for violation in result["violations"]:
                    # Apply filters
                    if severity and violation.severity.value != severity:
                        continue
                    if violation_type and violation.violation_type.value != violation_type:
                        continue
                    if auto_remediable_only and not violation.auto_remediable:
                        continue
                    
                    violations.append(ViolationResponse(
                        violation_id=violation.id,
                        violation_type=violation.violation_type.value,
                        severity=violation.severity.value,
                        title=violation.title,
                        description=violation.description,
                        affected_resource=violation.affected_resource,
                        remediation_steps=violation.remediation_steps,
                        auto_remediable=violation.auto_remediable
                    ))
        
        return violations
        
    except Exception as e:
        logger.error(f"Violations retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Violations retrieval failed: {str(e)}")


@router.post("/remediate")
async def execute_remediation(
    request: RemediationRequest,
    current_user: User = Depends(require_role(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Execute automated remediation actions for compliance violations."""
    try:
        logger.info(f"Remediation requested by user {current_user.id} for violations: {request.violation_ids}")
        
        # In production, this would implement actual remediation logic
        remediation_results = []
        
        for violation_id in request.violation_ids:
            # Simulate remediation action
            result = {
                "violation_id": violation_id,
                "action_type": request.action_type,
                "status": "scheduled" if request.approval_required else "executed",
                "timestamp": datetime.utcnow().isoformat(),
                "success": True,
                "message": f"Remediation action {request.action_type} {'scheduled' if request.approval_required else 'executed'}"
            }
            remediation_results.append(result)
        
        return {
            "remediation_id": f"REM_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "total_violations": len(request.violation_ids),
            "successful_remediations": len([r for r in remediation_results if r["success"]]),
            "results": remediation_results
        }
        
    except Exception as e:
        logger.error(f"Remediation execution failed: {e}")
        raise HTTPException(status_code=500, detail=f"Remediation execution failed: {str(e)}")


# Risk Assessment Endpoints

@router.get("/risk-assessment", response_model=RiskAssessmentResponse)
async def get_risk_assessment(
    user_id: Optional[UUID] = Query(None, description="Focus assessment on specific user"),
    include_historical: bool = Query(True, description="Include historical trend analysis"),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """Get current risk assessment with trending analysis."""
    try:
        logger.info(f"Risk assessment requested by user {current_user.id}")
        
        risk_assessment = await run_risk_assessment(db, user_id, include_historical)
        
        return RiskAssessmentResponse(
            assessment_id=risk_assessment.assessment_id,
            overall_risk_score=risk_assessment.overall_risk_score,
            risk_level=risk_assessment.risk_level.value,
            trend=risk_assessment.trend,
            high_risk_areas=risk_assessment.high_risk_areas,
            mitigation_recommendations=risk_assessment.mitigation_recommendations,
            confidence_score=risk_assessment.confidence_score,
            assessment_duration_seconds=risk_assessment.assessment_duration_seconds
        )
        
    except Exception as e:
        logger.error(f"Risk assessment failed: {e}")
        raise HTTPException(status_code=500, detail=f"Risk assessment failed: {str(e)}")


@router.post("/risk/update")
async def update_risk_factors(
    risk_factors: Dict[str, Any] = Body(..., description="Updated risk factor values"),
    current_user: User = Depends(require_role(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Update risk factors and recalculate risk assessment."""
    try:
        logger.info(f"Risk factors update requested by user {current_user.id}")
        
        # In production, this would update risk factor configurations
        risk_assessor = HealthcareRiskAssessment(db)
        
        # Trigger new assessment with updated factors
        updated_assessment = await risk_assessor.perform_comprehensive_risk_assessment()
        
        return {
            "update_id": f"RUP_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "updated_factors": list(risk_factors.keys()),
            "new_risk_score": updated_assessment.overall_risk_score,
            "risk_level": updated_assessment.risk_level.value,
            "update_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Risk factors update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Risk factors update failed: {str(e)}")


@router.get("/risk/trends")
async def get_risk_trends(
    days: int = Query(30, description="Number of days to analyze", ge=1, le=365),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """Get risk trending over time."""
    try:
        # In production, this would query historical risk assessments
        risk_trends = {
            "period_days": days,
            "trend_direction": "stable",
            "average_risk_score": 65,
            "risk_score_variance": 5.2,
            "trend_data": [
                {
                    "date": (datetime.utcnow() - timedelta(days=i)).date().isoformat(),
                    "risk_score": 65 + (i % 10) - 5,
                    "risk_level": "medium"
                }
                for i in range(days)
            ],
            "key_risk_factors": [
                "access_control_violations",
                "data_encryption_gaps",
                "audit_log_completeness"
            ]
        }
        
        return risk_trends
        
    except Exception as e:
        logger.error(f"Risk trends retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Risk trends retrieval failed: {str(e)}")


# Incident Response Endpoints

@router.post("/incident", response_model=IncidentResponse)
async def create_incident(
    request: IncidentCreateRequest,
    current_user: User = Depends(require_role(["admin", "compliance_officer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """Report and create a new security incident."""
    try:
        logger.info(f"Security incident reported by user {current_user.id}: {request.title}")
        
        incident_manager = IncidentResponseManager(db)
        
        # Convert category and severity strings to enums
        from src.compliance.incident_response import IncidentCategory, IncidentSeverity
        
        try:
            category = IncidentCategory(request.category.lower())
            severity = IncidentSeverity(request.severity.lower())
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid category or severity: {str(e)}")
        
        incident = await incident_manager.create_incident(
            title=request.title,
            description=request.description,
            category=category,
            severity=severity,
            phi_involved=request.phi_involved,
            affected_systems=request.affected_systems,
            reporter_id=current_user.id
        )
        
        return IncidentResponse(
            incident_id=incident.incident_id,
            title=incident.title,
            description=incident.description,
            category=incident.category.value,
            severity=incident.severity.value,
            status=incident.status.value,
            detected_date=incident.detected_date.isoformat(),
            phi_involved=incident.phi_involved,
            affected_systems=incident.affected_systems
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Incident creation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Incident creation failed: {str(e)}")


@router.get("/incidents")
async def list_incidents(
    status: Optional[str] = Query(None, description="Filter by incident status"),
    severity: Optional[str] = Query(None, description="Filter by incident severity"),
    days: int = Query(30, description="Number of days to look back", ge=1, le=365),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """List security incidents with filtering options."""
    try:
        incidents_result = await run_incident_response(db, action="list")
        
        # Apply filters
        filtered_incidents = incidents_result["active_incidents"]
        
        if status:
            filtered_incidents = [i for i in filtered_incidents if i.get("status") == status]
        
        if severity:
            filtered_incidents = [i for i in filtered_incidents if i.get("severity") == severity]
        
        return {
            "total_incidents": len(filtered_incidents),
            "incidents": filtered_incidents,
            "filter_criteria": {
                "status": status,
                "severity": severity,
                "days": days
            }
        }
        
    except Exception as e:
        logger.error(f"Incidents listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Incidents listing failed: {str(e)}")


@router.put("/incident/{incident_id}/status")
async def update_incident_status(
    incident_id: str = Path(..., description="Incident ID"),
    status: str = Body(..., description="New incident status", embed=True),
    notes: Optional[str] = Body(None, description="Status update notes", embed=True),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    """Update incident status."""
    try:
        incident_manager = IncidentResponseManager(db)
        
        # Convert status string to enum
        from src.compliance.incident_response import ResponseStatus
        try:
            response_status = ResponseStatus(status.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        
        incident = await incident_manager.update_incident_status(
            incident_id=incident_id,
            status=response_status,
            notes=notes
        )
        
        return {
            "incident_id": incident_id,
            "old_status": incident.status.value,
            "new_status": status,
            "updated_by": str(current_user.id),
            "update_timestamp": datetime.utcnow().isoformat(),
            "notes": notes
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Incident status update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Incident status update failed: {str(e)}")


# Audit and Reporting Endpoints

@router.get("/audit/trail")
async def get_audit_trail(
    start_date: datetime = Query(..., description="Audit trail start date"),
    end_date: datetime = Query(..., description="Audit trail end date"),
    user_id: Optional[UUID] = Query(None, description="Filter by specific user"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "auditor"])),
    db: Session = Depends(get_db)
):
    """Get HIPAA audit trail for specified period."""
    try:
        logger.info(f"Audit trail requested by user {current_user.id} for period {start_date} to {end_date}")
        
        audit_report = await run_hipaa_audit(db, start_date, end_date, user_id)
        
        return {
            "report_id": audit_report.report_id,
            "period_start": audit_report.report_period_start.isoformat(),
            "period_end": audit_report.report_period_end.isoformat(),
            "total_events": audit_report.total_events,
            "events_by_type": audit_report.events_by_type,
            "events_by_user": audit_report.events_by_user,
            "compliance_status": audit_report.compliance_status.value,
            "compliance_score": audit_report.compliance_score,
            "integrity_verification": audit_report.integrity_verification,
            "recommendations": audit_report.recommendations
        }
        
    except Exception as e:
        logger.error(f"Audit trail retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit trail retrieval failed: {str(e)}")


@router.get("/audit/integrity")
async def verify_audit_integrity(
    start_date: Optional[datetime] = Query(None, description="Start date for integrity check"),
    end_date: Optional[datetime] = Query(None, description="End date for integrity check"),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "auditor"])),
    db: Session = Depends(get_db)
):
    """Verify audit log integrity and detect tampering."""
    try:
        # Default to last 7 days if dates not provided
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=7)
        if not end_date:
            end_date = datetime.utcnow()
        
        audit_manager = HIPAAAuditManager(db)
        audit_events = await audit_manager._gather_audit_events(start_date, end_date)
        integrity_result = await audit_manager._verify_audit_integrity(audit_events)
        
        return {
            "check_id": integrity_result.check_id,
            "check_timestamp": integrity_result.timestamp.isoformat(),
            "total_logs_checked": integrity_result.total_logs_checked,
            "integrity_score": integrity_result.overall_integrity_score,
            "hash_verification_passed": integrity_result.hash_verification_passed,
            "sequential_verification_passed": integrity_result.sequential_verification_passed,
            "cross_system_correlation_passed": integrity_result.cross_system_correlation_passed,
            "violations_count": len(integrity_result.integrity_violations),
            "violations": integrity_result.integrity_violations
        }
        
    except Exception as e:
        logger.error(f"Audit integrity verification failed: {e}")
        raise HTTPException(status_code=500, detail=f"Audit integrity verification failed: {str(e)}")


# Data Retention Endpoints

@router.get("/retention/status")
async def get_retention_status(
    data_category: Optional[str] = Query(None, description="Filter by data category"),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "data_protection_officer"])),
    db: Session = Depends(get_db)
):
    """Get data retention compliance status."""
    try:
        retention_result = await run_retention_enforcement(db, dry_run=True)
        
        return {
            "assessment_id": retention_result.get("assessment_id"),
            "total_records": retention_result.get("total_records_assessed", 0),
            "eligible_for_deletion": retention_result.get("total_eligible_for_deletion", 0),
            "approaching_retention": retention_result.get("total_approaching_retention", 0),
            "storage_savings_gb": retention_result.get("storage_savings_potential_gb", 0),
            "compliance_summary": retention_result.get("compliance_summary", {}),
            "recommendations": retention_result.get("recommendations", [])
        }
        
    except Exception as e:
        logger.error(f"Retention status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Retention status check failed: {str(e)}")


@router.post("/retention/enforce")
async def enforce_retention_policy(
    policy_id: Optional[str] = Body(None, description="Specific policy to enforce"),
    dry_run: bool = Body(True, description="Whether to perform actual deletions"),
    current_user: User = Depends(require_role(["admin", "data_protection_officer"])),
    db: Session = Depends(get_db)
):
    """Enforce data retention policies."""
    try:
        logger.info(f"Retention enforcement requested by user {current_user.id} (dry_run={dry_run})")
        
        if not dry_run:
            # Require additional confirmation for actual deletions
            logger.warning(f"ACTUAL DELETION requested by user {current_user.id}")
        
        enforcement_result = await run_retention_enforcement(db, policy_id, dry_run)
        
        return {
            "enforcement_id": f"ENF_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "policy_id": policy_id,
            "dry_run": dry_run,
            "enforcement_result": enforcement_result,
            "executed_by": str(current_user.id),
            "execution_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Retention enforcement failed: {e}")
        raise HTTPException(status_code=500, detail=f"Retention enforcement failed: {str(e)}")


# Business Associate Agreement Endpoints

@router.get("/baa/status")
async def get_baa_compliance_status(
    business_associate_id: Optional[str] = Query(None, description="Specific business associate"),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "privacy_officer"])),
    db: Session = Depends(get_db)
):
    """Get Business Associate Agreement compliance status."""
    try:
        baa_result = await run_baa_compliance_check(db, business_associate_id)
        
        return {
            "assessment_timestamp": baa_result["assessment_timestamp"],
            "total_associates": baa_result["total_associates_assessed"],
            "compliant_associates": baa_result["compliant_associates"],
            "non_compliant_associates": baa_result["non_compliant_associates"],
            "expired_baas": baa_result["expired_baas"],
            "critical_violations": baa_result["critical_violations"],
            "compliance_rate": (baa_result["compliant_associates"] / max(baa_result["total_associates_assessed"], 1)) * 100,
            "recommendations": baa_result["recommendations"]
        }
        
    except Exception as e:
        logger.error(f"BAA compliance check failed: {e}")
        raise HTTPException(status_code=500, detail=f"BAA compliance check failed: {str(e)}")


# Threat Detection Endpoints

@router.get("/threats/scan")
async def run_threat_scan(
    lookback_hours: int = Query(1, description="Hours to look back for threats", ge=1, le=168),
    user_id: Optional[UUID] = Query(None, description="Focus scan on specific user"),
    current_user: User = Depends(require_role(["admin", "security_analyst", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Run comprehensive threat detection scan."""
    try:
        logger.info(f"Threat detection scan requested by user {current_user.id}")
        
        threat_result = await run_threat_detection(db, lookback_hours, user_id)
        
        return {
            "scan_timestamp": threat_result["scan_timestamp"],
            "scan_period_hours": threat_result["scan_period_hours"],
            "total_incidents": threat_result["total_incidents"],
            "incidents_by_severity": threat_result["incidents_by_severity"],
            "incidents_by_type": threat_result["incidents_by_type"],
            "high_priority_incidents": len(threat_result["high_priority_incidents"]),
            "automated_responses": threat_result["automated_responses"],
            "recommendations": threat_result["recommendations"]
        }
        
    except Exception as e:
        logger.error(f"Threat detection scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Threat detection scan failed: {str(e)}")


# Report Generation Endpoints

@router.get("/reports/compliance")
async def generate_compliance_report(
    report_type: str = Query("comprehensive", description="Type of compliance report"),
    start_date: Optional[datetime] = Query(None, description="Report start date"),
    end_date: Optional[datetime] = Query(None, description="Report end date"),
    include_recommendations: bool = Query(True, description="Include recommendations"),
    current_user: User = Depends(require_role(["admin", "compliance_officer", "auditor"])),
    db: Session = Depends(get_db)
):
    """Generate comprehensive compliance report."""
    try:
        logger.info(f"Compliance report generation requested by user {current_user.id}")
        
        # Default to last 30 days if dates not provided
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
        # Run all assessments in parallel
        assessment_results = await asyncio.gather(
            run_compliance_check(db),
            run_risk_assessment(db, include_historical=True),
            run_hipaa_audit(db, start_date, end_date),
            run_threat_detection(db, lookback_hours=24),
            return_exceptions=True
        )
        
        compliance_result, risk_result, audit_result, threat_result = assessment_results
        
        # Generate comprehensive report
        report = {
            "report_id": f"COMP_RPT_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            "report_type": report_type,
            "generated_date": datetime.utcnow().isoformat(),
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "generated_by": str(current_user.id),
            "executive_summary": {
                "overall_compliance_score": compliance_result.get("compliance_score", {}).get("total_score", 0) if not isinstance(compliance_result, Exception) else 0,
                "overall_risk_score": risk_result.overall_risk_score if not isinstance(risk_result, Exception) else 0,
                "total_violations": compliance_result.get("total_violations", 0) if not isinstance(compliance_result, Exception) else 0,
                "security_incidents": threat_result.get("total_incidents", 0) if not isinstance(threat_result, Exception) else 0,
                "audit_compliance": audit_result.compliance_status.value if not isinstance(audit_result, Exception) else "unknown"
            },
            "detailed_assessments": {
                "compliance_check": compliance_result if not isinstance(compliance_result, Exception) else {"error": str(compliance_result)},
                "risk_assessment": risk_result.__dict__ if not isinstance(risk_result, Exception) else {"error": str(risk_result)},
                "audit_analysis": audit_result.__dict__ if not isinstance(audit_result, Exception) else {"error": str(audit_result)},
                "threat_detection": threat_result if not isinstance(threat_result, Exception) else {"error": str(threat_result)}
            }
        }
        
        if include_recommendations:
            recommendations = []
            if not isinstance(compliance_result, Exception):
                recommendations.extend(compliance_result.get("recommendations", []))
            if not isinstance(risk_result, Exception):
                recommendations.extend(risk_result.mitigation_recommendations)
            if not isinstance(threat_result, Exception):
                recommendations.extend(threat_result.get("recommendations", []))
            
            report["recommendations"] = list(set(recommendations))  # Remove duplicates
        
        return report
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Compliance report generation failed: {str(e)}")


# Health Check Endpoint

@router.get("/health")
async def compliance_health_check(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Check health of compliance monitoring systems."""
    try:
        health_status = {
            "compliance_monitoring": "operational",
            "risk_assessment": "operational",
            "threat_detection": "operational",
            "audit_logging": "operational",
            "incident_response": "operational",
            "last_check": datetime.utcnow().isoformat(),
            "overall_status": "healthy"
        }
        
        # In production, this would check actual system health
        
        return health_status
        
    except Exception as e:
        logger.error(f"Compliance health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Compliance health check failed: {str(e)}") 