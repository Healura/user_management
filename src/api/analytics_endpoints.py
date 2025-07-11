"""
Healthcare Analytics API Endpoints

De-identified healthcare analytics and reporting API for clinical insights,
usage analytics, and quality assurance reporting while protecting PHI.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Body, Path, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.auth.dependencies import get_current_user, require_role
from src.auth.authorization import RoleChecker
from src.database.database import get_db
from src.database.models import User

# Import analytics services
from src.admin.analytics_service import HealthcareAnalyticsService
from src.security.data_anonymization import anonymize_for_analytics

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/analytics", tags=["Healthcare Analytics"])


# Request/Response Models
class AnalyticsQuery(BaseModel):
    """Request model for analytics queries"""
    metric: str = Field(..., description="Metric to analyze")
    start_date: datetime = Field(..., description="Analysis start date")
    end_date: datetime = Field(..., description="Analysis end date")
    granularity: str = Field(default="day", description="Time granularity: hour, day, week, month")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Analysis filters")
    anonymization_level: str = Field(default="safe_harbor", description="Anonymization level")

class UsageAnalyticsResponse(BaseModel):
    """Response model for usage analytics"""
    period: Dict[str, str]
    total_users: int
    active_users: int
    new_registrations: int
    session_statistics: Dict[str, Any]
    feature_usage: Dict[str, Any]
    geographic_distribution: Dict[str, Any]
    device_analytics: Dict[str, Any]
    performance_metrics: Dict[str, Any]

class ClinicalAnalyticsResponse(BaseModel):
    """Response model for clinical analytics"""
    period: Dict[str, str]
    analysis_volume: Dict[str, Any]
    outcome_trends: Dict[str, Any]
    quality_metrics: Dict[str, Any]
    provider_statistics: Dict[str, Any]
    patient_demographics: Dict[str, Any]
    clinical_insights: Dict[str, Any]

class ComplianceMetricsResponse(BaseModel):
    """Response model for compliance analytics"""
    period: Dict[str, str]
    compliance_score_trend: List[Dict[str, Any]]
    violation_analytics: Dict[str, Any]
    audit_completion_rate: float
    incident_statistics: Dict[str, Any]
    risk_assessment_trends: Dict[str, Any]
    training_completion: Dict[str, Any]

class QualityAssuranceResponse(BaseModel):
    """Response model for quality assurance metrics"""
    period: Dict[str, str]
    system_performance: Dict[str, Any]
    data_quality_metrics: Dict[str, Any]
    error_analytics: Dict[str, Any]
    user_satisfaction: Dict[str, Any]
    service_availability: Dict[str, Any]

class ExportRequest(BaseModel):
    """Request model for analytics data export"""
    report_type: str = Field(..., description="Type of report to export")
    format: str = Field(default="csv", description="Export format: csv, excel, json, pdf")
    start_date: datetime = Field(..., description="Export start date")
    end_date: datetime = Field(..., description="Export end date")
    include_charts: bool = Field(default=True, description="Include charts in export")
    anonymization_level: str = Field(default="safe_harbor", description="Anonymization level")


# Usage Analytics Endpoints

@router.get("/usage", response_model=UsageAnalyticsResponse)
async def get_usage_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    granularity: str = Query("day", description="Time granularity"),
    facility_id: Optional[str] = Query(None, description="Filter by facility"),
    user_type: Optional[str] = Query(None, description="Filter by user type"),
    current_user: User = Depends(RoleChecker(["admin", "analytics_viewer"])),
    db: Session = Depends(get_db)
):
    """Get de-identified system usage analytics."""
    try:
        logger.info(f"Usage analytics requested by user {current_user.id}")
        
        analytics_service = HealthcareAnalyticsService(db)
        usage_data = await analytics_service.get_usage_analytics(
            start_date=start_date,
            end_date=end_date,
            granularity=granularity,
            facility_filter=facility_id,
            user_type_filter=user_type,
            requesting_user_id=current_user.id
        )
        
        # Anonymize sensitive data
        anonymized_data = await anonymize_for_analytics(
            data=usage_data,
            purpose="usage_analytics",
            compliance_level="safe_harbor"
        )
        
        return UsageAnalyticsResponse(**anonymized_data["anonymized_data"])
        
    except Exception as e:
        logger.error(f"Usage analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Usage analytics failed: {str(e)}")

@router.get("/usage/trends")
async def get_usage_trends(
    metric: str = Query(..., description="Metric to trend"),
    days: int = Query(30, ge=1, le=365, description="Days to analyze"),
    comparison_period: bool = Query(True, description="Include comparison period"),
    current_user: User = Depends(RoleChecker(["admin", "analytics_viewer"])),
    db: Session = Depends(get_db)
):
    """Get usage trend analysis."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        trends = await analytics_service.get_usage_trends(
            metric=metric,
            days=days,
            include_comparison=comparison_period,
            requesting_user_id=current_user.id
        )
        
        return trends
        
    except Exception as e:
        logger.error(f"Usage trends analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Usage trends analysis failed: {str(e)}")

@router.get("/usage/cohorts")
async def get_user_cohort_analysis(
    cohort_type: str = Query("registration", description="Type of cohort analysis"),
    start_date: datetime = Query(..., description="Cohort start date"),
    end_date: datetime = Query(..., description="Cohort end date"),
    current_user: User = Depends(RoleChecker(["admin", "analytics_viewer"])),
    db: Session = Depends(get_db)
):
    """Get user cohort analysis."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        cohorts = await analytics_service.get_cohort_analysis(
            cohort_type=cohort_type,
            start_date=start_date,
            end_date=end_date,
            requesting_user_id=current_user.id
        )
        
        return cohorts
        
    except Exception as e:
        logger.error(f"Cohort analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cohort analysis failed: {str(e)}")


# Clinical Analytics Endpoints

@router.get("/clinical", response_model=ClinicalAnalyticsResponse)
async def get_clinical_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    specialization: Optional[str] = Query(None, description="Filter by provider specialization"),
    facility_id: Optional[str] = Query(None, description="Filter by facility"),
    current_user: User = Depends(RoleChecker(["admin", "clinical_analyst", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """Get de-identified clinical outcome analytics."""
    try:
        logger.info(f"Clinical analytics requested by user {current_user.id}")
        
        analytics_service = HealthcareAnalyticsService(db)
        clinical_data = await analytics_service.get_clinical_analytics(
            start_date=start_date,
            end_date=end_date,
            specialization_filter=specialization,
            facility_filter=facility_id,
            requesting_user_id=current_user.id
        )
        
        # Apply clinical data anonymization
        anonymized_data = await anonymize_for_analytics(
            data=clinical_data,
            purpose="clinical_research",
            compliance_level="expert_determination"
        )
        
        return ClinicalAnalyticsResponse(**anonymized_data["anonymized_data"])
        
    except Exception as e:
        logger.error(f"Clinical analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Clinical analytics failed: {str(e)}")

@router.get("/clinical/outcomes")
async def get_outcome_analysis(
    outcome_metric: str = Query(..., description="Outcome metric to analyze"),
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    risk_adjustment: bool = Query(True, description="Apply risk adjustment"),
    current_user: User = Depends(RoleChecker(["admin", "clinical_analyst", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """Get clinical outcome analysis."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        outcomes = await analytics_service.get_outcome_analysis(
            metric=outcome_metric,
            start_date=start_date,
            end_date=end_date,
            risk_adjusted=risk_adjustment,
            requesting_user_id=current_user.id
        )
        
        return outcomes
        
    except Exception as e:
        logger.error(f"Outcome analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Outcome analysis failed: {str(e)}")

@router.get("/clinical/quality")
async def get_quality_metrics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    quality_measure: Optional[str] = Query(None, description="Specific quality measure"),
    current_user: User = Depends(RoleChecker(["admin", "quality_analyst", "healthcare_provider"])),
    db: Session = Depends(get_db)
):
    """Get clinical quality metrics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        quality_data = await analytics_service.get_quality_metrics(
            start_date=start_date,
            end_date=end_date,
            measure_filter=quality_measure,
            requesting_user_id=current_user.id
        )
        
        return quality_data
        
    except Exception as e:
        logger.error(f"Quality metrics analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Quality metrics analysis failed: {str(e)}")

@router.get("/clinical/population")
async def get_population_health_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    geographic_level: str = Query("state", description="Geographic aggregation level"),
    demographic_breakdown: bool = Query(True, description="Include demographic breakdown"),
    current_user: User = Depends(RoleChecker(["admin", "population_health_analyst"])),
    db: Session = Depends(get_db)
):
    """Get population health analytics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        population_data = await analytics_service.get_population_health_analytics(
            start_date=start_date,
            end_date=end_date,
            geographic_level=geographic_level,
            include_demographics=demographic_breakdown,
            requesting_user_id=current_user.id
        )
        
        return population_data
        
    except Exception as e:
        logger.error(f"Population health analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Population health analytics failed: {str(e)}")


# Compliance Analytics Endpoints

@router.get("/compliance", response_model=ComplianceMetricsResponse)
async def get_compliance_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    compliance_area: Optional[str] = Query(None, description="Specific compliance area"),
    current_user: User = Depends(RoleChecker(["admin", "compliance_officer", "auditor"])),
    db: Session = Depends(get_db)
):
    """Get compliance performance analytics."""
    try:
        logger.info(f"Compliance analytics requested by user {current_user.id}")
        
        analytics_service = HealthcareAnalyticsService(db)
        compliance_data = await analytics_service.get_compliance_analytics(
            start_date=start_date,
            end_date=end_date,
            area_filter=compliance_area,
            requesting_user_id=current_user.id
        )
        
        return ComplianceMetricsResponse(**compliance_data)
        
    except Exception as e:
        logger.error(f"Compliance analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Compliance analytics failed: {str(e)}")

@router.get("/compliance/violations")
async def get_violation_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    violation_type: Optional[str] = Query(None, description="Filter by violation type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    current_user: User = Depends(RoleChecker(["admin", "compliance_officer"])),
    db: Session = Depends(get_db)
):
    """Get compliance violation analytics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        violations = await analytics_service.get_violation_analytics(
            start_date=start_date,
            end_date=end_date,
            type_filter=violation_type,
            severity_filter=severity,
            requesting_user_id=current_user.id
        )
        
        return violations
        
    except Exception as e:
        logger.error(f"Violation analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Violation analytics failed: {str(e)}")

@router.get("/compliance/training")
async def get_training_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    training_type: Optional[str] = Query(None, description="Filter by training type"),
    current_user: User = Depends(RoleChecker(["admin", "training_manager"])),
    db: Session = Depends(get_db)
):
    """Get compliance training analytics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        training_data = await analytics_service.get_training_analytics(
            start_date=start_date,
            end_date=end_date,
            type_filter=training_type,
            requesting_user_id=current_user.id
        )
        
        return training_data
        
    except Exception as e:
        logger.error(f"Training analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Training analytics failed: {str(e)}")


# Quality Assurance Analytics

@router.get("/quality", response_model=QualityAssuranceResponse)
async def get_quality_assurance_metrics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    metric_category: Optional[str] = Query(None, description="Filter by metric category"),
    current_user: User = Depends(RoleChecker(["admin", "quality_analyst"])),
    db: Session = Depends(get_db)
):
    """Get quality assurance metrics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        quality_data = await analytics_service.get_quality_assurance_metrics(
            start_date=start_date,
            end_date=end_date,
            category_filter=metric_category,
            requesting_user_id=current_user.id
        )
        
        return QualityAssuranceResponse(**quality_data)
        
    except Exception as e:
        logger.error(f"Quality assurance analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Quality assurance analytics failed: {str(e)}")

@router.get("/quality/performance")
async def get_performance_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    service_component: Optional[str] = Query(None, description="Filter by service component"),
    current_user: User = Depends(RoleChecker(["admin", "performance_analyst"])),
    db: Session = Depends(get_db)
):
    """Get system performance analytics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        performance_data = await analytics_service.get_performance_analytics(
            start_date=start_date,
            end_date=end_date,
            component_filter=service_component,
            requesting_user_id=current_user.id
        )
        
        return performance_data
        
    except Exception as e:
        logger.error(f"Performance analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Performance analytics failed: {str(e)}")

@router.get("/quality/errors")
async def get_error_analytics(
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    error_category: Optional[str] = Query(None, description="Filter by error category"),
    current_user: User = Depends(RoleChecker(["admin", "technical_analyst"])),
    db: Session = Depends(get_db)
):
    """Get error and incident analytics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        error_data = await analytics_service.get_error_analytics(
            start_date=start_date,
            end_date=end_date,
            category_filter=error_category,
            requesting_user_id=current_user.id
        )
        
        return error_data
        
    except Exception as e:
        logger.error(f"Error analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Error analytics failed: {str(e)}")


# Custom Analytics and Reporting

@router.post("/custom")
async def run_custom_analytics(
    query: AnalyticsQuery,
    current_user: User = Depends(RoleChecker(["admin", "data_analyst"])),
    db: Session = Depends(get_db)
):
    """Run custom analytics query."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        results = await analytics_service.run_custom_query(
            metric=query.metric,
            start_date=query.start_date,
            end_date=query.end_date,
            granularity=query.granularity,
            filters=query.filters,
            anonymization_level=query.anonymization_level,
            requesting_user_id=current_user.id
        )
        
        return results
        
    except Exception as e:
        logger.error(f"Custom analytics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Custom analytics failed: {str(e)}")

@router.post("/export")
async def export_analytics_data(
    export_request: ExportRequest,
    current_user: User = Depends(RoleChecker(["admin", "data_analyst"])),
    db: Session = Depends(get_db)
):
    """Export analytics data in specified format."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        export_result = await analytics_service.export_analytics(
            report_type=export_request.report_type,
            format=export_request.format,
            start_date=export_request.start_date,
            end_date=export_request.end_date,
            include_charts=export_request.include_charts,
            anonymization_level=export_request.anonymization_level,
            requesting_user_id=current_user.id
        )
        
        if export_request.format in ["csv", "excel", "pdf"]:
            return FileResponse(
                path=export_result["file_path"],
                filename=export_result["filename"],
                media_type=export_result["media_type"]
            )
        else:
            return export_result["data"]
        
    except Exception as e:
        logger.error(f"Analytics export failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analytics export failed: {str(e)}")

@router.get("/reports")
async def list_available_reports(
    category: Optional[str] = Query(None, description="Filter by report category"),
    current_user: User = Depends(RoleChecker(["admin", "analytics_viewer"])),
    db: Session = Depends(get_db)
):
    """List available analytics reports."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        reports = await analytics_service.get_available_reports(
            category_filter=category,
            requesting_user_id=current_user.id
        )
        
        return reports
        
    except Exception as e:
        logger.error(f"Report listing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report listing failed: {str(e)}")

@router.get("/reports/{report_id}")
async def get_report_details(
    report_id: str = Path(..., description="Report ID"),
    current_user: User = Depends(RoleChecker(["admin", "analytics_viewer"])),
    db: Session = Depends(get_db)
):
    """Get detailed report information."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        report_details = await analytics_service.get_report_details(
            report_id=report_id,
            requesting_user_id=current_user.id
        )
        
        return report_details
        
    except Exception as e:
        logger.error(f"Report details retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report details retrieval failed: {str(e)}")

@router.post("/reports/{report_id}/schedule")
async def schedule_report_generation(
    report_id: str = Path(..., description="Report ID"),
    schedule_config: Dict[str, Any] = Body(..., description="Schedule configuration"),
    current_user: User = Depends(RoleChecker(["admin", "report_manager"])),
    db: Session = Depends(get_db)
):
    """Schedule automated report generation."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        schedule_result = await analytics_service.schedule_report(
            report_id=report_id,
            schedule_config=schedule_config,
            scheduled_by=current_user.id
        )
        
        return {"message": "Report scheduled successfully", "result": schedule_result}
        
    except Exception as e:
        logger.error(f"Report scheduling failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report scheduling failed: {str(e)}")


# Real-time Analytics Dashboard

@router.get("/dashboard/realtime")
async def get_realtime_dashboard_data(
    dashboard_type: str = Query("executive", description="Dashboard type"),
    refresh_interval: int = Query(30, description="Refresh interval in seconds"),
    current_user: User = Depends(RoleChecker(["admin", "dashboard_viewer"])),
    db: Session = Depends(get_db)
):
    """Get real-time dashboard data."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        dashboard_data = await analytics_service.get_realtime_dashboard(
            dashboard_type=dashboard_type,
            refresh_interval=refresh_interval,
            requesting_user_id=current_user.id
        )
        
        return dashboard_data
        
    except Exception as e:
        logger.error(f"Real-time dashboard failed: {e}")
        raise HTTPException(status_code=500, detail=f"Real-time dashboard failed: {str(e)}")

@router.get("/dashboard/kpis")
async def get_key_performance_indicators(
    time_period: str = Query("24h", description="Time period for KPIs"),
    current_user: User = Depends(RoleChecker(["admin", "executive"])),
    db: Session = Depends(get_db)
):
    """Get key performance indicators."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        kpis = await analytics_service.get_key_performance_indicators(
            time_period=time_period,
            requesting_user_id=current_user.id
        )
        
        return kpis
        
    except Exception as e:
        logger.error(f"KPI retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"KPI retrieval failed: {str(e)}")

@router.get("/dashboard/alerts")
async def get_analytics_alerts(
    severity: Optional[str] = Query(None, description="Filter by alert severity"),
    current_user: User = Depends(RoleChecker(["admin", "operations_manager"])),
    db: Session = Depends(get_db)
):
    """Get analytics-based alerts and notifications."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        alerts = await analytics_service.get_analytics_alerts(
            severity_filter=severity,
            requesting_user_id=current_user.id
        )
        
        return alerts
        
    except Exception as e:
        logger.error(f"Analytics alerts retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analytics alerts retrieval failed: {str(e)}")


# Data Insights and Machine Learning

@router.get("/insights/predictions")
async def get_predictive_insights(
    prediction_type: str = Query(..., description="Type of prediction"),
    horizon_days: int = Query(30, description="Prediction horizon in days"),
    current_user: User = Depends(RoleChecker(["admin", "data_scientist"])),
    db: Session = Depends(get_db)
):
    """Get predictive analytics insights."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        predictions = await analytics_service.get_predictive_insights(
            prediction_type=prediction_type,
            horizon_days=horizon_days,
            requesting_user_id=current_user.id
        )
        
        return predictions
        
    except Exception as e:
        logger.error(f"Predictive insights failed: {e}")
        raise HTTPException(status_code=500, detail=f"Predictive insights failed: {str(e)}")

@router.get("/insights/anomalies")
async def get_anomaly_detection(
    data_stream: str = Query(..., description="Data stream to analyze"),
    sensitivity: float = Query(0.95, description="Anomaly detection sensitivity"),
    current_user: User = Depends(RoleChecker(["admin", "data_scientist"])),
    db: Session = Depends(get_db)
):
    """Get anomaly detection insights."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        anomalies = await analytics_service.get_anomaly_detection(
            data_stream=data_stream,
            sensitivity=sensitivity,
            requesting_user_id=current_user.id
        )
        
        return anomalies
        
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")

@router.get("/insights/correlations")
async def get_correlation_analysis(
    primary_metric: str = Query(..., description="Primary metric for correlation"),
    start_date: datetime = Query(..., description="Analysis start date"),
    end_date: datetime = Query(..., description="Analysis end date"),
    current_user: User = Depends(RoleChecker(["admin", "research_analyst"])),
    db: Session = Depends(get_db)
):
    """Get correlation analysis between metrics."""
    try:
        analytics_service = HealthcareAnalyticsService(db)
        correlations = await analytics_service.get_correlation_analysis(
            primary_metric=primary_metric,
            start_date=start_date,
            end_date=end_date,
            requesting_user_id=current_user.id
        )
        
        return correlations
        
    except Exception as e:
        logger.error(f"Correlation analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Correlation analysis failed: {str(e)}") 