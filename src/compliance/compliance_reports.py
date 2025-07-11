"""
Automated HIPAA Compliance Reporting

Comprehensive compliance reporting system with multiple report types,
automated generation, and regulatory compliance documentation.
"""

import asyncio
import logging
import json
import csv
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID
import pandas as pd

from sqlalchemy.orm import Session

from src.security.compliance_checker import run_compliance_check
from src.security.risk_assessment import run_risk_assessment
from src.security.breach_detection import run_threat_detection
from src.compliance.hipaa_audit import run_hipaa_audit
from src.compliance.retention_manager import run_retention_enforcement
from src.security.baa_compliance import run_baa_compliance_check
from config.compliance_config import get_compliance_config

logger = logging.getLogger(__name__)


class ReportType(Enum):
    """Types of compliance reports."""
    COMPREHENSIVE_COMPLIANCE = "comprehensive_compliance"
    RISK_ASSESSMENT = "risk_assessment"
    AUDIT_TRAIL = "audit_trail"
    BREACH_DETECTION = "breach_detection"
    DATA_RETENTION = "data_retention"
    BAA_COMPLIANCE = "baa_compliance"
    EXECUTIVE_SUMMARY = "executive_summary"
    REGULATORY_FILING = "regulatory_filing"
    INCIDENT_SUMMARY = "incident_summary"
    PRIVACY_IMPACT = "privacy_impact"


class ReportFormat(Enum):
    """Report output formats."""
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"
    EXCEL = "xlsx"
    HTML = "html"


class ReportFrequency(Enum):
    """Report generation frequencies."""
    ON_DEMAND = "on_demand"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"


@dataclass
class ComplianceReport:
    """Compliance report data structure."""
    report_id: str
    report_type: ReportType
    generated_date: datetime
    period_start: datetime
    period_end: datetime
    generated_by: Optional[str] = None
    format: ReportFormat = ReportFormat.JSON
    executive_summary: Dict[str, Any] = None
    detailed_findings: Dict[str, Any] = None
    recommendations: List[str] = None
    compliance_score: int = 0
    risk_level: str = "unknown"
    file_path: Optional[str] = None
    
    def __post_init__(self):
        if self.executive_summary is None:
            self.executive_summary = {}
        if self.detailed_findings is None:
            self.detailed_findings = {}
        if self.recommendations is None:
            self.recommendations = []


class ComplianceReportGenerator:
    """Automated compliance report generation system."""
    
    def __init__(self, db: Session):
        self.db = db
        self.compliance_config = get_compliance_config()
        
        # Report templates
        self.report_templates = self._initialize_report_templates()
        
    def _initialize_report_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize report templates for different report types."""
        return {
            ReportType.COMPREHENSIVE_COMPLIANCE.value: {
                "name": "Comprehensive HIPAA Compliance Report",
                "description": "Complete compliance assessment covering all HIPAA requirements",
                "sections": [
                    "executive_summary",
                    "compliance_status",
                    "risk_assessment",
                    "violations_summary",
                    "audit_findings",
                    "recommendations",
                    "action_plan"
                ],
                "data_sources": [
                    "compliance_check",
                    "risk_assessment",
                    "audit_analysis",
                    "threat_detection"
                ]
            },
            ReportType.EXECUTIVE_SUMMARY.value: {
                "name": "Executive Compliance Summary",
                "description": "High-level compliance summary for executive leadership",
                "sections": [
                    "key_metrics",
                    "risk_overview",
                    "critical_issues",
                    "strategic_recommendations"
                ],
                "data_sources": [
                    "compliance_check",
                    "risk_assessment"
                ]
            },
            ReportType.AUDIT_TRAIL.value: {
                "name": "HIPAA Audit Trail Report",
                "description": "Comprehensive audit trail analysis for compliance verification",
                "sections": [
                    "audit_summary",
                    "event_analysis",
                    "integrity_verification",
                    "compliance_gaps"
                ],
                "data_sources": [
                    "audit_analysis"
                ]
            },
            ReportType.RISK_ASSESSMENT.value: {
                "name": "Healthcare Risk Assessment Report",
                "description": "Detailed risk assessment with mitigation recommendations",
                "sections": [
                    "risk_overview",
                    "risk_factors",
                    "threat_landscape",
                    "mitigation_strategies"
                ],
                "data_sources": [
                    "risk_assessment",
                    "threat_detection"
                ]
            },
            ReportType.REGULATORY_FILING.value: {
                "name": "Regulatory Compliance Filing",
                "description": "Formal compliance report for regulatory submission",
                "sections": [
                    "organization_info",
                    "compliance_framework",
                    "assessment_methodology",
                    "findings",
                    "corrective_actions",
                    "attestation"
                ],
                "data_sources": [
                    "compliance_check",
                    "audit_analysis",
                    "risk_assessment"
                ]
            }
        }
    
    async def generate_report(
        self,
        report_type: ReportType,
        start_date: datetime,
        end_date: datetime,
        format: ReportFormat = ReportFormat.JSON,
        generated_by: Optional[str] = None,
        include_recommendations: bool = True
    ) -> ComplianceReport:
        """Generate compliance report of specified type."""
        try:
            logger.info(f"Generating {report_type.value} report for period {start_date} to {end_date}")
            
            report_id = f"{report_type.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            # Get report template
            template = self.report_templates.get(report_type.value, {})
            
            # Gather data from required sources
            report_data = await self._gather_report_data(template.get("data_sources", []), start_date, end_date)
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(report_type, report_data)
            
            # Generate detailed findings
            detailed_findings = self._generate_detailed_findings(report_type, report_data, template)
            
            # Generate recommendations
            recommendations = []
            if include_recommendations:
                recommendations = self._generate_recommendations(report_type, report_data)
            
            # Calculate overall compliance score
            compliance_score = self._calculate_overall_compliance_score(report_data)
            
            # Determine risk level
            risk_level = self._determine_overall_risk_level(report_data)
            
            # Create report
            report = ComplianceReport(
                report_id=report_id,
                report_type=report_type,
                generated_date=datetime.utcnow(),
                period_start=start_date,
                period_end=end_date,
                generated_by=generated_by,
                format=format,
                executive_summary=executive_summary,
                detailed_findings=detailed_findings,
                recommendations=recommendations,
                compliance_score=compliance_score,
                risk_level=risk_level
            )
            
            # Export report in specified format
            if format != ReportFormat.JSON:
                file_path = await self._export_report(report, format)
                report.file_path = file_path
            
            return report
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
    
    async def _gather_report_data(
        self,
        data_sources: List[str],
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Gather data from specified sources for report generation."""
        report_data = {}
        
        try:
            # Run assessments in parallel based on required data sources
            tasks = []
            
            if "compliance_check" in data_sources:
                tasks.append(self._gather_compliance_data())
            
            if "risk_assessment" in data_sources:
                tasks.append(self._gather_risk_data())
            
            if "audit_analysis" in data_sources:
                tasks.append(self._gather_audit_data(start_date, end_date))
            
            if "threat_detection" in data_sources:
                tasks.append(self._gather_threat_data())
            
            if "retention_analysis" in data_sources:
                tasks.append(self._gather_retention_data())
            
            if "baa_compliance" in data_sources:
                tasks.append(self._gather_baa_data())
            
            # Execute all data gathering tasks
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(f"Data gathering task {i} failed: {result}")
                        continue
                    
                    # Merge result into report data
                    if isinstance(result, dict):
                        report_data.update(result)
            
            return report_data
            
        except Exception as e:
            logger.error(f"Report data gathering failed: {e}")
            return {}
    
    async def _gather_compliance_data(self) -> Dict[str, Any]:
        """Gather compliance check data."""
        try:
            compliance_result = await run_compliance_check(self.db)
            return {"compliance_check": compliance_result}
        except Exception as e:
            logger.error(f"Compliance data gathering failed: {e}")
            return {"compliance_check": {"error": str(e)}}
    
    async def _gather_risk_data(self) -> Dict[str, Any]:
        """Gather risk assessment data."""
        try:
            risk_result = await run_risk_assessment(self.db, include_historical=True)
            return {"risk_assessment": asdict(risk_result)}
        except Exception as e:
            logger.error(f"Risk data gathering failed: {e}")
            return {"risk_assessment": {"error": str(e)}}
    
    async def _gather_audit_data(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Gather audit analysis data."""
        try:
            audit_result = await run_hipaa_audit(self.db, start_date, end_date)
            return {"audit_analysis": asdict(audit_result)}
        except Exception as e:
            logger.error(f"Audit data gathering failed: {e}")
            return {"audit_analysis": {"error": str(e)}}
    
    async def _gather_threat_data(self) -> Dict[str, Any]:
        """Gather threat detection data."""
        try:
            threat_result = await run_threat_detection(self.db, lookback_hours=24)
            return {"threat_detection": threat_result}
        except Exception as e:
            logger.error(f"Threat data gathering failed: {e}")
            return {"threat_detection": {"error": str(e)}}
    
    async def _gather_retention_data(self) -> Dict[str, Any]:
        """Gather data retention analysis."""
        try:
            retention_result = await run_retention_enforcement(self.db, dry_run=True)
            return {"retention_analysis": retention_result}
        except Exception as e:
            logger.error(f"Retention data gathering failed: {e}")
            return {"retention_analysis": {"error": str(e)}}
    
    async def _gather_baa_data(self) -> Dict[str, Any]:
        """Gather BAA compliance data."""
        try:
            baa_result = await run_baa_compliance_check(self.db)
            return {"baa_compliance": baa_result}
        except Exception as e:
            logger.error(f"BAA data gathering failed: {e}")
            return {"baa_compliance": {"error": str(e)}}
    
    def _generate_executive_summary(self, report_type: ReportType, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for report."""
        summary = {
            "report_type": report_type.value,
            "generation_timestamp": datetime.utcnow().isoformat(),
            "period_assessed": None,
            "key_metrics": {},
            "critical_findings": [],
            "overall_status": "unknown"
        }
        
        try:
            # Extract key metrics from data sources
            if "compliance_check" in data and "error" not in data["compliance_check"]:
                compliance_data = data["compliance_check"]
                summary["key_metrics"]["compliance_score"] = compliance_data.get("compliance_score", {}).get("total_score", 0)
                summary["key_metrics"]["total_violations"] = compliance_data.get("total_violations", 0)
                summary["key_metrics"]["critical_violations"] = len(compliance_data.get("critical_violations", []))
            
            if "risk_assessment" in data and "error" not in data["risk_assessment"]:
                risk_data = data["risk_assessment"]
                summary["key_metrics"]["risk_score"] = risk_data.get("overall_risk_score", 0)
                summary["key_metrics"]["risk_level"] = risk_data.get("risk_level", "unknown")
                summary["key_metrics"]["high_risk_areas"] = len(risk_data.get("high_risk_areas", []))
            
            if "threat_detection" in data and "error" not in data["threat_detection"]:
                threat_data = data["threat_detection"]
                summary["key_metrics"]["security_incidents"] = threat_data.get("total_incidents", 0)
                summary["key_metrics"]["high_priority_incidents"] = len(threat_data.get("high_priority_incidents", []))
            
            if "audit_analysis" in data and "error" not in data["audit_analysis"]:
                audit_data = data["audit_analysis"]
                summary["key_metrics"]["audit_events"] = audit_data.get("total_events", 0)
                summary["key_metrics"]["audit_compliance"] = audit_data.get("compliance_status", "unknown")
                summary["key_metrics"]["integrity_score"] = audit_data.get("integrity_verification", {}).get("overall_integrity_score", 0)
            
            # Determine overall status
            compliance_score = summary["key_metrics"].get("compliance_score", 0)
            risk_score = summary["key_metrics"].get("risk_score", 0)
            critical_violations = summary["key_metrics"].get("critical_violations", 0)
            
            if critical_violations > 0:
                summary["overall_status"] = "critical"
            elif compliance_score < 70 or risk_score > 80:
                summary["overall_status"] = "needs_attention"
            elif compliance_score >= 90 and risk_score < 50:
                summary["overall_status"] = "excellent"
            else:
                summary["overall_status"] = "satisfactory"
            
            # Generate critical findings
            if critical_violations > 0:
                summary["critical_findings"].append(f"{critical_violations} critical compliance violations detected")
            
            if risk_score > 80:
                summary["critical_findings"].append(f"High risk score: {risk_score}/100")
            
            high_priority_incidents = summary["key_metrics"].get("high_priority_incidents", 0)
            if high_priority_incidents > 0:
                summary["critical_findings"].append(f"{high_priority_incidents} high-priority security incidents")
            
            return summary
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            summary["error"] = str(e)
            return summary
    
    def _generate_detailed_findings(
        self,
        report_type: ReportType,
        data: Dict[str, Any],
        template: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate detailed findings section of report."""
        findings = {}
        
        try:
            sections = template.get("sections", [])
            
            for section in sections:
                if section == "compliance_status" and "compliance_check" in data:
                    findings[section] = self._generate_compliance_status_section(data["compliance_check"])
                
                elif section == "risk_assessment" and "risk_assessment" in data:
                    findings[section] = self._generate_risk_assessment_section(data["risk_assessment"])
                
                elif section == "audit_findings" and "audit_analysis" in data:
                    findings[section] = self._generate_audit_findings_section(data["audit_analysis"])
                
                elif section == "violations_summary" and "compliance_check" in data:
                    findings[section] = self._generate_violations_summary_section(data["compliance_check"])
                
                elif section == "threat_landscape" and "threat_detection" in data:
                    findings[section] = self._generate_threat_landscape_section(data["threat_detection"])
                
                elif section == "retention_status" and "retention_analysis" in data:
                    findings[section] = self._generate_retention_status_section(data["retention_analysis"])
                
                elif section == "baa_status" and "baa_compliance" in data:
                    findings[section] = self._generate_baa_status_section(data["baa_compliance"])
                
                else:
                    findings[section] = {"status": "not_available", "reason": "Data source not available"}
            
            return findings
            
        except Exception as e:
            logger.error(f"Detailed findings generation failed: {e}")
            return {"error": str(e)}
    
    def _generate_compliance_status_section(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance status section."""
        return {
            "overall_score": compliance_data.get("compliance_score", {}).get("total_score", 0),
            "category_scores": compliance_data.get("compliance_score", {}).get("category_scores", {}),
            "total_violations": compliance_data.get("total_violations", 0),
            "violations_by_severity": compliance_data.get("violations_by_severity", {}),
            "violations_by_type": compliance_data.get("violations_by_type", {}),
            "trending": compliance_data.get("compliance_score", {}).get("trending", "stable"),
            "last_assessment": compliance_data.get("assessment_timestamp", ""),
            "detailed_results": compliance_data.get("detailed_results", {})
        }
    
    def _generate_risk_assessment_section(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment section."""
        return {
            "overall_risk_score": risk_data.get("overall_risk_score", 0),
            "risk_level": risk_data.get("risk_level", "unknown"),
            "trending": risk_data.get("trend", "stable"),
            "high_risk_areas": risk_data.get("high_risk_areas", []),
            "category_scores": risk_data.get("category_scores", {}),
            "confidence_score": risk_data.get("confidence_score", 0),
            "mitigation_recommendations": risk_data.get("mitigation_recommendations", []),
            "risk_factors": risk_data.get("risk_factors", [])
        }
    
    def _generate_audit_findings_section(self, audit_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate audit findings section."""
        return {
            "total_events": audit_data.get("total_events", 0),
            "compliance_status": audit_data.get("compliance_status", "unknown"),
            "compliance_score": audit_data.get("compliance_score", 0),
            "events_by_type": audit_data.get("events_by_type", {}),
            "events_by_user": audit_data.get("events_by_user", {}),
            "integrity_verification": audit_data.get("integrity_verification", {}),
            "missing_events": audit_data.get("missing_events", []),
            "recommendations": audit_data.get("recommendations", [])
        }
    
    def _generate_violations_summary_section(self, compliance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate violations summary section."""
        violations_summary = {
            "total_violations": compliance_data.get("total_violations", 0),
            "by_severity": compliance_data.get("violations_by_severity", {}),
            "by_type": compliance_data.get("violations_by_type", {}),
            "critical_violations": [],
            "auto_remediable": 0,
            "manual_remediation_required": 0
        }
        
        # Extract critical violations from detailed results
        for result in compliance_data.get("detailed_results", {}).values():
            if "violations" in result:
                for violation in result["violations"]:
                    if violation.get("severity") == "critical":
                        violations_summary["critical_violations"].append({
                            "id": violation.get("id"),
                            "title": violation.get("title"),
                            "description": violation.get("description"),
                            "auto_remediable": violation.get("auto_remediable", False)
                        })
                    
                    if violation.get("auto_remediable", False):
                        violations_summary["auto_remediable"] += 1
                    else:
                        violations_summary["manual_remediation_required"] += 1
        
        return violations_summary
    
    def _generate_threat_landscape_section(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate threat landscape section."""
        return {
            "total_incidents": threat_data.get("total_incidents", 0),
            "incidents_by_severity": threat_data.get("incidents_by_severity", {}),
            "incidents_by_type": threat_data.get("incidents_by_type", {}),
            "high_priority_incidents": len(threat_data.get("high_priority_incidents", [])),
            "automated_responses": threat_data.get("automated_responses", []),
            "recommendations": threat_data.get("recommendations", [])
        }
    
    def _generate_retention_status_section(self, retention_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate retention status section."""
        return {
            "total_records_assessed": retention_data.get("total_records_assessed", 0),
            "eligible_for_deletion": retention_data.get("total_eligible_for_deletion", 0),
            "approaching_retention": retention_data.get("total_approaching_retention", 0),
            "storage_savings_gb": retention_data.get("storage_savings_potential_gb", 0),
            "compliance_summary": retention_data.get("compliance_summary", {}),
            "recommendations": retention_data.get("recommendations", [])
        }
    
    def _generate_baa_status_section(self, baa_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate BAA status section."""
        return {
            "total_associates": baa_data.get("total_associates_assessed", 0),
            "compliant_associates": baa_data.get("compliant_associates", 0),
            "non_compliant_associates": baa_data.get("non_compliant_associates", 0),
            "expired_baas": baa_data.get("expired_baas", 0),
            "critical_violations": baa_data.get("critical_violations", 0),
            "compliance_rate": (baa_data.get("compliant_associates", 0) / max(baa_data.get("total_associates_assessed", 1), 1)) * 100,
            "recommendations": baa_data.get("recommendations", [])
        }
    
    def _generate_recommendations(self, report_type: ReportType, data: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on report findings."""
        recommendations = []
        
        try:
            # Collect recommendations from all data sources
            for source, source_data in data.items():
                if isinstance(source_data, dict) and "recommendations" in source_data:
                    recommendations.extend(source_data["recommendations"])
            
            # Add report-type specific recommendations
            if report_type == ReportType.COMPREHENSIVE_COMPLIANCE:
                recommendations.extend(self._get_comprehensive_recommendations(data))
            elif report_type == ReportType.EXECUTIVE_SUMMARY:
                recommendations.extend(self._get_executive_recommendations(data))
            elif report_type == ReportType.RISK_ASSESSMENT:
                recommendations.extend(self._get_risk_recommendations(data))
            
            # Remove duplicates and prioritize
            unique_recommendations = list(set(recommendations))
            return self._prioritize_recommendations(unique_recommendations, data)
            
        except Exception as e:
            logger.error(f"Recommendations generation failed: {e}")
            return ["Review compliance status and address identified issues"]
    
    def _get_comprehensive_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Get recommendations for comprehensive compliance report."""
        recommendations = []
        
        # Compliance-based recommendations
        if "compliance_check" in data:
            compliance_score = data["compliance_check"].get("compliance_score", {}).get("total_score", 0)
            if compliance_score < 70:
                recommendations.append("Implement immediate compliance improvement plan")
        
        # Risk-based recommendations
        if "risk_assessment" in data:
            risk_score = data["risk_assessment"].get("overall_risk_score", 0)
            if risk_score > 80:
                recommendations.append("Execute high-priority risk mitigation strategies")
        
        return recommendations
    
    def _get_executive_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Get recommendations for executive summary."""
        return [
            "Review monthly compliance dashboard",
            "Ensure adequate compliance staffing",
            "Validate business continuity plans",
            "Consider compliance automation investments"
        ]
    
    def _get_risk_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Get recommendations for risk assessment report."""
        return [
            "Implement continuous risk monitoring",
            "Enhance threat detection capabilities",
            "Review and update risk assessment procedures",
            "Conduct regular security awareness training"
        ]
    
    def _prioritize_recommendations(self, recommendations: List[str], data: Dict[str, Any]) -> List[str]:
        """Prioritize recommendations based on severity and impact."""
        # Simple prioritization based on keywords
        priority_keywords = ["urgent", "critical", "immediate", "breach", "violation"]
        
        high_priority = []
        medium_priority = []
        low_priority = []
        
        for rec in recommendations:
            rec_lower = rec.lower()
            if any(keyword in rec_lower for keyword in priority_keywords):
                high_priority.append(rec)
            elif "implement" in rec_lower or "enhance" in rec_lower:
                medium_priority.append(rec)
            else:
                low_priority.append(rec)
        
        return high_priority + medium_priority + low_priority
    
    def _calculate_overall_compliance_score(self, data: Dict[str, Any]) -> int:
        """Calculate overall compliance score from all data sources."""
        scores = []
        
        if "compliance_check" in data and "error" not in data["compliance_check"]:
            score = data["compliance_check"].get("compliance_score", {}).get("total_score", 0)
            scores.append(score)
        
        if "audit_analysis" in data and "error" not in data["audit_analysis"]:
            score = data["audit_analysis"].get("compliance_score", 0)
            scores.append(score)
        
        if scores:
            return int(sum(scores) / len(scores))
        
        return 0
    
    def _determine_overall_risk_level(self, data: Dict[str, Any]) -> str:
        """Determine overall risk level from assessment data."""
        if "risk_assessment" in data and "error" not in data["risk_assessment"]:
            return data["risk_assessment"].get("risk_level", "unknown")
        
        # Fallback based on compliance score
        compliance_score = self._calculate_overall_compliance_score(data)
        if compliance_score >= 90:
            return "low"
        elif compliance_score >= 70:
            return "medium"
        else:
            return "high"
    
    async def _export_report(self, report: ComplianceReport, format: ReportFormat) -> str:
        """Export report to specified format."""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{report.report_type.value}_{timestamp}.{format.value}"
            file_path = f"/tmp/compliance_reports/{filename}"  # In production, use proper storage
            
            if format == ReportFormat.JSON:
                with open(file_path, 'w') as f:
                    json.dump(asdict(report), f, indent=2, default=str)
            
            elif format == ReportFormat.CSV:
                # Convert report data to CSV format
                await self._export_to_csv(report, file_path)
            
            elif format == ReportFormat.EXCEL:
                # Convert report data to Excel format
                await self._export_to_excel(report, file_path)
            
            elif format == ReportFormat.HTML:
                # Convert report data to HTML format
                await self._export_to_html(report, file_path)
            
            elif format == ReportFormat.PDF:
                # Convert report data to PDF format
                await self._export_to_pdf(report, file_path)
            
            return file_path
            
        except Exception as e:
            logger.error(f"Report export failed: {e}")
            raise
    
    async def _export_to_csv(self, report: ComplianceReport, file_path: str):
        """Export report to CSV format."""
        # Create CSV with key metrics and findings
        data = []
        
        # Executive summary data
        for key, value in report.executive_summary.items():
            if isinstance(value, (int, float, str)):
                data.append({"Section": "Executive Summary", "Metric": key, "Value": value})
        
        # Key metrics
        if "key_metrics" in report.executive_summary:
            for metric, value in report.executive_summary["key_metrics"].items():
                data.append({"Section": "Key Metrics", "Metric": metric, "Value": value})
        
        # Write CSV
        if data:
            df = pd.DataFrame(data)
            df.to_csv(file_path, index=False)
    
    async def _export_to_excel(self, report: ComplianceReport, file_path: str):
        """Export report to Excel format."""
        with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
            # Executive Summary sheet
            summary_data = pd.DataFrame([report.executive_summary])
            summary_data.to_excel(writer, sheet_name='Executive Summary', index=False)
            
            # Detailed findings sheets
            for section, findings in report.detailed_findings.items():
                if isinstance(findings, dict):
                    findings_df = pd.DataFrame([findings])
                    sheet_name = section.replace('_', ' ').title()[:31]  # Excel sheet name limit
                    findings_df.to_excel(writer, sheet_name=sheet_name, index=False)
    
    async def _export_to_html(self, report: ComplianceReport, file_path: str):
        """Export report to HTML format."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{report.report_type.value.replace('_', ' ').title()} Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #e9e9e9; border-radius: 3px; }}
                .critical {{ background-color: #ffebee; }}
                .warning {{ background-color: #fff3e0; }}
                .success {{ background-color: #e8f5e8; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{report.report_type.value.replace('_', ' ').title()} Report</h1>
                <p>Generated: {report.generated_date}</p>
                <p>Period: {report.period_start} to {report.period_end}</p>
                <p>Overall Compliance Score: {report.compliance_score}/100</p>
                <p>Risk Level: {report.risk_level}</p>
            </div>
        """
        
        # Add executive summary
        html_content += '<div class="section"><h2>Executive Summary</h2>'
        for key, value in report.executive_summary.items():
            html_content += f'<div class="metric"><strong>{key}:</strong> {value}</div>'
        html_content += '</div>'
        
        # Add recommendations
        if report.recommendations:
            html_content += '<div class="section"><h2>Recommendations</h2><ul>'
            for rec in report.recommendations[:10]:  # Limit to top 10
                html_content += f'<li>{rec}</li>'
            html_content += '</ul></div>'
        
        html_content += '</body></html>'
        
        with open(file_path, 'w') as f:
            f.write(html_content)
    
    async def _export_to_pdf(self, report: ComplianceReport, file_path: str):
        """Export report to PDF format."""
        # In production, this would use a proper PDF library like reportlab
        # For now, create a simple text-based PDF placeholder
        
        # Convert to HTML first, then to PDF (would use wkhtmltopdf or similar)
        html_path = file_path.replace('.pdf', '.html')
        await self._export_to_html(report, html_path)
        
        # Placeholder for PDF conversion
        # In production: subprocess.run(['wkhtmltopdf', html_path, file_path])
        
        # For now, just copy the HTML file with PDF extension
        import shutil
        shutil.copy(html_path, file_path)


async def generate_compliance_report(
    db: Session,
    report_type: ReportType,
    start_date: datetime,
    end_date: datetime,
    format: ReportFormat = ReportFormat.JSON,
    generated_by: Optional[str] = None
) -> ComplianceReport:
    """
    High-level function to generate compliance report.
    
    Args:
        db: Database session
        report_type: Type of report to generate
        start_date: Report period start date
        end_date: Report period end date
        format: Output format for the report
        generated_by: User who requested the report
        
    Returns:
        Generated compliance report
    """
    generator = ComplianceReportGenerator(db)
    return await generator.generate_report(
        report_type=report_type,
        start_date=start_date,
        end_date=end_date,
        format=format,
        generated_by=generated_by
    ) 