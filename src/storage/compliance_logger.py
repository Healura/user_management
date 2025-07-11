"""Healthcare compliance logging for HIPAA audit requirements."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from uuid import UUID
from enum import Enum

from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from src.database.models import AuditLog, User, AudioFile
from src.database.repositories import AuditLogRepository
from config.storage_config import storage_config
from .file_manager import PHIClassification

logger = logging.getLogger(__name__)


class ComplianceEventType(Enum):
    """Compliance-specific event types."""
    PHI_ACCESS = "phi_access"
    PHI_MODIFICATION = "phi_modification"
    PHI_DELETION = "phi_deletion"
    RETENTION_ACTION = "retention_action"
    BREACH_DETECTION = "breach_detection"
    CONSENT_UPDATE = "consent_update"
    AUDIT_EXPORT = "audit_export"
    COMPLIANCE_VIOLATION = "compliance_violation"


class ComplianceLogger:
    """HIPAA-compliant audit logger for healthcare file operations."""
    
    def __init__(self, db: Session):
        """Initialize compliance logger."""
        self.db = db
        self.audit_repo = AuditLogRepository(db)
    
    async def log_phi_access(
        self,
        user_id: UUID,
        action: str,
        resource_type: str,
        resource_id: Optional[UUID],
        phi_classification: PHIClassification,
        ip_address: Optional[str] = None,
        purpose: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None
    ) -> None:
        """
        Log PHI access for HIPAA compliance.
        
        Args:
            user_id: User accessing PHI
            action: Action performed (view, download, upload, etc.)
            resource_type: Type of resource
            resource_id: Resource ID
            phi_classification: PHI classification level
            ip_address: Client IP
            purpose: Purpose of access
            success: Whether access was successful
            error: Error message if failed
        """
        try:
            details = {
                'compliance_event': ComplianceEventType.PHI_ACCESS.value,
                'phi_classification': phi_classification.value,
                'action_type': action,
                'purpose': purpose or 'Not specified',
                'success': success,
                'timestamp': datetime.utcnow().isoformat(),
                'compliance_standard': 'HIPAA',
                'minimum_necessary': storage_config.minimum_necessary_access
            }
            
            if error:
                details['error'] = error
                details['violation_type'] = 'unauthorized_access_attempt'
            
            # Check for suspicious patterns
            if await self._is_suspicious_access(user_id, resource_type, action):
                details['suspicious_activity'] = True
                details['alert_required'] = True
            
            self.audit_repo.log_action(
                action=f"phi.{action}",
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                details=details
            )
            
            # Trigger alerts for high-risk events
            if phi_classification == PHIClassification.HIGH and not success:
                await self._trigger_security_alert(
                    user_id=user_id,
                    event_type='failed_phi_access',
                    details=details
                )
                
        except Exception as e:
            logger.error(f"Failed to log PHI access: {e}")
    
    async def log_file_deletion(
        self,
        user_id: UUID,
        file_id: UUID,
        phi_classification: PHIClassification,
        permanent: bool,
        reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True
    ) -> None:
        """Log file deletion with retention compliance."""
        try:
            details = {
                'compliance_event': ComplianceEventType.PHI_DELETION.value,
                'phi_classification': phi_classification.value,
                'deletion_type': 'permanent' if permanent else 'soft',
                'reason': reason or 'User initiated',
                'success': success,
                'retention_compliant': await self._check_retention_compliance(file_id),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.audit_repo.log_action(
                action='file.delete',
                user_id=user_id,
                resource_type='audio_file',
                resource_id=file_id,
                ip_address=ip_address,
                details=details
            )
            
        except Exception as e:
            logger.error(f"Failed to log file deletion: {e}")
    
    async def log_retention_action(
        self,
        action: str,
        affected_files: int,
        details: Dict[str, Any]
    ) -> None:
        """Log retention policy actions."""
        try:
            self.audit_repo.log_action(
                action=f"retention.{action}",
                user_id=None,  # System action
                resource_type='retention_policy',
                details={
                    'compliance_event': ComplianceEventType.RETENTION_ACTION.value,
                    'affected_files': affected_files,
                    'timestamp': datetime.utcnow().isoformat(),
                    **details
                }
            )
        except Exception as e:
            logger.error(f"Failed to log retention action: {e}")
    
    async def log_integrity_failure(
        self,
        file_id: UUID,
        user_id: UUID,
        action: str
    ) -> None:
        """Log file integrity check failures."""
        try:
            details = {
                'compliance_event': ComplianceEventType.COMPLIANCE_VIOLATION.value,
                'violation_type': 'integrity_check_failed',
                'action': action,
                'severity': 'high',
                'timestamp': datetime.utcnow().isoformat(),
                'requires_investigation': True
            }
            
            self.audit_repo.log_action(
                action='integrity.failure',
                user_id=user_id,
                resource_type='audio_file',
                resource_id=file_id,
                details=details
            )
            
            # Trigger immediate alert
            await self._trigger_security_alert(
                user_id=user_id,
                event_type='integrity_failure',
                details=details
            )
            
        except Exception as e:
            logger.error(f"Failed to log integrity failure: {e}")
    
    async def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        report_type: str = 'hipaa_audit'
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report.
        
        Args:
            start_date: Report start date
            end_date: Report end date
            report_type: Type of compliance report
            
        Returns:
            Compliance report data
        """
        try:
            # Get PHI access logs
            phi_logs = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= start_date,
                    AuditLog.timestamp <= end_date,
                    AuditLog.action.like('phi.%')
                )
            ).all()
            
            # Analyze access patterns
            access_summary = self._analyze_access_patterns(phi_logs)
            
            # Get deletion logs
            deletion_logs = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= start_date,
                    AuditLog.timestamp <= end_date,
                    AuditLog.action == 'file.delete'
                )
            ).all()
            
            # Get violation logs
            violation_logs = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= start_date,
                    AuditLog.timestamp <= end_date,
                    or_(
                        AuditLog.details['compliance_event'].astext == ComplianceEventType.COMPLIANCE_VIOLATION.value,
                        AuditLog.details['success'].astext == 'false'
                    )
                )
            ).all()
            
            # Generate report
            report = {
                'report_type': report_type,
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'generated_at': datetime.utcnow().isoformat(),
                'summary': {
                    'total_phi_accesses': len(phi_logs),
                    'successful_accesses': sum(1 for log in phi_logs if log.details.get('success', True)),
                    'failed_accesses': sum(1 for log in phi_logs if not log.details.get('success', True)),
                    'total_deletions': len(deletion_logs),
                    'compliance_violations': len(violation_logs)
                },
                'access_patterns': access_summary,
                'high_risk_events': self._identify_high_risk_events(phi_logs + deletion_logs + violation_logs),
                'user_activity': self._summarize_user_activity(phi_logs),
                'recommendations': self._generate_recommendations(access_summary, violation_logs)
            }
            
            # Log report generation
            self.audit_repo.log_action(
                action='compliance.report_generated',
                user_id=None,
                resource_type='compliance_report',
                details={
                    'report_type': report_type,
                    'period': report['period']
                }
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {'error': str(e)}
    
    async def detect_breach_patterns(
        self,
        time_window: timedelta = timedelta(hours=1)
    ) -> List[Dict[str, Any]]:
        """Detect potential breach patterns in access logs."""
        try:
            cutoff_time = datetime.utcnow() - time_window
            
            # Look for suspicious patterns
            suspicious_patterns = []
            
            # Pattern 1: Excessive downloads by single user
            excessive_downloads = self.db.query(
                AuditLog.user_id,
                func.count(AuditLog.id).label('access_count')
            ).filter(
                and_(
                    AuditLog.timestamp >= cutoff_time,
                    AuditLog.action.in_(['phi.download', 'file.download'])
                )
            ).group_by(
                AuditLog.user_id
            ).having(
                func.count(AuditLog.id) > 10  # Threshold
            ).all()
            
            for user_activity in excessive_downloads:
                suspicious_patterns.append({
                    'pattern_type': 'excessive_downloads',
                    'user_id': str(user_activity.user_id),
                    'access_count': user_activity.access_count,
                    'severity': 'high',
                    'detected_at': datetime.utcnow().isoformat()
                })
            
            # Pattern 2: Access outside normal hours
            off_hours_access = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= cutoff_time,
                    AuditLog.action.like('phi.%'),
                    or_(
                        func.extract('hour', AuditLog.timestamp) < 6,
                        func.extract('hour', AuditLog.timestamp) > 22
                    )
                )
            ).all()
            
            if off_hours_access:
                suspicious_patterns.append({
                    'pattern_type': 'off_hours_access',
                    'event_count': len(off_hours_access),
                    'severity': 'medium',
                    'events': [
                        {
                            'user_id': str(log.user_id),
                            'timestamp': log.timestamp.isoformat(),
                            'action': log.action
                        }
                        for log in off_hours_access[:5]  # Limit to 5 examples
                    ]
                })
            
            # Log breach detection run
            if suspicious_patterns:
                for pattern in suspicious_patterns:
                    await self._trigger_security_alert(
                        event_type='breach_pattern_detected',
                        details=pattern
                    )
            
            return suspicious_patterns
            
        except Exception as e:
            logger.error(f"Failed to detect breach patterns: {e}")
            return []
    
    def _analyze_access_patterns(
        self,
        logs: List[AuditLog]
    ) -> Dict[str, Any]:
        """Analyze PHI access patterns."""
        patterns = {
            'by_action': {},
            'by_classification': {},
            'by_hour': {},
            'by_user_role': {}
        }
        
        for log in logs:
            # By action
            action = log.action.split('.')[-1]
            patterns['by_action'][action] = patterns['by_action'].get(action, 0) + 1
            
            # By PHI classification
            classification = log.details.get('phi_classification', 'unknown')
            patterns['by_classification'][classification] = patterns['by_classification'].get(classification, 0) + 1
            
            # By hour
            hour = log.timestamp.hour
            patterns['by_hour'][hour] = patterns['by_hour'].get(hour, 0) + 1
        
        return patterns
    
    def _identify_high_risk_events(
        self,
        logs: List[AuditLog]
    ) -> List[Dict[str, Any]]:
        """Identify high-risk compliance events."""
        high_risk_events = []
        
        for log in logs:
            risk_score = 0
            risk_factors = []
            
            # Failed access to HIGH PHI
            if not log.details.get('success', True) and log.details.get('phi_classification') == 'HIGH':
                risk_score += 3
                risk_factors.append('failed_high_phi_access')
            
            # Suspicious activity flag
            if log.details.get('suspicious_activity'):
                risk_score += 2
                risk_factors.append('suspicious_activity')
            
            # Integrity failure
            if log.action == 'integrity.failure':
                risk_score += 4
                risk_factors.append('integrity_failure')
            
            # Compliance violation
            if log.details.get('compliance_event') == ComplianceEventType.COMPLIANCE_VIOLATION.value:
                risk_score += 3
                risk_factors.append('compliance_violation')
            
            if risk_score >= 3:
                high_risk_events.append({
                    'log_id': str(log.id),
                    'timestamp': log.timestamp.isoformat(),
                    'user_id': str(log.user_id) if log.user_id else None,
                    'action': log.action,
                    'risk_score': risk_score,
                    'risk_factors': risk_factors
                })
        
        return sorted(high_risk_events, key=lambda x: x['risk_score'], reverse=True)[:10]
    
    def _summarize_user_activity(
        self,
        logs: List[AuditLog]
    ) -> Dict[str, Any]:
        """Summarize user activity for compliance reporting."""
        user_summary = {}
        
        for log in logs:
            if log.user_id:
                user_id = str(log.user_id)
                if user_id not in user_summary:
                    user_summary[user_id] = {
                        'total_accesses': 0,
                        'successful_accesses': 0,
                        'failed_accesses': 0,
                        'actions': {}
                    }
                
                user_summary[user_id]['total_accesses'] += 1
                
                if log.details.get('success', True):
                    user_summary[user_id]['successful_accesses'] += 1
                else:
                    user_summary[user_id]['failed_accesses'] += 1
                
                action = log.action.split('.')[-1]
                user_summary[user_id]['actions'][action] = user_summary[user_id]['actions'].get(action, 0) + 1
        
        return user_summary
    
    def _generate_recommendations(
        self,
        access_patterns: Dict[str, Any],
        violations: List[AuditLog]
    ) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        # Check for off-hours access
        off_hours_access = sum(access_patterns['by_hour'].get(h, 0) for h in range(0, 6)) + \
                          sum(access_patterns['by_hour'].get(h, 0) for h in range(22, 24))
        total_access = sum(access_patterns['by_hour'].values()) if access_patterns['by_hour'] else 1
        
        if off_hours_access / total_access > 0.2:
            recommendations.append(
                "High volume of off-hours access detected. Consider implementing stricter access controls during non-business hours."
            )
        
        # Check for violations
        if len(violations) > 10:
            recommendations.append(
                "Multiple compliance violations detected. Review access control policies and user training."
            )
        
        # Check for HIGH PHI access
        high_phi_percentage = access_patterns['by_classification'].get('HIGH', 0) / \
                             sum(access_patterns['by_classification'].values()) if access_patterns['by_classification'] else 0
        
        if high_phi_percentage > 0.8:
            recommendations.append(
                "Majority of accesses are to HIGH classification PHI. Ensure minimum necessary access principle is enforced."
            )
        
        return recommendations
    
    async def _is_suspicious_access(
        self,
        user_id: UUID,
        resource_type: str,
        action: str
    ) -> bool:
        """Check if access pattern is suspicious."""
        # Check recent access frequency
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_accesses = self.db.query(func.count(AuditLog.id)).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= one_hour_ago,
                AuditLog.action.like(f'%.{action}')
            )
        ).scalar()
        
        # Threshold for suspicious activity
        if recent_accesses > 20:
            return True
        
        return False
    
    async def _check_retention_compliance(
        self,
        file_id: UUID
    ) -> bool:
        """Check if file deletion complies with retention policy."""
        try:
            # Get file info
            file = self.db.query(AudioFile).filter(AudioFile.id == file_id).first()
            if not file:
                return False
            
            # Calculate retention period
            retention_years = storage_config.healthcare_retention_years
            retention_end = file.uploaded_at + timedelta(days=retention_years * 365)
            
            # Check if retention period has passed
            return datetime.utcnow() > retention_end
            
        except Exception as e:
            logger.error(f"Failed to check retention compliance: {e}")
            return False
    
    async def _trigger_security_alert(
        self,
        user_id: Optional[UUID] = None,
        event_type: str = 'security_event',
        details: Dict[str, Any] = None
    ) -> None:
        """Trigger security alert for high-risk events."""
        try:
            alert_details = {
                'alert_type': event_type,
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': str(user_id) if user_id else None,
                'details': details or {},
                'severity': details.get('severity', 'high') if details else 'high'
            }
            
            # Log the alert
            self.audit_repo.log_action(
                action='security.alert',
                user_id=user_id,
                resource_type='security_alert',
                details=alert_details
            )
            
            # In production, this would:
            # - Send email to security team
            # - Trigger CloudWatch alarm
            # - Post to security incident channel
            logger.warning(f"SECURITY ALERT: {alert_details}")
            
        except Exception as e:
            logger.error(f"Failed to trigger security alert: {e}")


# Helper functions
async def log_phi_access(
    db: Session,
    user_id: UUID,
    action: str,
    resource_type: str,
    resource_id: Optional[UUID],
    phi_classification: PHIClassification,
    **kwargs
) -> None:
    """Log PHI access for compliance."""
    logger = ComplianceLogger(db)
    await logger.log_phi_access(
        user_id, action, resource_type, resource_id, phi_classification, **kwargs
    )


async def log_retention_action(
    db: Session,
    action: str,
    affected_files: int,
    details: Dict[str, Any]
) -> None:
    """Log retention policy action."""
    logger = ComplianceLogger(db)
    await logger.log_retention_action(action, affected_files, details)


async def generate_compliance_report(
    db: Session,
    start_date: datetime,
    end_date: datetime,
    report_type: str = 'hipaa_audit'
) -> Dict[str, Any]:
    """Generate compliance report."""
    logger = ComplianceLogger(db)
    return await logger.generate_compliance_report(start_date, end_date, report_type)