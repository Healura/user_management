"""
Healthcare Security Incident Detection

Advanced breach detection with behavioral analytics, insider threat monitoring,
and automated incident response for healthcare environments.
"""

import asyncio
import logging
import json
import ipaddress
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta, time
from enum import Enum
from dataclasses import dataclass, asdict
from uuid import UUID
from collections import defaultdict, deque
import math
import statistics

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, text

from src.database.models import User, AuditLog, AudioFile, UserSession, NotificationHistory
from src.database.repositories import AuditLogRepository
from src.security.audit_logger import AuditLogger
from src.utils.cloudtrail_parser import CloudTrailParser, CloudTrailEvent
from src.notifications.notification_manager import NotificationManager, NotificationType
from config.compliance_config import (
    get_breach_detection_config,
    get_incident_response_config,
    get_compliance_config
)

logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Types of security threats in healthcare environments."""
    INSIDER_THREAT = "insider_threat"
    EXTERNAL_ATTACK = "external_attack"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BRUTE_FORCE = "brute_force"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    BULK_DOWNLOAD = "bulk_download"
    OFF_HOURS_ACCESS = "off_hours_access"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    DEVICE_ANOMALY = "device_anomaly"
    SESSION_HIJACKING = "session_hijacking"


class ThreatSeverity(Enum):
    """Severity levels for detected threats."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseAction(Enum):
    """Automated response actions."""
    MONITOR = "monitor"
    ALERT = "alert"
    DISABLE_ACCOUNT = "disable_account"
    TERMINATE_SESSION = "terminate_session"
    QUARANTINE_DATA = "quarantine_data"
    NOTIFY_SECURITY = "notify_security"
    ESCALATE = "escalate"


@dataclass
class SecurityIncident:
    """Represents a detected security incident."""
    id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    title: str
    description: str
    user_id: Optional[UUID] = None
    affected_resources: List[str] = None
    indicators: Dict[str, Any] = None
    confidence_score: float = 0.0
    risk_score: int = 0
    first_detected: datetime = None
    last_updated: datetime = None
    status: str = "active"
    response_actions: List[ResponseAction] = None
    evidence: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.first_detected is None:
            self.first_detected = datetime.utcnow()
        if self.last_updated is None:
            self.last_updated = datetime.utcnow()
        if self.affected_resources is None:
            self.affected_resources = []
        if self.indicators is None:
            self.indicators = {}
        if self.response_actions is None:
            self.response_actions = []
        if self.evidence is None:
            self.evidence = []


@dataclass
class UserBehaviorProfile:
    """User behavior baseline for anomaly detection."""
    user_id: UUID
    typical_login_hours: List[int]
    typical_access_patterns: Dict[str, int]
    average_session_duration: float
    typical_file_access_count: int
    typical_locations: List[str]
    typical_devices: List[str]
    baseline_period_days: int
    last_updated: datetime
    confidence_level: float


class HealthcareThreatDetector:
    """Advanced threat detection for healthcare environments."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
        self.audit_logger = AuditLogger(db)
        self.notification_manager = NotificationManager()
        
        # Configuration
        self.breach_config = get_breach_detection_config()
        self.incident_config = get_incident_response_config()
        self.compliance_config = get_compliance_config()
        
        # CloudTrail integration
        self.cloudtrail_parser = CloudTrailParser()
        
        # Behavior analysis storage
        self.user_profiles = {}
        self.incident_cache = {}
        self.threat_indicators = deque(maxlen=1000)
        
        # Thresholds
        self.suspicious_access_threshold = self.breach_config.SUSPICIOUS_ACCESS_THRESHOLD
        self.bulk_download_threshold = self.breach_config.BULK_DOWNLOAD_ALERT_THRESHOLD
        self.rapid_access_threshold = self.breach_config.RAPID_ACCESS_THRESHOLD_MINUTES
        
    async def run_threat_detection_scan(
        self,
        lookback_hours: int = 1,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """
        Run comprehensive threat detection scan.
        
        Args:
            lookback_hours: How far back to analyze
            user_id: Focus on specific user (optional)
            
        Returns:
            Threat detection results
        """
        try:
            logger.info(f"Starting threat detection scan (lookback: {lookback_hours}h)")
            
            scan_start = datetime.utcnow() - timedelta(hours=lookback_hours)
            
            # Run all detection modules concurrently
            detection_results = await asyncio.gather(
                self._detect_insider_threats(scan_start, user_id),
                self._detect_external_attacks(scan_start, user_id),
                self._detect_data_exfiltration(scan_start, user_id),
                self._detect_unauthorized_access(scan_start, user_id),
                self._detect_brute_force_attacks(scan_start),
                self._detect_anomalous_behavior(scan_start, user_id),
                self._detect_bulk_downloads(scan_start, user_id),
                self._detect_off_hours_access(scan_start, user_id),
                self._detect_geographic_anomalies(scan_start, user_id),
                self._detect_device_anomalies(scan_start, user_id),
                return_exceptions=True
            )
            
            # Collect all incidents
            all_incidents = []
            detection_names = [
                "insider_threats", "external_attacks", "data_exfiltration",
                "unauthorized_access", "brute_force", "anomalous_behavior",
                "bulk_downloads", "off_hours_access", "geographic_anomalies",
                "device_anomalies"
            ]
            
            detection_summary = {}
            for i, result in enumerate(detection_results):
                detection_name = detection_names[i]
                if isinstance(result, Exception):
                    logger.error(f"Detection {detection_name} failed: {result}")
                    detection_summary[detection_name] = {"error": str(result)}
                else:
                    detection_summary[detection_name] = result
                    all_incidents.extend(result.get("incidents", []))
            
            # Process and prioritize incidents
            processed_incidents = await self._process_incidents(all_incidents)
            
            # Generate automated responses
            response_actions = await self._generate_automated_responses(processed_incidents)
            
            # Create summary
            summary = {
                "scan_timestamp": datetime.utcnow().isoformat(),
                "scan_period_hours": lookback_hours,
                "total_incidents": len(processed_incidents),
                "incidents_by_severity": self._count_incidents_by_severity(processed_incidents),
                "incidents_by_type": self._count_incidents_by_type(processed_incidents),
                "high_priority_incidents": [i for i in processed_incidents if i.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]],
                "automated_responses": response_actions,
                "detection_summary": detection_summary,
                "recommendations": self._generate_security_recommendations(processed_incidents)
            }
            
            # Log threat detection scan
            await self._log_threat_detection_scan(summary)
            
            return summary
            
        except Exception as e:
            logger.error(f"Threat detection scan failed: {e}")
            raise
    
    async def _detect_insider_threats(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect insider threat patterns."""
        incidents = []
        
        try:
            # Query user activity
            query = self.db.query(AuditLog).filter(AuditLog.timestamp >= since)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            recent_activities = query.all()
            
            # Group by user
            user_activities = defaultdict(list)
            for activity in recent_activities:
                if activity.user_id:
                    user_activities[activity.user_id].append(activity)
            
            for uid, activities in user_activities.items():
                # Check for suspicious insider patterns
                
                # Pattern 1: Excessive file access
                file_access_count = len([a for a in activities if "file" in a.action.lower()])
                if file_access_count > self.suspicious_access_threshold:
                    incidents.append(SecurityIncident(
                        id=f"insider_excessive_access_{uid}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.INSIDER_THREAT,
                        severity=ThreatSeverity.MEDIUM,
                        title="Excessive file access by insider",
                        description=f"User accessed {file_access_count} files in short period",
                        user_id=uid,
                        indicators={
                            "file_access_count": file_access_count,
                            "threshold": self.suspicious_access_threshold,
                            "time_period_hours": (datetime.utcnow() - since).total_seconds() / 3600
                        },
                        confidence_score=0.7,
                        risk_score=60,
                        evidence=[{"type": "audit_log", "count": file_access_count}]
                    ))
                
                # Pattern 2: Access to unusual resources
                accessed_resources = set()
                for activity in activities:
                    if activity.resource_id:
                        accessed_resources.add(activity.resource_id)
                
                # Get user's typical resources (simplified)
                typical_resources = await self._get_user_typical_resources(uid)
                unusual_resources = accessed_resources - typical_resources
                
                if len(unusual_resources) > 3:
                    incidents.append(SecurityIncident(
                        id=f"insider_unusual_resources_{uid}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.INSIDER_THREAT,
                        severity=ThreatSeverity.MEDIUM,
                        title="Access to unusual resources",
                        description=f"User accessed {len(unusual_resources)} unusual resources",
                        user_id=uid,
                        affected_resources=list(unusual_resources),
                        indicators={
                            "unusual_resource_count": len(unusual_resources),
                            "total_accessed": len(accessed_resources)
                        },
                        confidence_score=0.6,
                        risk_score=50,
                        evidence=[{"type": "resource_access", "unusual_count": len(unusual_resources)}]
                    ))
                
                # Pattern 3: Privilege escalation attempts
                privilege_actions = [a for a in activities if "role" in a.action.lower() or "permission" in a.action.lower()]
                if privilege_actions:
                    incidents.append(SecurityIncident(
                        id=f"insider_privilege_escalation_{uid}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.PRIVILEGE_ESCALATION,
                        severity=ThreatSeverity.HIGH,
                        title="Potential privilege escalation attempt",
                        description=f"User performed {len(privilege_actions)} privilege-related actions",
                        user_id=uid,
                        indicators={
                            "privilege_actions": len(privilege_actions)
                        },
                        confidence_score=0.8,
                        risk_score=75,
                        evidence=[{"type": "privilege_action", "actions": [a.action for a in privilege_actions]}]
                    ))
            
            return {
                "detection_type": "insider_threats",
                "incidents": incidents,
                "users_analyzed": len(user_activities),
                "activities_analyzed": len(recent_activities)
            }
            
        except Exception as e:
            logger.error(f"Insider threat detection failed: {e}")
            return {"detection_type": "insider_threats", "error": str(e)}
    
    async def _detect_external_attacks(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect external attack patterns."""
        incidents = []
        
        try:
            # Query failed login attempts
            failed_logins = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= since,
                    AuditLog.action.like("%login_failed%")
                )
            ).all()
            
            # Group by IP address
            ip_attempts = defaultdict(list)
            for login in failed_logins:
                if login.ip_address:
                    ip_attempts[str(login.ip_address)].append(login)
            
            # Check for brute force patterns
            for ip, attempts in ip_attempts.items():
                if len(attempts) > 5:  # Threshold for suspicious activity
                    # Check if IP is from known bad ranges or unusual locations
                    is_suspicious_ip = await self._is_suspicious_ip(ip)
                    
                    severity = ThreatSeverity.HIGH if is_suspicious_ip else ThreatSeverity.MEDIUM
                    
                    incidents.append(SecurityIncident(
                        id=f"external_brute_force_{ip.replace('.', '_')}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.BRUTE_FORCE,
                        severity=severity,
                        title="Brute force attack detected",
                        description=f"Multiple failed login attempts from IP {ip}",
                        indicators={
                            "source_ip": ip,
                            "failed_attempts": len(attempts),
                            "suspicious_ip": is_suspicious_ip,
                            "time_span_minutes": (attempts[-1].timestamp - attempts[0].timestamp).total_seconds() / 60
                        },
                        confidence_score=0.9 if is_suspicious_ip else 0.7,
                        risk_score=85 if is_suspicious_ip else 65,
                        evidence=[{"type": "failed_login", "ip": ip, "count": len(attempts)}]
                    ))
            
            # Check for suspicious login patterns
            successful_logins = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= since,
                    AuditLog.action.like("%login_success%")
                )
            ).all()
            
            for login in successful_logins:
                if login.ip_address:
                    is_suspicious = await self._is_suspicious_ip(str(login.ip_address))
                    if is_suspicious:
                        incidents.append(SecurityIncident(
                            id=f"external_suspicious_login_{login.user_id}_{datetime.utcnow().timestamp()}",
                            threat_type=ThreatType.EXTERNAL_ATTACK,
                            severity=ThreatSeverity.HIGH,
                            title="Login from suspicious IP",
                            description=f"Successful login from suspicious IP {login.ip_address}",
                            user_id=login.user_id,
                            indicators={
                                "source_ip": str(login.ip_address),
                                "suspicious_indicators": "Known bad IP range or unusual geolocation"
                            },
                            confidence_score=0.8,
                            risk_score=70,
                            evidence=[{"type": "suspicious_login", "ip": str(login.ip_address)}]
                        ))
            
            return {
                "detection_type": "external_attacks",
                "incidents": incidents,
                "failed_logins_analyzed": len(failed_logins),
                "suspicious_ips": len([ip for ip in ip_attempts.keys() if await self._is_suspicious_ip(ip)])
            }
            
        except Exception as e:
            logger.error(f"External attack detection failed: {e}")
            return {"detection_type": "external_attacks", "error": str(e)}
    
    async def _detect_data_exfiltration(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect data exfiltration patterns."""
        incidents = []
        
        try:
            # Query file download activities
            query = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= since,
                    or_(
                        AuditLog.action.like("%download%"),
                        AuditLog.action.like("%export%")
                    )
                )
            )
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            download_activities = query.all()
            
            # Group by user
            user_downloads = defaultdict(list)
            for activity in download_activities:
                if activity.user_id:
                    user_downloads[activity.user_id].append(activity)
            
            for uid, downloads in user_downloads.items():
                # Check for bulk download patterns
                if len(downloads) >= self.bulk_download_threshold:
                    # Check time span
                    time_span = (downloads[-1].timestamp - downloads[0].timestamp).total_seconds() / 60
                    
                    if time_span <= self.rapid_access_threshold:
                        incidents.append(SecurityIncident(
                            id=f"exfiltration_bulk_download_{uid}_{datetime.utcnow().timestamp()}",
                            threat_type=ThreatType.DATA_EXFILTRATION,
                            severity=ThreatSeverity.HIGH,
                            title="Suspicious bulk data download",
                            description=f"User downloaded {len(downloads)} files in {time_span:.1f} minutes",
                            user_id=uid,
                            affected_resources=[str(d.resource_id) for d in downloads if d.resource_id],
                            indicators={
                                "download_count": len(downloads),
                                "time_span_minutes": time_span,
                                "download_rate": len(downloads) / max(1, time_span)
                            },
                            confidence_score=0.8,
                            risk_score=80,
                            evidence=[{"type": "bulk_download", "count": len(downloads), "time_span": time_span}]
                        ))
                
                # Check for unusual download patterns
                user_profile = await self._get_user_behavior_profile(uid)
                if user_profile and len(downloads) > user_profile.typical_file_access_count * 3:
                    incidents.append(SecurityIncident(
                        id=f"exfiltration_unusual_volume_{uid}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.DATA_EXFILTRATION,
                        severity=ThreatSeverity.MEDIUM,
                        title="Unusual download volume",
                        description=f"User download volume exceeds typical pattern by 3x",
                        user_id=uid,
                        indicators={
                            "current_downloads": len(downloads),
                            "typical_downloads": user_profile.typical_file_access_count,
                            "deviation_factor": len(downloads) / max(1, user_profile.typical_file_access_count)
                        },
                        confidence_score=0.6,
                        risk_score=55,
                        evidence=[{"type": "volume_anomaly", "current": len(downloads), "typical": user_profile.typical_file_access_count}]
                    ))
            
            return {
                "detection_type": "data_exfiltration",
                "incidents": incidents,
                "download_activities": len(download_activities),
                "users_analyzed": len(user_downloads)
            }
            
        except Exception as e:
            logger.error(f"Data exfiltration detection failed: {e}")
            return {"detection_type": "data_exfiltration", "error": str(e)}
    
    async def _detect_unauthorized_access(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect unauthorized access patterns."""
        incidents = []
        
        try:
            # Check for access to files user doesn't own
            query = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= since,
                    AuditLog.action.like("%file%"),
                    AuditLog.resource_type == "audio_file"
                )
            )
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            file_accesses = query.all()
            
            for access in file_accesses:
                if access.resource_id and access.user_id:
                    # Check if user owns the file
                    file = self.db.query(AudioFile).get(access.resource_id)
                    if file and file.user_id != access.user_id:
                        # Check if user is authorized (provider accessing patient data)
                        user = self.db.query(User).get(access.user_id)
                        is_authorized = (
                            user and 
                            any(role.role.name in ["admin", "healthcare_provider"] 
                                for role in user.role_assignments)
                        )
                        
                        if not is_authorized:
                            incidents.append(SecurityIncident(
                                id=f"unauthorized_file_access_{access.user_id}_{access.resource_id}_{datetime.utcnow().timestamp()}",
                                threat_type=ThreatType.UNAUTHORIZED_ACCESS,
                                severity=ThreatSeverity.HIGH,
                                title="Unauthorized file access",
                                description=f"User accessed file belonging to another user without authorization",
                                user_id=access.user_id,
                                affected_resources=[str(access.resource_id)],
                                indicators={
                                    "accessed_file": str(access.resource_id),
                                    "file_owner": str(file.user_id),
                                    "accessor": str(access.user_id)
                                },
                                confidence_score=0.9,
                                risk_score=85,
                                evidence=[{"type": "unauthorized_access", "audit_log_id": str(access.id)}]
                            ))
            
            return {
                "detection_type": "unauthorized_access",
                "incidents": incidents,
                "file_accesses_analyzed": len(file_accesses)
            }
            
        except Exception as e:
            logger.error(f"Unauthorized access detection failed: {e}")
            return {"detection_type": "unauthorized_access", "error": str(e)}
    
    async def _detect_brute_force_attacks(self, since: datetime) -> Dict[str, Any]:
        """Detect brute force attack patterns."""
        incidents = []
        
        try:
            # Already covered in external attacks detection
            # This could include additional brute force patterns like:
            # - Password reset abuse
            # - Account enumeration
            # - API endpoint brute forcing
            
            return {
                "detection_type": "brute_force",
                "incidents": incidents,
                "note": "Covered in external attacks detection"
            }
            
        except Exception as e:
            logger.error(f"Brute force detection failed: {e}")
            return {"detection_type": "brute_force", "error": str(e)}
    
    async def _detect_anomalous_behavior(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect anomalous user behavior patterns."""
        incidents = []
        
        try:
            # Get user behavior profiles and compare with recent activity
            query = self.db.query(AuditLog).filter(AuditLog.timestamp >= since)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            recent_activities = query.all()
            
            # Group by user
            user_activities = defaultdict(list)
            for activity in recent_activities:
                if activity.user_id:
                    user_activities[activity.user_id].append(activity)
            
            for uid, activities in user_activities.items():
                profile = await self._get_user_behavior_profile(uid)
                if not profile:
                    continue  # Skip users without established profiles
                
                # Analyze session duration anomalies
                current_sessions = self.db.query(UserSession).filter(
                    and_(
                        UserSession.user_id == uid,
                        UserSession.created_at >= since,
                        UserSession.is_active == True
                    )
                ).all()
                
                for session in current_sessions:
                    session_duration = (datetime.utcnow() - session.created_at).total_seconds() / 3600
                    if session_duration > profile.average_session_duration * 3:  # 3x typical duration
                        incidents.append(SecurityIncident(
                            id=f"behavior_long_session_{uid}_{datetime.utcnow().timestamp()}",
                            threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                            severity=ThreatSeverity.MEDIUM,
                            title="Unusually long session duration",
                            description=f"Session duration ({session_duration:.1f}h) exceeds typical pattern",
                            user_id=uid,
                            indicators={
                                "current_duration": session_duration,
                                "typical_duration": profile.average_session_duration,
                                "deviation_factor": session_duration / max(0.1, profile.average_session_duration)
                            },
                            confidence_score=0.6,
                            risk_score=45,
                            evidence=[{"type": "session_anomaly", "session_id": str(session.id)}]
                        ))
                
                # Analyze access pattern anomalies
                activity_types = [a.action for a in activities]
                unusual_activities = []
                for activity_type in set(activity_types):
                    current_count = activity_types.count(activity_type)
                    typical_count = profile.typical_access_patterns.get(activity_type, 0)
                    
                    if typical_count > 0 and current_count > typical_count * 5:  # 5x typical count
                        unusual_activities.append({
                            "activity": activity_type,
                            "current": current_count,
                            "typical": typical_count
                        })
                
                if unusual_activities:
                    incidents.append(SecurityIncident(
                        id=f"behavior_unusual_activities_{uid}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                        severity=ThreatSeverity.MEDIUM,
                        title="Unusual activity pattern",
                        description=f"User activity pattern deviates significantly from baseline",
                        user_id=uid,
                        indicators={
                            "unusual_activities": unusual_activities
                        },
                        confidence_score=0.7,
                        risk_score=55,
                        evidence=[{"type": "activity_anomaly", "activities": unusual_activities}]
                    ))
            
            return {
                "detection_type": "anomalous_behavior",
                "incidents": incidents,
                "users_analyzed": len(user_activities),
                "profiles_available": len([uid for uid in user_activities.keys() if await self._get_user_behavior_profile(uid)])
            }
            
        except Exception as e:
            logger.error(f"Anomalous behavior detection failed: {e}")
            return {"detection_type": "anomalous_behavior", "error": str(e)}
    
    async def _detect_bulk_downloads(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect bulk download patterns (covered in data exfiltration)."""
        # This is already covered in _detect_data_exfiltration
        return {
            "detection_type": "bulk_downloads",
            "incidents": [],
            "note": "Covered in data exfiltration detection"
        }
    
    async def _detect_off_hours_access(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect access during off-business hours."""
        incidents = []
        
        try:
            if not self.breach_config.OFF_HOURS_ACCESS_MONITORING:
                return {"detection_type": "off_hours_access", "incidents": [], "disabled": True}
            
            # Parse business hours
            business_start = time.fromisoformat(self.breach_config.BUSINESS_HOURS_START)
            business_end = time.fromisoformat(self.breach_config.BUSINESS_HOURS_END)
            business_days = self.breach_config.BUSINESS_DAYS
            
            # Query activities during the period
            query = self.db.query(AuditLog).filter(AuditLog.timestamp >= since)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            activities = query.all()
            
            off_hours_activities = []
            for activity in activities:
                activity_time = activity.timestamp.time()
                activity_weekday = activity.timestamp.weekday() + 1  # Monday = 1
                
                # Check if outside business hours or business days
                is_off_hours = (
                    activity_time < business_start or 
                    activity_time > business_end or
                    activity_weekday not in business_days
                )
                
                if is_off_hours:
                    off_hours_activities.append(activity)
            
            # Group by user and analyze
            user_off_hours = defaultdict(list)
            for activity in off_hours_activities:
                if activity.user_id:
                    user_off_hours[activity.user_id].append(activity)
            
            for uid, activities in user_off_hours.items():
                if len(activities) > 5:  # Threshold for suspicious off-hours activity
                    incidents.append(SecurityIncident(
                        id=f"off_hours_access_{uid}_{datetime.utcnow().timestamp()}",
                        threat_type=ThreatType.OFF_HOURS_ACCESS,
                        severity=ThreatSeverity.MEDIUM,
                        title="Excessive off-hours access",
                        description=f"User performed {len(activities)} activities outside business hours",
                        user_id=uid,
                        indicators={
                            "off_hours_activities": len(activities),
                            "business_hours": f"{business_start}-{business_end}",
                            "business_days": business_days
                        },
                        confidence_score=0.6,
                        risk_score=50,
                        evidence=[{"type": "off_hours_activity", "count": len(activities)}]
                    ))
            
            return {
                "detection_type": "off_hours_access",
                "incidents": incidents,
                "total_off_hours_activities": len(off_hours_activities),
                "users_with_off_hours_access": len(user_off_hours)
            }
            
        except Exception as e:
            logger.error(f"Off-hours access detection failed: {e}")
            return {"detection_type": "off_hours_access", "error": str(e)}
    
    async def _detect_geographic_anomalies(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect geographic location anomalies."""
        incidents = []
        
        try:
            if not self.breach_config.GEOGRAPHIC_ANOMALY_DETECTION:
                return {"detection_type": "geographic_anomalies", "incidents": [], "disabled": True}
            
            # Query login activities with IP addresses
            query = self.db.query(AuditLog).filter(
                and_(
                    AuditLog.timestamp >= since,
                    AuditLog.action.like("%login%"),
                    AuditLog.ip_address.isnot(None)
                )
            )
            
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            
            login_activities = query.all()
            
            # Group by user
            user_logins = defaultdict(list)
            for login in login_activities:
                if login.user_id:
                    user_logins[login.user_id].append(login)
            
            for uid, logins in user_logins.items():
                profile = await self._get_user_behavior_profile(uid)
                if not profile:
                    continue
                
                for login in logins:
                    # Get approximate location from IP (simplified)
                    location = await self._get_ip_location(str(login.ip_address))
                    
                    if location and location not in profile.typical_locations:
                        # Check if it's a significant geographic distance
                        is_anomalous = await self._is_anomalous_location(location, profile.typical_locations)
                        
                        if is_anomalous:
                            incidents.append(SecurityIncident(
                                id=f"geo_anomaly_{uid}_{datetime.utcnow().timestamp()}",
                                threat_type=ThreatType.GEOGRAPHIC_ANOMALY,
                                severity=ThreatSeverity.MEDIUM,
                                title="Login from unusual geographic location",
                                description=f"User logged in from {location}, which is unusual for this user",
                                user_id=uid,
                                indicators={
                                    "login_location": location,
                                    "typical_locations": profile.typical_locations,
                                    "login_ip": str(login.ip_address)
                                },
                                confidence_score=0.7,
                                risk_score=60,
                                evidence=[{"type": "geographic_anomaly", "location": location, "ip": str(login.ip_address)}]
                            ))
            
            return {
                "detection_type": "geographic_anomalies",
                "incidents": incidents,
                "login_activities_analyzed": len(login_activities),
                "users_analyzed": len(user_logins)
            }
            
        except Exception as e:
            logger.error(f"Geographic anomaly detection failed: {e}")
            return {"detection_type": "geographic_anomalies", "error": str(e)}
    
    async def _detect_device_anomalies(
        self,
        since: datetime,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """Detect device-based anomalies."""
        incidents = []
        
        try:
            # Query sessions with device information
            query = self.db.query(UserSession).filter(UserSession.created_at >= since)
            if user_id:
                query = query.filter(UserSession.user_id == user_id)
            
            sessions = query.all()
            
            # Group by user
            user_sessions = defaultdict(list)
            for session in sessions:
                user_sessions[session.user_id].append(session)
            
            for uid, sessions in user_sessions.items():
                profile = await self._get_user_behavior_profile(uid)
                if not profile:
                    continue
                
                for session in sessions:
                    device_info = f"{session.device_type}_{session.user_agent}"
                    
                    if device_info not in profile.typical_devices:
                        incidents.append(SecurityIncident(
                            id=f"device_anomaly_{uid}_{datetime.utcnow().timestamp()}",
                            threat_type=ThreatType.DEVICE_ANOMALY,
                            severity=ThreatSeverity.LOW,
                            title="Login from new/unusual device",
                            description=f"User logged in from an unusual device: {session.device_type}",
                            user_id=uid,
                            indicators={
                                "new_device": device_info,
                                "typical_devices": profile.typical_devices
                            },
                            confidence_score=0.5,
                            risk_score=30,
                            evidence=[{"type": "device_anomaly", "device": device_info}]
                        ))
            
            return {
                "detection_type": "device_anomalies",
                "incidents": incidents,
                "sessions_analyzed": len(sessions),
                "users_analyzed": len(user_sessions)
            }
            
        except Exception as e:
            logger.error(f"Device anomaly detection failed: {e}")
            return {"detection_type": "device_anomalies", "error": str(e)}
    
    async def _process_incidents(self, incidents: List[SecurityIncident]) -> List[SecurityIncident]:
        """Process and deduplicate incidents."""
        # Remove duplicates and merge similar incidents
        processed = []
        incident_signatures = set()
        
        for incident in incidents:
            # Create signature for deduplication
            signature = f"{incident.threat_type.value}_{incident.user_id}_{incident.title}"
            
            if signature not in incident_signatures:
                incident_signatures.add(signature)
                processed.append(incident)
        
        # Sort by severity and risk score
        processed.sort(
            key=lambda x: (
                x.severity == ThreatSeverity.CRITICAL,
                x.severity == ThreatSeverity.HIGH,
                x.severity == ThreatSeverity.MEDIUM,
                x.risk_score
            ),
            reverse=True
        )
        
        return processed
    
    async def _generate_automated_responses(
        self,
        incidents: List[SecurityIncident]
    ) -> List[Dict[str, Any]]:
        """Generate automated response actions for incidents."""
        responses = []
        
        for incident in incidents:
            response_actions = []
            
            # Determine appropriate responses based on threat type and severity
            if incident.severity == ThreatSeverity.CRITICAL:
                if incident.threat_type in [ThreatType.DATA_EXFILTRATION, ThreatType.INSIDER_THREAT]:
                    response_actions.extend([
                        ResponseAction.DISABLE_ACCOUNT,
                        ResponseAction.TERMINATE_SESSION,
                        ResponseAction.NOTIFY_SECURITY,
                        ResponseAction.ESCALATE
                    ])
                elif incident.threat_type == ThreatType.EXTERNAL_ATTACK:
                    response_actions.extend([
                        ResponseAction.TERMINATE_SESSION,
                        ResponseAction.NOTIFY_SECURITY,
                        ResponseAction.ESCALATE
                    ])
            
            elif incident.severity == ThreatSeverity.HIGH:
                response_actions.extend([
                    ResponseAction.NOTIFY_SECURITY,
                    ResponseAction.MONITOR
                ])
                
                if incident.threat_type in [ThreatType.BRUTE_FORCE, ThreatType.UNAUTHORIZED_ACCESS]:
                    response_actions.append(ResponseAction.TERMINATE_SESSION)
            
            elif incident.severity in [ThreatSeverity.MEDIUM, ThreatSeverity.LOW]:
                response_actions.extend([
                    ResponseAction.ALERT,
                    ResponseAction.MONITOR
                ])
            
            # Execute automated responses if enabled
            if self.incident_config.INCIDENT_AUTO_RESPONSE:
                executed_actions = await self._execute_response_actions(incident, response_actions)
                responses.append({
                    "incident_id": incident.id,
                    "actions_planned": [action.value for action in response_actions],
                    "actions_executed": executed_actions,
                    "execution_timestamp": datetime.utcnow().isoformat()
                })
        
        return responses
    
    async def _execute_response_actions(
        self,
        incident: SecurityIncident,
        actions: List[ResponseAction]
    ) -> List[str]:
        """Execute automated response actions."""
        executed = []
        
        try:
            for action in actions:
                if action == ResponseAction.DISABLE_ACCOUNT and incident.user_id:
                    if self.incident_config.AUTO_DISABLE_COMPROMISED_ACCOUNTS:
                        # Disable user account
                        user = self.db.query(User).get(incident.user_id)
                        if user:
                            user.is_active = False
                            self.db.commit()
                            executed.append("disable_account")
                
                elif action == ResponseAction.TERMINATE_SESSION and incident.user_id:
                    if self.incident_config.AUTO_REVOKE_SUSPICIOUS_SESSIONS:
                        # Terminate all user sessions
                        sessions = self.db.query(UserSession).filter(
                            and_(
                                UserSession.user_id == incident.user_id,
                                UserSession.is_active == True
                            )
                        ).all()
                        
                        for session in sessions:
                            session.is_active = False
                        self.db.commit()
                        executed.append("terminate_session")
                
                elif action == ResponseAction.NOTIFY_SECURITY:
                    # Send security notification
                    await self.notification_manager.send_notification(
                        user_id=None,  # Send to security team
                        notification_type=NotificationType.SUSPICIOUS_ACTIVITY,
                        data={
                            "incident_id": incident.id,
                            "threat_type": incident.threat_type.value,
                            "severity": incident.severity.value,
                            "title": incident.title,
                            "description": incident.description,
                            "affected_user": str(incident.user_id) if incident.user_id else None
                        },
                        override_preferences=True
                    )
                    executed.append("notify_security")
                
                elif action == ResponseAction.ALERT:
                    # Log security alert
                    await self.audit_logger.log_security_event(
                        event_type="security_incident",
                        user_id=incident.user_id,
                        severity=incident.severity.value,
                        description=f"Security incident detected: {incident.title}",
                        details=asdict(incident)
                    )
                    executed.append("alert")
                
                elif action == ResponseAction.MONITOR:
                    # Enhanced monitoring (would implement additional tracking)
                    executed.append("monitor")
                
                elif action == ResponseAction.ESCALATE:
                    # Escalate to incident response team
                    executed.append("escalate")
        
        except Exception as e:
            logger.error(f"Error executing response actions: {e}")
        
        return executed
    
    # Helper methods
    async def _get_user_typical_resources(self, user_id: UUID) -> set:
        """Get user's typically accessed resources."""
        # Query historical access patterns
        historical_access = self.db.query(AuditLog).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= datetime.utcnow() - timedelta(days=30),
                AuditLog.resource_id.isnot(None)
            )
        ).all()
        
        return set(access.resource_id for access in historical_access)
    
    async def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if private IP (generally less suspicious)
            if ip_obj.is_private:
                return False
            
            # Check against known bad IP ranges (simplified)
            # In production, you'd use threat intelligence feeds
            suspicious_ranges = [
                # Add known bad IP ranges here
            ]
            
            # For now, consider any non-private IP as potentially suspicious
            # In production, you'd implement proper threat intelligence
            return not ip_obj.is_private
            
        except ValueError:
            return True  # Invalid IP format is suspicious
    
    async def _get_user_behavior_profile(self, user_id: UUID) -> Optional[UserBehaviorProfile]:
        """Get or create user behavior profile."""
        # In production, this would be stored in database
        # For now, return a simplified profile
        if user_id in self.user_profiles:
            return self.user_profiles[user_id]
        
        # Create basic profile from historical data
        historical_activities = self.db.query(AuditLog).filter(
            and_(
                AuditLog.user_id == user_id,
                AuditLog.timestamp >= datetime.utcnow() - timedelta(days=30)
            )
        ).all()
        
        if len(historical_activities) < 10:  # Not enough data
            return None
        
        # Calculate basic profile metrics
        login_hours = []
        access_patterns = defaultdict(int)
        
        for activity in historical_activities:
            if "login" in activity.action:
                login_hours.append(activity.timestamp.hour)
            access_patterns[activity.action] += 1
        
        profile = UserBehaviorProfile(
            user_id=user_id,
            typical_login_hours=list(set(login_hours)) if login_hours else [9, 10, 11, 14, 15, 16],
            typical_access_patterns=dict(access_patterns),
            average_session_duration=8.0,  # 8 hours default
            typical_file_access_count=statistics.mean([access_patterns.get(k, 0) for k in access_patterns.keys() if "file" in k]) if access_patterns else 5,
            typical_locations=["US", "Internal"],  # Simplified
            typical_devices=["web_browser", "mobile_app"],  # Simplified
            baseline_period_days=30,
            last_updated=datetime.utcnow(),
            confidence_level=0.7
        )
        
        self.user_profiles[user_id] = profile
        return profile
    
    async def _get_ip_location(self, ip: str) -> Optional[str]:
        """Get approximate location from IP address."""
        # In production, you'd use a geolocation service
        # For now, return simplified location
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return "Internal"
            else:
                return "External"  # Would be actual country/region in production
        except ValueError:
            return "Unknown"
    
    async def _is_anomalous_location(self, location: str, typical_locations: List[str]) -> bool:
        """Check if location is anomalous compared to typical locations."""
        # Simplified check - in production would calculate geographic distance
        return location not in typical_locations and location != "Internal"
    
    def _count_incidents_by_severity(self, incidents: List[SecurityIncident]) -> Dict[str, int]:
        """Count incidents by severity level."""
        counts = {severity.value: 0 for severity in ThreatSeverity}
        for incident in incidents:
            counts[incident.severity.value] += 1
        return counts
    
    def _count_incidents_by_type(self, incidents: List[SecurityIncident]) -> Dict[str, int]:
        """Count incidents by threat type."""
        counts = {}
        for incident in incidents:
            threat_type = incident.threat_type.value
            counts[threat_type] = counts.get(threat_type, 0) + 1
        return counts
    
    def _generate_security_recommendations(self, incidents: List[SecurityIncident]) -> List[str]:
        """Generate security recommendations based on detected incidents."""
        recommendations = []
        
        incident_types = [i.threat_type for i in incidents]
        
        if ThreatType.INSIDER_THREAT in incident_types:
            recommendations.append("Implement enhanced insider threat monitoring and user behavior analytics")
        
        if ThreatType.BRUTE_FORCE in incident_types:
            recommendations.append("Strengthen password policies and implement account lockout mechanisms")
        
        if ThreatType.DATA_EXFILTRATION in incident_types:
            recommendations.append("Implement data loss prevention (DLP) controls and monitor bulk data transfers")
        
        if ThreatType.UNAUTHORIZED_ACCESS in incident_types:
            recommendations.append("Review and strengthen access controls and authorization mechanisms")
        
        if ThreatType.OFF_HOURS_ACCESS in incident_types:
            recommendations.append("Implement time-based access controls and enhanced off-hours monitoring")
        
        critical_count = len([i for i in incidents if i.severity == ThreatSeverity.CRITICAL])
        if critical_count > 0:
            recommendations.append(f"URGENT: Address {critical_count} critical security incidents immediately")
        
        return recommendations
    
    async def _log_threat_detection_scan(self, summary: Dict[str, Any]):
        """Log threat detection scan for audit trail."""
        try:
            await self.audit_logger.log_security_event(
                event_type="threat_detection_scan",
                severity="info" if summary["total_incidents"] == 0 else "warning",
                description=f"Threat detection scan completed. Found {summary['total_incidents']} incidents",
                details={
                    "total_incidents": summary["total_incidents"],
                    "high_priority_incidents": len(summary["high_priority_incidents"]),
                    "scan_period_hours": summary["scan_period_hours"]
                }
            )
        except Exception as e:
            logger.error(f"Failed to log threat detection scan: {e}")


async def run_threat_detection(
    db: Session,
    lookback_hours: int = 1,
    user_id: Optional[UUID] = None
) -> Dict[str, Any]:
    """
    High-level function to run threat detection.
    
    Args:
        db: Database session
        lookback_hours: How far back to analyze
        user_id: Focus on specific user (optional)
        
    Returns:
        Threat detection results
    """
    detector = HealthcareThreatDetector(db)
    return await detector.run_threat_detection_scan(lookback_hours, user_id) 