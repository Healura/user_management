import logging
from typing import Optional, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy.orm import Session

from src.database.repositories import AuditLogRepository
from config.security_config import security_config

logger = logging.getLogger(__name__)


class AuditLogger:
    """HIPAA-compliant audit logger."""
    
    def __init__(self, db: Session):
        self.db = db
        self.audit_repo = AuditLogRepository(db)
    
    async def log_authentication_event(
        self,
        action: str,
        user_id: Optional[UUID] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log authentication-related events.
        
        Args:
            action: Authentication action (login, logout, register, etc.)
            user_id: User ID if available
            email: Email used for authentication
            ip_address: Client IP address
            user_agent: Client user agent
            success: Whether the action was successful
            details: Additional details
        """
        if not security_config.enable_audit_logging:
            return
        
        audit_details = {
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
            "email": email
        }
        
        if details:
            audit_details.update(details)
        
        try:
            self.audit_repo.log_action(
                action=f"auth.{action}",
                user_id=user_id,
                resource_type="authentication",
                ip_address=ip_address,
                user_agent=user_agent,
                details=audit_details
            )
        except Exception as e:
            logger.error(f"Failed to log authentication event: {e}")
    
    async def log_successful_login(
        self,
        user_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        mfa_used: bool = False
    ) -> None:
        """Log successful login."""
        await self.log_authentication_event(
            action="login_success",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            details={"mfa_used": mfa_used}
        )
    
    async def log_failed_login(
        self,
        email: str,
        user_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        reason: str = "Invalid credentials"
    ) -> None:
        """Log failed login attempt."""
        await self.log_authentication_event(
            action="login_failed",
            user_id=user_id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=False,
            details={"reason": reason}
        )
    
    async def log_data_access(
        self,
        user_id: UUID,
        action: str,
        resource_type: str,
        resource_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        purpose: Optional[str] = None,
        success: bool = True
    ) -> None:
        """
        Log data access for HIPAA compliance.
        
        Args:
            user_id: User accessing data
            action: Action performed (read, write, delete)
            resource_type: Type of resource accessed
            resource_id: ID of resource
            ip_address: Client IP
            user_agent: Client user agent
            purpose: Purpose of access
            success: Whether access was successful
        """
        if not security_config.enable_audit_logging:
            return
        
        details = {
            "purpose": purpose,
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            self.audit_repo.log_action(
                action=f"data.{action}",
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details
            )
        except Exception as e:
            logger.error(f"Failed to log data access: {e}")
    
    async def log_security_event(
        self,
        event_type: str,
        user_id: Optional[UUID] = None,
        severity: str = "info",
        description: str = "",
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event
            user_id: User involved (if any)
            severity: Event severity (info, warning, error, critical)
            description: Event description
            ip_address: Client IP
            details: Additional details
        """
        if not security_config.enable_audit_logging:
            return
        
        audit_details = {
            "severity": severity,
            "description": description,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if details:
            audit_details.update(details)
        
        try:
            self.audit_repo.log_action(
                action=f"security.{event_type}",
                user_id=user_id,
                resource_type="security",
                ip_address=ip_address,
                details=audit_details
            )
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    async def log_user_modification(
        self,
        modifier_id: UUID,
        user_id: UUID,
        action: str,
        changes: Dict[str, Any],
        ip_address: Optional[str] = None
    ) -> None:
        """
        Log user account modifications.
        
        Args:
            modifier_id: User making the change
            user_id: User being modified
            action: Modification action
            changes: Dictionary of changes made
            ip_address: Client IP
        """
        await self.log_data_access(
            user_id=modifier_id,
            action=action,
            resource_type="user",
            resource_id=user_id,
            ip_address=ip_address,
            purpose=f"User modification: {action}",
            success=True
        )
    
    async def log_file_access(
        self,
        user_id: UUID,
        file_id: UUID,
        action: str,
        ip_address: Optional[str] = None,
        success: bool = True
    ) -> None:
        """Log audio file access."""
        await self.log_data_access(
            user_id=user_id,
            action=action,
            resource_type="audio_file",
            resource_id=file_id,
            ip_address=ip_address,
            success=success
        )
    
    async def log_analysis_access(
        self,
        user_id: UUID,
        analysis_id: UUID,
        action: str,
        ip_address: Optional[str] = None,
        success: bool = True
    ) -> None:
        """Log voice analysis access."""
        await self.log_data_access(
            user_id=user_id,
            action=action,
            resource_type="voice_analysis",
            resource_id=analysis_id,
            ip_address=ip_address,
            success=success
        )


# Helper functions for quick logging
async def log_security_event(
    db: Session,
    event_type: str,
    user_id: Optional[UUID] = None,
    severity: str = "info",
    description: str = "",
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Quick helper to log security events."""
    logger_instance = AuditLogger(db)
    await logger_instance.log_security_event(
        event_type=event_type,
        user_id=user_id,
        severity=severity,
        description=description,
        details=details
    )


async def log_data_access(
    db: Session,
    user_id: UUID,
    action: str,
    resource_type: str,
    resource_id: UUID,
    success: bool = True
) -> None:
    """Quick helper to log data access."""
    logger_instance = AuditLogger(db)
    await logger_instance.log_data_access(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        success=success
    )


async def log_authentication_event(
    db: Session,
    action: str,
    user_id: Optional[UUID] = None,
    email: Optional[str] = None,
    success: bool = True,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Quick helper to log authentication events."""
    logger_instance = AuditLogger(db)
    await logger_instance.log_authentication_event(
        action=action,
        user_id=user_id,
        email=email,
        success=success,
        details=details
    )