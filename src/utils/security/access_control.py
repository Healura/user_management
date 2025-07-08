import logging
from enum import Enum
from typing import Optional, List
from uuid import UUID
from datetime import datetime, timedelta

from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from src.database.models import User, AudioFile, VoiceAnalysis
from src.database.repositories import UserRoleAssignmentRepository

logger = logging.getLogger(__name__)


class ResourceType(Enum):
    """Types of resources in the system."""
    USER = "user"
    AUDIO_FILE = "audio_file"
    VOICE_ANALYSIS = "voice_analysis"
    NOTIFICATION = "notification"
    AUDIT_LOG = "audit_log"


class AccessDeniedError(Exception):
    """Raised when access to a resource is denied."""
    pass


def check_resource_access(
    user: User,
    resource_type: ResourceType,
    resource_id: Optional[UUID] = None,
    action: str = "read"
) -> bool:
    """
    Check if user has access to a resource.
    
    Args:
        user: User object
        resource_type: Type of resource
        resource_id: Optional resource ID
        action: Action to perform (read, write, delete)
        
    Returns:
        True if access is allowed
    """
    # Get user roles
    user_roles = {assignment.role.name for assignment in user.role_assignments}
    
    # Admin has access to everything
    if "admin" in user_roles:
        return True
    
    # Healthcare provider access rules
    if "healthcare_provider" in user_roles:
        if resource_type in [ResourceType.USER, ResourceType.AUDIO_FILE, ResourceType.VOICE_ANALYSIS]:
            # Providers can access their assigned patients' data
            # This would check a provider_patient_assignments table
            return True
        if resource_type == ResourceType.AUDIT_LOG and action == "read":
            # Providers can read audit logs for their patients
            return True
    
    # Patient access rules
    if "patient" in user_roles:
        if resource_type == ResourceType.USER:
            # Patients can only access their own user data
            return str(resource_id) == str(user.id)
        if resource_type in [ResourceType.AUDIO_FILE, ResourceType.VOICE_ANALYSIS]:
            # Patients can access their own audio files and analyses
            # This would need to check ownership
            return True
        if resource_type == ResourceType.NOTIFICATION:
            # Patients can access their own notifications
            return True
    
    return False


def check_user_permission(
    user: User,
    permission: str
) -> bool:
    """
    Check if user has a specific permission.
    
    Args:
        user: User object
        permission: Permission name
        
    Returns:
        True if user has permission
    """
    # Map permissions to roles
    permission_role_map = {
        # User management
        "users.create": ["admin"],
        "users.read": ["admin", "healthcare_provider"],
        "users.update": ["admin"],
        "users.delete": ["admin"],
        "users.read_own": ["patient", "healthcare_provider", "admin"],
        "users.update_own": ["patient", "healthcare_provider", "admin"],
        
        # Audio file management
        "audio.upload": ["patient", "healthcare_provider", "admin"],
        "audio.read": ["admin", "healthcare_provider"],
        "audio.read_own": ["patient", "healthcare_provider", "admin"],
        "audio.delete": ["admin"],
        "audio.delete_own": ["patient", "healthcare_provider", "admin"],
        
        # Analysis management
        "analysis.create": ["admin", "healthcare_provider"],
        "analysis.read": ["admin", "healthcare_provider"],
        "analysis.read_own": ["patient", "healthcare_provider", "admin"],
        
        # Audit logs
        "audit.read": ["admin"],
        "audit.read_limited": ["healthcare_provider"],
        
        # Role management
        "roles.assign": ["admin"],
        "roles.revoke": ["admin"],
        
        # System administration
        "system.config": ["admin"],
        "system.maintenance": ["admin"],
    }
    
    # Get required roles for permission
    required_roles = permission_role_map.get(permission, [])
    if not required_roles:
        return False
    
    # Check if user has any of the required roles
    user_roles = {assignment.role.name for assignment in user.role_assignments}
    return any(role in user_roles for role in required_roles)


async def enforce_data_retention(
    db: Session,
    user_id: UUID
) -> None:
    """
    Enforce data retention policy for a user.
    
    Args:
        db: Database session
        user_id: User ID
    """
    from src.database.repositories import UserRepository, AudioFileRepository
    
    user_repo = UserRepository(db)
    audio_repo = AudioFileRepository(db)
    
    # Get user's data retention setting
    user = user_repo.get(user_id)
    if not user:
        return
    
    retention_days = user.data_retention_days or 365
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    # Get files older than retention period
    user_files = audio_repo.get_user_files(user_id, include_deleted=False)
    
    for file in user_files:
        if file.uploaded_at < cutoff_date:
            # Schedule file for deletion
            audio_repo.soft_delete(
                file.id,
                deletion_date=datetime.utcnow() + timedelta(days=30)
            )
            logger.info(f"Scheduled file {file.id} for deletion due to retention policy")


def check_file_ownership(
    db: Session,
    user: User,
    file_id: UUID
) -> bool:
    """
    Check if user owns an audio file.
    
    Args:
        db: Database session
        user: User object
        file_id: Audio file ID
        
    Returns:
        True if user owns the file
    """
    # Admin can access all files
    if any(assignment.role.name == "admin" for assignment in user.role_assignments):
        return True
    
    # Check direct ownership
    file = db.query(AudioFile).filter(
        AudioFile.id == file_id,
        AudioFile.user_id == user.id
    ).first()
    
    if file:
        return True
    
    # Healthcare providers can access their patients' files
    if any(assignment.role.name == "healthcare_provider" for assignment in user.role_assignments):
        # This would check provider_patient_assignments
        # For now, returning False
        return False
    
    return False


def check_analysis_access(
    db: Session,
    user: User,
    analysis_id: UUID
) -> bool:
    """
    Check if user can access a voice analysis.
    
    Args:
        db: Database session
        user: User object
        analysis_id: Analysis ID
        
    Returns:
        True if user can access the analysis
    """
    # Get the analysis
    analysis = db.query(VoiceAnalysis).filter(
        VoiceAnalysis.id == analysis_id
    ).first()
    
    if not analysis:
        return False
    
    # Check access through the associated audio file
    return check_file_ownership(db, user, analysis.audio_file_id)


def require_privacy_consent(user: User) -> None:
    """
    Ensure user has given privacy consent.
    
    Args:
        user: User object
        
    Raises:
        HTTPException: If privacy consent not given
    """
    if not user.privacy_consent:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privacy consent required to access this resource"
        )


def validate_data_access_request(
    user: User,
    resource_type: ResourceType,
    resource_id: UUID,
    purpose: Optional[str] = None
) -> bool:
    """
    Validate and log data access request for HIPAA compliance.
    
    Args:
        user: User requesting access
        resource_type: Type of resource
        resource_id: Resource ID
        purpose: Purpose of access
        
    Returns:
        True if access is valid
    """
    # Check basic access permissions
    if not check_resource_access(user, resource_type, resource_id):
        logger.warning(
            f"Access denied for user {user.id} to {resource_type.value} {resource_id}"
        )
        return False
    
    # Additional validation for sensitive data
    if resource_type in [ResourceType.AUDIO_FILE, ResourceType.VOICE_ANALYSIS]:
        # Ensure user has privacy consent
        require_privacy_consent(user)
    
    return True