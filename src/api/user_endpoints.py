import logging
from typing import Optional, List
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import User, UserSession
from src.database.repositories import (
    UserRepository,
    UserSessionRepository,
    AuditLogRepository
)
from src.auth.dependencies import CurrentUser, AdminUser
from src.auth.authorization import RoleChecker
from src.security import AuditLogger
from src.utils.validation import sanitize_input, validate_phone_number

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])


# Request/Response Models
class UserProfile(BaseModel):
    id: UUID
    email: EmailStr
    first_name: str
    last_name: str
    phone_number: Optional[str]
    date_of_birth: Optional[datetime]
    created_at: datetime
    last_login: Optional[datetime]
    email_verified: bool
    is_active: bool
    privacy_consent: bool
    data_retention_days: int
    roles: List[str]
    
    class Config:
        orm_mode = True


class UpdateProfileRequest(BaseModel):
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    date_of_birth: Optional[str] = None
    data_retention_days: Optional[int] = Field(None, ge=30, le=3650)
    
    @validator('first_name', 'last_name')
    def sanitize_names(cls, v):
        if v:
            return sanitize_input(v, max_length=100)
        return v
    
    @validator('phone_number')
    def validate_phone(cls, v):
        if v:
            is_valid, normalized = validate_phone_number(v)
            if not is_valid:
                raise ValueError("Invalid phone number format")
            return normalized
        return v


class SessionInfo(BaseModel):
    id: UUID
    device_id: str
    device_type: Optional[str]
    ip_address: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool
    
    class Config:
        orm_mode = True


class UserListResponse(BaseModel):
    users: List[UserProfile]
    total: int
    page: int
    page_size: int


class AuditLogEntry(BaseModel):
    id: UUID
    action: str
    resource_type: Optional[str]
    resource_id: Optional[UUID]
    timestamp: datetime
    ip_address: Optional[str]
    details: Optional[dict]
    
    class Config:
        orm_mode = True


# Helper function to format user profile
def format_user_profile(user: User) -> UserProfile:
    """Format user object to UserProfile response."""
    return UserProfile(
        id=user.id,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        phone_number=user.phone_number,
        date_of_birth=user.date_of_birth,
        created_at=user.created_at,
        last_login=user.last_login,
        email_verified=user.email_verified,
        is_active=user.is_active,
        privacy_consent=user.privacy_consent,
        data_retention_days=user.data_retention_days,
        roles=[assignment.role.name for assignment in user.role_assignments]
    )


# Endpoints
@router.get("/profile", response_model=UserProfile)
async def get_profile(
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Get current user profile."""
    # Log profile access
    audit_logger = AuditLogger(db)
    await audit_logger.log_data_access(
        user_id=current_user.id,
        action="read",
        resource_type="user",
        resource_id=current_user.id,
        purpose="View own profile"
    )
    
    return format_user_profile(current_user)


@router.put("/profile", response_model=UserProfile)
async def update_profile(
    request: UpdateProfileRequest,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Update current user profile."""
    user_repo = UserRepository(db)
    
    # Prepare update data
    update_data = {}
    if request.first_name is not None:
        update_data["first_name"] = request.first_name
    if request.last_name is not None:
        update_data["last_name"] = request.last_name
    if request.phone_number is not None:
        update_data["phone_number"] = request.phone_number
    if request.date_of_birth is not None:
        update_data["date_of_birth"] = datetime.strptime(request.date_of_birth, '%Y-%m-%d').date()
    if request.data_retention_days is not None:
        update_data["data_retention_days"] = request.data_retention_days
    
    # Update user
    updated_user = user_repo.update(current_user.id, **update_data)
    
    # Log profile update
    audit_logger = AuditLogger(db)
    await audit_logger.log_user_modification(
        modifier_id=current_user.id,
        user_id=current_user.id,
        action="update_profile",
        changes=update_data
    )
    
    return format_user_profile(updated_user)


@router.delete("/account", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Delete user account (soft delete)."""
    user_repo = UserRepository(db)
    
    # Soft delete - deactivate account
    user_repo.update(current_user.id, is_active=False)
    
    # Invalidate all sessions
    from src.auth.session_manager import SessionManager
    session_manager = SessionManager(db)
    await session_manager.invalidate_all_user_sessions(current_user.id)
    
    # Log account deletion
    audit_logger = AuditLogger(db)
    await audit_logger.log_security_event(
        event_type="account_deletion",
        user_id=current_user.id,
        severity="warning",
        description="User requested account deletion"
    )


@router.get("/sessions", response_model=List[SessionInfo])
async def get_sessions(
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """List active sessions for current user."""
    session_repo = UserSessionRepository(db)
    sessions = session_repo.get_active_sessions(current_user.id)
    
    return [
        SessionInfo(
            id=session.id,
            device_id=session.device_id,
            device_type=session.device_type,
            ip_address=session.ip_address,
            created_at=session.created_at,
            last_activity=session.last_activity,
            expires_at=session.expires_at,
            is_active=session.is_active
        )
        for session in sessions
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: UUID,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Revoke a specific session."""
    session_repo = UserSessionRepository(db)
    
    # Verify session belongs to user
    session = session_repo.get(session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    # Invalidate session
    session_repo.invalidate_session(session_id)
    
    # Log session revocation
    audit_logger = AuditLogger(db)
    await audit_logger.log_security_event(
        event_type="session_revoked",
        user_id=current_user.id,
        description=f"Session {session_id} revoked by user"
    )


@router.delete("/sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_sessions(
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Revoke all sessions for current user."""
    session_repo = UserSessionRepository(db)
    count = session_repo.invalidate_all_user_sessions(current_user.id)
    
    # Log mass session revocation
    audit_logger = AuditLogger(db)
    await audit_logger.log_security_event(
        event_type="all_sessions_revoked",
        user_id=current_user.id,
        severity="warning",
        description=f"All {count} sessions revoked by user"
    )


# Admin endpoints
@router.get("/", response_model=UserListResponse, dependencies=[Depends(RoleChecker(["admin"]))])
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """List all users (admin only)."""
    user_repo = UserRepository(db)
    
    # Calculate offset
    offset = (page - 1) * page_size
    
    # Get users
    if search:
        users = user_repo.search_users(search, skip=offset, limit=page_size)
        # For total count, we'd need a separate count query
        total = 100  # Placeholder
    else:
        if is_active is not None:
            users = user_repo.get_active_users(skip=offset, limit=page_size) if is_active else []
        else:
            users = user_repo.get_all(skip=offset, limit=page_size)
        total = 100  # Placeholder
    
    return UserListResponse(
        users=[format_user_profile(user) for user in users],
        total=total,
        page=page,
        page_size=page_size
    )


@router.put("/{user_id}/status", dependencies=[Depends(RoleChecker(["admin"]))])
async def update_user_status(
    user_id: UUID,
    is_active: bool,
    admin_user: AdminUser,
    db: Session = Depends(get_db)
):
    """Activate or deactivate a user (admin only)."""
    user_repo = UserRepository(db)
    
    # Get user
    user = user_repo.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update status
    user_repo.update(user_id, is_active=is_active)
    
    # Log status change
    audit_logger = AuditLogger(db)
    await audit_logger.log_user_modification(
        modifier_id=admin_user.id,
        user_id=user_id,
        action="status_change",
        changes={"is_active": is_active}
    )
    
    return {"message": f"User {'activated' if is_active else 'deactivated'} successfully"}


@router.get("/{user_id}/audit", response_model=List[AuditLogEntry], dependencies=[Depends(RoleChecker(["admin"]))])
async def get_user_audit_log(
    user_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Get audit log for a specific user (admin only)."""
    audit_repo = AuditLogRepository(db)
    
    # Get audit logs
    logs = audit_repo.get_user_audit_logs(user_id, limit=limit)
    
    return [
        AuditLogEntry(
            id=log.id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            timestamp=log.timestamp,
            ip_address=log.ip_address,
            details=log.details
        )
        for log in logs
    ]