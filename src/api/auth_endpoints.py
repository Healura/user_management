import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import User
from src.database.repositories import UserRepository, UserRoleRepository
from src.auth import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    verify_token,
    SessionManager,
    hash_password,
    validate_password,
    MFAManager,
    assign_default_role
)
from src.auth.dependencies import (
    CurrentUser,
    verify_email_token,
    verify_password_reset_token
)
from src.utils import (
    create_email_verification_token,
    create_password_reset_token,
    send_verification_email,
    send_password_reset_email,
    validate_email,
    sanitize_input
)
from src.security import AuditLogger
from src.utils.rate_limiting import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


# Request/Response Models
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    phone_number: Optional[str] = Field(None, max_length=20)
    date_of_birth: Optional[str] = None
    privacy_consent: bool = Field(..., description="User must consent to privacy policy")
    
    @validator('first_name', 'last_name')
    def sanitize_names(cls, v):
        return sanitize_input(v, max_length=100)
    
    @validator('date_of_birth')
    def validate_dob(cls, v):
        if v:
            from src.utils.validation import validate_date_of_birth
            is_valid, error = validate_date_of_birth(v)
            if not is_valid:
                raise ValueError(error)
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_id: Optional[str] = None
    device_type: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Access token expiration in seconds")


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class EmailVerificationRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class MFAEnableRequest(BaseModel):
    password: str  # Require password confirmation


class MFAVerifyRequest(BaseModel):
    token: str


class MessageResponse(BaseModel):
    message: str


# Endpoints
@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """Register a new user with email verification."""
    user_repo = UserRepository(db)
    audit_logger = AuditLogger(db)
    
    # Check if user already exists
    existing_user = user_repo.get_by_email(request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Validate password
    is_valid, errors = validate_password(request.password, request.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors}
        )
    
    # Check privacy consent
    if not request.privacy_consent:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Privacy consent is required"
        )
    
    try:
        # Create user
        user = user_repo.create(
            email=request.email,
            password_hash=hash_password(request.password),
            first_name=request.first_name,
            last_name=request.last_name,
            phone_number=request.phone_number,
            date_of_birth=datetime.strptime(request.date_of_birth, '%Y-%m-%d').date() if request.date_of_birth else None,
            privacy_consent=request.privacy_consent,
            email_verified=False,
            is_active=True
        )
        
        # Assign default role
        await assign_default_role(db, user.id, "patient")
        
        # Create verification token
        verification_token = create_email_verification_token(str(user.id))
        
        # Send verification email
        verification_url = f"https://app.voicebiomarker.com/verify-email?token={verification_token}"
        await send_verification_email(
            user.email,
            verification_url,
            f"{user.first_name} {user.last_name}"
        )
        
        # Log registration
        await audit_logger.log_authentication_event(
            action="register",
            user_id=user.id,
            email=user.email,
            ip_address=req.client.host if req.client else None,
            user_agent=req.headers.get("user-agent"),
            success=True
        )
        
        return MessageResponse(
            message="Registration successful. Please check your email to verify your account."
        )
        
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    request: EmailVerificationRequest,
    db: Session = Depends(get_db)
):
    """Verify email address with token."""
    user_id = await verify_email_token(request.token, db)
    user_repo = UserRepository(db)
    
    # Update user email verification status
    user = user_repo.update(user_id, email_verified=True)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return MessageResponse(message="Email verified successfully. You can now log in.")


@router.post("/login", response_model=TokenResponse)
@rate_limit(max_requests=10, window_seconds=60, key_prefix="login")
async def login(
    request: LoginRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """Login with email and password."""
    try:
        # Authenticate user
        user = await authenticate_user(
            db,
            request.email,
            request.password,
            ip_address=req.client.host if req.client else None,
            user_agent=req.headers.get("user-agent")
        )
        
        # Create tokens
        access_token = create_access_token(user)
        refresh_token = create_refresh_token(user)
        
        # Create session
        session_manager = SessionManager(db)
        await session_manager.create_session(
            user_id=user.id,
            access_token=access_token,
            refresh_token=refresh_token,
            device_id=request.device_id,
            device_type=request.device_type,
            ip_address=req.client.host if req.client else None,
            user_agent=req.headers.get("user-agent")
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=900  # 15 minutes
        )
        
    except Exception as e:
        logger.error(f"Login failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Logout and invalidate tokens."""
    # Invalidate all user sessions
    session_manager = SessionManager(db)
    count = await session_manager.invalidate_all_user_sessions(current_user.id)
    
    # Log logout
    audit_logger = AuditLogger(db)
    await audit_logger.log_authentication_event(
        action="logout",
        user_id=current_user.id,
        success=True
    )
    
    return MessageResponse(message=f"Logged out successfully. {count} sessions invalidated.")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token."""
    try:
        # Verify refresh token
        payload = verify_token(request.refresh_token, token_type="refresh")
        user_id = payload.get("sub")
        
        # Get user
        user_repo = UserRepository(db)
        user = user_repo.get(user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Get session
        session_manager = SessionManager(db)
        session = await session_manager.get_session_by_token(request.refresh_token)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session"
            )
        
        # Create new tokens
        new_access_token = create_access_token(user)
        new_refresh_token = create_refresh_token(user)
        
        # Rotate refresh token
        await session_manager.rotate_refresh_token(session.id, new_refresh_token)
        
        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=900
        )
        
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/forgot-password", response_model=MessageResponse)
@rate_limit(max_requests=3, window_seconds=3600, key_prefix="forgot_password")
async def forgot_password(
    request: ForgotPasswordRequest,
    req: Request,
    db: Session = Depends(get_db)
):
    """Request password reset email."""
    user_repo = UserRepository(db)
    user = user_repo.get_by_email(request.email)
    
    # Always return success to prevent email enumeration
    if user and user.is_active:
        # Create reset token
        reset_token = create_password_reset_token(str(user.id))
        
        # Send reset email
        reset_url = f"https://app.voicebiomarker.com/reset-password?token={reset_token}"
        await send_password_reset_email(
            user.email,
            reset_url,
            f"{user.first_name} {user.last_name}"
        )
        
        # Log password reset request
        audit_logger = AuditLogger(db)
        await audit_logger.log_authentication_event(
            action="password_reset_request",
            user_id=user.id,
            email=user.email,
            ip_address=req.client.host if req.client else None,
            success=True
        )
    
    return MessageResponse(
        message="If an account exists with this email, you will receive password reset instructions."
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    request: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    """Reset password with token."""
    # Verify token and get user ID
    user_id = await verify_password_reset_token(request.token, db)
    
    # Validate new password
    user_repo = UserRepository(db)
    user = user_repo.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    is_valid, errors = validate_password(request.new_password, user.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors}
        )
    
    # Update password
    user_repo.update(
        user_id,
        password_hash=hash_password(request.new_password)
    )
    
    # Invalidate all sessions
    session_manager = SessionManager(db)
    await session_manager.invalidate_all_user_sessions(user_id)
    
    # Log password reset
    audit_logger = AuditLogger(db)
    await audit_logger.log_authentication_event(
        action="password_reset",
        user_id=user_id,
        success=True
    )
    
    return MessageResponse(message="Password reset successfully. Please log in with your new password.")


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: CurrentUser,
    db: Session = Depends(get_db)
):
    """Change password for authenticated user."""
    from src.utils.password_utils import verify_password
    
    # Verify current password
    if not verify_password(request.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Validate new password
    is_valid, errors = validate_password(request.new_password, current_user.email)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors}
        )
    
    # Update password
    user_repo = UserRepository(db)
    user_repo.update(
        current_user.id,
        password_hash=hash_password(request.new_password)
    )
    
    # Log password change
    audit_logger = AuditLogger(db)
    await audit_logger.log_authentication_event(
        action="password_change",
        user_id=current_user.id,
        success=True
    )
    
    return MessageResponse(message="Password changed successfully.")