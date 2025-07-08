import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from uuid import UUID

from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config.auth_settings import auth_settings
from src.database.models import User
from src.database.repositories import UserRepository, UserSessionRepository
from src.utils.jwt_utils import create_jwt_token, decode_jwt_token
from src.utils.password_utils import verify_password
from src.security.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Base exception for authentication errors."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid."""
    pass


class AccountLockedError(AuthenticationError):
    """Raised when account is locked due to failed attempts."""
    pass


class EmailNotVerifiedError(AuthenticationError):
    """Raised when email is not verified."""
    pass


async def authenticate_user(
    db: Session,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> User:
    """
    Authenticate a user with email and password.
    
    Args:
        db: Database session
        email: User email
        password: Plain text password
        ip_address: Client IP address
        user_agent: Client user agent
        
    Returns:
        Authenticated user object
        
    Raises:
        InvalidCredentialsError: If credentials are invalid
        AccountLockedError: If account is locked
        EmailNotVerifiedError: If email is not verified
    """
    user_repo = UserRepository(db)
    audit_logger = AuditLogger(db)
    
    # Get user by email
    user = user_repo.get_by_email(email)
    if not user:
        # Log failed attempt
        await audit_logger.log_failed_login(
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="User not found"
        )
        raise InvalidCredentialsError("Invalid email or password")
    
    # Check if account is locked
    if await _is_account_locked(db, user.id):
        await audit_logger.log_failed_login(
            email=email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="Account locked"
        )
        raise AccountLockedError("Account is locked due to multiple failed attempts")
    
    # Verify password
    if not verify_password(password, user.password_hash):
        # Increment failed attempts
        await _increment_failed_attempts(db, user.id)
        
        await audit_logger.log_failed_login(
            email=email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="Invalid password"
        )
        raise InvalidCredentialsError("Invalid email or password")
    
    # Check if email is verified
    if not user.email_verified:
        await audit_logger.log_failed_login(
            email=email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="Email not verified"
        )
        raise EmailNotVerifiedError("Please verify your email address")
    
    # Check if account is active
    if not user.is_active:
        await audit_logger.log_failed_login(
            email=email,
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            reason="Account inactive"
        )
        raise InvalidCredentialsError("Account is inactive")
    
    # Reset failed attempts on successful login
    await _reset_failed_attempts(db, user.id)
    
    # Update last login
    user_repo.update_last_login(user.id)
    
    # Log successful login
    await audit_logger.log_successful_login(
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return user


def create_access_token(user: User) -> str:
    """
    Create a JWT access token for a user.
    
    Args:
        user: User object
        
    Returns:
        JWT access token
    """
    # Get user roles
    roles = [assignment.role.name for assignment in user.role_assignments]
    
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "roles": roles,
        "type": "access"
    }
    
    return create_jwt_token(
        payload,
        expires_delta=auth_settings.access_token_expire_timedelta
    )


def create_refresh_token(user: User) -> str:
    """
    Create a JWT refresh token for a user.
    
    Args:
        user: User object
        
    Returns:
        JWT refresh token
    """
    payload = {
        "sub": str(user.id),
        "type": "refresh"
    }
    
    return create_jwt_token(
        payload,
        expires_delta=auth_settings.refresh_token_expire_timedelta
    )


def verify_token(token: str, token_type: str = "access") -> Dict[str, Any]:
    """
    Verify and decode a JWT token.
    
    Args:
        token: JWT token
        token_type: Type of token (access or refresh)
        
    Returns:
        Token payload
        
    Raises:
        JWTError: If token is invalid
    """
    payload = decode_jwt_token(token)
    
    # Verify token type
    if payload.get("type") != token_type:
        raise JWTError("Invalid token type")
    
    return payload


async def get_current_user(
    db: Session,
    token: str
) -> User:
    """
    Get current user from JWT token.
    
    Args:
        db: Database session
        token: JWT access token
        
    Returns:
        Current user object
        
    Raises:
        JWTError: If token is invalid
        AuthenticationError: If user not found
    """
    try:
        payload = verify_token(token, token_type="access")
        user_id = UUID(payload.get("sub"))
    except (JWTError, ValueError) as e:
        logger.error(f"Invalid token: {e}")
        raise AuthenticationError("Invalid authentication token")
    
    user_repo = UserRepository(db)
    user = user_repo.get(user_id)
    
    if not user:
        raise AuthenticationError("User not found")
    
    if not user.is_active:
        raise AuthenticationError("User account is inactive")
    
    return user


async def get_current_active_user(
    db: Session,
    token: str
) -> User:
    """
    Get current active user with valid session.
    
    Args:
        db: Database session
        token: JWT access token
        
    Returns:
        Current active user object
    """
    user = await get_current_user(db, token)
    
    # Additional checks can be added here
    # For example, checking if the session is still valid
    
    return user


async def _is_account_locked(db: Session, user_id: UUID) -> bool:
    """
    Check if account is locked due to failed attempts.
    
    Args:
        db: Database session
        user_id: User ID
        
    Returns:
        True if account is locked
    """
    # This would check a failed_login_attempts table or cache
    # For now, returning False
    return False


async def _increment_failed_attempts(db: Session, user_id: UUID) -> None:
    """
    Increment failed login attempts for a user.
    
    Args:
        db: Database session
        user_id: User ID
    """
    # This would increment a counter in a failed_login_attempts table or cache
    pass


async def _reset_failed_attempts(db: Session, user_id: UUID) -> None:
    """
    Reset failed login attempts for a user.
    
    Args:
        db: Database session
        user_id: User ID
    """
    # This would reset the counter in a failed_login_attempts table or cache
    pass