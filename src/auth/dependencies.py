import logging
from typing import Optional, Annotated

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import User
from src.auth.authentication import get_current_user, AuthenticationError
from src.auth.authorization import RoleChecker

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()


async def get_current_user_dependency(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency to get current authenticated user.
    
    Args:
        credentials: HTTP Bearer credentials
        db: Database session
        
    Returns:
        Current user object
        
    Raises:
        HTTPException: If authentication fails
    """
    try:
        token = credentials.credentials
        user = await get_current_user(db, token)
        return user
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise None.
    
    Args:
        request: FastAPI request
        db: Database session
        
    Returns:
        User object or None
    """
    authorization = request.headers.get("Authorization")
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    try:
        token = authorization.split(" ")[1]
        user = await get_current_user(db, token)
        return user
    except Exception:
        return None


# Convenience dependencies for role-based access
CurrentUser = Annotated[User, Depends(get_current_user_dependency)]

# Role-based dependencies
require_admin = Depends(RoleChecker(["admin"]))
require_healthcare_provider = Depends(RoleChecker(["healthcare_provider"]))
require_patient = Depends(RoleChecker(["patient"]))
require_admin_or_provider = Depends(RoleChecker(["admin", "healthcare_provider"]))


async def get_current_active_user(
    current_user: CurrentUser
) -> User:
    """
    Get current active user.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User object
        
    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


# Annotated types for cleaner dependencies
ActiveUser = Annotated[User, Depends(get_current_active_user)]
AdminUser = Annotated[User, Depends(require_admin)]
ProviderUser = Annotated[User, Depends(require_healthcare_provider)]
PatientUser = Annotated[User, Depends(require_patient)]


async def verify_email_token(
    token: str,
    db: Session = Depends(get_db)
) -> str:
    """
    Verify email verification token.
    
    Args:
        token: Email verification token
        db: Database session
        
    Returns:
        User ID from token
        
    Raises:
        HTTPException: If token is invalid
    """
    from src.utils.jwt_utils import decode_jwt_token
    
    try:
        payload = decode_jwt_token(token)
        if payload.get("type") != "email_verification":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        return payload.get("sub")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )


async def verify_password_reset_token(
    token: str,
    db: Session = Depends(get_db)
) -> str:
    """
    Verify password reset token.
    
    Args:
        token: Password reset token
        db: Database session
        
    Returns:
        User ID from token
        
    Raises:
        HTTPException: If token is invalid
    """
    from src.utils.jwt_utils import decode_jwt_token
    
    try:
        payload = decode_jwt_token(token)
        if payload.get("type") != "password_reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        return payload.get("sub")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )