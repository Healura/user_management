import logging
from typing import List, Optional, Callable
from functools import wraps

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from src.database.models import User
from src.database.repositories import UserRoleAssignmentRepository

logger = logging.getLogger(__name__)


class PermissionDeniedError(Exception):
    """Raised when user lacks required permissions."""
    pass


def check_permission(
    user: User,
    required_roles: List[str],
    require_all: bool = False
) -> bool:
    """
    Check if user has required roles.
    
    Args:
        user: User object with role_assignments loaded
        required_roles: List of role names required
        require_all: If True, user must have all roles. If False, any role is sufficient
        
    Returns:
        True if user has required permissions
    """
    if not required_roles:
        return True
    
    user_roles = {assignment.role.name for assignment in user.role_assignments}
    
    if require_all:
        # User must have all required roles
        return all(role in user_roles for role in required_roles)
    else:
        # User must have at least one required role
        return any(role in user_roles for role in required_roles)


def require_role(roles: List[str], require_all: bool = False):
    """
    Decorator to require specific roles for endpoint access.
    
    Args:
        roles: List of role names required
        require_all: If True, user must have all roles
        
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get current_user from kwargs (injected by dependency)
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            if not check_permission(current_user, roles, require_all):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {', '.join(roles)}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    
    return decorator


class RoleChecker:
    """
    Dependency class for role-based access control in FastAPI.
    
    Usage:
        @router.get("/admin", dependencies=[Depends(RoleChecker(["admin"]))])
    """
    
    def __init__(self, allowed_roles: List[str], require_all: bool = False):
        self.allowed_roles = allowed_roles
        self.require_all = require_all
    
    def __call__(self, current_user: User) -> User:
        if not check_permission(current_user, self.allowed_roles, self.require_all):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required roles: {', '.join(self.allowed_roles)}"
            )
        return current_user


# Predefined role checkers for common roles
class RequireAdmin(RoleChecker):
    """Require admin role."""
    def __init__(self):
        super().__init__(["admin"])


class RequireHealthcareProvider(RoleChecker):
    """Require healthcare_provider role."""
    def __init__(self):
        super().__init__(["healthcare_provider"])


class RequirePatient(RoleChecker):
    """Require patient role."""
    def __init__(self):
        super().__init__(["patient"])


class RequireAdminOrProvider(RoleChecker):
    """Require either admin or healthcare_provider role."""
    def __init__(self):
        super().__init__(["admin", "healthcare_provider"], require_all=False)


async def assign_default_role(
    db: Session,
    user_id: str,
    default_role: str = "patient"
) -> None:
    """
    Assign default role to a new user.
    
    Args:
        db: Database session
        user_id: User ID
        default_role: Role name to assign (default: "patient")
    """
    from src.database.repositories import UserRoleRepository
    
    role_repo = UserRoleRepository(db)
    role_assignment_repo = UserRoleAssignmentRepository(db)
    
    # Get the role
    role = role_repo.get_by_name(default_role)
    if not role:
        logger.error(f"Default role '{default_role}' not found")
        raise ValueError(f"Role '{default_role}' not found in database")
    
    try:
        # Assign the role to the user
        role_assignment_repo.assign_role(
            user_id=user_id,
            role_id=role.id
        )
        logger.info(f"Assigned role '{default_role}' to user {user_id}")
    except Exception as e:
        logger.error(f"Failed to assign default role: {e}")
        raise


def get_user_permissions(user: User) -> List[str]:
    """
    Get all permissions for a user based on their roles.
    
    Args:
        user: User object with role_assignments loaded
        
    Returns:
        List of permission names
    """
    # For now, returning role names as permissions
    # In a more complex system, roles would have associated permissions
    return [assignment.role.name for assignment in user.role_assignments]


def has_permission(user: User, permission: str) -> bool:
    """
    Check if user has a specific permission.
    
    Args:
        user: User object
        permission: Permission name
        
    Returns:
        True if user has the permission
    """
    user_permissions = get_user_permissions(user)
    return permission in user_permissions
