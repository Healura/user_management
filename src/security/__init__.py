"""Security module for access control and audit logging."""

from .access_control import (
    check_resource_access,
    check_user_permission,
    enforce_data_retention,
    ResourceType
)
from .audit_logger import (
    AuditLogger,
    log_security_event,
    log_data_access,
    log_authentication_event
)
from .security_middleware import (
    SecurityMiddleware,
    add_security_headers,
    validate_request_origin
)

__all__ = [
    # Access Control
    "check_resource_access",
    "check_user_permission",
    "enforce_data_retention",
    "ResourceType",
    # Audit Logging
    "AuditLogger",
    "log_security_event",
    "log_data_access",
    "log_authentication_event",
    # Security Middleware
    "SecurityMiddleware",
    "add_security_headers",
    "validate_request_origin",
]