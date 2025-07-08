"""Database package for models, connections, and repositories."""

from .database import (
    get_db,
    engine,
    SessionLocal,
    init_db,
    check_database_connection
)
from .models import (
    User,
    UserRole,
    UserRoleAssignment,
    AudioFile,
    VoiceAnalysis,
    UserSession,
    NotificationPreference,
    NotificationHistory,
    AuditLog
)

__all__ = [
    # Database utilities
    "get_db",
    "engine",
    "SessionLocal",
    "init_db",
    "check_database_connection",
    # Models
    "User",
    "UserRole",
    "UserRoleAssignment",
    "AudioFile",
    "VoiceAnalysis",
    "UserSession",
    "NotificationPreference",
    "NotificationHistory",
    "AuditLog",
]