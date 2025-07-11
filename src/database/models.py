"""SQLAlchemy models for the user management service."""

import uuid
from datetime import datetime, date, time
from decimal import Decimal
from typing import Optional, Dict, Any

from sqlalchemy import (
    Column, String, Boolean, DateTime, Date, Time, Integer, 
    ForeignKey, UniqueConstraint, DECIMAL, Text, JSON,
    BigInteger, Enum as SQLEnum
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    """User model with comprehensive profile information."""
    
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100))
    last_name = Column(String(100))
    phone_number = Column(String(20))
    date_of_birth = Column(Date)
    healthcare_provider_id = Column(UUID(as_uuid=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    privacy_consent = Column(Boolean, default=False)
    data_retention_days = Column(Integer, default=365)
    
    # Relationships
    role_assignments = relationship("UserRoleAssignment", back_populates="user", foreign_keys="UserRoleAssignment.user_id", cascade="all, delete-orphan")
    audio_files = relationship("AudioFile", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    notification_preferences = relationship("NotificationPreference", back_populates="user", uselist=False, cascade="all, delete-orphan")
    notification_history = relationship("NotificationHistory", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email})>"


class UserRole(Base):
    """User roles for role-based access control."""
    
    __tablename__ = "user_roles"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    assignments = relationship("UserRoleAssignment", back_populates="role", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<UserRole(id={self.id}, name={self.name})>"


class UserRoleAssignment(Base):
    """Many-to-many relationship between users and roles."""
    
    __tablename__ = "user_role_assignments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("user_roles.id", ondelete="CASCADE"), nullable=False)
    assigned_at = Column(DateTime(timezone=True), server_default=func.now())
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    user = relationship("User", back_populates="role_assignments", foreign_keys=[user_id])
    role = relationship("UserRole", back_populates="assignments")
    assigner = relationship("User", foreign_keys=[assigned_by])
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='_user_role_uc'),
    )
    
    def __repr__(self):
        return f"<UserRoleAssignment(user_id={self.user_id}, role_id={self.role_id})>"


class AudioFile(Base):
    """Audio files with metadata and soft delete capability."""
    
    __tablename__ = "audio_files"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(BigInteger)
    duration_seconds = Column(DECIMAL(10, 3))
    mime_type = Column(String(100))
    encryption_key_id = Column(String(255))
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    analysis_status = Column(String(50), default="pending")
    is_deleted = Column(Boolean, default=False)
    scheduled_deletion_at = Column(DateTime(timezone=True))
    
    # Relationships
    user = relationship("User", back_populates="audio_files")
    analyses = relationship("VoiceAnalysis", back_populates="audio_file", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<AudioFile(id={self.id}, filename={self.filename})>"


class VoiceAnalysis(Base):
    """Voice analysis results with emotional metrics."""
    
    __tablename__ = "voice_analyses"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audio_file_id = Column(UUID(as_uuid=True), ForeignKey("audio_files.id", ondelete="CASCADE"), nullable=False, index=True)
    arousal = Column(DECIMAL(5, 4))
    valence = Column(DECIMAL(5, 4))
    dominance = Column(DECIMAL(5, 4))
    phq8_score = Column(Integer)
    gad7_score = Column(Integer)
    confidence_score = Column(DECIMAL(5, 4))
    analysis_model_version = Column(String(50))
    analyzed_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    raw_features = Column(JSONB)
    
    # Relationships
    audio_file = relationship("AudioFile", back_populates="analyses")
    
    def __repr__(self):
        return f"<VoiceAnalysis(id={self.id}, audio_file_id={self.audio_file_id})>"


class UserSession(Base):
    """User sessions and device tracking."""
    
    __tablename__ = "user_sessions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(String(255))
    device_type = Column(String(100))
    ip_address = Column(INET)
    user_agent = Column(Text)
    access_token_hash = Column(String(255))
    refresh_token_hash = Column(String(255))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), index=True)
    last_activity = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    def __repr__(self):
        return f"<UserSession(id={self.id}, user_id={self.user_id})>"


class NotificationPreference(Base):
    """User notification preferences."""
    
    __tablename__ = "notification_preferences"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    reminder_enabled = Column(Boolean, default=True)
    reminder_frequency = Column(String(20), default="daily")
    reminder_time = Column(Time, default=time(9, 0, 0))
    insights_enabled = Column(Boolean, default=True)
    security_alerts_enabled = Column(Boolean, default=True)
    email_enabled = Column(Boolean, default=True)
    sms_enabled = Column(Boolean, default=False)
    push_enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="notification_preferences")
    
    def __repr__(self):
        return f"<NotificationPreference(id={self.id}, user_id={self.user_id})>"


class NotificationHistory(Base):
    """Notification history tracking."""
    
    __tablename__ = "notification_history"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    notification_type = Column(String(50), nullable=False)
    channel = Column(String(20), nullable=False)
    subject = Column(String(255))
    content = Column(Text)
    sent_at = Column(DateTime(timezone=True), server_default=func.now())
    delivery_status = Column(String(20), default="pending")
    error_message = Column(Text)
    
    # Relationships
    user = relationship("User", back_populates="notification_history")
    
    def __repr__(self):
        return f"<NotificationHistory(id={self.id}, user_id={self.user_id}, type={self.notification_type})>"


class AuditLog(Base):
    """Audit log for HIPAA compliance."""
    
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(UUID(as_uuid=True))
    ip_address = Column(INET)
    user_agent = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    details = Column(JSONB)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, action={self.action}, user_id={self.user_id})>"


class UserDevice(Base):
    """User devices for push notifications."""
    
    __tablename__ = "user_devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_token = Column(String(255), nullable=False, unique=True)
    device_type = Column(String(50))  # 'ios', 'android', 'web'
    device_name = Column(String(100))
    platform_version = Column(String(50))
    app_version = Column(String(50))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_used_at = Column(DateTime(timezone=True))
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return f"<UserDevice(id={self.id}, user_id={self.user_id}, device_type={self.device_type})>"


class SMSOptInOut(Base):
    """SMS opt-in/opt-out tracking for compliance."""
    
    __tablename__ = "sms_opt_in_out"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone_number = Column(String(20), nullable=False, index=True)
    status = Column(String(20), nullable=False)  # 'opted_in', 'opted_out'
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    source = Column(String(50))  # 'sms_keyword', 'web_form', 'api', etc.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return f"<SMSOptInOut(id={self.id}, phone_number={self.phone_number}, status={self.status})>"


class ScheduledNotification(Base):
    """One-time scheduled notifications."""
    
    __tablename__ = "scheduled_notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    notification_type = Column(String(50), nullable=False)
    scheduled_time = Column(DateTime(timezone=True), nullable=False)
    status = Column(String(20), default="pending")  # 'pending', 'sent', 'failed', 'cancelled'
    data = Column(JSONB)
    result = Column(JSONB)
    sent_at = Column(DateTime(timezone=True))
    cancelled_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return f"<ScheduledNotification(id={self.id}, user_id={self.user_id}, type={self.notification_type})>"


class RecurringNotification(Base):
    """Recurring scheduled notifications."""
    
    __tablename__ = "recurring_notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    notification_type = Column(String(50), nullable=False)
    schedule_type = Column(String(20), nullable=False)  # 'daily', 'weekly', 'monthly', 'custom_cron', 'interval'
    cron_expression = Column(String(100))
    interval_seconds = Column(Integer)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True))
    timezone = Column(String(50), default="UTC")
    is_active = Column(Boolean, default=True)
    data = Column(JSONB)
    last_run = Column(DateTime(timezone=True))
    next_run = Column(DateTime(timezone=True))
    run_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    cancelled_at = Column(DateTime(timezone=True))
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return f"<RecurringNotification(id={self.id}, user_id={self.user_id}, type={self.notification_type})>"

