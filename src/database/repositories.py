"""Repository pattern implementation for database operations."""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import and_, or_, func

from .models import (
    User, UserRole, UserRoleAssignment, AudioFile, 
    VoiceAnalysis, UserSession, NotificationPreference,
    NotificationHistory, AuditLog
)

logger = logging.getLogger(__name__)


class BaseRepository:
    """Base repository with common CRUD operations."""
    
    def __init__(self, db: Session, model):
        self.db = db
        self.model = model
    
    def get(self, id: UUID) -> Optional[Any]:
        """Get a single record by ID."""
        try:
            return self.db.query(self.model).filter(self.model.id == id).first()
        except SQLAlchemyError as e:
            logger.error(f"Error getting {self.model.__name__} by id: {e}")
            raise
    
    def get_all(self, skip: int = 0, limit: int = 100) -> List[Any]:
        """Get all records with pagination."""
        try:
            return self.db.query(self.model).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting all {self.model.__name__}: {e}")
            raise
    
    def create(self, **kwargs) -> Any:
        """Create a new record."""
        try:
            db_obj = self.model(**kwargs)
            self.db.add(db_obj)
            self.db.commit()
            self.db.refresh(db_obj)
            return db_obj
        except SQLAlchemyError as e:
            logger.error(f"Error creating {self.model.__name__}: {e}")
            self.db.rollback()
            raise
    
    def update(self, id: UUID, **kwargs) -> Optional[Any]:
        """Update a record."""
        try:
            db_obj = self.get(id)
            if db_obj:
                for key, value in kwargs.items():
                    setattr(db_obj, key, value)
                self.db.commit()
                self.db.refresh(db_obj)
            return db_obj
        except SQLAlchemyError as e:
            logger.error(f"Error updating {self.model.__name__}: {e}")
            self.db.rollback()
            raise
    
    def delete(self, id: UUID) -> bool:
        """Delete a record."""
        try:
            db_obj = self.get(id)
            if db_obj:
                self.db.delete(db_obj)
                self.db.commit()
                return True
            return False
        except SQLAlchemyError as e:
            logger.error(f"Error deleting {self.model.__name__}: {e}")
            self.db.rollback()
            raise


class UserRepository(BaseRepository):
    """Repository for User operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, User)
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        try:
            return self.db.query(User).filter(User.email == email).first()
        except SQLAlchemyError as e:
            logger.error(f"Error getting user by email: {e}")
            raise
    
    def get_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """Get all active users."""
        try:
            return self.db.query(User).filter(
                User.is_active == True
            ).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting active users: {e}")
            raise
    
    def update_last_login(self, user_id: UUID) -> Optional[User]:
        """Update user's last login timestamp."""
        return self.update(user_id, last_login=datetime.utcnow())
    
    def search_users(self, query: str, skip: int = 0, limit: int = 100) -> List[User]:
        """Search users by email, first name, or last name."""
        try:
            search_filter = or_(
                User.email.ilike(f"%{query}%"),
                User.first_name.ilike(f"%{query}%"),
                User.last_name.ilike(f"%{query}%")
            )
            return self.db.query(User).filter(search_filter).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error searching users: {e}")
            raise


class UserRoleRepository(BaseRepository):
    """Repository for UserRole operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, UserRole)
    
    def get_by_name(self, name: str) -> Optional[UserRole]:
        """Get role by name."""
        try:
            return self.db.query(UserRole).filter(UserRole.name == name).first()
        except SQLAlchemyError as e:
            logger.error(f"Error getting role by name: {e}")
            raise


class UserRoleAssignmentRepository(BaseRepository):
    """Repository for UserRoleAssignment operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, UserRoleAssignment)
    
    def assign_role(self, user_id: UUID, role_id: UUID, assigned_by: Optional[UUID] = None) -> UserRoleAssignment:
        """Assign a role to a user."""
        return self.create(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by
        )
    
    def get_user_roles(self, user_id: UUID) -> List[UserRoleAssignment]:
        """Get all roles assigned to a user."""
        try:
            return self.db.query(UserRoleAssignment).filter(
                UserRoleAssignment.user_id == user_id
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting user roles: {e}")
            raise
    
    def has_role(self, user_id: UUID, role_name: str) -> bool:
        """Check if user has a specific role."""
        try:
            return self.db.query(UserRoleAssignment).join(
                UserRole
            ).filter(
                and_(
                    UserRoleAssignment.user_id == user_id,
                    UserRole.name == role_name
                )
            ).first() is not None
        except SQLAlchemyError as e:
            logger.error(f"Error checking user role: {e}")
            raise


class AudioFileRepository(BaseRepository):
    """Repository for AudioFile operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, AudioFile)
    
    def get_user_files(self, user_id: UUID, include_deleted: bool = False) -> List[AudioFile]:
        """Get all audio files for a user."""
        try:
            query = self.db.query(AudioFile).filter(AudioFile.user_id == user_id)
            if not include_deleted:
                query = query.filter(AudioFile.is_deleted == False)
            return query.order_by(AudioFile.uploaded_at.desc()).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting user audio files: {e}")
            raise
    
    def soft_delete(self, file_id: UUID, deletion_date: Optional[datetime] = None) -> Optional[AudioFile]:
        """Soft delete an audio file."""
        if deletion_date is None:
            deletion_date = datetime.utcnow() + timedelta(days=30)
        
        return self.update(
            file_id,
            is_deleted=True,
            scheduled_deletion_at=deletion_date
        )
    
    def get_files_for_deletion(self) -> List[AudioFile]:
        """Get files scheduled for permanent deletion."""
        try:
            return self.db.query(AudioFile).filter(
                and_(
                    AudioFile.is_deleted == True,
                    AudioFile.scheduled_deletion_at <= datetime.utcnow()
                )
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting files for deletion: {e}")
            raise


class VoiceAnalysisRepository(BaseRepository):
    """Repository for VoiceAnalysis operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, VoiceAnalysis)
    
    def get_by_audio_file(self, audio_file_id: UUID) -> List[VoiceAnalysis]:
        """Get all analyses for an audio file."""
        try:
            return self.db.query(VoiceAnalysis).filter(
                VoiceAnalysis.audio_file_id == audio_file_id
            ).order_by(VoiceAnalysis.analyzed_at.desc()).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting analyses by audio file: {e}")
            raise
    
    def get_latest_analysis(self, audio_file_id: UUID) -> Optional[VoiceAnalysis]:
        """Get the most recent analysis for an audio file."""
        try:
            return self.db.query(VoiceAnalysis).filter(
                VoiceAnalysis.audio_file_id == audio_file_id
            ).order_by(VoiceAnalysis.analyzed_at.desc()).first()
        except SQLAlchemyError as e:
            logger.error(f"Error getting latest analysis: {e}")
            raise


class UserSessionRepository(BaseRepository):
    """Repository for UserSession operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, UserSession)
    
    def get_active_sessions(self, user_id: UUID) -> List[UserSession]:
        """Get all active sessions for a user."""
        try:
            return self.db.query(UserSession).filter(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )
            ).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting active sessions: {e}")
            raise
    
    def invalidate_session(self, session_id: UUID) -> Optional[UserSession]:
        """Invalidate a session."""
        return self.update(session_id, is_active=False)
    
    def invalidate_all_user_sessions(self, user_id: UUID) -> int:
        """Invalidate all sessions for a user."""
        try:
            count = self.db.query(UserSession).filter(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True
                )
            ).update({UserSession.is_active: False})
            self.db.commit()
            return count
        except SQLAlchemyError as e:
            logger.error(f"Error invalidating user sessions: {e}")
            self.db.rollback()
            raise
    
    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions."""
        try:
            count = self.db.query(UserSession).filter(
                UserSession.expires_at < datetime.utcnow()
            ).delete()
            self.db.commit()
            return count
        except SQLAlchemyError as e:
            logger.error(f"Error cleaning up expired sessions: {e}")
            self.db.rollback()
            raise


class NotificationPreferenceRepository(BaseRepository):
    """Repository for NotificationPreference operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, NotificationPreference)
    
    def get_by_user(self, user_id: UUID) -> Optional[NotificationPreference]:
        """Get notification preferences for a user."""
        try:
            return self.db.query(NotificationPreference).filter(
                NotificationPreference.user_id == user_id
            ).first()
        except SQLAlchemyError as e:
            logger.error(f"Error getting notification preferences: {e}")
            raise
    
    def create_default_preferences(self, user_id: UUID) -> NotificationPreference:
        """Create default notification preferences for a new user."""
        return self.create(user_id=user_id)


class NotificationHistoryRepository(BaseRepository):
    """Repository for NotificationHistory operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, NotificationHistory)
    
    def get_user_notifications(
        self, 
        user_id: UUID, 
        notification_type: Optional[str] = None,
        skip: int = 0, 
        limit: int = 100
    ) -> List[NotificationHistory]:
        """Get notification history for a user."""
        try:
            query = self.db.query(NotificationHistory).filter(
                NotificationHistory.user_id == user_id
            )
            if notification_type:
                query = query.filter(NotificationHistory.notification_type == notification_type)
            
            return query.order_by(
                NotificationHistory.sent_at.desc()
            ).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting notification history: {e}")
            raise


class AuditLogRepository(BaseRepository):
    """Repository for AuditLog operations."""
    
    def __init__(self, db: Session):
        super().__init__(db, AuditLog)
    
    def log_action(
        self,
        action: str,
        user_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """Log an audit action."""
        return self.create(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details
        )
    
    def get_user_audit_logs(
        self, 
        user_id: UUID, 
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get audit logs for a user."""
        try:
            query = self.db.query(AuditLog).filter(AuditLog.user_id == user_id)
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            return query.order_by(
                AuditLog.timestamp.desc()
            ).offset(skip).limit(limit).all()
        except SQLAlchemyError as e:
            logger.error(f"Error getting user audit logs: {e}")
            raise
    
    def cleanup_old_logs(self, retention_days: int) -> int:
        """Delete audit logs older than retention period."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            count = self.db.query(AuditLog).filter(
                AuditLog.timestamp < cutoff_date
            ).delete()
            self.db.commit()
            return count
        except SQLAlchemyError as e:
            logger.error(f"Error cleaning up old audit logs: {e}")
            self.db.rollback()
            raise