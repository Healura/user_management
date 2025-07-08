import logging
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import UUID, uuid4

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from config.auth_settings import auth_settings
from src.database.models import UserSession
from src.database.repositories import UserSessionRepository
from src.utils.password_utils import hash_token

logger = logging.getLogger(__name__)


class SessionManager:
    """Manage user sessions with device tracking."""
    
    def __init__(self, db: Session):
        self.db = db
        self.session_repo = UserSessionRepository(db)
    
    async def create_session(
        self,
        user_id: UUID,
        access_token: str,
        refresh_token: str,
        device_id: Optional[str] = None,
        device_type: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> UserSession:
        """
        Create a new user session.
        
        Args:
            user_id: User ID
            access_token: Access token
            refresh_token: Refresh token
            device_id: Device identifier
            device_type: Device type (mobile, web, etc.)
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Created session object
        """
        # Check max sessions limit
        active_sessions = self.session_repo.get_active_sessions(user_id)
        if len(active_sessions) >= auth_settings.max_sessions_per_user:
            # Remove oldest session
            oldest_session = min(active_sessions, key=lambda s: s.created_at)
            await self.invalidate_session(oldest_session.id)
        
        # Create new session
        session = self.session_repo.create(
            user_id=user_id,
            device_id=device_id or str(uuid4()),
            device_type=device_type,
            ip_address=ip_address,
            user_agent=user_agent,
            access_token_hash=hash_token(access_token),
            refresh_token_hash=hash_token(refresh_token),
            expires_at=datetime.utcnow() + auth_settings.refresh_token_expire_timedelta,
            is_active=True
        )
        
        logger.info(f"Created session {session.id} for user {user_id}")
        return session
    
    async def get_session_by_token(
        self,
        refresh_token: str
    ) -> Optional[UserSession]:
        """
        Get session by refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            Session object if found and valid
        """
        token_hash = hash_token(refresh_token)
        
        try:
            sessions = self.db.query(UserSession).filter(
                UserSession.refresh_token_hash == token_hash,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).all()
            
            return sessions[0] if sessions else None
        except SQLAlchemyError as e:
            logger.error(f"Error retrieving session: {e}")
            return None
    
    async def update_session_activity(
        self,
        session_id: UUID
    ) -> None:
        """
        Update session last activity timestamp.
        
        Args:
            session_id: Session ID
        """
        self.session_repo.update(
            session_id,
            last_activity=datetime.utcnow()
        )
    
    async def rotate_refresh_token(
        self,
        session_id: UUID,
        new_refresh_token: str
    ) -> None:
        """
        Rotate refresh token for a session.
        
        Args:
            session_id: Session ID
            new_refresh_token: New refresh token
        """
        self.session_repo.update(
            session_id,
            refresh_token_hash=hash_token(new_refresh_token),
            expires_at=datetime.utcnow() + auth_settings.refresh_token_expire_timedelta
        )
    
    async def invalidate_session(
        self,
        session_id: UUID
    ) -> None:
        """
        Invalidate a specific session.
        
        Args:
            session_id: Session ID
        """
        self.session_repo.invalidate_session(session_id)
        logger.info(f"Invalidated session {session_id}")
    
    async def invalidate_all_user_sessions(
        self,
        user_id: UUID,
        except_session_id: Optional[UUID] = None
    ) -> int:
        """
        Invalidate all sessions for a user.
        
        Args:
            user_id: User ID
            except_session_id: Optional session ID to keep active
            
        Returns:
            Number of sessions invalidated
        """
        if except_session_id:
            # Invalidate all except specified session
            sessions = self.session_repo.get_active_sessions(user_id)
            count = 0
            for session in sessions:
                if session.id != except_session_id:
                    await self.invalidate_session(session.id)
                    count += 1
            return count
        else:
            # Invalidate all sessions
            count = self.session_repo.invalidate_all_user_sessions(user_id)
            logger.info(f"Invalidated {count} sessions for user {user_id}")
            return count
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from database.
        
        Returns:
            Number of sessions cleaned up
        """
        count = self.session_repo.cleanup_expired_sessions()
        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions")
        return count
    
    async def get_user_sessions(
        self,
        user_id: UUID
    ) -> List[UserSession]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        return self.session_repo.get_active_sessions(user_id)
    
    async def check_session_validity(
        self,
        session_id: UUID
    ) -> bool:
        """
        Check if a session is still valid.
        
        Args:
            session_id: Session ID
            
        Returns:
            True if session is valid
        """
        session = self.session_repo.get(session_id)
        
        if not session:
            return False
        
        if not session.is_active:
            return False
        
        if session.expires_at <= datetime.utcnow():
            return False
        
        # Check for inactivity timeout
        if auth_settings.session_timeout_minutes > 0:
            timeout = timedelta(minutes=auth_settings.session_timeout_minutes)
            if session.last_activity + timeout < datetime.utcnow():
                await self.invalidate_session(session_id)
                return False
        
        return True


async def create_user_session(
    db: Session,
    user_id: UUID,
    access_token: str,
    refresh_token: str,
    device_info: Optional[dict] = None
) -> UserSession:
    """
    Helper function to create a user session.
    
    Args:
        db: Database session
        user_id: User ID
        access_token: Access token
        refresh_token: Refresh token
        device_info: Optional device information
        
    Returns:
        Created session
    """
    manager = SessionManager(db)
    
    device_id = device_info.get('device_id') if device_info else None
    device_type = device_info.get('device_type') if device_info else None
    ip_address = device_info.get('ip_address') if device_info else None
    user_agent = device_info.get('user_agent') if device_info else None
    
    return await manager.create_session(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        device_id=device_id,
        device_type=device_type,
        ip_address=ip_address,
        user_agent=user_agent
    )


async def invalidate_session(
    db: Session,
    session_id: UUID
) -> None:
    """
    Helper function to invalidate a session.
    
    Args:
        db: Database session
        session_id: Session ID
    """
    manager = SessionManager(db)
    await manager.invalidate_session(session_id)