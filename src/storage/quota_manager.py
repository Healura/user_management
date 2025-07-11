"""Healthcare storage quota management."""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from uuid import UUID
from decimal import Decimal

from sqlalchemy.orm import Session
from sqlalchemy import func

from src.database.models import User, AudioFile
from src.database.repositories import AudioFileRepository
from config.storage_config import storage_config

logger = logging.getLogger(__name__)


class QuotaManager:
    """Manage storage quotas for healthcare compliance."""
    
    def __init__(self, db: Session):
        """Initialize quota manager."""
        self.db = db
        self.file_repo = AudioFileRepository(db)
    
    async def check_quota(
        self,
        user_id: UUID,
        requested_size: int
    ) -> bool:
        """
        Check if user has sufficient quota for upload.
        
        Args:
            user_id: User ID
            requested_size: Size of file to upload in bytes
            
        Returns:
            True if quota available
        """
        try:
            # Get user's current usage
            current_usage = await self.get_user_usage(user_id)
            
            # Get user's quota limit
            quota_limit = await self.get_user_quota_limit(user_id)
            
            # Check if request would exceed quota
            new_usage = current_usage['total_bytes'] + requested_size
            
            if new_usage > quota_limit['quota_bytes']:
                logger.warning(
                    f"Quota exceeded for user {user_id}: "
                    f"{new_usage} > {quota_limit['quota_bytes']}"
                )
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking quota: {e}")
            return False
    
    async def get_user_usage(
        self,
        user_id: UUID
    ) -> Dict[str, Any]:
        """
        Get detailed storage usage for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Usage statistics
        """
        try:
            # Query total usage
            result = self.db.query(
                func.count(AudioFile.id).label('file_count'),
                func.sum(AudioFile.file_size).label('total_size'),
                func.sum(AudioFile.duration_seconds).label('total_duration')
            ).filter(
                AudioFile.user_id == user_id,
                AudioFile.is_deleted == False
            ).first()
            
            file_count = result.file_count or 0
            total_bytes = int(result.total_size or 0)
            total_duration = float(result.total_duration or 0)
            
            # Get usage by file type
            type_usage = self.db.query(
                AudioFile.mime_type,
                func.count(AudioFile.id).label('count'),
                func.sum(AudioFile.file_size).label('size')
            ).filter(
                AudioFile.user_id == user_id,
                AudioFile.is_deleted == False
            ).group_by(AudioFile.mime_type).all()
            
            # Get usage over time
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_usage = self.db.query(
                func.sum(AudioFile.file_size).label('size')
            ).filter(
                AudioFile.user_id == user_id,
                AudioFile.uploaded_at >= thirty_days_ago,
                AudioFile.is_deleted == False
            ).scalar() or 0
            
            return {
                'user_id': str(user_id),
                'file_count': file_count,
                'total_bytes': total_bytes,
                'total_gb': round(total_bytes / (1024 ** 3), 2),
                'total_duration_seconds': total_duration,
                'total_duration_hours': round(total_duration / 3600, 2),
                'recent_usage_bytes': int(recent_usage),
                'usage_by_type': [
                    {
                        'mime_type': item.mime_type,
                        'count': item.count,
                        'bytes': int(item.size),
                        'gb': round(item.size / (1024 ** 3), 2)
                    }
                    for item in type_usage
                ],
                'calculated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error calculating usage: {e}")
            return {
                'user_id': str(user_id),
                'file_count': 0,
                'total_bytes': 0,
                'total_gb': 0,
                'error': str(e)
            }
    
    async def get_user_quota_limit(
        self,
        user_id: UUID
    ) -> Dict[str, Any]:
        """
        Get quota limit for a user based on their role.
        
        Args:
            user_id: User ID
            
        Returns:
            Quota limit information
        """
        try:
            # Get user with roles
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                raise ValueError("User not found")
            
            # Determine quota based on role
            user_roles = [assignment.role.name for assignment in user.role_assignments]
            
            if 'admin' in user_roles:
                quota_gb = storage_config.organization_storage_quota_gb
            elif 'healthcare_provider' in user_roles:
                quota_gb = storage_config.provider_storage_quota_gb
            else:
                quota_gb = storage_config.patient_storage_quota_gb
            
            quota_bytes = quota_gb * (1024 ** 3)
            
            return {
                'user_id': str(user_id),
                'quota_gb': quota_gb,
                'quota_bytes': quota_bytes,
                'quota_type': 'role_based',
                'roles': user_roles,
                'unlimited': 'admin' in user_roles
            }
            
        except Exception as e:
            logger.error(f"Error getting quota limit: {e}")
            # Return default patient quota on error
            return {
                'user_id': str(user_id),
                'quota_gb': storage_config.patient_storage_quota_gb,
                'quota_bytes': storage_config.patient_storage_quota_gb * (1024 ** 3),
                'quota_type': 'default',
                'error': str(e)
            }
    
    async def get_storage_summary(
        self,
        user_id: UUID
    ) -> Dict[str, Any]:
        """
        Get comprehensive storage summary for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Storage summary with usage and limits
        """
        try:
            # Get current usage
            usage = await self.get_user_usage(user_id)
            
            # Get quota limit
            quota = await self.get_user_quota_limit(user_id)
            
            # Calculate percentages
            used_percentage = 0
            if quota['quota_bytes'] > 0:
                used_percentage = round((usage['total_bytes'] / quota['quota_bytes']) * 100, 2)
            
            available_bytes = max(0, quota['quota_bytes'] - usage['total_bytes'])
            
            # Determine status
            if used_percentage >= 95:
                status = 'critical'
            elif used_percentage >= 80:
                status = 'warning'
            else:
                status = 'normal'
            
            return {
                'user_id': str(user_id),
                'usage': usage,
                'quota': quota,
                'available_bytes': available_bytes,
                'available_gb': round(available_bytes / (1024 ** 3), 2),
                'used_percentage': used_percentage,
                'status': status,
                'warnings': self._generate_quota_warnings(used_percentage),
                'summary_generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating storage summary: {e}")
            return {
                'user_id': str(user_id),
                'error': str(e)
            }
    
    async def update_usage(
        self,
        user_id: UUID,
        size_change: int
    ) -> None:
        """
        Update usage tracking (for cache optimization in production).
        
        Args:
            user_id: User ID
            size_change: Bytes added (positive) or removed (negative)
        """
        # In production, this would update a Redis cache
        # For now, we rely on database queries
        logger.info(f"Usage updated for user {user_id}: {size_change:+d} bytes")
    
    async def get_organization_usage(
        self,
        organization_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """
        Get storage usage for an entire organization.
        
        Args:
            organization_id: Organization ID (if applicable)
            
        Returns:
            Organization-wide usage statistics
        """
        try:
            # Get all users (in production, filter by organization)
            total_result = self.db.query(
                func.count(func.distinct(AudioFile.user_id)).label('user_count'),
                func.count(AudioFile.id).label('file_count'),
                func.sum(AudioFile.file_size).label('total_size')
            ).filter(
                AudioFile.is_deleted == False
            ).first()
            
            # Get top users by usage
            top_users = self.db.query(
                AudioFile.user_id,
                User.email,
                func.count(AudioFile.id).label('file_count'),
                func.sum(AudioFile.file_size).label('total_size')
            ).join(
                User, User.id == AudioFile.user_id
            ).filter(
                AudioFile.is_deleted == False
            ).group_by(
                AudioFile.user_id, User.email
            ).order_by(
                func.sum(AudioFile.file_size).desc()
            ).limit(10).all()
            
            return {
                'organization_id': str(organization_id) if organization_id else 'all',
                'total_users': total_result.user_count or 0,
                'total_files': total_result.file_count or 0,
                'total_bytes': int(total_result.total_size or 0),
                'total_tb': round((total_result.total_size or 0) / (1024 ** 4), 2),
                'top_users': [
                    {
                        'user_id': str(user.user_id),
                        'email': user.email,
                        'file_count': user.file_count,
                        'bytes': int(user.total_size),
                        'gb': round(user.total_size / (1024 ** 3), 2)
                    }
                    for user in top_users
                ],
                'calculated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error calculating organization usage: {e}")
            return {'error': str(e)}
    
    async def enforce_quotas(self) -> List[Dict[str, Any]]:
        """
        Enforce quotas by identifying users over limit.
        
        Returns:
            List of users exceeding quotas
        """
        try:
            violations = []
            
            # Get all users with usage
            users_usage = self.db.query(
                AudioFile.user_id,
                func.sum(AudioFile.file_size).label('total_size')
            ).filter(
                AudioFile.is_deleted == False
            ).group_by(
                AudioFile.user_id
            ).all()
            
            for usage in users_usage:
                # Get user's quota
                quota = await self.get_user_quota_limit(usage.user_id)
                
                if usage.total_size > quota['quota_bytes']:
                    violation = {
                        'user_id': str(usage.user_id),
                        'usage_bytes': int(usage.total_size),
                        'quota_bytes': quota['quota_bytes'],
                        'excess_bytes': int(usage.total_size - quota['quota_bytes']),
                        'excess_gb': round((usage.total_size - quota['quota_bytes']) / (1024 ** 3), 2)
                    }
                    violations.append(violation)
                    
                    logger.warning(f"Quota violation detected: {violation}")
            
            return violations
            
        except Exception as e:
            logger.error(f"Error enforcing quotas: {e}")
            return []
    
    def _generate_quota_warnings(
        self,
        used_percentage: float
    ) -> List[str]:
        """Generate appropriate quota warnings."""
        warnings = []
        
        if used_percentage >= 100:
            warnings.append("Storage quota exceeded. Cannot upload new files.")
        elif used_percentage >= 95:
            warnings.append("Critical: Less than 5% storage remaining.")
        elif used_percentage >= 90:
            warnings.append("Warning: Less than 10% storage remaining.")
        elif used_percentage >= 80:
            warnings.append("Notice: Storage usage above 80%.")
        
        return warnings


# Helper functions
async def check_user_quota(
    db: Session,
    user_id: UUID,
    requested_size: int
) -> bool:
    """Check if user has quota for upload."""
    manager = QuotaManager(db)
    return await manager.check_quota(user_id, requested_size)


async def get_storage_usage(
    db: Session,
    user_id: UUID
) -> Dict[str, Any]:
    """Get user's storage usage."""
    manager = QuotaManager(db)
    return await manager.get_storage_summary(user_id)


async def enforce_quota_limits(
    db: Session
) -> List[Dict[str, Any]]:
    """Enforce quota limits system-wide."""
    manager = QuotaManager(db)
    return await manager.enforce_quotas()