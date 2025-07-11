"""Healthcare backup and recovery manager for data protection."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID
import json

from sqlalchemy.orm import Session

from src.database.models import AudioFile
from src.database.repositories import AudioFileRepository
from config.storage_config import storage_config
from .storage_provider import get_storage_provider
from .compliance_logger import ComplianceLogger

logger = logging.getLogger(__name__)


class BackupManager:
    """Manage file backups and versioning for healthcare compliance."""
    
    def __init__(self, db: Session):
        """Initialize backup manager."""
        self.db = db
        self.file_repo = AudioFileRepository(db)
        self.storage_provider = get_storage_provider()
        self.compliance_logger = ComplianceLogger(db)
    
    async def create_backup(
        self,
        file_id: UUID,
        reason: str = "scheduled"
    ) -> Dict[str, Any]:
        """
        Create backup of a file.
        
        Args:
            file_id: File to backup
            reason: Reason for backup
            
        Returns:
            Backup result
        """
        try:
            # Get file info
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                return {'success': False, 'error': 'File not found'}
            
            # Generate backup key
            backup_key = self._generate_backup_key(audio_file.file_path)
            
            # Copy file to backup location
            success = await self.storage_provider.copy_file(
                source_key=audio_file.file_path,
                destination_key=backup_key
            )
            
            if success:
                # Store backup metadata
                backup_metadata = {
                    'original_file_id': str(file_id),
                    'original_path': audio_file.file_path,
                    'backup_timestamp': datetime.utcnow().isoformat(),
                    'backup_reason': reason,
                    'retention_days': storage_config.backup_retention_days
                }
                
                # Log backup creation
                await self.compliance_logger.log_retention_action(
                    action='backup_created',
                    affected_files=1,
                    details={
                        'file_id': str(file_id),
                        'backup_key': backup_key,
                        'reason': reason
                    }
                )
                
                return {
                    'success': True,
                    'backup_key': backup_key,
                    'metadata': backup_metadata
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to create backup'
                }
                
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def restore_backup(
        self,
        file_id: UUID,
        backup_version: Optional[str] = None,
        reason: str = "user_requested"
    ) -> Dict[str, Any]:
        """
        Restore file from backup.
        
        Args:
            file_id: Original file ID
            backup_version: Specific backup version to restore
            reason: Reason for restoration
            
        Returns:
            Restoration result
        """
        try:
            # Get file info
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                return {'success': False, 'error': 'File not found'}
            
            # Find backup
            backups = await self.list_backups(file_id)
            if not backups:
                return {'success': False, 'error': 'No backups found'}
            
            # Select backup to restore
            if backup_version:
                backup = next((b for b in backups if b['version'] == backup_version), None)
                if not backup:
                    return {'success': False, 'error': 'Backup version not found'}
            else:
                # Use most recent backup
                backup = backups[0]
            
            # Create current version backup before restore
            await self.create_backup(file_id, reason="pre_restore_backup")
            
            # Restore from backup
            success = await self.storage_provider.copy_file(
                source_key=backup['backup_key'],
                destination_key=audio_file.file_path
            )
            
            if success:
                # Log restoration
                await self.compliance_logger.log_retention_action(
                    action='backup_restored',
                    affected_files=1,
                    details={
                        'file_id': str(file_id),
                        'backup_version': backup['version'],
                        'reason': reason
                    }
                )
                
                return {
                    'success': True,
                    'restored_from': backup['backup_key'],
                    'backup_date': backup['created_at']
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to restore backup'
                }
                
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def list_backups(
        self,
        file_id: UUID
    ) -> List[Dict[str, Any]]:
        """
        List all backups for a file.
        
        Args:
            file_id: File ID
            
        Returns:
            List of backups
        """
        try:
            # Get file info
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                return []
            
            # Get backup prefix
            backup_prefix = f"backups/{audio_file.file_path}"
            
            # List backups from storage
            backup_files = await self.storage_provider.list_files(prefix=backup_prefix)
            
            backups = []
            for backup_file in backup_files:
                # Extract version from key
                version = backup_file['key'].split('/')[-1]
                
                # Get backup metadata
                metadata = await self.storage_provider.get_file_metadata(backup_file['key'])
                
                backups.append({
                    'version': version,
                    'backup_key': backup_file['key'],
                    'size': backup_file['size'],
                    'created_at': backup_file['last_modified'].isoformat(),
                    'metadata': metadata.get('metadata', {})
                })
            
            # Sort by creation date (newest first)
            backups.sort(key=lambda x: x['created_at'], reverse=True)
            
            return backups
            
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return []
    
    async def cleanup_old_backups(
        self,
        retention_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Clean up old backups past retention period.
        
        Args:
            retention_days: Override default retention days
            
        Returns:
            Cleanup summary
        """
        try:
            if retention_days is None:
                retention_days = storage_config.backup_retention_days
            
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            results = {
                'backups_reviewed': 0,
                'backups_deleted': 0,
                'space_recovered_gb': 0,
                'errors': []
            }
            
            # List all backups
            all_backups = await self.storage_provider.list_files(prefix="backups/")
            results['backups_reviewed'] = len(all_backups)
            
            for backup in all_backups:
                if backup['last_modified'] < cutoff_date:
                    try:
                        # Delete old backup
                        success = await self.storage_provider.delete_file(
                            backup['key'],
                            permanent=True
                        )
                        
                        if success:
                            results['backups_deleted'] += 1
                            results['space_recovered_gb'] += backup['size'] / (1024 ** 3)
                            
                    except Exception as e:
                        results['errors'].append({
                            'backup_key': backup['key'],
                            'error': str(e)
                        })
            
            # Log cleanup
            await self.compliance_logger.log_retention_action(
                action='backup_cleanup',
                affected_files=results['backups_deleted'],
                details=results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to cleanup backups: {e}")
            return {'error': str(e)}
    
    async def create_system_backup(
        self,
        backup_type: str = "daily"
    ) -> Dict[str, Any]:
        """
        Create system-wide backup of all files.
        
        Args:
            backup_type: Type of backup (daily, weekly, monthly)
            
        Returns:
            Backup summary
        """
        try:
            results = {
                'backup_type': backup_type,
                'started_at': datetime.utcnow().isoformat(),
                'files_backed_up': 0,
                'failed_backups': 0,
                'total_size_gb': 0
            }
            
            # Get all active files
            active_files = self.db.query(AudioFile).filter(
                AudioFile.is_deleted == False
            ).all()
            
            for file in active_files:
                try:
                    backup_result = await self.create_backup(
                        file.id,
                        reason=f"{backup_type}_backup"
                    )
                    
                    if backup_result['success']:
                        results['files_backed_up'] += 1
                        results['total_size_gb'] += file.file_size / (1024 ** 3)
                    else:
                        results['failed_backups'] += 1
                        
                except Exception as e:
                    results['failed_backups'] += 1
                    logger.error(f"Failed to backup file {file.id}: {e}")
            
            results['completed_at'] = datetime.utcnow().isoformat()
            
            # Log system backup
            await self.compliance_logger.log_retention_action(
                action='system_backup',
                affected_files=results['files_backed_up'],
                details=results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to create system backup: {e}")
            return {'error': str(e)}
    
    def _generate_backup_key(self, original_key: str) -> str:
        """Generate backup storage key."""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        return f"backups/{original_key}/{timestamp}"
    
    async def verify_backup_integrity(
        self,
        file_id: UUID
    ) -> Dict[str, Any]:
        """
        Verify integrity of file backups.
        
        Args:
            file_id: File ID to verify backups for
            
        Returns:
            Verification results
        """
        try:
            results = {
                'file_id': str(file_id),
                'backups_checked': 0,
                'backups_valid': 0,
                'backups_corrupted': 0,
                'details': []
            }
            
            # Get all backups
            backups = await self.list_backups(file_id)
            results['backups_checked'] = len(backups)
            
            for backup in backups:
                try:
                    # Download backup metadata
                    metadata = await self.storage_provider.get_file_metadata(backup['backup_key'])
                    
                    if metadata.get('success'):
                        results['backups_valid'] += 1
                        results['details'].append({
                            'version': backup['version'],
                            'status': 'valid',
                            'size': metadata.get('content_length')
                        })
                    else:
                        results['backups_corrupted'] += 1
                        results['details'].append({
                            'version': backup['version'],
                            'status': 'corrupted',
                            'error': metadata.get('error')
                        })
                        
                except Exception as e:
                    results['backups_corrupted'] += 1
                    results['details'].append({
                        'version': backup['version'],
                        'status': 'error',
                        'error': str(e)
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to verify backups: {e}")
            return {'error': str(e)}


# Helper functions
async def create_backup(
    db: Session,
    file_id: UUID,
    reason: str = "scheduled"
) -> Dict[str, Any]:
    """Create file backup."""
    manager = BackupManager(db)
    return await manager.create_backup(file_id, reason)


async def restore_backup(
    db: Session,
    file_id: UUID,
    backup_version: Optional[str] = None,
    reason: str = "user_requested"
) -> Dict[str, Any]:
    """Restore file from backup."""
    manager = BackupManager(db)
    return await manager.restore_backup(file_id, backup_version, reason)


async def list_backups(
    db: Session,
    file_id: UUID
) -> List[Dict[str, Any]]:
    """List file backups."""
    manager = BackupManager(db)
    return await manager.list_backups(file_id)