"""Healthcare retention policy scheduler and cleanup manager."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from src.database.models import AudioFile, User
from src.database.repositories import AudioFileRepository
from config.storage_config import storage_config
from .storage_provider import get_storage_provider
from .compliance_logger import ComplianceLogger
from .quota_manager import QuotaManager

logger = logging.getLogger(__name__)


class CleanupScheduler:
    """Manage file retention and cleanup for HIPAA compliance."""
    
    def __init__(self, db: Session):
        """Initialize cleanup scheduler."""
        self.db = db
        self.file_repo = AudioFileRepository(db)
        self.storage_provider = get_storage_provider()
        self.compliance_logger = ComplianceLogger(db)
        self.quota_manager = QuotaManager(db)
    
    async def schedule_file_deletion(
        self,
        file_id: UUID,
        deletion_date: datetime,
        reason: str = "retention_policy"
    ) -> Dict[str, Any]:
        """
        Schedule a file for deletion.
        
        Args:
            file_id: File to schedule for deletion
            deletion_date: When to delete the file
            reason: Reason for scheduling deletion
            
        Returns:
            Scheduling result
        """
        try:
            # Get file
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                return {'success': False, 'error': 'File not found'}
            
            # Update scheduled deletion
            audio_file = self.file_repo.update(
                file_id,
                scheduled_deletion_at=deletion_date,
                is_deleted=True  # Mark as soft deleted
            )
            
            # Log scheduling
            await self.compliance_logger.log_retention_action(
                action='schedule_deletion',
                affected_files=1,
                details={
                    'file_id': str(file_id),
                    'scheduled_date': deletion_date.isoformat(),
                    'reason': reason
                }
            )
            
            return {
                'success': True,
                'file_id': str(file_id),
                'scheduled_deletion': deletion_date.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to schedule deletion: {e}")
            return {'success': False, 'error': str(e)}
    
    async def process_scheduled_deletions(
        self,
        batch_size: int = 100
    ) -> Dict[str, Any]:
        """
        Process files scheduled for deletion.
        
        Args:
            batch_size: Number of files to process in one batch
            
        Returns:
            Processing summary
        """
        try:
            # Get files ready for deletion
            files_to_delete = self.file_repo.get_files_for_deletion()
            
            if not files_to_delete:
                return {
                    'processed': 0,
                    'deleted': 0,
                    'failed': 0
                }
            
            # Process in batches
            processed = 0
            deleted = 0
            failed = 0
            errors = []
            
            for file in files_to_delete[:batch_size]:
                try:
                    # Delete from storage
                    storage_result = await self.storage_provider.delete_file(
                        file.file_path,
                        permanent=True
                    )
                    
                    if storage_result:
                        # Delete from database
                        self.file_repo.delete(file.id)
                        
                        # Update quota
                        await self.quota_manager.update_usage(
                            file.user_id,
                            -file.file_size
                        )
                        
                        deleted += 1
                        
                        # Log successful deletion
                        await self.compliance_logger.log_retention_action(
                            action='permanent_deletion',
                            affected_files=1,
                            details={
                                'file_id': str(file.id),
                                'reason': 'scheduled_retention_deletion',
                                'file_age_days': (datetime.utcnow() - file.uploaded_at).days
                            }
                        )
                    else:
                        failed += 1
                        errors.append({
                            'file_id': str(file.id),
                            'error': 'Storage deletion failed'
                        })
                        
                except Exception as e:
                    failed += 1
                    errors.append({
                        'file_id': str(file.id),
                        'error': str(e)
                    })
                    logger.error(f"Failed to delete file {file.id}: {e}")
                
                processed += 1
            
            # Log batch summary
            await self.compliance_logger.log_retention_action(
                action='deletion_batch_complete',
                affected_files=processed,
                details={
                    'deleted': deleted,
                    'failed': failed,
                    'errors': errors[:10]  # Limit error details
                }
            )
            
            return {
                'processed': processed,
                'deleted': deleted,
                'failed': failed,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Failed to process scheduled deletions: {e}")
            return {
                'processed': 0,
                'deleted': 0,
                'failed': 0,
                'error': str(e)
            }
    
    async def enforce_retention_policies(
        self,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Enforce retention policies on all files.
        
        Args:
            dry_run: If True, only report what would be done
            
        Returns:
            Enforcement summary
        """
        try:
            results = {
                'files_reviewed': 0,
                'files_scheduled': 0,
                'files_warned': 0,
                'by_classification': {},
                'dry_run': dry_run
            }
            
            # Get all active files
            all_files = self.db.query(AudioFile).filter(
                AudioFile.is_deleted == False
            ).all()
            
            for file in all_files:
                results['files_reviewed'] += 1
                
                # Determine retention period based on metadata
                retention_years = await self._get_file_retention_years(file)
                retention_end = file.uploaded_at + timedelta(days=retention_years * 365)
                
                # Check if past retention
                if datetime.utcnow() > retention_end:
                    if not dry_run:
                        # Schedule for deletion in 30 days
                        deletion_date = datetime.utcnow() + timedelta(days=30)
                        await self.schedule_file_deletion(
                            file.id,
                            deletion_date,
                            reason='retention_policy_enforcement'
                        )
                    
                    results['files_scheduled'] += 1
                    
                    # Track by classification
                    classification = await self._get_file_classification(file)
                    results['by_classification'][classification] = \
                        results['by_classification'].get(classification, 0) + 1
                
                # Check if approaching retention
                elif datetime.utcnow() > retention_end - timedelta(days=storage_config.retention_warning_days):
                    results['files_warned'] += 1
                    
                    if not dry_run:
                        # Send warning notification
                        await self._send_retention_warning(file, retention_end)
            
            # Log enforcement run
            await self.compliance_logger.log_retention_action(
                action='policy_enforcement',
                affected_files=results['files_reviewed'],
                details=results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to enforce retention policies: {e}")
            return {'error': str(e)}
    
    async def get_retention_summary(
        self,
        user_id: Optional[UUID] = None
    ) -> Dict[str, Any]:
        """
        Get retention policy summary.
        
        Args:
            user_id: Optional user ID to filter by
            
        Returns:
            Retention summary
        """
        try:
            # Base query
            query = self.db.query(AudioFile).filter(AudioFile.is_deleted == False)
            
            if user_id:
                query = query.filter(AudioFile.user_id == user_id)
            
            files = query.all()
            
            summary = {
                'total_files': len(files),
                'files_by_age': {},
                'files_approaching_retention': 0,
                'files_past_retention': 0,
                'retention_schedule': []
            }
            
            # Analyze each file
            for file in files:
                # Calculate age
                age_days = (datetime.utcnow() - file.uploaded_at).days
                age_bucket = f"{age_days // 365}y"
                summary['files_by_age'][age_bucket] = \
                    summary['files_by_age'].get(age_bucket, 0) + 1
                
                # Check retention status
                retention_years = await self._get_file_retention_years(file)
                retention_end = file.uploaded_at + timedelta(days=retention_years * 365)
                
                if datetime.utcnow() > retention_end:
                    summary['files_past_retention'] += 1
                elif datetime.utcnow() > retention_end - timedelta(days=storage_config.retention_warning_days):
                    summary['files_approaching_retention'] += 1
                
                # Add to schedule if scheduled for deletion
                if file.scheduled_deletion_at:
                    summary['retention_schedule'].append({
                        'file_id': str(file.id),
                        'filename': file.filename,
                        'scheduled_deletion': file.scheduled_deletion_at.isoformat(),
                        'days_until_deletion': (file.scheduled_deletion_at - datetime.utcnow()).days
                    })
            
            # Sort schedule by deletion date
            summary['retention_schedule'].sort(key=lambda x: x['scheduled_deletion'])
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to get retention summary: {e}")
            return {'error': str(e)}
    
    async def cleanup_orphaned_files(self) -> Dict[str, Any]:
        """Clean up orphaned files in storage."""
        try:
            results = {
                'files_checked': 0,
                'orphaned_found': 0,
                'orphaned_deleted': 0,
                'space_recovered_gb': 0
            }
            
            # Get all files from storage
            storage_files = await self.storage_provider.list_files(limit=1000)
            results['files_checked'] = len(storage_files)
            
            # Get all database file paths
            db_files = set(
                file.file_path for file in 
                self.db.query(AudioFile.file_path).all()
            )
            
            # Find orphaned files
            orphaned_files = []
            for storage_file in storage_files:
                if storage_file['key'] not in db_files:
                    orphaned_files.append(storage_file)
                    results['orphaned_found'] += 1
            
            # Delete orphaned files
            for orphaned in orphaned_files:
                try:
                    success = await self.storage_provider.delete_file(
                        orphaned['key'],
                        permanent=True
                    )
                    
                    if success:
                        results['orphaned_deleted'] += 1
                        results['space_recovered_gb'] += orphaned['size'] / (1024 ** 3)
                        
                except Exception as e:
                    logger.error(f"Failed to delete orphaned file {orphaned['key']}: {e}")
            
            # Log cleanup
            await self.compliance_logger.log_retention_action(
                action='orphaned_cleanup',
                affected_files=results['orphaned_deleted'],
                details=results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to cleanup orphaned files: {e}")
            return {'error': str(e)}
    
    async def _get_file_retention_years(self, file: AudioFile) -> int:
        """Get retention period for a file."""
        # In production, this would check file metadata for classification
        # For now, use default healthcare retention
        return storage_config.healthcare_retention_years
    
    async def _get_file_classification(self, file: AudioFile) -> str:
        """Get PHI classification for a file."""
        try:
            # Get file metadata from storage
            metadata = await self.storage_provider.get_file_metadata(file.file_path)
            return metadata.get('metadata', {}).get('phi_classification', 'HIGH')
        except:
            return 'HIGH'  # Default to highest classification
    
    async def _send_retention_warning(self, file: AudioFile, retention_end: datetime) -> None:
        """Send retention warning notification."""
        # In production, this would send email/notification
        logger.info(
            f"Retention warning for file {file.id}: "
            f"expires on {retention_end.isoformat()}"
        )


# Helper functions
async def schedule_file_deletion(
    db: Session,
    file_id: UUID,
    deletion_date: datetime,
    reason: str = "retention_policy"
) -> Dict[str, Any]:
    """Schedule file for deletion."""
    scheduler = CleanupScheduler(db)
    return await scheduler.schedule_file_deletion(file_id, deletion_date, reason)


async def process_scheduled_deletions(
    db: Session,
    batch_size: int = 100
) -> Dict[str, Any]:
    """Process scheduled deletions."""
    scheduler = CleanupScheduler(db)
    return await scheduler.process_scheduled_deletions(batch_size)


async def enforce_retention_policies(
    db: Session,
    dry_run: bool = True
) -> Dict[str, Any]:
    """Enforce retention policies."""
    scheduler = CleanupScheduler(db)
    return await scheduler.enforce_retention_policies(dry_run)