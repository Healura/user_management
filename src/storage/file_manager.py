"""HIPAA-compliant file manager for healthcare file operations."""

import os
import logging
from enum import Enum
from typing import Optional, BinaryIO, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from pathlib import Path

from sqlalchemy.orm import Session

from src.database.models import AudioFile, User
from src.database.repositories import AudioFileRepository
from src.security.audit_logger import AuditLogger
from src.security.access_control import check_file_ownership, check_resource_access, ResourceType
from config.storage_config import storage_config
from .storage_provider import get_storage_provider
from .encryption import FileEncryption
from .quota_manager import QuotaManager
from .compliance_logger import ComplianceLogger

logger = logging.getLogger(__name__)


class PHIClassification(Enum):
    """PHI (Protected Health Information) classification levels."""
    HIGH = "HIGH"          # Identifiable patient data
    MEDIUM = "MEDIUM"      # De-identified but sensitive
    LOW = "LOW"            # Aggregated or anonymous
    PUBLIC = "PUBLIC"      # Non-PHI public data


class FileManager:
    """Healthcare-compliant file manager with PHI protection."""
    
    def __init__(self, db: Session):
        """Initialize file manager with dependencies."""
        self.db = db
        self.storage_provider = get_storage_provider()
        self.encryption = FileEncryption()
        self.quota_manager = QuotaManager(db)
        self.compliance_logger = ComplianceLogger(db)
        self.audit_logger = AuditLogger(db)
        self.file_repo = AudioFileRepository(db)
    
    async def upload_file(
        self,
        user: User,
        file_data: BinaryIO,
        filename: str,
        content_type: str,
        file_size: int,
        duration_seconds: Optional[float] = None,
        phi_classification: PHIClassification = PHIClassification.HIGH,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Upload file with HIPAA compliance and PHI protection.
        
        Args:
            user: User uploading the file
            file_data: File binary data
            filename: Original filename
            content_type: MIME type
            file_size: File size in bytes
            duration_seconds: Audio duration
            phi_classification: PHI classification level
            metadata: Additional metadata
            ip_address: Client IP address
            
        Returns:
            Upload result with file information
        """
        try:
            # Validate file type
            if not self._validate_file_type(content_type, filename):
                raise ValueError(f"File type not allowed: {content_type}")
            
            # Check file size
            if file_size > storage_config.max_file_size_mb * 1024 * 1024:
                raise ValueError(f"File size exceeds limit: {storage_config.max_file_size_mb}MB")
            
            # Check user quota
            if not await self.quota_manager.check_quota(user.id, file_size):
                raise ValueError("Storage quota exceeded")
            
            # Generate secure file key
            file_id = uuid4()
            file_key = self._generate_file_key(user.id, file_id, filename)
            
            # Prepare metadata
            file_metadata = {
                'user_id': str(user.id),
                'original_filename': filename,
                'content_type': content_type,
                'phi_classification': phi_classification.value,
                'upload_timestamp': datetime.utcnow().isoformat(),
                'patient_id': str(user.id),  # For healthcare tracking
                'retention_policy': self._get_retention_policy(phi_classification),
                **(metadata or {})
            }
            
            # Encrypt file if required
            if storage_config.encryption_at_rest_required:
                encrypted_data, encryption_metadata = await self.encryption.encrypt_file(
                    file_data,
                    str(file_id),
                    file_metadata
                )
                file_metadata.update(encryption_metadata)
                upload_data = encrypted_data
            else:
                upload_data = file_data
            
            # Upload to storage
            upload_result = await self.storage_provider.upload_file(
                upload_data,
                file_key,
                file_metadata,
                {'kms_key_id': storage_config.aws_kms_key_id}
            )
            
            if not upload_result.get('success'):
                raise Exception(f"Upload failed: {upload_result.get('error')}")
            
            # Create database record
            audio_file = self.file_repo.create(
                id=file_id,
                user_id=user.id,
                filename=filename,
                file_path=file_key,
                file_size=file_size,
                duration_seconds=duration_seconds,
                mime_type=content_type,
                encryption_key_id=upload_result.get('kms_key_id'),
                analysis_status='pending'
            )
            
            # Update storage quota
            await self.quota_manager.update_usage(user.id, file_size)
            
            # Log PHI access for HIPAA compliance
            await self.compliance_logger.log_phi_access(
                user_id=user.id,
                action='upload',
                resource_type='audio_file',
                resource_id=audio_file.id,
                phi_classification=phi_classification,
                ip_address=ip_address,
                success=True
            )
            
            # Audit log
            await self.audit_logger.log_file_access(
                user_id=user.id,
                file_id=audio_file.id,
                action='upload',
                ip_address=ip_address,
                success=True
            )
            
            return {
                'success': True,
                'file_id': str(audio_file.id),
                'filename': filename,
                'size': file_size,
                'content_type': content_type,
                'phi_classification': phi_classification.value,
                'encryption': upload_result.get('encryption'),
                'storage_class': upload_result.get('storage_class'),
                'retention_policy': file_metadata['retention_policy']
            }
            
        except Exception as e:
            logger.error(f"File upload failed: {e}")
            
            # Log failed attempt
            await self.compliance_logger.log_phi_access(
                user_id=user.id,
                action='upload',
                resource_type='audio_file',
                resource_id=None,
                phi_classification=phi_classification,
                ip_address=ip_address,
                success=False,
                error=str(e)
            )
            
            return {
                'success': False,
                'error': str(e)
            }
    
    async def download_file(
        self,
        user: User,
        file_id: UUID,
        ip_address: Optional[str] = None,
        purpose: Optional[str] = None
    ) -> Tuple[Optional[BinaryIO], Dict[str, Any]]:
        """
        Download file with HIPAA access control and audit.
        
        Args:
            user: User requesting download
            file_id: File ID
            ip_address: Client IP address
            purpose: Purpose of access for audit
            
        Returns:
            Tuple of (file_data, metadata)
        """
        try:
            # Get file record
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                raise ValueError("File not found")
            
            # Check access permissions
            if not check_file_ownership(self.db, user, file_id):
                raise PermissionError("Access denied")
            
            # Check if file is soft deleted
            if audio_file.is_deleted:
                raise ValueError("File has been deleted")
            
            # Download from storage
            file_data, storage_metadata = await self.storage_provider.download_file(
                audio_file.file_path
            )
            
            if not file_data:
                raise Exception("Failed to download file")
            
            # Decrypt if encrypted
            if storage_metadata.get('metadata', {}).get('encryption_version'):
                decrypted_data, integrity_verified = await self.encryption.decrypt_file(
                    file_data,
                    storage_metadata['metadata'],
                    str(file_id)
                )
                
                if not integrity_verified:
                    logger.error(f"File integrity check failed for {file_id}")
                    # Continue but log the issue
                    await self.compliance_logger.log_integrity_failure(
                        file_id=file_id,
                        user_id=user.id,
                        action='download'
                    )
                
                file_data = decrypted_data
            
            # Get PHI classification
            phi_classification = PHIClassification(
                storage_metadata.get('metadata', {}).get('phi_classification', 'HIGH')
            )
            
            # Log PHI access
            await self.compliance_logger.log_phi_access(
                user_id=user.id,
                action='download',
                resource_type='audio_file',
                resource_id=file_id,
                phi_classification=phi_classification,
                ip_address=ip_address,
                purpose=purpose,
                success=True
            )
            
            # Audit log
            await self.audit_logger.log_file_access(
                user_id=user.id,
                file_id=file_id,
                action='download',
                ip_address=ip_address,
                success=True
            )
            
            # Prepare metadata
            metadata = {
                'file_id': str(file_id),
                'filename': audio_file.filename,
                'size': audio_file.file_size,
                'content_type': audio_file.mime_type,
                'uploaded_at': audio_file.uploaded_at.isoformat(),
                'phi_classification': phi_classification.value,
                'integrity_verified': integrity_verified if 'integrity_verified' in locals() else True,
                **storage_metadata
            }
            
            return file_data, metadata
            
        except Exception as e:
            logger.error(f"File download failed: {e}")
            
            # Log failed attempt
            await self.compliance_logger.log_phi_access(
                user_id=user.id,
                action='download',
                resource_type='audio_file',
                resource_id=file_id,
                ip_address=ip_address,
                purpose=purpose,
                success=False,
                error=str(e)
            )
            
            return None, {'success': False, 'error': str(e)}
    
    async def delete_file(
        self,
        user: User,
        file_id: UUID,
        permanent: bool = False,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Delete file with HIPAA-compliant audit trail.
        
        Args:
            user: User requesting deletion
            file_id: File ID
            permanent: Whether to permanently delete
            ip_address: Client IP address
            reason: Reason for deletion
            
        Returns:
            Deletion result
        """
        try:
            # Get file record
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                raise ValueError("File not found")
            
            # Check permissions
            if not check_file_ownership(self.db, user, file_id):
                raise PermissionError("Access denied")
            
            # Check retention policy
            if permanent and not self._can_permanently_delete(audio_file, user):
                raise PermissionError("Cannot permanently delete - retention policy active")
            
            # Get file metadata before deletion
            file_metadata = await self.storage_provider.get_file_metadata(audio_file.file_path)
            phi_classification = PHIClassification(
                file_metadata.get('metadata', {}).get('phi_classification', 'HIGH')
            )
            
            if permanent:
                # Permanent deletion requires additional verification
                logger.warning(f"Permanent deletion requested for file {file_id} by user {user.id}")
                
                # Delete from storage
                deleted = await self.storage_provider.delete_file(audio_file.file_path, permanent=True)
                
                if deleted:
                    # Delete from database
                    self.file_repo.delete(file_id)
                    
                    # Update quota
                    await self.quota_manager.update_usage(user.id, -audio_file.file_size)
            else:
                # Soft delete
                deletion_date = datetime.utcnow() + timedelta(days=30)
                audio_file = self.file_repo.soft_delete(file_id, deletion_date)
                deleted = True
            
            # Log deletion
            await self.compliance_logger.log_file_deletion(
                user_id=user.id,
                file_id=file_id,
                phi_classification=phi_classification,
                permanent=permanent,
                reason=reason,
                ip_address=ip_address,
                success=deleted
            )
            
            # Audit log
            await self.audit_logger.log_file_access(
                user_id=user.id,
                file_id=file_id,
                action='delete' if permanent else 'soft_delete',
                ip_address=ip_address,
                success=deleted
            )
            
            return {
                'success': deleted,
                'permanent': permanent,
                'scheduled_deletion': deletion_date.isoformat() if not permanent else None
            }
            
        except Exception as e:
            logger.error(f"File deletion failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_file_metadata(
        self,
        user: User,
        file_id: UUID
    ) -> Dict[str, Any]:
        """Get comprehensive file metadata with access control."""
        try:
            # Get file record
            audio_file = self.file_repo.get(file_id)
            if not audio_file:
                raise ValueError("File not found")
            
            # Check permissions
            if not check_file_ownership(self.db, user, file_id):
                raise PermissionError("Access denied")
            
            # Get storage metadata
            storage_metadata = await self.storage_provider.get_file_metadata(audio_file.file_path)
            
            # Combine database and storage metadata
            metadata = {
                'file_id': str(audio_file.id),
                'user_id': str(audio_file.user_id),
                'filename': audio_file.filename,
                'file_size': audio_file.file_size,
                'mime_type': audio_file.mime_type,
                'duration_seconds': audio_file.duration_seconds,
                'uploaded_at': audio_file.uploaded_at.isoformat(),
                'analysis_status': audio_file.analysis_status,
                'is_deleted': audio_file.is_deleted,
                'scheduled_deletion_at': audio_file.scheduled_deletion_at.isoformat() if audio_file.scheduled_deletion_at else None,
                'storage_metadata': storage_metadata,
                'phi_classification': storage_metadata.get('metadata', {}).get('phi_classification', 'HIGH'),
                'retention_policy': storage_metadata.get('metadata', {}).get('retention_policy', {}),
                'encryption': {
                    'encrypted': bool(audio_file.encryption_key_id),
                    'encryption_key_id': audio_file.encryption_key_id,
                    'algorithm': storage_metadata.get('metadata', {}).get('algorithm'),
                    'double_encryption': storage_metadata.get('metadata', {}).get('double_encryption', False)
                }
            }
            
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to get file metadata: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def list_user_files(
        self,
        user: User,
        include_deleted: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List user's files with PHI filtering."""
        try:
            # Get files from database
            files = self.file_repo.get_user_files(user.id, include_deleted)
            
            # Apply pagination
            paginated_files = files[offset:offset + limit]
            
            # Build file list with metadata
            file_list = []
            for audio_file in paginated_files:
                # Get storage metadata
                try:
                    storage_metadata = await self.storage_provider.get_file_metadata(audio_file.file_path)
                    phi_classification = storage_metadata.get('metadata', {}).get('phi_classification', 'HIGH')
                except:
                    storage_metadata = {}
                    phi_classification = 'HIGH'
                
                file_list.append({
                    'file_id': str(audio_file.id),
                    'filename': audio_file.filename,
                    'size': audio_file.file_size,
                    'content_type': audio_file.mime_type,
                    'duration_seconds': audio_file.duration_seconds,
                    'uploaded_at': audio_file.uploaded_at.isoformat(),
                    'analysis_status': audio_file.analysis_status,
                    'is_deleted': audio_file.is_deleted,
                    'phi_classification': phi_classification
                })
            
            return file_list
            
        except Exception as e:
            logger.error(f"Failed to list user files: {e}")
            return []
    
    def _validate_file_type(self, content_type: str, filename: str) -> bool:
        """Validate file type against allowed types."""
        # Check MIME type
        if content_type not in storage_config.allowed_file_types:
            return False
        
        # Check file extension
        ext = Path(filename).suffix.lower()
        if ext not in storage_config.allowed_extensions:
            return False
        
        return True
    
    def _generate_file_key(self, user_id: UUID, file_id: UUID, filename: str) -> str:
        """Generate secure S3 key for file storage."""
        # Sanitize filename
        safe_filename = "".join(c for c in filename if c.isalnum() or c in '.-_')
        
        # Generate hierarchical key for better S3 organization
        # Format: users/{user_id}/audio/{year}/{month}/{file_id}/{filename}
        now = datetime.utcnow()
        return f"users/{user_id}/audio/{now.year}/{now.month:02d}/{file_id}/{safe_filename}"
    
    def _get_retention_policy(self, phi_classification: PHIClassification) -> Dict[str, Any]:
        """Get retention policy based on PHI classification."""
        if phi_classification == PHIClassification.HIGH:
            retention_years = storage_config.patient_retention_years
        elif phi_classification == PHIClassification.MEDIUM:
            retention_years = storage_config.healthcare_retention_years
        else:
            retention_years = storage_config.healthcare_retention_years
        
        return {
            'retention_years': retention_years,
            'retention_end_date': (datetime.utcnow() + timedelta(days=retention_years * 365)).isoformat(),
            'auto_delete': storage_config.auto_retention_enforcement,
            'warning_days': storage_config.retention_warning_days
        }
    
    def _can_permanently_delete(self, audio_file: AudioFile, user: User) -> bool:
        """Check if file can be permanently deleted based on retention policy."""
        # Admins can always delete
        if any(assignment.role.name == 'admin' for assignment in user.role_assignments):
            return True
        
        # Check if retention period has passed
        retention_years = storage_config.healthcare_retention_years
        retention_end = audio_file.uploaded_at + timedelta(days=retention_years * 365)
        
        return datetime.utcnow() > retention_end


# Helper functions for direct usage
async def upload_file(
    db: Session,
    user: User,
    file_data: BinaryIO,
    filename: str,
    content_type: str,
    file_size: int,
    **kwargs
) -> Dict[str, Any]:
    """Upload file with HIPAA compliance."""
    manager = FileManager(db)
    return await manager.upload_file(user, file_data, filename, content_type, file_size, **kwargs)


async def download_file(
    db: Session,
    user: User,
    file_id: UUID,
    **kwargs
) -> Tuple[Optional[BinaryIO], Dict[str, Any]]:
    """Download file with access control."""
    manager = FileManager(db)
    return await manager.download_file(user, file_id, **kwargs)


async def delete_file(
    db: Session,
    user: User,
    file_id: UUID,
    **kwargs
) -> Dict[str, Any]:
    """Delete file with audit trail."""
    manager = FileManager(db)
    return await manager.delete_file(user, file_id, **kwargs)


async def get_file_metadata(
    db: Session,
    user: User,
    file_id: UUID
) -> Dict[str, Any]:
    """Get file metadata."""
    manager = FileManager(db)
    return await manager.get_file_metadata(user, file_id)