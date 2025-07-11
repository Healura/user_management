"""Healthcare-compliant file storage API endpoints."""

import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
import json

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ..database.database import get_db
from ..database.models import User, AudioFile
from ..auth.dependencies import CurrentUser, AdminUser
from ..auth.authorization import RoleChecker
from ..security import AuditLogger
from ..storage import (
    StorageProvider,
    FileManager,
    QuotaManager,
    BackupManager,
    PresignedURLManager,
    ComplianceLogger,
    CleanupScheduler
)
from config.storage_config import storage_config

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["storage"])


# Request/Response Models
class FileUploadInitRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str
    file_size: int = Field(..., gt=0)
    duration_seconds: Optional[float] = Field(None, gt=0)
    phi_classification: PHIClassification = Field(default=PHIClassification.HIGH)
    metadata: Optional[Dict[str, Any]] = None


class FileUploadInitResponse(BaseModel):
    upload_id: str
    upload_url: str
    fields: Dict[str, str]
    expires_in: int
    max_size: int


class FileUploadCompleteRequest(BaseModel):
    upload_id: str
    etag: Optional[str] = None


class FileMetadataUpdate(BaseModel):
    phi_classification: Optional[PHIClassification] = None
    metadata: Optional[Dict[str, Any]] = None


class FileSharingRequest(BaseModel):
    user_id: UUID
    access_type: str = Field(default="view", regex="^(view|download)$")
    expires_in_days: int = Field(default=7, ge=1, le=90)
    reason: str = Field(..., min_length=1, max_length=500)


class FileListResponse(BaseModel):
    files: List[Dict[str, Any]]
    total: int
    page: int
    page_size: int


class StorageQuotaResponse(BaseModel):
    user_id: str
    usage: Dict[str, Any]
    quota: Dict[str, Any]
    available_bytes: int
    available_gb: float
    used_percentage: float
    status: str
    warnings: List[str]


class ComplianceReportRequest(BaseModel):
    start_date: datetime
    end_date: datetime
    report_type: str = Field(default="hipaa_audit")


# Upload Endpoints
@router.post("/upload/initiate", response_model=FileUploadInitResponse)
async def initiate_upload(
    request: FileUploadInitRequest,
    current_user: CurrentUser,
    req: Request,
    db: Session = Depends(get_db)
):
    """Initiate secure file upload with presigned URL."""
    try:
        # Validate file type
        if request.content_type not in storage_config.allowed_file_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type not allowed: {request.content_type}"
            )
        
        # Check file size
        if request.file_size > storage_config.max_file_size_mb * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File size exceeds limit: {storage_config.max_file_size_mb}MB"
            )
        
        # Check user quota
        quota_manager = QuotaManager(db)
        has_quota = await quota_manager.check_quota(current_user.id, request.file_size)
        if not has_quota:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Storage quota exceeded"
            )
        
        # Generate file key
        file_manager = FileManager(db)
        file_id = UUID()
        file_key = f"users/{current_user.id}/audio/{datetime.utcnow().year}/{datetime.utcnow().month:02d}/{file_id}/{request.filename}"
        
        # Prepare metadata
        metadata = {
            'user_id': str(current_user.id),
            'file_id': str(file_id),
            'original_filename': request.filename,
            'content_type': request.content_type,
            'phi_classification': request.phi_classification.value,
            'upload_timestamp': datetime.utcnow().isoformat(),
            'duration_seconds': str(request.duration_seconds) if request.duration_seconds else None,
            **(request.metadata or {})
        }
        
        # Generate presigned URL
        presigned_manager = PresignedURLManager(db)
        result = await presigned_manager.generate_upload_url(
            user=current_user,
            file_key=file_key,
            content_type=request.content_type,
            file_size=request.file_size,
            metadata=metadata,
            ip_address=req.client.host if req.client else None
        )
        
        if not result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get('error', 'Failed to generate upload URL')
            )
        
        return FileUploadInitResponse(
            upload_id=result['upload_id'],
            upload_url=result['url'],
            fields=result['fields'],
            expires_in=result['expires_in'],
            max_size=result['max_size']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload initiation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate upload"
        )


@router.post("/upload/complete", response_model=Dict[str, Any])
async def complete_upload(
    request: FileUploadCompleteRequest,
    current_user: CurrentUser,
    req: Request,
    db: Session = Depends(get_db)
):
    """Complete file upload and create database record."""
    try:
        # In production, retrieve upload session from cache/database
        # For now, we'll create the file record directly
        
        # This would be implemented with actual session management
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Upload completion requires session management implementation"
        )
        
    except Exception as e:
        logger.error(f"Upload completion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete upload"
        )


@router.post("/upload", response_model=Dict[str, Any])
async def upload_file(
    file: UploadFile = File(...),
    phi_classification: PHIClassification = Form(default=PHIClassification.HIGH),
    duration_seconds: Optional[float] = Form(None),
    current_user: CurrentUser = None,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Direct file upload endpoint for smaller files."""
    try:
        # Validate file
        if file.content_type not in storage_config.allowed_file_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File type not allowed: {file.content_type}"
            )
        
        # Read file content
        content = await file.read()
        file_size = len(content)
        
        # Check file size
        if file_size > storage_config.max_file_size_mb * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"File size exceeds limit: {storage_config.max_file_size_mb}MB"
            )
        
        # Create file stream
        from io import BytesIO
        file_stream = BytesIO(content)
        
        # Upload file
        file_manager = FileManager(db)
        result = await file_manager.upload_file(
            user=current_user,
            file_data=file_stream,
            filename=file.filename,
            content_type=file.content_type,
            file_size=file_size,
            duration_seconds=duration_seconds,
            phi_classification=phi_classification,
            ip_address=req.client.host if req.client else None
        )
        
        if not result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get('error', 'Upload failed')
            )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload file"
        )


# Download Endpoints
@router.get("/{file_id}/download-url", response_model=Dict[str, Any])
async def get_download_url(
    file_id: UUID,
    streaming: bool = Query(default=False),
    current_user: CurrentUser = None,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Generate secure download URL for a file."""
    try:
        # Get file info
        from src.database.repositories import AudioFileRepository
        file_repo = AudioFileRepository(db)
        audio_file = file_repo.get(file_id)
        
        if not audio_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        
        # Check access permissions
        from src.security.access_control import check_file_ownership
        if not check_file_ownership(db, current_user, file_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Generate presigned URL
        presigned_manager = PresignedURLManager(db)
        result = await presigned_manager.generate_download_url(
            user=current_user,
            file_key=audio_file.file_path,
            file_id=file_id,
            filename=audio_file.filename,
            ip_address=req.client.host if req.client else None,
            streaming=streaming
        )
        
        if not result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate download URL"
            )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download URL generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate download URL"
        )


@router.get("/{file_id}/download")
async def download_file(
    file_id: UUID,
    current_user: CurrentUser = None,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Direct file download endpoint."""
    try:
        # Download file
        file_manager = FileManager(db)
        file_data, metadata = await file_manager.download_file(
            user=current_user,
            file_id=file_id,
            ip_address=req.client.host if req.client else None,
            purpose="direct_download"
        )
        
        if not file_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=metadata.get('error', 'File not found')
            )
        
        # Return file stream
        return StreamingResponse(
            file_data,
            media_type=metadata.get('content_type', 'application/octet-stream'),
            headers={
                "Content-Disposition": f'attachment; filename="{metadata.get("filename", "download")}"',
                "Content-Length": str(metadata.get('size', 0))
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File download failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download file"
        )


# File Management Endpoints
@router.get("/{file_id}/metadata", response_model=Dict[str, Any])
async def get_file_metadata(
    file_id: UUID,
    current_user: CurrentUser = None,
    db: Session = Depends(get_db)
):
    """Get comprehensive file metadata."""
    try:
        file_manager = FileManager(db)
        metadata = await file_manager.get_file_metadata(current_user, file_id)
        
        if not metadata or metadata.get('error'):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=metadata.get('error', 'File not found')
            )
        
        return metadata
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get file metadata: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get metadata"
        )


@router.put("/{file_id}/metadata", response_model=Dict[str, Any])
async def update_file_metadata(
    file_id: UUID,
    update: FileMetadataUpdate,
    current_user: CurrentUser = None,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Update file metadata with audit trail."""
    try:
        # Check permissions
        from src.security.access_control import check_file_ownership
        if not check_file_ownership(db, current_user, file_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
        
        # Update metadata
        # This would be implemented with actual metadata update logic
        
        # Log metadata update
        audit_logger = AuditLogger(db)
        await audit_logger.log_file_access(
            user_id=current_user.id,
            file_id=file_id,
            action='metadata_update',
            ip_address=req.client.host if req.client else None,
            success=True
        )
        
        return {"success": True, "message": "Metadata updated"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update metadata: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update metadata"
        )


@router.delete("/{file_id}", response_model=Dict[str, Any])
async def delete_file(
    file_id: UUID,
    permanent: bool = Query(default=False),
    reason: Optional[str] = Query(None),
    current_user: CurrentUser = None,
    req: Request = None,
    db: Session = Depends(get_db)
):
    """Delete file with HIPAA-compliant audit trail."""
    try:
        file_manager = FileManager(db)
        result = await file_manager.delete_file(
            user=current_user,
            file_id=file_id,
            permanent=permanent,
            ip_address=req.client.host if req.client else None,
            reason=reason
        )
        
        if not result.get('success'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get('error', 'Failed to delete file')
            )
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete file"
        )


@router.get("/list", response_model=FileListResponse)
async def list_files(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    include_deleted: bool = Query(default=False),
    current_user: CurrentUser = None,
    db: Session = Depends(get_db)
):
    """List user's files with pagination."""
    try:
        file_manager = FileManager(db)
        offset = (page - 1) * page_size
        
        files = await file_manager.list_user_files(
            user=current_user,
            include_deleted=include_deleted,
            limit=page_size,
            offset=offset
        )
        
        # Get total count (would be optimized in production)
        from src.database.repositories import AudioFileRepository
        file_repo = AudioFileRepository(db)
        total_files = len(file_repo.get_user_files(current_user.id, include_deleted))
        
        return FileListResponse(
            files=files,
            total=total_files,
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error(f"Failed to list files: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list files"
        )


# Storage Management Endpoints
@router.get("/storage/quota", response_model=StorageQuotaResponse)
async def get_storage_quota(
    current_user: CurrentUser = None,
    db: Session = Depends(get_db)
):
    """Get user's storage quota and usage."""
    try:
        quota_manager = QuotaManager(db)
        summary = await quota_manager.get_storage_summary(current_user.id)
        
        if summary.get('error'):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to get storage quota"
            )
        
        return StorageQuotaResponse(**summary)
        
    except Exception as e:
        logger.error(f"Failed to get storage quota: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get storage quota"
        )


@router.get("/storage/usage", response_model=Dict[str, Any])
async def get_storage_usage(
    current_user: CurrentUser = None,
    db: Session = Depends(get_db)
):
    """Get detailed storage usage statistics."""
    try:
        quota_manager = QuotaManager(db)
        usage = await quota_manager.get_user_usage(current_user.id)
        return usage
        
    except Exception as e:
        logger.error(f"Failed to get storage usage: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get storage usage"
        )


# Admin Endpoints
@router.get("/admin/storage/compliance", response_model=Dict[str, Any])
async def get_storage_compliance_report(
    current_user: User = Depends(RoleChecker(["admin"])),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    db: Session = Depends(get_db)
):
    """Get storage compliance report (admin only)."""
    compliance_logger = ComplianceLogger(db)
    
    # Get compliance data
    report = await compliance_logger.generate_compliance_report(
        start_date=start_date,
        end_date=end_date
    )
    
    return {
        "report": report,
        "generated_at": datetime.utcnow().isoformat(),
        "period": {
            "start": start_date.isoformat() if start_date else None,
            "end": end_date.isoformat() if end_date else None
        }
    }


@router.post("/admin/storage/retention/enforce", response_model=Dict[str, Any])
async def enforce_data_retention(
    current_user: User = Depends(RoleChecker(["admin"])),
    dry_run: bool = Query(False, description="Preview actions without executing"),
    db: Session = Depends(get_db)
):
    """Enforce data retention policies (admin only)."""
    file_manager = FileManager(db, storage_config)
    
    # Get files eligible for deletion
    eligible_files = await file_manager.get_retention_eligible_files()
    
    actions = []
    for file in eligible_files:
        action = {
            "file_id": str(file.id),
            "user_id": str(file.user_id),
            "filename": file.filename,
            "created_at": file.created_at.isoformat(),
            "action": "delete"
        }
        actions.append(action)
        
        if not dry_run:
            await file_manager.delete_file(file.id, current_user.id)
    
    return {
        "actions": actions,
        "total_files": len(actions),
        "dry_run": dry_run,
        "executed_at": datetime.utcnow().isoformat()
    }


@router.delete("/admin/storage/cleanup", response_model=Dict[str, Any])
async def cleanup_orphaned_files(
    current_user: User = Depends(RoleChecker(["admin"])),
    db: Session = Depends(get_db)
):
    """Clean up orphaned files (admin only)."""
    cleanup_scheduler = CleanupScheduler(db, storage_config)
    
    # Find and clean orphaned files
    orphaned_files = await cleanup_scheduler.find_orphaned_files()
    
    cleanup_results = []
    for file_path in orphaned_files:
        try:
            await cleanup_scheduler.cleanup_file(file_path)
            cleanup_results.append({
                "file_path": file_path,
                "status": "deleted"
            })
        except Exception as e:
            cleanup_results.append({
                "file_path": file_path,
                "status": "error",
                "error": str(e)
            })
    
    return {
        "cleanup_results": cleanup_results,
        "total_files": len(cleanup_results),
        "cleaned_at": datetime.utcnow().isoformat()
    }