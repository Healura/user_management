"""Secure presigned URL generation for healthcare file access."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from uuid import UUID
import json
import hmac
import hashlib

import boto3
from botocore.exceptions import ClientError

from config.storage_config import storage_config, get_s3_client_config
from config.aws_config import aws_config
from src.security.audit_logger import AuditLogger
from src.database.models import User
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class PresignedURLManager:
    """Manage presigned URLs with healthcare security requirements."""
    
    def __init__(self, db: Session):
        """Initialize with S3 client and audit logger."""
        self.db = db
        self.audit_logger = AuditLogger(db)
        
        # Initialize S3 client
        if aws_config.aws_access_key_id:
            session = boto3.Session(
                aws_access_key_id=aws_config.aws_access_key_id,
                aws_secret_access_key=aws_config.aws_secret_access_key.get_secret_value() if aws_config.aws_secret_access_key else None,
                region_name=aws_config.aws_region
            )
            
            client_config = get_s3_client_config()
            self.s3_client = session.client('s3', **client_config)
        else:
            self.s3_client = None
            logger.warning("S3 client not initialized - presigned URLs unavailable")
    
    async def generate_upload_url(
        self,
        user: User,
        file_key: str,
        content_type: str,
        file_size: int,
        metadata: Dict[str, Any],
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate presigned URL for secure file upload.
        
        Args:
            user: User requesting upload
            file_key: S3 object key
            content_type: File MIME type
            file_size: Expected file size
            metadata: File metadata including PHI classification
            ip_address: Client IP address
            
        Returns:
            Presigned URL information
        """
        try:
            if not self.s3_client:
                raise Exception("S3 client not available")
            
            # Set expiration based on file size
            if file_size > 100 * 1024 * 1024:  # > 100MB
                expiry_seconds = storage_config.presigned_url_expiry_minutes * 60 * 2  # Double time for large files
            else:
                expiry_seconds = storage_config.presigned_url_expiry_minutes * 60
            
            # Prepare upload conditions
            conditions = [
                ["content-length-range", 0, file_size + 1024],  # Allow slight overhead
                ["starts-with", "$Content-Type", content_type],
                {"x-amz-server-side-encryption": "aws:kms"},
                {"x-amz-server-side-encryption-aws-kms-key-id": storage_config.aws_kms_key_id}
            ]
            
            # Add metadata conditions
            for key, value in metadata.items():
                conditions.append({f"x-amz-meta-{key.lower()}": str(value)})
            
            # Generate presigned POST URL
            response = self.s3_client.generate_presigned_post(
                Bucket=storage_config.aws_s3_bucket,
                Key=file_key,
                Fields={
                    "Content-Type": content_type,
                    "x-amz-server-side-encryption": "aws:kms",
                    "x-amz-server-side-encryption-aws-kms-key-id": storage_config.aws_kms_key_id,
                    **{f"x-amz-meta-{k.lower()}": str(v) for k, v in metadata.items()}
                },
                Conditions=conditions,
                ExpiresIn=expiry_seconds
            )
            
            # Generate upload ID for tracking
            upload_id = str(UUID())
            
            # Store upload session info (would go to cache/Redis in production)
            upload_session = {
                'upload_id': upload_id,
                'user_id': str(user.id),
                'file_key': file_key,
                'expected_size': file_size,
                'content_type': content_type,
                'phi_classification': metadata.get('phi_classification', 'HIGH'),
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(seconds=expiry_seconds)).isoformat(),
                'ip_address': ip_address
            }
            
            # Log presigned URL generation
            await self.audit_logger.log_security_event(
                event_type="presigned_url_generated",
                user_id=user.id,
                description=f"Upload URL generated for {file_key}",
                ip_address=ip_address,
                details={
                    'upload_id': upload_id,
                    'expiry_seconds': expiry_seconds,
                    'file_size': file_size
                }
            )
            
            return {
                'success': True,
                'upload_id': upload_id,
                'url': response['url'],
                'fields': response['fields'],
                'expires_in': expiry_seconds,
                'max_size': file_size,
                'session': upload_session
            }
            
        except Exception as e:
            logger.error(f"Failed to generate upload URL: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def generate_download_url(
        self,
        user: User,
        file_key: str,
        file_id: UUID,
        filename: str,
        ip_address: Optional[str] = None,
        streaming: bool = False
    ) -> Dict[str, Any]:
        """
        Generate presigned URL for secure file download.
        
        Args:
            user: User requesting download
            file_key: S3 object key
            file_id: File ID for tracking
            filename: Original filename for content disposition
            ip_address: Client IP address
            streaming: Whether URL is for streaming
            
        Returns:
            Presigned download URL information
        """
        try:
            if not self.s3_client:
                raise Exception("S3 client not available")
            
            # Shorter expiry for healthcare security
            expiry_seconds = storage_config.presigned_url_expiry_minutes * 60
            
            # Set response parameters
            response_params = {
                'ResponseContentDisposition': f'{"inline" if streaming else "attachment"}; filename="{filename}"',
                'ResponseContentType': 'audio/mpeg' if streaming else 'application/octet-stream'
            }
            
            # Generate presigned GET URL
            presigned_url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': storage_config.aws_s3_bucket,
                    'Key': file_key,
                    **response_params
                },
                ExpiresIn=expiry_seconds
            )
            
            # Generate download token for additional verification
            download_token = self._generate_download_token(user.id, file_id, ip_address)
            
            # Log URL generation
            await self.audit_logger.log_security_event(
                event_type="presigned_url_generated",
                user_id=user.id,
                description=f"Download URL generated for {filename}",
                ip_address=ip_address,
                details={
                    'file_id': str(file_id),
                    'streaming': streaming,
                    'expiry_seconds': expiry_seconds
                }
            )
            
            return {
                'success': True,
                'url': presigned_url,
                'token': download_token,
                'expires_in': expiry_seconds,
                'streaming': streaming,
                'filename': filename
            }
            
        except Exception as e:
            logger.error(f"Failed to generate download URL: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def generate_multipart_upload_urls(
        self,
        user: User,
        file_key: str,
        parts: int,
        content_type: str,
        metadata: Dict[str, Any],
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate URLs for multipart upload of large files.
        
        Args:
            user: User requesting upload
            file_key: S3 object key
            parts: Number of parts
            content_type: File MIME type
            metadata: File metadata
            ip_address: Client IP address
            
        Returns:
            Multipart upload information
        """
        try:
            if not self.s3_client:
                raise Exception("S3 client not available")
            
            # Initiate multipart upload
            response = self.s3_client.create_multipart_upload(
                Bucket=storage_config.aws_s3_bucket,
                Key=file_key,
                ContentType=content_type,
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=storage_config.aws_kms_key_id,
                Metadata=metadata
            )
            
            upload_id = response['UploadId']
            
            # Generate presigned URLs for each part
            part_urls = []
            expiry_seconds = storage_config.presigned_url_expiry_minutes * 60 * 4  # Longer for multipart
            
            for part_number in range(1, parts + 1):
                url = self.s3_client.generate_presigned_url(
                    'upload_part',
                    Params={
                        'Bucket': storage_config.aws_s3_bucket,
                        'Key': file_key,
                        'UploadId': upload_id,
                        'PartNumber': part_number
                    },
                    ExpiresIn=expiry_seconds
                )
                part_urls.append({
                    'part_number': part_number,
                    'url': url
                })
            
            # Log multipart upload initiation
            await self.audit_logger.log_security_event(
                event_type="multipart_upload_initiated",
                user_id=user.id,
                description=f"Multipart upload started for {file_key}",
                ip_address=ip_address,
                details={
                    'upload_id': upload_id,
                    'parts': parts,
                    'expiry_seconds': expiry_seconds
                }
            )
            
            return {
                'success': True,
                'upload_id': upload_id,
                'file_key': file_key,
                'parts': part_urls,
                'expires_in': expiry_seconds
            }
            
        except Exception as e:
            logger.error(f"Failed to initiate multipart upload: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def complete_multipart_upload(
        self,
        user: User,
        file_key: str,
        upload_id: str,
        parts: List[Dict[str, Any]],
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Complete multipart upload."""
        try:
            if not self.s3_client:
                raise Exception("S3 client not available")
            
            # Complete the upload
            response = self.s3_client.complete_multipart_upload(
                Bucket=storage_config.aws_s3_bucket,
                Key=file_key,
                UploadId=upload_id,
                MultipartUpload={'Parts': parts}
            )
            
            # Log completion
            await self.audit_logger.log_security_event(
                event_type="multipart_upload_completed",
                user_id=user.id,
                description=f"Multipart upload completed for {file_key}",
                ip_address=ip_address,
                details={
                    'upload_id': upload_id,
                    'etag': response.get('ETag')
                }
            )
            
            return {
                'success': True,
                'etag': response.get('ETag'),
                'location': response.get('Location')
            }
            
        except Exception as e:
            logger.error(f"Failed to complete multipart upload: {e}")
            
            # Try to abort the upload
            try:
                self.s3_client.abort_multipart_upload(
                    Bucket=storage_config.aws_s3_bucket,
                    Key=file_key,
                    UploadId=upload_id
                )
            except:
                pass
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_download_token(
        self,
        user_id: UUID,
        file_id: UUID,
        ip_address: Optional[str]
    ) -> str:
        """Generate secure download token for additional verification."""
        # Create token data
        token_data = {
            'user_id': str(user_id),
            'file_id': str(file_id),
            'ip': ip_address or 'unknown',
            'timestamp': datetime.utcnow().isoformat(),
            'expires': (datetime.utcnow() + timedelta(minutes=storage_config.presigned_url_expiry_minutes)).isoformat()
        }
        
        # Generate HMAC signature
        secret = aws_config.aws_secret_access_key.get_secret_value() if aws_config.aws_secret_access_key else 'default-secret'
        message = json.dumps(token_data, sort_keys=True)
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Combine token data and signature
        token = f"{message}|{signature}"
        
        # Base64 encode for URL safety
        import base64
        return base64.urlsafe_b64encode(token.encode('utf-8')).decode('utf-8')
    
    async def validate_download_token(
        self,
        token: str,
        user_id: UUID,
        file_id: UUID,
        ip_address: Optional[str]
    ) -> bool:
        """Validate download token."""
        try:
            # Base64 decode
            import base64
            decoded = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
            
            # Split token and signature
            message, signature = decoded.rsplit('|', 1)
            
            # Verify signature
            secret = aws_config.aws_secret_access_key.get_secret_value() if aws_config.aws_secret_access_key else 'default-secret'
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                message.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if signature != expected_signature:
                return False
            
            # Parse token data
            token_data = json.loads(message)
            
            # Validate token data
            if token_data['user_id'] != str(user_id):
                return False
            
            if token_data['file_id'] != str(file_id):
                return False
            
            # Check expiration
            expires = datetime.fromisoformat(token_data['expires'])
            if datetime.utcnow() > expires:
                return False
            
            # Optionally validate IP
            if storage_config.require_vpc_access and ip_address:
                if token_data['ip'] != ip_address:
                    logger.warning(f"IP mismatch in download token: {token_data['ip']} != {ip_address}")
                    # Could return False here for stricter security
            
            return True
            
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return False


# Helper functions
async def generate_upload_url(
    db: Session,
    user: User,
    file_key: str,
    content_type: str,
    file_size: int,
    metadata: Dict[str, Any],
    **kwargs
) -> Dict[str, Any]:
    """Generate presigned upload URL."""
    manager = PresignedURLManager(db)
    return await manager.generate_upload_url(user, file_key, content_type, file_size, metadata, **kwargs)


async def generate_download_url(
    db: Session,
    user: User,
    file_key: str,
    file_id: UUID,
    filename: str,
    **kwargs
) -> Dict[str, Any]:
    """Generate presigned download URL."""
    manager = PresignedURLManager(db)
    return await manager.generate_download_url(user, file_key, file_id, filename, **kwargs)


async def validate_presigned_url(
    db: Session,
    token: str,
    user_id: UUID,
    file_id: UUID,
    ip_address: Optional[str] = None
) -> bool:
    """Validate presigned URL token."""
    manager = PresignedURLManager(db)
    return await manager.validate_download_token(token, user_id, file_id, ip_address)