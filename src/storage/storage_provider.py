import os
import shutil
import logging
from abc import ABC, abstractmethod
from typing import Optional, BinaryIO, Dict, Any, Tuple
from datetime import datetime
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from config.storage_config import storage_config, get_s3_client_config
from config.aws_config import aws_config

logger = logging.getLogger(__name__)


class StorageProvider(ABC):
    """Abstract base class for storage providers."""
    
    @abstractmethod
    async def upload_file(
        self,
        file_data: BinaryIO,
        file_key: str,
        metadata: Optional[Dict[str, str]] = None,
        encryption_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Upload a file to storage."""
        pass
    
    @abstractmethod
    async def download_file(
        self,
        file_key: str,
        destination: Optional[str] = None
    ) -> Tuple[BinaryIO, Dict[str, Any]]:
        """Download a file from storage."""
        pass
    
    @abstractmethod
    async def delete_file(
        self,
        file_key: str,
        permanent: bool = False
    ) -> bool:
        """Delete a file from storage."""
        pass
    
    @abstractmethod
    async def file_exists(
        self,
        file_key: str
    ) -> bool:
        """Check if a file exists."""
        pass
    
    @abstractmethod
    async def get_file_metadata(
        self,
        file_key: str
    ) -> Dict[str, Any]:
        """Get file metadata."""
        pass
    
    @abstractmethod
    async def list_files(
        self,
        prefix: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List files in storage."""
        pass
    
    @abstractmethod
    async def copy_file(
        self,
        source_key: str,
        destination_key: str
    ) -> bool:
        """Copy a file within storage."""
        pass
    
    @abstractmethod
    async def move_file(
        self,
        source_key: str,
        destination_key: str
    ) -> bool:
        """Move a file within storage."""
        pass


class S3StorageProvider(StorageProvider):
    """S3 storage provider with healthcare compliance features."""
    
    def __init__(self):
        """Initialize S3 client with VPC endpoint configuration."""
        self.bucket_name = storage_config.aws_s3_bucket
        self.client_config = get_s3_client_config()
        
        # Create S3 client with VPC endpoint if configured
        session = boto3.Session(
            aws_access_key_id=aws_config.aws_access_key_id,
            aws_secret_access_key=aws_config.aws_secret_access_key.get_secret_value() if aws_config.aws_secret_access_key else None,
            region_name=self.client_config['region_name']
        )
        
        self.s3_client = session.client('s3', **self.client_config)
        self.kms_client = session.client('kms', region_name=self.client_config['region_name'])
        
        logger.info(f"S3 storage provider initialized with bucket: {self.bucket_name}")
        if storage_config.s3_vpc_endpoint_url:
            logger.info(f"Using VPC endpoint: {storage_config.s3_vpc_endpoint_url}")
    
    async def upload_file(
        self,
        file_data: BinaryIO,
        file_key: str,
        metadata: Optional[Dict[str, str]] = None,
        encryption_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Upload file to S3 with healthcare encryption."""
        try:
            # Prepare upload parameters
            upload_params = {
                'Bucket': self.bucket_name,
                'Key': file_key,
                'Body': file_data,
                'ServerSideEncryption': 'aws:kms',
                'SSEKMSKeyId': storage_config.aws_kms_key_id,
                'StorageClass': 'STANDARD_IA'  # Infrequent access for cost optimization
            }
            
            # Add metadata if provided
            if metadata:
                # Add PHI classification to metadata
                metadata['PHIClassification'] = metadata.get('PHIClassification', storage_config.default_phi_classification)
                metadata['UploadTimestamp'] = datetime.utcnow().isoformat()
                metadata['ComplianceMode'] = 'HIPAA'
                upload_params['Metadata'] = metadata
            
            # Add tagging for compliance
            tags = {
                'Environment': 'production',
                'Compliance': 'HIPAA',
                'DataType': 'PHI',
                'Retention': str(storage_config.healthcare_retention_years)
            }
            upload_params['Tagging'] = '&'.join([f"{k}={v}" for k, v in tags.items()])
            
            # Perform upload
            response = self.s3_client.put_object(**upload_params)
            
            # Log successful upload
            logger.info(f"File uploaded successfully: {file_key}")
            
            return {
                'success': True,
                'key': file_key,
                'etag': response.get('ETag', '').strip('"'),
                'version_id': response.get('VersionId'),
                'encryption': response.get('ServerSideEncryption'),
                'kms_key_id': response.get('SSEKMSKeyId'),
                'storage_class': upload_params['StorageClass']
            }
            
        except ClientError as e:
            logger.error(f"S3 upload failed for {file_key}: {e}")
            return {
                'success': False,
                'error': str(e),
                'error_code': e.response.get('Error', {}).get('Code', 'Unknown')
            }
        except Exception as e:
            logger.error(f"Unexpected error during upload: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def download_file(
        self,
        file_key: str,
        destination: Optional[str] = None
    ) -> Tuple[Optional[BinaryIO], Dict[str, Any]]:
        """Download file from S3 with compliance tracking."""
        try:
            # Get object
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=file_key
            )
            
            # Extract metadata
            metadata = {
                'content_type': response.get('ContentType'),
                'content_length': response.get('ContentLength'),
                'etag': response.get('ETag', '').strip('"'),
                'last_modified': response.get('LastModified'),
                'version_id': response.get('VersionId'),
                'metadata': response.get('Metadata', {}),
                'encryption': response.get('ServerSideEncryption'),
                'storage_class': response.get('StorageClass')
            }
            
            # Handle file data
            file_data = response['Body']
            
            if destination:
                # Save to file if destination provided
                with open(destination, 'wb') as f:
                    f.write(file_data.read())
                logger.info(f"File downloaded to: {destination}")
                return None, metadata
            else:
                # Return file stream
                return file_data, metadata
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"S3 download failed for {file_key}: {error_code}")
            return None, {
                'success': False,
                'error': str(e),
                'error_code': error_code
            }
        except Exception as e:
            logger.error(f"Unexpected error during download: {e}")
            return None, {
                'success': False,
                'error': str(e)
            }
    
    async def delete_file(
        self,
        file_key: str,
        permanent: bool = False
    ) -> bool:
        """Delete file from S3 with compliance verification."""
        try:
            if permanent:
                # Permanent deletion requires additional verification
                logger.warning(f"Permanent deletion requested for: {file_key}")
                
                # Delete all versions if versioning is enabled
                if storage_config.enable_versioning:
                    # List all versions
                    versions = self.s3_client.list_object_versions(
                        Bucket=self.bucket_name,
                        Prefix=file_key
                    )
                    
                    # Delete each version
                    for version in versions.get('Versions', []):
                        self.s3_client.delete_object(
                            Bucket=self.bucket_name,
                            Key=file_key,
                            VersionId=version['VersionId']
                        )
                    
                    # Delete delete markers
                    for marker in versions.get('DeleteMarkers', []):
                        self.s3_client.delete_object(
                            Bucket=self.bucket_name,
                            Key=file_key,
                            VersionId=marker['VersionId']
                        )
                else:
                    # Simple deletion
                    self.s3_client.delete_object(
                        Bucket=self.bucket_name,
                        Key=file_key
                    )
            else:
                # Soft delete - just add delete marker
                self.s3_client.delete_object(
                    Bucket=self.bucket_name,
                    Key=file_key
                )
            
            logger.info(f"File deleted {'permanently' if permanent else 'soft'}: {file_key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 deletion failed for {file_key}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during deletion: {e}")
            return False
    
    async def file_exists(
        self,
        file_key: str
    ) -> bool:
        """Check if file exists in S3."""
        try:
            self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=file_key
            )
            return True
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == '404':
                return False
            logger.error(f"Error checking file existence: {e}")
            return False
    
    async def get_file_metadata(
        self,
        file_key: str
    ) -> Dict[str, Any]:
        """Get comprehensive file metadata from S3."""
        try:
            response = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=file_key
            )
            
            # Get tags
            tags_response = self.s3_client.get_object_tagging(
                Bucket=self.bucket_name,
                Key=file_key
            )
            tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagSet', [])}
            
            return {
                'success': True,
                'content_type': response.get('ContentType'),
                'content_length': response.get('ContentLength'),
                'etag': response.get('ETag', '').strip('"'),
                'last_modified': response.get('LastModified'),
                'version_id': response.get('VersionId'),
                'metadata': response.get('Metadata', {}),
                'encryption': response.get('ServerSideEncryption'),
                'storage_class': response.get('StorageClass'),
                'tags': tags
            }
            
        except ClientError as e:
            logger.error(f"Failed to get metadata for {file_key}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def list_files(
        self,
        prefix: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List files in S3 with metadata."""
        try:
            params = {
                'Bucket': self.bucket_name,
                'MaxKeys': limit
            }
            if prefix:
                params['Prefix'] = prefix
            
            response = self.s3_client.list_objects_v2(**params)
            
            files = []
            for obj in response.get('Contents', []):
                files.append({
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'],
                    'etag': obj['ETag'].strip('"'),
                    'storage_class': obj.get('StorageClass', 'STANDARD')
                })
            
            return files
            
        except ClientError as e:
            logger.error(f"Failed to list files: {e}")
            return []
    
    async def copy_file(
        self,
        source_key: str,
        destination_key: str
    ) -> bool:
        """Copy file within S3 with metadata preservation."""
        try:
            copy_source = {
                'Bucket': self.bucket_name,
                'Key': source_key
            }
            
            # Copy with same encryption settings
            self.s3_client.copy_object(
                CopySource=copy_source,
                Bucket=self.bucket_name,
                Key=destination_key,
                ServerSideEncryption='aws:kms',
                SSEKMSKeyId=storage_config.aws_kms_key_id,
                MetadataDirective='COPY',
                TaggingDirective='COPY'
            )
            
            logger.info(f"File copied from {source_key} to {destination_key}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to copy file: {e}")
            return False
    
    async def move_file(
        self,
        source_key: str,
        destination_key: str
    ) -> bool:
        """Move file within S3."""
        # Copy then delete
        if await self.copy_file(source_key, destination_key):
            return await self.delete_file(source_key)
        return False


class LocalStorageProvider(StorageProvider):
    """Local file storage provider for development/testing."""
    
    def __init__(self):
        """Initialize local storage provider."""
        self.base_path = Path(storage_config.local_storage_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Local storage provider initialized at: {self.base_path}")
    
    def _get_file_path(self, file_key: str) -> Path:
        """Get full file path from key."""
        # Ensure path safety
        safe_key = file_key.replace('..', '').lstrip('/')
        return self.base_path / safe_key
    
    async def upload_file(
        self,
        file_data: BinaryIO,
        file_key: str,
        metadata: Optional[Dict[str, str]] = None,
        encryption_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Upload file to local storage."""
        try:
            file_path = self._get_file_path(file_key)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(file_path, 'wb') as f:
                f.write(file_data.read())
            
            # Save metadata
            if metadata:
                metadata_path = file_path.with_suffix(file_path.suffix + '.metadata')
                import json
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f)
            
            return {
                'success': True,
                'key': file_key,
                'path': str(file_path),
                'size': file_path.stat().st_size
            }
            
        except Exception as e:
            logger.error(f"Local upload failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def download_file(
        self,
        file_key: str,
        destination: Optional[str] = None
    ) -> Tuple[Optional[BinaryIO], Dict[str, Any]]:
        """Download file from local storage."""
        try:
            file_path = self._get_file_path(file_key)
            
            if not file_path.exists():
                return None, {
                    'success': False,
                    'error': 'File not found'
                }
            
            # Get metadata
            metadata = {
                'size': file_path.stat().st_size,
                'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime)
            }
            
            # Load additional metadata if exists
            metadata_path = file_path.with_suffix(file_path.suffix + '.metadata')
            if metadata_path.exists():
                import json
                with open(metadata_path, 'r') as f:
                    metadata.update(json.load(f))
            
            if destination:
                shutil.copy2(file_path, destination)
                return None, metadata
            else:
                return open(file_path, 'rb'), metadata
                
        except Exception as e:
            logger.error(f"Local download failed: {e}")
            return None, {
                'success': False,
                'error': str(e)
            }
    
    async def delete_file(
        self,
        file_key: str,
        permanent: bool = False
    ) -> bool:
        """Delete file from local storage."""
        try:
            file_path = self._get_file_path(file_key)
            
            if not file_path.exists():
                return False
            
            if permanent:
                # Permanent deletion
                file_path.unlink()
                
                # Delete metadata if exists
                metadata_path = file_path.with_suffix(file_path.suffix + '.metadata')
                if metadata_path.exists():
                    metadata_path.unlink()
            else:
                # Soft delete - rename file
                deleted_path = file_path.with_suffix(file_path.suffix + '.deleted')
                file_path.rename(deleted_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Local deletion failed: {e}")
            return False
    
    async def file_exists(self, file_key: str) -> bool:
        """Check if file exists locally."""
        return self._get_file_path(file_key).exists()
    
    async def get_file_metadata(self, file_key: str) -> Dict[str, Any]:
        """Get file metadata from local storage."""
        try:
            file_path = self._get_file_path(file_key)
            
            if not file_path.exists():
                return {'success': False, 'error': 'File not found'}
            
            stat = file_path.stat()
            metadata = {
                'success': True,
                'size': stat.st_size,
                'last_modified': datetime.fromtimestamp(stat.st_mtime),
                'created': datetime.fromtimestamp(stat.st_ctime)
            }
            
            # Load additional metadata if exists
            metadata_path = file_path.with_suffix(file_path.suffix + '.metadata')
            if metadata_path.exists():
                import json
                with open(metadata_path, 'r') as f:
                    metadata.update(json.load(f))
            
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to get metadata: {e}")
            return {'success': False, 'error': str(e)}
    
    async def list_files(
        self,
        prefix: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List files in local storage."""
        try:
            files = []
            search_path = self._get_file_path(prefix) if prefix else self.base_path
            
            for file_path in search_path.rglob('*'):
                if file_path.is_file() and not file_path.suffix in ['.metadata', '.deleted']:
                    files.append({
                        'key': str(file_path.relative_to(self.base_path)),
                        'size': file_path.stat().st_size,
                        'last_modified': datetime.fromtimestamp(file_path.stat().st_mtime)
                    })
                
                if len(files) >= limit:
                    break
            
            return files
            
        except Exception as e:
            logger.error(f"Failed to list files: {e}")
            return []
    
    async def copy_file(self, source_key: str, destination_key: str) -> bool:
        """Copy file in local storage."""
        try:
            source_path = self._get_file_path(source_key)
            dest_path = self._get_file_path(destination_key)
            
            if not source_path.exists():
                return False
            
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, dest_path)
            
            # Copy metadata if exists
            source_metadata = source_path.with_suffix(source_path.suffix + '.metadata')
            if source_metadata.exists():
                dest_metadata = dest_path.with_suffix(dest_path.suffix + '.metadata')
                shutil.copy2(source_metadata, dest_metadata)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to copy file: {e}")
            return False
    
    async def move_file(self, source_key: str, destination_key: str) -> bool:
        """Move file in local storage."""
        try:
            source_path = self._get_file_path(source_key)
            dest_path = self._get_file_path(destination_key)
            
            if not source_path.exists():
                return False
            
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.rename(dest_path)
            
            # Move metadata if exists
            source_metadata = source_path.with_suffix(source_path.suffix + '.metadata')
            if source_metadata.exists():
                dest_metadata = dest_path.with_suffix(dest_path.suffix + '.metadata')
                source_metadata.rename(dest_metadata)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to move file: {e}")
            return False


# Factory function
def get_storage_provider() -> StorageProvider:
    """Get the appropriate storage provider based on configuration."""
    if storage_config.storage_provider.lower() == 's3':
        return S3StorageProvider()
    else:
        return LocalStorageProvider()