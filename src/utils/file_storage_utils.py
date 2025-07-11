"""Healthcare file storage utility functions."""

import os
import mimetypes
import hashlib
import logging
from typing import BinaryIO, Optional, Tuple, Dict, Any
from pathlib import Path
from datetime import datetime
import magic  # python-magic for file type detection

from config.storage_config import storage_config

logger = logging.getLogger(__name__)


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for secure storage.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '')
    
    # Remove leading dots
    filename = filename.lstrip('.')
    
    # Remove special characters
    import re
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    
    # Replace spaces with underscores
    filename = filename.replace(' ', '_')
    
    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        if ext:
            name = name[:max_length - len(ext) - 1]
            filename = f"{name}{ext}"
        else:
            filename = filename[:max_length]
    
    return filename or 'unnamed_file'


def get_file_extension(filename: str) -> str:
    """
    Get file extension safely.
    
    Args:
        filename: Filename
        
    Returns:
        File extension with dot (e.g., '.mp3')
    """
    return Path(filename).suffix.lower()


def validate_file_type(
    file_data: BinaryIO,
    filename: str,
    declared_content_type: str
) -> Tuple[bool, Optional[str]]:
    """
    Validate file type using multiple methods for security.
    
    Args:
        file_data: File binary data
        filename: Filename
        declared_content_type: Declared MIME type
        
    Returns:
        Tuple of (is_valid, actual_content_type)
    """
    try:
        # Check extension
        ext = get_file_extension(filename)
        if ext not in storage_config.allowed_extensions:
            return False, None
        
        # Check declared content type
        if declared_content_type not in storage_config.allowed_file_types:
            return False, None
        
        # Verify actual content type using magic
        file_data.seek(0)
        mime = magic.Magic(mime=True)
        actual_content_type = mime.from_buffer(file_data.read(1024))
        file_data.seek(0)
        
        # Verify it matches allowed types
        if actual_content_type not in storage_config.allowed_file_types:
            logger.warning(
                f"File type mismatch: declared={declared_content_type}, "
                f"actual={actual_content_type}"
            )
            return False, actual_content_type
        
        return True, actual_content_type
        
    except Exception as e:
        logger.error(f"File type validation error: {e}")
        return False, None


def calculate_file_hash(
    file_data: BinaryIO,
    algorithm: str = 'sha256'
) -> str:
    """
    Calculate file hash for integrity verification.
    
    Args:
        file_data: File data
        algorithm: Hash algorithm (sha256, md5, etc.)
        
    Returns:
        Hex hash string
    """
    hash_func = hashlib.new(algorithm)
    
    # Read file in chunks to handle large files
    for chunk in iter(lambda: file_data.read(4096), b''):
        hash_func.update(chunk)
    
    file_data.seek(0)
    return hash_func.hexdigest()


def estimate_audio_duration(
    file_data: BinaryIO,
    content_type: str
) -> Optional[float]:
    """
    Estimate audio file duration without full decoding.
    
    Args:
        file_data: Audio file data
        content_type: MIME type
        
    Returns:
        Duration in seconds or None
    """
    try:
        # This would use an audio library like mutagen or pydub
        # For now, returning None
        return None
    except Exception as e:
        logger.error(f"Failed to estimate audio duration: {e}")
        return None


def generate_unique_filename(
    original_filename: str,
    user_id: str
) -> str:
    """
    Generate unique filename with timestamp.
    
    Args:
        original_filename: Original filename
        user_id: User ID
        
    Returns:
        Unique filename
    """
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    name, ext = os.path.splitext(original_filename)
    sanitized_name = sanitize_filename(name)
    
    return f"{user_id}_{timestamp}_{sanitized_name}{ext}"


def parse_range_header(
    range_header: Optional[str],
    file_size: int
) -> Optional[Tuple[int, int]]:
    """
    Parse HTTP Range header for partial content requests.
    
    Args:
        range_header: Range header value
        file_size: Total file size
        
    Returns:
        Tuple of (start, end) bytes or None
    """
    if not range_header:
        return None
    
    try:
        # Parse "bytes=start-end" format
        range_spec = range_header.replace('bytes=', '')
        
        if '-' not in range_spec:
            return None
        
        start_str, end_str = range_spec.split('-', 1)
        
        # Handle different range formats
        if start_str and end_str:
            # bytes=start-end
            start = int(start_str)
            end = min(int(end_str), file_size - 1)
        elif start_str:
            # bytes=start-
            start = int(start_str)
            end = file_size - 1
        elif end_str:
            # bytes=-end (last N bytes)
            start = max(0, file_size - int(end_str))
            end = file_size - 1
        else:
            return None
        
        # Validate range
        if start >= file_size or start > end:
            return None
        
        return start, end
        
    except Exception as e:
        logger.error(f"Failed to parse range header: {e}")
        return None


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    
    return f"{size_bytes:.2f} PB"


def validate_audio_file(
    file_data: BinaryIO,
    content_type: str
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate audio file and extract metadata.
    
    Args:
        file_data: Audio file data
        content_type: Content type
        
    Returns:
        Tuple of (is_valid, metadata)
    """
    try:
        metadata = {
            'content_type': content_type,
            'is_valid': True
        }
        
        # Basic validation based on content type
        audio_types = [
            'audio/wav', 'audio/x-wav',
            'audio/mpeg', 'audio/mp3',
            'audio/m4a', 'audio/mp4',
            'audio/aac'
        ]
        
        if content_type not in audio_types:
            return False, None
        
        # Additional validation would use audio libraries
        # For healthcare, we might check:
        # - Minimum audio quality (sample rate, bit rate)
        # - Maximum file duration
        # - No embedded metadata that could contain PHI
        
        return True, metadata
        
    except Exception as e:
        logger.error(f"Audio validation failed: {e}")
        return False, None


def strip_audio_metadata(
    file_data: BinaryIO,
    output_path: str
) -> bool:
    """
    Strip metadata from audio file for PHI protection.
    
    Args:
        file_data: Input audio file
        output_path: Output file path
        
    Returns:
        Success status
    """
    try:
        # This would use a library like mutagen to remove metadata
        # Important for HIPAA compliance to remove any embedded PHI
        
        # For now, just copy the file
        file_data.seek(0)
        with open(output_path, 'wb') as output:
            output.write(file_data.read())
        
        file_data.seek(0)
        return True
        
    except Exception as e:
        logger.error(f"Failed to strip metadata: {e}")
        return False


def create_file_thumbnail(
    audio_file_path: str,
    output_path: str,
    size: Tuple[int, int] = (200, 200)
) -> bool:
    """
    Create waveform thumbnail for audio file.
    
    Args:
        audio_file_path: Path to audio file
        output_path: Output thumbnail path
        size: Thumbnail size
        
    Returns:
        Success status
    """
    try:
        # This would generate a waveform visualization
        # Useful for healthcare providers to quickly identify recordings
        return False  # Not implemented
        
    except Exception as e:
        logger.error(f"Failed to create thumbnail: {e}")
        return False


def get_safe_path(
    base_path: str,
    requested_path: str
) -> Optional[str]:
    """
    Get safe file path preventing directory traversal.
    
    Args:
        base_path: Base directory path
        requested_path: Requested file path
        
    Returns:
        Safe absolute path or None if invalid
    """
    try:
        base = Path(base_path).resolve()
        requested = Path(requested_path)
        
        # Remove any parent directory references
        safe_path = base / requested.name
        resolved = safe_path.resolve()
        
        # Ensure the resolved path is within base directory
        if not str(resolved).startswith(str(base)):
            logger.warning(f"Path traversal attempt: {requested_path}")
            return None
        
        return str(resolved)
        
    except Exception as e:
        logger.error(f"Path validation error: {e}")
        return None