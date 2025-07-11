"""Healthcare-specific file validation for PHI protection."""

import re
import logging
from typing import BinaryIO, Dict, Any, Tuple, List, Optional
from datetime import datetime
import json

from config.storage_config import storage_config

logger = logging.getLogger(__name__)


class PHIDetector:
    """Detect potential PHI in files and metadata."""
    
    # Patterns that might indicate PHI
    PHI_PATTERNS = {
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'mrn': r'\b(MRN|mrn)\s*:?\s*\d+\b',  # Medical Record Number
        'dob': r'\b(DOB|dob|Date of Birth)\s*:?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        'address': r'\b\d+\s+[A-Za-z\s]+\s+(Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Drive|Dr)\b',
        'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    }
    
    @classmethod
    def scan_text(cls, text: str) -> Dict[str, List[str]]:
        """
        Scan text for potential PHI.
        
        Args:
            text: Text to scan
            
        Returns:
            Dictionary of detected PHI types and matches
        """
        findings = {}
        
        for phi_type, pattern in cls.PHI_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings[phi_type] = matches
        
        return findings
    
    @classmethod
    def scan_metadata(cls, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan metadata for potential PHI.
        
        Args:
            metadata: Metadata dictionary
            
        Returns:
            PHI scan results
        """
        findings = {}
        
        # Convert metadata to string for scanning
        metadata_str = json.dumps(metadata, default=str)
        text_findings = cls.scan_text(metadata_str)
        
        if text_findings:
            findings['metadata_phi'] = text_findings
        
        # Check specific metadata fields
        sensitive_fields = ['patient_name', 'patient_id', 'location', 'provider_name']
        for field in sensitive_fields:
            if field in metadata:
                findings[f'sensitive_field_{field}'] = True
        
        return findings


def validate_file_for_healthcare(
    file_data: BinaryIO,
    filename: str,
    content_type: str,
    metadata: Optional[Dict[str, Any]] = None
) -> Tuple[bool, Dict[str, Any]]:
    """
    Comprehensive healthcare file validation.
    
    Args:
        file_data: File binary data
        filename: Filename
        content_type: Content type
        metadata: File metadata
        
    Returns:
        Tuple of (is_valid, validation_results)
    """
    results = {
        'is_valid': True,
        'errors': [],
        'warnings': [],
        'phi_detected': False,
        'validation_timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        # Check file type
        from .file_storage_utils import validate_file_type
        is_valid_type, actual_type = validate_file_type(file_data, filename, content_type)
        
        if not is_valid_type:
            results['is_valid'] = False
            results['errors'].append(f"Invalid file type: {actual_type or content_type}")
        
        # Check file size
        file_data.seek(0, 2)  # Seek to end
        file_size = file_data.tell()
        file_data.seek(0)  # Reset
        
        if file_size > storage_config.max_file_size_mb * 1024 * 1024:
            results['is_valid'] = False
            results['errors'].append(f"File size exceeds limit: {storage_config.max_file_size_mb}MB")
        
        # Scan filename for PHI
        filename_phi = PHIDetector.scan_text(filename)
        if filename_phi:
            results['warnings'].append("Potential PHI detected in filename")
            results['phi_detected'] = True
            results['filename_phi'] = filename_phi
        
        # Scan metadata for PHI
        if metadata:
            metadata_phi = PHIDetector.scan_metadata(metadata)
            if metadata_phi:
                results['warnings'].append("Potential PHI detected in metadata")
                results['phi_detected'] = True
                results['metadata_phi'] = metadata_phi
        
        # Audio-specific validation
        if content_type.startswith('audio/'):
            audio_results = _validate_audio_specific(file_data, content_type)
            results['audio_validation'] = audio_results
            
            if not audio_results.get('is_valid', True):
                results['is_valid'] = False
                results['errors'].extend(audio_results.get('errors', []))
        
    except Exception as e:
        logger.error(f"File validation error: {e}")
        results['is_valid'] = False
        results['errors'].append(f"Validation error: {str(e)}")
    
    return results['is_valid'], results


def _validate_audio_specific(
    file_data: BinaryIO,
    content_type: str
) -> Dict[str, Any]:
    """
    Perform audio-specific validation.
    
    Args:
        file_data: Audio file data
        content_type: Audio content type
        
    Returns:
        Audio validation results
    """
    results = {
        'is_valid': True,
        'errors': [],
        'warnings': [],
        'audio_properties': {}
    }
    
    try:
        # Check for minimum audio quality requirements
        # In production, use audio libraries like pydub or mutagen
        
        # Healthcare audio requirements
        MIN_SAMPLE_RATE = 16000  # 16kHz minimum for voice analysis
        MIN_BIT_RATE = 64000     # 64kbps minimum
        MAX_DURATION = 600        # 10 minutes maximum
        
        # Placeholder validation
        results['audio_properties'] = {
            'sample_rate': 'unknown',
            'bit_rate': 'unknown',
            'duration': 'unknown',
            'channels': 'unknown'
        }
        
        # Add healthcare-specific warnings
        results['warnings'].append(
            "Ensure audio does not contain background conversations with PHI"
        )
        
    except Exception as e:
        logger.error(f"Audio validation error: {e}")
        results['is_valid'] = False
        results['errors'].append(f"Audio validation failed: {str(e)}")
    
    return results


def validate_bulk_upload(
    files: List[Tuple[str, str, int]]
) -> Dict[str, Any]:
    """
    Validate bulk file upload request.
    
    Args:
        files: List of (filename, content_type, size) tuples
        
    Returns:
        Bulk validation results
    """
    results = {
        'total_files': len(files),
        'valid_files': 0,
        'invalid_files': 0,
        'total_size': 0,
        'errors': [],
        'file_results': []
    }
    
    for filename, content_type, size in files:
        file_result = {
            'filename': filename,
            'is_valid': True,
            'errors': []
        }
        
        # Check file type
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        if f".{ext}" not in storage_config.allowed_extensions:
            file_result['is_valid'] = False
            file_result['errors'].append("Invalid file extension")
        
        # Check content type
        if content_type not in storage_config.allowed_file_types:
            file_result['is_valid'] = False
            file_result['errors'].append("Invalid content type")
        
        # Check size
        if size > storage_config.max_file_size_mb * 1024 * 1024:
            file_result['is_valid'] = False
            file_result['errors'].append("File too large")
        
        # Update counters
        if file_result['is_valid']:
            results['valid_files'] += 1
        else:
            results['invalid_files'] += 1
            results['errors'].extend(file_result['errors'])
        
        results['total_size'] += size
        results['file_results'].append(file_result)
    
    # Check total size against quota
    # This would check against user's available quota
    
    return results


def sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize metadata to remove or redact PHI.
    
    Args:
        metadata: Original metadata
        
    Returns:
        Sanitized metadata
    """
    sanitized = metadata.copy()
    
    # Remove sensitive fields
    sensitive_fields = [
        'patient_name', 'patient_id', 'ssn', 'mrn',
        'address', 'phone', 'email', 'ip_address'
    ]
    
    for field in sensitive_fields:
        if field in sanitized:
            # Redact rather than remove for audit trail
            sanitized[field] = '[REDACTED]'
    
    # Scan and redact PHI in string values
    phi_detector = PHIDetector()
    
    for key, value in sanitized.items():
        if isinstance(value, str):
            phi_findings = phi_detector.scan_text(value)
            if phi_findings:
                # Redact found PHI
                redacted_value = value
                for phi_type, matches in phi_findings.items():
                    for match in matches:
                        redacted_value = redacted_value.replace(match, '[REDACTED]')
                sanitized[key] = redacted_value
    
    return sanitized


def generate_file_compliance_report(
    file_id: str,
    validation_results: Dict[str, Any],
    phi_classification: str
) -> Dict[str, Any]:
    """
    Generate compliance report for a file.
    
    Args:
        file_id: File identifier
        validation_results: Validation results
        phi_classification: PHI classification level
        
    Returns:
        Compliance report
    """
    report = {
        'file_id': file_id,
        'report_date': datetime.utcnow().isoformat(),
        'compliance_status': 'compliant',
        'phi_classification': phi_classification,
        'validation_results': validation_results,
        'recommendations': [],
        'risk_score': 0
    }
    
    # Calculate risk score
    risk_score = 0
    
    if validation_results.get('phi_detected'):
        risk_score += 3
        report['recommendations'].append(
            "Review and remove PHI from filename and metadata"
        )
    
    if phi_classification == 'HIGH':
        risk_score += 2
        report['recommendations'].append(
            "Ensure minimum necessary access controls are in place"
        )
    
    if validation_results.get('errors'):
        risk_score += len(validation_results['errors'])
        report['compliance_status'] = 'non_compliant'
    
    report['risk_score'] = min(risk_score, 10)  # Cap at 10
    
    # Add specific recommendations based on findings
    if report['risk_score'] > 5:
        report['recommendations'].append(
            "High risk file - recommend additional security review"
        )
    
    return report