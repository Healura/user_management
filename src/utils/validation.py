import re
import html
from typing import Optional
from uuid import UUID
from email_validator import validate_email as _validate_email, EmailNotValidError


def validate_email(email: str) -> tuple[bool, Optional[str]]:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Validate and normalize email
        validation = _validate_email(email, check_deliverability=False)
        return True, validation.email
    except EmailNotValidError as e:
        return False, str(e)


def validate_phone_number(phone: str) -> tuple[bool, Optional[str]]:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        
    Returns:
        Tuple of (is_valid, normalized_phone)
    """
    # Remove common separators
    cleaned = re.sub(r'[\s\-\.\(\)]', '', phone)
    
    # Check if it starts with + for international
    if cleaned.startswith('+'):
        # International format: +1234567890
        if re.match(r'^\+\d{10,15}$', cleaned):
            return True, cleaned
    else:
        # US format: 1234567890
        if re.match(r'^\d{10}$', cleaned):
            return True, f"+1{cleaned}"
    
    return False, None


def sanitize_input(text: str, max_length: Optional[int] = None) -> str:
    """
    Sanitize user input to prevent XSS and injection attacks.
    
    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        
    Returns:
        Sanitized text
    """
    # HTML escape
    sanitized = html.escape(text)
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Trim whitespace
    sanitized = sanitized.strip()
    
    # Enforce max length
    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def validate_uuid(uuid_string: str) -> bool:
    """
    Validate UUID string format.
    
    Args:
        uuid_string: UUID string to validate
        
    Returns:
        True if valid UUID
    """
    try:
        UUID(uuid_string)
        return True
    except (ValueError, AttributeError):
        return False


def validate_password_reset_token(token: str) -> bool:
    """
    Validate password reset token format.
    
    Args:
        token: Token to validate
        
    Returns:
        True if valid format
    """
    # Check if token matches expected format (alphanumeric + some special chars)
    return bool(re.match(r'^[A-Za-z0-9_\-\.]+$', token))


def validate_date_of_birth(dob: str) -> tuple[bool, Optional[str]]:
    """
    Validate date of birth.
    
    Args:
        dob: Date of birth string (YYYY-MM-DD)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    from datetime import datetime, date
    
    try:
        birth_date = datetime.strptime(dob, '%Y-%m-%d').date()
        
        # Check if date is in the past
        if birth_date >= date.today():
            return False, "Date of birth must be in the past"
        
        # Check if age is reasonable (not more than 150 years old)
        age = (date.today() - birth_date).days / 365.25
        if age > 150:
            return False, "Invalid date of birth"
        
        # Check if user is at least 13 years old (COPPA compliance)
        if age < 13:
            return False, "User must be at least 13 years old"
        
        return True, None
        
    except ValueError:
        return False, "Invalid date format. Use YYYY-MM-DD"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove path separators
    filename = filename.replace('/', '').replace('\\', '')
    
    # Remove leading dots
    filename = filename.lstrip('.')
    
    # Remove special characters except common ones
    filename = re.sub(r'[^\w\s\-\.]', '', filename)
    
    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        if ext:
            # Preserve extension
            name = name[:max_length - len(ext) - 1]
            filename = f"{name}.{ext}"
        else:
            filename = filename[:max_length]
    
    return filename or 'unnamed'


def validate_json_input(data: dict, required_fields: list[str]) -> tuple[bool, Optional[str]]:
    """
    Validate JSON input has required fields.
    
    Args:
        data: JSON data as dictionary
        required_fields: List of required field names
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    missing_fields = [field for field in required_fields if field not in data]
    
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    return True, None


def validate_strong_password(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength with detailed feedback.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    from src.auth.password_policy import validate_password
    return validate_password(password)