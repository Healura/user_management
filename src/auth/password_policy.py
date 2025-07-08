import re
import logging
from typing import List, Optional, Tuple
from datetime import datetime, timedelta

from passlib.context import CryptContext
from sqlalchemy.orm import Session

from config.auth_settings import auth_settings

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=auth_settings.bcrypt_rounds
)


class PasswordPolicyError(Exception):
    """Base exception for password policy violations."""
    pass


class PasswordValidationError(PasswordPolicyError):
    """Raised when password doesn't meet policy requirements."""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(f"Password validation failed: {'; '.join(errors)}")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password matches
    """
    return pwd_context.verify(plain_password, hashed_password)


def validate_password(password: str, email: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Validate password against policy requirements.
    
    Args:
        password: Password to validate
        email: User email (to check password doesn't contain email)
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check minimum length
    if len(password) < auth_settings.password_min_length:
        errors.append(f"Password must be at least {auth_settings.password_min_length} characters long")
    
    # Check uppercase requirement
    if auth_settings.password_require_uppercase and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Check lowercase requirement
    if auth_settings.password_require_lowercase and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    # Check number requirement
    if auth_settings.password_require_numbers and not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    # Check special character requirement
    if auth_settings.password_require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check password doesn't contain email
    if email and email.lower() in password.lower():
        errors.append("Password must not contain your email address")
    
    # Check for common patterns
    if _contains_common_pattern(password):
        errors.append("Password contains common patterns and is too predictable")
    
    return len(errors) == 0, errors


def enforce_password_policy(password: str, email: Optional[str] = None) -> None:
    """
    Enforce password policy, raising exception if invalid.
    
    Args:
        password: Password to validate
        email: User email
        
    Raises:
        PasswordValidationError: If password doesn't meet requirements
    """
    is_valid, errors = validate_password(password, email)
    if not is_valid:
        raise PasswordValidationError(errors)


def _contains_common_pattern(password: str) -> bool:
    """
    Check if password contains common weak patterns.
    
    Args:
        password: Password to check
        
    Returns:
        True if contains common patterns
    """
    common_patterns = [
        r'123456',
        r'password',
        r'qwerty',
        r'abc123',
        r'111111',
        r'123123',
        r'admin',
        r'letmein',
        r'welcome',
        r'monkey',
        r'dragon',
        r'baseball',
        r'football',
        r'iloveyou',
        r'trustno1',
        r'sunshine',
        r'master',
        r'hello',
        r'shadow',
        r'ashley',
        r'passw0rd',
        r'qazwsx',
        r'qwertyuiop',
        r'1234567890',
    ]
    
    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            return True
    
    # Check for sequential characters
    if _has_sequential_chars(password):
        return True
    
    # Check for repeated characters
    if _has_excessive_repeated_chars(password):
        return True
    
    return False


def _has_sequential_chars(password: str, threshold: int = 4) -> bool:
    """
    Check if password has sequential characters.
    
    Args:
        password: Password to check
        threshold: Minimum length of sequence to flag
        
    Returns:
        True if has sequential characters
    """
    for i in range(len(password) - threshold + 1):
        sequence = password[i:i + threshold]
        
        # Check ascending sequence
        if all(ord(sequence[j]) == ord(sequence[j-1]) + 1 for j in range(1, len(sequence))):
            return True
        
        # Check descending sequence
        if all(ord(sequence[j]) == ord(sequence[j-1]) - 1 for j in range(1, len(sequence))):
            return True
    
    return False


def _has_excessive_repeated_chars(password: str, threshold: int = 3) -> bool:
    """
    Check if password has excessive repeated characters.
    
    Args:
        password: Password to check
        threshold: Maximum allowed consecutive repeated characters
        
    Returns:
        True if has excessive repeated characters
    """
    count = 1
    for i in range(1, len(password)):
        if password[i] == password[i-1]:
            count += 1
            if count > threshold:
                return True
        else:
            count = 1
    
    return False


class PasswordHistory:
    """Manage password history to prevent reuse."""
    
    def __init__(self, db: Session):
        self.db = db
    
    async def check_password_history(
        self,
        user_id: str,
        new_password: str,
        history_count: Optional[int] = None
    ) -> bool:
        """
        Check if password was recently used.
        
        Args:
            user_id: User ID
            new_password: New password to check
            history_count: Number of previous passwords to check
            
        Returns:
            True if password is acceptable (not in history)
        """
        if history_count is None:
            history_count = auth_settings.password_history_count
        
        # This would check a password_history table
        # For now, returning True (password is acceptable)
        return True
    
    async def add_to_history(
        self,
        user_id: str,
        password_hash: str
    ) -> None:
        """
        Add password to user's password history.
        
        Args:
            user_id: User ID
            password_hash: Hashed password
        """
        # This would add to a password_history table
        pass


def check_password_expiry(last_password_change: datetime) -> bool:
    """
    Check if password has expired.
    
    Args:
        last_password_change: Timestamp of last password change
        
    Returns:
        True if password has expired
    """
    if auth_settings.password_expiry_days <= 0:
        return False
    
    expiry_date = last_password_change + timedelta(days=auth_settings.password_expiry_days)
    return datetime.utcnow() > expiry_date


def get_password_strength(password: str) -> str:
    """
    Calculate password strength score.
    
    Args:
        password: Password to evaluate
        
    Returns:
        Strength level: "weak", "moderate", "strong", "very_strong"
    """
    score = 0
    
    # Length score
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    
    # Complexity score
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1
    
    # Entropy bonus
    unique_chars = len(set(password))
    if unique_chars >= 10:
        score += 1
    
    # Penalty for common patterns
    if _contains_common_pattern(password):
        score -= 2
    
    # Determine strength level
    if score <= 2:
        return "weak"
    elif score <= 4:
        return "moderate"
    elif score <= 6:
        return "strong"
    else:
        return "very_strong"