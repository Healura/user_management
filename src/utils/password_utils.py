"""Password hashing and verification utilities."""

import hashlib
from passlib.context import CryptContext

from config.auth_settings import auth_settings

# Create password context with bcrypt
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=auth_settings.bcrypt_rounds
)


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
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password matches
    """
    return pwd_context.verify(plain_password, hashed_password)


def hash_token(token: str) -> str:
    """
    Hash a token for storage (e.g., refresh tokens).
    
    Args:
        token: Token to hash
        
    Returns:
        SHA256 hash of token
    """
    return hashlib.sha256(token.encode()).hexdigest()


def generate_random_password(length: int = 16) -> str:
    """
    Generate a random password that meets policy requirements.
    
    Args:
        length: Password length
        
    Returns:
        Random password
    """
    import secrets
    import string
    
    # Ensure minimum length
    length = max(length, auth_settings.password_min_length)
    
    # Character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*(),.?\":{}|<>"
    
    # Ensure at least one character from each required set
    password = []
    
    if auth_settings.password_require_uppercase:
        password.append(secrets.choice(uppercase))
    if auth_settings.password_require_lowercase:
        password.append(secrets.choice(lowercase))
    if auth_settings.password_require_numbers:
        password.append(secrets.choice(digits))
    if auth_settings.password_require_special:
        password.append(secrets.choice(special))
    
    # Fill the rest of the password
    all_chars = ""
    if auth_settings.password_require_uppercase:
        all_chars += uppercase
    if auth_settings.password_require_lowercase:
        all_chars += lowercase
    if auth_settings.password_require_numbers:
        all_chars += digits
    if auth_settings.password_require_special:
        all_chars += special
    
    for _ in range(length - len(password)):
        password.append(secrets.choice(all_chars))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)