import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

from jose import JWTError, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from config.auth_settings import auth_settings

logger = logging.getLogger(__name__)

# Cache for keys
_private_key: Optional[str] = None
_public_key: Optional[str] = None


def _load_or_create_keys() -> tuple[str, str]:
    """
    Load or create RSA key pair for JWT signing.
    
    Returns:
        Tuple of (private_key, public_key) as PEM strings
    """
    global _private_key, _public_key
    
    if _private_key and _public_key:
        return _private_key, _public_key
    
    private_key_path = Path(auth_settings.jwt_private_key_path)
    public_key_path = Path(auth_settings.jwt_public_key_path)
    
    # Create keys directory if it doesn't exist
    keys_dir = private_key_path.parent
    keys_dir.mkdir(parents=True, exist_ok=True)
    
    if private_key_path.exists() and public_key_path.exists():
        # Load existing keys
        _private_key = private_key_path.read_text()
        _public_key = public_key_path.read_text()
        logger.info("Loaded existing JWT keys")
    else:
        # Generate new key pair
        logger.info("Generating new JWT key pair")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Get private key
        _private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Get public key
        _public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Save keys
        private_key_path.write_text(_private_key)
        public_key_path.write_text(_public_key)
        
        # Set secure permissions (Unix-like systems)
        try:
            import os
            os.chmod(private_key_path, 0o600)  # Read/write for owner only
            os.chmod(public_key_path, 0o644)   # Read for all, write for owner
        except Exception as e:
            logger.warning(f"Could not set key file permissions: {e}")
    
    return _private_key, _public_key


def create_jwt_token(
    payload: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT token with given payload.
    
    Args:
        payload: Token payload
        expires_delta: Token expiration time
        
    Returns:
        JWT token string
    """
    private_key, _ = _load_or_create_keys()
    
    to_encode = payload.copy()
    
    # Add expiration
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "iss": auth_settings.mfa_issuer_name
    })
    
    # Create token
    encoded_jwt = jwt.encode(
        to_encode,
        private_key,
        algorithm=auth_settings.algorithm
    )
    
    return encoded_jwt


def decode_jwt_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Token payload
        
    Raises:
        JWTError: If token is invalid or expired
    """
    _, public_key = _load_or_create_keys()
    
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[auth_settings.algorithm],
            issuer=auth_settings.mfa_issuer_name
        )
        return payload
    except JWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise


def create_email_verification_token(user_id: str) -> str:
    """
    Create an email verification token.
    
    Args:
        user_id: User ID
        
    Returns:
        JWT token for email verification
    """
    payload = {
        "sub": user_id,
        "type": "email_verification"
    }
    
    return create_jwt_token(
        payload,
        expires_delta=auth_settings.email_verification_expire_timedelta
    )


def create_password_reset_token(user_id: str) -> str:
    """
    Create a password reset token.
    
    Args:
        user_id: User ID
        
    Returns:
        JWT token for password reset
    """
    payload = {
        "sub": user_id,
        "type": "password_reset"
    }
    
    return create_jwt_token(
        payload,
        expires_delta=timedelta(hours=1)  # 1 hour expiration for password reset
    )


def verify_token_type(token: str, expected_type: str) -> Dict[str, Any]:
    """
    Verify token and check its type.
    
    Args:
        token: JWT token
        expected_type: Expected token type
        
    Returns:
        Token payload
        
    Raises:
        JWTError: If token is invalid or wrong type
    """
    payload = decode_jwt_token(token)
    
    if payload.get("type") != expected_type:
        raise JWTError(f"Invalid token type. Expected {expected_type}")
    
    return payload