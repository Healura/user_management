import logging
import secrets
import string
from typing import Optional, List, Tuple
from io import BytesIO

import pyotp
import qrcode
from sqlalchemy.orm import Session

from config.auth_settings import auth_settings
from src.database.models import User

logger = logging.getLogger(__name__)


class MFAError(Exception):
    """Base exception for MFA errors."""
    pass


class InvalidTOTPError(MFAError):
    """Raised when TOTP token is invalid."""
    pass


class MFAManager:
    """Manage multi-factor authentication for users."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def generate_totp_secret(self) -> str:
        """
        Generate a new TOTP secret.
        
        Returns:
            Base32 encoded secret
        """
        return pyotp.random_base32()
    
    def generate_qr_code(
        self,
        user_email: str,
        secret: str
    ) -> bytes:
        """
        Generate QR code for TOTP setup.
        
        Args:
            user_email: User's email address
            secret: TOTP secret
            
        Returns:
            QR code image as bytes
        """
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user_email,
            issuer_name=auth_settings.mfa_issuer_name
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return buffer.read()
    
    def verify_totp_token(
        self,
        secret: str,
        token: str,
        window: int = 1
    ) -> bool:
        """
        Verify a TOTP token.
        
        Args:
            secret: User's TOTP secret
            token: TOTP token to verify
            window: Time window for verification
            
        Returns:
            True if token is valid
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=window)
    
    def generate_backup_codes(
        self,
        count: Optional[int] = None
    ) -> List[str]:
        """
        Generate backup codes for account recovery.
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of backup codes
        """
        if count is None:
            count = auth_settings.mfa_backup_codes_count
        
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric code
            code = ''.join(
                secrets.choice(string.ascii_uppercase + string.digits)
                for _ in range(8)
            )
            # Format as XXXX-XXXX
            formatted_code = f"{code[:4]}-{code[4:]}"
            codes.append(formatted_code)
        
        return codes
    
    async def enable_mfa(
        self,
        user_id: str,
        secret: str,
        backup_codes: List[str]
    ) -> None:
        """
        Enable MFA for a user.
        
        Args:
            user_id: User ID
            secret: TOTP secret
            backup_codes: List of backup codes
        """
        # Store MFA data in user record or separate MFA table
        # For now, this would update the user record
        # In production, consider a separate mfa_settings table
        pass
    
    async def disable_mfa(
        self,
        user_id: str
    ) -> None:
        """
        Disable MFA for a user.
        
        Args:
            user_id: User ID
        """
        # Remove MFA data from user record
        pass
    
    async def verify_backup_code(
        self,
        user_id: str,
        code: str
    ) -> bool:
        """
        Verify and consume a backup code.
        
        Args:
            user_id: User ID
            code: Backup code
            
        Returns:
            True if code is valid
        """
        # This would check and consume the backup code
        # from a backup_codes table
        return False
    
    async def regenerate_backup_codes(
        self,
        user_id: str
    ) -> List[str]:
        """
        Regenerate backup codes for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            New list of backup codes
        """
        codes = self.generate_backup_codes()
        # Store new codes in database
        return codes


def generate_totp_secret() -> str:
    """
    Helper function to generate TOTP secret.
    
    Returns:
        Base32 encoded secret
    """
    return pyotp.random_base32()


def verify_totp_token(secret: str, token: str) -> bool:
    """
    Helper function to verify TOTP token.
    
    Args:
        secret: TOTP secret
        token: Token to verify
        
    Returns:
        True if valid
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


def generate_mfa_qr_code(email: str, secret: str) -> Tuple[str, bytes]:
    """
    Generate MFA QR code and provisioning URI.
    
    Args:
        email: User email
        secret: TOTP secret
        
    Returns:
        Tuple of (provisioning_uri, qr_code_bytes)
    """
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name=auth_settings.mfa_issuer_name
    )
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return provisioning_uri, buffer.read()