"""Healthcare-grade file encryption with KMS integration."""

import os
import hashlib
import logging
from typing import BinaryIO, Optional, Dict, Any, Tuple
from io import BytesIO
import base64

import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend

from config.storage_config import storage_config, get_encryption_config
from config.aws_config import aws_config

logger = logging.getLogger(__name__)


class FileEncryption:
    """Healthcare-compliant file encryption with AWS KMS."""
    
    def __init__(self):
        """Initialize encryption with KMS client."""
        self.encryption_config = get_encryption_config()
        
        # Initialize KMS client
        if aws_config.aws_access_key_id:
            session = boto3.Session(
                aws_access_key_id=aws_config.aws_access_key_id,
                aws_secret_access_key=aws_config.aws_secret_access_key.get_secret_value() if aws_config.aws_secret_access_key else None,
                region_name=aws_config.aws_region
            )
            self.kms_client = session.client('kms')
        else:
            self.kms_client = None
            logger.warning("KMS client not initialized - using local encryption only")
        
        # Initialize local encryption backend
        self.backend = default_backend()
    
    async def encrypt_file(
        self,
        file_data: BinaryIO,
        file_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[BinaryIO, Dict[str, Any]]:
        """
        Encrypt file data with double encryption for healthcare compliance.
        
        Args:
            file_data: File data to encrypt
            file_id: Unique file identifier
            metadata: Additional metadata
            
        Returns:
            Tuple of (encrypted_data, encryption_metadata)
        """
        try:
            # Read file data
            data = file_data.read()
            file_data.seek(0)
            
            # Generate file checksum before encryption
            original_checksum = self._calculate_checksum(data)
            
            if storage_config.enable_double_encryption and self.kms_client:
                # Double encryption: Local AES + KMS
                encrypted_data, encryption_info = await self._double_encrypt(data, file_id)
            else:
                # Single encryption: Local AES only
                encrypted_data, encryption_info = await self._local_encrypt(data, file_id)
            
            # Create encryption metadata
            encryption_metadata = {
                'encryption_version': '2.0',
                'algorithm': self.encryption_config['algorithm'],
                'double_encryption': storage_config.enable_double_encryption,
                'original_checksum': original_checksum,
                'encrypted_checksum': self._calculate_checksum(encrypted_data),
                'encryption_timestamp': datetime.utcnow().isoformat(),
                'compliance_mode': 'HIPAA',
                **encryption_info
            }
            
            # Add custom metadata
            if metadata:
                encryption_metadata.update(metadata)
            
            # Return encrypted data as BytesIO
            return BytesIO(encrypted_data), encryption_metadata
            
        except Exception as e:
            logger.error(f"Encryption failed for file {file_id}: {e}")
            raise
    
    async def decrypt_file(
        self,
        encrypted_data: BinaryIO,
        encryption_metadata: Dict[str, Any],
        file_id: str
    ) -> Tuple[BinaryIO, bool]:
        """
        Decrypt file data with integrity verification.
        
        Args:
            encrypted_data: Encrypted file data
            encryption_metadata: Encryption metadata
            file_id: File identifier
            
        Returns:
            Tuple of (decrypted_data, integrity_verified)
        """
        try:
            # Read encrypted data
            data = encrypted_data.read()
            encrypted_data.seek(0)
            
            # Verify encrypted checksum
            if 'encrypted_checksum' in encryption_metadata:
                expected_checksum = encryption_metadata['encrypted_checksum']
                actual_checksum = self._calculate_checksum(data)
                if expected_checksum != actual_checksum:
                    logger.error(f"Encrypted data integrity check failed for {file_id}")
                    return BytesIO(b''), False
            
            # Decrypt based on encryption type
            if encryption_metadata.get('double_encryption') and self.kms_client:
                decrypted_data = await self._double_decrypt(data, encryption_metadata, file_id)
            else:
                decrypted_data = await self._local_decrypt(data, encryption_metadata, file_id)
            
            # Verify original checksum
            integrity_verified = True
            if 'original_checksum' in encryption_metadata:
                expected_checksum = encryption_metadata['original_checksum']
                actual_checksum = self._calculate_checksum(decrypted_data)
                integrity_verified = expected_checksum == actual_checksum
                
                if not integrity_verified:
                    logger.error(f"Decrypted data integrity check failed for {file_id}")
            
            return BytesIO(decrypted_data), integrity_verified
            
        except Exception as e:
            logger.error(f"Decryption failed for file {file_id}: {e}")
            raise
    
    async def _double_encrypt(
        self,
        data: bytes,
        file_id: str
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Perform double encryption with local AES and KMS."""
        # First layer: Local AES encryption
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Pad data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Second layer: Encrypt AES key with KMS
        kms_response = self.kms_client.encrypt(
            KeyId=storage_config.aws_kms_key_id,
            Plaintext=aes_key,
            EncryptionContext={
                'file_id': file_id,
                'purpose': 'healthcare_file_encryption'
            }
        )
        
        encrypted_aes_key = base64.b64encode(kms_response['CiphertextBlob']).decode('utf-8')
        
        # Combine encrypted data with metadata
        result = {
            'data': encrypted_data,
            'iv': base64.b64encode(iv).decode('utf-8'),
            'encrypted_key': encrypted_aes_key
        }
        
        # Encode the complete package
        import json
        package = {
            'iv': result['iv'],
            'encrypted_key': result['encrypted_key'],
            'data': base64.b64encode(result['data']).decode('utf-8')
        }
        
        final_data = json.dumps(package).encode('utf-8')
        
        return final_data, {
            'encryption_method': 'double_aes_kms',
            'kms_key_id': storage_config.aws_kms_key_id
        }
    
    async def _double_decrypt(
        self,
        encrypted_package: bytes,
        metadata: Dict[str, Any],
        file_id: str
    ) -> bytes:
        """Perform double decryption."""
        import json
        
        # Parse the encrypted package
        package = json.loads(encrypted_package.decode('utf-8'))
        iv = base64.b64decode(package['iv'])
        encrypted_key = base64.b64decode(package['encrypted_key'])
        encrypted_data = base64.b64decode(package['data'])
        
        # First layer: Decrypt AES key with KMS
        kms_response = self.kms_client.decrypt(
            CiphertextBlob=encrypted_key,
            EncryptionContext={
                'file_id': file_id,
                'purpose': 'healthcare_file_encryption'
            }
        )
        
        aes_key = kms_response['Plaintext']
        
        # Second layer: Decrypt data with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    async def _local_encrypt(
        self,
        data: bytes,
        file_id: str
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Perform local AES encryption."""
        # Generate key from file_id and secret
        key = self._derive_key(file_id)
        iv = os.urandom(16)
        
        # Encrypt with AES
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Pad data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        result = iv + encrypted_data
        
        return result, {
            'encryption_method': 'local_aes',
            'key_derivation': 'pbkdf2'
        }
    
    async def _local_decrypt(
        self,
        encrypted_data: bytes,
        metadata: Dict[str, Any],
        file_id: str
    ) -> bytes:
        """Perform local AES decryption."""
        # Extract IV and data
        iv = encrypted_data[:16]
        data = encrypted_data[16:]
        
        # Derive key
        key = self._derive_key(file_id)
        
        # Decrypt with AES
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_data = decryptor.update(data) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return original_data
    
    def _derive_key(self, file_id: str) -> bytes:
        """Derive encryption key from file ID and secret."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Use secret key from config or environment
        secret = auth_settings.secret_key.get_secret_value().encode('utf-8')
        salt = file_id.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        return kdf.derive(secret)
    
    def _calculate_checksum(self, data: bytes) -> str:
        """Calculate SHA-256 checksum of data."""
        return hashlib.sha256(data).hexdigest()
    
    async def generate_file_checksum(
        self,
        file_data: BinaryIO
    ) -> str:
        """Generate checksum for file integrity verification."""
        sha256_hash = hashlib.sha256()
        
        # Read file in chunks
        for chunk in iter(lambda: file_data.read(4096), b''):
            sha256_hash.update(chunk)
        
        file_data.seek(0)
        return sha256_hash.hexdigest()
    
    async def verify_file_integrity(
        self,
        file_data: BinaryIO,
        expected_checksum: str
    ) -> bool:
        """Verify file integrity using checksum."""
        actual_checksum = await self.generate_file_checksum(file_data)
        return actual_checksum == expected_checksum


# Helper functions
async def encrypt_file(
    file_data: BinaryIO,
    file_id: str,
    metadata: Optional[Dict[str, Any]] = None
) -> Tuple[BinaryIO, Dict[str, Any]]:
    """Encrypt file with healthcare-grade encryption."""
    encryption = FileEncryption()
    return await encryption.encrypt_file(file_data, file_id, metadata)


async def decrypt_file(
    encrypted_data: BinaryIO,
    encryption_metadata: Dict[str, Any],
    file_id: str
) -> Tuple[BinaryIO, bool]:
    """Decrypt file with integrity verification."""
    encryption = FileEncryption()
    return await encryption.decrypt_file(encrypted_data, encryption_metadata, file_id)


async def generate_file_checksum(file_data: BinaryIO) -> str:
    """Generate file checksum for integrity verification."""
    encryption = FileEncryption()
    return await encryption.generate_file_checksum(file_data)


async def verify_file_integrity(
    file_data: BinaryIO,
    expected_checksum: str
) -> bool:
    """Verify file integrity."""
    encryption = FileEncryption()
    return await encryption.verify_file_integrity(file_data, expected_checksum)


from datetime import datetime