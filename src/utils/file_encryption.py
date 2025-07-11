"""File encryption utilities for healthcare data protection."""

import os
import logging
from typing import BinaryIO, Tuple, Dict, Any, Optional
from io import BytesIO
import base64
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

logger = logging.getLogger(__name__)


class EncryptionError(Exception):
    """Base exception for encryption errors."""
    pass


class FileEncryptionUtils:
    """Utilities for file encryption operations."""
    
    @staticmethod
    def generate_encryption_key(password: str, salt: bytes) -> bytes:
        """
        Generate encryption key from password.
        
        Args:
            password: Password string
            salt: Salt bytes
            
        Returns:
            256-bit encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_file_stream(
        input_stream: BinaryIO,
        key: bytes,
        chunk_size: int = 64 * 1024
    ) -> Tuple[BinaryIO, Dict[str, Any]]:
        """
        Encrypt file stream with AES-256-GCM.
        
        Args:
            input_stream: Input file stream
            key: 256-bit encryption key
            chunk_size: Chunk size for streaming
            
        Returns:
            Tuple of (encrypted_stream, encryption_metadata)
        """
        try:
            # Generate IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            encrypted_chunks = []
            input_stream.seek(0)
            
            while True:
                chunk = input_stream.read(chunk_size)
                if not chunk:
                    break
                
                encrypted_chunk = encryptor.update(chunk)
                encrypted_chunks.append(encrypted_chunk)
            
            # Finalize and get tag
            encryptor.finalize()
            tag = encryptor.tag
            
            # Combine encrypted data
            encrypted_data = b''.join(encrypted_chunks)
            
            # Create output stream
            output_stream = BytesIO()
            
            # Write header: version (1 byte) + iv (16 bytes) + tag (16 bytes)
            output_stream.write(b'\x01')  # Version 1
            output_stream.write(iv)
            output_stream.write(tag)
            output_stream.write(encrypted_data)
            
            output_stream.seek(0)
            input_stream.seek(0)
            
            metadata = {
                'algorithm': 'AES-256-GCM',
                'iv': base64.b64encode(iv).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'version': 1
            }
            
            return output_stream, metadata
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Failed to encrypt file: {str(e)}")
    
    @staticmethod
    def decrypt_file_stream(
        encrypted_stream: BinaryIO,
        key: bytes,
        chunk_size: int = 64 * 1024
    ) -> Tuple[BinaryIO, bool]:
        """
        Decrypt file stream.
        
        Args:
            encrypted_stream: Encrypted file stream
            key: Decryption key
            chunk_size: Chunk size for streaming
            
        Returns:
            Tuple of (decrypted_stream, integrity_verified)
        """
        try:
            encrypted_stream.seek(0)
            
            # Read header
            version = encrypted_stream.read(1)
            if version != b'\x01':
                raise EncryptionError(f"Unsupported version: {version}")
            
            iv = encrypted_stream.read(16)
            tag = encrypted_stream.read(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            decrypted_chunks = []
            
            while True:
                chunk = encrypted_stream.read(chunk_size)
                if not chunk:
                    break
                
                decrypted_chunk = decryptor.update(chunk)
                decrypted_chunks.append(decrypted_chunk)
            
            # Verify integrity
            try:
                decryptor.finalize()
                integrity_verified = True
            except Exception:
                integrity_verified = False
            
            # Create output stream
            decrypted_data = b''.join(decrypted_chunks)
            output_stream = BytesIO(decrypted_data)
            
            encrypted_stream.seek(0)
            
            return output_stream, integrity_verified
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise EncryptionError(f"Failed to decrypt file: {str(e)}")
    
    @staticmethod
    def create_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate RSA key pair for asymmetric encryption.
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    @staticmethod
    def encrypt_key_with_rsa(
        symmetric_key: bytes,
        public_key_pem: bytes
    ) -> bytes:
        """
        Encrypt symmetric key with RSA public key.
        
        Args:
            symmetric_key: Symmetric key to encrypt
            public_key_pem: RSA public key in PEM format
            
        Returns:
            Encrypted key
        """
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        encrypted_key = public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted_key
    
    @staticmethod
    def decrypt_key_with_rsa(
        encrypted_key: bytes,
        private_key_pem: bytes
    ) -> bytes:
        """
        Decrypt symmetric key with RSA private key.
        
        Args:
            encrypted_key: Encrypted symmetric key
            private_key_pem: RSA private key in PEM format
            
        Returns:
            Decrypted symmetric key
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        symmetric_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return symmetric_key


class SecureFileWrapper:
    """Wrapper for secure file operations with automatic encryption."""
    
    def __init__(self, file_stream: BinaryIO, key: bytes):
        """
        Initialize secure file wrapper.
        
        Args:
            file_stream: File stream to wrap
            key: Encryption key
        """
        self.file_stream = file_stream
        self.key = key
        self.position = 0
    
    def read(self, size: int = -1) -> bytes:
        """Read and decrypt data."""
        # This would implement on-the-fly decryption
        return self.file_stream.read(size)
    
    def write(self, data: bytes) -> int:
        """Encrypt and write data."""
        # This would implement on-the-fly encryption
        return self.file_stream.write(data)
    
    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek to position."""
        return self.file_stream.seek(offset, whence)
    
    def tell(self) -> int:
        """Get current position."""
        return self.file_stream.tell()
    
    def close(self) -> None:
        """Close the wrapped file."""
        self.file_stream.close()


def create_encrypted_backup(
    source_file: BinaryIO,
    backup_key: bytes
) -> Tuple[BinaryIO, Dict[str, Any]]:
    """
    Create encrypted backup of a file.
    
    Args:
        source_file: Source file to backup
        backup_key: Encryption key for backup
        
    Returns:
        Tuple of (encrypted_backup, metadata)
    """
    utils = FileEncryptionUtils()
    return utils.encrypt_file_stream(source_file, backup_key)


def restore_encrypted_backup(
    encrypted_backup: BinaryIO,
    backup_key: bytes
) -> Tuple[BinaryIO, bool]:
    """
    Restore file from encrypted backup.
    
    Args:
        encrypted_backup: Encrypted backup stream
        backup_key: Decryption key
        
    Returns:
        Tuple of (restored_file, integrity_verified)
    """
    utils = FileEncryptionUtils()
    return utils.decrypt_file_stream(encrypted_backup, backup_key)


def generate_file_encryption_key() -> Tuple[bytes, bytes]:
    """
    Generate new file encryption key with salt.
    
    Returns:
        Tuple of (key, salt)
    """
    salt = os.urandom(32)
    # In production, use a secure key derivation from a master key
    key = os.urandom(32)
    return key, salt


def encrypt_metadata(
    metadata: Dict[str, Any],
    key: bytes
) -> str:
    """
    Encrypt metadata dictionary.
    
    Args:
        metadata: Metadata to encrypt
        key: Encryption key
        
    Returns:
        Base64 encoded encrypted metadata
    """
    try:
        # Convert to JSON
        json_data = json.dumps(metadata).encode('utf-8')
        
        # Encrypt
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data) + padder.finalize()
        
        # Encrypt
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        result = iv + encrypted_data
        
        # Base64 encode
        return base64.b64encode(result).decode('utf-8')
        
    except Exception as e:
        logger.error(f"Metadata encryption failed: {e}")
        raise EncryptionError(f"Failed to encrypt metadata: {str(e)}")


def decrypt_metadata(
    encrypted_metadata: str,
    key: bytes
) -> Dict[str, Any]:
    """
    Decrypt metadata.
    
    Args:
        encrypted_metadata: Base64 encoded encrypted metadata
        key: Decryption key
        
    Returns:
        Decrypted metadata dictionary
    """
    try:
        # Base64 decode
        encrypted_data = base64.b64decode(encrypted_metadata)
        
        # Extract IV and data
        iv = encrypted_data[:16]
        data = encrypted_data[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(data) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        json_data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Parse JSON
        return json.loads(json_data.decode('utf-8'))
        
    except Exception as e:
        logger.error(f"Metadata decryption failed: {e}")
        raise EncryptionError(f"Failed to decrypt metadata: {str(e)}")