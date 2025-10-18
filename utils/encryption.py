"""
Encryption Service for sensitive data (TOTP secrets, etc.)
Uses Fernet (symmetric encryption with AES-128)
"""
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
from dotenv import load_dotenv

# Load environment variables (ensure .env is loaded before encryption initialization)
load_dotenv()

class EncryptionService:
    """
    Service for encrypting/decrypting sensitive data
    Uses Fernet (AES-128 in CBC mode with HMAC authentication)
    """

    def __init__(self, encryption_key=None):
        """
        Initialize encryption service with key

        Args:
            encryption_key: Base64-encoded Fernet key (32 bytes)
                          If None, generates from SECRET_KEY environment variable
        """
        if encryption_key is None:
            # Derive encryption key from SECRET_KEY
            secret_key = os.getenv('SECRET_KEY', 'default-secret-key-change-in-production')
            encryption_key = self._derive_key(secret_key.encode())

        self.cipher = Fernet(encryption_key)

    def _derive_key(self, password):
        """
        Derive Fernet key from password using PBKDF2

        SECURITY: Uses environment-specific salt to ensure unique encryption keys
        per deployment. This prevents rainbow table attacks and ensures
        compromising one deployment doesn't compromise others.

        Args:
            password: Password bytes

        Returns:
            Base64-encoded Fernet key

        Raises:
            ValueError: If ENCRYPTION_SALT not configured or too short
        """
        # Get salt from environment variable
        salt_str = os.getenv('ENCRYPTION_SALT')

        # Validate salt configuration
        if not salt_str:
            raise ValueError(
                "ENCRYPTION_SALT environment variable is required. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(16))'"
            )

        # Convert to bytes
        try:
            salt = salt_str.encode('utf-8')
        except Exception as e:
            raise ValueError(f"Invalid ENCRYPTION_SALT format: {e}")

        # Validate minimum length (16 bytes for security)
        if len(salt) < 16:
            raise ValueError(
                f"ENCRYPTION_SALT must be at least 16 bytes (got {len(salt)}). "
                "Generate with: python -c 'import secrets; print(secrets.token_hex(16))'"
            )

        # Derive encryption key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def encrypt(self, plaintext):
        """
        Encrypt plaintext string

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return None

        encrypted_bytes = self.cipher.encrypt(plaintext.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')

    def decrypt(self, ciphertext):
        """
        Decrypt ciphertext string

        Args:
            ciphertext: Base64-encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        if not ciphertext:
            return None

        try:
            decrypted_bytes = self.cipher.decrypt(ciphertext.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    @staticmethod
    def generate_key():
        """
        Generate new Fernet encryption key

        Returns:
            Base64-encoded 32-byte key
        """
        return Fernet.generate_key().decode('utf-8')


# Global instance
_encryption_service = None

def get_encryption_service():
    """Get singleton encryption service instance"""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service
