"""
TOTP Two-Factor Authentication Service
Implements Time-based One-Time Password (RFC 6238)
"""
import pyotp
import qrcode
import io
import base64
import secrets
import hashlib
import json
from datetime import datetime, timedelta
from database import get_db_connection
from utils.encryption import get_encryption_service

class TOTPService:
    """
    Two-Factor Authentication service using TOTP
    Generates secrets, QR codes, and verifies codes
    """

    def __init__(self):
        """Initialize TOTP service"""
        self.encryption = get_encryption_service()
        self.used_codes_cache = {}  # In-memory replay prevention

    def generate_secret(self):
        """
        Generate new TOTP secret

        Returns:
            Base32-encoded secret string
        """
        return pyotp.random_base32()

    def generate_qr_code(self, secret, username, issuer='RecipeApp'):
        """
        Generate QR code for authenticator app

        Args:
            secret: TOTP secret
            username: User's username
            issuer: App name for authenticator

        Returns:
            Base64-encoded PNG image
        """
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_base64}"

    def enable_2fa(self, user_id, secret):
        """
        Enable 2FA for user and generate backup codes

        Args:
            user_id: User ID
            secret: TOTP secret

        Returns:
            (success, backup_codes) tuple
        """
        # Encrypt secret before storing
        encrypted_secret = self.encryption.encrypt(secret)

        # Generate 10 backup codes
        backup_codes = [self._generate_backup_code() for _ in range(10)]

        # Hash backup codes before storing
        hashed_codes = [
            hashlib.sha256(code.encode()).hexdigest()
            for code in backup_codes
        ]

        conn = get_db_connection()
        conn.execute('''
            UPDATE users
            SET totp_secret = ?, totp_enabled = 1, backup_codes = ?
            WHERE id = ?
        ''', (encrypted_secret, json.dumps(hashed_codes), user_id))
        conn.commit()
        conn.close()

        return True, backup_codes

    def disable_2fa(self, user_id):
        """
        Disable 2FA for user

        Args:
            user_id: User ID

        Returns:
            Success boolean
        """
        conn = get_db_connection()
        conn.execute('''
            UPDATE users
            SET totp_secret = NULL, totp_enabled = 0, backup_codes = NULL
            WHERE id = ?
        ''', (user_id,))
        conn.commit()
        conn.close()

        return True

    def verify_totp(self, user_id, code):
        """
        Verify TOTP code with replay prevention

        Args:
            user_id: User ID
            code: 6-digit TOTP code

        Returns:
            (is_valid, error_message) tuple
        """
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        conn.close()

        if not user or not user['totp_enabled']:
            return False, "2FA not enabled for this user"

        # Decrypt secret
        encrypted_secret = user['totp_secret']
        secret = self.encryption.decrypt(encrypted_secret)

        if not secret:
            return False, "Invalid 2FA configuration"

        # Check for replay attack
        current_window = int(datetime.utcnow().timestamp() // 30)
        cache_key = f"{user_id}:{code}:{current_window}"

        if cache_key in self.used_codes_cache:
            return False, "Code already used"

        # Verify TOTP with ±1 window tolerance (±30 seconds)
        totp = pyotp.TOTP(secret)

        if totp.verify(code, valid_window=1):
            # Mark code as used
            self.used_codes_cache[cache_key] = True

            # Clean old entries (keep only current and previous window)
            self._cleanup_used_codes(current_window)

            return True, None

        return False, "Invalid code"

    def verify_backup_code(self, user_id, code):
        """
        Verify and consume backup code

        Args:
            user_id: User ID
            code: Backup code

        Returns:
            (is_valid, remaining_codes) tuple
        """
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        if not user or not user['backup_codes']:
            conn.close()
            return False, 0

        # Hash provided code
        code_hash = hashlib.sha256(code.encode()).hexdigest()

        # Load backup codes
        backup_codes = json.loads(user['backup_codes'])

        if code_hash in backup_codes:
            # Remove used code
            backup_codes.remove(code_hash)

            # Update database
            conn.execute('''
                UPDATE users SET backup_codes = ? WHERE id = ?
            ''', (json.dumps(backup_codes), user_id))
            conn.commit()
            conn.close()

            return True, len(backup_codes)
        else:
            conn.close()
            return False, len(backup_codes)

    def _generate_backup_code(self):
        """
        Generate backup code in format XXXX-XXXX

        Returns:
            Backup code string
        """
        part1 = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(4))
        part2 = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(4))
        return f"{part1}-{part2}"

    def _cleanup_used_codes(self, current_window):
        """
        Clean up old used codes from cache

        Args:
            current_window: Current time window
        """
        # Keep only codes from current and previous 2 windows (90 seconds)
        cutoff_window = current_window - 2

        keys_to_delete = [
            key for key in self.used_codes_cache.keys()
            if int(key.split(':')[2]) < cutoff_window
        ]

        for key in keys_to_delete:
            del self.used_codes_cache[key]


# Singleton instance
_totp_service = None

def get_totp_service():
    """Get singleton TOTP service instance"""
    global _totp_service
    if _totp_service is None:
        _totp_service = TOTPService()
    return _totp_service
