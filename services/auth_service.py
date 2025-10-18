"""
Authentication Service
Handles user registration, login, password hashing with Argon2id
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
import secrets
import hmac
from datetime import datetime
from database import get_db_connection
from utils.validators import PasswordValidator, UsernameValidator, EmailValidator

class AuthService:
    """
    Core authentication service
    Uses Argon2id for password hashing (OWASP recommended)
    """

    def __init__(self):
        """Initialize with Argon2id hasher"""
        # OWASP recommended parameters
        self.hasher = PasswordHasher(
            time_cost=2,        # Iterations
            memory_cost=19456,  # 19 MiB memory
            parallelism=1,      # Single thread
            hash_len=32,        # 32-byte hash
            salt_len=16         # 16-byte salt
        )

    def register_user(self, username, email, password):
        """
        Register new user with secure password hashing

        Args:
            username: Unique username
            email: User email address
            password: Plain text password

        Returns:
            (success, user_id_or_error) tuple
        """
        # Validate inputs
        is_valid, error = UsernameValidator.validate(username)
        if not is_valid:
            return False, error

        is_valid, error = EmailValidator.validate(email)
        if not is_valid:
            return False, error

        is_valid, error = PasswordValidator.validate(password)
        if not is_valid:
            return False, error

        # Check for breached password
        is_breached, count = PasswordValidator.check_breach(password)
        if is_breached:
            return False, f"This password has appeared in {count} data breaches. Please choose a different password."

        conn = get_db_connection()

        # Check if user exists
        existing = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()

        if existing:
            conn.close()
            return False, "Username or email already exists"

        try:
            # Hash password with Argon2id
            password_hash = self.hasher.hash(password)

            # Generate unique salt for additional security (stored separately)
            password_salt = secrets.token_hex(16)

            # Insert user
            cursor = conn.execute('''
                INSERT INTO users
                (username, email, password, password_salt, password_version,
                 is_active, email_verified)
                VALUES (?, ?, ?, ?, 1, 1, 0)
            ''', (username, email, password_hash, password_salt))

            user_id = cursor.lastrowid
            conn.commit()
            conn.close()

            return True, user_id

        except Exception as e:
            conn.close()
            return False, f"Registration failed: {str(e)}"

    def authenticate(self, username, password):
        """
        Authenticate user with timing-safe verification

        Args:
            username: Username to authenticate
            password: Plain text password

        Returns:
            (success, user_or_error) tuple
        """
        conn = get_db_connection()

        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()

        # Timing-safe authentication
        if user:
            try:
                # Verify password
                self.hasher.verify(user['password'], password)

                # Check if password needs rehashing (parameter update)
                if self.hasher.check_needs_rehash(user['password']):
                    new_hash = self.hasher.hash(password)
                    conn.execute(
                        'UPDATE users SET password = ? WHERE id = ?',
                        (new_hash, user['id'])
                    )
                    conn.commit()

                # Update last login
                conn.execute(
                    'UPDATE users SET last_login = ? WHERE id = ?',
                    (datetime.utcnow(), user['id'])
                )
                conn.commit()

                conn.close()
                return True, dict(user)

            except (VerifyMismatchError, InvalidHash):
                # Perform dummy timing to prevent timing attacks
                dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXJhbmRvbXNhbHQ$fakehashvalue"
                try:
                    self.hasher.verify(dummy_hash, password)
                except:
                    pass

                conn.close()
                return False, "Invalid username or password"
        else:
            # Dummy operation to match timing
            dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXJhbmRvbXNhbHQ$fakehashvalue"
            try:
                self.hasher.verify(dummy_hash, password)
            except:
                pass

            conn.close()
            return False, "Invalid username or password"

    def change_password(self, user_id, old_password, new_password):
        """
        Change user password with verification

        Args:
            user_id: User ID
            old_password: Current password for verification
            new_password: New password to set

        Returns:
            (success, error_message) tuple
        """
        # Validate new password
        is_valid, error = PasswordValidator.validate(new_password)
        if not is_valid:
            return False, error

        conn = get_db_connection()

        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        if not user:
            conn.close()
            return False, "User not found"

        try:
            # Verify old password
            self.hasher.verify(user['password'], old_password)

            # Hash new password
            new_hash = self.hasher.hash(new_password)

            # Update password
            conn.execute(
                'UPDATE users SET password = ?, password_version = password_version + 1 WHERE id = ?',
                (new_hash, user_id)
            )
            conn.commit()
            conn.close()

            return True, None

        except VerifyMismatchError:
            conn.close()
            return False, "Current password is incorrect"

    def get_user_by_id(self, user_id):
        """
        Get user by ID

        Args:
            user_id: User ID

        Returns:
            User dict or None
        """
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        conn.close()

        return dict(user) if user else None

    def get_user_by_username(self, username):
        """
        Get user by username

        Args:
            username: Username

        Returns:
            User dict or None
        """
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()

        return dict(user) if user else None


# Singleton instance
_auth_service = None

def get_auth_service():
    """Get singleton auth service instance"""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
