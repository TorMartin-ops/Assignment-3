"""
Input Validation Utilities
Password strength checking, email validation, etc.
"""
import re
import requests
import hashlib

class PasswordValidator:
    """
    NIST-compliant password validator
    Follows NIST SP 800-63B guidelines (2024)
    """

    MIN_LENGTH = 12
    MAX_LENGTH = 128

    # Common passwords to block (top 100 subset)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'password123', 'Password1', 'admin', 'welcome'
    }

    @classmethod
    def validate(cls, password):
        """
        Validate password against NIST guidelines

        Args:
            password: Password string to validate

        Returns:
            (is_valid, error_message) tuple
        """
        if not password:
            return False, "Password is required"

        # Length check
        if len(password) < cls.MIN_LENGTH:
            return False, f"Password must be at least {cls.MIN_LENGTH} characters"

        if len(password) > cls.MAX_LENGTH:
            return False, f"Password must be at most {cls.MAX_LENGTH} characters"

        # Common password check
        if password.lower() in cls.COMMON_PASSWORDS:
            return False, "Password is too common. Please choose a stronger password"

        # Character diversity check (optional but recommended)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)

        diversity_score = sum([has_upper, has_lower, has_digit])

        if diversity_score < 2:
            return False, "Password should contain uppercase, lowercase, and numbers"

        return True, None

    @classmethod
    def check_breach(cls, password):
        """
        Check if password appears in known data breaches using haveibeenpwned API

        Args:
            password: Password to check

        Returns:
            (is_breached, count) tuple
        """
        try:
            # Hash password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query haveibeenpwned API (k-anonymity model)
            response = requests.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                timeout=2
            )

            if response.status_code == 200:
                hashes = response.text.splitlines()
                for hash_line in hashes:
                    hash_suffix, count = hash_line.split(':')
                    if hash_suffix == suffix:
                        return True, int(count)

            return False, 0
        except Exception as e:
            # Don't fail validation if API is down
            print(f"Breach check error: {e}")
            return False, 0


class EmailValidator:
    """Email validation utility"""

    # RFC 5322 compliant email regex (prevents consecutive dots, leading/trailing dots)
    EMAIL_REGEX = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9._%+-]*[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$|^[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$'
    )

    @classmethod
    def validate(cls, email):
        """
        Validate email format

        Args:
            email: Email string to validate

        Returns:
            (is_valid, error_message) tuple
        """
        if not email:
            return False, "Email is required"

        # Check for consecutive dots (RFC 5322 violation)
        if '..' in email:
            return False, "Invalid email format"

        if not cls.EMAIL_REGEX.match(email):
            return False, "Invalid email format"

        if len(email) > 254:  # RFC 5321
            return False, "Email is too long"

        return True, None


class UsernameValidator:
    """Username validation utility"""

    MIN_LENGTH = 3
    MAX_LENGTH = 30
    USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')

    @classmethod
    def validate(cls, username):
        """
        Validate username format

        Args:
            username: Username string to validate

        Returns:
            (is_valid, error_message) tuple
        """
        if not username:
            return False, "Username is required"

        if len(username) < cls.MIN_LENGTH:
            return False, f"Username must be at least {cls.MIN_LENGTH} characters"

        if len(username) > cls.MAX_LENGTH:
            return False, f"Username must be at most {cls.MAX_LENGTH} characters"

        if not cls.USERNAME_REGEX.match(username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"

        return True, None
