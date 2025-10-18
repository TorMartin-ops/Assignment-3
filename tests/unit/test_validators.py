"""
Unit Tests for Input Validators
Tests password, email, and username validation logic
"""
import pytest
from utils.validators import PasswordValidator, EmailValidator, UsernameValidator


class TestPasswordValidator:
    """Test password validation and security checks"""

    def test_valid_strong_password(self):
        """Test that strong passwords pass validation"""
        valid_passwords = [
            'MySecurePass123!',
            'Testing@2024Secure',
            'P@ssw0rd1234Complex',
            'SuperStrong999#Pass'
        ]

        for password in valid_passwords:
            is_valid, error = PasswordValidator.validate_strength(password)
            assert is_valid, f"Password '{password}' should be valid, but got: {error}"

    def test_password_too_short(self):
        """Test that short passwords are rejected"""
        short_passwords = ['Pass1!', 'Test@123', 'Ab1!']

        for password in short_passwords:
            is_valid, error = PasswordValidator.validate_strength(password)
            assert not is_valid
            assert '12 characters' in error.lower()

    def test_password_missing_complexity(self):
        """Test that passwords without complexity requirements fail"""
        weak_passwords = [
            'allowercase1234',  # No uppercase
            'ALLUPPERCASE123',  # No lowercase
            'NoNumbersHere!!',  # No digits
        ]

        for password in weak_passwords:
            is_valid, error = PasswordValidator.validate_strength(password)
            assert not is_valid
            assert 'complexity' in error.lower() or 'requirements' in error.lower()

    def test_common_password_blocked(self):
        """Test that common passwords are rejected"""
        common_passwords = ['password123', 'qwerty12345', '123456789012']

        for password in common_passwords:
            is_valid, error = PasswordValidator.validate_strength(password)
            assert not is_valid
            assert 'common' in error.lower()

    @pytest.mark.skip(reason="Requires network connection to HaveIBeenPwned API")
    def test_breached_password_detection(self):
        """Test HaveIBeenPwned integration (network required)"""
        # Known breached password
        is_breached, count = PasswordValidator.check_breach('password123')
        assert is_breached
        assert count > 0


class TestEmailValidator:
    """Test email validation logic"""

    def test_valid_emails(self):
        """Test that valid email formats pass"""
        valid_emails = [
            'user@example.com',
            'test.user@domain.co.uk',
            'name+tag@company.org',
            'admin@sub.domain.com'
        ]

        for email in valid_emails:
            is_valid, error = EmailValidator.validate(email)
            assert is_valid, f"Email '{email}' should be valid, but got: {error}"

    def test_invalid_email_formats(self):
        """Test that invalid email formats are rejected"""
        invalid_emails = [
            'notanemail',
            '@domain.com',
            'user@',
            'user @domain.com',  # Space
            'user..name@domain.com',  # Double dot
        ]

        for email in invalid_emails:
            is_valid, error = EmailValidator.validate(email)
            assert not is_valid
            assert 'invalid' in error.lower() or 'format' in error.lower()

    def test_email_max_length(self):
        """Test that overly long emails are rejected"""
        # Email longer than 254 characters (RFC 5321 limit)
        long_email = 'a' * 250 + '@example.com'
        is_valid, error = EmailValidator.validate(long_email)
        assert not is_valid


class TestUsernameValidator:
    """Test username validation logic"""

    def test_valid_usernames(self):
        """Test that valid usernames pass"""
        valid_usernames = [
            'user123',
            'test_user',
            'admin-account',
            'JohnDoe2024'
        ]

        for username in valid_usernames:
            is_valid, error = UsernameValidator.validate(username)
            assert is_valid, f"Username '{username}' should be valid, but got: {error}"

    def test_username_too_short(self):
        """Test that short usernames are rejected"""
        is_valid, error = UsernameValidator.validate('ab')
        assert not is_valid
        assert '3' in error or 'short' in error.lower()

    def test_username_too_long(self):
        """Test that long usernames are rejected"""
        long_username = 'a' * 31  # 31 characters (max is 30)
        is_valid, error = UsernameValidator.validate(long_username)
        assert not is_valid
        assert '30' in error or 'long' in error.lower()

    def test_username_invalid_characters(self):
        """Test that usernames with special characters are rejected"""
        invalid_usernames = [
            'user@name',  # @ not allowed
            'user name',  # Space
            'user!123',   # Exclamation
            'user$money', # Dollar sign
        ]

        for username in invalid_usernames:
            is_valid, error = UsernameValidator.validate(username)
            assert not is_valid
            assert 'character' in error.lower() or 'alphanumeric' in error.lower()
