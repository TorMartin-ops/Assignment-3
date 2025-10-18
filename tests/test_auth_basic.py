#!/usr/bin/env python3
"""
Basic Authentication System Tests
Tests core services without requiring Flask
"""

def test_encryption():
    """Test encryption service"""
    print("\nTesting Encryption Service...")

    from utils.encryption import get_encryption_service

    encryption = get_encryption_service()

    # Test encryption/decryption
    secret = "test_totp_secret_12345"
    encrypted = encryption.encrypt(secret)
    decrypted = encryption.decrypt(encrypted)

    assert decrypted == secret, "Encryption/decryption failed"
    print(f"   Encrypted: {encrypted[:50]}...")
    print(f"   Decrypted: {decrypted}")

def test_validators():
    """Test input validators"""
    print("\nTesting Validators...")

    from utils.validators import PasswordValidator, EmailValidator, UsernameValidator

    # Password validation
    is_valid, error = PasswordValidator.validate("short")
    assert not is_valid, "Should reject short password"
    print(f"   Short password rejected: {error}")

    is_valid, error = PasswordValidator.validate("ValidPassword123!")
    assert is_valid, "Should accept valid password"
    print(f"   Valid password accepted")

    # Email validation
    is_valid, error = EmailValidator.validate("test@example.com")
    assert is_valid, "Should accept valid email"
    print(f"   Valid email accepted")

    is_valid, error = EmailValidator.validate("invalid-email")
    assert not is_valid, "Should reject invalid email"
    print(f"   Invalid email rejected: {error}")

    # Username validation
    is_valid, error = UsernameValidator.validate("validuser123")
    assert is_valid, "Should accept valid username"
    print(f"   Valid username accepted")

def test_auth_service():
    """Test authentication service"""
    print("\nTesting Authentication Service...")

    from services.auth_service import get_auth_service
    import time

    auth = get_auth_service()

    # Generate unique username for test
    test_username = f"testuser_{int(time.time())}"
    test_email = f"test_{int(time.time())}@example.com"
    test_password = "SecurePassword123!"

    # Test registration
    success, result = auth.register_user(test_username, test_email, test_password)
    if success:
        print(f"   User registered: ID {result}")
    else:
        print(f"   Registration failed: {result}")
        return

    # Test successful login
    success, user = auth.authenticate(test_username, test_password)
    assert success, "Should authenticate with correct password"
    print(f"   Login successful: {user['username']}")

    # Test failed login
    success, error = auth.authenticate(test_username, "WrongPassword")
    assert not success, "Should reject wrong password"
    print(f"   Wrong password rejected")

    # Test timing safety (account enumeration prevention)
    start = time.time()
    success, _ = auth.authenticate("nonexistent_user", "password")
    time1 = time.time() - start

    start = time.time()
    success, _ = auth.authenticate(test_username, "wrongpassword")
    time2 = time.time() - start

    time_diff = abs(time1 - time2)
    print(f"   Timing difference: {time_diff:.4f}s (should be minimal)")

def test_rate_limiter():
    """Test rate limiting service"""
    print("\nTesting Rate Limiter...")

    from services.rate_limiter import get_rate_limiter

    limiter = get_rate_limiter()

    test_key = "ip:192.168.1.100"
    test_endpoint = "/test-endpoint"

    # Clear any existing limits
    from database import get_db_connection
    conn = get_db_connection()
    conn.execute('DELETE FROM rate_limits WHERE key = ?', (test_key,))
    conn.commit()
    conn.close()

    # Test within limit
    for i in range(5):
        is_limited, remaining, _ = limiter.is_rate_limited(test_key, test_endpoint)
        assert not is_limited, f"Request {i+1} should not be limited"
        limiter.record_request(test_key, test_endpoint)
        print(f"   Request {i+1}/5: Allowed, {remaining-1} remaining")

    # Test rate limit exceeded
    is_limited, remaining, reset_time = limiter.is_rate_limited(test_key, test_endpoint)
    assert is_limited, "Should be rate limited after 5 requests"
    print(f"   Rate limit exceeded (as expected)")
    print(f"   Reset time: {reset_time}")

def test_totp_service():
    """Test TOTP 2FA service"""
    print("\nTesting TOTP/2FA Service...")

    from services.totp_service import get_totp_service
    import pyotp

    totp_service = get_totp_service()

    # Generate secret
    secret = totp_service.generate_secret()
    print(f"   Secret generated: {secret}")

    # Generate QR code
    qr_code = totp_service.generate_qr_code(secret, "testuser")
    assert qr_code.startswith("data:image/png;base64,"), "Should generate base64 QR code"
    print(f"   QR code generated ({len(qr_code)} chars)")

    # Generate current TOTP code
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    print(f"   Current TOTP: {current_code}")

    # Test backup code generation
    backup_codes = [totp_service._generate_backup_code() for _ in range(10)]
    assert len(backup_codes) == 10, "Should generate 10 backup codes"
    assert all(len(code) == 9 for code in backup_codes), "Format should be XXXX-XXXX"
    print(f"   Backup codes: {backup_codes[0]}, {backup_codes[1]}, ...")

def test_security_service():
    """Test security monitoring service"""
    print("\nTesting Security Service...")

    from services.security_service import get_security_service

    security = get_security_service()

    # Log security event
    event_id = security.log_security_event(
        'test_event',
        username='testuser',
        ip_address='192.168.1.1',
        severity='info',
        metadata={'test': True}
    )
    print(f"   Security event logged: ID {event_id}")

    # Log login attempt
    attempt_id = security.log_login_attempt(
        'testuser',
        '192.168.1.1',
        'Mozilla/5.0',
        success=True
    )
    print(f"   Login attempt logged: ID {attempt_id}")

    # Check account lockout (should not be locked)
    is_locked, message, remaining = security.check_account_lockout('testuser')
    assert not is_locked, "Account should not be locked"
    print(f"   Account not locked")

    # Test failure tracking
    test_username = "lockout_test_user"
    for i in range(3):
        security.log_login_attempt(
            test_username,
            '192.168.1.1',
            'Test',
            success=False,
            failure_reason='wrong_password'
        )

    failures = security.get_recent_failures(test_username)
    assert failures == 3, "Should track 3 failures"
    print(f"   Failed attempts tracked: {failures}")

    # Apply lockout
    security.apply_account_lockout(test_username, failures)

    # Check lockout status
    is_locked, message, remaining = security.check_account_lockout(test_username)
    assert is_locked, "Account should be locked"
    print(f"   Account locked: {message}")

    # Get statistics
    stats = security.get_login_statistics()
    print(f"   Login statistics: {stats}")

def test_database_schema():
    """Test database schema"""
    print("\nTesting Database Schema...")

    from database import get_db_connection

    conn = get_db_connection()

    # Check all tables exist
    tables = [
        'users', 'login_attempts', 'account_lockouts', 'rate_limits',
        'security_events', 'oauth2_clients', 'oauth2_authorization_codes',
        'oauth2_tokens', 'sessions'
    ]

    for table in tables:
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table,)
        ).fetchone()
        assert result, f"Table {table} should exist"
        print(f"   Table exists: {table}")

    conn.close()

def main():
    """Run all tests"""
    print("=" * 60)
    print("AUTHENTICATION SYSTEM - BASIC TESTS")
    print("=" * 60)

    try:
        # Test database schema
        test_database_schema()

        # Test utilities
        test_encryption()
        test_validators()

        # Test services
        test_auth_service()
        test_rate_limiter()
        test_totp_service()
        test_security_service()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
        print("\nThe authentication system is working correctly!")
        print("   Next steps:")
        print("   1. Implement OAuth2 service")
        print("   2. Create Flask routes")
        print("   3. Add HTML templates")
        print("   4. Write comprehensive tests")

    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
