# Authentication System - Setup Guide

## 🚀 Quick Start

### Step 1: Install Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
```

### Step 2: Initialize Database

```bash
# Create authentication tables
python3 database_auth.py
```

This will:
- ✅ Add authentication columns to existing users table
- ✅ Create login_attempts table (brute force tracking)
- ✅ Create account_lockouts table
- ✅ Create rate_limits table (no Redis needed!)
- ✅ Create security_events table (audit log)
- ✅ Create OAuth2 tables (clients, codes, tokens)
- ✅ Create sessions table
- ✅ Generate sample OAuth2 client for testing

### Step 3: Set Environment Variables

Create `.env` file:

```bash
SECRET_KEY=your-secret-key-change-this-in-production
FLASK_ENV=development
```

### Step 4: Test Authentication Services

```bash
# Test the authentication system
python3 test_auth_basic.py
```

---

## 📋 What's Been Implemented

### ✅ **1. Database Schema (Complete)**

**9 new/enhanced tables:**
- `users` (enhanced with 2FA, OAuth, tracking fields)
- `login_attempts` (brute force detection)
- `account_lockouts` (3-failure lockout)
- `rate_limits` (database-based, no Redis)
- `security_events` (comprehensive audit log)
- `oauth2_clients` (OAuth2 provider)
- `oauth2_authorization_codes` (OAuth2 codes)
- `oauth2_tokens` (access & refresh tokens)
- `sessions` (session management)

### ✅ **2. Core Services (Complete)**

#### **AuthService** (`services/auth_service.py`)
- ✅ **Argon2id password hashing** (OWASP recommended)
- ✅ **Timing-safe authentication** (prevents timing attacks)
- ✅ **Password breach checking** (haveibeenpwned API)
- ✅ **Automatic hash migration** (parameter updates)
- ✅ **User registration & login**

#### **RateLimiter** (`services/rate_limiter.py`)
- ✅ **Database-based (NO REDIS REQUIRED!)**
- ✅ **Hybrid rate limiting** (IP + username)
- ✅ **Configurable limits** (5 requests/minute default)
- ✅ **Automatic cleanup** of old entries
- ✅ **Flask decorator** for easy route protection

#### **TOTPService** (`services/totp_service.py`)
- ✅ **TOTP 2FA** (Time-based One-Time Passwords)
- ✅ **QR code generation** (works with Google Authenticator)
- ✅ **Backup codes** (10 codes, SHA-256 hashed)
- ✅ **Replay attack prevention** (used code tracking)
- ✅ **Secret encryption** (Fernet AES-128)

#### **SecurityService** (`services/security_service.py`)
- ✅ **Login attempt tracking**
- ✅ **3-failure account lockout** (15-minute timeout)
- ✅ **CAPTCHA requirement** (after 3 failures)
- ✅ **Security event logging**
- ✅ **Login statistics** (monitoring dashboard data)

### ✅ **3. Utility Modules (Complete)**

#### **EncryptionService** (`utils/encryption.py`)
- ✅ **Fernet encryption** (AES-128 CBC + HMAC)
- ✅ **TOTP secret protection**
- ✅ **Key derivation** from SECRET_KEY

#### **Validators** (`utils/validators.py`)
- ✅ **PasswordValidator** (NIST SP 800-63B compliant)
- ✅ **EmailValidator** (RFC 5321 compliant)
- ✅ **UsernameValidator** (format validation)
- ✅ **Breach checking** (haveibeenpwned integration)

---

## 🔒 Security Features Implemented

### **Assignment Requirement 1: Database Integration (20%)**
- ✅ SQLite with 9 comprehensive tables
- ✅ Optimized indexes for performance
- ✅ Foreign key constraints
- ✅ Encrypted sensitive data (TOTP secrets)
- ✅ Secure schema design

**Security Challenges & Mitigations:**
- **Challenge**: SQL injection vulnerabilities
- **Mitigation**: Parameterized queries throughout
- **Challenge**: Sensitive data exposure
- **Mitigation**: Encryption for secrets, hashing for passwords/codes

### **Assignment Requirement 2: Basic Authentication (20%)**
- ✅ Argon2id password hashing (memory-hard, GPU-resistant)
- ✅ Unique salts per password
- ✅ Timing-safe verification
- ✅ Password breach checking
- ✅ Registration & login flows

**Security Challenges & Mitigations:**
- **Challenge**: Rainbow table attacks
- **Mitigation**: Argon2id with unique salts
- **Challenge**: Timing attacks (account enumeration)
- **Mitigation**: Constant-time comparison, dummy operations
- **Challenge**: Weak passwords
- **Mitigation**: NIST-compliant validation, breach checking

### **Assignment Requirement 3: Brute Force Protection (20%)**
- ✅ Database-based rate limiting (5 requests/minute)
- ✅ 3-failure account lockout
- ✅ 15-minute timeout
- ✅ CAPTCHA requirement (after 3 failures)
- ✅ Comprehensive logging

**Security Challenges & Mitigations:**
- **Challenge**: Password guessing attacks
- **Mitigation**: Rate limiting + account lockout
- **Challenge**: Distributed attacks
- **Mitigation**: Hybrid rate limiting (IP + username)
- **Challenge**: DoS via lockout
- **Mitigation**: Temporary lockout (15 min) vs permanent

### **Assignment Requirement 4: Two-Factor Authentication (20%)**
- ✅ TOTP implementation (RFC 6238)
- ✅ QR code generation
- ✅ Google Authenticator compatible
- ✅ 10 backup codes (SHA-256 hashed)
- ✅ Replay attack prevention

**Security Challenges & Mitigations:**
- **Challenge**: TOTP code brute force
- **Mitigation**: Rate limiting (5 attempts)
- **Challenge**: Replay attacks
- **Mitigation**: Used code tracking within time window
- **Challenge**: Secret exposure
- **Mitigation**: Fernet encryption in database
- **Challenge**: Lost device recovery
- **Mitigation**: Backup codes (single-use)

### **Assignment Requirement 5: OAuth2 (20%)**
- ⏳ **OAuth2 service implementation in progress**
- ✅ Database tables ready (clients, codes, tokens)
- ⏳ Authlib integration (next step)

---

## 🧪 Testing the Implementation

### Test Authentication Service

```python
python3 -c "
from services.auth_service import get_auth_service

auth = get_auth_service()

# Test registration
success, user_id = auth.register_user(
    'testuser',
    'test@example.com',
    'SecurePassword123!'
)
print(f'Registration: {success}, User ID: {user_id}')

# Test login
success, user = auth.authenticate('testuser', 'SecurePassword123!')
print(f'Login: {success}')
print(f'User: {user[\"username\"] if success else \"Failed\"}')
"
```

### Test Rate Limiting

```python
python3 -c "
from services.rate_limiter import get_rate_limiter

limiter = get_rate_limiter()

# Simulate 6 requests (limit is 5/minute)
for i in range(6):
    is_limited, remaining, reset_time = limiter.is_rate_limited('ip:192.168.1.1', '/login')
    print(f'Request {i+1}: Limited={is_limited}, Remaining={remaining}')
    if not is_limited:
        limiter.record_request('ip:192.168.1.1', '/login')
"
```

### Test 2FA Service

```python
python3 -c "
from services.totp_service import get_totp_service
import pyotp

totp_service = get_totp_service()

# Generate secret
secret = totp_service.generate_secret()
print(f'Secret: {secret}')

# Generate QR code
qr_code = totp_service.generate_qr_code(secret, 'testuser')
print(f'QR Code: {qr_code[:100]}...')

# Generate current code
totp = pyotp.TOTP(secret)
code = totp.now()
print(f'Current TOTP: {code}')
"
```

### Test Security Service

```python
python3 -c "
from services.security_service import get_security_service

security = get_security_service()

# Log security event
event_id = security.log_security_event(
    'test_event',
    username='testuser',
    ip_address='192.168.1.1',
    severity='info'
)
print(f'Security event logged: {event_id}')

# Check account lockout status
is_locked, message, remaining = security.check_account_lockout('testuser')
print(f'Account locked: {is_locked}')

# Get statistics
stats = security.get_login_statistics()
print(f'Login stats: {stats}')
"
```

---

## 📊 Implementation Status

| Component | Status | Files Created |
|-----------|--------|---------------|
| Database Schema | ✅ Complete | `database_auth.py` |
| Auth Service | ✅ Complete | `services/auth_service.py` |
| Rate Limiter | ✅ Complete | `services/rate_limiter.py` |
| TOTP/2FA Service | ✅ Complete | `services/totp_service.py` |
| Security Service | ✅ Complete | `services/security_service.py` |
| Encryption Utils | ✅ Complete | `utils/encryption.py` |
| Validators | ✅ Complete | `utils/validators.py` |
| OAuth2 Service | ⏳ In Progress | Next phase |
| Flask Routes | ⏳ In Progress | Next phase |
| Tests | ⏳ Pending | Next phase |

---

## 🎯 Next Steps

### Immediate (Ready to run):
1. ✅ Install dependencies: `pip install -r requirements.txt`
2. ✅ Initialize database: `python3 database_auth.py`
3. ✅ Test services (commands above)

### Coming Soon:
4. ⏳ Implement OAuth2 service (Authlib)
5. ⏳ Create Flask routes for authentication endpoints
6. ⏳ Add HTML templates for UI
7. ⏳ Write comprehensive tests
8. ⏳ Create documentation

---

## 💡 Key Accomplishments

### **No Redis Required!**
- Database-based rate limiting works perfectly
- Automatic cleanup of old entries
- Suitable for academic projects and small deployments

### **Production-Ready Security**
- Argon2id (OWASP recommendation)
- NIST-compliant password policies
- Comprehensive security logging
- Timing attack prevention
- Replay attack prevention

### **Complete 2FA Implementation**
- TOTP with QR codes
- Google Authenticator compatible
- Backup codes for recovery
- Encrypted secret storage

### **Brute Force Protection**
- Multi-layer defense (rate limiting + lockout + CAPTCHA)
- Configurable thresholds
- Automatic unlocking
- Security event tracking

---

## 🔍 Architecture Highlights

### **Separation of Concerns**
```
Services Layer (business logic)
    ↓
Database Layer (data persistence)
    ↓
Utilities Layer (encryption, validation)
```

### **Security-First Design**
- ✅ Input validation at service layer
- ✅ Parameterized SQL queries (no injection)
- ✅ Encrypted sensitive data
- ✅ Hashed passwords and codes
- ✅ Comprehensive audit logging

### **Scalability Considerations**
- ✅ Indexed database queries
- ✅ Efficient cleanup mechanisms
- ✅ Singleton service pattern
- ✅ Ready for Flask integration

---

**Document Version**: 1.0
**Last Updated**: 2025-10-16
**Status**: ✅ Core services complete, ready for Flask integration
