# User Authentication System - Comprehensive Implementation Plan

**Assignment**: OAuth2 + 2FA Authentication System
**Date**: 2025-10-16
**Status**: Security-First Design Phase

---

## 🎯 Assignment Requirements Overview

| Task | Weight | Key Deliverables |
|------|--------|------------------|
| **Database Integration** | 20% | SQLite/JSON with secure schemas, optimized retrieval |
| **Basic Authentication** | 20% | Username/password with bcrypt/Argon2, registration/login |
| **Brute Force Protection** | 20% | Rate limiting, 3-attempt lockout, timeout mechanism |
| **Two-Factor Authentication** | 20% | TOTP with pyotp, QR codes, authenticator app integration |
| **OAuth2 Implementation** | 20% | Authorization Code Flow, third-party integration |

---

## 📊 Database Schema Design

### Option 1: SQLite (Recommended for Assignment)

**Rationale**: Lightweight, no external dependencies, sufficient for academic project, already used in existing codebase.

#### **Schema Design**

```sql
-- ============================================
-- 1. USERS TABLE (Enhanced from existing)
-- ============================================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,

    -- Password authentication (hashed with Argon2id)
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    password_version INTEGER DEFAULT 1,  -- For hash migration

    -- Account status
    is_active BOOLEAN DEFAULT 1,
    is_verified BOOLEAN DEFAULT 0,
    email_verified BOOLEAN DEFAULT 0,

    -- Two-Factor Authentication
    totp_secret TEXT,  -- Encrypted TOTP secret
    totp_enabled BOOLEAN DEFAULT 0,
    backup_codes TEXT,  -- JSON array of hashed backup codes

    -- OAuth2 Integration
    oauth_provider TEXT,  -- 'google', 'github', etc.
    oauth_user_id TEXT,   -- Provider's user ID
    oauth_linked BOOLEAN DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,

    -- Constraints
    CHECK (length(username) >= 3),
    CHECK (email LIKE '%@%')
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_oauth ON users(oauth_provider, oauth_user_id);

-- ============================================
-- 2. LOGIN ATTEMPTS TABLE (Brute Force Protection)
-- ============================================
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,

    -- Attempt details
    success BOOLEAN DEFAULT 0,
    failure_reason TEXT,  -- 'invalid_credentials', 'account_locked', etc.

    -- Timestamps
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Indexes for fast queries
    CONSTRAINT idx_login_username_time UNIQUE (username, timestamp)
);

CREATE INDEX idx_login_attempts_username ON login_attempts(username, timestamp);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip_address, timestamp);
CREATE INDEX idx_login_attempts_success ON login_attempts(success, timestamp);

-- ============================================
-- 3. ACCOUNT LOCKOUTS TABLE
-- ============================================
CREATE TABLE account_lockouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,

    -- Lockout details
    locked_until TIMESTAMP NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lockout_reason TEXT,  -- 'too_many_failures', 'security_hold'

    -- Tracking
    locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked_by TEXT DEFAULT 'system',  -- 'system' or 'admin'

    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX idx_lockouts_until ON account_lockouts(locked_until);

-- ============================================
-- 4. OAUTH2 CLIENTS TABLE
-- ============================================
CREATE TABLE oauth2_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Client identification
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,  -- Hashed client secret
    client_name TEXT NOT NULL,

    -- Client metadata
    redirect_uris TEXT NOT NULL,  -- JSON array of allowed redirect URIs
    default_redirect_uri TEXT,
    grant_types TEXT DEFAULT 'authorization_code refresh_token',
    response_types TEXT DEFAULT 'code',
    scope TEXT DEFAULT 'profile email',

    -- Security settings
    token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
    require_pkce BOOLEAN DEFAULT 1,

    -- Public key for private_key_jwt (optional)
    public_key TEXT,

    -- Ownership
    user_id INTEGER,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (grant_types != ''),
    CHECK (redirect_uris != '')
);

CREATE INDEX idx_oauth_client_id ON oauth2_clients(client_id);

-- ============================================
-- 5. OAUTH2 AUTHORIZATION CODES TABLE
-- ============================================
CREATE TABLE oauth2_authorization_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Code details
    code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,

    -- Authorization details
    redirect_uri TEXT NOT NULL,
    scope TEXT,

    -- PKCE support
    code_challenge TEXT,
    code_challenge_method TEXT,  -- 'S256' or 'plain'

    -- State
    used BOOLEAN DEFAULT 0,

    -- Expiration (codes valid for 10 minutes)
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_auth_code ON oauth2_authorization_codes(code);
CREATE INDEX idx_auth_code_expiry ON oauth2_authorization_codes(expires_at);

-- ============================================
-- 6. OAUTH2 TOKENS TABLE
-- ============================================
CREATE TABLE oauth2_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Token identification
    access_token TEXT UNIQUE NOT NULL,
    refresh_token TEXT UNIQUE,
    token_type TEXT DEFAULT 'Bearer',

    -- Token ownership
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,

    -- Token details
    scope TEXT,

    -- Token family for rotation
    token_family_id TEXT NOT NULL,  -- UUID for tracking token families

    -- Reuse detection
    refresh_token_used BOOLEAN DEFAULT 0,
    revoked BOOLEAN DEFAULT 0,
    revoked_at TIMESTAMP,

    -- Expiration
    issued_at INTEGER NOT NULL,  -- Unix timestamp
    expires_in INTEGER NOT NULL,  -- Seconds (3600 = 1 hour)
    refresh_token_expires_at INTEGER,  -- Unix timestamp

    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_token_access ON oauth2_tokens(access_token);
CREATE INDEX idx_token_refresh ON oauth2_tokens(refresh_token);
CREATE INDEX idx_token_family ON oauth2_tokens(token_family_id);
CREATE INDEX idx_token_user ON oauth2_tokens(user_id);

-- ============================================
-- 7. RATE LIMIT TRACKING (Alternative to Redis)
-- ============================================
-- Note: Redis is preferred, but this provides database fallback
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Rate limit key (ip:192.168.1.1 or user:alice)
    key TEXT NOT NULL,
    endpoint TEXT NOT NULL,  -- '/login', '/oauth/token', etc.

    -- Tracking
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    window_end TIMESTAMP NOT NULL,

    -- Unique constraint for atomic operations
    CONSTRAINT unique_rate_limit UNIQUE (key, endpoint, window_start)
);

CREATE INDEX idx_rate_limit_key ON rate_limits(key, endpoint, window_end);

-- Cleanup old rate limit entries (run periodically)
-- DELETE FROM rate_limits WHERE window_end < datetime('now', '-1 hour');

-- ============================================
-- 8. SECURITY EVENTS TABLE (Audit Log)
-- ============================================
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Event details
    event_type TEXT NOT NULL,  -- 'login_success', 'login_failed', 'lockout_applied', etc.
    severity TEXT DEFAULT 'info',  -- 'info', 'warning', 'critical'

    -- Context
    username TEXT,
    ip_address TEXT,
    user_agent TEXT,
    endpoint TEXT,

    -- Additional data (JSON)
    metadata TEXT,  -- JSON object with extra details

    -- Timestamp
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_security_events_type ON security_events(event_type, timestamp);
CREATE INDEX idx_security_events_username ON security_events(username, timestamp);
CREATE INDEX idx_security_events_severity ON security_events(severity, timestamp);

-- ============================================
-- 9. SESSION MANAGEMENT TABLE
-- ============================================
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Session identification
    session_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,

    -- Session data (encrypted)
    session_data TEXT,  -- JSON object

    -- Security tracking
    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,

    -- Status
    is_active BOOLEAN DEFAULT 1,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_sessions_id ON sessions(session_id);
CREATE INDEX idx_sessions_user ON sessions(user_id, is_active);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

-- Cleanup expired sessions (run periodically)
-- DELETE FROM sessions WHERE expires_at < datetime('now');
```

---

## 🏗️ Secure Architecture Design

### **Architecture Pattern: Layered Separation of Concerns**

```
┌─────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│  (Flask Routes, Templates, API Endpoints)                   │
│  - /register, /login, /logout                               │
│  - /setup-2fa, /verify-2fa                                  │
│  - /oauth/authorize, /oauth/token, /oauth/callback         │
└─────────────────────────────────────────────────────────────┘
                            ↓↑
┌─────────────────────────────────────────────────────────────┐
│                     SECURITY MIDDLEWARE                      │
│  - Rate Limiting (Flask-Limiter + Redis)                    │
│  - CSRF Protection (Flask-WTF)                              │
│  - Security Headers (Flask-Talisman)                        │
│  - Session Management (Flask-Login)                         │
└─────────────────────────────────────────────────────────────┘
                            ↓↑
┌─────────────────────────────────────────────────────────────┐
│                     SERVICE LAYER                            │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │ AuthService      │  │ OAuth2Service    │                │
│  │ - register()     │  │ - authorize()    │                │
│  │ - authenticate() │  │ - token()        │                │
│  │ - verify_2fa()   │  │ - validate()     │                │
│  └──────────────────┘  └──────────────────┘                │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │ TOTPService      │  │ SecurityService  │                │
│  │ - generate()     │  │ - log_event()    │                │
│  │ - verify()       │  │ - check_lockout()│                │
│  │ - qr_code()      │  │ - rate_limit()   │                │
│  └──────────────────┘  └──────────────────┘                │
└─────────────────────────────────────────────────────────────┘
                            ↓↑
┌─────────────────────────────────────────────────────────────┐
│                     DATA ACCESS LAYER                        │
│  ┌──────────────────┐  ┌──────────────────┐                │
│  │ UserRepository   │  │ TokenRepository  │                │
│  │ LockoutRepo      │  │ SessionRepo      │                │
│  └──────────────────┘  └──────────────────┘                │
└─────────────────────────────────────────────────────────────┘
                            ↓↑
┌─────────────────────────────────────────────────────────────┐
│                     DATABASE LAYER                           │
│  SQLite + Encryption Module (Fernet)                        │
└─────────────────────────────────────────────────────────────┘
```

### **Project Structure**

```
assignment-2-auth/
├── app.py                      # Flask application entry point
├── config.py                   # Configuration management
├── requirements.txt            # Python dependencies
├── .env                        # Environment variables (SECRET_KEY, etc.)
│
├── database/
│   ├── __init__.py
│   ├── models.py               # SQLAlchemy models
│   ├── schema.sql              # Database schema
│   └── migrations.py           # Database migration utilities
│
├── services/
│   ├── __init__.py
│   ├── auth_service.py         # User authentication logic
│   ├── oauth2_service.py       # OAuth2 provider logic
│   ├── totp_service.py         # TOTP/2FA logic
│   └── security_service.py     # Security monitoring, logging
│
├── repositories/
│   ├── __init__.py
│   ├── user_repository.py      # User CRUD operations
│   ├── token_repository.py     # Token management
│   └── session_repository.py   # Session management
│
├── middleware/
│   ├── __init__.py
│   ├── rate_limiter.py         # Rate limiting configuration
│   ├── security_headers.py     # Security header middleware
│   └── csrf_protection.py      # CSRF token management
│
├── routes/
│   ├── __init__.py
│   ├── auth_routes.py          # /register, /login, /logout
│   ├── oauth_routes.py         # /oauth/* endpoints
│   └── api_routes.py           # Protected API endpoints
│
├── utils/
│   ├── __init__.py
│   ├── encryption.py           # Fernet encryption for TOTP secrets
│   ├── validators.py           # Input validation
│   └── helpers.py              # Utility functions
│
├── templates/
│   ├── base.html
│   ├── register.html
│   ├── login.html
│   ├── setup_2fa.html
│   ├── verify_2fa.html
│   └── oauth_authorize.html
│
├── static/
│   ├── css/
│   └── js/
│
├── tests/
│   ├── test_auth.py
│   ├── test_oauth2.py
│   ├── test_2fa.py
│   ├── test_rate_limiting.py
│   └── test_security.py
│
├── logs/
│   ├── app.log
│   └── security.log
│
└── docs/
    ├── SECURITY_ANALYSIS.md    # Security documentation
    ├── API_DOCUMENTATION.md    # API reference
    └── TESTING_GUIDE.md        # Testing procedures
```

---

## 🔒 Security Threat Model & Mitigations

### **STRIDE Threat Analysis**

| Threat Category | Specific Threats | Mitigation Strategies |
|-----------------|------------------|----------------------|
| **Spoofing** | Account takeover, session hijacking | Strong password hashing (Argon2id), 2FA required, secure session cookies |
| **Tampering** | SQL injection, data modification | Parameterized queries, input validation, integrity checks |
| **Repudiation** | Unauthorized access denial | Comprehensive audit logging, immutable security events |
| **Information Disclosure** | Credential theft, token exposure | Encryption at rest (Fernet), HTTPS only, httpOnly cookies |
| **Denial of Service** | Brute force, lockout attacks | Rate limiting (Flask-Limiter + Redis), account lockout after 3 attempts |
| **Elevation of Privilege** | Unauthorized admin access | Role-based access control, scope validation, least privilege |

### **Threat Scenarios & Countermeasures**

#### **1. Password-Based Attacks**

**Threat**: Attacker attempts to crack user passwords.

**Attack Vectors**:
- Brute force online attacks
- Dictionary attacks
- Rainbow table attacks (offline)
- Credential stuffing (breached databases)

**Mitigations**:
- ✅ **Argon2id hashing** (memory-hard, GPU-resistant)
- ✅ **Unique salts per password** (prevents rainbow tables)
- ✅ **Rate limiting**: 5 attempts/minute per IP, 3 attempts before lockout
- ✅ **Account lockout**: 15-minute lockout after 3 failures
- ✅ **Progressive delays**: Exponential backoff (2s, 4s, 8s, 16s)
- ✅ **CAPTCHA**: Required after 3 failures
- ✅ **Password complexity**: Minimum 12 characters, breach checking (haveibeenpwned API)

**Implementation**:
```python
# services/auth_service.py
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class AuthService:
    def __init__(self):
        self.hasher = PasswordHasher(
            time_cost=2,
            memory_cost=19456,  # 19 MiB
            parallelism=1,
            hash_len=32,
            salt_len=16
        )

    def hash_password(self, password):
        """Hash password with Argon2id"""
        return self.hasher.hash(password)

    def verify_password(self, hash, password):
        """Verify password against hash"""
        try:
            self.hasher.verify(hash, password)

            # Check if rehashing needed (parameter update)
            if self.hasher.check_needs_rehash(hash):
                return True, self.hasher.hash(password)

            return True, None
        except VerifyMismatchError:
            return False, None
```

#### **2. Session Hijacking**

**Threat**: Attacker steals user session to gain unauthorized access.

**Attack Vectors**:
- XSS attacks stealing session cookies
- Man-in-the-middle (MITM) attacks
- Session fixation
- CSRF attacks

**Mitigations**:
- ✅ **httpOnly cookies**: Blocks JavaScript access
- ✅ **Secure flag**: HTTPS-only transmission
- ✅ **SameSite=Strict**: Prevents CSRF
- ✅ **Session regeneration**: New session ID after login
- ✅ **CSRF tokens**: Flask-WTF protection
- ✅ **Content Security Policy**: Blocks inline scripts
- ✅ **Session timeout**: 30-minute inactivity, 24-hour absolute

**Implementation**:
```python
# app.py
from flask_talisman import Talisman

# Enforce HTTPS and security headers
Talisman(app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    session_cookie_http_only=True,
    session_cookie_samesite='Strict',
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' https: data:"
    }
)
```

#### **3. OAuth2 Authorization Code Interception**

**Threat**: Attacker intercepts authorization code to obtain access tokens.

**Attack Vectors**:
- Code interception via compromised redirect URI
- Man-in-the-middle attacks
- Malicious browser extensions

**Mitigations**:
- ✅ **PKCE (RFC 7636)**: Mandatory for all clients
- ✅ **State parameter**: CSRF protection with cryptographic randomness
- ✅ **Exact redirect URI matching**: No wildcards or pattern matching
- ✅ **Short-lived codes**: 10-minute expiration
- ✅ **Single-use codes**: Marked as used immediately
- ✅ **HTTPS-only**: All OAuth endpoints require TLS

**Implementation**:
```python
# services/oauth2_service.py
import secrets
import hashlib
import base64

def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge"""
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge

def validate_redirect_uri(client, redirect_uri):
    """Exact string matching only"""
    allowed_uris = json.loads(client.redirect_uris)
    return redirect_uri in allowed_uris
```

#### **4. Two-Factor Authentication Bypass**

**Threat**: Attacker bypasses 2FA to gain account access.

**Attack Vectors**:
- Brute force TOTP codes (1,000,000 combinations)
- Replay attacks (reusing codes)
- Clock synchronization attacks
- Backup code theft

**Mitigations**:
- ✅ **Rate limiting**: 5 attempts/minute for TOTP verification
- ✅ **Replay prevention**: Track used codes within time window
- ✅ **Clock tolerance**: ±30 seconds (1 window before/after)
- ✅ **Backup codes hashed**: SHA-256, single-use only
- ✅ **Account lockout**: After 5 failed TOTP attempts
- ✅ **Time-based expiration**: 30-second windows

**Implementation**:
```python
# services/totp_service.py
import pyotp
import time

class TOTPService:
    def __init__(self):
        self.used_codes_cache = {}  # Redis in production

    def verify_totp(self, secret, code, username):
        """Verify TOTP with replay prevention"""
        totp = pyotp.TOTP(secret)

        # Check if code was already used
        cache_key = f"{username}:{code}:{int(time.time() // 30)}"
        if cache_key in self.used_codes_cache:
            return False, "Code already used"

        # Verify with ±1 window tolerance (±30 seconds)
        if totp.verify(code, valid_window=1):
            # Mark code as used
            self.used_codes_cache[cache_key] = True
            return True, None

        return False, "Invalid code"
```

#### **5. Account Enumeration**

**Threat**: Attacker determines which usernames/emails exist in system.

**Attack Vectors**:
- Different error messages for existing vs non-existing accounts
- Timing differences in authentication
- Registration endpoint probing

**Mitigations**:
- ✅ **Generic error messages**: "Invalid username or password" (no distinction)
- ✅ **Constant-time comparison**: Timing-safe verification even for non-existent users
- ✅ **Dummy operations**: Perform hash verification even if user doesn't exist
- ✅ **Rate limiting**: Prevents mass enumeration

**Implementation**:
```python
def authenticate(username, password):
    """Timing-safe authentication"""
    user = User.query.filter_by(username=username).first()

    if user:
        is_valid, new_hash = verify_password(user.password_hash, password)
    else:
        # Dummy operation to match timing
        dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
        verify_password(dummy_hash, password)
        is_valid = False

    # Generic error message regardless
    if not is_valid:
        return None, "Invalid username or password"

    return user, None
```

#### **6. Token Theft & Reuse**

**Threat**: Attacker steals and reuses OAuth2 tokens.

**Attack Vectors**:
- XSS attacks extracting tokens from localStorage
- Token logging in server/client logs
- Network interception (MITM)
- Refresh token reuse after compromise

**Mitigations**:
- ✅ **httpOnly cookies**: Tokens never accessible to JavaScript
- ✅ **Short-lived access tokens**: 15-30 minute expiration
- ✅ **Refresh token rotation**: New refresh token on every use
- ✅ **Token family tracking**: Revoke entire family if reuse detected
- ✅ **Token logging prevention**: Redacting filters in logging
- ✅ **TLS enforcement**: HTTPS-only transmission

**Implementation**:
```python
# repositories/token_repository.py
import uuid

class TokenRepository:
    def rotate_refresh_token(self, old_token):
        """Rotate refresh token and detect reuse"""
        token = Token.query.filter_by(refresh_token=old_token).first()

        if not token:
            return None, "Invalid token"

        # Reuse detection
        if token.refresh_token_used:
            # Revoke entire token family
            self.revoke_token_family(token.token_family_id)
            log_security_event('TOKEN_REUSE_DETECTED', token.user_id)
            return None, "Token reuse detected"

        # Mark old token as used
        token.refresh_token_used = True
        token.revoked = True
        db.session.commit()

        # Generate new token pair
        new_token = Token(
            access_token=secrets.token_urlsafe(32),
            refresh_token=secrets.token_urlsafe(32),
            token_family_id=token.token_family_id,  # Same family
            user_id=token.user_id,
            client_id=token.client_id,
            scope=token.scope,
            issued_at=int(time.time()),
            expires_in=3600  # 1 hour
        )

        db.session.add(new_token)
        db.session.commit()

        return new_token, None
```

---

## 📋 Implementation Roadmap

### **Week 1: Foundation & Database** (20 points)

**Days 1-2: Database Setup**
- [ ] Create SQLite database with comprehensive schema
- [ ] Implement database connection management
- [ ] Create migration scripts
- [ ] Add sample data for testing
- [ ] Implement encryption module (Fernet) for TOTP secrets

**Days 3-4: Basic Authentication** (20 points)
- [ ] Implement user registration with Argon2id hashing
- [ ] Create login endpoint with password verification
- [ ] Add logout functionality
- [ ] Implement session management
- [ ] Create user profile page

**Days 5-7: Testing & Documentation**
- [ ] Write unit tests for authentication flows
- [ ] Document database schema design
- [ ] Document security challenges (SQL injection, weak hashing)
- [ ] Document mitigations (parameterized queries, Argon2id)

**Deliverable**: Working registration/login system with secure password storage.

---

### **Week 2: Brute Force Protection** (20 points)

**Days 1-2: Rate Limiting**
- [ ] Install and configure Flask-Limiter
- [ ] Set up Redis for distributed rate limiting
- [ ] Implement hybrid rate limiting (IP + username)
- [ ] Add rate limit decorators to login endpoint

**Days 3-4: Account Lockout**
- [ ] Create login_attempts tracking table
- [ ] Implement 3-failure lockout mechanism
- [ ] Add 15-minute timeout logic
- [ ] Create account unlock after timeout

**Days 5-7: CAPTCHA & Monitoring**
- [ ] Integrate Google reCAPTCHA v2
- [ ] Add CAPTCHA requirement after 3 failures
- [ ] Implement security event logging
- [ ] Create monitoring dashboard for failed attempts
- [ ] Test brute force scenarios

**Deliverable**: Protected login endpoint with rate limiting, lockout, and CAPTCHA.

---

### **Week 3: Two-Factor Authentication** (20 points)

**Days 1-2: TOTP Implementation**
- [ ] Install pyotp and qrcode libraries
- [ ] Create TOTP secret generation
- [ ] Implement QR code generation
- [ ] Add TOTP verification logic
- [ ] Implement replay attack prevention

**Days 3-4: User Interface**
- [ ] Create 2FA setup page
- [ ] Display QR code for scanning
- [ ] Create 2FA verification page during login
- [ ] Implement backup code generation (10 codes)
- [ ] Create backup code verification

**Days 5-7: Recovery & Testing**
- [ ] Implement 2FA disable functionality
- [ ] Add email-based recovery mechanism
- [ ] Create security settings dashboard
- [ ] Test 2FA flows with Google Authenticator
- [ ] Document 2FA security considerations

**Deliverable**: Complete 2FA system with TOTP, QR codes, and backup codes.

---

### **Week 4: OAuth2 Implementation** (20 points)

**Days 1-3: OAuth2 Provider**
- [ ] Install Authlib library
- [ ] Create OAuth2 client registration
- [ ] Implement /oauth/authorize endpoint
- [ ] Implement /oauth/token endpoint
- [ ] Add PKCE support (mandatory)

**Days 4-5: OAuth2 Client**
- [ ] Create OAuth2 client application
- [ ] Implement authorization request
- [ ] Handle authorization callback
- [ ] Exchange code for tokens
- [ ] Store tokens securely (httpOnly cookies)

**Days 6-7: Testing & Documentation**
- [ ] Test complete OAuth2 flow
- [ ] Test PKCE validation
- [ ] Test refresh token rotation
- [ ] Document OAuth2 security benefits
- [ ] Document authorization code flow

**Deliverable**: Working OAuth2 provider and client with PKCE.

---

### **Week 5: Integration & Documentation** (Final deliverables)

**Days 1-2: Integration Testing**
- [ ] End-to-end testing of all features
- [ ] Security penetration testing
- [ ] Performance testing (rate limits, database queries)
- [ ] Cross-browser compatibility testing

**Days 3-5: Comprehensive Documentation**
- [ ] **Security Analysis Report**:
  - Architecture overview
  - Threat model (STRIDE analysis)
  - Security challenges for each feature
  - Vulnerabilities identified
  - Mitigation strategies implemented
  - Testing results and validation

- [ ] **Technical Documentation**:
  - Database schema documentation
  - API reference (all endpoints)
  - Configuration guide
  - Deployment instructions
  - Troubleshooting guide

- [ ] **Code Comments**:
  - Inline comments explaining security decisions
  - Function docstrings
  - Module documentation

**Days 6-7: Final Polish**
- [ ] Code refactoring and cleanup
- [ ] Final security review
- [ ] Demo video/screenshots
- [ ] Submit assignment

---

## 🧪 Testing Strategy

### **Unit Tests**

```python
# tests/test_auth.py
def test_registration_with_weak_password():
    """Should reject passwords < 12 characters"""
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'short'
    })
    assert response.status_code == 400
    assert b'Password must be at least 12 characters' in response.data

def test_password_hashing():
    """Passwords should be hashed with Argon2id"""
    user = User(username='test', email='test@example.com')
    user.set_password('ValidPassword123!')
    assert user.password_hash.startswith('$argon2id$')
    assert user.verify_password('ValidPassword123!') == True
    assert user.verify_password('WrongPassword') == False

def test_brute_force_lockout():
    """Should lock account after 3 failures"""
    for i in range(3):
        client.post('/login', data={'username': 'alice', 'password': 'wrong'})

    response = client.post('/login', data={'username': 'alice', 'password': 'correct'})
    assert response.status_code == 429
    assert b'Account locked' in response.data

def test_2fa_verification():
    """Should verify valid TOTP codes"""
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    code = totp.now()

    result = totp_service.verify_totp(secret, code, 'alice')
    assert result[0] == True

def test_oauth2_pkce_required():
    """OAuth2 authorization should require PKCE"""
    response = client.get('/oauth/authorize?client_id=test&response_type=code')
    assert response.status_code == 400
    assert b'code_challenge required' in response.data
```

### **Integration Tests**

```python
# tests/test_integration.py
def test_complete_authentication_flow():
    """Test full flow: register → login → 2FA → protected resource"""

    # Register
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'SecurePassword123!'
    })
    assert response.status_code == 302

    # Login (without 2FA)
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'SecurePassword123!'
    })
    assert response.status_code == 200

    # Setup 2FA
    response = client.get('/setup-2fa')
    secret = extract_secret_from_qr(response.data)

    # Verify 2FA setup
    totp = pyotp.TOTP(secret)
    code = totp.now()
    response = client.post('/verify-2fa-setup', data={'code': code})
    assert response.status_code == 302

    # Logout and login again (now requires 2FA)
    client.get('/logout')
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'SecurePassword123!'
    })
    assert response.status_code == 302
    assert b'verify-2fa' in response.location

    # Verify 2FA
    code = totp.now()
    response = client.post('/verify-2fa', data={'code': code})
    assert response.status_code == 302

    # Access protected resource
    response = client.get('/profile')
    assert response.status_code == 200

def test_oauth2_authorization_code_flow():
    """Test complete OAuth2 flow with PKCE"""

    # Generate PKCE pair
    verifier, challenge = generate_pkce_pair()

    # Authorization request
    response = client.get('/oauth/authorize', query_string={
        'client_id': 'test_client',
        'response_type': 'code',
        'redirect_uri': 'http://localhost:3000/callback',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': 'random_state'
    })
    assert response.status_code == 200

    # User approves
    response = client.post('/oauth/authorize', data={
        'client_id': 'test_client',
        'approved': 'yes'
    })
    assert response.status_code == 302
    code = extract_code_from_redirect(response.location)

    # Exchange code for token
    response = client.post('/oauth/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': 'http://localhost:3000/callback',
        'client_id': 'test_client',
        'client_secret': 'test_secret',
        'code_verifier': verifier
    })
    assert response.status_code == 200
    token_data = response.json
    assert 'access_token' in token_data
    assert 'refresh_token' in token_data
```

---

## 📦 Dependencies (requirements.txt)

```txt
# Web Framework
Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Login==0.6.3
Flask-WTF==1.2.1

# Security
Argon2-cffi==23.1.0           # Password hashing
pyotp==2.9.0                  # TOTP 2FA
qrcode[pil]==7.4.2            # QR code generation
Flask-Limiter==3.5.0          # Rate limiting
Flask-Talisman==1.1.0         # Security headers
cryptography==41.0.7          # Encryption (Fernet)
authlib==1.3.0                # OAuth2 provider
redis==5.0.1                  # Rate limit storage

# Database
SQLAlchemy==2.0.23

# Utilities
python-dotenv==1.0.0          # Environment variables
requests==2.31.0              # HTTP client (OAuth testing)

# Testing
pytest==7.4.3
pytest-flask==1.3.0
pytest-cov==4.1.0

# Development
black==23.12.1                # Code formatter
flake8==6.1.0                 # Linter
```

---

## 🎓 Grading Rubric Alignment

| Requirement | Implementation | Documentation | Score Target |
|-------------|----------------|---------------|--------------|
| **Database Integration (20%)** | SQLite schema with 9 tables, encrypted TOTP storage, optimized indexes | Schema design documentation, security challenges (SQL injection), mitigations (parameterized queries) | **18-20/20** (Excellent) |
| **Basic Authentication (20%)** | Argon2id hashing, salt generation, registration/login/logout, session management | Password security analysis, rainbow table prevention, timing attack mitigation | **18-20/20** (Excellent) |
| **Brute Force Protection (20%)** | Flask-Limiter + Redis, 3-attempt lockout, 15-min timeout, CAPTCHA after 3 failures, security logging | Rate limiting strategies, lockout mechanisms, attack scenarios, testing evidence | **18-20/20** (Excellent) |
| **2FA Implementation (20%)** | pyotp TOTP, QR codes, backup codes, replay prevention, rate limiting | 2FA security benefits, TOTP algorithm explanation, recovery mechanisms | **18-20/20** (Excellent) |
| **OAuth2 Implementation (20%)** | Authlib provider, PKCE mandatory, refresh token rotation, token family tracking | OAuth2 flow diagrams, security benefits, PKCE necessity, state parameter usage | **18-20/20** (Excellent) |

**Expected Total**: **90-100/100** (Excellent grade)

---

## 🚀 Quick Start Commands

```bash
# Setup virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env with your SECRET_KEY, REDIS_URL, etc.

# Initialize database
python -c "from database.models import init_database; init_database()"

# Run Redis (for rate limiting)
docker run -d -p 6379:6379 redis:alpine

# Run Flask application
flask run --debug

# Run tests
pytest tests/ -v --cov

# Access application
open http://localhost:5000
```

---

## 📚 Key Security Documentation Points

### **For Each Feature, Document:**

1. **Security Challenge**: What vulnerability exists?
2. **Attack Scenario**: How could it be exploited?
3. **Vulnerability Analysis**: Why is it dangerous?
4. **Mitigation Strategy**: How did you fix it?
5. **Testing Evidence**: Proof that mitigation works
6. **Code Examples**: Before/after comparisons

### **Example Documentation Structure**

```markdown
## Task 2: Basic User Authentication

### Security Challenge
**Vulnerability**: Weak password storage using MD5 or plain text.

**Attack Scenario**: Attacker gains database access through SQL injection
or backup file exposure. If passwords are stored in plain text or hashed
with MD5, the attacker can immediately use them to compromise all accounts.

### Vulnerability Analysis
- MD5 is broken (collision attacks, rainbow tables)
- Fast hashing allows brute force (billions of hashes/second on GPU)
- No protection against rainbow tables if no salt
- Timing attacks possible with unsafe comparison

### Mitigation Strategy
1. **Argon2id Password Hashing**: Memory-hard algorithm resistant to
   GPU/ASIC attacks
2. **Unique Salts**: Auto-generated per password, prevents rainbow tables
3. **Timing-Safe Comparison**: `hmac.compare_digest()` prevents timing attacks
4. **Hash Migration**: Support upgrading from weaker algorithms

### Implementation
```python
from argon2 import PasswordHasher

hasher = PasswordHasher(
    time_cost=2,        # Iterations
    memory_cost=19456,  # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16
)

# Registration
password_hash = hasher.hash(password)
user = User(username=username, password_hash=password_hash)

# Login
try:
    hasher.verify(user.password_hash, password)
    return True
except VerifyMismatchError:
    return False
```

### Testing Evidence
- ✅ Passwords stored as `$argon2id$v=19$m=19456,t=2,p=1$...`
- ✅ Hashing takes 200-500ms (prevents brute force)
- ✅ Each password has unique salt
- ✅ Timing attack test: constant verification time regardless of input
- ✅ Rainbow table test: identical passwords produce different hashes

### Recommendations
- Use Argon2id over bcrypt for new applications
- Monitor hash computation time (<500ms target)
- Consider password breach checking (haveibeenpwned API)
- Implement progressive rehashing for algorithm updates
```

---

## ✅ Success Criteria

**Your implementation is successful when:**

- [ ] All 5 assignment requirements implemented and working
- [ ] Comprehensive security documentation for each feature
- [ ] Database schema supports all features securely
- [ ] All tests passing (unit + integration)
- [ ] No TODO comments in production code
- [ ] Security vulnerabilities identified and mitigated
- [ ] Code follows SOLID principles and separation of concerns
- [ ] Professional documentation with diagrams
- [ ] Demo-ready application
- [ ] Expected grade: 90-100/100 (Excellent)

---

**Document Version**: 1.0
**Last Updated**: 2025-10-16
**Status**: ✅ Ready for Implementation
