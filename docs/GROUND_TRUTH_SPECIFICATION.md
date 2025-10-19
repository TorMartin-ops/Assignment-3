# Complete Ground Truth Specification for Diagram Generation
## Assignment 3 - Authentication System

**Generated**: 2025-10-19
**Purpose**: Complete file:line evidence for all UML diagrams

---

## 1. SYSTEM ARCHITECTURE GROUND TRUTH

### 1.1 Flask Application Core
**File**: `/home/torma/Assignment-3/app_auth.py`

| Component | Lines | Description | Evidence |
|-----------|-------|-------------|----------|
| Flask App Initialization | 20 | `app = Flask(__name__)` | Core Flask application instance |
| Secret Key Configuration | 21 | `app.secret_key = os.getenv('SECRET_KEY', ...)` | Session encryption key |
| Session Cookie Security | 24-26 | `SESSION_COOKIE_SECURE`, `HTTPONLY`, `SAMESITE` | Cookie hardening |
| CSRF Protection | 29 | `csrf = CSRFProtect(app)` | Global CSRF protection |
| Database Initialization | 32-33 | `init_database()`, `initialize_auth_database()` | Database setup |
| Blueprint Registration | 36-38 | `register_blueprint(auth_bp, oauth_bp, twofa_bp)` | Route registration |
| reCAPTCHA Service | 41 | `recaptcha_service = get_recaptcha_service()` | CAPTCHA initialization |
| Security Headers | 53-56 | `@app.after_request` decorator | Apply headers to all responses |
| Rate Limit Handler | 316-320 | `@app.errorhandler(429)` | 429 Too Many Requests handler |

**Trust Boundary**: HTTP → HTTPS (TLS terminates at reverse proxy/server level)

---

### 1.2 Blueprint Architecture
**File**: `/home/torma/Assignment-3/routes/__init__.py`

| Blueprint | Prefix | Lines | Registered In |
|-----------|--------|-------|---------------|
| `auth_bp` | `/` | auth_routes.py:12 | app_auth.py:36 |
| `oauth_bp` | `/oauth` | oauth_routes.py:22 | app_auth.py:37 |
| `twofa_bp` | `/` | twofa_routes.py:12 | app_auth.py:38 |

---

### 1.3 Database Schema (9 Tables, 15 Indexes)
**File**: `/home/torma/Assignment-3/database_auth.py`

#### Table 1: users (Enhanced)
**Lines**: 22-80
```
ALTER TABLE users ADD COLUMN:
- password_salt TEXT (line 26)
- password_version INTEGER DEFAULT 1 (line 31)
- is_active INTEGER DEFAULT 1 (line 36)
- email_verified INTEGER DEFAULT 0 (line 41)
- totp_secret TEXT (line 47)
- totp_enabled INTEGER DEFAULT 0 (line 52)
- backup_codes TEXT (line 57)
- oauth_provider TEXT (line 63)
- oauth_user_id TEXT (line 68)
- oauth_linked INTEGER DEFAULT 0 (line 73)
- last_login TIMESTAMP (line 78)
```

#### Table 2: login_attempts
**Lines**: 87-97
```sql
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    success INTEGER DEFAULT 0,
    failure_reason TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```
**Indexes**:
- `idx_login_attempts_username` (lines 100-103): username, timestamp
- `idx_login_attempts_ip` (lines 105-108): ip_address, timestamp

#### Table 3: account_lockouts
**Lines**: 113-123
```sql
CREATE TABLE IF NOT EXISTS account_lockouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    locked_until TIMESTAMP NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    lockout_reason TEXT,
    locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked_by TEXT DEFAULT 'system'
)
```
**Index**:
- `idx_lockouts_until` (lines 125-128): locked_until

#### Table 4: rate_limits
**Lines**: 133-143
```sql
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    window_end TIMESTAMP NOT NULL,
    UNIQUE(key, endpoint, window_start)
)
```
**Index**:
- `idx_rate_limit_key` (lines 145-148): key, endpoint, window_end

#### Table 5: security_events
**Lines**: 153-165
```sql
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    username TEXT,
    ip_address TEXT,
    user_agent TEXT,
    endpoint TEXT,
    metadata TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```
**Indexes**:
- `idx_security_events_type` (lines 167-170): event_type, timestamp
- `idx_security_events_username` (lines 172-175): username, timestamp

#### Table 6: oauth2_clients
**Lines**: 180-199
```sql
CREATE TABLE IF NOT EXISTS oauth2_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT NOT NULL,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    default_redirect_uri TEXT,
    grant_types TEXT DEFAULT 'authorization_code refresh_token',
    response_types TEXT DEFAULT 'code',
    scope TEXT DEFAULT 'profile email',
    token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
    require_pkce INTEGER DEFAULT 1,
    public_key TEXT,
    user_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
```
**Index**:
- `idx_oauth_client_id` (lines 201-204): client_id

#### Table 7: oauth2_authorization_codes
**Lines**: 209-225
```sql
CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    used INTEGER DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
```
**Index**:
- `idx_auth_code` (lines 227-230): code

#### Table 8: oauth2_tokens
**Lines**: 235-254
```sql
CREATE TABLE IF NOT EXISTS oauth2_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_token TEXT UNIQUE NOT NULL,
    refresh_token TEXT UNIQUE,
    token_type TEXT DEFAULT 'Bearer',
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scope TEXT,
    token_family_id TEXT NOT NULL,
    refresh_token_used INTEGER DEFAULT 0,
    revoked INTEGER DEFAULT 0,
    revoked_at TIMESTAMP,
    issued_at INTEGER NOT NULL,
    expires_in INTEGER NOT NULL,
    refresh_token_expires_at INTEGER,
    FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
```
**Indexes**:
- `idx_token_access` (lines 256-259): access_token
- `idx_token_refresh` (lines 261-264): refresh_token
- `idx_token_family` (lines 266-269): token_family_id

#### Table 9: sessions
**Lines**: 274-289
```sql
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    session_data TEXT,
    ip_address TEXT,
    user_agent TEXT,
    device_fingerprint TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
```
**Indexes**:
- `idx_sessions_id` (lines 291-294): session_id
- `idx_sessions_user` (lines 296-299): user_id, is_active

**Total**: 9 tables, 15 indexes, 3 foreign key relationships

---

### 1.4 Service Layer (Singleton Pattern)
**All services use singleton pattern for lifecycle management**

#### AuthService
**File**: `/home/torma/Assignment-3/services/auth_service.py`
- **Class Definition**: Lines 13-247
- **Singleton Instance**: Lines 249-257
- **Argon2id Configuration**: Lines 19-28
  - `time_cost=2` (line 23)
  - `memory_cost=19456` (19 MiB, line 24)
  - `parallelism=1` (line 25)
  - `hash_len=32, salt_len=16` (lines 26-27)

#### OAuth2Service
**File**: `/home/torma/Assignment-3/services/oauth2_service.py`
- **Class Definition**: Lines 14-444
- **Singleton Instance**: Lines 447-455
- **Token Expiration**:
  - `ACCESS_TOKEN_EXPIRES = 3600` (1 hour, line 21)
  - `REFRESH_TOKEN_EXPIRES = 2592000` (30 days, line 22)
  - `AUTH_CODE_EXPIRES = 600` (10 minutes, line 23)

#### TOTPService
**File**: `/home/torma/Assignment-3/services/totp_service.py`
- **Class Definition**: Lines 16-250
- **Singleton Instance**: Lines 252-260
- **Replay Prevention Cache**: Line 25 (`used_codes_cache`)

#### SecurityService
**File**: `/home/torma/Assignment-3/services/security_service.py`
- **Class Definition**: Lines 9-314
- **Singleton Instance**: Lines 316-324
- **Brute Force Thresholds**:
  - `LOCKOUT_THRESHOLD = 3` (line 16)
  - `LOCKOUT_DURATION = timedelta(minutes=15)` (line 17)
  - `CAPTCHA_THRESHOLD = 3` (line 18)

#### RateLimiter
**File**: `/home/torma/Assignment-3/services/rate_limiter.py`
- **Class Definition**: Lines 11-178
- **Singleton Instance**: Lines 180-188
- **Default Configuration**:
  - `requests_per_minute=5` (line 17)
  - `window_minutes=1` (line 18)

---

### 1.5 Utility Modules

#### Encryption Service (Fernet)
**File**: `/home/torma/Assignment-3/utils/encryption.py`
- **Class**: Lines 16-133
- **Singleton**: Lines 135-143
- **Key Derivation (PBKDF2)**: Lines 37-86
  - Algorithm: SHA-256 (line 79)
  - Iterations: 100,000 (line 82)
  - Salt: From `ENCRYPTION_SALT` env var (line 55)

#### Validators
**File**: `/home/torma/Assignment-3/utils/validators.py`

**PasswordValidator** (lines 9-98):
- `MIN_LENGTH = 12` (line 15)
- `MAX_LENGTH = 128` (line 16)
- HIBP API Integration: Lines 64-97
  - API: `https://api.pwnedpasswords.com/range/{prefix}` (line 82-84)
  - K-anonymity model (SHA-1 prefix matching)

**EmailValidator** (lines 100-133):
- RFC 5322 compliant regex (lines 104-106)
- Max length 254 (RFC 5321, line 129)

**UsernameValidator** (lines 135-166):
- `MIN_LENGTH = 3, MAX_LENGTH = 30` (lines 138-139)
- Regex: `^[a-zA-Z0-9_-]+$` (line 140)

#### Security Headers
**File**: `/home/torma/Assignment-3/utils/security_headers.py`
- **Function**: `set_security_headers()` (lines 7-37)
- **Headers Applied**:
  - CSP (lines 24-32): Restricts script sources, prevents inline scripts
  - X-Content-Type-Options: nosniff (line 33)
  - X-Frame-Options: DENY (line 34)
  - X-XSS-Protection: 1; mode=block (line 35)
  - HSTS: max-age=31536000; includeSubDomains (line 36)

#### Decorators
**File**: `/home/torma/Assignment-3/utils/decorators.py`
- `login_required` (lines 8-20): Check session, redirect if not authenticated
- `regenerate_session()` (lines 23-53): Session fixation prevention

#### reCAPTCHA Service
**File**: `/home/torma/Assignment-3/utils/recaptcha.py`
- **Class**: Lines 10-126
- **Singleton**: Lines 128-142
- **Verification URL**: `https://www.google.com/recaptcha/api/siteverify` (line 21)
- **Verify Method**: Lines 42-96

---

## 2. AUTHENTICATION ROUTES (auth_routes.py)

**File**: `/home/torma/Assignment-3/routes/auth_routes.py`

| Route | Method | Lines | Rate Limit | Key Security Features |
|-------|--------|-------|------------|----------------------|
| `/register` | GET/POST | 20-57 | None | HIBP check (line 39), Argon2id hashing |
| `/login` | GET/POST | 59-146 | 5/min per-user | Lockout check (72), CAPTCHA (78-94), Session regen (116) |
| `/logout` | GET | 148-163 | None | Session clear (161) |
| `/change-password` | GET/POST | 165-202 | None | Old password verification (182-186) |
| `/security-settings` | GET | 204-218 | None | Login stats display |

### Login Flow Details (lines 59-146):
1. **Input validation** (lines 64-69)
2. **Lockout check** (lines 72-75): `check_account_lockout(username)`
3. **CAPTCHA check** (lines 78-94): If `requires_captcha(username)`
4. **Authenticate** (line 97): `auth_service.authenticate(username, password)`
5. **Log attempt** (lines 100-106): `log_login_attempt()`
6. **Success path**:
   - Clear lockout (line 112)
   - **Session regeneration** (line 116): `regenerate_session()` - CRITICAL
   - Check 2FA enabled (line 119)
   - If 2FA: Store pending state (lines 121-123), redirect to verify
   - If no 2FA: Complete login (lines 126-129)
7. **Failure path** (lines 130-144):
   - Count failures (line 132)
   - Apply lockout if threshold reached (lines 134-137)
   - Show remaining attempts (lines 139-140)

---

## 3. OAUTH2 ROUTES (oauth_routes.py)

**File**: `/home/torma/Assignment-3/routes/oauth_routes.py`

### Route 1: /oauth/authorize (lines 28-122)
**Method**: GET/POST
**CSRF**: Protected (not exempt)

**GET Flow (Authorization Request)**:
1. **Parse parameters** (lines 37-43):
   - `client_id` (required)
   - `redirect_uri` (required)
   - `response_type` (must be 'code')
   - `state` (recommended)
   - `code_challenge` (MANDATORY, line 42)
   - `code_challenge_method` (default S256, line 43)

2. **Validate client** (lines 46-51):
   - `oauth2_service.get_client(client_id)`
   - `validate_redirect_uri(client_id, redirect_uri)` - EXACT match only

3. **Validate PKCE** (lines 62-63):
   - If no `code_challenge`: Return error (PKCE mandatory)

4. **Check authentication** (lines 66-70):
   - If not logged in: Save return URL, redirect to login

5. **Store request in session** (lines 73-80)

6. **Show consent screen** (lines 83-85)

**POST Flow (User Consent)**:
1. **Check approval** (line 88): `request.form.get('approved') == 'yes'`
2. **Generate auth code** (lines 102-109):
   - `oauth2_service.generate_authorization_code()`
   - Stores: client_id, user_id, redirect_uri, scope, code_challenge, method
3. **Log event** (lines 112-118)
4. **Redirect with code** (lines 121-122)

### Route 2: /oauth/token (lines 124-212)
**Method**: POST
**CSRF**: EXEMPT (line 125)

**Grant Type: authorization_code (lines 133-182)**:
1. **Extract parameters** (lines 135-139):
   - code, redirect_uri, client_id, client_secret, code_verifier

2. **Validate client** (lines 142-144):
   - `validate_client(client_id, client_secret)`

3. **Validate authorization code** (lines 147-149):
   - `validate_authorization_code(code, client_id)`
   - **Uses BEGIN IMMEDIATE transaction** (oauth2_service.py:178)

4. **Validate redirect_uri match** (lines 152-153)

5. **Validate PKCE** (lines 156-164):
   - `validate_pkce(code_verifier, code_challenge, method)`

6. **Generate tokens** (lines 167-171):
   - `generate_tokens(client_id, user_id, scope)`

7. **Return token response** (line 182)

**Grant Type: refresh_token (lines 184-210)**:
1. **Extract parameters** (lines 186-188)
2. **Validate client** (lines 191-193)
3. **Refresh token** (lines 196):
   - `refresh_access_token(refresh_token, client_id)`
   - **Uses BEGIN IMMEDIATE transaction** (oauth2_service.py:307)
   - **Rotation**: Old token marked used, new token issued
   - **Reuse detection**: If refresh_token_used=1, revoke entire family (oauth2_service.py:320-325)

### Route 3: /oauth/userinfo (lines 214-240)
**Method**: GET
**Authorization**: Bearer token required

1. **Extract token** (lines 221-226): From `Authorization: Bearer {token}`
2. **Validate token** (lines 229-232): `validate_access_token(access_token)`
3. **Return user info** (lines 235-239): `get_user_info(user_id)`

### Route 4: /oauth/revoke (lines 242-273)
**Method**: POST
**CSRF**: EXEMPT (line 243)

1. **Validate client** (lines 254-256)
2. **Revoke token** (line 262): `revoke_token(token, token_type_hint)`
3. **Return 200** (line 273): Per RFC 7009

---

## 4. TWO-FACTOR AUTHENTICATION ROUTES (twofa_routes.py)

**File**: `/home/torma/Assignment-3/routes/twofa_routes.py`

### Route 1: /setup-2fa (lines 20-80)
**Method**: GET/POST
**Rate Limit**: 5/min per-user (line 21)

**GET Flow**:
1. **Check login** (lines 24-26)
2. **Check if already enabled** (lines 30-32)
3. **Generate secret** (line 74): `totp_service.generate_secret()`
4. **Store in session** (line 75): `session['temp_totp_secret'] = secret`
5. **Generate QR code** (line 78): `generate_qr_code(secret, username)`
6. **Show setup page** (line 80)

**POST Flow**:
1. **Retrieve temp secret** (lines 36-37)
2. **Verify code** (lines 44-46): `pyotp.TOTP(secret).verify(code, valid_window=1)`
3. **Enable 2FA** (line 48): `totp_service.enable_2fa(user_id, secret)`
   - Encrypts secret (totp_service.py:87)
   - Generates 10 backup codes (totp_service.py:90)
   - Hashes backup codes with SHA-256 (totp_service.py:93-96)
4. **Store backup codes in session** (line 55): One-time display
5. **Log event** (lines 57-62)
6. **Redirect to backup codes** (line 65)

### Route 2: /verify-2fa (lines 82-153)
**Method**: GET/POST
**Rate Limit**: 5/min per-IP (line 83)

**POST Flow**:
1. **Check pending state** (lines 86-88): `pending_2fa_user_id` in session
2. **Get code** (lines 91-95)

**TOTP Verification (lines 125-147)**:
1. **Verify code** (line 126): `totp_service.verify_totp(user_id, code)`
   - **Replay prevention** (totp_service.py:159-163):
     - Cache key: `{user_id}:{code}:{time_window}`
     - Window: 30 seconds (timestamp // 30)
     - If used: Return "Code already used"
   - **Tolerance**: ±1 window (±30 seconds)
2. **Clean session** (lines 131-133)
3. **Session regeneration** (line 133): `regenerate_session()` - SECOND regen point
4. **Complete login** (lines 136-137)
5. **Log event** (lines 139-144)

**Backup Code Verification (lines 97-123)**:
1. **Verify backup code** (line 99): `verify_backup_code(user_id, code)`
   - Hash code with SHA-256 (totp_service.py:201)
   - Check against stored hashes (totp_service.py:206)
   - Remove if found (totp_service.py:208)
2. **Session regeneration** (line 106): `regenerate_session()`
3. **Complete login** (lines 109-110)
4. **Log event** (lines 112-118): Includes remaining codes count

### Route 3: /backup-codes (lines 155-168)
**Method**: GET

1. **Pop from session** (line 162): One-time display only
2. **Show codes** (line 168)

### Route 4: /disable-2fa (lines 170-206)
**Method**: GET/POST
**Rate Limit**: 3/min per-user (line 171)

**POST Flow**:
1. **Verify password** (line 188): `auth_service.authenticate(username, password)`
2. **Disable 2FA** (line 192): `totp_service.disable_2fa(user_id)`
3. **Log critical event** (lines 194-199): Severity='critical'

---

## 5. CLASS DIAGRAM GROUND TRUTH

### Service Classes

#### AuthService
**File**: `services/auth_service.py` (lines 13-247)

**Attributes**:
- `hasher: PasswordHasher` (line 22)

**Methods**:
```python
__init__(self) -> None  # lines 19-28
register_user(self, username: str, email: str, password: str) -> Tuple[bool, Any]  # lines 30-95
authenticate(self, username: str, password: str) -> Tuple[bool, Any]  # lines 97-159
change_password(self, user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]  # lines 161-208
get_user_by_id(self, user_id: int) -> Optional[dict]  # lines 210-227
get_user_by_username(self, username: str) -> Optional[dict]  # lines 229-246
```

**Dependencies**:
- PasswordHasher (argon2, line 5)
- PasswordValidator, UsernameValidator, EmailValidator (line 11)
- Database connection (line 10)

#### OAuth2Service
**File**: `services/oauth2_service.py` (lines 14-444)

**Attributes**:
- `ACCESS_TOKEN_EXPIRES: int = 3600` (line 21)
- `REFRESH_TOKEN_EXPIRES: int = 2592000` (line 22)
- `AUTH_CODE_EXPIRES: int = 600` (line 23)

**Methods**:
```python
__init__(self) -> None  # lines 25-27
get_client(self, client_id: str) -> Optional[dict]  # lines 29-45
validate_client(self, client_id: str, client_secret: str) -> Tuple[bool, Any]  # lines 48-74
validate_redirect_uri(self, client_id: str, redirect_uri: str) -> bool  # lines 76-96
validate_pkce(self, code_verifier: str, code_challenge: str, code_challenge_method: str) -> bool  # lines 98-122
generate_authorization_code(self, client_id: str, user_id: int, redirect_uri: str, scope: str, code_challenge: str, code_challenge_method: str) -> str  # lines 124-159
validate_authorization_code(self, code: str, client_id: str) -> Tuple[bool, Any]  # lines 161-209
generate_tokens(self, client_id: str, user_id: int, scope: str, conn: Optional[Connection]) -> dict  # lines 211-259
validate_access_token(self, access_token: str) -> Tuple[bool, Any]  # lines 261-288
refresh_access_token(self, refresh_token: str, client_id: str) -> Tuple[bool, Any]  # lines 290-364
revoke_token(self, token: str, token_type_hint: str) -> bool  # lines 366-395
_revoke_token_family(self, token_family_id: str) -> None  # lines 397-416
get_user_info(self, user_id: int) -> Optional[dict]  # lines 418-444
```

**Transaction Safety**:
- `validate_authorization_code()`: BEGIN IMMEDIATE (line 178)
- `refresh_access_token()`: BEGIN IMMEDIATE (line 307)

#### TOTPService
**File**: `services/totp_service.py` (lines 16-250)

**Attributes**:
- `encryption: EncryptionService` (line 24)
- `used_codes_cache: dict` (line 25)

**Methods**:
```python
__init__(self) -> None  # lines 22-25
generate_secret(self) -> str  # lines 27-34
generate_qr_code(self, secret: str, username: str, issuer: str) -> str  # lines 36-73
enable_2fa(self, user_id: int, secret: str) -> Tuple[bool, List[str]]  # lines 75-107
disable_2fa(self, user_id: int) -> bool  # lines 109-128
verify_totp(self, user_id: int, code: str) -> Tuple[bool, Optional[str]]  # lines 130-177
verify_backup_code(self, user_id: int, code: str) -> Tuple[bool, int]  # lines 179-220
_generate_backup_code(self) -> str  # lines 222-231
_cleanup_used_codes(self, current_window: int) -> None  # lines 233-249
```

**Dependencies**:
- pyotp (line 5)
- qrcode (line 6)
- EncryptionService (line 14)

#### SecurityService
**File**: `services/security_service.py` (lines 9-314)

**Attributes**:
- `LOCKOUT_THRESHOLD: int = 3` (line 16)
- `LOCKOUT_DURATION: timedelta` (line 17)
- `CAPTCHA_THRESHOLD: int = 3` (line 18)

**Methods**:
```python
__init__(self) -> None  # lines 20-22
log_security_event(self, event_type: str, username: str, ip_address: str, user_agent: str, endpoint: str, metadata: dict, severity: str) -> int  # lines 24-61
log_login_attempt(self, username: str, ip_address: str, user_agent: str, success: bool, failure_reason: str) -> int  # lines 63-102
check_account_lockout(self, username: str) -> Tuple[bool, str, int]  # lines 104-133
get_recent_failures(self, username: str, window: timedelta) -> int  # lines 135-157
apply_account_lockout(self, username: str, failed_count: int) -> bool  # lines 159-217
clear_account_lockout(self, username: str) -> bool  # lines 219-245
requires_captcha(self, username: str) -> bool  # lines 247-258
get_login_statistics(self, username: str, hours: int) -> dict  # lines 260-313
```

**Transaction Safety**:
- `apply_account_lockout()`: BEGIN IMMEDIATE (line 178)

#### RateLimiter
**File**: `services/rate_limiter.py` (lines 11-178)

**Attributes**:
- `requests_per_minute: int` (line 17)
- `window_minutes: int` (line 18)

**Methods**:
```python
__init__(self, requests_per_minute: int, window_minutes: int) -> None  # lines 17-26
is_rate_limited(self, key: str, endpoint: str) -> Tuple[bool, int, datetime]  # lines 28-75
record_request(self, key: str, endpoint: str) -> bool  # lines 77-127
limit(self, requests_per_minute: int, per_user: bool) -> Callable  # lines 129-177
```

**Transaction Safety**:
- `record_request()`: BEGIN IMMEDIATE (line 96)

### Utility Classes

#### EncryptionService
**File**: `utils/encryption.py` (lines 16-133)

**Attributes**:
- `cipher: Fernet` (line 35)

**Methods**:
```python
__init__(self, encryption_key: bytes) -> None  # lines 22-35
_derive_key(self, password: bytes) -> bytes  # lines 37-86
encrypt(self, plaintext: str) -> str  # lines 88-102
decrypt(self, ciphertext: str) -> str  # lines 104-122
generate_key() -> str  # static, lines 124-132
```

**PBKDF2 Parameters** (line 78-83):
- Algorithm: SHA-256
- Length: 32 bytes
- Iterations: 100,000
- Salt: From ENCRYPTION_SALT env var

#### PasswordValidator
**File**: `utils/validators.py` (lines 9-98)

**Class Attributes**:
- `MIN_LENGTH: int = 12` (line 15)
- `MAX_LENGTH: int = 128` (line 16)
- `COMMON_PASSWORDS: Set[str]` (lines 19-25)

**Methods**:
```python
validate(cls, password: str) -> Tuple[bool, str]  # classmethod, lines 27-62
check_breach(cls, password: str) -> Tuple[bool, int]  # classmethod, lines 64-97
```

**HIBP Integration** (lines 76-93):
- API: haveibeenpwned.com
- K-anonymity: SHA-1 prefix (5 chars)
- Timeout: 2 seconds

#### EmailValidator
**File**: `utils/validators.py` (lines 100-133)

**Class Attributes**:
- `EMAIL_REGEX: Pattern` (lines 104-106)

**Methods**:
```python
validate(cls, email: str) -> Tuple[bool, str]  # classmethod, lines 108-132
```

#### UsernameValidator
**File**: `utils/validators.py` (lines 135-166)

**Class Attributes**:
- `MIN_LENGTH: int = 3` (line 138)
- `MAX_LENGTH: int = 30` (line 139)
- `USERNAME_REGEX: Pattern` (line 140)

**Methods**:
```python
validate(cls, username: str) -> Tuple[bool, str]  # classmethod, lines 142-165
```

#### ReCaptchaService
**File**: `utils/recaptcha.py` (lines 10-126)

**Attributes**:
- `secret_key: str` (line 19)
- `site_key: str` (line 20)
- `verify_url: str` (line 21)
- `enabled: bool` (line 22)

**Methods**:
```python
__init__(self) -> None  # lines 17-22
get_site_key(self) -> str  # lines 24-30
is_enabled(self) -> bool  # lines 32-40
verify_response(self, recaptcha_response: str) -> Tuple[bool, str]  # lines 42-96
_translate_error_codes(self, error_codes: List[str]) -> str  # lines 98-125
```

---

## 6. SEQUENCE DIAGRAMS GROUND TRUTH

### 6.1 OAuth2 Authorization Code Flow with PKCE

**Participants**:
1. Client Application
2. User Browser
3. Authorization Server (Flask app)
4. Resource Owner (User)
5. Database

**Step-by-Step with Evidence**:

#### Phase 1: Authorization Request
**File**: `routes/oauth_routes.py`

1. **Client generates PKCE parameters** (Client-side, RFC 7636):
   ```
   code_verifier = random(43-128 chars)
   code_challenge = BASE64URL(SHA256(code_verifier))
   code_challenge_method = "S256"
   ```

2. **Client redirects to /oauth/authorize** (line 28):
   ```
   GET /oauth/authorize?
     client_id=CLIENT_ID
     &redirect_uri=REDIRECT_URI
     &response_type=code
     &scope=profile email
     &state=RANDOM_STATE
     &code_challenge=CHALLENGE
     &code_challenge_method=S256
   ```

3. **Server validates client** (lines 46-51):
   - `oauth2_service.get_client(client_id)` → oauth2_service.py:39-45
   - Query: `SELECT * FROM oauth2_clients WHERE client_id = ?`

4. **Server validates redirect_uri** (lines 54-55):
   - `oauth2_service.validate_redirect_uri(client_id, redirect_uri)` → oauth2_service.py:76-96
   - EXACT string match only (line 96)

5. **Server validates PKCE** (lines 62-63):
   - If no code_challenge: Return error 'code_challenge required'

6. **Server checks authentication** (lines 66-70):
   - If `'user_id' not in session`: Save return URL, redirect to /login

7. **User logs in** → See section 6.2

8. **Server shows consent screen** (lines 83-85):
   - Template: `oauth/authorize.html`
   - Displays: client name, requested scope

#### Phase 2: User Consent
**File**: `routes/oauth_routes.py`

9. **User approves** (line 88):
   - POST /oauth/authorize with `approved=yes`

10. **Server generates authorization code** (lines 102-109):
    - `oauth2_service.generate_authorization_code()` → oauth2_service.py:124-159
    - Code: `secrets.token_urlsafe(32)` (line 141)
    - Expires: 10 minutes (line 144)
    - INSERT query (lines 148-154):
      ```sql
      INSERT INTO oauth2_authorization_codes
      (code, client_id, user_id, redirect_uri, scope,
       code_challenge, code_challenge_method, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ```

11. **Server logs event** (lines 112-118):
    - `security_service.log_security_event('oauth_authorization_granted')`

12. **Server redirects to client** (lines 121-122):
    ```
    HTTP 302 REDIRECT_URI?code=AUTH_CODE&state=STATE
    ```

#### Phase 3: Token Exchange
**File**: `routes/oauth_routes.py`

13. **Client requests token** (line 124):
    ```
    POST /oauth/token
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code
    &code=AUTH_CODE
    &redirect_uri=REDIRECT_URI
    &client_id=CLIENT_ID
    &client_secret=CLIENT_SECRET
    &code_verifier=CODE_VERIFIER
    ```

14. **Server validates client** (lines 142-144):
    - `oauth2_service.validate_client(client_id, client_secret)` → oauth2_service.py:48-74
    - Check: `check_password_hash(client_secret_hash, client_secret)` (line 71)

15. **Server validates authorization code** (lines 147-149):
    - `oauth2_service.validate_authorization_code(code, client_id)` → oauth2_service.py:161-209
    - **CRITICAL TRANSACTION** (line 178):
      ```sql
      BEGIN IMMEDIATE  -- Write lock to prevent concurrent use
      SELECT * FROM oauth2_authorization_codes
      WHERE code = ? AND client_id = ? AND used = 0
      ```
    - Check expiration (line 191)
    - Mark as used (lines 197-199):
      ```sql
      UPDATE oauth2_authorization_codes SET used = 1 WHERE code = ?
      ```
    - COMMIT (line 200)

16. **Server validates redirect_uri match** (lines 152-153):
    - If `auth_code['redirect_uri'] != redirect_uri`: Error

17. **Server validates PKCE** (lines 159-164):
    - `oauth2_service.validate_pkce(code_verifier, code_challenge, method)` → oauth2_service.py:98-122
    - Compute: `SHA256(code_verifier)` → Base64URL encode (lines 112-114)
    - Compare: `computed_challenge == code_challenge` (line 116)

18. **Server generates tokens** (lines 167-171):
    - `oauth2_service.generate_tokens(client_id, user_id, scope)` → oauth2_service.py:211-259
    - Generate: `access_token`, `refresh_token`, `token_family_id` (lines 225-227)
    - Insert (lines 238-246):
      ```sql
      INSERT INTO oauth2_tokens
      (access_token, refresh_token, token_type, client_id, user_id,
       scope, token_family_id, issued_at, expires_in,
       refresh_token_expires_at)
      VALUES (?, ?, 'Bearer', ?, ?, ?, ?, ?, ?, ?)
      ```

19. **Server returns token response** (line 182):
    ```json
    {
      "access_token": "...",
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": "...",
      "scope": "profile email"
    }
    ```

#### Phase 4: Access Protected Resource
**File**: `routes/oauth_routes.py`

20. **Client requests userinfo** (line 214):
    ```
    GET /oauth/userinfo
    Authorization: Bearer ACCESS_TOKEN
    ```

21. **Server validates access token** (lines 229-232):
    - `oauth2_service.validate_access_token(access_token)` → oauth2_service.py:261-288
    - Query (lines 273-275):
      ```sql
      SELECT * FROM oauth2_tokens WHERE access_token = ? AND revoked = 0
      ```
    - Check expiration: `expires_at < int(time.time())` (line 283)

22. **Server returns user info** (lines 235-239):
    - `oauth2_service.get_user_info(user_id)` → oauth2_service.py:418-444
    - Response:
      ```json
      {
        "sub": "USER_ID",
        "username": "USERNAME",
        "email": "EMAIL"
      }
      ```

#### Phase 5: Token Refresh
**File**: `routes/oauth_routes.py`

23. **Client refreshes token** (line 184):
    ```
    POST /oauth/token

    grant_type=refresh_token
    &refresh_token=REFRESH_TOKEN
    &client_id=CLIENT_ID
    &client_secret=CLIENT_SECRET
    ```

24. **Server validates client** (lines 191-193)

25. **Server refreshes token** (lines 196):
    - `oauth2_service.refresh_access_token(refresh_token, client_id)` → oauth2_service.py:290-364
    - **CRITICAL TRANSACTION** (line 307):
      ```sql
      BEGIN IMMEDIATE
      SELECT * FROM oauth2_tokens
      WHERE refresh_token = ? AND client_id = ? AND revoked = 0
      ```
    - **REUSE DETECTION** (lines 320-325):
      ```python
      if token['refresh_token_used']:
          # Token was already used once - this is a reuse attack
          self._revoke_token_family(token['token_family_id'])
          return False, "Token reuse detected - all tokens revoked"
      ```
    - Mark old token as used (lines 334-338):
      ```sql
      UPDATE oauth2_tokens SET refresh_token_used = 1 WHERE id = ?
      ```
    - Generate new tokens (lines 341-346): Same token_family_id
    - COMMIT (line 355)

26. **Server returns new tokens** (line 207)

---

### 6.2 Password + 2FA Authentication Flow

**Participants**:
1. User Browser
2. Flask App (auth_bp)
3. AuthService
4. SecurityService
5. TOTPService
6. Database

**Step-by-Step with Evidence**:

#### Phase 1: Password Authentication
**File**: `routes/auth_routes.py`

1. **User submits credentials** (line 59):
   ```
   POST /login
   username=USER&password=PASS
   ```

2. **Rate limit check** (line 60):
   - `@rate_limiter.limit(requests_per_minute=5, per_user=True)`
   - rate_limiter.py:129-177
   - Key: `user:USERNAME` (line 147)
   - Check: `is_rate_limited(key, '/login')` (line 154)
   - If limited: Return 429 (lines 157-162)

3. **Input validation** (lines 64-69):
   - Check username and password present

4. **Check account lockout** (lines 72-75):
   - `security_service.check_account_lockout(username)` → security_service.py:104-133
   - Query (lines 116-119):
     ```sql
     SELECT * FROM account_lockouts
     WHERE username = ? AND locked_until > ?
     ```
   - If locked: Return remaining time (lines 124-130)

5. **Check CAPTCHA requirement** (lines 78-94):
   - `security_service.requires_captcha(username)` → security_service.py:247-258
   - Threshold: 3 failures (line 18)
   - If required:
     - `recaptcha_service.verify_response()` → recaptcha.py:42-96
     - POST to Google API (lines 79-83)
     - If invalid: Log event, return error (lines 84-94)

6. **Authenticate** (line 97):
   - `auth_service.authenticate(username, password)` → auth_service.py:97-159
   - Query (lines 110-113):
     ```sql
     SELECT * FROM users WHERE username = ?
     ```
   - **Argon2id verification** (line 119):
     ```python
     self.hasher.verify(user['password'], password)
     ```
   - **Timing-safe failure** (lines 141-156): Dummy hash operation
   - **Password rehash check** (lines 122-128): Update if params changed
   - **Update last_login** (lines 131-135)

7. **Log login attempt** (lines 100-106):
   - `security_service.log_login_attempt()` → security_service.py:63-102
   - Insert (lines 80-89):
     ```sql
     INSERT INTO login_attempts
     (username, ip_address, user_agent, success, failure_reason, timestamp)
     VALUES (?, ?, ?, ?, ?, ?)
     ```

8. **On success** (lines 108-129):
   - Clear lockout (line 112): `security_service.clear_account_lockout(username)`
   - **SESSION REGENERATION #1** (line 116):
     - `regenerate_session()` → decorators.py:23-53
     - Save session data (line 44)
     - Clear session (line 47)
     - Restore with new ID (line 50)
   - Check 2FA enabled (line 119): `user.get('totp_enabled')`

9. **If 2FA enabled** (lines 121-123):
   - Store pending login:
     ```python
     session['pending_2fa_user_id'] = user['id']
     session['pending_2fa_username'] = user['username']
     ```
   - Redirect to /verify-2fa

10. **If no 2FA** (lines 126-129):
    - Complete login:
      ```python
      session['user_id'] = user['id']
      session['username'] = user['username']
      ```
    - Redirect to home

11. **On failure** (lines 130-144):
    - Count recent failures (line 132): `security_service.get_recent_failures(username)`
    - If threshold reached (line 134):
      - Apply lockout (line 136): `security_service.apply_account_lockout(username, failures)`
        - **TRANSACTION** (security_service.py:178): BEGIN IMMEDIATE
        - Insert/update (lines 187-197):
          ```sql
          INSERT INTO account_lockouts
          (username, locked_until, failed_attempts, lockout_reason)
          VALUES (?, ?, ?, 'too_many_failures')
          ```
        - Log critical event (lines 203-208)
    - Show remaining attempts (lines 139-140)

#### Phase 2: 2FA Verification
**File**: `routes/twofa_routes.py`

12. **User enters TOTP code** (line 82):
    ```
    POST /verify-2fa
    code=123456
    ```

13. **Rate limit check** (line 83):
    - `@rate_limiter.limit(requests_per_minute=5, per_user=False)`
    - Key: `ip:IP_ADDRESS` (line 149)

14. **Check pending state** (lines 86-88):
    - Verify `'pending_2fa_user_id' in session`

15. **Get pending info** (lines 94-95):
    ```python
    user_id = session['pending_2fa_user_id']
    username = session['pending_2fa_username']
    ```

16. **Verify TOTP** (line 126):
    - `totp_service.verify_totp(user_id, code)` → totp_service.py:130-177
    - Get user (lines 142-146):
      ```sql
      SELECT * FROM users WHERE id = ?
      ```
    - Decrypt secret (lines 152-153):
      - `encryption.decrypt(encrypted_secret)`
      - Uses Fernet (AES-128 CBC + HMAC)
    - **REPLAY PREVENTION** (lines 159-163):
      ```python
      current_window = int(datetime.utcnow().timestamp() // 30)
      cache_key = f"{user_id}:{code}:{current_window}"
      if cache_key in self.used_codes_cache:
          return False, "Code already used"
      ```
    - **TOTP verification** (lines 166-168):
      ```python
      totp = pyotp.TOTP(secret)
      if totp.verify(code, valid_window=1):  # ±30 seconds
      ```
    - Mark code as used (line 170): `used_codes_cache[cache_key] = True`
    - Cleanup old entries (line 173): `_cleanup_used_codes(current_window)`

17. **On success** (lines 128-147):
    - Clean pending session (lines 131-133):
      ```python
      session.pop('pending_2fa_user_id')
      session.pop('pending_2fa_username')
      ```
    - **SESSION REGENERATION #2** (line 133):
      - `regenerate_session()` - SECOND regeneration point
    - Complete login (lines 136-137):
      ```python
      session['user_id'] = user_id
      session['username'] = username
      ```
    - Log event (lines 139-144):
      ```python
      security_service.log_security_event('2fa_verified', ...)
      ```
    - Redirect to home (line 147)

18. **Backup code path** (lines 97-123):
    - If `use_backup == 'true'` (line 92)
    - Verify backup code (line 99):
      - `totp_service.verify_backup_code(user_id, code)` → totp_service.py:179-220
      - Hash provided code (line 201): `hashlib.sha256(code.encode()).hexdigest()`
      - Load stored hashes (line 204): `json.loads(user['backup_codes'])`
      - Check and remove (lines 206-208)
      - Update database (lines 211-214):
        ```sql
        UPDATE users SET backup_codes = ? WHERE id = ?
        ```
    - Same session cleanup and regeneration (lines 104-110)
    - Log with remaining count (lines 112-118)

---

### 6.3 Brute Force Protection Flow

**Participants**:
1. Attacker Browser
2. Flask App
3. RateLimiter
4. SecurityService
5. ReCaptchaService
6. Database

**Step-by-Step with Evidence**:

#### Layer 1: Per-IP Rate Limiting
**File**: `services/rate_limiter.py`

1. **Request arrives** at protected endpoint

2. **Decorator checks rate** (lines 144-174):
   - Determine key (lines 146-149):
     - Per-user: `user:USERNAME` (if username in form)
     - Per-IP: `ip:IP_ADDRESS` (default)
   - Check limit (line 154):
     - `is_rate_limited(key, endpoint)` → lines 28-75
     - Count recent requests (lines 51-56):
       ```sql
       SELECT SUM(request_count) as total
       FROM rate_limits
       WHERE key = ? AND endpoint = ? AND window_end > ?
       ```
     - If `total >= requests_per_minute` (line 59):
       - Return 429 (lines 157-162):
         ```json
         {
           "error": "Rate limit exceeded",
           "retry_after": SECONDS
         }
         ```

3. **Record request** (line 165):
   - `record_request(key, endpoint)` → lines 77-127
   - **TRANSACTION** (line 96): BEGIN IMMEDIATE
   - Try to increment existing window (lines 99-110)
   - Or create new window (lines 112-117):
     ```sql
     INSERT INTO rate_limits
     (key, endpoint, request_count, window_start, window_end)
     VALUES (?, ?, 1, ?, ?)
     ```

#### Layer 2: Per-Account Failure Tracking
**File**: `services/security_service.py`

4. **Login fails** (line 97): `auth_service.authenticate()` returns False

5. **Count recent failures** (line 132):
   - `get_recent_failures(username)` → lines 135-157
   - Window: 15 minutes (LOCKOUT_DURATION)
   - Query (lines 151-154):
     ```sql
     SELECT COUNT(*) as count FROM login_attempts
     WHERE username = ? AND success = 0 AND timestamp >= ?
     ```

6. **Check threshold** (line 134):
   - `if failures >= LOCKOUT_THRESHOLD` (3 failures)

7. **Apply lockout** (line 136):
   - `apply_account_lockout(username, failures)` → lines 159-217
   - **TRANSACTION** (line 178): BEGIN IMMEDIATE
   - Calculate lock time (line 172): `locked_until = now + 15 minutes`
   - Insert/update (lines 187-197):
     ```sql
     INSERT INTO account_lockouts
     (username, locked_until, failed_attempts, lockout_reason)
     VALUES (?, ?, ?, 'too_many_failures')
     ```
   - Log critical event (lines 203-208)

8. **Return lockout message** (line 137):
   - "Account locked for 15 minutes"

#### Layer 3: CAPTCHA Challenge
**File**: `routes/auth_routes.py` + `utils/recaptcha.py`

9. **Check CAPTCHA requirement** (line 78):
   - `requires_captcha(username)` → security_service.py:247-258
   - `failures >= CAPTCHA_THRESHOLD` (3 failures)

10. **Show CAPTCHA** (lines 92-94):
    - Template includes reCAPTCHA widget
    - Site key from: `recaptcha_service.get_site_key()` (line 48)

11. **User solves CAPTCHA**

12. **Verify CAPTCHA** (lines 81-94):
    - `recaptcha_service.verify_response()` → recaptcha.py:42-96
    - Extract token (lines 65-69): `request.form.get('g-recaptcha-response')`
    - Verify with Google (lines 79-83):
      ```python
      POST https://www.google.com/recaptcha/api/siteverify
      {
        'secret': SECRET_KEY,
        'response': TOKEN,
        'remoteip': IP
      }
      ```
    - Check result (lines 87-92)

13. **On CAPTCHA failure** (lines 84-94):
    - Log event (lines 85-91): `log_security_event('captcha_failed')`
    - Show error (line 84)
    - Re-show CAPTCHA (lines 92-94)

14. **On CAPTCHA success**:
    - Allow login attempt to proceed

#### Attack Prevention Summary

**SQL Injection**: Parameterized queries throughout
- Example: auth_service.py:110-113

**Timing Attacks**: Constant-time verification
- auth_service.py:141-156 (dummy hash operations)

**Session Fixation**: Session regeneration
- decorators.py:23-53 (called at auth_routes.py:116, twofa_routes.py:133)

**CSRF**: Flask-WTF CSRFProtect
- app_auth.py:29

**XSS**: Content Security Policy
- security_headers.py:24-32

---

## 7. SECURITY CONTROLS MAPPING

### 7.1 PREVENT Controls

| Control | Implementation | File:Line | Description |
|---------|----------------|-----------|-------------|
| **Argon2id** | PasswordHasher | auth_service.py:22-28 | OWASP-recommended password hashing |
| **PKCE** | S256 validation | oauth2_service.py:110-116 | SHA-256 code challenge |
| **TOTP** | pyotp verify | totp_service.py:166-168 | RFC 6238 time-based OTP |
| **Encryption** | Fernet (AES-128) | encryption.py:35 | TOTP secret encryption |
| **PBKDF2** | Key derivation | encryption.py:78-85 | 100k iterations, SHA-256 |
| **CSP** | Security headers | security_headers.py:24-32 | Restrict script sources |
| **HSTS** | Security headers | security_headers.py:36 | Force HTTPS |
| **CSRF** | Flask-WTF | app_auth.py:29 | Token validation |
| **Rate Limiting** | Database-backed | rate_limiter.py:11-178 | 5 req/min default |
| **Account Lockout** | After 3 failures | security_service.py:159-217 | 15-minute lockout |
| **CAPTCHA** | reCAPTCHA v2 | recaptcha.py:42-96 | After 3 failures |
| **Session Security** | Cookie flags | app_auth.py:24-26 | Secure, HttpOnly, SameSite |
| **Input Validation** | Validators | validators.py:9-166 | Username, email, password |
| **HIBP Check** | API integration | validators.py:64-97 | Password breach detection |
| **Transaction Safety** | BEGIN IMMEDIATE | oauth2_service.py:178, 307 | Prevent race conditions |

### 7.2 DETECT Controls

| Control | Implementation | File:Line | Description |
|---------|----------------|-----------|-------------|
| **Login Attempts** | Tracking table | database_auth.py:87-108 | All attempts logged |
| **Security Events** | Audit log | database_auth.py:153-175 | Centralized event logging |
| **Replay Prevention** | Code cache | totp_service.py:159-173 | 30-second window tracking |
| **Token Reuse** | refresh_token_used flag | oauth2_service.py:320-325 | Detect refresh token reuse |
| **Failure Counting** | Time-windowed query | security_service.py:135-157 | 15-minute window |
| **CAPTCHA Failure** | Event logging | auth_routes.py:85-91 | Log CAPTCHA failures |

### 7.3 RESPOND Controls

| Control | Implementation | File:Line | Description |
|---------|----------------|-----------|-------------|
| **Token Family Revocation** | Revoke all tokens | oauth2_service.py:397-416 | On reuse detection |
| **Account Lockout** | 15-minute lock | security_service.py:159-217 | After threshold |
| **Rate Limit 429** | HTTP 429 response | rate_limiter.py:157-162 | Too many requests |
| **Session Regeneration** | New session ID | decorators.py:23-53 | After auth events |
| **Lockout Clearing** | On success | security_service.py:219-245 | Clear failed attempts |
| **Backup Code Removal** | One-time use | totp_service.py:208 | Remove after use |

---

## 8. DATA FLOW PATHS

### 8.1 HTTP Request → Response Flow

```
1. HTTP Request (TLS terminated at server/proxy)
   ↓
2. Flask App (app_auth.py:20)
   ↓
3. Security Headers Middleware (app_auth.py:53-56)
   → set_security_headers() (security_headers.py:7-37)
   ↓
4. CSRF Protection (app_auth.py:29)
   → CSRFProtect checks token
   ↓
5. Blueprint Routing (app_auth.py:36-38)
   → auth_bp, oauth_bp, twofa_bp
   ↓
6. Rate Limiter Decorator (routes/auth_routes.py:60)
   → @rate_limiter.limit()
   → BEGIN IMMEDIATE transaction (rate_limiter.py:96)
   ↓
7. Route Handler Function
   → Service layer calls
   ↓
8. Service Layer
   → Database queries (parameterized)
   → External API calls (HIBP, reCAPTCHA)
   ↓
9. Database (SQLite)
   → Transactional safety (BEGIN IMMEDIATE)
   ↓
10. Response with Security Headers
    → CSP, HSTS, X-Frame-Options, etc.
    ↓
11. HTTP Response
```

### 8.2 Authentication Data Flow

```
Password Registration:
Browser → Flask → AuthService.register_user()
  → PasswordValidator.validate()
  → PasswordValidator.check_breach() [HIBP API]
  → Argon2id.hash()
  → Database INSERT users
  → SecurityService.log_security_event()

Password Login:
Browser → Flask → RateLimiter
  → SecurityService.check_account_lockout()
  → SecurityService.requires_captcha()
  → ReCaptchaService.verify_response() [Google API]
  → AuthService.authenticate()
    → Argon2id.verify() [timing-safe]
    → UPDATE users.last_login
  → SecurityService.log_login_attempt()
  → regenerate_session() [session fixation prevention]
  → Check totp_enabled
    → If true: Store pending_2fa_user_id
    → If false: Set session user_id

2FA Verification:
Browser → Flask → RateLimiter
  → TOTPService.verify_totp()
    → EncryptionService.decrypt(totp_secret)
    → pyotp.TOTP.verify()
    → Replay prevention cache check
    → Mark code as used in cache
  → regenerate_session() [second regeneration]
  → Set session user_id
  → SecurityService.log_security_event('2fa_verified')
```

### 8.3 OAuth2 Token Flow

```
Authorization Code Generation:
Browser → /oauth/authorize [GET]
  → OAuth2Service.get_client()
  → OAuth2Service.validate_redirect_uri() [exact match]
  → Check PKCE code_challenge present
  → Check user authenticated
  → Show consent screen
Browser → /oauth/authorize [POST]
  → OAuth2Service.generate_authorization_code()
    → secrets.token_urlsafe(32)
    → BEGIN transaction
    → INSERT oauth2_authorization_codes
    → COMMIT

Token Exchange:
Client → /oauth/token [POST]
  → OAuth2Service.validate_client()
  → OAuth2Service.validate_authorization_code()
    → BEGIN IMMEDIATE [CRITICAL]
    → SELECT ... WHERE used = 0
    → UPDATE used = 1
    → COMMIT
  → OAuth2Service.validate_pkce()
    → SHA256(code_verifier) == code_challenge
  → OAuth2Service.generate_tokens()
    → secrets.token_urlsafe() for access & refresh
    → INSERT oauth2_tokens with token_family_id
    → Return JSON response

Token Refresh:
Client → /oauth/token [POST, grant_type=refresh_token]
  → OAuth2Service.validate_client()
  → OAuth2Service.refresh_access_token()
    → BEGIN IMMEDIATE [CRITICAL]
    → SELECT ... WHERE refresh_token = ?
    → Check refresh_token_used flag
      → If used: REVOKE ENTIRE FAMILY [reuse attack]
      → If not: Mark used, generate new tokens
    → UPDATE refresh_token_used = 1
    → INSERT new tokens with same token_family_id
    → COMMIT
```

---

## 9. TRANSACTION SAFETY LOCATIONS

**All BEGIN IMMEDIATE transactions for race condition prevention:**

| Location | File:Line | Purpose |
|----------|-----------|---------|
| Authorization code validation | oauth2_service.py:178 | Prevent code reuse |
| Refresh token rotation | oauth2_service.py:307 | Prevent token reuse |
| Account lockout application | security_service.py:178 | Prevent concurrent lockouts |
| Rate limit recording | rate_limiter.py:96 | Prevent TOCTOU races |

**Why BEGIN IMMEDIATE?**
- Standard BEGIN uses deferred locking (read lock first, upgrade to write)
- Concurrent writes can cause "database is locked" errors
- BEGIN IMMEDIATE acquires write lock immediately
- Prevents race conditions in high-concurrency scenarios

---

## 10. CONFIGURATION VALUES

### Environment Variables Required
**File**: `.env` (referenced throughout)

```
SECRET_KEY=<flask session encryption key>
ENCRYPTION_SALT=<32+ char hex string for PBKDF2>

# reCAPTCHA (optional)
RECAPTCHA_SITE_KEY=<google site key>
RECAPTCHA_SECRET_KEY=<google secret key>

# Database
DATABASE=recipe_app.db  # Default
```

### Security Thresholds

| Parameter | Value | File:Line |
|-----------|-------|-----------|
| Login rate limit | 5/min per-user | auth_routes.py:60 |
| 2FA setup rate limit | 5/min per-user | twofa_routes.py:21 |
| 2FA verify rate limit | 5/min per-IP | twofa_routes.py:83 |
| Lockout threshold | 3 failures | security_service.py:16 |
| Lockout duration | 15 minutes | security_service.py:17 |
| CAPTCHA threshold | 3 failures | security_service.py:18 |
| Password min length | 12 chars | validators.py:15 |
| Password max length | 128 chars | validators.py:16 |
| Access token lifetime | 3600 sec (1 hour) | oauth2_service.py:21 |
| Refresh token lifetime | 2592000 sec (30 days) | oauth2_service.py:22 |
| Auth code lifetime | 600 sec (10 min) | oauth2_service.py:23 |
| TOTP window | ±1 (±30 sec) | totp_service.py:168 |
| Backup codes | 10 codes | totp_service.py:90 |
| Argon2id time_cost | 2 iterations | auth_service.py:23 |
| Argon2id memory_cost | 19456 KiB (19 MiB) | auth_service.py:24 |
| PBKDF2 iterations | 100,000 | encryption.py:82 |

---

## 11. EXTERNAL DEPENDENCIES

| Service | Purpose | API Endpoint | File:Line |
|---------|---------|--------------|-----------|
| HIBP | Password breach check | https://api.pwnedpasswords.com/range/{prefix} | validators.py:82-84 |
| Google reCAPTCHA | Bot prevention | https://www.google.com/recaptcha/api/siteverify | recaptcha.py:21 |

---

## 12. ROUTE SUMMARY TABLE

| Route | Method | File:Line | Rate Limit | Auth Required | CSRF | 2FA Impact |
|-------|--------|-----------|------------|---------------|------|-----------|
| `/register` | GET/POST | auth_routes.py:20-57 | None | No | Yes | - |
| `/login` | GET/POST | auth_routes.py:59-146 | 5/min user | No | Yes | Redirects to verify |
| `/logout` | GET | auth_routes.py:148-163 | None | No | Yes | - |
| `/change-password` | GET/POST | auth_routes.py:165-202 | None | Yes | Yes | - |
| `/security-settings` | GET | auth_routes.py:204-218 | None | Yes | Yes | - |
| `/setup-2fa` | GET/POST | twofa_routes.py:20-80 | 5/min user | Yes | Yes | Enables 2FA |
| `/verify-2fa` | GET/POST | twofa_routes.py:82-153 | 5/min IP | Pending | Yes | Completes login |
| `/backup-codes` | GET | twofa_routes.py:155-168 | None | Yes | Yes | One-time display |
| `/disable-2fa` | GET/POST | twofa_routes.py:170-206 | 3/min user | Yes | Yes | Disables 2FA |
| `/oauth/authorize` | GET/POST | oauth_routes.py:28-122 | None | Yes | Yes | - |
| `/oauth/token` | POST | oauth_routes.py:124-212 | None | No | **Exempt** | - |
| `/oauth/userinfo` | GET | oauth_routes.py:214-240 | None | Token | Yes | - |
| `/oauth/revoke` | POST | oauth_routes.py:242-273 | None | No | **Exempt** | - |

---

## 13. FILE DEPENDENCY GRAPH

```
app_auth.py
├── database.py (init_database)
├── database_auth.py (initialize_auth_database)
├── routes/
│   ├── auth_routes.py
│   │   ├── services/auth_service.py
│   │   ├── services/security_service.py
│   │   ├── services/rate_limiter.py
│   │   └── utils/recaptcha.py
│   ├── oauth_routes.py
│   │   ├── services/oauth2_service.py
│   │   └── services/security_service.py
│   └── twofa_routes.py
│       ├── services/totp_service.py
│       ├── services/security_service.py
│       ├── services/auth_service.py
│       └── services/rate_limiter.py
├── services/
│   ├── auth_service.py
│   │   ├── argon2 (PasswordHasher)
│   │   └── utils/validators.py
│   ├── oauth2_service.py
│   │   └── database.py
│   ├── totp_service.py
│   │   ├── pyotp
│   │   ├── qrcode
│   │   └── utils/encryption.py
│   ├── security_service.py
│   │   └── database.py
│   └── rate_limiter.py
│       └── database.py
└── utils/
    ├── decorators.py
    ├── security_headers.py
    ├── encryption.py
    │   └── cryptography.fernet
    ├── validators.py
    │   └── requests (HIBP API)
    ├── recaptcha.py
    │   └── requests (Google API)
    └── sanitization.py
```

---

## END OF GROUND TRUTH SPECIFICATION

**Total Lines Analyzed**: ~4,000 lines of Python code
**Total Tables**: 9
**Total Indexes**: 15
**Total Routes**: 13
**Total Service Classes**: 5
**Total Utility Classes**: 6
**Total Transactions**: 4 critical BEGIN IMMEDIATE locations
**External APIs**: 2 (HIBP, reCAPTCHA)

This document provides complete file:line evidence for generating all required UML diagrams:
- System Architecture Diagram
- Class Diagram
- OAuth2 Sequence Diagram
- 2FA Sequence Diagram
- Database Schema Diagram
- Brute Force Protection Flow Diagram
- Security Controls Layering Diagram
