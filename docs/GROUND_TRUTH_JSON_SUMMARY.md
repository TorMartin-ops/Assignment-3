# Ground Truth JSON Summary

**Source**: `/docs/ground_truth_index.json`
**Version**: 2.0
**Generated**: 2025-10-19
**Purpose**: Human-readable summary of the authoritative ground truth JSON specification

---

## Document Overview

The ground truth JSON (`ground_truth_index.json`) is a 1099-line comprehensive specification that serves as the single source of truth for all UML diagrams and documentation. Every claim, component, relationship, and security mechanism in the diagrams is traced directly to source code via this specification.

**Analysis Scope**:
- **Files Analyzed**: 18 Python source files
- **Analysis Approach**: Evidence-based with file:line references
- **Coverage**: Complete system (routes, services, utilities, database, core application)

---

## System Architecture Summary

### Components (8 total)

1. **Flask Application** (`app_auth.py:20`)
   - Main web framework
   - Security configurations (CSRF, session, headers)
   - Connects to: All 3 blueprints, CSRFProtect, both databases

2. **Authentication Blueprint** (`routes/auth_routes.py:12`)
   - Handles: Registration, login, logout, password changes
   - Dependencies: AuthService, SecurityService, RateLimiter, ReCaptchaService

3. **OAuth2 Blueprint** (`routes/oauth_routes.py:22`)
   - OAuth2 Authorization Code Flow with PKCE
   - 8 endpoints: authorize, token, refresh, revoke, userinfo
   - Dependencies: OAuth2Service, SecurityService

4. **2FA Blueprint** (`routes/twofa_routes.py:12`)
   - TOTP-based two-factor authentication
   - Dependencies: TOTPService, SecurityService, AuthService, RateLimiter

5. **Recipe Database** (`database.py:1`)
   - Original application database (separate from auth)

6. **Auth Database** (`database_auth.py:9`)
   - 9 tables: users, login_attempts, account_lockouts, rate_limits, security_events, oauth2_clients, oauth2_authorization_codes, oauth2_tokens, sessions
   - 102 total columns, 15 indexes, 8 foreign keys

7. **CSRF Protection** (`app_auth.py:29`)
   - Flask-WTF CSRF token protection
   - Applied to all state-changing requests

8. **Security Headers Middleware** (`app_auth.py:53`)
   - CSP, HSTS, X-Frame-Options, X-Content-Type-Options
   - Applied to all responses

### Trust Boundaries (3 total)

1. **Internet ↔ Application**
   - Controls: HTTPS, HSTS, CSP, CSRF tokens, Rate limiting

2. **Application ↔ Database**
   - Controls: Parameterized queries, Transaction isolation (BEGIN IMMEDIATE)

3. **OAuth2 Client ↔ Authorization Server**
   - Controls: PKCE (mandatory S256), Client authentication, Redirect URI validation (exact match)

### External Services (2 total)

1. **Google reCAPTCHA** (`utils/recaptcha.py:10`)
   - Triggered after 3 failed login attempts
   - API: `https://www.google.com/recaptcha/api/siteverify`

2. **HaveIBeenPwned API** (`utils/validators.py:82`)
   - Password breach detection with k-anonymity model
   - API: `https://api.pwnedpasswords.com/range/{prefix}`

---

## Database Schema Summary

### Tables Overview

**Total**: 9 tables
**Total Columns**: 102
**Total Indexes**: 15 (including UNIQUE constraints)
**Total Foreign Keys**: 8 (all with ON DELETE CASCADE)

### Table Details

1. **users** (`database_auth.py:22`) - 14 columns
   - Primary key, username/email (UNIQUE), password (Argon2id)
   - TOTP fields: totp_secret (Fernet encrypted), totp_enabled, backup_codes (SHA-256 JSON)
   - OAuth fields: oauth_provider, oauth_user_id, oauth_linked

2. **login_attempts** (`database_auth.py:87`) - 7 columns
   - Tracks all login attempts (success/failure)
   - Indexes: username+timestamp, ip_address+timestamp (2 indexes)

3. **account_lockouts** (`database_auth.py:113`) - 7 columns
   - Tracks account lockout state
   - Unique constraint on username
   - Index: locked_until (1 index)

4. **rate_limits** (`database_auth.py:133`) - 6 columns
   - Database-backed rate limiting (no Redis)
   - Composite UNIQUE: key + endpoint + window_start
   - Index: key+endpoint+window_end (1 index)

5. **security_events** (`database_auth.py:153`) - 9 columns
   - Audit log with severity levels
   - Indexes: event_type+timestamp, username+timestamp (2 indexes)

6. **oauth2_clients** (`database_auth.py:180`) - 14 columns
   - OAuth2 client registration
   - Includes: client_id, client_secret_hash, redirect_uris (JSON), require_pkce (default 1)
   - Foreign key: user_id → users(id) CASCADE
   - Index: client_id (1 index)

7. **oauth2_authorization_codes** (`database_auth.py:209`) - 11 columns
   - 10-minute lifetime authorization codes
   - PKCE fields: code_challenge, code_challenge_method
   - Single-use enforcement: used flag
   - Foreign keys: client_id → oauth2_clients, user_id → users (2 FKs)
   - Index: code (1 index)

8. **oauth2_tokens** (`database_auth.py:235`) - 14 columns
   - Access tokens (1 hour) and refresh tokens (30 days)
   - Token family tracking: token_family_id
   - Reuse detection: refresh_token_used flag
   - Foreign keys: client_id → oauth2_clients, user_id → users (2 FKs)
   - Indexes: access_token, refresh_token, token_family_id (3 indexes)

9. **sessions** (`database_auth.py:274`) - 11 columns
   - User session tracking
   - Includes: session_id, session_data, ip_address, user_agent, device_fingerprint
   - Foreign key: user_id → users(id) CASCADE
   - Indexes: session_id, user_id+is_active (2 indexes)

---

## OAuth2 Flow Summary

**Total Steps**: 8

### Step-by-Step Flow

1. **Authorization Request** (`oauth_routes.py:35`)
   - Security checks: 5 (client_id, redirect_uri exact match, response_type, PKCE code_challenge, user logged in)

2. **User Authorization** (`oauth_routes.py:83`)
   - Show consent screen with client name and scopes

3. **Authorization Grant** (`oauth_routes.py:88`)
   - User approves/denies
   - Generate secure authorization code
   - Store code_challenge for PKCE verification

4. **Token Request** (`oauth_routes.py:133`)
   - Validate client credentials
   - Validate authorization code (single-use, unexpired)
   - Validate PKCE: SHA256(code_verifier) == code_challenge
   - Mark code as used with BEGIN IMMEDIATE transaction

5. **Token Response** (`oauth_routes.py:166`)
   - Generate access token (1 hour expiration)
   - Generate refresh token (30 days expiration)
   - Create token family (token_family_id for rotation)

6. **Resource Access** (`oauth_routes.py:214`)
   - Validate Bearer token from Authorization header
   - Check not expired, not revoked
   - Return user info

7. **Token Refresh** (`oauth_routes.py:184`)
   - Validate client credentials
   - Check refresh token reuse (if reused → revoke entire family)
   - Mark old refresh token as used (not revoked)
   - Generate new tokens with same token_family_id
   - Use BEGIN IMMEDIATE transaction

8. **Token Revocation** (`oauth_routes.py:242`)
   - Validate client credentials
   - Mark token as revoked with timestamp
   - Return 200 even if token doesn't exist (RFC 7009)

### PKCE Implementation

- **Method**: S256 (SHA-256 hashing of code_verifier)
- **File**: `services/oauth2_service.py:98`
- **Enforcement**: Mandatory - code_challenge required in authorization request

### Token Lifecycle

- **Authorization Code**: 10 minutes (`oauth2_service.py:23`)
- **Access Token**: 1 hour / 3600 seconds (`oauth2_service.py:21`)
- **Refresh Token**: 30 days / 2592000 seconds (`oauth2_service.py:22`)

### Refresh Token Rotation

- **Strategy**: Token family rotation with reuse detection
- **Implementation**: `oauth2_service.py:290`
- **Token Family**: Each token belongs to token_family_id
- **Reuse Detection**: Old token marked as "used" (not "revoked")
- **Revocation**: If used token is reused → revoke entire family
- **Inheritance**: New tokens inherit same token_family_id

---

## 2FA Flow Summary

### Setup Steps (6 total)

1. **Initiate Setup** (`twofa_routes.py:73`) - Rate limited 5 req/min
2. **Generate Secret** (`totp_service.py:27`) - pyotp.random_base32()
3. **Generate QR Code** (`totp_service.py:36`) - Provisioning URI for authenticator apps
4. **Verify Setup** (`twofa_routes.py:34`) - User scans QR and submits code
5. **Enable 2FA** (`totp_service.py:75`) - Encrypt secret, generate backup codes
6. **Display Backup Codes** (`twofa_routes.py:64`) - Show 10 codes once

### Verification Steps (6 total)

1. **Password Authentication** (`auth_routes.py:97`) - Argon2id verification
2. **Check 2FA Enabled** (`auth_routes.py:119`)
3. **2FA Challenge** (`twofa_routes.py:82`) - Rate limited 5 req/min per IP
4. **Verify TOTP Code** (`totp_service.py:130`) - Decrypt, replay check, ±1 window
5. **Backup Code Alternative** (`totp_service.py:179`) - SHA-256 hash check, single-use
6. **Complete Login** (`twofa_routes.py:103`) - Session regeneration #2

### Session Regeneration Points (2 critical points)

1. **After Password Auth** (`auth_routes.py:116`) - Prevents session fixation #1
2. **After 2FA Verification** (`twofa_routes.py:106, 133`) - Prevents session fixation #2

### TOTP Details

- **Encryption**: Fernet (AES-128-CBC + HMAC) with PBKDF2 (100,000 iterations)
- **Replay Prevention**: In-memory cache with key `{user_id}:{code}:{window}`
- **Window Tolerance**: ±1 (±30 seconds)
- **Cleanup**: Old cache entries automatically removed

### Backup Codes

- **Format**: `XXXX-XXXX` (8 alphanumeric characters)
- **Count**: 10 codes generated
- **Storage**: SHA-256 hashed before database storage
- **Single-Use**: Removed from database after use

---

## Security Layers Summary

**Total Mechanisms**: 26 (14 Prevent + 6 Detect + 6 Respond)

### PREVENT Layer (14 mechanisms)

1. Argon2id Password Hashing (`auth_service.py:22`) - OWASP params t=2, m=19456, p=1
2. Password Validation (`validators.py:28`) - NIST SP 800-63B: 12-128 chars
3. Breach Detection (`validators.py:65`) - HaveIBeenPwned k-anonymity
4. CSRF Protection (`app_auth.py:29`) - Flask-WTF tokens
5. Content Security Policy (`security_headers.py:24`) - Strict CSP
6. XSS Prevention (`sanitization.py:8`) - Bleach library
7. Session Security (`app_auth.py:24`) - Secure, HttpOnly, SameSite=Lax
8. Session Fixation Prevention (`decorators.py:23`) - Regenerate after auth
9. TOTP Secret Encryption (`totp_service.py:87`) - Fernet + PBKDF2
10. PKCE for OAuth2 (`oauth2_service.py:98`) - Mandatory S256
11. Exact Redirect URI Matching (`oauth2_service.py:96`) - No wildcards
12. HSTS Header (`security_headers.py:36`) - 1 year max-age
13. X-Frame-Options (`security_headers.py:34`) - DENY
14. X-Content-Type-Options (`security_headers.py:33`) - nosniff

### DETECT Layer (6 mechanisms)

1. Login Attempt Tracking (`security_service.py:63`) - Timestamp, IP, user agent
2. Security Event Logging (`security_service.py:24`) - Audit log with severity
3. Failed Login Counting (`security_service.py:135`) - 15-minute window
4. TOTP Replay Detection (`totp_service.py:159`) - In-memory cache
5. Refresh Token Reuse Detection (`oauth2_service.py:320`) - Family revocation
6. Authorization Code Single-Use (`oauth2_service.py:197`) - Transaction-protected

### RESPOND Layer (6 mechanisms)

1. Account Lockout (`security_service.py:159`) - 3 failures → 15 min
2. CAPTCHA Challenge (`auth_routes.py:78`) - Google reCAPTCHA v2
3. Rate Limiting (`rate_limiter.py:28`) - 429 response
4. Token Family Revocation (`oauth2_service.py:397`) - Reuse → revoke all
5. Lockout Clearing (`security_service.py:219`) - After successful login
6. Backup Code Depletion Warning (`twofa_routes.py:120`) - Show remaining

---

## Brute Force Protection Summary

### Rate Limits (4 endpoints)

1. **Login**: 5 req/min per username (`auth_routes.py:60`)
2. **2FA Setup**: 5 req/min per user (`twofa_routes.py:21`)
3. **2FA Verify**: 5 req/min per IP (`twofa_routes.py:83`)
4. **2FA Disable**: 3 req/min per user (`twofa_routes.py:171`)

### Lockout Policy

- **Threshold**: 3 failed attempts (`security_service.py:16`)
- **Duration**: 15 minutes (`security_service.py:17`)
- **Implementation**: Account lockout with BEGIN IMMEDIATE (`security_service.py:178`)

### CAPTCHA Integration

- **Trigger**: 3 failed attempts (`security_service.py:18`)
- **Provider**: Google reCAPTCHA v2
- **Verification**: Server-side (`recaptcha.py:42`)

### Timing Attack Prevention

- **File**: `auth_service.py:141`
- **Method**: Dummy hash verification on invalid credentials
- **Purpose**: Consistent timing regardless of user existence

### Database Transaction Locks (BEGIN IMMEDIATE)

Used in 4 critical operations to prevent race conditions:

1. **Authorization code validation** (`oauth2_service.py:178`)
2. **Refresh token rotation** (`oauth2_service.py:307`)
3. **Rate limit recording** (`rate_limiter.py:96`)
4. **Account lockout** (`security_service.py:178`)

---

## Key Security Parameters

### Password Policy
- **Min Length**: 12 characters
- **Max Length**: 128 characters
- **Hashing**: Argon2id (time_cost=2, memory_cost=19456, parallelism=1)
- **Breach Check**: HaveIBeenPwned API with k-anonymity

### Lockout Settings
- **Threshold**: 3 failures
- **Duration**: 15 minutes
- **CAPTCHA Trigger**: 3 failures

### Rate Limiting
- **Login**: 5 requests/minute per username
- **2FA Verify**: 5 requests/minute per IP
- **2FA Setup**: 5 requests/minute per user
- **2FA Disable**: 3 requests/minute per user

### OAuth2 Token Lifetimes
- **Authorization Code**: 10 minutes
- **Access Token**: 1 hour (3600 seconds)
- **Refresh Token**: 30 days (2592000 seconds)

### 2FA Configuration
- **Algorithm**: TOTP (RFC 6238)
- **Window Tolerance**: ±1 (±30 seconds)
- **Secret Encryption**: Fernet (AES-128-CBC + HMAC)
- **Key Derivation**: PBKDF2 (100,000 iterations)
- **Backup Codes**: 10 codes, SHA-256 hashed, format `XXXX-XXXX`

### Session Security
- **Cookie Flags**: Secure, HttpOnly, SameSite=Lax
- **Regeneration**: After password auth, after 2FA verification
- **Session ID**: Regenerated to prevent fixation attacks

---

## Service Architecture Summary

### Core Services (6 total)

1. **AuthService** (`auth_service.py:13`)
   - 6 methods: __init__, register_user, authenticate, change_password, get_user_by_id, get_user_by_username
   - Argon2id hasher initialization (line 19)
   - Timing attack prevention with dummy hash (line 141)

2. **OAuth2Service** (`oauth2_service.py:14`)
   - 12 methods covering full OAuth2 flow
   - PKCE S256 validation (line 98)
   - Token rotation with family tracking (line 290)
   - Reuse detection and family revocation (line 320, 397)

3. **TOTPService** (`totp_service.py:16`)
   - 8 methods: __init__, generate_secret, generate_qr_code, enable_2fa, disable_2fa, verify_totp, verify_backup_code, helpers
   - Replay prevention with in-memory cache (line 159)
   - Fernet encryption for TOTP secrets (line 87)

4. **SecurityService** (`security_service.py:9`)
   - 8 methods: log_security_event, log_login_attempt, check_account_lockout, get_recent_failures, apply_account_lockout, clear_account_lockout, requires_captcha, get_login_statistics
   - Constants: LOCKOUT_THRESHOLD=3, LOCKOUT_DURATION=15 min, CAPTCHA_THRESHOLD=3

5. **RateLimiter** (`rate_limiter.py:11`)
   - 3 methods: __init__, is_rate_limited, record_request, limit decorator
   - Database-backed (no Redis)
   - BEGIN IMMEDIATE for race condition prevention (line 96)

6. **EncryptionService** (`encryption.py:16`)
   - 4 methods: __init__, _derive_key, encrypt, decrypt, generate_key
   - Fernet symmetric encryption
   - PBKDF2 key derivation (100,000 iterations, line 37)

### Utility Classes (6 total)

1. **PasswordValidator** (`validators.py:9`) - MIN_LENGTH=12, MAX_LENGTH=128
2. **EmailValidator** (`validators.py:100`) - Format validation
3. **UsernameValidator** (`validators.py:135`) - MIN_LENGTH=3, MAX_LENGTH=30
4. **ReCaptchaService** (`recaptcha.py:10`) - Google reCAPTCHA integration
5. **SecurityHeaders** (`security_headers.py:7`) - CSP, HSTS, X-Frame-Options
6. **Sanitization** (`sanitization.py:8`) - HTML sanitization with bleach

### Decorators (4 total)

1. **login_required** (`decorators.py:8`) - Check user_id in session
2. **regenerate_session** (`decorators.py:23`) - Prevent session fixation
3. **csrf_exempt** (`oauth_routes.py:14`) - OAuth2 endpoints
4. **rate_limiter.limit** (`rate_limiter.py:129`) - Route rate limiting

---

## Source File Coverage

**Total Files**: 18

**Routes** (3 files):
- routes/auth_routes.py
- routes/oauth_routes.py
- routes/twofa_routes.py

**Services** (5 files):
- services/auth_service.py
- services/oauth2_service.py
- services/totp_service.py
- services/security_service.py
- services/rate_limiter.py

**Utilities** (6 files):
- utils/validators.py
- utils/encryption.py
- utils/decorators.py
- utils/security_headers.py
- utils/sanitization.py
- utils/recaptcha.py

**Core** (3 files):
- app_auth.py
- database.py
- database_auth.py

**Config** (1 file):
- config files (referenced but not analyzed in detail)

---

## Diagram Coverage

The ground truth JSON supports the following diagrams:

1. **System Architecture** - Section: system_architecture
2. **Class Diagram (Services)** - Section: class_diagram
3. **OAuth2 Sequence** - Section: oauth2_flow
4. **Database ER** - Section: database_schema
5. **2FA Login Sequence** - Section: twofa_flow
6. **Brute Force Activity** - Section: brute_force_protection
7. **Security Layers** - Section: security_layers

**Additional diagrams suggested** (section: missing_diagrams):
- Rate Limiting Flow
- Session Management Lifecycle
- Encryption Service Architecture
- Security Event Audit Flow
- Password Validation Pipeline
- Account Lockout State Machine (created as #13)
- Token Family Rotation (created as #14)

---

## How to Use This Summary

**For Developers**:
- Locate implementation details with file:line references
- Understand security mechanisms and their locations
- Trace authentication flows step-by-step

**For Architects**:
- Review system components and trust boundaries
- Analyze service architecture and dependencies
- Evaluate security layer coverage

**For Security Reviewers**:
- Verify 26 security mechanisms with evidence
- Audit transaction safety (BEGIN IMMEDIATE locations)
- Validate defense-in-depth architecture

**For Diagram Creators**:
- Use file:line references for evidence-based diagrams
- Ensure semantic accuracy with ground truth
- Maintain consistency across all diagrams

---

## Related Documentation

**Full JSON Specification**: `/docs/ground_truth_index.json` (1099 lines)

**UML Diagrams**: `/diagrams/*.svg` (9 diagrams)

**Diagram Index**: `/diagrams/DIAGRAM_INDEX.md`

**Style Guide**: `/diagrams/sources/STYLEGUIDE.md`

**QA Reports**:
- Visual QA: `/diagrams/sources/VISUAL_QA_REPORT.md`
- Semantic QA: `/diagrams/sources/SEMANTIC_QA_REPORT.md`
- Consistency Report: `/diagrams/sources/CONSISTENCY_REPORT.md`
- Final Verification: `/diagrams/sources/FINAL_VERIFICATION_REPORT.md`

---

**Document Version**: 1.0
**Generated**: 2025-10-19
**Maintained By**: Documentation Agent
**Status**: Complete
