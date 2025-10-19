# Ground Truth Specification - Quick Reference
## Assignment 3 Authentication System

This document provides a quick reference to the comprehensive ground truth specification.

---

## Document Location

**Full Specification**: `/home/torma/Assignment-3/docs/GROUND_TRUTH_SPECIFICATION.md`

**Size**: 54 KB, 1596 lines

---

## Key Statistics

- **Total Python Files Analyzed**: 20+ core files
- **Lines of Code Analyzed**: ~4,000 lines
- **Database Tables**: 9 tables with complete schema
- **Database Indexes**: 15 performance indexes
- **Routes**: 13 HTTP endpoints
- **Service Classes**: 5 singleton services
- **Utility Classes**: 6 helper classes
- **Critical Transactions**: 4 BEGIN IMMEDIATE locations
- **External APIs**: 2 (HIBP password breach, Google reCAPTCHA)

---

## Core Components with File:Line Evidence

### Application Entry Point
- **File**: `app_auth.py`
- **Flask App**: Line 20
- **CSRF Protection**: Line 29
- **Security Headers**: Lines 53-56
- **Blueprint Registration**: Lines 36-38

### Database Schema
- **File**: `database_auth.py`
- **9 Tables**: Lines 22-299
  - users (enhanced): Lines 22-80
  - login_attempts: Lines 87-97
  - account_lockouts: Lines 113-123
  - rate_limits: Lines 133-143
  - security_events: Lines 153-165
  - oauth2_clients: Lines 180-199
  - oauth2_authorization_codes: Lines 209-225
  - oauth2_tokens: Lines 235-254
  - sessions: Lines 274-289

### Service Layer (All Singletons)
1. **AuthService** (`services/auth_service.py`)
   - Lines: 13-247
   - Argon2id config: Lines 22-28
   - Key methods: register_user, authenticate, change_password

2. **OAuth2Service** (`services/oauth2_service.py`)
   - Lines: 14-444
   - Token lifetimes: Lines 21-23
   - PKCE validation: Lines 98-122
   - Transaction safety: Lines 178, 307

3. **TOTPService** (`services/totp_service.py`)
   - Lines: 16-250
   - Replay prevention: Line 25
   - QR code generation: Lines 36-73
   - Backup codes: Lines 90, 222-231

4. **SecurityService** (`services/security_service.py`)
   - Lines: 9-314
   - Brute force thresholds: Lines 16-18
   - Account lockout: Lines 159-217
   - Audit logging: Lines 24-61

5. **RateLimiter** (`services/rate_limiter.py`)
   - Lines: 11-178
   - Database-backed: No Redis required
   - Transaction safety: Line 96

### Security Controls

#### PREVENT Controls
- Argon2id (auth_service.py:22-28): OWASP-recommended hashing
- PKCE (oauth2_service.py:110-116): OAuth2 security
- TOTP (totp_service.py:166-168): RFC 6238 2FA
- Encryption (encryption.py:35): Fernet AES-128
- CSP (security_headers.py:24-32): XSS prevention
- Rate Limiting (rate_limiter.py): Brute force prevention

#### DETECT Controls
- Login attempts tracking (database_auth.py:87-108)
- Security events log (database_auth.py:153-175)
- Replay prevention cache (totp_service.py:159-173)
- Token reuse detection (oauth2_service.py:320-325)

#### RESPOND Controls
- Token family revocation (oauth2_service.py:397-416)
- Account lockout (security_service.py:159-217)
- Session regeneration (decorators.py:23-53)
- Rate limit 429 responses (rate_limiter.py:157-162)

---

## Critical Security Mechanisms

### Session Fixation Prevention
**File**: `utils/decorators.py`, lines 23-53
**Called at**:
1. After password auth: `auth_routes.py:116`
2. After 2FA verification: `twofa_routes.py:133`

### Transaction Safety (BEGIN IMMEDIATE)
Prevents race conditions in concurrent operations:
1. **Authorization code validation**: `oauth2_service.py:178`
2. **Refresh token rotation**: `oauth2_service.py:307`
3. **Account lockout**: `security_service.py:178`
4. **Rate limit recording**: `rate_limiter.py:96`

### Token Reuse Detection
**File**: `oauth2_service.py`, lines 320-325
- Checks `refresh_token_used` flag
- If reused: Revokes entire token family
- Prevents token replay attacks

### Replay Prevention (TOTP)
**File**: `totp_service.py`, lines 159-173
- Cache key: `{user_id}:{code}:{time_window}`
- Time window: 30 seconds
- Prevents code reuse within window

---

## Authentication Flows

### Password Login Flow
**File**: `routes/auth_routes.py`, lines 59-146

```
1. Rate limit check (line 60)
2. Input validation (lines 64-69)
3. Account lockout check (lines 72-75)
4. CAPTCHA check if required (lines 78-94)
5. Authenticate with Argon2id (line 97)
6. Log attempt (lines 100-106)
7. On success:
   - Clear lockout (line 112)
   - Regenerate session (line 116) ← CRITICAL
   - Check 2FA enabled (line 119)
   - If 2FA: Store pending, redirect
   - If no 2FA: Complete login
8. On failure:
   - Count failures (line 132)
   - Apply lockout if threshold reached (lines 134-137)
```

### 2FA Verification Flow
**File**: `routes/twofa_routes.py`, lines 82-153

```
1. Rate limit (per-IP, line 83)
2. Check pending state (lines 86-88)
3. Verify TOTP:
   - Decrypt secret (totp_service.py:152-153)
   - Check replay cache (totp_service.py:159-163)
   - Verify with pyotp (totp_service.py:166-168)
4. On success:
   - Clear pending state (lines 131-133)
   - Regenerate session (line 133) ← SECOND regeneration
   - Complete login (lines 136-137)
   - Log event (lines 139-144)
```

### OAuth2 Flow
**File**: `routes/oauth_routes.py`

**Authorization** (lines 28-122):
1. Validate client (lines 46-51)
2. Validate redirect_uri - EXACT match (lines 54-55)
3. Check PKCE code_challenge present (lines 62-63)
4. Check user authenticated (lines 66-70)
5. Show consent screen (lines 83-85)
6. Generate authorization code (lines 102-109)

**Token Exchange** (lines 133-182):
1. Validate client (lines 142-144)
2. Validate auth code with BEGIN IMMEDIATE (lines 147-149)
3. Validate PKCE: SHA256(verifier) == challenge (lines 159-164)
4. Generate tokens (lines 167-171)

**Token Refresh** (lines 184-210):
1. Validate client (lines 191-193)
2. Refresh with BEGIN IMMEDIATE (line 196)
3. Check reuse detection (oauth2_service.py:320-325)
4. Mark old token used, issue new tokens

---

## Configuration Thresholds

| Parameter | Value | Location |
|-----------|-------|----------|
| Login rate limit | 5/min per-user | auth_routes.py:60 |
| 2FA verify rate limit | 5/min per-IP | twofa_routes.py:83 |
| Lockout threshold | 3 failures | security_service.py:16 |
| Lockout duration | 15 minutes | security_service.py:17 |
| CAPTCHA threshold | 3 failures | security_service.py:18 |
| Password min length | 12 chars | validators.py:15 |
| Access token lifetime | 1 hour | oauth2_service.py:21 |
| Refresh token lifetime | 30 days | oauth2_service.py:22 |
| Auth code lifetime | 10 minutes | oauth2_service.py:23 |
| TOTP tolerance | ±30 seconds | totp_service.py:168 |
| Argon2id memory | 19 MiB | auth_service.py:24 |
| PBKDF2 iterations | 100,000 | encryption.py:82 |

---

## External API Integrations

### 1. Have I Been Pwned (HIBP)
**File**: `utils/validators.py`, lines 64-97
- **Endpoint**: `https://api.pwnedpasswords.com/range/{prefix}`
- **Method**: K-anonymity model (SHA-1 prefix matching)
- **Timeout**: 2 seconds
- **Fail-open**: On error, allow registration (availability over security)

### 2. Google reCAPTCHA v2
**File**: `utils/recaptcha.py`, lines 42-96
- **Endpoint**: `https://www.google.com/recaptcha/api/siteverify`
- **Trigger**: After 3 login failures
- **Timeout**: 5 seconds
- **Error translation**: Lines 98-125

---

## Route Summary

| Route | File:Line | Rate Limit | 2FA Impact |
|-------|-----------|------------|-----------|
| `/register` | auth_routes.py:20-57 | None | - |
| `/login` | auth_routes.py:59-146 | 5/min user | Redirects to verify |
| `/logout` | auth_routes.py:148-163 | None | - |
| `/change-password` | auth_routes.py:165-202 | None | - |
| `/security-settings` | auth_routes.py:204-218 | None | - |
| `/setup-2fa` | twofa_routes.py:20-80 | 5/min user | Enables 2FA |
| `/verify-2fa` | twofa_routes.py:82-153 | 5/min IP | Completes login |
| `/backup-codes` | twofa_routes.py:155-168 | None | One-time display |
| `/disable-2fa` | twofa_routes.py:170-206 | 3/min user | Disables 2FA |
| `/oauth/authorize` | oauth_routes.py:28-122 | None | - |
| `/oauth/token` | oauth_routes.py:124-212 | None | CSRF exempt |
| `/oauth/userinfo` | oauth_routes.py:214-240 | None | Bearer auth |
| `/oauth/revoke` | oauth_routes.py:242-273 | None | CSRF exempt |

---

## Data Flow Summary

### Request Processing Pipeline
```
HTTP Request
  ↓
TLS Termination (server/proxy level)
  ↓
Flask App (app_auth.py:20)
  ↓
Security Headers (app_auth.py:53-56)
  ↓
CSRF Protection (app_auth.py:29)
  ↓
Blueprint Routing (app_auth.py:36-38)
  ↓
Rate Limiter (decorator with BEGIN IMMEDIATE)
  ↓
Route Handler
  ↓
Service Layer (singleton instances)
  ↓
Database (parameterized queries, transactions)
  ↓
Response with Security Headers
  ↓
HTTP Response
```

### Password Storage Flow
```
User Input (plaintext)
  ↓
PasswordValidator.validate() (validators.py:27-62)
  ↓
PasswordValidator.check_breach() (HIBP API, validators.py:64-97)
  ↓
Argon2id.hash() (auth_service.py:74)
  - memory_cost: 19 MiB
  - time_cost: 2 iterations
  - parallelism: 1
  ↓
Database INSERT users.password (parameterized)
```

### TOTP Secret Storage Flow
```
User Setup 2FA
  ↓
TOTPService.generate_secret() (pyotp.random_base32())
  ↓
EncryptionService.encrypt()
  - PBKDF2 key derivation (100k iterations)
  - Fernet (AES-128 CBC + HMAC)
  ↓
Database UPDATE users.totp_secret (encrypted)
```

---

## Diagram Generation Checklist

### System Architecture Diagram
- [ ] Flask app entry point (app_auth.py:20)
- [ ] 3 Blueprints (auth, oauth, twofa)
- [ ] 5 Service singletons
- [ ] 9 Database tables
- [ ] Security middleware layers
- [ ] External API connections (HIBP, reCAPTCHA)

### Class Diagram
- [ ] AuthService with Argon2id hasher (auth_service.py:13-247)
- [ ] OAuth2Service with token management (oauth2_service.py:14-444)
- [ ] TOTPService with encryption (totp_service.py:16-250)
- [ ] SecurityService with audit logging (security_service.py:9-314)
- [ ] RateLimiter with database backend (rate_limiter.py:11-178)
- [ ] EncryptionService with Fernet (encryption.py:16-133)
- [ ] Validators (password, email, username)
- [ ] ReCaptchaService (recaptcha.py:10-126)
- [ ] All relationships and dependencies

### OAuth2 Sequence Diagram
- [ ] 5 phases: Authorization, Consent, Token Exchange, Resource Access, Refresh
- [ ] PKCE flow with code_challenge and code_verifier
- [ ] Transaction safety points (BEGIN IMMEDIATE)
- [ ] Token reuse detection
- [ ] Token family revocation

### 2FA Sequence Diagram
- [ ] Password authentication phase
- [ ] Session regeneration (first time)
- [ ] TOTP verification phase
- [ ] Replay prevention cache
- [ ] Session regeneration (second time)
- [ ] Backup code alternative flow

### Database Schema Diagram
- [ ] 9 tables with all columns
- [ ] 15 indexes
- [ ] 3 foreign key relationships
- [ ] ON DELETE CASCADE behaviors
- [ ] UNIQUE constraints
- [ ] Token family tracking mechanism

### Brute Force Protection Diagram
- [ ] Layer 1: Per-IP rate limiting
- [ ] Layer 2: Per-account failure tracking
- [ ] Layer 3: CAPTCHA challenge
- [ ] Lockout mechanism
- [ ] 3-failure threshold
- [ ] 15-minute lockout duration

### Security Controls Diagram
- [ ] PREVENT layer (15 controls)
- [ ] DETECT layer (6 controls)
- [ ] RESPOND layer (6 controls)
- [ ] Trust boundaries
- [ ] Data flow paths

---

## Using This Specification

This ground truth specification provides complete file:line evidence for every component, flow, and security mechanism in the authentication system. Use it to:

1. **Generate accurate UML diagrams**: All file:line references ensure diagrams match implementation
2. **Verify security controls**: Each control has precise implementation location
3. **Understand data flows**: Complete request/response pipelines documented
4. **Review transaction safety**: All BEGIN IMMEDIATE locations identified
5. **Audit security mechanisms**: Evidence for every prevent/detect/respond control

For detailed implementation details, see the full specification at:
`/home/torma/Assignment-3/docs/GROUND_TRUTH_SPECIFICATION.md`

---

**Generated**: 2025-10-19
**Specification Version**: 1.0
**Codebase Analyzed**: ~4,000 lines across 20+ files
**Completeness**: 100% - All critical paths documented with file:line evidence
