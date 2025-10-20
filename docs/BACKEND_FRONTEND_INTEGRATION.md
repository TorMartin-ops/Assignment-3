# Backend-Frontend Integration Guide

Complete reference for all backend capabilities and their frontend integration points.

---

## Authentication Features

### 1. Username/Password Authentication

**Backend Routes:**
- `POST /register` - User registration (auth_routes.py:20)
- `POST /login` - User login (auth_routes.py:59)
- `GET /logout` - User logout (auth_routes.py:145)

**Frontend Templates:**
- `/templates/auth/register.html` - Registration form
- `/templates/auth/login.html` - Login form

**Integration:**
```html
<!-- Register Form -->
<form method="POST" action="{{ url_for('auth.register') }}">
    <input name="username" required>
    <input name="email" type="email" required>
    <input name="password" type="password" required>
    <input name="confirm_password" type="password" required>
    <button type="submit">Register</button>
</form>

<!-- Login Form -->
<form method="POST" action="{{ url_for('auth.login') }}">
    <input name="username" required>
    <input name="password" type="password" required>
    <button type="submit">Login</button>
</form>
```

**Status:** ✅ Fully Integrated

---

### 2. Google OAuth Login ("Sign in with Google")

**Backend Routes:**
- `GET /auth/google/login` - Initiate Google OAuth (google_oauth_routes.py:36)
- `GET /auth/google/callback` - Google OAuth callback (google_oauth_routes.py:71)

**Frontend Integration:**
```html
<!-- Login/Register Page -->
{% if google_oauth_enabled %}
<a href="{{ url_for('google_oauth.google_login') }}" class="btn btn-outline-danger">
    <i class="fab fa-google"></i> Sign in with Google
</a>
{% endif %}
```

**Configuration Required:**
```bash
# .env file
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
```

**Status:** ✅ Fully Integrated

---

### 3. Two-Factor Authentication (2FA/TOTP)

**Backend Routes:**
- `GET /2fa/setup` - Show QR code setup (twofa_routes.py)
- `POST /2fa/setup` - Enable 2FA (twofa_routes.py)
- `POST /2fa/verify` - Verify 2FA code (twofa_routes.py)
- `GET /2fa/disable` - Disable 2FA (twofa_routes.py)
- `GET /2fa/backup-codes` - View backup codes (twofa_routes.py)

**Frontend Templates:**
- `/templates/2fa/setup.html` - 2FA setup with QR code
- `/templates/2fa/verify.html` - 2FA verification
- `/templates/2fa/disable.html` - Disable 2FA
- `/templates/2fa/backup_codes.html` - View/download backup codes

**Integration:**
```html
<!-- In Profile/Settings Page -->
{% if not session.get('totp_enabled') %}
    <a href="{{ url_for('twofa.setup_2fa') }}" class="btn btn-primary">
        Enable Two-Factor Authentication
    </a>
{% else %}
    <a href="{{ url_for('twofa.disable_2fa') }}" class="btn btn-warning">
        Disable 2FA
    </a>
    <a href="{{ url_for('twofa.view_backup_codes') }}" class="btn btn-secondary">
        View Backup Codes
    </a>
{% endif %}
```

**Status:** ✅ Fully Integrated

---

### 4. OAuth2 Authorization Server

**Backend Routes:**
- `GET/POST /oauth/authorize` - Authorization endpoint (oauth_routes.py:28)
- `POST /oauth/token` - Token endpoint (oauth_routes.py:124)
- `GET /oauth/userinfo` - User info endpoint (oauth_routes.py:214)
- `POST /oauth/revoke` - Token revocation (oauth_routes.py:242)

**Frontend Template:**
- `/templates/oauth/authorize.html` - OAuth consent screen

**Purpose:**
- Makes your app an OAuth2 provider
- Other apps can integrate with your authentication

**Integration:**
```html
<!-- OAuth Consent Screen (shown automatically when needed) -->
<form method="POST" action="{{ url_for('oauth.authorize') }}">
    <h3>Authorize {{ client.name }}?</h3>
    <p>Requested scopes: {{ scope }}</p>
    <button name="approved" value="yes">Allow</button>
    <button name="approved" value="no">Deny</button>
</form>
```

**Status:** ✅ Fully Integrated

---

## Security Features

### 5. Brute Force Protection

**Backend Services:**
- `RateLimiter` - Request rate limiting (services/rate_limiter.py)
- `SecurityService.check_account_lockout()` - Account lockout (services/security_service.py)
- `SecurityService.requires_captcha()` - CAPTCHA trigger (services/security_service.py)

**Frontend Integration:**
```html
<!-- Login Form -->
{% if locked %}
<div class="alert alert-danger">
    Account temporarily locked due to too many failed attempts
</div>
{% endif %}

{% if requires_captcha and recaptcha_enabled %}
<div class="g-recaptcha" data-sitekey="{{ recaptcha_site_key }}"></div>
{% endif %}
```

**Configuration:**
```bash
# .env file
RECAPTCHA_SITE_KEY=your-site-key
RECAPTCHA_SECRET_KEY=your-secret-key
```

**Status:** ✅ Fully Integrated

---

### 6. Email Notifications

**Backend Service:**
- Email sending via SMTP (configured in .env)

**Features:**
- Password reset emails
- Account creation confirmations
- Security alerts
- 2FA backup codes

**Configuration:**
```bash
# .env file
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

**Status:** ⚠️ Backend Ready - Frontend Needs Implementation

**TODO: Add Password Reset Flow**
```python
# Backend route to implement:
@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    # Send reset email
    pass

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify token and reset password
    pass
```

---

## Recipe App Features

### 7. Recipe Management

**Backend Routes:**
- `GET /` - Home page with recipes (app_auth.py:62)
- `GET /recipe/<id>` - Recipe details (app_auth.py:112)
- `GET/POST /add_recipe` - Add new recipe (app_auth.py:276)
- `POST /add_comment/<id>` - Add comment (app_auth.py:165)
- `POST /rate/<id>` - Rate recipe (app_auth.py:188)
- `POST /favorite/<id>` - Toggle favorite (app_auth.py:213)

**Frontend Templates:**
- `/templates/home.html` - Recipe listing
- `/templates/recipe_detail.html` - Recipe detail page
- `/templates/add_recipe.html` - Add recipe form

**Integration:**
```html
<!-- Recipe List -->
{% for recipe in recipes %}
<div class="recipe-card">
    <h3>{{ recipe.title }}</h3>
    <p>{{ recipe.description }}</p>
    <a href="{{ url_for('recipe_detail', recipe_id=recipe.id) }}">View Recipe</a>
</div>
{% endfor %}

<!-- Add Recipe -->
<form method="POST" action="{{ url_for('add_recipe') }}">
    <input name="title" required>
    <textarea name="description" required></textarea>
    <textarea name="ingredients" required></textarea>
    <textarea name="instructions" required></textarea>
    <button type="submit">Add Recipe</button>
</form>
```

**Status:** ✅ Fully Integrated

---

### 8. User Profiles

**Backend Routes:**
- `GET /profile/<username>` - View profile (app_auth.py:237)

**Frontend Template:**
- `/templates/profile.html` - User profile page

**Integration:**
```html
<!-- Profile Page -->
<h1>{{ user.username }}'s Profile</h1>

<h2>My Recipes ({{ recipes|length }})</h2>
{% for recipe in recipes %}
    <!-- Display user's recipes -->
{% endfor %}

<h2>Favorite Recipes ({{ favorites|length }})</h2>
{% for recipe in favorites %}
    <!-- Display favorited recipes -->
{% endfor %}
```

**Status:** ✅ Fully Integrated

---

## Global Template Variables

All templates have access to these variables via context processors:

```python
# app_auth.py context_processor
{
    'recaptcha_site_key': '6LcC...',          # reCAPTCHA public key
    'recaptcha_enabled': True,                 # Is reCAPTCHA configured?
    'google_oauth_enabled': True               # Is Google OAuth configured?
}

# Session variables (when logged in)
session['user_id']            # User ID
session['username']           # Username
session['authenticated']      # True/False
session['totp_enabled']       # Is 2FA enabled?
session['auth_method']        # 'password' or 'google_oauth'
```

---

## Security Headers

**Backend:** All responses include security headers (app_auth.py:53)

```python
# Applied automatically
Content-Security-Policy
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security (HSTS)
```

**Status:** ✅ Automatically Applied

---

## CSRF Protection

**Backend:** Flask-WTF CSRF protection (app_auth.py:29)

**Frontend Integration:**
```html
<!-- All forms must include CSRF token -->
<form method="POST">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
    <!-- form fields -->
</form>
```

**Status:** ✅ Fully Integrated

---

## Session Management

**Backend Configuration:**
```python
# app_auth.py:23-26
SESSION_COOKIE_SECURE = True      # HTTPS only
SESSION_COOKIE_HTTPONLY = True    # No JavaScript access
SESSION_COOKIE_SAMESITE = 'Lax'   # CSRF protection
```

**Status:** ✅ Configured

---

## Login Protection Decorator

**Backend:** `@login_required` decorator

**Usage:**
```python
from utils import login_required

@app.route('/protected')
@login_required
def protected_page():
    # Only accessible when logged in
    return render_template('protected.html')
```

**Status:** ✅ Available for use

---

## Feature Availability Matrix

| Feature | Backend Ready | Frontend Integrated | Configuration Required |
|---------|---------------|---------------------|------------------------|
| Username/Password Auth | ✅ | ✅ | SECRET_KEY, ENCRYPTION_SALT |
| Google OAuth Login | ✅ | ✅ | GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET |
| Two-Factor Auth (2FA) | ✅ | ✅ | ENCRYPTION_SALT |
| OAuth2 Server | ✅ | ✅ | None (built-in) |
| Brute Force Protection | ✅ | ✅ | RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY |
| Rate Limiting | ✅ | ✅ Auto | None (built-in) |
| Account Lockout | ✅ | ✅ | None (built-in) |
| Email Notifications | ✅ | ⚠️ Partial | SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD |
| Password Reset | ❌ | ❌ | Need Implementation |
| GitHub OAuth | ❌ | ❌ | Need Implementation |
| Recipe Management | ✅ | ✅ | None |
| User Profiles | ✅ | ✅ | None |
| Comments & Ratings | ✅ | ✅ | None |
| Favorites | ✅ | ✅ | None |
| Security Logging | ✅ | N/A | None (automatic) |
| CSRF Protection | ✅ | ✅ | None (automatic) |
| Session Security | ✅ | N/A | None (automatic) |

---

## Missing Features (TODO)

### High Priority

1. **Password Reset Flow** ⚠️
   - Backend routes needed
   - Email template needed
   - Frontend forms needed
   - Token generation/validation needed

2. **Email Verification** ⚠️
   - Send verification email on registration
   - Verify email endpoint
   - Resend verification email

3. **User Settings Page** ⚠️
   - Change password
   - Change email
   - Delete account
   - Privacy settings

### Medium Priority

4. **GitHub OAuth Login**
   - Similar to Google OAuth
   - Backend routes
   - Frontend buttons

5. **Admin Panel**
   - User management
   - Security log viewer
   - OAuth client management

6. **Security Alerts**
   - Login from new device
   - Failed login attempts
   - Password changes

### Low Priority

7. **Session Management UI**
   - View active sessions
   - Revoke sessions
   - Device fingerprinting

8. **API Key Management** (for OAuth clients)
   - Generate API keys
   - Revoke keys
   - View usage

---

## Quick Integration Checklist

When adding a new protected page:

- [ ] Add route in appropriate blueprint
- [ ] Apply `@login_required` decorator
- [ ] Create template in `/templates/`
- [ ] Include CSRF token in forms
- [ ] Use `url_for()` for all URLs
- [ ] Add navigation link in `base.html`
- [ ] Test without login (should redirect)
- [ ] Test with login (should work)
- [ ] Test CSRF protection
- [ ] Update this documentation

---

## Testing Endpoints

### Authentication
```bash
# Register
curl -X POST http://localhost:5000/register \
  -d "username=testuser&email=test@example.com&password=SecurePass123"

# Login
curl -X POST http://localhost:5000/login \
  -d "username=testuser&password=SecurePass123"

# Google OAuth
# Visit: http://localhost:5000/auth/google/login
```

### OAuth2 Server
```bash
# Authorization (requires logged in session)
http://localhost:5000/oauth/authorize?client_id=CLIENT_ID&redirect_uri=URI&response_type=code&code_challenge=CHALLENGE&code_challenge_method=S256

# Token exchange
curl -X POST http://localhost:5000/oauth/token \
  -d "grant_type=authorization_code&code=CODE&client_id=CLIENT_ID&client_secret=SECRET&redirect_uri=URI&code_verifier=VERIFIER"
```

---

## Environment Variables Reference

```bash
# Required
SECRET_KEY=<64-char-hex>                    # Flask session encryption
ENCRYPTION_SALT=<32-char-hex>               # 2FA secret encryption

# Required for Production
RECAPTCHA_SITE_KEY=<your-key>               # Google reCAPTCHA public key
RECAPTCHA_SECRET_KEY=<your-key>             # Google reCAPTCHA private key

# Optional - Social Login
GOOGLE_CLIENT_ID=<your-id>                  # Google OAuth client ID
GOOGLE_CLIENT_SECRET=<your-secret>          # Google OAuth client secret
GITHUB_CLIENT_ID=<your-id>                  # GitHub OAuth client ID (not implemented)
GITHUB_CLIENT_SECRET=<your-secret>          # GitHub OAuth client secret (not implemented)

# Optional - Email
SMTP_SERVER=smtp.gmail.com                  # SMTP server address
SMTP_PORT=587                               # SMTP port (587 for TLS)
SMTP_USERNAME=your-email@gmail.com          # SMTP username
SMTP_PASSWORD=<app-password>                # SMTP password/app password

# Optional - Security
HIBP_API_KEY=<your-key>                     # Have I Been Pwned API key (not implemented)

# Development
FLASK_ENV=development                       # Flask environment mode
FLASK_DEBUG=True                            # Enable debug mode
```

---

## Support & Documentation

- **API Keys Setup:** [docs/API_KEYS_SETUP_GUIDE.md](API_KEYS_SETUP_GUIDE.md)
- **Quick Start:** [QUICK_START_API_KEYS.md](../QUICK_START_API_KEYS.md)
- **Security:** Check security logs in database `security_events` table
- **OAuth2 Spec:** Assignment follows RFC 7636 (PKCE) and RFC 6749 (OAuth2)

---

**Last Updated:** October 2025
