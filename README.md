# Recipe Sharing Platform - User Authentication System

A secure recipe sharing application with comprehensive authentication features including OAuth2, 2FA, and brute force protection.

## Quick Start

### Prerequisites
- Docker and Docker Compose OR Python 3.8+
- Basic understanding of environment variables

### 1. Configure Environment Variables

**See:** [QUICK_START_API_KEYS.md](QUICK_START_API_KEYS.md) for detailed setup instructions

```bash
# Copy the example environment file
cp .env.example .env

# Generate required secret keys
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('ENCRYPTION_SALT=' + secrets.token_hex(16))"

# Edit .env and paste the generated values
# (reCAPTCHA test keys are already configured for development)
```

**Required API Keys:**
- ✅ **SECRET_KEY** - Generate yourself (see command above)
- ✅ **ENCRYPTION_SALT** - Generate yourself (see command above)
- ✅ **reCAPTCHA keys** - Test keys provided in `.env.example` (FREE production keys available)

**Optional API Keys:**
- SendGrid/SMTP (email notifications)
- Google/GitHub OAuth (social login)
- Have I Been Pwned (password breach checking)

See [docs/API_KEYS_SETUP_GUIDE.md](docs/API_KEYS_SETUP_GUIDE.md) for obtaining production API keys.

### 2. Run with Docker (Recommended)

```bash
# Build and start the application
docker compose up --build

# Access at http://localhost:5001
```

### 3. Or Run Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize database
python3 -c "from database_auth import init_db; init_db()"

# Run application
python3 app_auth.py

# Access at http://localhost:5000
```

## Features

### Authentication Methods
- **Username/Password** - Secure bcrypt hashing with salt
- **Google OAuth** - "Sign in with Google" (fully integrated)
- **Two-Factor Authentication (2FA)** - TOTP with authenticator apps ([Setup Guide](2FA_QUICK_START.md))
- **OAuth2 Authorization Code Flow with PKCE** - RFC 7636 compliant (your app as provider)

### Security Features
- **Brute Force Protection** - Rate limiting and account lockout
- **Google reCAPTCHA** - Bot detection on login
- **Session Security** - HTTPOnly, Secure, SameSite cookies
- **CSRF Protection** - Flask-WTF token validation
- **Password Requirements** - Minimum 12 characters, complexity rules
- **Token Family Rotation** - Prevents refresh token replay attacks

### Application Features
- Recipe creation and sharing
- User profiles
- Session management
- Security event logging

## API Keys Cost Summary

| Service | Required? | Cost | Purpose |
|---------|-----------|------|---------|
| Flask secrets (self-generated) | ✅ Required | **FREE** | Session encryption |
| Google reCAPTCHA | ✅ Required | **FREE** | Brute force protection |
| SendGrid/SMTP | ❌ Optional | **FREE** tier | Email notifications |
| Google OAuth | ❌ Optional | **FREE** | Social login |
| GitHub OAuth | ❌ Optional | **FREE** | Social login |
| Have I Been Pwned | ❌ Optional | **$3.50/month** | Password breach check |

**Total cost for full production deployment: FREE to $3.50/month**

## Documentation

### Setup Guides
- **[QUICK_START_API_KEYS.md](QUICK_START_API_KEYS.md)** - API keys setup (2 min)
- **[2FA_QUICK_START.md](2FA_QUICK_START.md)** - Enable Two-Factor Auth (2 min)
- **[docs/API_KEYS_SETUP_GUIDE.md](docs/API_KEYS_SETUP_GUIDE.md)** - Complete API key guide

### Feature Guides
- **[HOW_TO_USE_2FA.md](HOW_TO_USE_2FA.md)** - Complete 2FA guide with troubleshooting
- **[FEATURES_READY.md](FEATURES_READY.md)** - All features status and usage
- **[docs/BACKEND_FRONTEND_INTEGRATION.md](docs/BACKEND_FRONTEND_INTEGRATION.md)** - Developer integration guide

### Project Documentation
- **[Assignment_3_Report.tex](Assignment_3_Report.tex)** - Academic report with UML diagrams
- **[ASSIGNMENT_REQUIREMENTS_VERIFICATION.md](ASSIGNMENT_REQUIREMENTS_VERIFICATION.md)** - Requirements verification
- **[INTEGRATION_COMPLETE.md](INTEGRATION_COMPLETE.md)** - Integration summary