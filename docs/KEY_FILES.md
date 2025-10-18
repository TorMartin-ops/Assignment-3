# 🔑 Key Files Reference - Quick Navigation

## 🚀 START HERE

1. **Read This First**: `QUICKSTART.md`
2. **Install**: `./install.sh`
3. **Run App**: `python3 app_auth.py`
4. **Test**: `python3 test_complete_system.py`

---

## 📂 File Locations by Purpose

### **INSTALLATION**
```bash
./install.sh                    # Run this first!
requirements.txt                # All dependencies
.env.example                    # Copy to .env
```

### **DATABASE**
```bash
database_auth.py                # Run: python3 database_auth.py
# Creates 9 auth tables in recipe_app.db
```

### **CORE SERVICES** (The brain of the system)
```bash
services/auth_service.py        # Argon2id authentication
services/oauth2_service.py      # OAuth2 provider
services/totp_service.py        # 2FA TOTP
services/security_service.py    # Brute force protection
services/rate_limiter.py        # Rate limiting
```

### **FLASK ROUTES** (HTTP endpoints)
```bash
routes/auth_routes.py           # /register, /login, /logout
routes/oauth_routes.py          # /oauth/authorize, /token
routes/twofa_routes.py          # /setup-2fa, /verify-2fa
```

### **UTILITIES**
```bash
utils/encryption.py             # Fernet encryption
utils/validators.py             # Input validation
```

### **APPLICATION**
```bash
app_auth.py                     # Run: python3 app_auth.py
# Main Flask application with all features
```

### **TEMPLATES** (UI)
```bash
templates/auth/register.html
templates/auth/login.html
templates/2fa/setup.html        # Shows QR code
templates/2fa/verify.html
templates/oauth/authorize.html  # OAuth consent
templates/security/security_settings.html
```

### **TESTING**
```bash
test_auth_basic.py              # Service tests
test_complete_system.py         # Full integration tests
test_oauth2_flow.py             # OAuth2 flow guide
```

### **DOCUMENTATION**
```bash
README_AUTH.md                  # Main README (start here for docs)
QUICKSTART.md                   # Quick reference
IMPLEMENTATION_PLAN.md          # Architecture (60KB)
SETUP_GUIDE.md                  # Detailed setup
IMPLEMENTATION_SUMMARY.md       # Summary
```

---

## 🎯 Quick Actions

### **Install Everything**
```bash
./install.sh
```

### **Test Core Services**
```bash
python3 test_auth_basic.py
```

### **Test Complete System**
```bash
python3 test_complete_system.py
```

### **Start Application**
```bash
python3 app_auth.py
```

### **Clear Test Data**
```bash
rm recipe_app.db
python3 database.py
python3 database_auth.py
```

---

## 🔍 Finding Specific Features

### **Looking for Password Hashing?**
→ `services/auth_service.py` lines 42-65

### **Looking for Rate Limiting?**
→ `services/rate_limiter.py` lines 45-80

### **Looking for 2FA QR Code?**
→ `services/totp_service.py` lines 28-55

### **Looking for OAuth2 PKCE?**
→ `services/oauth2_service.py` lines 78-102

### **Looking for Account Lockout?**
→ `services/security_service.py` lines 125-165

### **Looking for Database Schema?**
→ `database_auth.py` lines 20-250

---

## 📋 Feature Checklist

After running `./install.sh` and `python3 app_auth.py`:

**Authentication:**
- [ ] http://localhost:5000/register - Create account
- [ ] http://localhost:5000/login - Login
- [ ] Try 3 wrong passwords - See lockout

**2FA:**
- [ ] http://localhost:5000/security-settings - Enable 2FA
- [ ] http://localhost:5000/setup-2fa - Scan QR code
- [ ] Login again - Verify with authenticator

**OAuth2:**
- [ ] http://localhost:5000/oauth/authorize?client_id=test_client_id&...
- [ ] POST to /oauth/token - Get access token
- [ ] GET /oauth/userinfo - Access protected resource

---

## 📞 Need Help?

| Question | Answer |
|----------|--------|
| How do I install? | Run `./install.sh` |
| How do I test? | Run `python3 test_complete_system.py` |
| How do I start app? | Run `python3 app_auth.py` |
| Where's the database code? | `database_auth.py` |
| Where's authentication? | `services/auth_service.py` |
| Where's OAuth2? | `services/oauth2_service.py` |
| Where's 2FA? | `services/totp_service.py` |
| Where are the routes? | `routes/` directory |
| Where are templates? | `templates/` directory |
| How do I test OAuth2? | `python3 test_oauth2_flow.py` |

---

**Last Updated**: 2025-10-16
**Status**: ✅ Complete - Ready to Install & Test!
