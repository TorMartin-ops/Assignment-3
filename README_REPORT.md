# Assignment 3 Report

## 📄 Report File
**Assignment_3_Report.tex** - Ready for Overleaf upload

## 📊 Report Details
- **Length**: ~12-15 pages (similar to Assignment 2's 11 pages)
- **Format**: Academic LaTeX matching Assignment 2 style
- **Authors**: Gruppe 2 (Bjarte, Brage, Matias, Tor Martin)
- **Diagrams**: All 9 SVG diagrams embedded
- **Screenshots**: 7 placeholders with capture instructions

## 🎯 All 5 Tasks Covered
1. Database Integration - 9 tables with ER diagram
2. Basic Authentication - Argon2id + HIBP
3. Brute Force Protection - 3-layer defense
4. Two-Factor Authentication - TOTP + QR codes
5. OAuth2 - Authorization Code Flow + PKCE

## 📁 Upload to Overleaf

1. Go to https://www.overleaf.com
2. New Project → Upload Project → ZIP
3. Or manually:
   - Upload `Assignment_3_Report.tex`
   - Create `diagrams/` folder
   - Upload all 9 SVG files to `diagrams/` folder
   - Upload `uia_logo.png`
4. Compile and download PDF!

## 📸 Screenshot Instructions

App running at: **http://127.0.0.1:5001**

All screenshot placeholders have capture instructions inside the .tex file.

### Quick Capture (5 screenshots):

**1. HIBP Breach Detection**
- Go to /register, try password "password123"

**2. Account Lockout**
- Go to /login, fail 3 times

**3. CAPTCHA Challenge**
- After lockout expires, try login

**4. 2FA QR Code**
- Register account, go to /setup-2fa

**5. Backup Codes**
- Scan QR, verify code, see 10 codes

**6. 2FA Verification**
- Logout, login again, see TOTP input

**7. OAuth Consent**
- Use test_oauth2_teacher.py, visit /oauth/authorize

## ✅ Files to Upload to Overleaf

```
Assignment_3_Report.tex
uia_logo.png
diagrams/
  ├── 1_system_architecture.svg
  ├── 2_class_diagram_services.svg
  ├── 3_oauth2_sequence.svg
  ├── 4_database_er.svg
  ├── 5_2fa_login_sequence.svg
  ├── 6_brute_force_activity.svg
  ├── 7_security_layers.svg
  ├── 13_account_lockout_state_machine.svg
  └── 14_token_family_rotation.svg
```

(Optional: Add screenshot PNG files to root after capturing)

---

**Report is concise, properly formatted, and ready!** 🎓
