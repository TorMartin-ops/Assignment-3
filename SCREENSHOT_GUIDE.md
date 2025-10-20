# 📸 Screenshot Capture Guide for Assignment 3

## ✅ Server Status
**Server is RUNNING on:** http://127.0.0.1:5001

---

## 📋 7 Screenshots Required

### Screenshot 1: HIBP Password Breach Detection
**Location in Report:** Figure after line 197
**Purpose:** Show password breach detection during registration

**Steps:**
1. Open browser: http://127.0.0.1:5001/register
2. Fill in registration form:
   - Username: testuser1
   - Email: test@example.com
   - Password: **password123** (known breached password)
3. Click "Register"
4. **CAPTURE**: Error message showing "Password found in X data breaches!"
5. **Save as:** `screenshots/fig_hibp_breach.png`

---

### Screenshot 2: Account Lockout Message
**Location in Report:** Figure caption line 251
**Purpose:** Show account locked after 5 failed login attempts

**Steps:**
1. Register a test account first (if not already done)
2. Go to: http://127.0.0.1:5001/login
3. Enter correct username but wrong password
4. **Fail login 5 times consecutively**
5. On 5th attempt, you'll see: "Account locked for 15 minutes"
6. **CAPTURE**: The lockout error message
7. **Save as:** `screenshots/fig_account_lockout.png`

**Note:** After 5 failures = LOCKED (not 3!)

---

### Screenshot 3: CAPTCHA Challenge After Lockout
**Location in Report:** Figure caption line 267
**Purpose:** Show Google reCAPTCHA appearing after failures

**Steps:**
1. After lockout expires (wait 15 minutes OR clear database)
2. OR use a different username that has 3+ failures but not locked
3. Go to: http://127.0.0.1:5001/login
4. **CAPTURE**: Login page showing the Google reCAPTCHA checkbox
5. **Save as:** `screenshots/fig_captcha_challenge.png`

**Note:** CAPTCHA appears after 3 failures, lockout after 5

---

### Screenshot 4: 2FA Setup - QR Code
**Location in Report:** Figure caption line 323
**Purpose:** Show 2FA QR code for Google Authenticator

**Steps:**
1. Register and login with a fresh account (without 2FA enabled)
2. Go to: http://127.0.0.1:5001/setup-2fa
3. Page will show:
   - QR code image
   - Secret key (text version)
   - Instructions
4. **CAPTURE**: The entire 2FA setup page with QR code visible
5. **Save as:** `screenshots/fig_2fa_qr_setup.png`

**Tip:** You can scan this QR code with Google Authenticator on your phone to test!

---

### Screenshot 5: Backup Codes Display
**Location in Report:** Figure caption line 339
**Purpose:** Show 10 backup codes after successful 2FA setup

**Steps:**
1. From Screenshot 4, scan the QR code with Google Authenticator
2. Enter the 6-digit code from your authenticator app
3. Click "Enable 2FA"
4. **CAPTURE**: Page showing all 10 backup codes
5. **Save as:** `screenshots/fig_backup_codes.png`

**Important:** This screen only appears ONCE after enabling 2FA!

---

### Screenshot 6: 2FA Verification Page
**Location in Report:** Figure caption line 372
**Purpose:** Show 2FA code input during login

**Steps:**
1. Logout from the account with 2FA enabled
2. Login again with username and password
3. After password verification, you'll be redirected to 2FA page
4. **CAPTURE**: The page asking for 6-digit TOTP code
5. **Save as:** `screenshots/fig_2fa_verification.png`

**Note:** Don't enter the code yet, just capture the input page!

---

### Screenshot 7: OAuth2 Consent Screen
**Location in Report:** Figure caption line 445
**Purpose:** Show OAuth2 authorization consent screen

**Steps:**
1. Open file: `tests/test_oauth2_teacher.py`
2. Run: `python3 tests/test_oauth2_teacher.py`
   - This will register an OAuth2 client
3. Copy the authorization URL from output
4. Open that URL in browser (should look like):
   `http://127.0.0.1:5001/oauth/authorize?response_type=code&client_id=...`
5. **CAPTURE**: The consent screen showing:
   - Client name
   - Requested scopes (profile, email)
   - Allow/Deny buttons
6. **Save as:** `screenshots/fig_oauth2_consent.png`

---

## 📁 File Organization

Create screenshots directory:
```bash
mkdir -p screenshots
```

**Save all screenshots as:**
```
screenshots/
├── fig_hibp_breach.png
├── fig_account_lockout.png
├── fig_captcha_challenge.png
├── fig_2fa_qr_setup.png
├── fig_backup_codes.png
├── fig_2fa_verification.png
└── fig_oauth2_consent.png
```

---

## 🔧 Testing Tips

### Reset Database Between Tests
```bash
# Remove database to start fresh
rm recipe_app.db

# Restart server
# Server will recreate database automatically
```

### Quick Account Creation
```bash
# Use registration form or run:
curl -X POST http://127.0.0.1:5001/register \
  -d "username=testuser&email=test@example.com&password=SecurePass123!"
```

### Trigger CAPTCHA Without Lockout
- 3 failures = CAPTCHA appears
- 5 failures = Account locks
- To show CAPTCHA only: fail exactly 3-4 times

### Clear Account Lockout
```bash
# Remove lockout from database
sqlite3 recipe_app.db "DELETE FROM account_lockouts;"
```

---

## 📊 Screenshot Requirements

**Resolution:** At least 1920x1080 recommended
**Format:** PNG (preferred) or JPG
**Content:** Full browser window showing URL bar + page content
**Quality:** Clear, readable text and UI elements

---

## ⚡ Quick Capture Workflow

**Recommended Order:**
1. ✅ Screenshot 1: HIBP (during registration)
2. ✅ Screenshot 4: 2FA QR code (after registration)
3. ✅ Screenshot 5: Backup codes (complete 2FA setup)
4. ✅ Screenshot 6: 2FA verification (logout and login)
5. ✅ Screenshot 2: Account lockout (5 failures)
6. ✅ Screenshot 3: CAPTCHA (after lockout expires)
7. ✅ Screenshot 7: OAuth2 (run test script)

**Total Time:** ~30-45 minutes

---

## 🛠️ Troubleshooting

**Server not running?**
```bash
source venv/bin/activate
python3 app_auth.py
```

**Port already in use?**
```bash
lsof -ti:5001 | xargs kill -9
```

**CAPTCHA not showing?**
- Check that you have 3+ failed login attempts
- Verify RECAPTCHA keys in .env file

**2FA not working?**
- Check that ENCRYPTION_SALT is set in .env
- Time sync between server and phone must be accurate

---

## 📝 After Capturing Screenshots

1. Review each screenshot for clarity
2. Ensure all required elements are visible
3. Update Assignment_3_Report.tex to reference actual images
4. Replace placeholder \fbox sections with \includegraphics

**Example replacement:**
```latex
% Replace this:
\fbox{\parbox{0.85\textwidth}{
    ...SCREENSHOT PLACEHOLDER...
}}

% With this:
\includegraphics[width=0.85\textwidth]{screenshots/fig_hibp_breach.png}
```

---

## ✅ Completion Checklist

- [ ] Screenshot 1: HIBP breach detection
- [ ] Screenshot 2: Account lockout (5 failures)
- [ ] Screenshot 3: CAPTCHA challenge
- [ ] Screenshot 4: 2FA QR code
- [ ] Screenshot 5: Backup codes (10 codes)
- [ ] Screenshot 6: 2FA verification page
- [ ] Screenshot 7: OAuth2 consent screen
- [ ] All screenshots saved in `screenshots/` directory
- [ ] All screenshots are clear and readable
- [ ] Report updated with actual image references

---

**Server URL:** http://127.0.0.1:5001
**Status:** ✅ RUNNING (Background Process ID: 102dc3)
