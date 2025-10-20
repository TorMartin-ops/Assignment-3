# 📸 OAuth2 Consent Screen Screenshot - READY TO CAPTURE

## ✅ Setup Complete

- ✅ Server running on: http://127.0.0.1:5001
- ✅ OAuth2 test client created in database
- ✅ Authorization URL generated

---

## 🎯 Quick Steps to Capture Screenshot

### Step 1: Login First
Open your browser and go to:
```
http://127.0.0.1:5001/login
```

**Login with any existing account:**
- Username: `testuser`
- Password: `TestPassword123`

(Or use any account you've already created)

---

### Step 2: Open the Authorization URL

**Copy and paste this FULL URL into your browser:**

```
http://127.0.0.1:5001/oauth/authorize?response_type=code&client_id=test_client_id&redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fcallback&scope=profile+email&state=aH_I2GpZ36Jn4uAZwYjn6no50Ozz2ucNs20_EXDFwhw&code_challenge=klu_oBBlXja-3KpdQJ0ccuV4Fa-0PUZVmjpb1UDu014&code_challenge_method=S256
```

---

### Step 3: You'll See the Consent Screen

The page will display:

✅ **Client Information:**
- Client ID: `test_client_id`
- Client Name: `Test OAuth2 Client`

✅ **Requested Permissions:**
- Access to your profile information
- Access to your email address

✅ **Scopes:**
- `profile`
- `email`

✅ **Buttons:**
- Allow (green button)
- Deny (red button)

---

### Step 4: Capture the Screenshot

**IMPORTANT:** Take the screenshot BEFORE clicking Allow or Deny!

📸 **Screenshot should show:**
- Full browser window (including URL bar)
- Client information clearly visible
- Requested scopes/permissions
- Allow/Deny buttons

**Save as:**
```
screenshots/fig_oauth2_consent.png
```

---

## 🔧 Troubleshooting

### "Please login first" error?
- Make sure you completed Step 1 (login)
- The OAuth2 flow requires an authenticated user session

### Page redirects immediately?
- The URL was already used before
- Run this command to generate a fresh URL:
  ```bash
  python3 generate_oauth_consent_url.py
  ```

### Can't see the consent screen?
- Make sure you're logged in FIRST
- Try clearing browser cookies and login again
- Generate a new authorization URL

---

## 📊 What You're Looking At

This consent screen demonstrates **OAuth2 Authorization Code Flow**:

1. **Third-party application** (`test_client_id`) wants to access your account
2. **You** (the resource owner) must grant permission
3. **The authorization server** (your app) shows what access is being requested
4. **After consent**, an authorization code is issued
5. **The third-party app** exchanges the code for an access token (with PKCE verification)

This is how Google, Facebook, GitHub, etc. allow third-party apps to access your data WITHOUT giving them your password!

---

## ✅ After Screenshot

Once you've captured the screenshot:

1. ✅ Save it as `screenshots/fig_oauth2_consent.png`
2. ✅ You can click "Allow" or "Deny" (doesn't matter for the screenshot)
3. ✅ Update the report to reference the actual screenshot

---

## 🎉 All Screenshots Complete!

After this screenshot, you should have all 7:

- [x] Screenshot 1: HIBP breach detection
- [x] Screenshot 2: Account lockout message
- [x] Screenshot 3: CAPTCHA challenge
- [x] Screenshot 4: 2FA QR code
- [x] Screenshot 5: Backup codes
- [x] Screenshot 6: 2FA verification page
- [ ] Screenshot 7: OAuth2 consent screen ← **YOU ARE HERE**

---

## 🔗 Quick Links

- **Server**: http://127.0.0.1:5001
- **Login**: http://127.0.0.1:5001/login
- **Generate new URL**: `python3 generate_oauth_consent_url.py`

---

**Need help?** Check `SCREENSHOT_GUIDE.md` for full details on all 7 screenshots.
