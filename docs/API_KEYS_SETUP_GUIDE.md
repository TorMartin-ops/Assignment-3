# Third-Party API Keys Setup Guide

This guide explains which third-party API keys are needed for full functionality and how to obtain them.

---

## Required API Keys

### 1. Google reCAPTCHA (Brute Force Protection)

**Status:** REQUIRED for production (test keys provided for development)

**Purpose:** Protects login forms from automated brute force attacks

**Current Setup:**
- Test keys are already in `.env.example` (always pass validation)
- Test keys work for local development and testing

**Get Production Keys:**

1. **Visit Google reCAPTCHA Admin Console:**
   - URL: https://www.google.com/recaptcha/admin/create
   - Sign in with your Google account

2. **Create New Site:**
   - **Label:** Your application name (e.g., "Recipe Sharing App")
   - **reCAPTCHA type:** Select **reCAPTCHA v2** → "I'm not a robot" Checkbox
   - **Domains:** Add your production domain(s)
     - Example: `yourdomain.com`
     - For local testing: `localhost` or `127.0.0.1`

3. **Submit and Get Keys:**
   - After creating, you'll receive:
     - **Site Key** (public key - used in HTML)
     - **Secret Key** (private key - used server-side)

4. **Update `.env` File:**
   ```bash
   RECAPTCHA_SITE_KEY=your_site_key_here
   RECAPTCHA_SECRET_KEY=your_secret_key_here
   ```

**Cost:** FREE (100% free for unlimited requests)

---

## Optional API Keys

### 2. Google OAuth2 (Social Login)

**Status:** OPTIONAL (application has built-in username/password authentication)

**Purpose:** Allow users to sign in with their Google account

**Get Google OAuth2 Credentials:**

1. **Visit Google Cloud Console:**
   - URL: https://console.cloud.google.com/

2. **Create or Select Project:**
   - Click project dropdown → "New Project"
   - Name: "Recipe App OAuth"
   - Click "Create"

3. **Enable Google+ API:**
   - Navigate to: APIs & Services → Library
   - Search: "Google+ API" or "Google Identity"
   - Click "Enable"

4. **Configure OAuth Consent Screen:**
   - APIs & Services → OAuth consent screen
   - User Type: **External** (for public apps)
   - App name: Your application name
   - User support email: Your email
   - Developer contact: Your email
   - Save and Continue through all steps

5. **Create OAuth2 Credentials:**
   - APIs & Services → Credentials
   - Click "+ CREATE CREDENTIALS" → OAuth client ID
   - Application type: **Web application**
   - Name: "Recipe App Web Client"
   - **Authorized redirect URIs:**
     - `http://localhost:5000/oauth/google/callback` (development)
     - `https://yourdomain.com/oauth/google/callback` (production)
   - Click "Create"

6. **Copy Credentials:**
   - Copy **Client ID** and **Client Secret**

7. **Update `.env` File:**
   ```bash
   GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   ```

**Cost:** FREE

---

### 3. GitHub OAuth2 (Social Login)

**Status:** OPTIONAL

**Purpose:** Allow users to sign in with their GitHub account

**Get GitHub OAuth2 Credentials:**

1. **Visit GitHub Settings:**
   - URL: https://github.com/settings/developers
   - Or: Profile → Settings → Developer settings → OAuth Apps

2. **Create New OAuth App:**
   - Click "New OAuth App"
   - **Application name:** Recipe Sharing App
   - **Homepage URL:**
     - Development: `http://localhost:5000`
     - Production: `https://yourdomain.com`
   - **Authorization callback URL:**
     - Development: `http://localhost:5000/oauth/github/callback`
     - Production: `https://yourdomain.com/oauth/github/callback`
   - Click "Register application"

3. **Generate Client Secret:**
   - Click "Generate a new client secret"
   - Copy the secret immediately (won't be shown again)

4. **Update `.env` File:**
   ```bash
   GITHUB_CLIENT_ID=your_github_client_id
   GITHUB_CLIENT_SECRET=your_github_client_secret
   ```

**Cost:** FREE

---

### 4. Have I Been Pwned (Password Breach Check)

**Status:** OPTIONAL (nice-to-have security feature)

**Purpose:** Check if user passwords have been exposed in known data breaches

**Get HIBP API Key:**

1. **Visit Have I Been Pwned:**
   - URL: https://haveibeenpwned.com/API/Key

2. **Purchase API Key:**
   - Click "Get API Key"
   - Cost: $3.50 USD per month
   - Supports independent security research

3. **Receive API Key:**
   - Sent to your email after payment
   - API key format: 32-character hexadecimal string

4. **Update `.env` File:**
   ```bash
   HIBP_API_KEY=your_32_character_api_key
   ```

**Cost:** $3.50/month (supports Troy Hunt's security research)

**Alternative:** The app works without HIBP - it uses local password validation only

---

### 5. SMTP Email Service (Notifications)

**Status:** OPTIONAL (for production - password resets, security alerts)

**Purpose:** Send email notifications to users

**Option A: Gmail SMTP (Easiest for Testing)**

1. **Enable 2-Factor Authentication:**
   - Go to Google Account settings
   - Security → 2-Step Verification → Enable

2. **Generate App Password:**
   - Security → 2-Step Verification → App passwords
   - Select app: "Mail"
   - Select device: "Other" (enter "Recipe App")
   - Click "Generate"
   - Copy the 16-character password

3. **Update `.env` File:**
   ```bash
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your.email@gmail.com
   SMTP_PASSWORD=your_16_char_app_password
   ```

**Option B: SendGrid (Production Recommended)**

1. **Sign Up for SendGrid:**
   - URL: https://signup.sendgrid.com/
   - Free tier: 100 emails/day

2. **Create API Key:**
   - Settings → API Keys → Create API Key
   - Name: "Recipe App"
   - Permissions: "Full Access" or "Mail Send"
   - Copy the API key

3. **Update `.env` File:**
   ```bash
   SMTP_SERVER=smtp.sendgrid.net
   SMTP_PORT=587
   SMTP_USERNAME=apikey
   SMTP_PASSWORD=your_sendgrid_api_key
   ```

**Option C: AWS SES (Large Scale)**

1. **Sign up for AWS:** https://aws.amazon.com/ses/
2. **Verify email/domain**
3. **Create SMTP credentials**
4. **Update `.env` with AWS SES SMTP settings**

**Cost:**
- Gmail: FREE (with limitations)
- SendGrid: FREE tier (100 emails/day), paid plans from $15/month
- AWS SES: $0.10 per 1,000 emails

---

## Required Environment Variables (Non-API)

### Generate Secret Keys

These are cryptographic secrets you generate yourself (not from third parties):

```bash
# Generate SECRET_KEY (Flask session encryption)
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"

# Generate ENCRYPTION_SALT (TOTP secret encryption)
python3 -c "import secrets; print('ENCRYPTION_SALT=' + secrets.token_hex(16))"
```

**Add to `.env` file:**
```bash
SECRET_KEY=your_generated_64_char_hex_string
ENCRYPTION_SALT=your_generated_32_char_hex_string
```

**CRITICAL:** Never use the example values from `.env.example` in production!

---

## Summary: What Do You Actually Need?

### Minimal Setup (Development/Testing)
```bash
# Required
SECRET_KEY=<generate with command above>
ENCRYPTION_SALT=<generate with command above>
RECAPTCHA_SITE_KEY=6LeIxAcTAAAAAA JcZVRqyHh71UMIEGNQ_MXjiZKhI  # test key
RECAPTCHA_SECRET_KEY=6LeIxAcTAAAAAA GG-vFI1TnRWxMZNFuojJ4WifJWe  # test key
```

**Cost: FREE** - Application fully functional with built-in authentication

---

### Production Setup (Recommended)
```bash
# Required
SECRET_KEY=<generate new for production>
ENCRYPTION_SALT=<generate new for production>
RECAPTCHA_SITE_KEY=<your production Google reCAPTCHA key>
RECAPTCHA_SECRET_KEY=<your production Google reCAPTCHA key>

# Optional but recommended
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=<your SendGrid API key>

# Optional - Social login
GOOGLE_CLIENT_ID=<if enabling Google login>
GOOGLE_CLIENT_SECRET=<if enabling Google login>
GITHUB_CLIENT_ID=<if enabling GitHub login>
GITHUB_CLIENT_SECRET=<if enabling GitHub login>

# Optional - Enhanced security
HIBP_API_KEY=<if you want password breach checking>
```

**Cost:**
- **FREE**: With Gmail SMTP and no HIBP
- **~$3.50/month**: With HIBP only
- **~$15/month**: With SendGrid + HIBP for professional setup

---

## Quick Start Instructions

1. **Copy example environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Generate required secrets:**
   ```bash
   python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
   python3 -c "import secrets; print('ENCRYPTION_SALT=' + secrets.token_hex(16))"
   ```

3. **Edit `.env` and paste the generated values**

4. **For development:** Leave reCAPTCHA test keys as-is

5. **For production:**
   - Get Google reCAPTCHA keys (FREE)
   - Optionally set up SMTP email
   - Optionally add OAuth providers

---

## Testing API Key Configuration

### Test reCAPTCHA
1. Start the application
2. Visit login page
3. Test keys will always validate (green checkmark)
4. Production keys will require solving CAPTCHA

### Test OAuth (if configured)
1. Visit login page
2. Click "Sign in with Google" or "Sign in with GitHub"
3. Complete OAuth flow
4. Should redirect back to application

### Test SMTP (if configured)
1. Trigger password reset or account creation
2. Check email inbox
3. Verify email delivery

---

## Security Best Practices

1. **Never commit `.env` to version control** (already in `.gitignore`)
2. **Rotate secrets regularly** in production
3. **Use different keys for dev/staging/production**
4. **Store production secrets in secure vault** (AWS Secrets Manager, HashiCorp Vault, etc.)
5. **Limit API key permissions** to minimum required
6. **Monitor API usage** for unusual patterns
7. **Set up billing alerts** for paid services

---

## Troubleshooting

### reCAPTCHA not working
- Check site key and secret key match
- Verify domain is registered in reCAPTCHA admin
- Check browser console for errors

### OAuth redirect errors
- Verify redirect URIs exactly match (including protocol http/https)
- Check OAuth app is not in testing mode (Google)
- Verify client ID and secret are correct

### Email not sending
- Check SMTP credentials
- Verify sender email is verified (SendGrid, SES)
- Check spam folder
- Review application logs for SMTP errors

### HIBP API errors
- Verify API key is valid
- Check you haven't exceeded rate limits
- Ensure User-Agent header is set correctly

---

## Support Resources

- **reCAPTCHA:** https://developers.google.com/recaptcha/docs/display
- **Google OAuth:** https://developers.google.com/identity/protocols/oauth2
- **GitHub OAuth:** https://docs.github.com/en/developers/apps/building-oauth-apps
- **HIBP API:** https://haveibeenpwned.com/API/v3
- **SendGrid:** https://docs.sendgrid.com/
- **Flask Environment Variables:** https://flask.palletsprojects.com/en/2.3.x/config/
