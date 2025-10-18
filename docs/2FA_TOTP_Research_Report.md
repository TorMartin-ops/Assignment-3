# Two-Factor Authentication (2FA) with TOTP - Comprehensive Research Report

## Executive Summary

This report provides a comprehensive analysis of implementing Time-based One-Time Password (TOTP) authentication in Python/Flask applications, based on RFC 6238 standards. The research covers algorithm fundamentals, secure implementation patterns, library usage, and security best practices specifically tailored for the existing Flask recipe application.

**Key Findings:**
- TOTP provides robust 2FA when properly implemented with rate limiting and secure storage
- pyotp library offers production-ready TOTP functionality with minimal complexity
- Secret keys MUST be encrypted before database storage (Fernet recommended)
- Rate limiting is critical - TOTP is vulnerable to brute force without proper protection
- Backup codes are essential for account recovery but must be single-use and hashed

---

## 1. TOTP Algorithm Fundamentals (RFC 6238)

### 1.1 Core Algorithm Specification

**RFC 6238** defines TOTP as an extension of HMAC-based One-Time Password (HOTP) algorithm that uses time as the moving factor.

**Basic Formula:**
```
TOTP = HOTP(K, T)
```

Where:
- `K` = Shared secret key between client and server
- `T` = Time steps since Unix epoch: `T = (Current Unix time - T0) / X`
- `T0` = Unix time to start counting (default: 0, i.e., Unix epoch)
- `X` = Time step interval (default: 30 seconds)

### 1.2 Algorithm Requirements

**RFC 6238 Mandates:**
1. Prover (client) and verifier (server) MUST use the same time-step value X
2. Each prover MUST have a unique secret (key)
3. Keys SHOULD be randomly generated or derived using key derivation algorithms
4. Keys SHOULD be of sufficient length (minimum 128 bits recommended, 160 bits preferred)

### 1.3 Hash Functions

**Default:** HMAC-SHA-1 (backward compatibility)
**Recommended:** HMAC-SHA-256 or HMAC-SHA-512 for enhanced security

**Example:** 6-digit TOTP code valid for 30 seconds, regenerated every 30 seconds

### 1.4 Security Properties

- **Time-bound validity:** Codes expire after time window (typically 30-60 seconds)
- **One-time use:** Each code should only be accepted once within its validity window
- **Cryptographic strength:** Security depends on HMAC properties and secret key entropy
- **Synchronization:** Client and server must have reasonably synchronized clocks (±30-60 seconds tolerance)

---

## 2. Secret Key Generation and Secure Storage

### 2.1 Secret Key Generation

**Best Practices:**

#### Using pyotp (Recommended)
```python
import pyotp

# Generate cryptographically secure random base32 secret
secret = pyotp.random_base32()  # Returns 16-character base32 string
# Example output: 'JBSWY3DPEHPK3PXP'
```

**Key Characteristics:**
- **Length:** 16 characters base32-encoded (80 bits entropy minimum, 160 bits recommended)
- **Encoding:** Base32 (A-Z, 2-7) - compatible with Google Authenticator and other apps
- **Randomness:** Must use cryptographically secure random number generator
- **Uniqueness:** Each user MUST have a unique secret

#### Manual Generation (Alternative)
```python
import secrets
import base64

# Generate 20 random bytes (160 bits)
random_bytes = secrets.token_bytes(20)
# Encode as base32
secret = base64.b32encode(random_bytes).decode('utf-8')
```

### 2.2 Secure Storage - Critical Security Requirement

**❌ NEVER store secrets in plain text**

**✅ Required: Encryption before database storage**

#### Recommended: Fernet Encryption (cryptography library)

**Why Fernet?**
- Symmetric authenticated encryption (AES-128 CBC with HMAC)
- Guarantees confidentiality, integrity, and authentication
- Built-in key derivation and timestamp handling
- Simple API, hard to misuse

**Implementation:**

```python
from cryptography.fernet import Fernet
import os

# 1. Generate and store encryption key (ONE TIME - store securely!)
# Store in environment variable, NOT in code
encryption_key = Fernet.generate_key()
# Store this in: environment variable, AWS Secrets Manager, Azure Key Vault, etc.

# 2. Initialize Fernet instance
def get_cipher():
    """Get Fernet cipher using key from environment"""
    key = os.environ.get('TOTP_ENCRYPTION_KEY')
    if not key:
        raise ValueError("TOTP_ENCRYPTION_KEY not set in environment")
    return Fernet(key.encode())

# 3. Encrypt before storing in database
def encrypt_totp_secret(secret):
    """Encrypt TOTP secret for database storage"""
    cipher = get_cipher()
    encrypted = cipher.encrypt(secret.encode())
    return encrypted.decode('utf-8')  # Store as string

# 4. Decrypt when verifying TOTP
def decrypt_totp_secret(encrypted_secret):
    """Decrypt TOTP secret from database"""
    cipher = get_cipher()
    decrypted = cipher.decrypt(encrypted_secret.encode())
    return decrypted.decode('utf-8')

# Usage example
secret = pyotp.random_base32()
encrypted_secret = encrypt_totp_secret(secret)
# Store encrypted_secret in database

# Later, when verifying:
decrypted_secret = decrypt_totp_secret(encrypted_secret)
totp = pyotp.TOTP(decrypted_secret)
```

**Key Management Best Practices:**
1. **Never hardcode encryption keys** - use environment variables or secret management services
2. **Rotate encryption keys periodically** - implement key versioning for re-encryption
3. **Separate encryption keys by environment** - dev/staging/production should use different keys
4. **Use managed secret services in production:**
   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault
   - Google Cloud Secret Manager

### 2.3 Database Schema Design

**SQLite Schema (matches existing app.py):**

```sql
-- Add to existing users table
ALTER TABLE users ADD COLUMN totp_secret TEXT;  -- Stores ENCRYPTED secret
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_backup_codes TEXT;  -- JSON array of HASHED codes

-- Migration for existing database
-- Note: In production, use proper migration tool (Alembic, Flask-Migrate)
```

**SQLAlchemy Model (if migrating to SQLAlchemy):**

```python
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    # 2FA TOTP fields
    totp_secret = db.Column(db.String(200))  # Encrypted secret (longer for encrypted data)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    totp_backup_codes = db.Column(db.Text)  # JSON array of hashed backup codes
    totp_failed_attempts = db.Column(db.Integer, default=0)  # Rate limiting counter
    totp_lockout_until = db.Column(db.DateTime)  # Account lockout timestamp

    bio = db.Column(db.Text)
    avatar_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```

**Security Considerations:**
- **totp_secret:** Stores encrypted secret (longer field to accommodate encrypted data + encoding)
- **totp_backup_codes:** JSON array of HASHED backup codes (never store plain text)
- **totp_failed_attempts:** Counter for rate limiting failed verification attempts
- **totp_lockout_until:** Timestamp for temporary account lockout after too many failures

---

## 3. QR Code Generation for Authenticator Apps

### 3.1 Provisioning URI Format

TOTP-compatible authenticator apps (Google Authenticator, Authy, Microsoft Authenticator, etc.) use the **otpauth URI scheme**:

```
otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER
```

**Parameters:**
- `ISSUER`: Application name (e.g., "RecipeApp", "MyService")
- `ACCOUNT`: User identifier (email or username, e.g., "user@example.com")
- `SECRET`: Base32-encoded secret key
- `issuer`: Same as ISSUER (for redundancy and app compatibility)

### 3.2 Implementation with pyotp

**Generate Provisioning URI:**

```python
import pyotp

def generate_totp_uri(secret, username, issuer_name="Recipe App"):
    """
    Generate TOTP provisioning URI for QR code

    Args:
        secret: Base32-encoded TOTP secret
        username: User's email or username
        issuer_name: Application name

    Returns:
        str: otpauth:// URI for QR code generation
    """
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=username,
        issuer_name=issuer_name
    )
    return uri

# Example usage
secret = pyotp.random_base32()
uri = generate_totp_uri(secret, "user@example.com")
# Output: otpauth://totp/Recipe%20App:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Recipe%20App
```

### 3.3 QR Code Generation

**Install Required Libraries:**
```bash
pip install qrcode[pil]  # Includes Pillow for image generation
```

**Method 1: Generate QR Code Image (Save to File)**

```python
import qrcode
import io

def generate_qr_code_file(uri, filepath):
    """
    Generate QR code image file from provisioning URI

    Args:
        uri: otpauth:// provisioning URI
        filepath: Path to save QR code image
    """
    qr = qrcode.QRCode(
        version=1,  # Controls size (1 = smallest, 40 = largest)
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,  # Size of each box in pixels
        border=4,  # Border size in boxes
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filepath)
    print(f"QR code saved to {filepath}")

# Usage
uri = generate_totp_uri(secret, "user@example.com")
generate_qr_code_file(uri, "totp_qr.png")
```

**Method 2: Generate QR Code as Base64 (For Web Display - Recommended for Flask)**

```python
import qrcode
import io
import base64

def generate_qr_code_base64(uri):
    """
    Generate QR code as base64-encoded image for HTML embedding

    Args:
        uri: otpauth:// provisioning URI

    Returns:
        str: Base64-encoded PNG image (data URI format)
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # Save to in-memory buffer
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)

    # Encode as base64
    img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    # Return as data URI for HTML <img> tag
    return f"data:image/png;base64,{img_base64}"

# Flask route example
@app.route('/setup-2fa')
@login_required
def setup_2fa():
    # Generate secret and URI
    secret = pyotp.random_base32()
    uri = generate_totp_uri(secret, session.get('username'))

    # Generate QR code as base64
    qr_code_data = generate_qr_code_base64(uri)

    # Store secret temporarily in session (NOT yet in database)
    session['totp_secret_temp'] = secret

    return render_template('setup_2fa.html',
                         qr_code=qr_code_data,
                         secret=secret)  # Also show secret as text for manual entry
```

**HTML Template (setup_2fa.html):**

```html
<div class="container">
    <h2>Set Up Two-Factor Authentication</h2>

    <div class="instructions">
        <h3>Step 1: Install an Authenticator App</h3>
        <p>Download one of these apps on your mobile device:</p>
        <ul>
            <li>Google Authenticator (iOS/Android)</li>
            <li>Authy (iOS/Android)</li>
            <li>Microsoft Authenticator (iOS/Android)</li>
            <li>FreeOTP (iOS/Android)</li>
        </ul>

        <h3>Step 2: Scan QR Code</h3>
        <p>Open your authenticator app and scan this QR code:</p>
        <img src="{{ qr_code }}" alt="TOTP QR Code" style="max-width: 300px;">

        <h3>Manual Entry Alternative</h3>
        <p>Can't scan? Enter this key manually in your app:</p>
        <code style="font-size: 1.2em; background: #f4f4f4; padding: 10px; display: block;">
            {{ secret }}
        </code>

        <h3>Step 3: Verify Setup</h3>
        <p>Enter the 6-digit code from your authenticator app to complete setup:</p>
        <form method="POST" action="{{ url_for('verify_2fa_setup') }}">
            <input type="text" name="totp_code" placeholder="000000" maxlength="6"
                   pattern="[0-9]{6}" required autofocus>
            <button type="submit">Verify & Enable 2FA</button>
        </form>
    </div>
</div>
```

### 3.4 Security Considerations for QR Code Display

**Important Security Practices:**

1. **Never log or store QR code images permanently** - Generate on-demand only
2. **Use HTTPS for QR code display** - Prevent MITM attacks during setup
3. **Temporary secret storage:** Store secret in session, not database, until verified
4. **One-time display:** After successful verification, don't show QR again (require re-setup)
5. **Show secret as text too:** Allows manual entry if QR scanning fails
6. **Clear session after setup:** Remove temporary secret from session after successful verification

**Rate Limiting for Setup:**
```python
# Prevent abuse of 2FA setup endpoint
from functools import wraps
from time import time

# Store in session or Redis
setup_attempts = {}

def rate_limit_setup(max_attempts=3, window=3600):
    """Rate limit 2FA setup attempts per user"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = session.get('user_id')
            key = f"2fa_setup_{user_id}"

            now = time()
            attempts = setup_attempts.get(key, [])

            # Remove old attempts outside window
            attempts = [t for t in attempts if now - t < window]

            if len(attempts) >= max_attempts:
                flash('Too many setup attempts. Please try again later.', 'danger')
                return redirect(url_for('home'))

            attempts.append(now)
            setup_attempts[key] = attempts

            return f(*args, **kwargs)
        return wrapped
    return decorator
```

---

## 4. Backup Codes Implementation

### 4.1 What Are Backup Codes?

**Purpose:** Single-use recovery codes that allow account access when TOTP device is unavailable (lost phone, broken device, etc.)

**Key Characteristics:**
- **Independent from TOTP:** Not generated from TOTP algorithm
- **Single-use:** Each code can only be used once, then invalidated
- **Long-lived:** Valid indefinitely until used (unlike time-limited TOTP)
- **Higher entropy:** Typically 8-12 characters (vs 6-digit TOTP)
- **Last resort:** Emergency access method, not primary 2FA

### 4.2 Generation Best Practices

**Recommended Format:**
- 10 backup codes
- 8-12 characters each
- Mix of letters and numbers (or just numbers for simplicity)
- Grouped for readability (e.g., "1234-5678" or "ABCD-EFGH")

**Implementation:**

```python
import secrets
import hashlib

def generate_backup_codes(count=10, length=8):
    """
    Generate cryptographically secure backup codes

    Args:
        count: Number of backup codes to generate (default: 10)
        length: Length of each code (default: 8)

    Returns:
        list: List of unhashed backup codes (show to user ONCE)
    """
    codes = []
    for _ in range(count):
        # Generate random alphanumeric code
        code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789')
                      for _ in range(length))

        # Format with hyphen for readability
        formatted_code = f"{code[:4]}-{code[4:]}"
        codes.append(formatted_code)

    return codes

def hash_backup_code(code):
    """
    Hash backup code for secure database storage

    Args:
        code: Plain text backup code

    Returns:
        str: SHA-256 hash of the code
    """
    # Remove hyphens before hashing
    clean_code = code.replace('-', '').upper()

    # Use SHA-256 (one-way hash, not reversible)
    hashed = hashlib.sha256(clean_code.encode()).hexdigest()
    return hashed

def verify_backup_code(provided_code, stored_hashes):
    """
    Verify a backup code against stored hashes

    Args:
        provided_code: Code entered by user
        stored_hashes: List of hashed backup codes from database

    Returns:
        tuple: (is_valid, matched_hash) - matched_hash for removal if valid
    """
    clean_code = provided_code.replace('-', '').replace(' ', '').upper()
    provided_hash = hashlib.sha256(clean_code.encode()).hexdigest()

    if provided_hash in stored_hashes:
        return True, provided_hash
    return False, None
```

### 4.3 Storage in Database

**Database Schema:**

```python
# JSON format in database (TEXT column)
import json

def store_backup_codes(user_id, plain_codes):
    """
    Hash and store backup codes in database

    Args:
        user_id: User ID
        plain_codes: List of plain text backup codes

    Returns:
        list: Plain codes to show to user (only time they're displayed)
    """
    # Hash all codes
    hashed_codes = [hash_backup_code(code) for code in plain_codes]

    # Store as JSON array in database
    conn = get_db_connection()
    conn.execute(
        'UPDATE users SET totp_backup_codes = ? WHERE id = ?',
        (json.dumps(hashed_codes), user_id)
    )
    conn.commit()
    conn.close()

    return plain_codes  # Return to display to user

def use_backup_code(user_id, provided_code):
    """
    Verify and invalidate (remove) a backup code

    Args:
        user_id: User ID
        provided_code: Code entered by user

    Returns:
        bool: True if code was valid and removed, False otherwise
    """
    conn = get_db_connection()

    # Get stored backup codes
    user = conn.execute(
        'SELECT totp_backup_codes FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()

    if not user or not user['totp_backup_codes']:
        conn.close()
        return False

    stored_hashes = json.loads(user['totp_backup_codes'])

    # Verify code
    is_valid, matched_hash = verify_backup_code(provided_code, stored_hashes)

    if is_valid:
        # Remove used code from list
        stored_hashes.remove(matched_hash)

        # Update database
        conn.execute(
            'UPDATE users SET totp_backup_codes = ? WHERE id = ?',
            (json.dumps(stored_hashes), user_id)
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

def get_remaining_backup_codes_count(user_id):
    """Get count of remaining (unused) backup codes"""
    conn = get_db_connection()
    user = conn.execute(
        'SELECT totp_backup_codes FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    if not user or not user['totp_backup_codes']:
        return 0

    codes = json.loads(user['totp_backup_codes'])
    return len(codes)
```

### 4.4 User Interface for Backup Codes

**Display to User (One-Time, After 2FA Setup):**

```html
<!-- Show after successful 2FA verification -->
<div class="backup-codes-container">
    <h3>⚠️ Save Your Backup Codes</h3>
    <p><strong>Important:</strong> These codes will only be shown ONCE. Save them securely!</p>

    <div class="codes-grid">
        {% for code in backup_codes %}
        <div class="backup-code">{{ code }}</div>
        {% endfor %}
    </div>

    <div class="backup-instructions">
        <h4>How to Store Backup Codes Safely:</h4>
        <ul>
            <li>✅ Print and store in a safe place</li>
            <li>✅ Save in a password manager (separate from passwords)</li>
            <li>❌ Do NOT store in the same place as your TOTP device</li>
            <li>❌ Do NOT share these codes with anyone</li>
        </ul>

        <p>Each code can only be used once. You have <strong>{{ backup_codes|length }}</strong> codes.</p>
    </div>

    <form method="POST" action="{{ url_for('confirm_backup_codes_saved') }}">
        <label>
            <input type="checkbox" name="confirm" required>
            I have securely saved these backup codes
        </label>
        <button type="submit">Continue</button>
    </form>
</div>

<style>
.codes-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 10px;
    margin: 20px 0;
}
.backup-code {
    font-family: monospace;
    font-size: 1.2em;
    background: #f4f4f4;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
    text-align: center;
}
</style>
```

### 4.5 Security Best Practices for Backup Codes

**DO:**
1. ✅ **Hash before storage** - Never store plain text backup codes
2. ✅ **Single-use enforcement** - Remove from database after use
3. ✅ **Log usage** - Track when backup codes are used (potential security indicator)
4. ✅ **Allow regeneration** - Let users generate new codes (invalidates old ones)
5. ✅ **Show count** - Display remaining backup codes count in user settings
6. ✅ **One-time display** - Show codes only once during generation
7. ✅ **Higher entropy** - Use 8+ character codes (vs 6-digit TOTP)

**DON'T:**
1. ❌ **Don't use predictable patterns** - No sequential numbers or common words
2. ❌ **Don't reuse codes** - Each code must be single-use
3. ❌ **Don't store unhashed** - Always hash before database storage
4. ❌ **Don't salt backup codes** - Salting is unnecessary (codes are already random and single-use)
5. ❌ **Don't rely solely on backup codes** - They're emergency-only, not primary 2FA

**Regeneration Flow:**

```python
@app.route('/regenerate-backup-codes', methods=['POST'])
@login_required
def regenerate_backup_codes():
    """
    Regenerate backup codes (requires TOTP verification)
    This invalidates all old backup codes
    """
    # Require TOTP verification before regenerating
    totp_code = request.form.get('totp_code')

    if not verify_totp_for_user(session['user_id'], totp_code):
        flash('Invalid TOTP code. Verification required to regenerate backup codes.', 'danger')
        return redirect(url_for('security_settings'))

    # Generate new codes
    new_codes = generate_backup_codes(count=10)

    # Store in database (invalidates old codes)
    store_backup_codes(session['user_id'], new_codes)

    # Log this action
    log_security_event(session['user_id'], 'backup_codes_regenerated')

    return render_template('show_backup_codes.html', backup_codes=new_codes)
```

---

## 5. Rate Limiting for TOTP Verification Attempts

### 5.1 Why Rate Limiting is Critical

**Vulnerability Without Rate Limiting:**
- Standard TOTP uses 6-digit codes (1,000,000 possible combinations)
- At 10 attempts/second, brute force can succeed in ~12 hours
- Even with 30-second time windows, attackers can try multiple codes per window

**Real-World Attacks:**
- Microsoft MFA vulnerability (AuthQuake): Accepted codes for 3 minutes instead of 30 seconds
- Proxmox: Fixed by limiting attempts and implementing account lockout
- Multiple services compromised due to missing rate limits

### 5.2 Multi-Layered Rate Limiting Strategy

**Layer 1: Per-Attempt Delays (Progressive Backoff)**

```python
import time
from functools import wraps

def progressive_delay_rate_limit(f):
    """
    Implement progressive delays after failed TOTP attempts
    Delay increases with each failure: 2s, 4s, 8s, 16s, etc.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return f(*args, **kwargs)

        conn = get_db_connection()
        user = conn.execute(
            'SELECT totp_failed_attempts, totp_last_attempt FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        if user:
            failed_attempts = user['totp_failed_attempts'] or 0
            last_attempt = user['totp_last_attempt']

            if failed_attempts > 0 and last_attempt:
                # Calculate required delay: 2^(attempts-1) seconds
                delay_seconds = 2 ** (failed_attempts - 1)
                max_delay = 32  # Cap at 32 seconds
                delay_seconds = min(delay_seconds, max_delay)

                # Check if enough time has passed
                time_since_last = time.time() - float(last_attempt)
                if time_since_last < delay_seconds:
                    remaining = int(delay_seconds - time_since_last)
                    conn.close()
                    flash(f'Too many failed attempts. Please wait {remaining} seconds.', 'danger')
                    return redirect(url_for('login'))

        conn.close()
        return f(*args, **kwargs)
    return wrapped
```

**Layer 2: Maximum Attempts Counter**

```python
MAX_TOTP_ATTEMPTS = 5  # Maximum failed attempts before lockout
LOCKOUT_DURATION = 3600  # 1 hour lockout

def check_totp_lockout(user_id):
    """
    Check if user is locked out due to too many failed TOTP attempts

    Returns:
        tuple: (is_locked_out, remaining_time_seconds)
    """
    conn = get_db_connection()
    user = conn.execute(
        'SELECT totp_lockout_until FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    if user and user['totp_lockout_until']:
        lockout_until = float(user['totp_lockout_until'])
        now = time.time()

        if now < lockout_until:
            remaining = int(lockout_until - now)
            return True, remaining

    return False, 0

def record_failed_totp_attempt(user_id):
    """
    Record failed TOTP attempt and implement lockout if threshold exceeded
    """
    conn = get_db_connection()

    # Increment failed attempts counter
    conn.execute('''
        UPDATE users
        SET totp_failed_attempts = totp_failed_attempts + 1,
            totp_last_attempt = ?
        WHERE id = ?
    ''', (time.time(), user_id))

    # Check if lockout threshold exceeded
    user = conn.execute(
        'SELECT totp_failed_attempts FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()

    if user and user['totp_failed_attempts'] >= MAX_TOTP_ATTEMPTS:
        # Lock account for LOCKOUT_DURATION
        lockout_until = time.time() + LOCKOUT_DURATION
        conn.execute(
            'UPDATE users SET totp_lockout_until = ? WHERE id = ?',
            (lockout_until, user_id)
        )

        # Log security event
        log_security_event(user_id, 'totp_account_locked', {
            'failed_attempts': user['totp_failed_attempts'],
            'lockout_duration': LOCKOUT_DURATION
        })

    conn.commit()
    conn.close()

def reset_totp_attempts(user_id):
    """Reset failed attempts counter after successful verification"""
    conn = get_db_connection()
    conn.execute('''
        UPDATE users
        SET totp_failed_attempts = 0,
            totp_lockout_until = NULL,
            totp_last_attempt = NULL
        WHERE id = ?
    ''', (user_id,))
    conn.commit()
    conn.close()
```

**Layer 3: Atomic Counter Increments (Prevent Race Conditions)**

```python
def atomic_increment_totp_attempts(user_id):
    """
    Atomically increment TOTP attempts to prevent race conditions
    in high-concurrency scenarios
    """
    conn = get_db_connection()

    # SQLite supports atomic operations through transactions
    conn.execute('BEGIN IMMEDIATE')  # Start exclusive transaction

    try:
        conn.execute('''
            UPDATE users
            SET totp_failed_attempts = totp_failed_attempts + 1,
                totp_last_attempt = ?
            WHERE id = ?
        ''', (time.time(), user_id))

        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()
```

**Layer 4: Cross-Session Protection**

```python
# Store in Redis or database (NOT in-memory dict for production)
import redis

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

def check_global_rate_limit(user_id):
    """
    Check global rate limit across all sessions
    Prevents parallel brute force attacks
    """
    key = f"totp_attempts:{user_id}"
    attempts = redis_client.get(key)

    if attempts and int(attempts) >= 10:  # Max 10 attempts per 10 minutes
        ttl = redis_client.ttl(key)
        return False, ttl

    # Increment attempts with 10-minute expiry
    pipeline = redis_client.pipeline()
    pipeline.incr(key)
    pipeline.expire(key, 600)  # 10 minutes
    pipeline.execute()

    return True, 0
```

### 5.3 Complete TOTP Verification with Rate Limiting

```python
def verify_totp_with_rate_limiting(user_id, provided_code):
    """
    Verify TOTP code with comprehensive rate limiting

    Args:
        user_id: User ID
        provided_code: 6-digit TOTP code from user

    Returns:
        tuple: (is_valid, error_message)
    """
    # 1. Check account lockout
    is_locked, remaining_time = check_totp_lockout(user_id)
    if is_locked:
        minutes = remaining_time // 60
        seconds = remaining_time % 60
        return False, f"Account locked due to too many failed attempts. Try again in {minutes}m {seconds}s."

    # 2. Check global rate limit (cross-session)
    allowed, ttl = check_global_rate_limit(user_id)
    if not allowed:
        return False, f"Too many verification attempts. Please wait {ttl} seconds."

    # 3. Get user's encrypted TOTP secret
    conn = get_db_connection()
    user = conn.execute(
        'SELECT totp_secret, totp_enabled FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    conn.close()

    if not user or not user['totp_enabled'] or not user['totp_secret']:
        return False, "2FA not enabled for this account."

    # 4. Decrypt secret
    try:
        decrypted_secret = decrypt_totp_secret(user['totp_secret'])
    except Exception as e:
        log_security_event(user_id, 'totp_decryption_failed', {'error': str(e)})
        return False, "Error verifying code. Please contact support."

    # 5. Verify TOTP code
    totp = pyotp.TOTP(decrypted_secret)

    # Allow 1 time window of drift (±30 seconds) for clock sync issues
    is_valid = totp.verify(provided_code, valid_window=1)

    if is_valid:
        # Success: Reset all rate limiting counters
        reset_totp_attempts(user_id)
        redis_client.delete(f"totp_attempts:{user_id}")

        log_security_event(user_id, 'totp_verification_success')
        return True, None
    else:
        # Failed: Record attempt and check for lockout
        record_failed_totp_attempt(user_id)

        # Get updated attempt count
        conn = get_db_connection()
        user = conn.execute(
            'SELECT totp_failed_attempts FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()
        conn.close()

        remaining_attempts = MAX_TOTP_ATTEMPTS - user['totp_failed_attempts']

        if remaining_attempts <= 0:
            return False, "Account locked due to too many failed attempts."

        log_security_event(user_id, 'totp_verification_failed', {
            'attempts_remaining': remaining_attempts
        })

        return False, f"Invalid code. {remaining_attempts} attempts remaining."
```

### 5.4 Rate Limiting Best Practices Summary

**Essential Protections:**
1. ✅ **Progressive delays:** Exponential backoff (2s, 4s, 8s, 16s, 32s)
2. ✅ **Maximum attempts:** Lock after 5 failed attempts
3. ✅ **Atomic counters:** Prevent race conditions in concurrent attempts
4. ✅ **Cross-session tracking:** Prevent parallel brute force (use Redis/database)
5. ✅ **Time window restriction:** Accept codes only for ±30-60 seconds (valid_window=1)
6. ✅ **Account lockout:** Temporary ban (1 hour) after threshold
7. ✅ **Security logging:** Log all failed attempts and lockouts

**Configuration Parameters:**
- `MAX_TOTP_ATTEMPTS`: 5 (industry standard)
- `LOCKOUT_DURATION`: 3600 seconds (1 hour)
- `TOTP_VALID_WINDOW`: 1 (±30 seconds, total 90 seconds validity)
- `MAX_GLOBAL_ATTEMPTS`: 10 per 10 minutes per user
- `PROGRESSIVE_DELAY_CAP`: 32 seconds maximum delay

---

## 6. Recovery Mechanisms if User Loses Device

### 6.1 Recovery Options Hierarchy

**Primary Recovery Method:**
1. **Backup Codes** (implemented in Section 4)
   - User enters one of their pre-generated backup codes
   - Code is single-use and immediately invalidated
   - Grants temporary access to regenerate 2FA

**Secondary Recovery Methods:**

### 6.2 Account Recovery Flow

**Option 1: Self-Service Recovery (Backup Codes)**

```python
@app.route('/login-2fa', methods=['GET', 'POST'])
def login_2fa():
    """
    2FA verification page with backup code option
    """
    if request.method == 'POST':
        # Check if user provided TOTP or backup code
        code_type = request.form.get('code_type', 'totp')
        provided_code = request.form.get('code')
        user_id = session.get('temp_user_id')  # Stored after successful password auth

        if not user_id:
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))

        if code_type == 'totp':
            # Verify TOTP code
            is_valid, error_msg = verify_totp_with_rate_limiting(user_id, provided_code)
        else:  # backup_code
            # Verify backup code
            is_valid = use_backup_code(user_id, provided_code)
            error_msg = "Invalid or already used backup code." if not is_valid else None

        if is_valid:
            # Complete login
            session['user_id'] = user_id
            session.pop('temp_user_id', None)

            # Warn if backup code was used
            if code_type == 'backup_code':
                remaining = get_remaining_backup_codes_count(user_id)
                flash(f'Backup code used. You have {remaining} codes remaining.', 'warning')

            return redirect(url_for('home'))
        else:
            flash(error_msg or 'Invalid code.', 'danger')

    return render_template('login_2fa.html')
```

**HTML Template (login_2fa.html):**

```html
<div class="2fa-container">
    <h2>Two-Factor Authentication</h2>

    <form method="POST" id="totpForm">
        <input type="hidden" name="code_type" value="totp">

        <div class="form-group">
            <label>Enter 6-digit code from your authenticator app:</label>
            <input type="text" name="code" placeholder="000000"
                   maxlength="6" pattern="[0-9]{6}" required autofocus>
        </div>

        <button type="submit">Verify</button>
    </form>

    <div class="recovery-options">
        <hr>
        <p><strong>Lost your device?</strong></p>
        <button onclick="showBackupCodeForm()">Use a backup code instead</button>
    </div>

    <!-- Hidden backup code form -->
    <form method="POST" id="backupForm" style="display: none;">
        <input type="hidden" name="code_type" value="backup_code">

        <div class="form-group">
            <label>Enter backup code:</label>
            <input type="text" name="code" placeholder="XXXX-XXXX"
                   maxlength="9" required>
            <small>Format: XXXX-XXXX (e.g., AB12-CD34)</small>
        </div>

        <button type="submit">Verify Backup Code</button>
        <button type="button" onclick="showTotpForm()">Cancel</button>
    </form>
</div>

<script>
function showBackupCodeForm() {
    document.getElementById('totpForm').style.display = 'none';
    document.getElementById('backupForm').style.display = 'block';
}

function showTotpForm() {
    document.getElementById('backupForm').style.display = 'none';
    document.getElementById('totpForm').style.display = 'block';
}
</script>
```

**Option 2: Email-Based Recovery (Last Resort)**

```python
import secrets
from datetime import datetime, timedelta

def generate_recovery_token(user_id):
    """
    Generate one-time recovery token for email-based recovery
    Valid for 1 hour only
    """
    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1)

    conn = get_db_connection()
    conn.execute('''
        UPDATE users
        SET recovery_token = ?,
            recovery_token_expiry = ?
        WHERE id = ?
    ''', (token, expiry.isoformat(), user_id))
    conn.commit()
    conn.close()

    return token

@app.route('/request-2fa-recovery', methods=['GET', 'POST'])
def request_2fa_recovery():
    """
    Request email-based 2FA recovery link
    """
    if request.method == 'POST':
        email = request.form.get('email')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT id, username, totp_enabled FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        conn.close()

        if user and user['totp_enabled']:
            # Generate recovery token
            token = generate_recovery_token(user['id'])

            # Send recovery email
            recovery_url = url_for('verify_recovery_token',
                                  token=token,
                                  _external=True)

            send_recovery_email(email, user['username'], recovery_url)

            # Log this action
            log_security_event(user['id'], '2fa_recovery_requested', {
                'ip': request.remote_addr
            })

        # Always show success (prevent email enumeration)
        flash('If an account exists with that email, a recovery link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('request_2fa_recovery.html')

@app.route('/recover-2fa/<token>', methods=['GET', 'POST'])
def verify_recovery_token(token):
    """
    Verify recovery token and allow user to disable/reset 2FA
    """
    conn = get_db_connection()
    user = conn.execute('''
        SELECT id, username, recovery_token, recovery_token_expiry
        FROM users
        WHERE recovery_token = ?
    ''', (token,)).fetchone()

    if not user:
        flash('Invalid or expired recovery link.', 'danger')
        return redirect(url_for('login'))

    # Check expiry
    expiry = datetime.fromisoformat(user['recovery_token_expiry'])
    if datetime.utcnow() > expiry:
        flash('Recovery link has expired. Please request a new one.', 'danger')
        return redirect(url_for('request_2fa_recovery'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'disable':
            # Disable 2FA completely
            conn.execute('''
                UPDATE users
                SET totp_enabled = 0,
                    totp_secret = NULL,
                    totp_backup_codes = NULL,
                    recovery_token = NULL,
                    recovery_token_expiry = NULL
                WHERE id = ?
            ''', (user['id'],))
            conn.commit()

            log_security_event(user['id'], '2fa_disabled_via_recovery')
            flash('2FA has been disabled. You can re-enable it in your account settings.', 'warning')

        elif action == 'reset':
            # Reset 2FA (user will need to set up again)
            conn.execute('''
                UPDATE users
                SET totp_secret = NULL,
                    totp_backup_codes = NULL,
                    totp_enabled = 0,
                    recovery_token = NULL,
                    recovery_token_expiry = NULL
                WHERE id = ?
            ''', (user['id'],))
            conn.commit()

            # Log in user and redirect to 2FA setup
            session['user_id'] = user['id']
            log_security_event(user['id'], '2fa_reset_via_recovery')
            flash('2FA has been reset. Please set up 2FA again.', 'info')
            return redirect(url_for('setup_2fa'))

        conn.close()
        return redirect(url_for('login'))

    conn.close()
    return render_template('verify_recovery.html', username=user['username'])
```

### 6.3 Recovery Best Practices

**DO:**
1. ✅ **Prioritize backup codes** - Fastest, most secure recovery method
2. ✅ **Warn about remaining codes** - Notify user when backup codes are used
3. ✅ **Time-limited recovery tokens** - Email tokens expire in 1 hour
4. ✅ **Log all recovery actions** - Track for security monitoring
5. ✅ **Require re-setup after email recovery** - Don't just disable 2FA permanently
6. ✅ **Show remaining backup codes count** - In user settings dashboard
7. ✅ **Allow backup code regeneration** - Let users generate new codes (requires TOTP verification)

**DON'T:**
1. ❌ **Don't allow SMS recovery** - SMS is vulnerable to SIM swapping attacks
2. ❌ **Don't skip verification** - Always verify identity before recovery
3. ❌ **Don't make recovery too easy** - Balance usability with security
4. ❌ **Don't expose user existence** - Use same message for valid/invalid emails
5. ❌ **Don't allow unlimited recovery attempts** - Rate limit recovery token requests

**Recovery Flow Summary:**

```
User loses 2FA device
    ↓
Option 1: Has backup codes?
    → Yes: Enter backup code → Login successful → Regenerate backup codes
    → No: Proceed to Option 2
    ↓
Option 2: Request email recovery
    → Verify email ownership → Click recovery link
    → Choose: Disable 2FA OR Reset and re-setup
    → If Reset: Set up new TOTP → Generate new backup codes
```

---

## 7. pyotp Library Usage Patterns and Security Considerations

### 7.1 Core pyotp Classes

**TOTP Class (Time-based)**
```python
import pyotp

# Create TOTP instance
totp = pyotp.TOTP('JBSWY3DPEHPK3PXP')  # Base32-encoded secret

# Generate current code
current_code = totp.now()  # Returns string like '492039'

# Verify code
is_valid = totp.verify('492039')  # Returns True/False

# Verify with time drift tolerance
is_valid = totp.verify('492039', valid_window=1)  # ±30 seconds
```

**HOTP Class (Counter-based) - Not Recommended for 2FA**
```python
# HOTP uses counter instead of time
hotp = pyotp.HOTP('JBSWY3DPEHPK3PXP')
code = hotp.at(0)  # Generate code for counter=0
```

### 7.2 Advanced pyotp Configuration

**Custom Time Step (Default: 30 seconds)**
```python
# Use 60-second time steps (less user-friendly, more secure)
totp = pyotp.TOTP('SECRET', interval=60)

# Use 15-second steps (more user-friendly, less secure)
totp = pyotp.TOTP('SECRET', interval=15)  # Not recommended
```

**Custom Digest Algorithm**
```python
import hashlib

# Default: SHA-1
totp_sha1 = pyotp.TOTP('SECRET')  # Uses SHA-1

# More secure: SHA-256
totp_sha256 = pyotp.TOTP('SECRET', digest=hashlib.sha256)

# Most secure: SHA-512
totp_sha512 = pyotp.TOTP('SECRET', digest=hashlib.sha512)
```

**Custom Code Length**
```python
# Default: 6 digits
totp_6 = pyotp.TOTP('SECRET')  # 6-digit codes

# 8 digits (more secure, less compatible)
totp_8 = pyotp.TOTP('SECRET', digits=8)

# Note: Google Authenticator only supports 6 digits
```

### 7.3 Provisioning URI Generation

**Basic URI**
```python
totp = pyotp.TOTP('JBSWY3DPEHPK3PXP')
uri = totp.provisioning_uri(
    name='user@example.com',
    issuer_name='Recipe App'
)
# Output: otpauth://totp/Recipe%20App:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Recipe%20App
```

**URI with Custom Parameters**
```python
totp = pyotp.TOTP(
    'JBSWY3DPEHPK3PXP',
    interval=60,      # 60-second time steps
    digits=8,         # 8-digit codes
    digest=hashlib.sha256  # SHA-256 instead of SHA-1
)

uri = totp.provisioning_uri(
    name='user@example.com',
    issuer_name='Recipe App'
)
# URI includes all custom parameters for authenticator app
```

### 7.4 Time Window Handling

**Understanding valid_window Parameter:**

```python
totp = pyotp.TOTP('SECRET')

# valid_window=0 (default): Only accept codes for current 30-second window
is_valid = totp.verify('123456', valid_window=0)

# valid_window=1: Accept codes for ±1 time window (90 seconds total)
# Current window + 1 past + 1 future
is_valid = totp.verify('123456', valid_window=1)  # Recommended

# valid_window=2: Accept ±2 windows (150 seconds total)
# Not recommended - increases attack window
```

**Visual Representation:**
```
valid_window=0:  [Current 30s window only]
valid_window=1:  [Past 30s] [Current 30s] [Future 30s]  ← Recommended
valid_window=2:  [Past 60s] [Current 30s] [Future 60s]  ← Too permissive
```

### 7.5 Security Considerations

**Critical Security Issues:**

1. **⚠️ No Built-in Rate Limiting**
   - pyotp does NOT implement rate limiting
   - **You MUST implement this yourself** (see Section 5)

2. **⚠️ No Replay Attack Prevention**
   - pyotp does NOT track used codes
   - Same code can be verified multiple times within time window
   - **Solution:** Track used codes in database or cache

```python
# Redis-based replay prevention
import redis
redis_client = redis.Redis()

def verify_totp_with_replay_protection(user_id, code):
    """Verify TOTP and prevent replay attacks"""
    totp = pyotp.TOTP(get_user_secret(user_id))

    # Check if code was already used
    code_key = f"totp_used:{user_id}:{code}"
    if redis_client.exists(code_key):
        return False  # Code already used

    # Verify code
    is_valid = totp.verify(code, valid_window=1)

    if is_valid:
        # Mark code as used (expires after 90 seconds - max valid window)
        redis_client.setex(code_key, 90, '1')

    return is_valid
```

3. **⚠️ Clock Synchronization Dependency**
   - TOTP requires synchronized clocks between client and server
   - **Solution:** Use valid_window=1 to tolerate ±30 seconds drift
   - **Monitoring:** Log time drift issues for investigation

4. **⚠️ Secret Key Management**
   - pyotp does NOT handle secret encryption
   - **You MUST encrypt secrets** before database storage (see Section 2)

5. **⚠️ No Session Management**
   - pyotp is stateless
   - **You MUST implement** session handling, lockouts, attempt tracking

### 7.6 Common Pitfalls and Solutions

**Pitfall 1: Using verify() Multiple Times**
```python
# ❌ WRONG: Multiple verify() calls consume time
if not totp.verify(code):
    # Time passes...
    if not totp.verify(code):  # Might fail even if code was valid
        pass

# ✅ CORRECT: Store verification result
is_valid = totp.verify(code, valid_window=1)
if is_valid:
    # Process valid code
else:
    # Handle invalid code
```

**Pitfall 2: Ignoring Time Window**
```python
# ❌ WRONG: Too strict, causes legitimate failures due to clock drift
is_valid = totp.verify(code, valid_window=0)

# ✅ CORRECT: Allow 1 window of drift
is_valid = totp.verify(code, valid_window=1)
```

**Pitfall 3: Not Handling Exceptions**
```python
# ❌ WRONG: Crashes on invalid input
code = "invalid"
is_valid = totp.verify(code)  # May raise exception

# ✅ CORRECT: Handle invalid input
try:
    is_valid = totp.verify(code, valid_window=1)
except Exception as e:
    log_error(f"TOTP verification error: {e}")
    is_valid = False
```

**Pitfall 4: Exposing Secrets in Logs**
```python
# ❌ WRONG: Logs secret key
print(f"Verifying TOTP for secret: {secret}")

# ✅ CORRECT: Never log secrets
print(f"Verifying TOTP for user: {user_id}")
```

### 7.7 Production-Ready pyotp Usage Pattern

```python
import pyotp
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

class TOTPService:
    """Production-ready TOTP service wrapper around pyotp"""

    def __init__(self, interval=30, valid_window=1, digits=6):
        """
        Initialize TOTP service

        Args:
            interval: Time step in seconds (default: 30)
            valid_window: Number of time windows to accept (default: 1 = ±30s)
            digits: Number of digits in code (default: 6)
        """
        self.interval = interval
        self.valid_window = valid_window
        self.digits = digits

    def generate_secret(self) -> str:
        """Generate cryptographically secure random secret"""
        return pyotp.random_base32()

    def get_totp(self, secret: str) -> pyotp.TOTP:
        """Create TOTP instance with configured parameters"""
        return pyotp.TOTP(
            secret,
            interval=self.interval,
            digits=self.digits
        )

    def generate_code(self, secret: str) -> str:
        """Generate current TOTP code"""
        try:
            totp = self.get_totp(secret)
            return totp.now()
        except Exception as e:
            logger.error(f"Error generating TOTP code: {e}")
            raise

    def verify_code(self, secret: str, code: str) -> Tuple[bool, str]:
        """
        Verify TOTP code with comprehensive error handling

        Args:
            secret: User's TOTP secret (decrypted)
            code: Code provided by user

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Validate input format
            if not code or not code.isdigit() or len(code) != self.digits:
                return False, f"Invalid code format. Expected {self.digits} digits."

            # Create TOTP instance and verify
            totp = self.get_totp(secret)
            is_valid = totp.verify(code, valid_window=self.valid_window)

            if is_valid:
                logger.info("TOTP verification successful")
                return True, None
            else:
                logger.warning("TOTP verification failed - invalid code")
                return False, "Invalid code or code expired."

        except Exception as e:
            logger.error(f"TOTP verification error: {e}")
            return False, "Error verifying code. Please try again."

    def generate_provisioning_uri(self, secret: str, username: str,
                                  issuer: str = "Recipe App") -> str:
        """
        Generate provisioning URI for QR code

        Args:
            secret: User's TOTP secret
            username: User's email or username
            issuer: Application name

        Returns:
            otpauth:// URI string
        """
        try:
            totp = self.get_totp(secret)
            return totp.provisioning_uri(name=username, issuer_name=issuer)
        except Exception as e:
            logger.error(f"Error generating provisioning URI: {e}")
            raise

# Usage
totp_service = TOTPService()

# Generate secret
secret = totp_service.generate_secret()

# Verify code
is_valid, error = totp_service.verify_code(secret, "123456")
```

---

## 8. Integration Patterns with Existing Flask Authentication

### 8.1 Current Authentication Analysis

**Existing App Structure (app.py):**
- Uses Flask sessions for authentication
- Password hashing with `werkzeug.security`
- Custom `@login_required` decorator
- SQLite database with `users` table

**Integration Points:**
1. Login flow (after password verification)
2. User registration (optional 2FA prompt)
3. Account settings (enable/disable 2FA)
4. Session management

### 8.2 Database Schema Migration

**Step 1: Add 2FA Columns to Existing Database**

```python
# database.py - Add to init_database() function

def migrate_add_2fa_columns():
    """Add 2FA columns to existing users table"""
    conn = get_db_connection()

    try:
        # Check if columns already exist
        cursor = conn.execute("PRAGMA table_info(users)")
        columns = [row['name'] for row in cursor.fetchall()]

        if 'totp_secret' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
            print("Added totp_secret column")

        if 'totp_enabled' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0')
            print("Added totp_enabled column")

        if 'totp_backup_codes' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN totp_backup_codes TEXT')
            print("Added totp_backup_codes column")

        if 'totp_failed_attempts' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN totp_failed_attempts INTEGER DEFAULT 0')
            print("Added totp_failed_attempts column")

        if 'totp_lockout_until' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN totp_lockout_until TEXT')
            print("Added totp_lockout_until column")

        if 'totp_last_attempt' not in columns:
            conn.execute('ALTER TABLE users ADD COLUMN totp_last_attempt TEXT')
            print("Added totp_last_attempt column")

        conn.commit()
        print("✓ 2FA database migration completed successfully")

    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

# Run migration
if __name__ == '__main__':
    init_database()  # Existing function
    migrate_add_2fa_columns()  # New migration
```

### 8.3 Modified Login Flow with 2FA

**Update Login Route:**

```python
# app.py - Replace existing login route

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login with 2FA support"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # Password correct - check if 2FA is enabled
            if user['totp_enabled']:
                # Store user ID temporarily for 2FA verification
                session['temp_user_id'] = user['id']
                session['temp_username'] = user['username']

                flash('Password correct. Please enter your 2FA code.', 'info')
                return redirect(url_for('verify_2fa'))
            else:
                # No 2FA - log in directly
                session['user_id'] = user['id']
                session['username'] = user['username']

                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'danger')

    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """2FA verification page"""
    temp_user_id = session.get('temp_user_id')

    if not temp_user_id:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        code_type = request.form.get('code_type', 'totp')
        provided_code = request.form.get('code')

        if code_type == 'totp':
            # Verify TOTP code with rate limiting
            is_valid, error_msg = verify_totp_with_rate_limiting(temp_user_id, provided_code)
        else:  # backup_code
            is_valid = use_backup_code(temp_user_id, provided_code)
            error_msg = "Invalid or already used backup code." if not is_valid else None

        if is_valid:
            # Complete login
            session['user_id'] = temp_user_id
            session['username'] = session.get('temp_username')

            # Clean up temporary session data
            session.pop('temp_user_id', None)
            session.pop('temp_username', None)

            # Warn if backup code was used
            if code_type == 'backup_code':
                remaining = get_remaining_backup_codes_count(temp_user_id)
                flash(f'Login successful! Backup code used. You have {remaining} codes remaining.', 'warning')
            else:
                flash('Login successful!', 'success')

            return redirect(url_for('home'))
        else:
            flash(error_msg or 'Invalid code.', 'danger')

    return render_template('verify_2fa.html')
```

### 8.4 2FA Setup Flow

**Setup Routes:**

```python
# app.py - Add 2FA setup routes

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    """Initiate 2FA setup"""
    user_id = session.get('user_id')

    # Check if 2FA already enabled
    conn = get_db_connection()
    user = conn.execute('SELECT totp_enabled FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()

    if user and user['totp_enabled']:
        flash('2FA is already enabled on your account.', 'info')
        return redirect(url_for('security_settings'))

    # Generate new secret
    secret = pyotp.random_base32()

    # Store temporarily in session (NOT in database yet)
    session['totp_secret_temp'] = secret

    # Generate QR code
    uri = generate_totp_uri(secret, session.get('username'))
    qr_code_data = generate_qr_code_base64(uri)

    return render_template('setup_2fa.html',
                         qr_code=qr_code_data,
                         secret=secret)

@app.route('/verify-2fa-setup', methods=['POST'])
@login_required
def verify_2fa_setup():
    """Verify 2FA setup with test code"""
    user_id = session.get('user_id')
    temp_secret = session.get('totp_secret_temp')
    provided_code = request.form.get('totp_code')

    if not temp_secret:
        flash('Setup session expired. Please start again.', 'warning')
        return redirect(url_for('setup_2fa'))

    # Verify the test code
    totp = pyotp.TOTP(temp_secret)
    is_valid = totp.verify(provided_code, valid_window=1)

    if is_valid:
        # Encrypt and store secret in database
        encrypted_secret = encrypt_totp_secret(temp_secret)

        # Generate backup codes
        backup_codes = generate_backup_codes(count=10)

        # Store in database
        conn = get_db_connection()
        conn.execute('''
            UPDATE users
            SET totp_secret = ?, totp_enabled = 1
            WHERE id = ?
        ''', (encrypted_secret, user_id))
        conn.commit()
        conn.close()

        # Store backup codes
        store_backup_codes(user_id, backup_codes)

        # Clear temporary session data
        session.pop('totp_secret_temp', None)

        # Show backup codes
        session['backup_codes_display'] = backup_codes
        return redirect(url_for('show_backup_codes'))
    else:
        flash('Invalid code. Please try again.', 'danger')
        return redirect(url_for('setup_2fa'))

@app.route('/show-backup-codes')
@login_required
def show_backup_codes():
    """Display backup codes (one-time only)"""
    backup_codes = session.get('backup_codes_display')

    if not backup_codes:
        flash('No backup codes to display.', 'warning')
        return redirect(url_for('security_settings'))

    return render_template('show_backup_codes.html', backup_codes=backup_codes)

@app.route('/confirm-backup-codes-saved', methods=['POST'])
@login_required
def confirm_backup_codes_saved():
    """User confirms they saved backup codes"""
    # Clear from session
    session.pop('backup_codes_display', None)

    flash('2FA setup complete! Your account is now more secure.', 'success')
    return redirect(url_for('security_settings'))

@app.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Disable 2FA (requires TOTP verification)"""
    user_id = session.get('user_id')
    totp_code = request.form.get('totp_code')

    # Verify TOTP before disabling
    is_valid, error_msg = verify_totp_with_rate_limiting(user_id, totp_code)

    if not is_valid:
        flash(error_msg or 'Invalid code. Cannot disable 2FA.', 'danger')
        return redirect(url_for('security_settings'))

    # Disable 2FA
    conn = get_db_connection()
    conn.execute('''
        UPDATE users
        SET totp_enabled = 0,
            totp_secret = NULL,
            totp_backup_codes = NULL,
            totp_failed_attempts = 0,
            totp_lockout_until = NULL
        WHERE id = ?
    ''', (user_id,))
    conn.commit()
    conn.close()

    flash('2FA has been disabled.', 'warning')
    return redirect(url_for('security_settings'))

@app.route('/security-settings')
@login_required
def security_settings():
    """Security settings page"""
    user_id = session.get('user_id')

    conn = get_db_connection()
    user = conn.execute('''
        SELECT totp_enabled, totp_backup_codes
        FROM users
        WHERE id = ?
    ''', (user_id,)).fetchone()
    conn.close()

    backup_codes_count = 0
    if user and user['totp_backup_codes']:
        backup_codes_count = get_remaining_backup_codes_count(user_id)

    return render_template('security_settings.html',
                         totp_enabled=user['totp_enabled'] if user else False,
                         backup_codes_count=backup_codes_count)
```

### 8.5 Updated Requirements.txt

```bash
# Add to existing requirements.txt

# Existing packages
bleach==6.2.0
blinker==1.9.0
click==8.3.0
colorama==0.4.6
Flask==3.1.2
itsdangerous==2.2.0
Jinja2==3.1.6
MarkupSafe==3.0.2
webencodings==0.5.1
Werkzeug==3.1.3

# 2FA packages
pyotp==2.9.0
qrcode[pil]==7.4.2
cryptography==42.0.5
```

### 8.6 Configuration File

```python
# config.py - Create new configuration file

import os

class Config:
    """Application configuration"""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this-in-production'

    # Database
    DATABASE = 'recipe_app.db'

    # 2FA Configuration
    TOTP_ISSUER_NAME = "Recipe App"
    TOTP_INTERVAL = 30  # Time step in seconds
    TOTP_DIGITS = 6  # Number of digits in TOTP code
    TOTP_VALID_WINDOW = 1  # ±30 seconds tolerance

    # Rate Limiting
    TOTP_MAX_ATTEMPTS = 5  # Max failed attempts before lockout
    TOTP_LOCKOUT_DURATION = 3600  # 1 hour in seconds

    # Backup Codes
    BACKUP_CODES_COUNT = 10
    BACKUP_CODES_LENGTH = 8

    # Encryption
    TOTP_ENCRYPTION_KEY = os.environ.get('TOTP_ENCRYPTION_KEY')

    # Security
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

# Usage in app.py
from config import Config
app.config.from_object(Config)
```

### 8.7 Environment Variables (.env)

```bash
# .env - Create for local development
# IMPORTANT: Add .env to .gitignore

SECRET_KEY=your-very-secure-random-secret-key-here
TOTP_ENCRYPTION_KEY=your-fernet-encryption-key-here

# Generate keys with Python:
# import secrets
# print(f"SECRET_KEY={secrets.token_urlsafe(32)}")
#
# from cryptography.fernet import Fernet
# print(f"TOTP_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
```

---

## 9. Complete Implementation Example

### 9.1 Project Structure

```
Assignment-2---Cross-Site-Scripting/
├── app.py                 # Main Flask application
├── database.py            # Database initialization
├── config.py              # Configuration (NEW)
├── totp_service.py        # 2FA service layer (NEW)
├── encryption.py          # Fernet encryption utilities (NEW)
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (NEW - add to .gitignore)
├── templates/
│   ├── login.html
│   ├── verify_2fa.html          # (NEW)
│   ├── setup_2fa.html           # (NEW)
│   ├── show_backup_codes.html   # (NEW)
│   ├── security_settings.html   # (NEW)
│   └── ...
└── static/
    └── ...
```

### 9.2 Helper Module: encryption.py

```python
"""
encryption.py - TOTP secret encryption utilities
"""

from cryptography.fernet import Fernet
import os
import logging

logger = logging.getLogger(__name__)

def get_cipher():
    """
    Get Fernet cipher instance from environment variable

    Returns:
        Fernet: Cipher instance for encryption/decryption

    Raises:
        ValueError: If TOTP_ENCRYPTION_KEY not set
    """
    key = os.environ.get('TOTP_ENCRYPTION_KEY')

    if not key:
        raise ValueError(
            "TOTP_ENCRYPTION_KEY not set in environment. "
            "Generate with: from cryptography.fernet import Fernet; print(Fernet.generate_key())"
        )

    try:
        return Fernet(key.encode())
    except Exception as e:
        logger.error(f"Failed to initialize Fernet cipher: {e}")
        raise

def encrypt_totp_secret(secret: str) -> str:
    """
    Encrypt TOTP secret for database storage

    Args:
        secret: Plain text TOTP secret (base32)

    Returns:
        str: Encrypted secret (base64-encoded)
    """
    try:
        cipher = get_cipher()
        encrypted = cipher.encrypt(secret.encode())
        return encrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting TOTP secret: {e}")
        raise

def decrypt_totp_secret(encrypted_secret: str) -> str:
    """
    Decrypt TOTP secret from database

    Args:
        encrypted_secret: Encrypted secret from database

    Returns:
        str: Plain text TOTP secret (base32)
    """
    try:
        cipher = get_cipher()
        decrypted = cipher.decrypt(encrypted_secret.encode())
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Error decrypting TOTP secret: {e}")
        raise

def generate_encryption_key() -> str:
    """
    Generate new Fernet encryption key

    Returns:
        str: Base64-encoded Fernet key
    """
    return Fernet.generate_key().decode('utf-8')

# Test function
if __name__ == '__main__':
    # Generate a new encryption key
    print("New encryption key (add to .env as TOTP_ENCRYPTION_KEY):")
    print(generate_encryption_key())

    # Test encryption/decryption
    if os.environ.get('TOTP_ENCRYPTION_KEY'):
        test_secret = "JBSWY3DPEHPK3PXP"
        encrypted = encrypt_totp_secret(test_secret)
        decrypted = decrypt_totp_secret(encrypted)

        print(f"\nTest encryption:")
        print(f"Original:  {test_secret}")
        print(f"Encrypted: {encrypted}")
        print(f"Decrypted: {decrypted}")
        print(f"Match: {test_secret == decrypted}")
```

### 9.3 Complete totp_service.py Module

**See Section 7.7 for complete TOTPService class - use that implementation**

### 9.4 Installation and Setup Instructions

**Step 1: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 2: Generate Encryption Key**
```bash
python encryption.py
# Copy output to .env file
```

**Step 3: Create .env File**
```bash
# .env
SECRET_KEY=<generated-secret-key>
TOTP_ENCRYPTION_KEY=<generated-encryption-key>
```

**Step 4: Run Database Migration**
```bash
python database.py
```

**Step 5: Start Application**
```bash
python app.py
```

**Step 6: Test 2FA**
1. Register new account or log in
2. Navigate to Security Settings
3. Click "Enable 2FA"
4. Scan QR code with Google Authenticator
5. Enter test code to verify setup
6. Save backup codes securely
7. Log out and log in again with 2FA

---

## 10. Security Checklist

### 10.1 Implementation Checklist

**Secret Management:**
- [ ] TOTP secrets encrypted before database storage (Fernet)
- [ ] Encryption key stored in environment variable
- [ ] Encryption key NOT in source code
- [ ] Different keys for dev/staging/production
- [ ] Backup codes hashed (SHA-256) before storage
- [ ] Secrets never logged or exposed in errors

**Rate Limiting:**
- [ ] Progressive delays after failed attempts
- [ ] Maximum attempts counter (5 attempts)
- [ ] Account lockout after threshold (1 hour)
- [ ] Atomic counter increments (prevent race conditions)
- [ ] Cross-session protection (Redis or database)
- [ ] Time window restriction (valid_window=1)

**TOTP Configuration:**
- [ ] 30-second time steps (standard)
- [ ] 6-digit codes (Google Authenticator compatible)
- [ ] ±30 second clock drift tolerance (valid_window=1)
- [ ] SHA-1 or SHA-256 hash function
- [ ] Replay attack prevention (track used codes)

**Backup Codes:**
- [ ] 10 backup codes generated
- [ ] 8+ character codes (high entropy)
- [ ] Hashed before storage (SHA-256)
- [ ] Single-use enforcement (delete after use)
- [ ] One-time display to user
- [ ] Regeneration requires TOTP verification

**Recovery Mechanisms:**
- [ ] Backup codes as primary recovery
- [ ] Email recovery as fallback
- [ ] Time-limited recovery tokens (1 hour)
- [ ] Log all recovery actions
- [ ] Require re-setup after email recovery

**User Experience:**
- [ ] QR code generation for easy setup
- [ ] Manual secret entry option
- [ ] Clear setup instructions
- [ ] Backup codes displayed once
- [ ] Remaining codes count shown
- [ ] Lost device recovery instructions

**Session Security:**
- [ ] HTTPS-only cookies
- [ ] HTTP-only flag (prevent XSS)
- [ ] SameSite=Lax (CSRF protection)
- [ ] Session expiration (1 hour)
- [ ] Temporary session data cleared after use

**Database Schema:**
- [ ] totp_secret column (encrypted)
- [ ] totp_enabled flag
- [ ] totp_backup_codes (hashed JSON array)
- [ ] totp_failed_attempts counter
- [ ] totp_lockout_until timestamp
- [ ] totp_last_attempt timestamp

**Monitoring & Logging:**
- [ ] Log 2FA setup events
- [ ] Log verification attempts (success/failure)
- [ ] Log backup code usage
- [ ] Log account lockouts
- [ ] Log recovery actions
- [ ] Alert on suspicious patterns

**Testing:**
- [ ] Unit tests for TOTP generation/verification
- [ ] Tests for rate limiting
- [ ] Tests for backup code usage
- [ ] Tests for encryption/decryption
- [ ] Tests for lockout mechanism
- [ ] Integration tests for full login flow

---

## 11. Performance and Scalability Considerations

### 11.1 Performance Optimizations

**Caching:**
- Cache decrypted TOTP secrets in Redis (5-minute TTL) - reduces database load
- Cache user 2FA settings (enabled/disabled) - reduces queries

**Rate Limiting:**
- Use Redis for cross-session rate limiting (faster than database)
- Implement sliding window counters for better UX

**Database Indexes:**
```sql
CREATE INDEX idx_users_totp_enabled ON users(totp_enabled);
CREATE INDEX idx_users_lockout ON users(totp_lockout_until) WHERE totp_lockout_until IS NOT NULL;
```

### 11.2 Scalability Patterns

**Horizontal Scaling:**
- Stateless TOTP verification (scales horizontally)
- Share rate limiting state via Redis cluster
- Centralized session storage (Redis/Memcached)

**High-Availability:**
- Redis replication for rate limiting state
- Database replication for user data
- Load balancer with sticky sessions

---

## 12. References and Further Reading

### 12.1 Official Specifications
1. **RFC 6238** - TOTP: Time-Based One-Time Password Algorithm
   https://datatracker.ietf.org/doc/html/rfc6238

2. **RFC 4226** - HOTP: HMAC-Based One-Time Password Algorithm
   https://datatracker.ietf.org/doc/html/rfc4226

### 12.2 Libraries and Tools
3. **PyOTP Documentation**
   https://pyauth.github.io/pyotp/

4. **Cryptography (Fernet) Documentation**
   https://cryptography.io/en/latest/fernet/

5. **QRCode Library**
   https://pypi.org/project/qrcode/

### 12.3 Security Best Practices
6. **OWASP Authentication Cheat Sheet**
   https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

7. **NIST SP 800-63B - Digital Identity Guidelines**
   https://pages.nist.gov/800-63-3/sp800-63b.html

8. **Brute Forcing TOTP Multi-Factor Authentication**
   https://pulsesecurity.co.nz/articles/totp-bruting

### 12.4 Implementation Guides
9. **Miguel Grinberg - Two Factor Authentication with Flask**
   https://blog.miguelgrinberg.com/post/two-factor-authentication-with-flask

10. **FreeCodeCamp - Implement 2FA in Flask**
    https://www.freecodecamp.org/news/how-to-implement-two-factor-authentication-in-your-flask-app/

---

## 13. Conclusion

### 13.1 Key Takeaways

**Critical Success Factors:**
1. ✅ **Encrypt all secrets** - Never store TOTP secrets in plain text
2. ✅ **Implement rate limiting** - Essential to prevent brute force attacks
3. ✅ **Provide backup codes** - Users WILL lose devices
4. ✅ **Use pyotp correctly** - Understand valid_window and security implications
5. ✅ **Monitor and log** - Track 2FA events for security analysis

**Security vs. Usability Balance:**
- TOTP provides strong security without SMS vulnerabilities
- Backup codes ensure account recovery
- Progressive delays maintain security while minimizing UX friction
- QR codes make setup accessible to non-technical users

### 13.2 Implementation Roadmap

**Phase 1: Core Implementation (Week 1)**
- Database schema updates
- TOTP service layer
- Encryption utilities
- Basic setup flow

**Phase 2: Security Hardening (Week 2)**
- Rate limiting implementation
- Replay attack prevention
- Account lockout mechanism
- Security logging

**Phase 3: User Experience (Week 3)**
- QR code generation
- Backup codes UI
- Recovery flows
- Settings dashboard

**Phase 4: Testing & Deployment (Week 4)**
- Unit tests
- Integration tests
- Security audit
- Production deployment

### 13.3 Next Steps

For the Recipe App specifically:
1. Review this research document thoroughly
2. Install required dependencies (pyotp, qrcode, cryptography)
3. Run database migration to add 2FA columns
4. Implement TOTP service layer (totp_service.py)
5. Implement encryption utilities (encryption.py)
6. Update login flow to support 2FA
7. Create setup and verification UI
8. Test thoroughly with authenticator apps
9. Deploy with proper environment variable configuration

**Success Metrics:**
- 0% plain text secrets in database
- <1% false negatives (legitimate users blocked)
- <0.001% successful brute force attempts
- >90% user setup completion rate
- <5% backup code recovery rate

---

## Appendix A: Quick Start Commands

```bash
# Install dependencies
pip install pyotp qrcode[pil] cryptography

# Generate encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Generate secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Test TOTP generation
python -c "import pyotp; secret = pyotp.random_base32(); print(f'Secret: {secret}\\nCode: {pyotp.TOTP(secret).now()}')"

# Run database migration
python database.py

# Start application
python app.py
```

---

## Appendix B: Troubleshooting Guide

**Issue: TOTP codes not verifying**
- Check clock synchronization (client and server)
- Verify valid_window=1 is set
- Confirm secret is correctly encrypted/decrypted
- Test with multiple time windows

**Issue: QR code not scanning**
- Ensure proper encoding (URL encoding)
- Check QR code size (should be 300x300px minimum)
- Verify provisioning URI format
- Try manual entry option

**Issue: Account lockout not working**
- Check atomic counter increments
- Verify lockout timestamp format
- Confirm cross-session protection (Redis)
- Test with multiple parallel requests

**Issue: Backup codes not working**
- Verify hashing algorithm (SHA-256)
- Check code format (remove hyphens before hashing)
- Confirm single-use enforcement (delete after use)
- Test with freshly generated codes

---

**Document Version:** 1.0
**Last Updated:** 2025-01-16
**Author:** Claude (Deep Research Agent)
**Status:** Production-Ready Research

---
