# Secure Credential Storage and Authentication Best Practices

**Research Date**: 2025-10-16
**Focus**: Python implementations with werkzeug.security, bcrypt, and Argon2

---

## Executive Summary

Modern password security requires:
1. **Argon2id** as the primary hashing algorithm (OWASP recommended)
2. **Automatic salt generation** per password (cryptographically secure)
3. **Optional pepper** for defense-in-depth
4. **Constant-time comparison** to prevent timing attacks
5. **Database encryption at rest** for comprehensive protection
6. **Progressive migration** strategies for legacy systems

---

## 1. Password Hashing Algorithm Comparison

### 1.1 Algorithm Rankings (2024/2025 Security Analysis)

| Algorithm | Security Rating | Recommended Use | Memory Hardness | GPU Resistance |
|-----------|----------------|-----------------|-----------------|----------------|
| **Argon2id** | ⭐⭐⭐⭐⭐ | Primary choice for all new systems | Configurable (high) | Excellent |
| **scrypt** | ⭐⭐⭐⭐ | Alternative when Argon2 unavailable | Configurable | Very Good |
| **bcrypt** | ⭐⭐⭐ | Legacy systems, widely supported | Fixed (4KB) | Good |
| **PBKDF2** | ⭐⭐ | FIPS-140 compliance required | None | Poor |

### 1.2 Detailed Algorithm Analysis

#### **Argon2id** (RECOMMENDED)
- **Winner of Password Hashing Competition** (2013-2015)
- **Three variants**: Argon2i (side-channel resistant), Argon2d (GPU resistant), **Argon2id (hybrid - best)**
- **OWASP 2024 Recommendation**:
  - Memory: 19 MiB minimum (m=19456)
  - Iterations: 2 (t=2)
  - Parallelism: 1 (p=1)
- **Strengths**: Configurable memory/CPU usage, resistant to all known attacks, future-proof
- **Weaknesses**: Relatively newer, less widespread support in legacy systems

#### **scrypt**
- **Memory-hard algorithm** designed by Colin Percival
- **OWASP Fallback**: CPU/memory cost 2^17, block size 8, parallelization 1
- **Strengths**: Very strong against hardware attacks, well-studied
- **Weaknesses**: More complex to implement correctly, potential DoS risk if misconfigured

#### **bcrypt**
- **Based on Blowfish cipher**, designed by Niels Provos and David Mazières
- **Work factor**: 10+ recommended (12-14 for high security)
- **Strengths**: Simple, widely supported, battle-tested (25+ years)
- **Weaknesses**: 72-byte password limit, vulnerable to FPGA attacks, fixed memory usage

#### **PBKDF2**
- **NIST-approved**, FIPS-140 validated implementations available
- **OWASP Configuration**: HMAC-SHA-256, 600,000+ iterations
- **Strengths**: Standards compliance, universal support
- **Weaknesses**: Not memory-hard, vulnerable to GPU/ASIC attacks

### 1.3 Performance Comparison

```
Operation: Hash "correct horse battery staple"

Argon2id (19 MiB, t=2, p=1):  ~100ms
scrypt (N=2^17, r=8, p=1):     ~80ms
bcrypt (cost=12):              ~300ms
PBKDF2-SHA256 (600k iter):     ~150ms

Note: Times vary by hardware; adjust parameters for 200-500ms target
```

---

## 2. Salt Generation and Storage Patterns

### 2.1 What is Salt?

Salt is a **unique, random value** added to each password before hashing to ensure:
- Identical passwords produce different hashes
- Rainbow tables become ineffective
- Each password requires individual cracking

### 2.2 Salt Requirements

**Length**: Minimum 16 bytes (128 bits), 32 bytes recommended
**Uniqueness**: Every password must have a unique salt
**Randomness**: Cryptographically secure random generation
**Storage**: Store alongside hash (not secret, but must not be lost)

### 2.3 Python Salt Generation

#### Using `secrets` Module (Recommended)

```python
import secrets

# Generate cryptographically secure random salt
def generate_salt(length=32):
    """
    Generate a cryptographically secure random salt.

    Args:
        length: Salt length in bytes (default 32)

    Returns:
        bytes: Random salt
    """
    return secrets.token_bytes(length)

# Alternative: hex-encoded salt
def generate_hex_salt(length=32):
    """Generate hex-encoded salt for text storage."""
    return secrets.token_hex(length)

# Alternative: URL-safe base64 salt
def generate_urlsafe_salt(length=32):
    """Generate URL-safe base64-encoded salt."""
    return secrets.token_urlsafe(length)
```

**Why `secrets` over `random`?**
- `secrets` uses OS-level cryptographic randomness (`os.urandom()`)
- `random` is pseudorandom, designed for simulation, NOT security
- `secrets` provides secure defaults and prevents common mistakes

### 2.4 Automatic Salt Handling in Libraries

Modern libraries handle salt automatically:

```python
# bcrypt - salt generated automatically
import bcrypt
password = b"my_password"
salt = bcrypt.gensalt(rounds=12)  # Generates random salt
hashed = bcrypt.hashpw(password, salt)  # Salt embedded in hash

# Argon2 - salt generated automatically
from argon2 import PasswordHasher
ph = PasswordHasher()
hash_value = ph.hash("my_password")  # Salt automatically generated and encoded

# werkzeug - salt generated automatically
from werkzeug.security import generate_password_hash
hashed = generate_password_hash("my_password")  # Salt handled internally
```

**Storage Format**: Most libraries encode salt + hash together:
```
$argon2id$v=19$m=19456,t=2,p=1$SALT_BASE64$HASH_BASE64
$2b$12$SALT_BASE64_HASH_COMBINED
scrypt:32768:8:1$SALT$HASH
```

---

## 3. Pepper Usage for Additional Security Layer

### 3.1 What is Pepper?

Pepper is a **secret key** added to passwords before hashing:
- **Stored separately** from database (config file, secrets manager, environment variable)
- **Single value** for entire system (unlike unique salts)
- **Never stored in database** - if DB compromised, pepper remains secret

### 3.2 Salt vs Pepper

| Property | Salt | Pepper |
|----------|------|--------|
| Uniqueness | Per password | System-wide |
| Storage | Database (with hash) | Separate secrets store |
| Secrecy | Public (not secret) | Secret (confidential) |
| Purpose | Prevent rainbow tables | Defense-in-depth |
| Recovery | Must never be lost | Can be rotated with care |

### 3.3 Python Pepper Implementation

```python
import os
import hmac
import hashlib
from argon2 import PasswordHasher

# Load pepper from environment or secrets manager
PEPPER = os.environ.get('PASSWORD_PEPPER', '').encode()

def hash_password_with_pepper(password: str) -> str:
    """
    Hash password with pepper using HMAC-based approach.

    Best practice: Use HMAC to combine password and pepper
    before passing to main hashing algorithm.

    Args:
        password: Plain text password

    Returns:
        str: Hashed password with pepper applied
    """
    if not PEPPER:
        raise ValueError("PASSWORD_PEPPER environment variable not set")

    # Step 1: Combine password with pepper using HMAC
    peppered_password = hmac.new(
        PEPPER,
        password.encode(),
        hashlib.sha256
    ).hexdigest()

    # Step 2: Hash the peppered password with Argon2
    ph = PasswordHasher()
    return ph.hash(peppered_password)

def verify_password_with_pepper(hash_value: str, password: str) -> bool:
    """Verify password that was hashed with pepper."""
    if not PEPPER:
        raise ValueError("PASSWORD_PEPPER environment variable not set")

    # Apply same pepper transformation
    peppered_password = hmac.new(
        PEPPER,
        password.encode(),
        hashlib.sha256
    ).hexdigest()

    # Verify against stored hash
    ph = PasswordHasher()
    try:
        ph.verify(hash_value, peppered_password)
        return True
    except Exception:
        return False
```

### 3.4 Pepper Best Practices

**DO:**
✅ Store pepper in environment variables or dedicated secrets manager
✅ Use different pepper for different environments (dev/staging/prod)
✅ Generate pepper with cryptographic randomness (32+ bytes)
✅ Use HMAC to combine pepper and password
✅ Document pepper recovery procedures
✅ Consider pepper rotation strategy before implementation

**DON'T:**
❌ Store pepper in source code or version control
❌ Store pepper in the same database as hashes
❌ Use pepper as a replacement for proper hashing algorithms
❌ Lose the pepper (makes all passwords unrecoverable)
❌ Expose pepper in logs or error messages

### 3.5 Pepper Rotation Strategy

```python
import json
from datetime import datetime

class PepperRotationManager:
    """
    Manage multiple peppers for rotation without breaking existing hashes.

    Strategy: Store pepper ID with hash, maintain historical peppers
    """

    def __init__(self):
        # Load peppers from secure storage
        # Format: {pepper_id: pepper_value}
        self.peppers = self._load_peppers()
        self.current_pepper_id = self._get_current_pepper_id()

    def hash_with_versioned_pepper(self, password: str) -> dict:
        """
        Hash password with current pepper and return hash + pepper ID.

        Returns:
            dict: {'hash': hash_value, 'pepper_id': id}
        """
        pepper = self.peppers[self.current_pepper_id]
        peppered_password = self._apply_pepper(password, pepper)

        ph = PasswordHasher()
        hash_value = ph.hash(peppered_password)

        return {
            'hash': hash_value,
            'pepper_id': self.current_pepper_id,
            'created_at': datetime.utcnow().isoformat()
        }

    def verify_with_versioned_pepper(
        self,
        hash_data: dict,
        password: str
    ) -> bool:
        """Verify password using correct historical pepper."""
        pepper_id = hash_data.get('pepper_id', 'default')

        if pepper_id not in self.peppers:
            raise ValueError(f"Pepper ID {pepper_id} not found in keystore")

        pepper = self.peppers[pepper_id]
        peppered_password = self._apply_pepper(password, pepper)

        ph = PasswordHasher()
        try:
            ph.verify(hash_data['hash'], peppered_password)
            return True
        except Exception:
            return False

    def _apply_pepper(self, password: str, pepper: bytes) -> str:
        """Apply pepper using HMAC."""
        return hmac.new(
            pepper,
            password.encode(),
            hashlib.sha256
        ).hexdigest()

    def _load_peppers(self) -> dict:
        """Load peppers from secure storage (implement based on your setup)."""
        # Example: Load from environment or secrets manager
        return {
            'v1': os.environ.get('PEPPER_V1', '').encode(),
            'v2': os.environ.get('PEPPER_V2', '').encode(),
        }

    def _get_current_pepper_id(self) -> str:
        """Get current active pepper ID."""
        return os.environ.get('CURRENT_PEPPER_ID', 'v2')
```

---

## 4. Rainbow Table Attack Prevention

### 4.1 What are Rainbow Tables?

Rainbow tables are **precomputed hash tables** for reversing cryptographic hash functions:
- Contain millions/billions of precomputed password hashes
- Enable rapid password lookup instead of brute force
- Effective against unsalted hashes

### 4.2 How Salt Defeats Rainbow Tables

**Without Salt**:
```
password123 → hash(password123) → 482c811...
                Same hash every time! ← Rainbow table contains this
```

**With Salt**:
```
password123 + salt1 → hash(password123 + salt1) → abc123...
password123 + salt2 → hash(password123 + salt2) → def456...
                Different hashes! ← Rainbow table useless
```

### 4.3 Mathematical Impact of Salt

**Rainbow table size required**:
- **No salt**: 1 table for all users
- **16-byte salt**: 2^128 different tables needed (340 undecillion)
- **32-byte salt**: 2^256 tables (essentially impossible)

**Storage calculation**:
```
Rainbow table for 1 trillion passwords: ~10 TB
With 16-byte salt: 10 TB × 2^128 = 3.4 × 10^39 TB (impossible)
```

### 4.4 Complete Protection Implementation

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets

class SecurePasswordManager:
    """
    Production-ready password manager with comprehensive protection.

    Features:
    - Argon2id hashing (OWASP recommended)
    - Automatic salt generation
    - Optional pepper support
    - Rainbow table protection
    - Timing attack resistance
    """

    def __init__(self, pepper: bytes = None):
        """
        Initialize password manager.

        Args:
            pepper: Optional system-wide secret (load from env)
        """
        self.ph = PasswordHasher(
            time_cost=2,        # OWASP minimum
            memory_cost=19456,  # 19 MiB (OWASP minimum)
            parallelism=1,
            hash_len=32,
            salt_len=16
        )
        self.pepper = pepper

    def hash_password(self, password: str) -> str:
        """
        Hash password with automatic salt generation.

        Rainbow table protection:
        - Unique salt per password (cryptographically random)
        - Salt embedded in output (no separate storage needed)
        - Argon2id memory-hard algorithm

        Args:
            password: Plain text password

        Returns:
            str: Hash string with embedded salt
        """
        if self.pepper:
            password = self._apply_pepper(password)

        # Argon2 automatically generates unique salt
        return self.ph.hash(password)

    def verify_password(self, hash_value: str, password: str) -> bool:
        """
        Verify password with constant-time comparison.

        Protection against:
        - Timing attacks (constant-time verification)
        - Rainbow tables (salt in hash)

        Args:
            hash_value: Stored hash
            password: Password to verify

        Returns:
            bool: True if password matches
        """
        if self.pepper:
            password = self._apply_pepper(password)

        try:
            # Uses constant-time comparison internally
            self.ph.verify(hash_value, password)
            return True
        except VerifyMismatchError:
            return False

    def needs_rehash(self, hash_value: str) -> bool:
        """
        Check if hash needs updating (parameters changed).

        Use for progressive security improvements.
        """
        return self.ph.check_needs_rehash(hash_value)

    def _apply_pepper(self, password: str) -> str:
        """Apply pepper using HMAC (if configured)."""
        import hmac
        import hashlib
        return hmac.new(
            self.pepper,
            password.encode(),
            hashlib.sha256
        ).hexdigest()

# Usage example
password_manager = SecurePasswordManager()

# Hash password (salt generated automatically)
hashed = password_manager.hash_password("user_password_123")
# Output: $argon2id$v=19$m=19456,t=2,p=1$[SALT]$[HASH]

# Verify password
is_valid = password_manager.verify_password(hashed, "user_password_123")
# Output: True

# Check if rehashing needed (after security updates)
if password_manager.needs_rehash(hashed):
    new_hash = password_manager.hash_password("user_password_123")
    # Update database with new_hash
```

---

## 5. Database Security for User Credentials

### 5.1 Defense-in-Depth Strategy

**Multiple layers of protection**:
```
Layer 1: Password Hashing (Argon2id + Salt)
Layer 2: Optional Pepper (Separate secret storage)
Layer 3: Database Encryption at Rest
Layer 4: Application-level Encryption (for sensitive columns)
Layer 5: Network Encryption (TLS/SSL)
Layer 6: Access Controls (Least privilege)
```

### 5.2 PostgreSQL Encryption at Rest

#### Option 1: Filesystem Encryption (Recommended for Most)

```bash
# Linux: dm-crypt + LUKS
cryptsetup luksFormat /dev/sdb
cryptsetup open /dev/sdb pgdata
mkfs.ext4 /dev/mapper/pgdata
mount /dev/mapper/pgdata /var/lib/postgresql/data

# macOS: FileVault 2 or encrypted APFS
diskutil apfs createVolume disk1 APFSX "PostgreSQL Data" -encrypted

# Benefits:
# - Transparent to PostgreSQL
# - Protects all files (data, WAL, configs)
# - Prevents offline attacks (stolen disk)
# - No performance overhead when mounted
```

#### Option 2: Transparent Data Encryption (TDE)

```python
"""
TDE not available in community PostgreSQL.
Available through:
- EDB Postgres Advanced Server
- Percona Distribution for PostgreSQL
- Cybertec PostgreSQL TDE

TDE features:
- Encrypts data files automatically
- Decrypts on read, encrypts on write
- Key management system integration
- No application changes needed
"""
```

#### Option 3: Column-Level Encryption with pgcrypto

```sql
-- Install pgcrypto extension
CREATE EXTENSION pgcrypto;

-- Create table with encrypted column
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    -- Password already hashed (Argon2id), store as TEXT
    password_hash TEXT NOT NULL,
    -- Additional sensitive data can be encrypted
    ssn BYTEA,  -- Encrypted with pgcrypto
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert with encrypted sensitive data
INSERT INTO users (username, email, password_hash, ssn)
VALUES (
    'johndoe',
    'john@example.com',
    '$argon2id$v=19$...',  -- Pre-hashed by application
    pgp_sym_encrypt('123-45-6789', 'encryption_key')
);

-- Query with decryption
SELECT
    username,
    email,
    password_hash,
    pgp_sym_decrypt(ssn, 'encryption_key') AS ssn_decrypted
FROM users
WHERE username = 'johndoe';
```

**Important**: Do NOT encrypt password hashes - they are already one-way hashes.

### 5.3 Python Application Integration

```python
import psycopg2
from argon2 import PasswordHasher
from typing import Optional

class SecureUserRepository:
    """
    Database repository with secure credential handling.

    Security features:
    - Parameterized queries (SQL injection prevention)
    - Password hashing (Argon2id)
    - Secure connection (TLS)
    - Prepared statements
    """

    def __init__(self, connection_string: str):
        """
        Initialize with secure database connection.

        Connection string should include sslmode=require for production.
        """
        self.conn = psycopg2.connect(
            connection_string,
            sslmode='require'  # Enforce TLS
        )
        self.ph = PasswordHasher()

    def create_user(
        self,
        username: str,
        email: str,
        password: str
    ) -> int:
        """
        Create new user with secure password storage.

        Args:
            username: Unique username
            email: User email
            password: Plain text password (hashed before storage)

        Returns:
            int: User ID
        """
        # Hash password before database insertion
        password_hash = self.ph.hash(password)

        with self.conn.cursor() as cur:
            # Parameterized query prevents SQL injection
            cur.execute("""
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (username, email, password_hash))

            user_id = cur.fetchone()[0]
            self.conn.commit()
            return user_id

    def verify_user(self, username: str, password: str) -> Optional[dict]:
        """
        Verify user credentials with timing attack protection.

        Args:
            username: Username to verify
            password: Password to check

        Returns:
            dict: User data if valid, None if invalid
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, email, password_hash
                FROM users
                WHERE username = %s
            """, (username,))

            user = cur.fetchone()

            if not user:
                # Perform dummy verification to prevent timing attacks
                self.ph.hash("dummy_password")
                return None

            user_id, username, email, password_hash = user

            try:
                # Constant-time verification
                self.ph.verify(password_hash, password)

                # Check if rehash needed (security parameters updated)
                if self.ph.check_needs_rehash(password_hash):
                    self._rehash_password(user_id, password)

                return {
                    'id': user_id,
                    'username': username,
                    'email': email
                }

            except Exception:
                return None

    def _rehash_password(self, user_id: int, password: str):
        """Rehash password with updated parameters."""
        new_hash = self.ph.hash(password)

        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET password_hash = %s
                WHERE id = %s
            """, (new_hash, user_id))
            self.conn.commit()

    def close(self):
        """Close database connection."""
        self.conn.close()

# Usage example
repo = SecureUserRepository(
    "postgresql://user:pass@localhost/mydb?sslmode=require"
)

# Create user (password hashed automatically)
user_id = repo.create_user("alice", "alice@example.com", "secure_pass_123")

# Verify credentials (constant-time comparison)
user_data = repo.verify_user("alice", "secure_pass_123")
if user_data:
    print(f"Login successful: {user_data['username']}")
else:
    print("Invalid credentials")

repo.close()
```

### 5.4 Database Security Checklist

**Access Control**:
- [ ] Principle of least privilege for database users
- [ ] Separate accounts for application vs admin
- [ ] No direct access to password_hash column for most users
- [ ] Row-level security policies where appropriate

**Network Security**:
- [ ] TLS/SSL enforced for all connections (`sslmode=require`)
- [ ] Certificate verification enabled
- [ ] Database not exposed to public internet
- [ ] Firewall rules limiting database access

**Encryption**:
- [ ] Filesystem encryption or TDE enabled
- [ ] Backups encrypted
- [ ] Encryption keys stored securely (not with data)
- [ ] Key rotation procedures documented

**Monitoring**:
- [ ] Failed login attempts logged
- [ ] Suspicious query patterns detected
- [ ] Regular security audits
- [ ] Automated backup verification

---

## 6. Timing Attack Prevention

### 6.1 What are Timing Attacks?

Timing attacks exploit **variations in execution time** to leak information:

```python
# VULNERABLE: String comparison stops at first difference
def insecure_compare(hash1, hash2):
    if len(hash1) != len(hash2):
        return False

    for i in range(len(hash1)):
        if hash1[i] != hash2[i]:
            return False  # ← Returns immediately!

    return True

# Attack scenario:
# "aaaa" vs "Xbcd" → Fast (fails at position 0)
# "abcd" vs "Xbcd" → Fast (fails at position 0)
# "Xacd" vs "Xbcd" → Slower (fails at position 1)
# "Xbad" vs "Xbcd" → Even slower (fails at position 2)
# Attacker measures timing to determine correct characters!
```

### 6.2 Constant-Time Comparison

**Goal**: Execution time independent of input values

```python
import hmac
import secrets

def secure_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison using hmac.compare_digest.

    Timing attack protection:
    - Compares entire strings regardless of differences
    - Execution time constant for strings of same length
    - Uses bitwise operations instead of short-circuit logic

    Args:
        a: First string
        b: Second string

    Returns:
        bool: True if strings match
    """
    # hmac.compare_digest is constant-time
    return hmac.compare_digest(a.encode(), b.encode())

# Alternative: secrets.compare_digest (Python 3.9+)
def secure_compare_v2(a: str, b: str) -> bool:
    """Uses secrets.compare_digest (preferred in Python 3.9+)."""
    return secrets.compare_digest(a, b)
```

### 6.3 How Libraries Prevent Timing Attacks

Most modern password libraries handle this automatically:

```python
# bcrypt - constant-time comparison built-in
import bcrypt
hashed = bcrypt.hashpw(b"password", bcrypt.gensalt())
is_valid = bcrypt.checkpw(b"password", hashed)  # ← Constant-time

# Argon2 - constant-time verification
from argon2 import PasswordHasher
ph = PasswordHasher()
hash_value = ph.hash("password")
try:
    ph.verify(hash_value, "password")  # ← Constant-time
    print("Valid")
except Exception:
    print("Invalid")

# werkzeug - uses constant-time comparison
from werkzeug.security import check_password_hash
is_valid = check_password_hash(hash_value, "password")  # ← Constant-time
```

### 6.4 Complete Timing-Safe Authentication

```python
import hmac
import secrets
from argon2 import PasswordHasher
from typing import Optional

class TimingSafeAuth:
    """
    Authentication system with comprehensive timing attack protection.

    Protection mechanisms:
    1. Constant-time password verification
    2. Dummy operations for non-existent users
    3. Consistent response times
    4. Secure random delays
    """

    def __init__(self):
        self.ph = PasswordHasher()
        # Precompute dummy hash for non-existent users
        self.dummy_hash = self.ph.hash("dummy_password_do_not_use")

    def authenticate(
        self,
        username: str,
        password: str,
        user_lookup_func
    ) -> Optional[dict]:
        """
        Authenticate user with timing attack protection.

        Strategy:
        - Always perform hash verification (even for invalid users)
        - Use constant-time comparisons
        - Add random delays to obscure timing patterns

        Args:
            username: Username to authenticate
            password: Password to verify
            user_lookup_func: Function to lookup user by username

        Returns:
            dict: User data if valid, None if invalid
        """
        # Lookup user from database
        user = user_lookup_func(username)

        # Determine which hash to verify against
        if user:
            hash_to_verify = user['password_hash']
        else:
            # Use dummy hash for non-existent users
            # Prevents timing leak from skipping verification
            hash_to_verify = self.dummy_hash

        # Always perform verification (constant-time operation)
        is_valid = False
        try:
            self.ph.verify(hash_to_verify, password)
            is_valid = True
        except Exception:
            is_valid = False

        # Return result only if user exists AND password valid
        if user and is_valid:
            return user
        else:
            # Add small random delay to further obscure timing
            self._add_timing_jitter()
            return None

    def _add_timing_jitter(self):
        """
        Add small random delay to obscure timing patterns.

        Delay: 10-50ms (adjust based on network latency)
        """
        import time
        delay = secrets.randbelow(40) + 10  # 10-50ms
        time.sleep(delay / 1000.0)

    def verify_username_exists(self, username: str, user_lookup_func) -> bool:
        """
        Check username existence with timing protection.

        Warning: Even with protection, username enumeration may be possible
        through repeated observations. Consider rate limiting.
        """
        user = user_lookup_func(username)

        # Add consistent delay regardless of result
        self._add_timing_jitter()

        return user is not None

# Example user lookup function
def lookup_user(username: str) -> Optional[dict]:
    """Simulated database lookup."""
    users_db = {
        'alice': {
            'username': 'alice',
            'password_hash': '$argon2id$v=19$...'
        }
    }
    return users_db.get(username)

# Usage
auth = TimingSafeAuth()
user = auth.authenticate('alice', 'correct_password', lookup_user)

if user:
    print(f"Authenticated: {user['username']}")
else:
    print("Authentication failed")
```

### 6.5 Additional Timing Attack Mitigations

```python
class EnhancedTimingSecurity:
    """Additional timing attack protections."""

    @staticmethod
    def constant_time_select(condition: bool, true_val, false_val):
        """
        Select value without branching (experimental).

        Eliminates conditional branches that could leak timing.
        """
        # Use bitwise operations for constant-time selection
        mask = -int(condition)  # -1 if True, 0 if False
        return (true_val & mask) | (false_val & ~mask)

    @staticmethod
    def early_failure_protection(checks: list) -> bool:
        """
        Perform all checks without early exit.

        Args:
            checks: List of boolean checks

        Returns:
            bool: True if all checks pass
        """
        result = True
        for check in checks:
            result = result and check  # No short-circuit evaluation
        return result

    @staticmethod
    def rate_limit_auth_attempts(
        username: str,
        max_attempts: int = 5,
        window_seconds: int = 300
    ) -> bool:
        """
        Rate limit authentication attempts.

        Reduces timing attack effectiveness by limiting observations.

        Args:
            username: Username being authenticated
            max_attempts: Max attempts in time window
            window_seconds: Time window in seconds

        Returns:
            bool: True if attempt allowed
        """
        # Implement with Redis or similar
        # Pseudocode:
        # attempts = redis.get(f"auth_attempts:{username}")
        # if attempts >= max_attempts:
        #     return False
        # redis.incr(f"auth_attempts:{username}")
        # redis.expire(f"auth_attempts:{username}", window_seconds)
        # return True
        pass
```

---

## 7. Password Policy Enforcement

### 7.1 NIST Password Guidelines (2024)

**Modern recommendations** (NIST SP 800-63B):

**DO**:
- ✅ Minimum 8 characters (12+ recommended)
- ✅ Allow long passwords (64+ characters)
- ✅ Allow all printable ASCII + Unicode
- ✅ Check against common password lists
- ✅ Check against breached password databases
- ✅ Allow paste functionality

**DON'T**:
- ❌ Mandatory complexity rules (e.g., "must have uppercase + number + special")
- ❌ Mandatory periodic password changes
- ❌ Password hints
- ❌ Security questions for password recovery
- ❌ Arbitrary composition rules

### 7.2 Python Password Validation Implementation

```python
import re
from typing import List, Tuple
import requests  # For haveibeenpwned API

class PasswordValidator:
    """
    Password validation following NIST guidelines.

    Features:
    - Minimum length enforcement
    - Common password checking
    - Breached password detection (haveibeenpwned)
    - Optional strength scoring
    """

    def __init__(
        self,
        min_length: int = 12,
        max_length: int = 128,
        check_breaches: bool = True
    ):
        """
        Initialize validator with configuration.

        Args:
            min_length: Minimum password length (default 12)
            max_length: Maximum password length (default 128)
            check_breaches: Check against breached passwords
        """
        self.min_length = min_length
        self.max_length = max_length
        self.check_breaches = check_breaches

        # Load common passwords list
        self.common_passwords = self._load_common_passwords()

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against policy.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check length
        if len(password) < self.min_length:
            errors.append(
                f"Password must be at least {self.min_length} characters"
            )

        if len(password) > self.max_length:
            errors.append(
                f"Password must not exceed {self.max_length} characters"
            )

        # Check against common passwords
        if password.lower() in self.common_passwords:
            errors.append("Password is too common")

        # Check against breached passwords
        if self.check_breaches and self._is_breached(password):
            errors.append(
                "Password has been exposed in a data breach. "
                "Please choose a different password."
            )

        return (len(errors) == 0, errors)

    def calculate_strength(self, password: str) -> dict:
        """
        Calculate password strength score.

        Returns:
            dict: {
                'score': 0-100,
                'strength': 'weak'|'fair'|'good'|'strong',
                'feedback': [suggestions]
            }
        """
        score = 0
        feedback = []

        # Length scoring (up to 40 points)
        if len(password) >= 8:
            score += 10
        if len(password) >= 12:
            score += 15
        if len(password) >= 16:
            score += 15

        # Character diversity (up to 40 points)
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 10

        # Entropy bonus (up to 20 points)
        unique_chars = len(set(password))
        if unique_chars >= 8:
            score += 10
        if unique_chars >= 12:
            score += 10

        # Penalize patterns
        if re.search(r'(.)\1{2,}', password):  # Repeated characters
            score -= 10
            feedback.append("Avoid repeating characters")

        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            score -= 10
            feedback.append("Avoid sequential numbers")

        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi)', password, re.I):
            score -= 10
            feedback.append("Avoid sequential letters")

        # Determine strength category
        if score < 40:
            strength = "weak"
            feedback.append("Consider using a longer, more complex password")
        elif score < 60:
            strength = "fair"
            feedback.append("Good, but could be stronger")
        elif score < 80:
            strength = "good"
        else:
            strength = "strong"

        return {
            'score': max(0, min(100, score)),
            'strength': strength,
            'feedback': feedback
        }

    def _load_common_passwords(self) -> set:
        """
        Load common passwords list.

        In production: Load from file (e.g., 10k most common passwords)
        Source: https://github.com/danielmiessler/SecLists
        """
        return {
            'password', '123456', 'password123', 'qwerty', 'letmein',
            'welcome', 'monkey', '1234567890', 'abc123', 'password1',
            'admin', 'root', 'test', 'guest', 'user'
            # Load full list from file in production
        }

    def _is_breached(self, password: str) -> bool:
        """
        Check if password has been breached using haveibeenpwned API.

        Uses k-anonymity model:
        1. SHA-1 hash the password
        2. Send first 5 characters to API
        3. API returns all hashes with that prefix
        4. Client checks if full hash is in results

        Privacy: Password never sent to server

        Returns:
            bool: True if password found in breach database
        """
        import hashlib

        try:
            # SHA-1 hash password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]

            # Query haveibeenpwned API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=2)

            if response.status_code != 200:
                # On error, fail open (don't block user)
                return False

            # Check if suffix in results
            hashes = (line.split(':') for line in response.text.splitlines())
            return any(suffix == hash_suffix for hash_suffix, _ in hashes)

        except Exception:
            # On error, fail open
            return False

# Usage example
validator = PasswordValidator(min_length=12)

# Validate password
password = "MySecureP@ssw0rd2024"
is_valid, errors = validator.validate(password)

if is_valid:
    print("Password valid!")
    strength = validator.calculate_strength(password)
    print(f"Strength: {strength['strength']} ({strength['score']}/100)")
else:
    print("Password invalid:")
    for error in errors:
        print(f"  - {error}")

# Example with weak password
weak_password = "password123"
is_valid, errors = validator.validate(weak_password)
# Output: Password invalid:
#   - Password is too common
#   - Password has been exposed in a data breach
```

### 7.3 Password Policy Configuration

```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class PasswordPolicy:
    """Password policy configuration."""

    # Length requirements
    min_length: int = 12
    max_length: int = 128

    # Complexity requirements (optional - NIST discourages)
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digits: bool = False
    require_special: bool = False

    # Security checks
    check_common_passwords: bool = True
    check_breached_passwords: bool = True

    # Rate limiting
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15

    # Password history
    prevent_reuse_count: int = 5  # Prevent reusing last N passwords

    # Expiration (optional - NIST discourages periodic changes)
    expiration_days: Optional[int] = None

# Example: High-security policy
high_security_policy = PasswordPolicy(
    min_length=16,
    check_breached_passwords=True,
    max_failed_attempts=3,
    prevent_reuse_count=10
)

# Example: Standard policy
standard_policy = PasswordPolicy(
    min_length=12,
    check_breached_passwords=True,
    max_failed_attempts=5
)

# Example: Legacy system (not recommended)
legacy_policy = PasswordPolicy(
    min_length=8,
    require_uppercase=True,
    require_digits=True,
    require_special=True,
    expiration_days=90  # Not recommended by NIST
)
```

---

## 8. Migration Strategies

### 8.1 Migration Overview

When upgrading hashing algorithms or parameters:

**Scenarios**:
1. **Weak → Strong**: MD5/SHA1 → bcrypt/Argon2
2. **Good → Better**: bcrypt → Argon2id
3. **Parameter Updates**: bcrypt rounds 10 → 12, Argon2 memory increase

**Strategy**: **Progressive rehashing on login** (recommended)

### 8.2 Progressive Rehashing Implementation

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt
from typing import Optional, Tuple

class MigrationPasswordManager:
    """
    Password manager supporting migration between hashing algorithms.

    Migration strategy:
    1. Detect hash format from stored hash
    2. Verify with appropriate algorithm
    3. On successful login, rehash with new algorithm
    4. Update database with new hash

    Supported migrations:
    - bcrypt → Argon2id
    - Argon2 parameter updates
    - MD5/SHA1 → Argon2id (with extra care)
    """

    def __init__(self):
        # New algorithm (target)
        self.argon2_ph = PasswordHasher(
            time_cost=2,
            memory_cost=19456,
            parallelism=1,
            hash_len=32,
            salt_len=16
        )

    def verify_and_upgrade(
        self,
        stored_hash: str,
        password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify password and return upgraded hash if needed.

        Args:
            stored_hash: Hash from database
            password: Password to verify

        Returns:
            Tuple of (is_valid, new_hash)
            - is_valid: True if password correct
            - new_hash: New hash if upgrade needed, None otherwise
        """
        # Detect hash algorithm from format
        hash_type = self._detect_hash_type(stored_hash)

        if hash_type == 'argon2':
            return self._verify_argon2(stored_hash, password)
        elif hash_type == 'bcrypt':
            return self._verify_bcrypt_and_upgrade(stored_hash, password)
        elif hash_type == 'md5' or hash_type == 'sha1':
            # Special handling for legacy weak hashes
            return self._verify_legacy_and_upgrade(
                stored_hash,
                password,
                hash_type
            )
        else:
            # Unknown format
            return (False, None)

    def _detect_hash_type(self, hash_string: str) -> str:
        """
        Detect hash algorithm from format.

        Hash format patterns:
        - Argon2: $argon2id$v=19$...
        - bcrypt: $2a$, $2b$, $2y$
        - scrypt: scrypt:...
        - MD5: 32 hex characters (if stored raw)
        - SHA1: 40 hex characters (if stored raw)
        """
        if hash_string.startswith('$argon2'):
            return 'argon2'
        elif hash_string.startswith(('$2a$', '$2b$', '$2y$')):
            return 'bcrypt'
        elif hash_string.startswith('scrypt:'):
            return 'scrypt'
        elif len(hash_string) == 32 and self._is_hex(hash_string):
            return 'md5'
        elif len(hash_string) == 40 and self._is_hex(hash_string):
            return 'sha1'
        else:
            return 'unknown'

    def _verify_argon2(
        self,
        stored_hash: str,
        password: str
    ) -> Tuple[bool, Optional[str]]:
        """Verify Argon2 hash and check if parameters need updating."""
        try:
            self.argon2_ph.verify(stored_hash, password)

            # Check if rehash needed (parameters updated)
            if self.argon2_ph.check_needs_rehash(stored_hash):
                new_hash = self.argon2_ph.hash(password)
                return (True, new_hash)

            return (True, None)  # Valid, no upgrade needed

        except VerifyMismatchError:
            return (False, None)

    def _verify_bcrypt_and_upgrade(
        self,
        stored_hash: str,
        password: str
    ) -> Tuple[bool, Optional[str]]:
        """Verify bcrypt hash and upgrade to Argon2."""
        try:
            # Verify with bcrypt
            is_valid = bcrypt.checkpw(
                password.encode(),
                stored_hash.encode()
            )

            if is_valid:
                # Generate new Argon2 hash
                new_hash = self.argon2_ph.hash(password)
                return (True, new_hash)
            else:
                return (False, None)

        except Exception:
            return (False, None)

    def _verify_legacy_and_upgrade(
        self,
        stored_hash: str,
        password: str,
        hash_type: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify legacy MD5/SHA1 hash and upgrade.

        WARNING: This should only be used as last resort for migration.
        MD5/SHA1 are cryptographically broken and should be migrated ASAP.

        Consider:
        1. Force password reset for all users (more secure)
        2. Use this migration only if password reset not feasible
        """
        import hashlib

        # Hash password with legacy algorithm
        if hash_type == 'md5':
            calculated_hash = hashlib.md5(password.encode()).hexdigest()
        elif hash_type == 'sha1':
            calculated_hash = hashlib.sha1(password.encode()).hexdigest()
        else:
            return (False, None)

        # Use constant-time comparison
        import hmac
        is_valid = hmac.compare_digest(stored_hash, calculated_hash)

        if is_valid:
            # Upgrade to Argon2
            new_hash = self.argon2_ph.hash(password)
            return (True, new_hash)
        else:
            return (False, None)

    @staticmethod
    def _is_hex(s: str) -> bool:
        """Check if string is hexadecimal."""
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

# Usage in authentication system
class AuthenticationSystem:
    """Authentication system with automatic hash migration."""

    def __init__(self, db_connection):
        self.db = db_connection
        self.password_manager = MigrationPasswordManager()

    def login(self, username: str, password: str) -> Optional[dict]:
        """
        Authenticate user with automatic hash upgrade.

        Args:
            username: Username
            password: Password

        Returns:
            dict: User data if valid, None if invalid
        """
        # Fetch user from database
        user = self._fetch_user(username)
        if not user:
            return None

        stored_hash = user['password_hash']

        # Verify and get upgrade hash if needed
        is_valid, new_hash = self.password_manager.verify_and_upgrade(
            stored_hash,
            password
        )

        if not is_valid:
            return None

        # If hash was upgraded, update database
        if new_hash:
            self._update_password_hash(user['id'], new_hash)
            print(f"Password hash upgraded for user {username}")

        return user

    def _fetch_user(self, username: str) -> Optional[dict]:
        """Fetch user from database."""
        # Implement database query
        pass

    def _update_password_hash(self, user_id: int, new_hash: str):
        """Update password hash in database."""
        # Implement database update
        pass

# Example: Monitor migration progress
class MigrationMonitor:
    """Track hash migration progress."""

    def __init__(self, db_connection):
        self.db = db_connection

    def get_migration_stats(self) -> dict:
        """
        Get statistics on hash algorithm distribution.

        Returns:
            dict: {
                'total_users': int,
                'argon2_count': int,
                'bcrypt_count': int,
                'legacy_count': int,
                'migration_percentage': float
            }
        """
        # Query database for hash prefixes
        # Example SQL:
        # SELECT
        #   COUNT(*) AS total,
        #   SUM(CASE WHEN password_hash LIKE '$argon2%' THEN 1 ELSE 0 END) AS argon2,
        #   SUM(CASE WHEN password_hash LIKE '$2%' THEN 1 ELSE 0 END) AS bcrypt,
        #   SUM(CASE WHEN LENGTH(password_hash) <= 40 THEN 1 ELSE 0 END) AS legacy
        # FROM users;

        pass

# Usage
manager = MigrationPasswordManager()

# Scenario 1: bcrypt hash being verified
bcrypt_hash = "$2b$12$abcd..."
is_valid, new_hash = manager.verify_and_upgrade(bcrypt_hash, "user_password")
if is_valid and new_hash:
    print("Password verified, upgraded to Argon2")
    # Update database with new_hash

# Scenario 2: Argon2 hash with old parameters
old_argon2_hash = "$argon2id$v=19$m=4096,t=1,p=1$..."
is_valid, new_hash = manager.verify_and_upgrade(old_argon2_hash, "user_password")
if is_valid and new_hash:
    print("Password verified, Argon2 parameters upgraded")
    # Update database with new_hash
```

### 8.3 Force Password Reset Strategy

For critically weak hashes (MD5, SHA1, plaintext), consider forced reset:

```python
class ForcedResetManager:
    """
    Manage forced password resets for security migrations.

    Use when:
    - Current hashing is critically weak (MD5, SHA1, plaintext)
    - Mass breach of password database
    - Compliance requirements mandate reset
    """

    def __init__(self, db_connection):
        self.db = db_connection
        self.password_manager = PasswordHasher()

    def mark_for_reset(self, user_id: int, reason: str):
        """
        Mark user account for mandatory password reset.

        Args:
            user_id: User ID
            reason: Reset reason (for logging/audit)
        """
        # Set flag in database
        # Example SQL:
        # UPDATE users
        # SET
        #   must_reset_password = TRUE,
        #   reset_reason = %s,
        #   reset_marked_at = NOW()
        # WHERE id = %s
        pass

    def bulk_mark_legacy_users(self):
        """Mark all users with legacy hashes for reset."""
        # Example SQL:
        # UPDATE users
        # SET must_reset_password = TRUE
        # WHERE password_hash NOT LIKE '$argon2%'
        #   AND password_hash NOT LIKE '$2%'
        pass

    def process_reset(
        self,
        user_id: int,
        new_password: str
    ) -> bool:
        """
        Process password reset with new secure hash.

        Args:
            user_id: User ID
            new_password: New password

        Returns:
            bool: True if successful
        """
        # Validate new password
        # Hash with Argon2id
        new_hash = self.password_manager.hash(new_password)

        # Update database
        # Example SQL:
        # UPDATE users
        # SET
        #   password_hash = %s,
        #   must_reset_password = FALSE,
        #   password_reset_at = NOW()
        # WHERE id = %s

        return True
```

### 8.4 Migration Checklist

**Pre-Migration**:
- [ ] Backup database before starting
- [ ] Test migration logic on development data
- [ ] Document rollback procedures
- [ ] Estimate migration timeline (depends on login frequency)
- [ ] Set up monitoring for migration progress

**During Migration**:
- [ ] Monitor error rates and performance
- [ ] Track migration statistics
- [ ] Have rollback plan ready
- [ ] Communicate to users if needed (especially for forced resets)

**Post-Migration**:
- [ ] Verify all critical accounts migrated
- [ ] Remove legacy hash verification code after 90%+ migration
- [ ] Document new password policy
- [ ] Update security documentation

---

## 9. Complete Production Example

### 9.1 Full Implementation

```python
"""
Production-ready secure credential storage system.

Features:
- Argon2id password hashing (OWASP recommended)
- Automatic salt generation
- Optional pepper support
- Timing attack prevention
- Progressive hash migration
- Password policy enforcement
- Audit logging
"""

import os
import hmac
import hashlib
import secrets
from datetime import datetime
from typing import Optional, Tuple, Dict
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt


@dataclass
class User:
    """User model."""
    id: int
    username: str
    email: str
    password_hash: str
    created_at: datetime
    must_reset_password: bool = False


class SecureCredentialSystem:
    """
    Production-ready credential storage and authentication system.

    Security features:
    - Argon2id hashing (memory-hard, GPU-resistant)
    - Automatic unique salt per password
    - Optional system-wide pepper
    - Constant-time password verification
    - Timing attack mitigation
    - Hash migration support
    - Password policy enforcement
    - Audit logging
    """

    def __init__(
        self,
        pepper: Optional[bytes] = None,
        enable_audit_log: bool = True
    ):
        """
        Initialize credential system.

        Args:
            pepper: Optional system-wide secret (load from env)
            enable_audit_log: Enable audit logging
        """
        # Argon2id configuration (OWASP 2024 recommendations)
        self.ph = PasswordHasher(
            time_cost=2,        # Iterations
            memory_cost=19456,  # 19 MiB
            parallelism=1,      # Single thread
            hash_len=32,        # 256-bit hash
            salt_len=16         # 128-bit salt
        )

        self.pepper = pepper or os.environ.get('PASSWORD_PEPPER', '').encode()
        self.enable_audit_log = enable_audit_log

        # Precompute dummy hash for timing attack protection
        self.dummy_hash = self.ph.hash("dummy_password_constant_time")

    def hash_password(self, password: str) -> str:
        """
        Hash password with Argon2id.

        Security features:
        - Unique salt generated automatically
        - Optional pepper applied via HMAC
        - Memory-hard algorithm (GPU/ASIC resistant)

        Args:
            password: Plain text password

        Returns:
            str: Hash with embedded salt and parameters
        """
        if self.pepper:
            password = self._apply_pepper(password)

        return self.ph.hash(password)

    def verify_password(
        self,
        stored_hash: str,
        password: str,
        username: Optional[str] = None
    ) -> bool:
        """
        Verify password with comprehensive security protections.

        Security features:
        - Constant-time comparison
        - Timing attack mitigation
        - Audit logging

        Args:
            stored_hash: Hash from database
            password: Password to verify
            username: Optional username for audit log

        Returns:
            bool: True if password matches
        """
        if self.pepper:
            password = self._apply_pepper(password)

        try:
            self.ph.verify(stored_hash, password)

            if self.enable_audit_log:
                self._log_auth_attempt(username, True, "password_verified")

            return True

        except VerifyMismatchError:
            if self.enable_audit_log:
                self._log_auth_attempt(username, False, "password_mismatch")

            # Add timing jitter to prevent timing analysis
            self._timing_jitter()
            return False

    def verify_and_migrate(
        self,
        stored_hash: str,
        password: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify password and return upgraded hash if needed.

        Supports migration from:
        - bcrypt → Argon2id
        - Old Argon2 parameters → New parameters

        Args:
            stored_hash: Current hash from database
            password: Password to verify

        Returns:
            Tuple of (is_valid, new_hash)
            - new_hash is None if no upgrade needed
        """
        hash_type = self._detect_hash_type(stored_hash)

        if hash_type == 'argon2':
            # Verify Argon2
            is_valid = self.verify_password(stored_hash, password)

            if is_valid and self.ph.check_needs_rehash(stored_hash):
                # Parameters outdated, rehash
                new_hash = self.hash_password(password)
                return (True, new_hash)

            return (is_valid, None)

        elif hash_type == 'bcrypt':
            # Verify bcrypt and upgrade
            try:
                if self.pepper:
                    password = self._apply_pepper(password)

                is_valid = bcrypt.checkpw(
                    password.encode(),
                    stored_hash.encode()
                )

                if is_valid:
                    # Upgrade to Argon2
                    new_hash = self.hash_password(password)
                    return (True, new_hash)

                return (False, None)

            except Exception:
                return (False, None)

        else:
            # Unknown or insecure hash type
            return (False, None)

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        validate_password: bool = True
    ) -> Dict:
        """
        Create new user with secure password storage.

        Args:
            username: Unique username
            email: User email
            password: Plain text password
            validate_password: Enforce password policy

        Returns:
            dict: User data with password_hash

        Raises:
            ValueError: If password validation fails
        """
        if validate_password:
            is_valid, errors = self.validate_password(password)
            if not is_valid:
                raise ValueError(f"Password validation failed: {errors}")

        password_hash = self.hash_password(password)

        user_data = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.utcnow()
        }

        if self.enable_audit_log:
            self._log_auth_attempt(username, True, "user_created")

        return user_data

    def authenticate(
        self,
        username: str,
        password: str,
        user_lookup_func
    ) -> Optional[User]:
        """
        Authenticate user with timing attack protection.

        Args:
            username: Username to authenticate
            password: Password to verify
            user_lookup_func: Function to fetch user from database

        Returns:
            User object if valid, None if invalid
        """
        # Fetch user from database
        user = user_lookup_func(username)

        # Determine hash to verify (or dummy for non-existent users)
        if user:
            hash_to_verify = user.password_hash
        else:
            hash_to_verify = self.dummy_hash

        # Always perform verification (constant-time)
        is_valid = self.verify_password(hash_to_verify, password, username)

        # Return user only if exists AND password valid
        if user and is_valid:
            return user
        else:
            self._timing_jitter()
            return None

    def validate_password(self, password: str) -> Tuple[bool, list]:
        """
        Validate password against security policy.

        Checks:
        - Minimum length (12 characters)
        - Maximum length (128 characters)
        - Not in common passwords list
        - Not in breach database (optional)

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Length checks
        if len(password) < 12:
            errors.append("Password must be at least 12 characters")

        if len(password) > 128:
            errors.append("Password must not exceed 128 characters")

        # Common password check
        if password.lower() in self._get_common_passwords():
            errors.append("Password is too common")

        return (len(errors) == 0, errors)

    def _apply_pepper(self, password: str) -> str:
        """Apply pepper using HMAC-SHA256."""
        return hmac.new(
            self.pepper,
            password.encode(),
            hashlib.sha256
        ).hexdigest()

    def _detect_hash_type(self, hash_string: str) -> str:
        """Detect hash algorithm from format."""
        if hash_string.startswith('$argon2'):
            return 'argon2'
        elif hash_string.startswith(('$2a$', '$2b$', '$2y$')):
            return 'bcrypt'
        else:
            return 'unknown'

    def _timing_jitter(self):
        """Add small random delay (10-50ms) for timing attack mitigation."""
        import time
        delay_ms = secrets.randbelow(40) + 10
        time.sleep(delay_ms / 1000.0)

    def _log_auth_attempt(
        self,
        username: Optional[str],
        success: bool,
        event_type: str
    ):
        """
        Log authentication attempt for audit trail.

        In production: Send to centralized logging system
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'username': username or 'unknown',
            'success': success,
            'event_type': event_type,
            'ip_address': 'unknown'  # Add from request context
        }

        # In production: Send to logging system (e.g., ELK, Splunk)
        print(f"[AUDIT] {log_entry}")

    def _get_common_passwords(self) -> set:
        """
        Get common passwords list.

        In production: Load from file
        Source: https://github.com/danielmiessler/SecLists
        """
        return {
            'password', '123456', 'password123', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890'
        }


# Example usage
def example_usage():
    """Demonstrate secure credential system usage."""

    # Initialize system (load pepper from environment)
    pepper = os.environ.get('PASSWORD_PEPPER', 'change_me_in_production').encode()
    cred_system = SecureCredentialSystem(pepper=pepper)

    print("=== Secure Credential Storage System Demo ===\n")

    # 1. Create user with password validation
    print("1. Creating user with strong password...")
    try:
        user_data = cred_system.create_user(
            username='alice',
            email='alice@example.com',
            password='MyStr0ng!P@ssw0rd2024'
        )
        print(f"✓ User created successfully")
        print(f"  Password hash: {user_data['password_hash'][:50]}...")
    except ValueError as e:
        print(f"✗ Failed: {e}")

    # 2. Attempt with weak password
    print("\n2. Attempting to create user with weak password...")
    try:
        cred_system.create_user(
            username='bob',
            email='bob@example.com',
            password='password123'
        )
    except ValueError as e:
        print(f"✓ Correctly rejected: {e}")

    # 3. Verify correct password
    print("\n3. Verifying correct password...")
    is_valid = cred_system.verify_password(
        user_data['password_hash'],
        'MyStr0ng!P@ssw0rd2024',
        'alice'
    )
    print(f"✓ Verification result: {is_valid}")

    # 4. Verify incorrect password
    print("\n4. Verifying incorrect password...")
    is_valid = cred_system.verify_password(
        user_data['password_hash'],
        'wrong_password',
        'alice'
    )
    print(f"✓ Verification result: {is_valid}")

    # 5. Demonstrate hash migration
    print("\n5. Demonstrating hash migration (bcrypt → Argon2)...")
    bcrypt_hash = bcrypt.hashpw(
        b'MyStr0ng!P@ssw0rd2024',
        bcrypt.gensalt()
    ).decode()
    print(f"  Old bcrypt hash: {bcrypt_hash[:50]}...")

    is_valid, new_hash = cred_system.verify_and_migrate(
        bcrypt_hash,
        'MyStr0ng!P@ssw0rd2024'
    )

    if new_hash:
        print(f"✓ Hash migrated to Argon2")
        print(f"  New hash: {new_hash[:50]}...")

    print("\n=== Demo Complete ===")


if __name__ == '__main__':
    example_usage()
```

---

## 10. Key Takeaways and Recommendations

### 10.1 Priority Implementation Checklist

**Immediate Actions** (Do First):
1. ✅ **Use Argon2id** for all new password hashing
   - Python: `pip install argon2-cffi`
   - Configuration: `time_cost=2, memory_cost=19456, parallelism=1`

2. ✅ **Let library handle salts** - Do not implement manual salt handling
   - All modern libraries generate unique salts automatically

3. ✅ **Use constant-time comparison** for password verification
   - `hmac.compare_digest()` or `secrets.compare_digest()`

4. ✅ **Store pepper separately** (if used)
   - Environment variables or secrets manager
   - Never in database or source code

5. ✅ **Enforce minimum password length** (12+ characters)
   - Drop complex composition rules (NIST guidance)

**Secondary Actions** (Add Next):
6. ✅ Enable progressive hash migration for legacy systems
7. ✅ Check passwords against breach databases (haveibeenpwned API)
8. ✅ Implement rate limiting on authentication endpoints
9. ✅ Enable audit logging for security events
10. ✅ Use database encryption at rest (filesystem or TDE)

### 10.2 Common Mistakes to Avoid

**❌ Don't**:
- Store passwords in plain text (ever)
- Use MD5, SHA1, or SHA256 for passwords (not password hashing algorithms)
- Implement custom hashing algorithms
- Store pepper in the same database as hashes
- Use predictable salts or reuse salts
- Skip password verification to "optimize" performance
- Disable paste functionality in password fields
- Force periodic password changes without reason
- Use overly complex password requirements

**✅ Do**:
- Use Argon2id (or bcrypt as fallback)
- Let libraries handle salt generation
- Apply pepper via HMAC if using
- Use constant-time comparisons
- Enforce minimum length (12+ characters)
- Check against common passwords and breaches
- Rate limit authentication attempts
- Enable audit logging
- Use TLS for all connections
- Implement progressive hash migration

### 10.3 Python Library Quick Reference

```python
# Argon2 (RECOMMENDED)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
hash = ph.hash("password")
ph.verify(hash, "password")

# bcrypt (WIDELY SUPPORTED)
import bcrypt
hash = bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=12))
bcrypt.checkpw(b"password", hash)

# werkzeug (FLASK USERS)
from werkzeug.security import generate_password_hash, check_password_hash
hash = generate_password_hash("password")  # Uses scrypt by default
check_password_hash(hash, "password")

# Cryptographic random (SALT/PEPPER GENERATION)
import secrets
salt = secrets.token_bytes(32)
pepper = secrets.token_hex(32)
```

### 10.4 Security Parameter Recommendations (2024-2025)

| Parameter | Minimum | Recommended | High Security |
|-----------|---------|-------------|---------------|
| **Argon2id** | | | |
| Memory (m) | 19456 (19 MiB) | 65536 (64 MiB) | 131072 (128 MiB) |
| Iterations (t) | 2 | 3 | 4 |
| Parallelism (p) | 1 | 1 | 2 |
| **bcrypt** | | | |
| Rounds | 10 | 12 | 14 |
| **scrypt** | | | |
| N (CPU/mem cost) | 2^17 | 2^18 | 2^20 |
| r (block size) | 8 | 8 | 8 |
| p (parallel) | 1 | 1 | 1 |
| **General** | | | |
| Salt length | 16 bytes | 32 bytes | 32 bytes |
| Hash length | 32 bytes | 32 bytes | 64 bytes |
| Password min | 12 chars | 16 chars | 20 chars |

### 10.5 Performance Targets

**Target hash computation time**: 200-500ms on server hardware
- Too fast: Vulnerable to brute force
- Too slow: DoS risk, poor UX

**Adjust parameters based on**:
- Server hardware capabilities
- Expected authentication load
- Security requirements
- User experience constraints

### 10.6 Compliance Mappings

| Standard | Password Hashing Requirement |
|----------|------------------------------|
| **OWASP ASVS 4.0** | V2.4.1: Argon2id, scrypt, bcrypt, or PBKDF2 |
| **NIST SP 800-63B** | Memorized secret ≥8 chars, salted hash |
| **PCI DSS 4.0** | Strong cryptography, salted hashes |
| **GDPR** | Appropriate security measures for personal data |
| **HIPAA** | Encryption and integrity controls |
| **ISO 27001** | Cryptographic controls (A.10.1) |

---

## 11. Additional Resources

### Documentation
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf)

### Python Libraries
- [argon2-cffi](https://github.com/hynek/argon2-cffi)
- [bcrypt](https://github.com/pyca/bcrypt/)
- [werkzeug.security](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security)
- [passlib](https://passlib.readthedocs.io/)

### Tools
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [Common Password Lists](https://github.com/danielmiessler/SecLists/tree/master/Passwords)

---

**Document Version**: 1.0
**Last Updated**: 2025-10-16
**Confidence Level**: High (based on 2024-2025 authoritative sources)
