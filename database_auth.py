"""
Enhanced Database Schema for Authentication System
Extends existing database with authentication, 2FA, OAuth2, and security features
"""
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

DATABASE = 'recipe_app.db'

def get_db_connection():
    """Get database connection with Row factory"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_auth_tables():
    """Create authentication-related tables"""
    conn = get_db_connection()

    # ============================================
    # 1. ENHANCE USERS TABLE (add new columns)
    # ============================================
    # Check if columns exist and add if missing
    try:
        conn.execute('ALTER TABLE users ADD COLUMN password_salt TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists

    try:
        conn.execute('ALTER TABLE users ADD COLUMN password_version INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass

    # Two-Factor Authentication columns
    try:
        conn.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN backup_codes TEXT')  # JSON array
    except sqlite3.OperationalError:
        pass

    # OAuth2 Integration
    try:
        conn.execute('ALTER TABLE users ADD COLUMN oauth_provider TEXT')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN oauth_user_id TEXT')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN oauth_linked INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute('ALTER TABLE users ADD COLUMN last_login TIMESTAMP')
    except sqlite3.OperationalError:
        pass

    conn.commit()

    # ============================================
    # 2. LOGIN ATTEMPTS TABLE (Brute Force Tracking)
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            success INTEGER DEFAULT 0,
            failure_reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create indexes for performance
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_login_attempts_username
        ON login_attempts(username, timestamp)
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip
        ON login_attempts(ip_address, timestamp)
    ''')

    # ============================================
    # 3. ACCOUNT LOCKOUTS TABLE
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS account_lockouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            locked_until TIMESTAMP NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_reason TEXT,
            locked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locked_by TEXT DEFAULT 'system'
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_lockouts_until
        ON account_lockouts(locked_until)
    ''')

    # ============================================
    # 4. RATE LIMIT TRACKING (Database-based, no Redis)
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            request_count INTEGER DEFAULT 1,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            window_end TIMESTAMP NOT NULL,
            UNIQUE(key, endpoint, window_start)
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_rate_limit_key
        ON rate_limits(key, endpoint, window_end)
    ''')

    # ============================================
    # 5. SECURITY EVENTS TABLE (Audit Log)
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            username TEXT,
            ip_address TEXT,
            user_agent TEXT,
            endpoint TEXT,
            metadata TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_security_events_type
        ON security_events(event_type, timestamp)
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_security_events_username
        ON security_events(username, timestamp)
    ''')

    # ============================================
    # 6. OAUTH2 CLIENTS TABLE
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS oauth2_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE NOT NULL,
            client_secret_hash TEXT NOT NULL,
            client_name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            default_redirect_uri TEXT,
            grant_types TEXT DEFAULT 'authorization_code refresh_token',
            response_types TEXT DEFAULT 'code',
            scope TEXT DEFAULT 'profile email',
            token_endpoint_auth_method TEXT DEFAULT 'client_secret_post',
            require_pkce INTEGER DEFAULT 1,
            public_key TEXT,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_oauth_client_id
        ON oauth2_clients(client_id)
    ''')

    # ============================================
    # 7. OAUTH2 AUTHORIZATION CODES TABLE
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            code_challenge TEXT,
            code_challenge_method TEXT,
            used INTEGER DEFAULT 0,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_auth_code
        ON oauth2_authorization_codes(code)
    ''')

    # ============================================
    # 8. OAUTH2 TOKENS TABLE
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS oauth2_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_token TEXT UNIQUE NOT NULL,
            refresh_token TEXT UNIQUE,
            token_type TEXT DEFAULT 'Bearer',
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            scope TEXT,
            token_family_id TEXT NOT NULL,
            refresh_token_used INTEGER DEFAULT 0,
            revoked INTEGER DEFAULT 0,
            revoked_at TIMESTAMP,
            issued_at INTEGER NOT NULL,
            expires_in INTEGER NOT NULL,
            refresh_token_expires_at INTEGER,
            FOREIGN KEY (client_id) REFERENCES oauth2_clients(client_id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_token_access
        ON oauth2_tokens(access_token)
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_token_refresh
        ON oauth2_tokens(refresh_token)
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_token_family
        ON oauth2_tokens(token_family_id)
    ''')

    # ============================================
    # 9. SESSIONS TABLE
    # ============================================
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            session_data TEXT,
            ip_address TEXT,
            user_agent TEXT,
            device_fingerprint TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_sessions_id
        ON sessions(session_id)
    ''')

    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_sessions_user
        ON sessions(user_id, is_active)
    ''')

    conn.commit()
    conn.close()

    # Authentication tables created successfully

def create_sample_oauth_client():
    """Create a sample OAuth2 client for testing"""
    conn = get_db_connection()

    # Check if sample client exists
    existing = conn.execute(
        'SELECT id FROM oauth2_clients WHERE client_id = ?',
        ('test_client_id',)
    ).fetchone()

    if not existing:
        import json

        client_secret = 'test_client_secret'
        client_secret_hash = generate_password_hash(client_secret)

        conn.execute('''
            INSERT INTO oauth2_clients
            (client_id, client_secret_hash, client_name, redirect_uris,
             default_redirect_uri, scope)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            'test_client_id',
            client_secret_hash,
            'Test OAuth2 Client',
            json.dumps(['http://localhost:5000/callback', 'http://localhost:3000/callback']),
            'http://localhost:5000/callback',
            'profile email'
        ))

        conn.commit()
        # Sample OAuth2 client created: test_client_id / test_client_secret

    conn.close()

def cleanup_expired_data():
    """Cleanup expired sessions, rate limits, and old login attempts"""
    conn = get_db_connection()
    now = datetime.utcnow()

    # Delete expired sessions
    deleted_sessions = conn.execute(
        'DELETE FROM sessions WHERE expires_at < ?',
        (now,)
    ).rowcount

    # Delete old rate limits (older than 1 hour)
    hour_ago = now - timedelta(hours=1)
    deleted_limits = conn.execute(
        'DELETE FROM rate_limits WHERE window_end < ?',
        (hour_ago,)
    ).rowcount

    # Delete old login attempts (older than 24 hours)
    day_ago = now - timedelta(days=1)
    deleted_attempts = conn.execute(
        'DELETE FROM login_attempts WHERE timestamp < ?',
        (day_ago,)
    ).rowcount

    conn.commit()
    conn.close()

    # Cleanup completed: sessions, rate limits, and login attempts purged
    return (deleted_sessions, deleted_limits, deleted_attempts)

def initialize_auth_database():
    """Initialize the complete authentication database"""
    # Create all auth tables
    create_auth_tables()

    # Create sample OAuth2 client
    create_sample_oauth_client()

    # Run initial cleanup
    cleanup_expired_data()

    # Authentication database initialization complete

if __name__ == '__main__':
    # Initialize database when run as script
    initialize_auth_database()
    print("Authentication database initialization complete.")
