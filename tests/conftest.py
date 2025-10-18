"""
Pytest Configuration and Fixtures
Shared test utilities for all test modules
"""
import pytest
import os
import tempfile
from datetime import datetime, timedelta
from database import get_db_connection
from database_auth import create_auth_tables
from app_auth import app as flask_app


@pytest.fixture(scope='session')
def test_db():
    """
    Create a temporary test database for the session

    Yields:
        Path to test database file
    """
    # Create temporary database file
    db_fd, db_path = tempfile.mkstemp(suffix='.db')

    # Set environment to use test database
    os.environ['DATABASE_PATH'] = db_path

    # Initialize database schema
    os.close(db_fd)

    yield db_path

    # Cleanup
    try:
        os.unlink(db_path)
    except:
        pass


@pytest.fixture
def db_connection(test_db):
    """
    Provide a clean database connection for each test

    Automatically rolls back after each test
    """
    import sqlite3
    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row

    # Initialize tables
    create_test_schema(conn)

    yield conn

    # Rollback and close
    conn.rollback()
    conn.close()


def create_test_schema(conn):
    """Create minimal test database schema"""
    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            totp_enabled INTEGER DEFAULT 0,
            totp_secret TEXT,
            backup_codes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Login attempts
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Account lockouts
    conn.execute('''
        CREATE TABLE IF NOT EXISTS account_lockouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            locked_until TIMESTAMP NOT NULL,
            failed_attempts INTEGER DEFAULT 0
        )
    ''')

    # Rate limits
    conn.execute('''
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            request_count INTEGER DEFAULT 1,
            window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            window_end TIMESTAMP NOT NULL
        )
    ''')

    # OAuth2 clients
    conn.execute('''
        CREATE TABLE IF NOT EXISTS oauth2_clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE NOT NULL,
            client_secret_hash TEXT NOT NULL,
            client_name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL
        )
    ''')

    # OAuth2 authorization codes
    conn.execute('''
        CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT,
            code_challenge_method TEXT,
            used INTEGER DEFAULT 0,
            expires_at TIMESTAMP NOT NULL
        )
    ''')

    # OAuth2 tokens
    conn.execute('''
        CREATE TABLE IF NOT EXISTS oauth2_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            access_token TEXT UNIQUE NOT NULL,
            refresh_token TEXT UNIQUE,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            scope TEXT,
            token_family_id TEXT NOT NULL,
            refresh_token_used INTEGER DEFAULT 0,
            revoked INTEGER DEFAULT 0,
            issued_at INTEGER NOT NULL,
            expires_in INTEGER NOT NULL,
            refresh_token_expires_at INTEGER
        )
    ''')

    # Security events
    conn.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            username TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()


@pytest.fixture
def app():
    """
    Flask application fixture with test configuration
    """
    flask_app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,  # Disable CSRF for testing
        'SECRET_KEY': 'test-secret-key',
    })

    yield flask_app


@pytest.fixture
def client(app):
    """
    Flask test client
    """
    return app.test_client()


@pytest.fixture
def runner(app):
    """
    Flask test CLI runner
    """
    return app.test_cli_runner()


@pytest.fixture
def test_user_data():
    """
    Standard test user data
    """
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'TestPassword123!@#',
        'password_hash': '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$abcd1234...'
    }


@pytest.fixture
def mock_time(monkeypatch):
    """
    Mock datetime.utcnow for time-sensitive tests
    """
    class MockDatetime:
        @staticmethod
        def utcnow():
            return datetime(2025, 1, 1, 12, 0, 0)

    monkeypatch.setattr('datetime.datetime', MockDatetime)
    return MockDatetime.utcnow()


@pytest.fixture
def mock_totp_code():
    """
    Mock TOTP code for 2FA testing
    """
    return '123456'


@pytest.fixture
def mock_oauth2_client():
    """
    Mock OAuth2 client data
    """
    return {
        'client_id': 'test_client_123',
        'client_secret': 'test_secret_456',
        'client_name': 'Test Client',
        'redirect_uris': ['http://localhost:5000/callback']
    }
