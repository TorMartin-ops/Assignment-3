"""
Google OAuth Routes
Handles "Sign in with Google" functionality
"""
from flask import Blueprint, redirect, url_for, session, flash, request
import requests
import secrets
import os
from database import get_db_connection
from services.security_service import get_security_service

google_oauth_bp = Blueprint('google_oauth', __name__, url_prefix='/auth/google')

security_service = get_security_service()

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

def get_google_provider_cfg():
    """Get Google's OpenID configuration"""
    try:
        return requests.get(GOOGLE_DISCOVERY_URL).json()
    except:
        return None

@google_oauth_bp.route('/login')
def google_login():
    """
    Initiate Google OAuth login flow
    Redirects user to Google login page
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash('Google OAuth is not configured. Please set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env file.', 'warning')
        return redirect(url_for('auth.login'))

    # Get Google's OAuth2 endpoints
    google_provider_cfg = get_google_provider_cfg()
    if not google_provider_cfg:
        flash('Could not connect to Google OAuth service', 'danger')
        return redirect(url_for('auth.login'))

    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    # Build authorization URL
    redirect_uri = url_for('google_oauth.google_callback', _external=True)

    auth_url = (
        f"{authorization_endpoint}?"
        f"client_id={GOOGLE_CLIENT_ID}&"
        f"redirect_uri={redirect_uri}&"
        f"response_type=code&"
        f"scope=openid email profile&"
        f"state={state}"
    )

    return redirect(auth_url)

@google_oauth_bp.route('/callback')
def google_callback():
    """
    Handle Google OAuth callback
    Exchange authorization code for user information
    """
    # Verify state to prevent CSRF
    state = request.args.get('state')
    if not state or state != session.get('oauth_state'):
        flash('Invalid state parameter. Possible CSRF attack.', 'danger')
        return redirect(url_for('auth.login'))

    # Clear state from session
    session.pop('oauth_state', None)

    # Get authorization code
    code = request.args.get('code')
    if not code:
        error = request.args.get('error', 'Unknown error')
        flash(f'Google authentication failed: {error}', 'danger')
        return redirect(url_for('auth.login'))

    # Get Google's OAuth2 endpoints
    google_provider_cfg = get_google_provider_cfg()
    if not google_provider_cfg:
        flash('Could not connect to Google OAuth service', 'danger')
        return redirect(url_for('auth.login'))

    token_endpoint = google_provider_cfg["token_endpoint"]
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]

    # Exchange code for tokens
    redirect_uri = url_for('google_oauth.google_callback', _external=True)

    token_response = requests.post(
        token_endpoint,
        data={
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    if token_response.status_code != 200:
        flash('Failed to get access token from Google', 'danger')
        return redirect(url_for('auth.login'))

    tokens = token_response.json()
    access_token = tokens.get('access_token')

    # Get user info from Google
    userinfo_response = requests.get(
        userinfo_endpoint,
        headers={'Authorization': f'Bearer {access_token}'}
    )

    if userinfo_response.status_code != 200:
        flash('Failed to get user information from Google', 'danger')
        return redirect(url_for('auth.login'))

    userinfo = userinfo_response.json()

    # Extract user information
    google_id = userinfo.get('sub')  # Google's unique user ID
    email = userinfo.get('email')
    name = userinfo.get('name', '')
    email_verified = userinfo.get('email_verified', False)

    if not email_verified:
        flash('Please verify your email with Google first', 'warning')
        return redirect(url_for('auth.login'))

    # Find or create user
    conn = get_db_connection()

    # Check if user exists with this Google ID
    user = conn.execute(
        'SELECT * FROM users WHERE google_id = ?',
        (google_id,)
    ).fetchone()

    if not user:
        # Check if user exists with this email
        user = conn.execute(
            'SELECT * FROM users WHERE email = ?',
            (email,)
        ).fetchone()

        if user:
            # Link Google ID to existing account
            conn.execute(
                'UPDATE users SET google_id = ? WHERE id = ?',
                (google_id, user['id'])
            )
            conn.commit()
            flash('Your Google account has been linked to your existing account', 'info')
        else:
            # Create new user
            # Generate username from email or name
            username_base = email.split('@')[0] if email else name.replace(' ', '').lower()
            username = username_base

            # Ensure username is unique
            counter = 1
            while conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
                username = f"{username_base}{counter}"
                counter += 1

            # Create user (no password needed for OAuth users)
            conn.execute('''
                INSERT INTO users (username, email, password, google_id, email_verified)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, '', google_id, 1))
            conn.commit()

            user = conn.execute(
                'SELECT * FROM users WHERE google_id = ?',
                (google_id,)
            ).fetchone()

            flash(f'Welcome! Account created successfully as {username}', 'success')

    # Log user in
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['authenticated'] = True
    session['auth_method'] = 'google_oauth'

    # Log security event
    security_service.log_security_event(
        'google_oauth_login',
        username=user['username'],
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        metadata={'email': email, 'google_id': google_id},
        severity='info'
    )

    conn.close()

    flash(f'Welcome back, {user["username"]}!', 'success')
    return redirect(url_for('home'))
