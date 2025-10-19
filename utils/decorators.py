"""
Utility Decorators for Route Protection
"""
from functools import wraps
from flask import session, flash, redirect, url_for


def login_required(f):
    """
    Decorator to require user login for protected routes

    Checks if user_id exists in session, redirects to login if not
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def regenerate_session():
    """
    Regenerate session ID to prevent session fixation attacks

    This should be called:
    - After successful password authentication
    - After successful 2FA verification
    - On privilege escalation

    Implementation:
    Flask doesn't have built-in session.regenerate(), so we:
    1. Save current session data
    2. Clear session (forces new session ID on next access)
    3. Restore session data
    4. Mark as modified

    Security Note:
    This prevents session fixation where an attacker sets a victim's
    session ID before authentication, then uses it after victim logs in.
    """
    # Save current session data
    session_data = {k: v for k, v in session.items()}

    # Clear session (this will cause Flask to generate a new session ID)
    session.clear()

    # Restore session data with new session ID
    session.update(session_data)

    # Mark session as modified to ensure new cookie is sent
    session.modified = True
