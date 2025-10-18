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
