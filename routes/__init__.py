"""
Flask Routes Package
"""
from .auth_routes import auth_bp
from .oauth_routes import oauth_bp
from .twofa_routes import twofa_bp
from .google_oauth_routes import google_oauth_bp

__all__ = ['auth_bp', 'oauth_bp', 'twofa_bp', 'google_oauth_bp']
