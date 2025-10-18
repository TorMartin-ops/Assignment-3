"""
OAuth2 Authorization Server Service
Implements OAuth2 Authorization Code Flow with PKCE (RFC 7636)
Uses Authlib for OAuth2 provider functionality
"""
import secrets
import hashlib
import base64
import json
import time
from datetime import datetime, timedelta
from database import get_db_connection

class OAuth2Service:
    """
    OAuth2 Authorization Server
    Implements Authorization Code Flow with mandatory PKCE
    """

    # Token expiration times
    ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    REFRESH_TOKEN_EXPIRES = 2592000  # 30 days
    AUTH_CODE_EXPIRES = 600  # 10 minutes

    def __init__(self):
        """Initialize OAuth2 service"""
        pass

    def get_client(self, client_id):
        """
        Get OAuth2 client by client_id

        Args:
            client_id: Client identifier

        Returns:
            Client dict or None
        """
        conn = get_db_connection()
        client = conn.execute(
            'SELECT * FROM oauth2_clients WHERE client_id = ?',
            (client_id,)
        ).fetchone()
        conn.close()

        return dict(client) if client else None

    def validate_client(self, client_id, client_secret=None):
        """
        Validate client credentials

        Args:
            client_id: Client identifier
            client_secret: Client secret (optional for public clients)

        Returns:
            (is_valid, client_or_error) tuple
        """
        client = self.get_client(client_id)

        if not client:
            return False, "Invalid client_id"

        # Public clients (e.g., SPAs) don't need secret validation
        if client_secret is None:
            return True, client

        # Validate client secret
        from werkzeug.security import check_password_hash

        if check_password_hash(client['client_secret_hash'], client_secret):
            return True, client
        else:
            return False, "Invalid client_secret"

    def validate_redirect_uri(self, client_id, redirect_uri):
        """
        Validate redirect URI against registered URIs (exact match only)

        Args:
            client_id: Client identifier
            redirect_uri: Redirect URI to validate

        Returns:
            Boolean indicating if URI is valid
        """
        client = self.get_client(client_id)

        if not client:
            return False

        # Parse allowed redirect URIs
        allowed_uris = json.loads(client['redirect_uris'])

        # SECURITY: Exact string match only (no wildcards, no pattern matching)
        return redirect_uri in allowed_uris

    def validate_pkce(self, code_verifier, code_challenge, code_challenge_method='S256'):
        """
        Validate PKCE code_verifier against code_challenge

        Args:
            code_verifier: Original code verifier
            code_challenge: Stored code challenge
            code_challenge_method: Challenge method (S256 or plain)

        Returns:
            Boolean indicating if PKCE is valid
        """
        if code_challenge_method == 'S256':
            # SHA-256 hash
            computed_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip('=')

            return computed_challenge == code_challenge

        elif code_challenge_method == 'plain':
            # Plain text (discouraged, but allowed by spec)
            return code_verifier == code_challenge

        return False

    def generate_authorization_code(self, client_id, user_id, redirect_uri,
                                   scope, code_challenge, code_challenge_method):
        """
        Generate authorization code

        Args:
            client_id: Client identifier
            user_id: User ID
            redirect_uri: Redirect URI
            scope: Requested scope
            code_challenge: PKCE code challenge
            code_challenge_method: Challenge method

        Returns:
            Authorization code string
        """
        # Generate cryptographically secure code
        code = secrets.token_urlsafe(32)

        # Calculate expiration
        expires_at = datetime.utcnow() + timedelta(seconds=self.AUTH_CODE_EXPIRES)

        conn = get_db_connection()

        conn.execute('''
            INSERT INTO oauth2_authorization_codes
            (code, client_id, user_id, redirect_uri, scope,
             code_challenge, code_challenge_method, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (code, client_id, user_id, redirect_uri, scope,
              code_challenge, code_challenge_method, expires_at))

        conn.commit()
        conn.close()

        return code

    def validate_authorization_code(self, code, client_id):
        """
        Validate and consume authorization code

        Args:
            code: Authorization code
            client_id: Client identifier

        Returns:
            (is_valid, code_data_or_error) tuple
        """
        conn = get_db_connection()

        auth_code = conn.execute('''
            SELECT * FROM oauth2_authorization_codes
            WHERE code = ? AND client_id = ? AND used = 0
        ''', (code, client_id)).fetchone()

        if not auth_code:
            conn.close()
            return False, "Invalid or expired authorization code"

        # Check expiration
        if datetime.fromisoformat(auth_code['expires_at']) < datetime.utcnow():
            conn.close()
            return False, "Authorization code expired"

        # Mark as used (single use only)
        conn.execute('''
            UPDATE oauth2_authorization_codes SET used = 1 WHERE code = ?
        ''', (code,))
        conn.commit()
        conn.close()

        return True, dict(auth_code)

    def generate_tokens(self, client_id, user_id, scope):
        """
        Generate access and refresh tokens

        Args:
            client_id: Client identifier
            user_id: User ID
            scope: Token scope

        Returns:
            Token response dict
        """
        # Generate tokens
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        token_family_id = secrets.token_urlsafe(16)

        # Current timestamp
        issued_at = int(time.time())
        refresh_expires_at = issued_at + self.REFRESH_TOKEN_EXPIRES

        conn = get_db_connection()

        conn.execute('''
            INSERT INTO oauth2_tokens
            (access_token, refresh_token, token_type, client_id, user_id,
             scope, token_family_id, issued_at, expires_in,
             refresh_token_expires_at)
            VALUES (?, ?, 'Bearer', ?, ?, ?, ?, ?, ?, ?)
        ''', (access_token, refresh_token, client_id, user_id, scope,
              token_family_id, issued_at, self.ACCESS_TOKEN_EXPIRES,
              refresh_expires_at))

        conn.commit()
        conn.close()

        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': self.ACCESS_TOKEN_EXPIRES,
            'refresh_token': refresh_token,
            'scope': scope
        }

    def validate_access_token(self, access_token):
        """
        Validate access token

        Args:
            access_token: Access token string

        Returns:
            (is_valid, token_data_or_error) tuple
        """
        conn = get_db_connection()

        token = conn.execute('''
            SELECT * FROM oauth2_tokens WHERE access_token = ? AND revoked = 0
        ''', (access_token,)).fetchone()

        if not token:
            conn.close()
            return False, "Invalid access token"

        # Check expiration
        expires_at = token['issued_at'] + token['expires_in']
        if expires_at < int(time.time()):
            conn.close()
            return False, "Access token expired"

        conn.close()
        return True, dict(token)

    def refresh_access_token(self, refresh_token, client_id):
        """
        Refresh access token using refresh token (with rotation)

        Args:
            refresh_token: Refresh token
            client_id: Client identifier

        Returns:
            (success, token_response_or_error) tuple
        """
        conn = get_db_connection()

        token = conn.execute('''
            SELECT * FROM oauth2_tokens
            WHERE refresh_token = ? AND client_id = ? AND revoked = 0
        ''', (refresh_token, client_id)).fetchone()

        if not token:
            conn.close()
            return False, "Invalid refresh token"

        # Check if already used (reuse detection)
        if token['refresh_token_used']:
            # SECURITY: Revoke entire token family
            self._revoke_token_family(token['token_family_id'])
            conn.close()
            return False, "Token reuse detected - all tokens revoked"

        # Check refresh token expiration
        if token['refresh_token_expires_at'] < int(time.time()):
            conn.close()
            return False, "Refresh token expired"

        # Mark old refresh token as used
        conn.execute('''
            UPDATE oauth2_tokens
            SET refresh_token_used = 1, revoked = 1
            WHERE id = ?
        ''', (token['id'],))
        conn.commit()

        # Generate new tokens (rotation)
        new_tokens = self.generate_tokens(
            client_id,
            token['user_id'],
            token['scope']
        )

        # Update token family
        conn.execute('''
            UPDATE oauth2_tokens
            SET token_family_id = ?
            WHERE access_token = ?
        ''', (token['token_family_id'], new_tokens['access_token']))
        conn.commit()
        conn.close()

        return True, new_tokens

    def revoke_token(self, token, token_type_hint='access_token'):
        """
        Revoke access or refresh token

        Args:
            token: Token string
            token_type_hint: Type of token (access_token or refresh_token)

        Returns:
            Success boolean
        """
        conn = get_db_connection()

        if token_type_hint == 'access_token':
            conn.execute('''
                UPDATE oauth2_tokens
                SET revoked = 1, revoked_at = ?
                WHERE access_token = ?
            ''', (datetime.utcnow(), token))
        else:
            conn.execute('''
                UPDATE oauth2_tokens
                SET revoked = 1, revoked_at = ?
                WHERE refresh_token = ?
            ''', (datetime.utcnow(), token))

        conn.commit()
        conn.close()

        return True

    def _revoke_token_family(self, token_family_id):
        """
        Revoke all tokens in a token family (for reuse detection)

        Args:
            token_family_id: Token family identifier
        """
        conn = get_db_connection()

        conn.execute('''
            UPDATE oauth2_tokens
            SET revoked = 1, revoked_at = ?
            WHERE token_family_id = ?
        ''', (datetime.utcnow(), token_family_id))

        conn.commit()
        conn.close()

        print(f"🚨 Token family revoked: {token_family_id} (reuse detected)")

    def get_user_info(self, user_id):
        """
        Get user information for OAuth2 userinfo endpoint

        Args:
            user_id: User ID

        Returns:
            User info dict
        """
        conn = get_db_connection()

        user = conn.execute(
            'SELECT id, username, email FROM users WHERE id = ?',
            (user_id,)
        ).fetchone()

        conn.close()

        if not user:
            return None

        return {
            'sub': str(user['id']),  # Subject (user identifier)
            'username': user['username'],
            'email': user['email']
        }


# Singleton instance
_oauth2_service = None

def get_oauth2_service():
    """Get singleton OAuth2 service instance"""
    global _oauth2_service
    if _oauth2_service is None:
        _oauth2_service = OAuth2Service()
    return _oauth2_service
