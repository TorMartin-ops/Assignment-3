"""
OAuth2 Routes
Handles OAuth2 Authorization Code Flow with PKCE
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import csrf
from services.oauth2_service import get_oauth2_service
from services.security_service import get_security_service
import secrets

oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

# Get services
oauth2_service = get_oauth2_service()
security_service = get_security_service()

@oauth_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    """
    OAuth2 authorization endpoint
    GET: Show consent screen
    POST: User approves/denies
    """
    if request.method == 'GET':
        # Parse authorization request
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        response_type = request.args.get('response_type', 'code')
        scope = request.args.get('scope', '')
        state = request.args.get('state')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method', 'S256')

        # Validate client
        if not client_id:
            return jsonify({'error': 'invalid_request', 'error_description': 'client_id required'}), 400

        client = oauth2_service.get_client(client_id)
        if not client:
            return jsonify({'error': 'invalid_client'}), 401

        # Validate redirect URI
        if not redirect_uri or not oauth2_service.validate_redirect_uri(client_id, redirect_uri):
            return jsonify({'error': 'invalid_request', 'error_description': 'invalid redirect_uri'}), 400

        # Validate response type
        if response_type != 'code':
            return redirect(f"{redirect_uri}?error=unsupported_response_type&state={state}")

        # Validate PKCE (MANDATORY)
        if not code_challenge:
            return redirect(f"{redirect_uri}?error=invalid_request&error_description=code_challenge required&state={state}")

        # Check if user is logged in
        if 'user_id' not in session:
            # Redirect to login, then back to authorize
            session['oauth_return_to'] = request.url
            flash('Please log in to continue', 'info')
            return redirect(url_for('auth.login'))

        # Store authorization request in session
        session['oauth_request'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method
        }

        # Show consent screen
        return render_template('oauth/authorize.html',
                             client=client,
                             scope=scope.split())

    # POST: User decision
    approved = request.form.get('approved') == 'yes'
    oauth_request = session.pop('oauth_request', None)

    if not oauth_request:
        return jsonify({'error': 'invalid_request'}), 400

    redirect_uri = oauth_request['redirect_uri']
    state = oauth_request['state']

    if not approved:
        # User denied
        return redirect(f"{redirect_uri}?error=access_denied&state={state}")

    # User approved - generate authorization code
    code = oauth2_service.generate_authorization_code(
        oauth_request['client_id'],
        session['user_id'],
        oauth_request['redirect_uri'],
        oauth_request['scope'],
        oauth_request['code_challenge'],
        oauth_request['code_challenge_method']
    )

    # Log event
    security_service.log_security_event(
        'oauth_authorization_granted',
        username=session['username'],
        ip_address=request.remote_addr,
        metadata={'client_id': oauth_request['client_id']},
        severity='info'
    )

    # Redirect with code
    separator = '&' if '?' in redirect_uri else '?'
    return redirect(f"{redirect_uri}{separator}code={code}&state={state}")

@oauth_bp.route('/token', methods=['POST'])
@csrf.exempt  # OAuth2 token endpoint uses client authentication, not CSRF tokens
def token():
    """
    OAuth2 token endpoint
    Exchange authorization code for tokens
    """
    grant_type = request.form.get('grant_type')

    if grant_type == 'authorization_code':
        # Authorization code flow
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        code_verifier = request.form.get('code_verifier')

        # Validate client
        is_valid, client = oauth2_service.validate_client(client_id, client_secret)
        if not is_valid:
            return jsonify({'error': 'invalid_client'}), 401

        # Validate authorization code
        is_valid, auth_code = oauth2_service.validate_authorization_code(code, client_id)
        if not is_valid:
            return jsonify({'error': 'invalid_grant', 'error_description': auth_code}), 400

        # Validate redirect URI matches
        if auth_code['redirect_uri'] != redirect_uri:
            return jsonify({'error': 'invalid_grant', 'error_description': 'redirect_uri mismatch'}), 400

        # Validate PKCE
        if not code_verifier:
            return jsonify({'error': 'invalid_request', 'error_description': 'code_verifier required'}), 400

        if not oauth2_service.validate_pkce(
            code_verifier,
            auth_code['code_challenge'],
            auth_code['code_challenge_method']
        ):
            return jsonify({'error': 'invalid_grant', 'error_description': 'PKCE validation failed'}), 400

        # Generate tokens
        tokens = oauth2_service.generate_tokens(
            client_id,
            auth_code['user_id'],
            auth_code['scope']
        )

        # Log event
        security_service.log_security_event(
            'oauth_token_issued',
            username=None,
            ip_address=request.remote_addr,
            metadata={'client_id': client_id, 'user_id': auth_code['user_id']},
            severity='info'
        )

        return jsonify(tokens), 200

    elif grant_type == 'refresh_token':
        # Refresh token flow
        refresh_token = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')

        # Validate client
        is_valid, client = oauth2_service.validate_client(client_id, client_secret)
        if not is_valid:
            return jsonify({'error': 'invalid_client'}), 401

        # Refresh access token
        success, result = oauth2_service.refresh_access_token(refresh_token, client_id)

        if success:
            security_service.log_security_event(
                'oauth_token_refreshed',
                username=None,
                ip_address=request.remote_addr,
                metadata={'client_id': client_id},
                severity='info'
            )

            return jsonify(result), 200
        else:
            return jsonify({'error': 'invalid_grant', 'error_description': result}), 400

    else:
        return jsonify({'error': 'unsupported_grant_type'}), 400

@oauth_bp.route('/userinfo', methods=['GET'])
def userinfo():
    """
    OAuth2 userinfo endpoint (protected resource)
    Returns information about the authenticated user
    """
    # Extract access token from Authorization header
    auth_header = request.headers.get('Authorization', '')

    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'invalid_request', 'error_description': 'Bearer token required'}), 401

    access_token = auth_header[7:]  # Remove 'Bearer ' prefix

    # Validate access token
    is_valid, token = oauth2_service.validate_access_token(access_token)

    if not is_valid:
        return jsonify({'error': 'invalid_token', 'error_description': token}), 401

    # Get user info
    user_info = oauth2_service.get_user_info(token['user_id'])

    if not user_info:
        return jsonify({'error': 'server_error'}), 500

    return jsonify(user_info), 200

@oauth_bp.route('/revoke', methods=['POST'])
@csrf.exempt  # OAuth2 revocation endpoint uses token authentication, not CSRF tokens
def revoke():
    """
    OAuth2 token revocation endpoint
    """
    token = request.form.get('token')
    token_type_hint = request.form.get('token_type_hint', 'access_token')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')

    # Validate client
    is_valid, client = oauth2_service.validate_client(client_id, client_secret)
    if not is_valid:
        return jsonify({'error': 'invalid_client'}), 401

    if not token:
        return jsonify({'error': 'invalid_request'}), 400

    # Revoke token
    oauth2_service.revoke_token(token, token_type_hint)

    security_service.log_security_event(
        'oauth_token_revoked',
        username=None,
        ip_address=request.remote_addr,
        metadata={'client_id': client_id, 'token_type': token_type_hint},
        severity='warning'
    )

    # RFC 7009: Return 200 even if token doesn't exist
    return '', 200
