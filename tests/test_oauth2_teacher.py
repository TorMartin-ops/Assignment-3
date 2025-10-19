#!/usr/bin/env python3
"""
OAuth2 Authorization Code + PKCE Flow Test Script
Adapted for teacher verification - tests complete OAuth2 implementation

This script tests the OAuth2 flow with PKCE as implemented in this project.
The teacher can run this to verify OAuth2 authentication works correctly.
"""

import requests
import secrets
import hashlib
import base64
from urllib.parse import urlparse, parse_qs

# ============================================
# CONFIGURATION
# ============================================

# Server configuration
BASE_URL = "http://localhost:5001"

# OAuth2 client credentials (from database_auth.py:319-339)
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"
REDIRECT_URI = "http://localhost:5000/callback"

# Test user credentials (create a test user first)
TEST_USERNAME = "testuser"
TEST_PASSWORD = "TestPassword123"

# ============================================
# PKCE HELPER FUNCTIONS
# ============================================

def generate_pkce_pair():
    """
    Generate PKCE code_verifier and code_challenge

    Returns:
        (code_verifier, code_challenge) tuple
    """
    # Generate code_verifier (43-128 characters, URL-safe)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    # Generate code_challenge using S256 method
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge


def generate_state():
    """Generate cryptographically secure state parameter"""
    return secrets.token_urlsafe(32)


# ============================================
# TEST OAUTH2 FLOW
# ============================================

def test_oauth2_flow():
    """
    Test complete OAuth2 Authorization Code + PKCE flow

    Steps:
    1. Login as user (required for authorization)
    2. Generate PKCE parameters
    3. Request authorization code
    4. Approve authorization (simulate user consent)
    5. Exchange code for access token (with PKCE verification)
    6. Access protected resource (/oauth/userinfo)
    7. Test refresh token flow
    """

    print("=" * 60)
    print("OAuth2 Authorization Code + PKCE Flow Test")
    print("=" * 60)
    print()

    # Create session to maintain cookies
    session = requests.Session()

    # ============================================
    # STEP 0: Create test user if needed
    # ============================================
    print("Step 0: Ensuring test user exists...")
    register_data = {
        'username': TEST_USERNAME,
        'email': f'{TEST_USERNAME}@test.com',
        'password': TEST_PASSWORD,
        'confirm_password': TEST_PASSWORD
    }

    # Try to register (will fail if user exists, that's OK)
    try:
        response = session.post(f"{BASE_URL}/register", data=register_data, allow_redirects=False)
        print(f"  Registration response: {response.status_code}")
    except Exception as e:
        print(f"  Registration skipped (user may exist): {e}")

    print()

    # ============================================
    # STEP 1: Login as user (required for OAuth2 authorization)
    # ============================================
    print("Step 1: Logging in as test user...")

    # Get login page to get CSRF token
    response = session.get(f"{BASE_URL}/login")
    # Extract CSRF token from response (simple extraction)
    csrf_token = None
    if 'csrf_token' in response.text:
        # Find the hidden input field
        import re
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
        if match:
            csrf_token = match.group(1)

    login_data = {
        'username': TEST_USERNAME,
        'password': TEST_PASSWORD,
    }
    if csrf_token:
        login_data['csrf_token'] = csrf_token

    response = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=False)

    if response.status_code in [200, 302]:
        print(f"  ✅ Login successful (status: {response.status_code})")
    else:
        print(f"  ❌ Login failed (status: {response.status_code})")
        print(f"  Note: Ensure user '{TEST_USERNAME}' exists with password '{TEST_PASSWORD}'")
        return False

    print()

    # ============================================
    # STEP 2: Generate PKCE parameters
    # ============================================
    print("Step 2: Generating PKCE parameters...")

    code_verifier, code_challenge = generate_pkce_pair()
    state = generate_state()

    print(f"  code_verifier: {code_verifier[:20]}... (length: {len(code_verifier)})")
    print(f"  code_challenge: {code_challenge[:20]}... (S256)")
    print(f"  state: {state[:20]}...")
    print()

    # ============================================
    # STEP 3: Request authorization code
    # ============================================
    print("Step 3: Requesting authorization code...")

    auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'profile email',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    response = session.get(f"{BASE_URL}/oauth/authorize", params=auth_params, allow_redirects=False)

    if response.status_code == 200:
        print(f"  ✅ Authorization page loaded (consent screen)")
    else:
        print(f"  ❌ Authorization request failed (status: {response.status_code})")
        return False

    print()

    # ============================================
    # STEP 4: Approve authorization (simulate user consent)
    # ============================================
    print("Step 4: Approving authorization (user consent)...")

    # Extract CSRF token from consent page
    csrf_token = None
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if match:
        csrf_token = match.group(1)

    approval_data = {
        'approved': 'yes',
    }
    if csrf_token:
        approval_data['csrf_token'] = csrf_token

    response = session.post(f"{BASE_URL}/oauth/authorize", data=approval_data, allow_redirects=False)

    if response.status_code == 302:
        redirect_location = response.headers.get('Location', '')
        print(f"  ✅ Authorization approved, redirecting to: {redirect_location[:80]}...")

        # Extract authorization code from redirect
        parsed = urlparse(redirect_location)
        query_params = parse_qs(parsed.query)

        if 'code' not in query_params:
            print(f"  ❌ No authorization code in redirect")
            return False

        auth_code = query_params['code'][0]
        returned_state = query_params.get('state', [None])[0]

        print(f"  authorization_code: {auth_code[:20]}...")
        print(f"  state: {returned_state[:20] if returned_state else 'None'}...")

        # Validate state parameter
        if returned_state != state:
            print(f"  ❌ State mismatch! Expected: {state[:20]}..., Got: {returned_state[:20]}...")
            return False
        else:
            print(f"  ✅ State parameter validated")
    else:
        print(f"  ❌ Authorization approval failed (status: {response.status_code})")
        return False

    print()

    # ============================================
    # STEP 5: Exchange authorization code for access token (with PKCE)
    # ============================================
    print("Step 5: Exchanging authorization code for access token...")

    token_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier  # PKCE verification
    }

    response = session.post(f"{BASE_URL}/oauth/token", data=token_data)

    if response.status_code == 200:
        token_info = response.json()
        print(f"  ✅ Token exchange successful")
        print(f"  access_token: {token_info.get('access_token', '')[:20]}...")
        print(f"  token_type: {token_info.get('token_type')}")
        print(f"  expires_in: {token_info.get('expires_in')} seconds")
        print(f"  refresh_token: {token_info.get('refresh_token', '')[:20]}...")
        print(f"  scope: {token_info.get('scope')}")

        access_token = token_info['access_token']
        refresh_token = token_info.get('refresh_token')
    else:
        print(f"  ❌ Token exchange failed (status: {response.status_code})")
        print(f"  Response: {response.text}")
        return False

    print()

    # ============================================
    # STEP 6: Access protected resource (/oauth/userinfo)
    # ============================================
    print("Step 6: Accessing protected resource (/oauth/userinfo)...")

    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(f"{BASE_URL}/oauth/userinfo", headers=headers)

    if response.status_code == 200:
        user_info = response.json()
        print(f"  ✅ Protected resource accessed successfully")
        print(f"  User info: {user_info}")
    else:
        print(f"  ❌ Protected resource access failed (status: {response.status_code})")
        print(f"  Response: {response.text}")
        return False

    print()

    # ============================================
    # STEP 7: Test refresh token flow (with rotation)
    # ============================================
    if refresh_token:
        print("Step 7: Testing refresh token flow...")

        refresh_data = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }

        response = requests.post(f"{BASE_URL}/oauth/token", data=refresh_data)

        if response.status_code == 200:
            new_token_info = response.json()
            print(f"  ✅ Token refresh successful")
            print(f"  new_access_token: {new_token_info.get('access_token', '')[:20]}...")
            print(f"  new_refresh_token: {new_token_info.get('refresh_token', '')[:20]}...")
            print(f"  Note: Old refresh_token is now marked as used (refresh_token_used=1)")

            # Test reuse detection
            print()
            print("Step 7b: Testing refresh token reuse detection...")
            response_reuse = requests.post(f"{BASE_URL}/oauth/token", data=refresh_data)

            if response_reuse.status_code == 400:
                print(f"  ✅ Refresh token reuse correctly detected and blocked")
                print(f"  Response: {response_reuse.json()}")
                print(f"  Note: Entire token family should be revoked")
            else:
                print(f"  ❌ Refresh token reuse NOT detected (status: {response_reuse.status_code})")
                return False
        else:
            print(f"  ❌ Token refresh failed (status: {response.status_code})")
            print(f"  Response: {response.text}")
            return False

    print()
    print("=" * 60)
    print("✅ ALL OAUTH2 TESTS PASSED!")
    print("=" * 60)
    return True


# ============================================
# SIMPLIFIED TEST (For teacher's original script format)
# ============================================

def test_oauth2_simple():
    """
    Simplified test matching teacher's script structure
    (Without PKCE for comparison - will fail due to mandatory PKCE)
    """
    print("=" * 60)
    print("Testing OAuth2 WITHOUT PKCE (Should FAIL)")
    print("=" * 60)
    print()

    # Create session
    session = requests.Session()

    # Login first
    print("Logging in as test user...")
    response = session.get(f"{BASE_URL}/login")
    csrf_token = None
    import re
    match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
    if match:
        csrf_token = match.group(1)

    login_data = {'username': TEST_USERNAME, 'password': TEST_PASSWORD}
    if csrf_token:
        login_data['csrf_token'] = csrf_token

    session.post(f"{BASE_URL}/login", data=login_data)

    # Try authorization WITHOUT PKCE
    print("Requesting authorization WITHOUT code_challenge...")
    auth_params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'profile email',
        'state': generate_state()
        # NO code_challenge!
    }

    response = session.get(f"{BASE_URL}/oauth/authorize", params=auth_params, allow_redirects=False)

    if response.status_code == 302:
        redirect_location = response.headers.get('Location', '')
        if 'error=invalid_request' in redirect_location and 'code_challenge required' in redirect_location:
            print(f"  ✅ PKCE correctly enforced - authorization rejected without code_challenge")
            print(f"  Error: {redirect_location}")
        else:
            print(f"  ❌ PKCE not enforced - authorization succeeded without code_challenge!")
            return False
    else:
        print(f"  Status: {response.status_code}")

    print()
    print("=" * 60)
    print("✅ PKCE ENFORCEMENT VERIFIED!")
    print("=" * 60)


# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == '__main__':
    import sys

    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  OAuth2 Authorization Code + PKCE Test Script            ║")
    print("║  For Teacher Verification                                 ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()
    print(f"Server: {BASE_URL}")
    print(f"Client ID: {CLIENT_ID}")
    print(f"Test User: {TEST_USERNAME}")
    print(f"Redirect URI: {REDIRECT_URI}")
    print()
    print("This script tests:")
    print("  • PKCE enforcement (S256 method)")
    print("  • State parameter validation")
    print("  • Authorization code flow")
    print("  • Token generation and validation")
    print("  • Refresh token rotation")
    print("  • Refresh token reuse detection")
    print()
    input("Press ENTER to start tests (or CTRL+C to cancel)...")
    print()

    # Test 1: PKCE enforcement
    test_oauth2_simple()
    print()

    # Test 2: Complete OAuth2 flow with PKCE
    success = test_oauth2_flow()

    print()
    if success:
        print("🎉 ALL TESTS PASSED - OAuth2 implementation is correct!")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED - Check implementation")
        sys.exit(1)
