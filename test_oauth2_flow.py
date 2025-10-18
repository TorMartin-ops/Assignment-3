#!/usr/bin/env python3
"""
OAuth2 Authorization Code Flow Test
Tests complete OAuth2 flow with PKCE
"""
import requests
import secrets
import hashlib
import base64
import json

# Configuration
BASE_URL = "http://localhost:5000"
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"
REDIRECT_URI = "http://localhost:5000/callback"

def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge"""
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge

def test_oauth2_flow():
    """Test complete OAuth2 authorization code flow"""
    print("=" * 60)
    print("🔐 OAuth2 Authorization Code Flow Test (with PKCE)")
    print("=" * 60)

    # Step 1: Generate PKCE pair
    code_verifier, code_challenge = generate_pkce_pair()
    print(f"\n✅ Step 1: Generated PKCE pair")
    print(f"   Code Verifier: {code_verifier[:20]}...")
    print(f"   Code Challenge: {code_challenge[:20]}...")

    # Step 2: Authorization Request
    state = secrets.token_urlsafe(16)

    auth_params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': REDIRECT_URI,
        'scope': 'profile email',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }

    auth_url = f"{BASE_URL}/oauth/authorize"
    print(f"\n📝 Step 2: Authorization Request")
    print(f"   URL: {auth_url}")
    print(f"   Params: {json.dumps(auth_params, indent=6)}")
    print(f"\n   ⚠️  NOTE: This requires manual browser interaction:")
    print(f"   1. Open: {auth_url}?{'&'.join(f'{k}={v}' for k,v in auth_params.items())}")
    print(f"   2. Login as a test user")
    print(f"   3. Approve the authorization")
    print(f"   4. Copy the 'code' parameter from the redirect URL")

    # Simulate getting authorization code (in real test, this comes from browser)
    print(f"\n   For automated testing, use the test_oauth2_automated.py script")

    # Step 3: Token Exchange (example)
    print(f"\n💱 Step 3: Token Exchange (after getting code)")
    print(f"   POST {BASE_URL}/oauth/token")
    print(f"   Data:")
    token_data = {
        'grant_type': 'authorization_code',
        'code': '[AUTHORIZATION_CODE_FROM_STEP_2]',
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': code_verifier
    }
    print(f"   {json.dumps(token_data, indent=6)}")

    # Step 4: Access Protected Resource (example)
    print(f"\n🔓 Step 4: Access Protected Resource")
    print(f"   GET {BASE_URL}/oauth/userinfo")
    print(f"   Headers:")
    print(f"      Authorization: Bearer [ACCESS_TOKEN_FROM_STEP_3]")

    # Step 5: Refresh Token (example)
    print(f"\n🔄 Step 5: Refresh Access Token")
    print(f"   POST {BASE_URL}/oauth/token")
    refresh_data = {
        'grant_type': 'refresh_token',
        'refresh_token': '[REFRESH_TOKEN_FROM_STEP_3]',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    print(f"   Data: {json.dumps(refresh_data, indent=6)}")

    print(f"\n" + "=" * 60)
    print(f"📚 For complete automated test, run:")
    print(f"   python3 test_oauth2_automated.py")
    print(f"=" * 60)

if __name__ == '__main__':
    test_oauth2_flow()
