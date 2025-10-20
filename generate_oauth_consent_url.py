#!/usr/bin/env python3
"""
Generate OAuth2 Authorization URL for Consent Screen Screenshot
This script creates the URL you need to open in your browser to see the consent screen.
"""

import secrets
import hashlib
import base64
from urllib.parse import urlencode

# Configuration
BASE_URL = "http://127.0.0.1:5001"
CLIENT_ID = "test_client_id"
REDIRECT_URI = "http://localhost:5000/callback"

def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge"""
    # Generate code_verifier (43-128 characters, URL-safe)
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    # Generate code_challenge using S256 method
    challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')

    return code_verifier, code_challenge

def generate_state():
    """Generate cryptographically secure state parameter"""
    return secrets.token_urlsafe(32)

# Generate PKCE parameters
code_verifier, code_challenge = generate_pkce_pair()
state = generate_state()

# Create authorization URL parameters
auth_params = {
    'response_type': 'code',
    'client_id': CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'scope': 'profile email',
    'state': state,
    'code_challenge': code_challenge,
    'code_challenge_method': 'S256'
}

# Build full authorization URL
authorization_url = f"{BASE_URL}/oauth/authorize?{urlencode(auth_params)}"

# Display instructions
print("=" * 80)
print("🔐 OAuth2 Consent Screen Screenshot Instructions")
print("=" * 80)
print()
print("STEP 1: Make sure you're logged in")
print("  → Open: http://127.0.0.1:5001/login")
print("  → Login with: username=testuser, password=TestPassword123")
print("  → (or any existing account)")
print()
print("STEP 2: Open the authorization URL below in your browser")
print("  → This will show the OAuth2 consent screen")
print()
print("=" * 80)
print("AUTHORIZATION URL (copy and paste into browser):")
print("=" * 80)
print()
print(authorization_url)
print()
print("=" * 80)
print()
print("STEP 3: Screenshot the consent screen that appears")
print("  → The page will show:")
print("    - Client name: 'test_client_id'")
print("    - Requested scopes: 'profile' and 'email'")
print("    - Allow/Deny buttons")
print()
print("STEP 4: Save screenshot as:")
print("  → screenshots/fig_oauth2_consent.png")
print()
print("=" * 80)
print()
print("📸 DO NOT click 'Allow' or 'Deny' yet - capture the screenshot first!")
print()
print("PKCE Parameters (for reference):")
print(f"  code_verifier: {code_verifier[:30]}...")
print(f"  code_challenge: {code_challenge[:30]}...")
print(f"  state: {state[:30]}...")
print()
