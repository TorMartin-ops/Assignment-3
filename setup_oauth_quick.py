#!/usr/bin/env python3
"""Quick OAuth2 Client Setup"""

from database_auth import create_sample_oauth_client

print("=" * 60)
print("Setting up OAuth2 Test Client")
print("=" * 60)
print()

create_sample_oauth_client()

print("✅ OAuth2 client setup complete!")
print()
print("Client Details:")
print("  Client ID: test_client_id")
print("  Client Secret: test_client_secret")
print("  Client Name: Test OAuth2 Client")
print("  Redirect URI: http://localhost:5000/callback")
print()
