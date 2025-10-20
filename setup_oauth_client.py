#!/usr/bin/env python3
"""
Setup OAuth2 Test Client
Creates the test OAuth2 client in the database if it doesn't exist
"""

import sqlite3
import bcrypt

# Configuration
DB_PATH = "recipe_app.db"
CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"
CLIENT_NAME = "Test OAuth2 Application"
REDIRECT_URI = "http://localhost:5000/callback"

def setup_oauth_client():
    """Create OAuth2 test client in database"""

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Check if client already exists
    cursor.execute("SELECT client_id FROM oauth2_clients WHERE client_id = ?", (CLIENT_ID,))
    existing = cursor.fetchone()

    if existing:
        print(f"✅ OAuth2 client '{CLIENT_ID}' already exists in database")
        print(f"   Client Name: {CLIENT_NAME}")
        print(f"   Redirect URI: {REDIRECT_URI}")
    else:
        print(f"Creating OAuth2 client '{CLIENT_ID}'...")

        # Hash the client secret with bcrypt
        secret_hash = bcrypt.hashpw(CLIENT_SECRET.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Insert the OAuth2 client
        cursor.execute('''
            INSERT INTO oauth2_clients (
                client_id, client_secret_hash, client_name,
                redirect_uri, client_type, grant_types
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            CLIENT_ID,
            secret_hash,
            CLIENT_NAME,
            REDIRECT_URI,
            'confidential',
            'authorization_code refresh_token'
        ))

        conn.commit()
        print(f"✅ OAuth2 client created successfully!")
        print(f"   Client ID: {CLIENT_ID}")
        print(f"   Client Secret: {CLIENT_SECRET}")
        print(f"   Client Name: {CLIENT_NAME}")
        print(f"   Redirect URI: {REDIRECT_URI}")

    conn.close()
    print()

if __name__ == '__main__':
    print("=" * 60)
    print("OAuth2 Client Setup")
    print("=" * 60)
    print()

    try:
        setup_oauth_client()
        print("✅ Setup complete! You can now generate the authorization URL.")
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
