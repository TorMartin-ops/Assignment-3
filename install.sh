#!/bin/bash
#
# Authentication System - Quick Install Script
# Installs dependencies and initializes database
#

echo "=================================="
echo "🚀 Authentication System Setup"
echo "=================================="
echo ""

# Check Python version
echo "1️⃣  Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "   ✅ Python $PYTHON_VERSION found"
echo ""

# Create virtual environment
echo "2️⃣  Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "   ✅ Virtual environment created"
else
    echo "   ℹ️  Virtual environment already exists"
fi
echo ""

# Activate virtual environment
echo "3️⃣  Activating virtual environment..."
source venv/bin/activate
echo "   ✅ Virtual environment activated"
echo ""

# Install dependencies
echo "4️⃣  Installing dependencies..."
pip install -r requirements.txt --quiet
if [ $? -eq 0 ]; then
    echo "   ✅ Dependencies installed successfully"
else
    echo "   ❌ Failed to install dependencies"
    exit 1
fi
echo ""

# Create .env file if it doesn't exist
echo "5️⃣  Setting up environment variables..."
if [ ! -f ".env" ]; then
    echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > .env
    echo "FLASK_ENV=development" >> .env
    echo "   ✅ .env file created with random SECRET_KEY"
else
    echo "   ℹ️  .env file already exists"
fi
echo ""

# Initialize databases
echo "6️⃣  Initializing databases..."
python3 database.py
python3 database_auth.py
if [ $? -eq 0 ]; then
    echo "   ✅ Databases initialized"
else
    echo "   ❌ Failed to initialize databases"
    exit 1
fi
echo ""

# Run tests
echo "7️⃣  Running basic tests..."
python3 test_auth_basic.py
if [ $? -eq 0 ]; then
    echo "   ✅ All basic tests passed"
else
    echo "   ⚠️  Some tests failed (check output above)"
fi
echo ""

echo "=================================="
echo "✅ SETUP COMPLETE!"
echo "=================================="
echo ""
echo "🚀 To start the application:"
echo "   source venv/bin/activate"
echo "   python3 app_auth.py"
echo ""
echo "🌐 Then open: http://localhost:5000"
echo ""
echo "📋 Test credentials:"
echo "   Username: chef_anna"
echo "   Password: password123"
echo ""
echo "🔑 OAuth2 Test Client:"
echo "   Client ID: test_client_id"
echo "   Client Secret: test_client_secret"
echo ""
