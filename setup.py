#!/usr/bin/env python3
"""
Setup script for VA-WebSec Assistant
Configures environment variables and initializes the system
"""

import os
import sys
import subprocess
from pathlib import Path

def create_env_file():
    """Create .env file with API configuration"""
    env_content = """# Gemini API Configuration
GEMINI_API_KEY=AIzaSyCGelelNnk_3nxKXpRFQh3Rt1MOLz-1S0k
GEMINI_API_URL=https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent

# Burp API Configuration
BURP_API_URL=http://127.0.0.1:1337
BURP_API_KEY=Z0ID48POpyXiYhKAksgHG4UlWB0bCHAL

# Database Configuration
DATABASE_URL=sqlite:///./app/data/vawebsec.db

# Target Whitelist
TARGET_WHITELIST_FILE=app/data/whitelist.json
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    print("[OK] Created .env file with API configuration")

def create_directories():
    """Create necessary directories"""
    directories = [
        'app/data',
        'app/data/scans',
        'app/data/sessions'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    print("[OK] Created necessary directories")

def install_dependencies():
    """Install Python dependencies"""
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'], 
                      check=True, capture_output=True)
        print("[OK] Installed Python dependencies")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to install dependencies: {e}")
        return False
    return True

def initialize_database():
    """Initialize the database"""
    try:
        from app.db.session import init_db
        init_db()
        print("[OK] Initialized database")
    except Exception as e:
        print(f"[ERROR] Failed to initialize database: {e}")
        return False
    return True

def generate_knowledge_base():
    """Generate the knowledge base"""
    try:
        subprocess.run([sys.executable, 'tools/generate_kb.py'], check=True, capture_output=True)
        print("[OK] Generated knowledge base")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to generate knowledge base: {e}")
        return False
    return True

def test_apis():
    """Test API connections"""
    print("\n[SCAN] Testing API connections...")
    
    # Test Gemini API
    try:
        from app.clients.gempy_real_stub import GeminiClient
        client = GeminiClient()
        response = client.chat("Test message", max_output_tokens=50)
        print("[OK] Gemini API connection successful")
    except Exception as e:
        print(f"[WARNING]  Gemini API test failed: {e}")
    
    # Test Burp API
    try:
        from app.clients.burp_real_stub import BurpClientReal
        client = BurpClientReal()
        # Just test connection, don't start actual scan
        print("[OK] Burp API client initialized")
    except Exception as e:
        print(f"[WARNING]  Burp API test failed: {e}")

def main():
    """Main setup function"""
    print("🚀 Setting up VA-WebSec Assistant...")
    
    # Create environment file
    create_env_file()
    
    # Create directories
    create_directories()
    
    # Install dependencies
    if not install_dependencies():
        print("[ERROR] Setup failed at dependency installation")
        return
    
    # Initialize database
    if not initialize_database():
        print("[ERROR] Setup failed at database initialization")
        return
    
    # Generate knowledge base
    if not generate_knowledge_base():
        print("[ERROR] Setup failed at knowledge base generation")
        return
    
    # Test APIs
    test_apis()
    
    print("\n🎉 Setup completed successfully!")
    print("\n[LIST] Next steps:")
    print("1. Start the backend: uvicorn app.main:app --reload --port 8000")
    print("2. Start the UI: streamlit run app/ui/streamlit_app.py")
    print("3. Open http://localhost:8501 in your browser")
    print("\n[TOOL] Configuration:")
    print("- Gemini API: Configured with your API key")
    print("- Burp API: Configured for http://127.0.0.1:1337")
    print("- Environment variables loaded from .env file")

if __name__ == "__main__":
    main()
