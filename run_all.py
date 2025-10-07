#!/usr/bin/env python3
"""
Auto-run script for VA-WebSec Assistant
Chạy tất cả các thành phần: Backend API + Frontend UI
"""

import subprocess
import sys
import time
import threading
import webbrowser
import requests
import os
from pathlib import Path

def check_dependencies():
    """Kiểm tra dependencies"""
    print("Checking dependencies...")
    
    try:
        import streamlit
        import uvicorn
        import fastapi
        print("All dependencies are installed")
        return True
    except ImportError as e:
        print(f"[ERROR] Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_ports():
    """Kiểm tra ports có available không"""
    print("Checking ports...")
    
    ports = [8002, 8501]  # Sử dụng port 8002 thay vì 8001
    available = True
    
    for port in ports:
        try:
            response = requests.get(f"http://localhost:{port}", timeout=2)
            print(f"[ERROR] Port {port} is already in use")
            available = False
        except requests.exceptions.ConnectionError:
            print(f"Port {port} is available")  
        except Exception:
            print(f"Port {port} is available")
    
    return available

def run_backend():
    """Chạy Backend API"""
    print("Starting Backend API...")
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn", 
            "app.main:app", 
            "--reload", 
            "--port", "8002",
            "--host", "0.0.0.0"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Backend failed to start: {e}")
    except KeyboardInterrupt:
        print("Backend stopped by user")

def run_frontend():
    """Chạy Frontend UI"""
    print("Starting Frontend UI...")
    try:
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            "app/ui/streamlit_app.py", 
            "--server.port", "8501",
            "--server.address", "0.0.0.0"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Frontend failed to start: {e}")
    except KeyboardInterrupt:
        print("Frontend stopped by user")

def wait_for_backend():
    """Chờ Backend khởi động"""
    print("Waiting for Backend API to start...")
    max_attempts = 30
    for i in range(max_attempts):
        try:
            response = requests.get("http://localhost:8002/api/health", timeout=2)
            if response.status_code == 200:
                print("Backend API is ready!")
                return True
        except:
            pass
        time.sleep(1)
        print(f"   Attempt {i+1}/{max_attempts}...")
    
    print("Backend API failed to start within 30 seconds")
    return False

def wait_for_frontend():
    """Chờ Frontend khởi động"""
    print("Waiting for Frontend UI to start...")
    max_attempts = 30
    for i in range(max_attempts):
        try:
            response = requests.get("http://localhost:8501", timeout=2)
            if response.status_code == 200:
                print("Frontend UI is ready!")
                return True
        except:
            pass
        time.sleep(1)
        print(f"   Attempt {i+1}/{max_attempts}...")
    
    print("Frontend UI failed to start within 30 seconds")
    return False

def open_browser():
    """Mở browser tự động"""
    print("Opening browser...")
    time.sleep(3)  # Chờ UI load
    
    urls = [
        "http://localhost:8501",  # VA-WebSec Assistant
        "http://localhost:8002/docs",  # API Documentation
        "http://testphp.vulnweb.com"  # Acunetix Test Site
    ]
    
    for url in urls:
        try:
            webbrowser.open(url)
            print(f"[OK] Opened: {url}")
        except Exception as e:
            print(f"[ERROR] Failed to open {url}: {e}")

def run_tests():
    """Chạy test scripts"""
    print("Running test scripts...")
    
    test_scripts = [
        "test_acunetix_site.py",
        "test_juice_shop.py"
    ]
    
    for script in test_scripts:
        if os.path.exists(script):
            print(f"Running {script}...")
            try:
                result = subprocess.run([sys.executable, script], 
                                      capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    print(f"[OK] {script} passed")
                else:
                    print(f"[ERROR] {script} failed")
                    print(result.stderr)
            except subprocess.TimeoutExpired:
                print(f"[TIMEOUT] {script} timed out")
            except Exception as e:
                print(f"[ERROR] {script} error: {e}")
        else:
            print(f"[WARNING] {script} not found")

def main():
    """Main function"""
    print("VA-WebSec Assistant - Auto Launcher")
    print("=" * 50)
    
    # Kiểm tra dependencies
    if not check_dependencies():
        return
    
    # Kiểm tra ports
    if not check_ports():
        print("[WARNING] Some ports are in use. Please stop other services or use different ports.")
        return
    
    # Chạy Backend trong thread riêng
    backend_thread = threading.Thread(target=run_backend, daemon=True)
    backend_thread.start()
    
    # Chờ Backend khởi động
    if not wait_for_backend():
        return
    
    # Chạy Frontend trong thread riêng
    frontend_thread = threading.Thread(target=run_frontend, daemon=True)
    frontend_thread.start()
    
    # Chờ Frontend khởi động
    if not wait_for_frontend():
        return
    
    # Mở browser
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()
    
    # Hiển thị thông tin
    print("\n" + "=" * 50)
    print("VA-WebSec Assistant is running!")
    print("=" * 50)
    print("Access URLs:")
    print("   • VA-WebSec Assistant: http://localhost:8501")
    print("   • API Documentation: http://localhost:8002/docs")
    print("   • Acunetix Test Site: http://testphp.vulnweb.com")
    print("   • Health Check: http://localhost:8002/api/health")
    print("=" * 50)
    print("Available Test Sites:")
    print("   • Acunetix Test Site: http://testphp.vulnweb.com")
    print("   • Juice Shop: http://localhost:3000 (if running)")
    print("=" * 50)
    print("Features Available:")
    print("   • Chat Assistant with AI-powered payload generation")
    print("   • Professional Smart Scanner with LLM analysis")
    print("   • Burp Scanner with detailed findings")
    print("   • Nikto Scanner with vulnerability detection")
    print("   • Attack System with real-time execution")
    print("=" * 50)
    print("Press Ctrl+C to stop all services")
    print("=" * 50)
    
    # Chạy tests (optional)
    try:
        run_tests()
    except Exception as e:
        print(f"[WARNING] Test execution failed: {e}")
    
    # Giữ chương trình chạy
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down VA-WebSec Assistant...")
        print("All services stopped")

if __name__ == "__main__":
    main()