@echo off
echo [SECURITY] VA-WebSec Assistant - Auto Launcher
echo ================================================

echo [SCAN] Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    pause
    exit /b 1
)

echo [SCAN] Checking dependencies...
python -c "import streamlit, uvicorn, fastapi" 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Missing dependencies. Installing...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)

echo [OK] Dependencies are ready

echo 🚀 Starting VA-WebSec Assistant...
echo ================================================
echo 📱 Access URLs:
echo    • VA-WebSec Assistant: http://localhost:8501
echo    • API Documentation: http://localhost:8000/docs
echo    • Acunetix Test Site: http://testphp.vulnweb.com
echo ================================================
echo [KEYBOARD] Press Ctrl+C to stop all services
echo ================================================

start "Backend API" cmd /k "python -m uvicorn app.main:app --reload --port 8000"
timeout /t 5 /nobreak >nul

start "Frontend UI" cmd /k "python -m streamlit run app/ui/streamlit_app.py --server.port 8501"
timeout /t 5 /nobreak >nul

echo [WEB] Opening browser...
start http://localhost:8501
start http://localhost:8000/docs
start http://testphp.vulnweb.com

echo 🎉 VA-WebSec Assistant is starting!
echo Please wait for both services to fully load...
echo.
echo Press any key to run tests...
pause >nul

echo [TEST] Running tests...
python test_acunetix_site.py
echo.
echo Press any key to exit...
pause >nul
