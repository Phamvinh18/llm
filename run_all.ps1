# VA-WebSec Assistant - PowerShell Auto Launcher

Write-Host "[SECURITY] VA-WebSec Assistant - Auto Launcher" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

# Check Python installation
Write-Host "[SCAN] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check dependencies
Write-Host "[SCAN] Checking dependencies..." -ForegroundColor Yellow
try {
    python -c "import streamlit, uvicorn, fastapi" 2>$null
    Write-Host "[OK] Dependencies are ready" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Missing dependencies. Installing..." -ForegroundColor Red
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host "🚀 Starting VA-WebSec Assistant..." -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "📱 Access URLs:" -ForegroundColor White
Write-Host "   • VA-WebSec Assistant: http://localhost:8501" -ForegroundColor White
Write-Host "   • API Documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host "   • Acunetix Test Site: http://testphp.vulnweb.com" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "[KEYBOARD] Press Ctrl+C to stop all services" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan

# Start Backend API
Write-Host "🚀 Starting Backend API..." -ForegroundColor Green
$backendJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    python -m uvicorn app.main:app --reload --port 8000
}

# Wait for backend to start
Write-Host "⏳ Waiting for Backend API to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Start Frontend UI
Write-Host "🚀 Starting Frontend UI..." -ForegroundColor Green
$frontendJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    python -m streamlit run app/ui/streamlit_app.py --server.port 8501
}

# Wait for frontend to start
Write-Host "⏳ Waiting for Frontend UI to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Open browser
Write-Host "[WEB] Opening browser..." -ForegroundColor Green
Start-Process "http://localhost:8501"
Start-Process "http://localhost:8000/docs"
Start-Process "http://testphp.vulnweb.com"

Write-Host "🎉 VA-WebSec Assistant is running!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "[TEST] Available Test Sites:" -ForegroundColor White
Write-Host "   • Acunetix Test Site: http://testphp.vulnweb.com" -ForegroundColor White
Write-Host "   • Juice Shop: http://localhost:3000 (if running)" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "[TARGET] Features Available:" -ForegroundColor White
Write-Host "   • Chat Assistant with AI-powered payload generation" -ForegroundColor White
Write-Host "   • Professional Smart Scanner with LLM analysis" -ForegroundColor White
Write-Host "   • Burp Scanner with detailed findings" -ForegroundColor White
Write-Host "   • Nikto Scanner with vulnerability detection" -ForegroundColor White
Write-Host "   • Attack System with real-time execution" -ForegroundColor White
Write-Host "================================================" -ForegroundColor Cyan

# Run tests
Write-Host "[TEST] Running tests..." -ForegroundColor Green
try {
    python test_acunetix_site.py
} catch {
    Write-Host "[WARNING] Test execution failed: $_" -ForegroundColor Yellow
}

Write-Host "Press Ctrl+C to stop all services..." -ForegroundColor White

# Keep running and handle cleanup
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} catch {
    Write-Host "[STOP] Shutting down VA-WebSec Assistant..." -ForegroundColor Yellow
    Stop-Job $backendJob, $frontendJob -ErrorAction SilentlyContinue
    Remove-Job $backendJob, $frontendJob -ErrorAction SilentlyContinue
    Write-Host "[OK] All services stopped" -ForegroundColor Green
}
