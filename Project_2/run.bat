@echo off
REM === Multi-Process Launcher for PBFT System (with shared keys) ===
setlocal

set "PYTHON_EXE=python"
cd /d "%~dp0" || (
    echo [ERROR] Could not change directory to %~dp0
    pause
    exit /b
)

echo ============================================================
echo Step 1: Generating shared cryptographic keys...
echo ============================================================
%PYTHON_EXE% pbft_server.py --generate-keys
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Key generation failed!
    pause
    exit /b
)
echo ✅ Keys generated successfully and saved to pbft_keys.json
echo.

echo ============================================================
echo Step 2: Launching 7 PBFT Replicas in separate terminals...
echo ============================================================
start "Replica-0" cmd /k "%PYTHON_EXE% pbft_server.py 7000 17000"
timeout /t 1 /nobreak >nul
start "Replica-1" cmd /k "%PYTHON_EXE% pbft_server.py 7001 17001"
timeout /t 1 /nobreak >nul
start "Replica-2" cmd /k "%PYTHON_EXE% pbft_server.py 7002 17002"
timeout /t 1 /nobreak >nul
start "Replica-3" cmd /k "%PYTHON_EXE% pbft_server.py 7003 17003"
timeout /t 1 /nobreak >nul
start "Replica-4" cmd /k "%PYTHON_EXE% pbft_server.py 7004 17004"
timeout /t 1 /nobreak >nul
start "Replica-5" cmd /k "%PYTHON_EXE% pbft_server.py 7005 17005"
timeout /t 1 /nobreak >nul
start "Replica-6" cmd /k "%PYTHON_EXE% pbft_server.py 7006 17006"
echo ✅ All replicas launched

echo.
echo ============================================================
echo Step 3: Waiting for replicas to initialize...
echo ============================================================
timeout /t 3 /nobreak

echo.
echo ============================================================
echo Step 4: Launching Client Controller...
echo ============================================================
start "Clients" cmd /k "%PYTHON_EXE% pbft_clients_controller.py"
echo ✅ Clients controller launched

echo.
echo ============================================================
echo Step 5: Launching Admin Controller...
echo ============================================================
start "Admin" cmd /k "%PYTHON_EXE% pbft_admin_controller.py CSE535-F25-Project-2-Testcases.csv"
echo ✅ Admin controller launched

echo.
echo ============================================================
echo 🎉 All components launched successfully!
echo ============================================================
echo.
echo You should now see:
echo   - 7 Replica terminals (Replica-0 through Replica-6)
echo   - 1 Clients terminal
echo   - 1 Admin terminal
echo.
echo Check each Replica terminal - you should see:
echo   "Loaded shared keys from pbft_keys.json: 7 keys"
echo.
pause
endlocal