@echo off
REM === SmallBank Benchmark Launcher for PBFT System ===
setlocal

set "PYTHON_EXE=python"
cd /d "%~dp0" || (
    echo [ERROR] Could not change directory to %~dp0
    pause
    exit /b
)

echo ============================================================
echo SmallBank Benchmark Launcher for PBFT
echo ============================================================
echo.

REM Check if required files exist
if not exist "pbft_server.py" (
    echo [ERROR] pbft_server.py not found!
    echo Please ensure the PBFT server is in the current directory.
    pause
    exit /b
)

if not exist "smallbank_benchmark.py" (
    echo [ERROR] smallbank_benchmark.py not found!
    echo Please ensure the benchmark script is in the current directory.
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
echo Step 2: Launching 7 PBFT Replicas with SmallBank support...
echo ============================================================
echo Note: Replicas will initialize with 100 SmallBank accounts
echo       (C000000 through C000099 with 10,000 initial balance)
echo.
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
timeout /t 5 /nobreak

echo.
echo ============================================================
echo Step 4: Setting up PBFT consensus (electing primary)...
echo ============================================================
echo Setting node 0 as PRIMARY and nodes 1-6 as BACKUPS...
echo.

REM Set node 0 as primary
%PYTHON_EXE% -c "import socket; s = socket.create_connection(('127.0.0.1', 17000), timeout=2); s.recv(1024); s.sendall(b'SET_VIEW 0 PRIMARY\n'); print('Node 0:', s.recv(1024).decode().strip()); s.close()"

REM Set nodes 1-6 as backups
for %%i in (1 2 3 4 5 6) do (
    %PYTHON_EXE% -c "import socket; s = socket.create_connection(('127.0.0.1', 1700%%i), timeout=2); s.recv(1024); s.sendall(b'SET_VIEW 0 BACKUP\n'); print('Node %%i:', s.recv(1024).decode().strip()); s.close()"
)

timeout /t 1 /nobreak >nul
echo ✅ Primary elected (Node 0)
echo.

echo ============================================================
echo Step 5: Displaying benchmark configuration menu...
echo ============================================================
echo.
echo Select benchmark configuration:
echo   [1] Quick Test      (10 accounts,  10 clients, 30 seconds)
echo   [2] Standard        (100 accounts, 10 clients, 60 seconds)
echo   [3] Large Scale     (1000 accounts, 20 clients, 120 seconds)
echo   [4] Custom          (Specify your own parameters)
echo   [5] Exit
echo.
set /p CHOICE="Enter choice [1-5]: "

if "%CHOICE%"=="1" (
    set NUM_ACCOUNTS=10
    set NUM_CLIENTS=10
    set DURATION=30
    set WARMUP=5
    echo Selected: Quick Test
) else if "%CHOICE%"=="2" (
    set NUM_ACCOUNTS=100
    set NUM_CLIENTS=10
    set DURATION=60
    set WARMUP=10
    echo Selected: Standard
) else if "%CHOICE%"=="3" (
    set NUM_ACCOUNTS=1000
    set NUM_CLIENTS=20
    set DURATION=120
    set WARMUP=15
    echo Selected: Large Scale
) else if "%CHOICE%"=="4" (
    echo.
    echo Custom Configuration:
    set /p NUM_ACCOUNTS="  Number of accounts [100]: "
    set /p NUM_CLIENTS="  Number of clients [10]: "
    set /p DURATION="  Duration in seconds [60]: "
    set /p WARMUP="  Warmup in seconds [10]: "
    
    if "%NUM_ACCOUNTS%"=="" set NUM_ACCOUNTS=100
    if "%NUM_CLIENTS%"=="" set NUM_CLIENTS=10
    if "%DURATION%"=="" set DURATION=60
    if "%WARMUP%"=="" set WARMUP=10
    echo Selected: Custom
) else if "%CHOICE%"=="5" (
    echo Exiting...
    exit /b
) else (
    echo [ERROR] Invalid choice!
    pause
    exit /b
)

echo.
echo ============================================================
echo Step 6: Initializing SmallBank database...
echo ============================================================
echo Configuring replicas with %NUM_ACCOUNTS% accounts...
echo.

REM Initialize SmallBank on primary replica (R0) using Python
echo Sending SMALLBANK_INIT command to primary...
%PYTHON_EXE% -c "import socket; s = socket.create_connection(('127.0.0.1', 17000), timeout=2); s.recv(1024); s.sendall(b'SMALLBANK_INIT %NUM_ACCOUNTS% 10000\n'); print(s.recv(1024).decode()); s.close()"
timeout /t 2 /nobreak >nul

echo ✅ SmallBank database initialized
echo.

echo ============================================================
echo Step 6: Launching SmallBank Benchmark...
echo ============================================================
echo Configuration:
echo   Accounts:  %NUM_ACCOUNTS%
echo   Clients:   %NUM_CLIENTS%
echo   Duration:  %DURATION% seconds
echo   Warmup:    %WARMUP% seconds
echo.
echo The benchmark will:
echo   1. Run warmup phase (%WARMUP%s)
echo   2. Execute transactions (%DURATION%s)
echo   3. Generate results and plots
echo.
echo Progress will be shown in the benchmark window...
echo.

start "SmallBank-Benchmark" cmd /k "%PYTHON_EXE% smallbank_benchmark.py --accounts %NUM_ACCOUNTS% --clients %NUM_CLIENTS% --duration %DURATION% --warmup %WARMUP%"

echo ✅ Benchmark launched in separate window
echo.

echo ============================================================
echo Step 7: Monitoring setup (optional)...
echo ============================================================
echo.
echo You can monitor the system by querying replica statistics using Python
echo.
set /p MONITOR="Launch monitoring window? [Y/N]: "

if /i "%MONITOR%"=="Y" (
    echo.
    echo Creating monitoring script...
    (
        echo @echo off
        echo :loop
        echo cls
        echo echo ============================================================
        echo echo SmallBank System Monitor - %%TIME%%
        echo echo ============================================================
        echo echo.
        echo python -c "import socket; s = socket.create_connection(('127.0.0.1', 17000), timeout=2); s.recv(1024); s.sendall(b'SMALLBANK_STATS\n'); resp=s.recv(8192).decode(); s.close(); print(resp)"
        echo echo.
        echo echo -----------------------------------------------------------
        echo echo Press Ctrl+C to exit, or wait 10s for refresh...
        echo timeout /t 10 /nobreak
        echo goto loop
    ) > smallbank_monitor_temp.bat
    
    start "SmallBank-Monitor" cmd /k smallbank_monitor_temp.bat
    echo ✅ Monitoring window launched
)

echo.
echo ============================================================
echo 🎉 SmallBank Benchmark System Launched Successfully!
echo ============================================================
echo.
echo Active Windows:
echo   - 7 Replica terminals (Replica-0 through Replica-6)
echo   - 1 SmallBank Benchmark terminal
if /i "%MONITOR%"=="Y" (
echo   - 1 System Monitor terminal
)
echo.
echo Expected Output in Replica terminals:
echo   "[SmallBank] Handler initialized"
echo   "[SmallBank] Initialized %NUM_ACCOUNTS% accounts with balance 10000"
echo   "Loaded shared keys from pbft_keys.json: 7 keys"
echo.
echo Expected Output in Benchmark terminal:
echo   "SmallBank Benchmark Starting"
echo   "Warmup phase..."
echo   "Starting measurement phase..."
echo   Progress updates every 10 seconds
echo   "SmallBank Benchmark Results" (at end)
echo.
echo Output Files (created after benchmark completes):
echo   - smallbank_results_^<timestamp^>.json
echo   - smallbank_plots_^<timestamp^>.png
echo.
echo ============================================================
echo Useful Commands (using Python):
echo ============================================================
echo   Query SmallBank stats:
echo     python -c "import socket; s=socket.create_connection(('127.0.0.1',17000)); s.recv(1024); s.sendall(b'SMALLBANK_STATS\n'); print(s.recv(8192).decode()); s.close()"
echo.
echo   Check replica status:
echo     python -c "import socket; s=socket.create_connection(('127.0.0.1',17000)); s.recv(1024); s.sendall(b'STATUS\n'); print(s.recv(8192).decode()); s.close()"
echo.
echo   View database:
echo     python -c "import socket; s=socket.create_connection(('127.0.0.1',17000)); s.recv(1024); s.sendall(b'PRINTDB\n'); print(s.recv(8192).decode()); s.close()"
echo.
echo ============================================================
echo.
echo When benchmark completes, check the results files!
echo.
pause
endlocal