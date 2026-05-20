@echo off
setlocal

cd /d "%~dp0"

echo [demo] Project root: %CD%

if not exist ".venv\Scripts\activate.bat" (
    echo [demo] ERROR: .venv is missing. Create the virtual environment and install dependencies first.
    exit /b 1
)

if not exist "data\edgeA\keys\ed25519_private.pem" (
    echo [demo] ERROR: setup has not been run. Missing data\edgeA\keys\ed25519_private.pem.
    exit /b 1
)
if not exist "data\edgeA\keys\ed25519_public.pem" (
    echo [demo] ERROR: setup has not been run. Missing data\edgeA\keys\ed25519_public.pem.
    exit /b 1
)
if not exist "data\edgeA\keys\fernet.key" (
    echo [demo] ERROR: setup has not been run. Missing data\edgeA\keys\fernet.key.
    exit /b 1
)
if not exist "data\edgeA\state\nonce_cache.json" (
    echo [demo] ERROR: setup has not been run. Missing data\edgeA\state\nonce_cache.json.
    exit /b 1
)
if not exist "data\cloud\state\registered_nodes.json" (
    echo [demo] ERROR: setup has not been run. Missing data\cloud\state\registered_nodes.json.
    exit /b 1
)
if not exist "data\cloud\state\nonce_cache.json" (
    echo [demo] ERROR: setup has not been run. Missing data\cloud\state\nonce_cache.json.
    exit /b 1
)

echo [demo] Starting cloud service on port 8200...
start "cloud" cmd /k "cd /d ""%CD%"" && call .venv\Scripts\activate.bat && echo [cloud] Running on http://127.0.0.1:8200 && uvicorn app.cloud_service:app --host 127.0.0.1 --port 8200"

echo [demo] Starting edgeA service on port 8101...
start "edgeA" cmd /k "cd /d ""%CD%"" && call .venv\Scripts\activate.bat && set ""EDGE_NODE_ID=edgeA"" && echo [edgeA] Running on http://127.0.0.1:8101 && uvicorn app.edge_service:app --host 127.0.0.1 --port 8101"

call :wait_health "http://127.0.0.1:8200/health" "cloud"
if errorlevel 1 exit /b 1

call :wait_health "http://127.0.0.1:8101/health" "edgeA"
if errorlevel 1 exit /b 1

echo [demo] Opening edge demo page...
start "" "http://127.0.0.1:8101/demo-page"

echo [demo] Demo page was opened.
echo [demo] Close those windows to stop the services.

endlocal
exit /b 0

:wait_health
echo [demo] Waiting for %~2 health at %~1...
for /L %%I in (1,1,30) do (
    powershell -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -Uri '%~1' -TimeoutSec 1; if ($r.StatusCode -eq 200) { exit 0 }; exit 1 } catch { exit 1 }" >nul 2>nul
    if not errorlevel 1 (
        echo [demo] %~2 is ready.
        exit /b 0
    )
    timeout /t 1 /nobreak >nul
)
echo [demo] ERROR: %~2 did not become healthy in time.
exit /b 1
