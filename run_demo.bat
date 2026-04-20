@echo off
setlocal

cd /d "%~dp0"

echo [demo] Project root: %CD%
echo [demo] Starting cloud service on port 8200...
start "cloud" cmd /k "cd /d ""%CD%"" && call .venv\Scripts\activate.bat && echo [cloud] Running on http://127.0.0.1:8200 && uvicorn app.cloud_service:app --host 127.0.0.1 --port 8200"

echo [demo] Starting edgeA service on port 8101...
start "edgeA" cmd /k "cd /d ""%CD%"" && call .venv\Scripts\activate.bat && set ""EDGE_NODE_ID=edgeA"" && echo [edgeA] Running on http://127.0.0.1:8101 && uvicorn app.edge_service:app --host 127.0.0.1 --port 8101"

echo [demo] Waiting briefly before opening browser pages...
timeout /t 3 /nobreak >nul

echo [demo] Opening edge demo page and cloud docs...
start "" "http://127.0.0.1:8101/demo-page"
start "" "http://127.0.0.1:8200/docs"

echo [demo] Two demo windows were opened.
echo [demo] Close those windows to stop the services.

endlocal
