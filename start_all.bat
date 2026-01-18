@echo off
echo Starting A2A Protocol System...
echo.

REM Start Control Server in new terminal
start "A2A Control Server" cmd /k "cd A2AControlServer && venv\Scripts\activate && python server.py"

REM Wait a moment for server to start
timeout /t 2 /nobreak >nul

REM Start Helper Agent in new terminal
start "A2A Helper Agent" cmd /k "cd A2AHelper && venv\Scripts\activate && python helper.py"

REM Wait a moment
timeout /t 1 /nobreak >nul

REM Start Traveller Agent in new terminal
start "A2A Traveller Agent" cmd /k "cd A2ATraveller && venv\Scripts\activate && python traveller.py"

echo.
echo All three terminals launched!
echo - Control Server (Port 5000)
echo - Helper Agent (Port 5001)
echo - Traveller Agent (Port 5002)
