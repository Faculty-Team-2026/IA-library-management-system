@echo off
REM NGrok Auto-Start Script
REM This batch file starts ngrok tunnel on http://localhost:5173 (Frontend)

echo.
echo ============================================
echo   NGrok Tunnel Startup
echo ============================================
echo.
echo Starting ngrok tunnel...
echo Tunnel will expose: http://localhost:5173 (Frontend)
echo.

REM Start ngrok with domain reservation
"%LOCALAPPDATA%\ngrok\ngrok.exe" http 5173 --domain=knox-mimosaceous-maris.ngrok-free.dev --log=stdout

REM If ngrok fails, show error
if errorlevel 1 (
    echo.
    echo ERROR: ngrok failed to start
    echo.
    echo Make sure ngrok is installed at:
    echo %LOCALAPPDATA%\ngrok\ngrok.exe
    echo.
    pause
    exit /b 1
)
