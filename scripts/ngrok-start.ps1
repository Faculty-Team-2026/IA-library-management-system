# NGrok Auto-Start Script for PowerShell
# Automatically starts ngrok tunnel on http://localhost:5173

Write-Host "🚀 Starting ngrok tunnel..." -ForegroundColor Cyan
Write-Host "📍 Tunnel will expose: http://localhost:5173" -ForegroundColor Cyan
Write-Host ""

$ngrokPath = "$env:LOCALAPPDATA\ngrok\ngrok.exe"

# Check if ngrok exists
if (-not (Test-Path $ngrokPath)) {
    Write-Host "❌ Error: ngrok not found at $ngrokPath" -ForegroundColor Red
    Write-Host ""
    Write-Host "To install ngrok, run:" -ForegroundColor Yellow
    Write-Host '$ProgressPreference = "SilentlyContinue"; Invoke-WebRequest -Uri "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip" -OutFile "$env:TEMP\ngrok.zip"; Expand-Archive -Path "$env:TEMP\ngrok.zip" -DestinationPath "$env:LOCALAPPDATA\ngrok" -Force;' -ForegroundColor Green
    Write-Host ""
    exit 1
}

# Start ngrok
Write-Host "✅ NGrok tunnel starting successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Once ngrok is running, your app will be available at:" -ForegroundColor Cyan
Write-Host "   https://[your-ngrok-url].ngrok-free.dev" -ForegroundColor Green
Write-Host ""
Write-Host "📌 Note: The ngrok URL changes each time you restart." -ForegroundColor Yellow
Write-Host "   Update Google OAuth settings with the new URL if needed." -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop all services." -ForegroundColor Magenta
Write-Host ""

# Start ngrok process
& $ngrokPath http 5173 --log=stdout
