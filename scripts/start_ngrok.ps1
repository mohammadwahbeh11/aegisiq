# scripts/start_ngrok.ps1
#
# Expose the running Lightweight SIEM (backend on 8000 + frontend on
# 5173) through two public ngrok URLs, then patch the running frontend
# so the browser calls the PUBLIC backend URL instead of localhost.
#
# Two windows will open:
#   * ngrok dashboard   -- the two public URLs are shown here
#   * a summary in this window with the ready-to-share link
#
# Prerequisites (one-time):
#   1. Install ngrok:   winget install --id Ngrok.Ngrok
#   2. Sign up free:    https://ngrok.com/signup   (get an authtoken)
#   3. Authorize:       ngrok config add-authtoken <YOUR_TOKEN>
#   4. Backend + frontend running locally (uvicorn + npm run dev)
#
# Usage:
#   .\scripts\start_ngrok.ps1
#
# When you close this window, both tunnels stop.

[CmdletBinding()]
param(
    [int] $FrontendPort = 5173,
    [int] $BackendPort  = 8000
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command ngrok -ErrorAction SilentlyContinue)) {
    throw "ngrok not on PATH. Install with:  winget install --id Ngrok.Ngrok"
}

# Preflight: are both local ports actually listening?
foreach ($port in @($FrontendPort, $BackendPort)) {
    $listening = (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    if (-not $listening) {
        Write-Warning "Nothing is listening on localhost:$port"
        Write-Warning "Start the backend (uvicorn) and frontend (npm run dev) first, then re-run this."
        if ($port -eq $BackendPort) {
            Write-Host "  Backend  =>  cd backend ; .\venv\Scripts\Activate.ps1 ; uvicorn app.main:app --host 0.0.0.0 --port 8000"
        } else {
            Write-Host "  Frontend =>  cd frontend ; npm run dev"
        }
        exit 1
    }
}

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$configPath = Join-Path $root "ngrok.yml"

# Generate a fresh ngrok config file exposing both ports.
$config = @"
version: "2"
tunnels:
  siem-frontend:
    proto: http
    addr: $FrontendPort
  siem-backend:
    proto: http
    addr: $BackendPort
"@
Set-Content -Path $configPath -Value $config -Encoding UTF8

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Starting ngrok tunnels " -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Frontend  : localhost:$FrontendPort"
Write-Host " Backend   : localhost:$BackendPort"
Write-Host " Config    : $configPath"
Write-Host ""
Write-Host " ngrok's own web UI (shows both URLs) opens at:"
Write-Host "   http://127.0.0.1:4040" -ForegroundColor Yellow
Write-Host ""
Write-Host " After ngrok starts, note both URLs from http://127.0.0.1:4040 and:"
Write-Host "   1. Edit frontend\.env   ->   VITE_API_URL=<the-backend-ngrok-url>"
Write-Host "   2. Edit .env at project root -> add the frontend ngrok URL to CORS_ORIGINS"
Write-Host "   3. Restart backend and frontend so the change is picked up"
Write-Host "   4. Share the FRONTEND ngrok URL"
Write-Host ""
Write-Host " Press Ctrl+C to stop the tunnels." -ForegroundColor Yellow
Write-Host ""

# Give the user a chance to see the notes before ngrok takes over the console.
Start-Sleep -Seconds 3

# Start both tunnels. ngrok's default TUI shows the URLs live.
ngrok start --config $configPath --all
