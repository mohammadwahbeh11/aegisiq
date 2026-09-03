# scripts/publish_docker.ps1
#
# Build both images (backend + frontend), tag them, and push to Docker
# Hub. Idempotent: safe to re-run.
#
# Prerequisites (one-time):
#   1. Docker Desktop running on Windows.
#   2. A free Docker Hub account:  https://hub.docker.com/signup
#   3. `docker login` executed once (stores your credentials).
#
# Usage:
#   .\scripts\publish_docker.ps1 -DockerUser your-hub-username
#   .\scripts\publish_docker.ps1 -DockerUser your-hub-username -Version 1.1
#
# What it produces on Docker Hub:
#   your-hub-username/lightweight-siem-backend:<version>  + :latest
#   your-hub-username/lightweight-siem-frontend:<version> + :latest
#
# What consumers then run:
#   docker compose -f docker-compose.public.yml up
#
# (See the bottom of this file for the exact compose file we generate.)

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DockerUser,

    [string] $Version = "1.0",

    # Where the built frontend will call the backend from the BROWSER.
    # For the published image this is normally left as localhost -- the
    # consumer runs both containers on their own machine, so the browser
    # reaches the backend at localhost:8000. Override with -ApiUrl when
    # you're baking an image tied to a specific public URL (see
    # docs/DEPLOYMENT.md).
    [string] $ApiUrl = "http://localhost:8000",

    # Also update / regenerate docker-compose.public.yml so the user's
    # README shows the exact one-command run recipe.
    [switch] $NoCompose
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Push-Location $root
try {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " Lightweight SIEM  ·  Docker Hub publish " -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " Docker user : $DockerUser"
    Write-Host " Version     : $Version"
    Write-Host " API URL     : $ApiUrl"
    Write-Host ""

    # ---- preflight ------------------------------------------------------
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker not on PATH. Install Docker Desktop and re-open PowerShell."
    }
    try {
        docker info | Out-Null
    } catch {
        throw "Docker daemon is not running. Start Docker Desktop first."
    }

    # Verify the caller has an active docker login. There is no clean
    # `docker login --status`, so probe by pulling the small `hello-world`
    # under the caller's namespace — if not logged in, tell them clearly.
    $whoami = docker system info --format '{{.Username}}' 2>$null
    if (-not $whoami -or $whoami -eq '<no value>') {
        Write-Host "Not logged in to Docker Hub yet." -ForegroundColor Yellow
        docker login
    } else {
        Write-Host "Logged in to Docker Hub as: $whoami" -ForegroundColor Green
    }

    $backendImage  = "${DockerUser}/lightweight-siem-backend"
    $frontendImage = "${DockerUser}/lightweight-siem-frontend"

    # ---- backend build + push ------------------------------------------
    Write-Host "`n[*] Building backend image..." -ForegroundColor Cyan
    docker build `
        --tag "${backendImage}:${Version}" `
        --tag "${backendImage}:latest" `
        .\backend
    if ($LASTEXITCODE -ne 0) { throw "backend build failed" }

    Write-Host "`n[*] Pushing backend image..." -ForegroundColor Cyan
    docker push "${backendImage}:${Version}"
    docker push "${backendImage}:latest"
    if ($LASTEXITCODE -ne 0) { throw "backend push failed" }

    # ---- frontend build + push -----------------------------------------
    Write-Host "`n[*] Building frontend image (VITE_API_URL=$ApiUrl)..." -ForegroundColor Cyan
    docker build `
        --build-arg "VITE_API_URL=$ApiUrl" `
        --tag "${frontendImage}:${Version}" `
        --tag "${frontendImage}:latest" `
        .\frontend
    if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }

    Write-Host "`n[*] Pushing frontend image..." -ForegroundColor Cyan
    docker push "${frontendImage}:${Version}"
    docker push "${frontendImage}:latest"
    if ($LASTEXITCODE -ne 0) { throw "frontend push failed" }

    # ---- generate the public compose file ------------------------------
    if (-not $NoCompose) {
        $composePath = Join-Path $root "docker-compose.public.yml"
        Write-Host "`n[*] Writing $composePath" -ForegroundColor Cyan
        $compose = @"
# docker-compose.public.yml -- one-command run for anyone with Docker.
# Pulls the images published by the maintainer to Docker Hub. Bring up:
#   docker compose -f docker-compose.public.yml up
# Then open http://localhost:5173  ·  login: admin / ChangeMe123!
# Change SECRET_KEY and DEFAULT_ADMIN_PASSWORD below before real use.

services:
  backend:
    image: ${backendImage}:${Version}
    container_name: siem-backend
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      DATABASE_URL: "sqlite:////app/data/siem.db"
      SECRET_KEY: "change-me-in-production"
      DEFAULT_ADMIN_USERNAME: "admin"
      DEFAULT_ADMIN_PASSWORD: "ChangeMe123!"
      CORS_ORIGINS: "http://localhost:5173,http://127.0.0.1:5173"
      SOAR_ENABLED: "true"
      SOAR_EXECUTE: "false"
    restart: unless-stopped

  frontend:
    image: ${frontendImage}:${Version}
    container_name: siem-frontend
    ports:
      - "5173:80"
    depends_on:
      - backend
    restart: unless-stopped
"@
        Set-Content -Path $composePath -Value $compose -Encoding UTF8
        Write-Host "  wrote $composePath" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host " ✓ PUBLISHED " -ForegroundColor Green
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host " Backend :  docker pull ${backendImage}:${Version}"
    Write-Host " Frontend:  docker pull ${frontendImage}:${Version}"
    Write-Host ""
    Write-Host " Consumers now run:"
    Write-Host "   docker compose -f docker-compose.public.yml up" -ForegroundColor Yellow
    Write-Host ""
    Write-Host " Hub pages:"
    Write-Host "   https://hub.docker.com/r/${backendImage}"
    Write-Host "   https://hub.docker.com/r/${frontendImage}"
    Write-Host ""
}
finally {
    Pop-Location
}
