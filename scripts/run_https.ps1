# scripts/run_https.ps1 - run the AegisIQ backend over HTTPS/TLS on Windows.
#
#   powershell -ExecutionPolicy Bypass -File scripts\run_https.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\run_https.ps1 -Port 9443
#
# Generates a self-signed cert on first run if certs\ is empty, activates
# the backend venv, then starts uvicorn with TLS at https://localhost:8443.
param([int]$Port = 8443)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$crt = Join-Path $root "certs\aegis.crt"
$key = Join-Path $root "certs\aegis.key"
if (-not (Test-Path $crt) -or -not (Test-Path $key)) {
    Write-Host "No cert found - generating a self-signed one..."
    powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "generate_certs.ps1")
}

# Activate the backend venv if it exists.
$venvActivate = Join-Path $root "backend\venv\Scripts\Activate.ps1"
$venvPy       = Join-Path $root "backend\venv\Scripts\python.exe"
Set-Location (Join-Path $root "backend")

if (Test-Path $venvPy) {
    Write-Host "Starting HTTPS backend on https://localhost:$Port (venv)"
    & $venvPy -m uvicorn app.main:app --host 0.0.0.0 --port $Port `
        --ssl-keyfile $key --ssl-certfile $crt
} else {
    Write-Host "backend\venv not found - using system python. (Create it: python -m venv backend\venv; backend\venv\Scripts\pip install -r backend\requirements.txt)"
    python -m uvicorn app.main:app --host 0.0.0.0 --port $Port `
        --ssl-keyfile $key --ssl-certfile $crt
}
