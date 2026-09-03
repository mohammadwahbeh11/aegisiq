# scripts/generate_certs.ps1 - create a self-signed TLS certificate for
# local HTTPS development of AegisIQ on Windows.
#
#   powershell -ExecutionPolicy Bypass -File scripts\generate_certs.ps1
#
# Writes certs\aegis.key and certs\aegis.crt with SANs for localhost /
# 127.0.0.1. Uses OpenSSL if present (ships with Git for Windows at
# C:\Program Files\Git\usr\bin\openssl.exe); otherwise falls back to the
# built-in New-SelfSignedCertificate + export. Self-signed: the browser
# warns once until you trust it. NOT for production.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$certDir = Join-Path $root "certs"
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
$key = Join-Path $certDir "aegis.key"
$crt = Join-Path $certDir "aegis.crt"

function Find-OpenSSL {
    $c = Get-Command openssl -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $git = "C:\Program Files\Git\usr\bin\openssl.exe"
    if (Test-Path $git) { return $git }
    return $null
}

$openssl = Find-OpenSSL
if ($openssl) {
    Write-Host "Using OpenSSL at $openssl"
    $san = "subjectAltName=DNS:localhost,IP:127.0.0.1"
    & $openssl req -x509 -nodes -newkey rsa:2048 `
        -keyout $key -out $crt -days 825 `
        -subj "/C=US/ST=Lab/L=Lab/O=AegisIQ/OU=SOC/CN=localhost" `
        -addext $san `
        -addext "extendedKeyUsage=serverAuth"
    Write-Host "Wrote $crt and $key (valid 825 days)."
} else {
    Write-Host "OpenSSL not found - using Windows New-SelfSignedCertificate."
    $cert = New-SelfSignedCertificate `
        -Subject "CN=localhost" `
        -DnsName "localhost","127.0.0.1" `
        -KeyAlgorithm RSA -KeyLength 2048 `
        -NotAfter (Get-Date).AddDays(825) `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyExportPolicy Exportable
    # Export cert (PEM) and key (PEM) via a temp PFX.
    $pfx = Join-Path $certDir "aegis.pfx"
    $pwd = ConvertTo-SecureString -String "aegis" -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null
    # Requires openssl to split PFX->PEM; if truly absent, keep the PFX
    # and point uvicorn at it is not supported, so tell the user.
    Write-Host "Exported $pfx. Install OpenSSL (or Git for Windows) and re-run,"
    Write-Host "or convert manually:"
    Write-Host "  openssl pkcs12 -in certs\aegis.pfx -nocerts -nodes -out certs\aegis.key -passin pass:aegis"
    Write-Host "  openssl pkcs12 -in certs\aegis.pfx -clcerts -nokeys -out certs\aegis.crt -passin pass:aegis"
}
Write-Host "Then run the backend over TLS with:  scripts\run_https.ps1"
