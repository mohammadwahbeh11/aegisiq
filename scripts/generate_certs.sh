#!/usr/bin/env bash
# scripts/generate_certs.sh — create a self-signed TLS certificate for
# local HTTPS development of AegisIQ.
#
#   ./scripts/generate_certs.sh
#
# Produces certs/aegis.key (private key) and certs/aegis.crt (cert),
# valid for 825 days, with Subject Alternative Names for localhost,
# 127.0.0.1 and ::1 so browsers and the smoke test accept it for the
# local hostnames. Self-signed — browsers will warn until you trust it
# once; that is expected for a lab. Do NOT ship this cert to production;
# use a CA-issued (or internal-CA/mkcert) certificate there.
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p certs

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found. Install it (apt install openssl / brew install openssl)." >&2
  exit 1
fi

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout certs/aegis.key \
  -out certs/aegis.crt \
  -days 825 \
  -subj "/C=US/ST=Lab/L=Lab/O=AegisIQ/OU=SOC/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 600 certs/aegis.key
echo "Wrote certs/aegis.crt and certs/aegis.key (valid 825 days)."
echo "Run the backend over TLS with:  scripts/run_https.sh"
