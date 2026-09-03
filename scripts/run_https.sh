#!/usr/bin/env bash
# scripts/run_https.sh — run the AegisIQ backend over HTTPS/TLS.
#
#   ./scripts/run_https.sh            # https://localhost:8443
#   PORT=9443 ./scripts/run_https.sh
#
# Generates a self-signed cert on first run if certs/ is empty, then
# starts uvicorn with TLS. Point the frontend at https://localhost:8443
# (VITE_API_URL); streamUrl() upgrades ws:// to wss:// automatically.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT="${PORT:-8443}"
CERT="certs/aegis.crt"
KEY="certs/aegis.key"

if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
  echo "No cert found — generating a self-signed one..."
  ./scripts/generate_certs.sh
fi

# Prefer the project venv if present.
if [[ -x "backend/venv/bin/uvicorn" ]]; then
  UVICORN="backend/venv/bin/uvicorn"
elif [[ -x ".venv/bin/uvicorn" ]]; then
  UVICORN=".venv/bin/uvicorn"
else
  UVICORN="uvicorn"
fi

cd backend
exec "../$UVICORN" app.main:app \
  --host 0.0.0.0 --port "$PORT" \
  --ssl-keyfile "../$KEY" \
  --ssl-certfile "../$CERT"
