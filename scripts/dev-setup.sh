#!/usr/bin/env bash
# Convenience script for the non-Docker backend setup path.
# See README.md "Local setup (without Docker)" for the frontend steps
# and for what this script does in plain commands.
set -euo pipefail

cd "$(dirname "$0")/../backend"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f "../.env" ]; then
  cp ../.env.example ../.env
  echo "Created .env from .env.example - review it before continuing."
fi

echo "Setup complete. Run the API with:"
echo "  cd backend && source .venv/bin/activate && uvicorn app.main:app --reload"
