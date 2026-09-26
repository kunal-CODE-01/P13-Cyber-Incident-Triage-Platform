#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
[ -f .env ] || cp .env.example .env
if ! command -v nmap >/dev/null 2>&1; then
  echo "WARNING: Nmap executable not found. Install nmap with your OS package manager for Network Scan."
fi
exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 app:app
