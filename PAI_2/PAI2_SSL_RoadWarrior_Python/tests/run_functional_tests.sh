#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 server_async_tls.py &
SERVER_PID=$!
sleep 1
python3 client_async_tls.py login alice alice1234
python3 client_async_tls.py send "mensaje de prueba"
python3 client_async_tls.py stats
kill $SERVER_PID || true
