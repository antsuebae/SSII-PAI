#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 server_async_tls.py &
SERVER_PID=$!
sleep 1
python3 load_test.py -n ${1:-300}
kill $SERVER_PID || true
