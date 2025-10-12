#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# Generate a self-signed certificate for the server (valid 365 days)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -sha256 -days 365 -nodes -subj "/CN=localhost"
echo "Self-signed certificate created at certs/server.crt and server.key"
