#!/bin/bash
# run_zap_docker_baseline.sh - run OWASP ZAP baseline scan using the official Docker image
# Usage: ./run_zap_docker_baseline.sh <TARGET_URL>
# Example: ./run_zap_docker_baseline.sh http://localhost:8080
set -e
if [ -z "$1" ]; then
    echo "Usage: $0 <TARGET_URL>"
    exit 1
fi
TARGET="$1"
mkdir -p outputs/zap
echo "[+] Pulling ZAP docker image..."
docker pull owasp/zap2docker-stable >/dev/null
echo "[+] Running ZAP baseline scan against ${TARGET} ... (this may take a few minutes)"
docker run --rm -v $(pwd)/outputs/zap:/zap/wrk/:Z owasp/zap2docker-stable zap-baseline.py -t ${TARGET} -r zap-report.html
echo "[+] Report saved to outputs/zap/zap-report.html"
