#!/bin/bash
# run_lynis_quick.sh - quick Lynis audit for deliverable (requires lynis installed and sudo)
# Output: /var/log/lynis.log and ./outputs/lynis-quick.txt (local copy)
set -e
mkdir -p outputs
echo "[+] Running Lynis quick audit (may require sudo)"
if ! command -v lynis >/dev/null 2>&1; then
    echo "ERROR: lynis not found. Install lynis or run on a system that has it."
    exit 1
fi
sudo lynis audit system --quick | tee outputs/lynis-quick.txt
echo "[+] Local copy saved to outputs/lynis-quick.txt"
echo "[+] Check /var/log/lynis.log and /var/log/lynis-report.dat for detailed logs"
