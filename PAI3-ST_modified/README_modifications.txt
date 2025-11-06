PAI3 - MODIFIED PACKAGE (web + laptop parts)
============================================
What I changed / added
- Added run_lynis_quick.sh: quick Lynis audit wrapper (requires lynis + sudo).
- Added run_zap_docker_baseline.sh: runs OWASP ZAP baseline via Docker (requires Docker).
- Added Informe_PAI3.pdf: a 1-page skeleton report describing the modifications and next steps.
- Added this README and an 'outputs' folder suggestion where scan outputs will be stored.

How to use (on your Kali/Ubuntu machine)
1) Copy this folder to the machine where you will run the tests.
2) For the laptop hardening (Lynis):
   - Ensure lynis is installed: sudo apt update && sudo apt install -y lynis
   - Run: ./run_lynis_quick.sh
   - Review outputs/lynis-quick.txt and /var/log/lynis.log
3) For the web application scan (OWASP ZAP baseline via Docker):
   - Ensure Docker is installed and the target web app is reachable.
   - Run: ./run_zap_docker_baseline.sh http://<target-host>:<port>
   - The HTML report will be in outputs/zap/zap-report.html
Notes
- I did NOT implement mobile device scanning (you asked to exclude mobile).
- The scripts only create local copies of reports in the 'outputs' folder for packaging.
- If you want, I can further customise the report PDF content (findings, screenshots) once you run these scripts and upload outputs.
