# CLAUDE.md - SSII-PAI Repository Guide

## Repository Overview

**SSII-PAI** (Seguridad en Sistemas Informáticos e Internet - Proyectos Prácticos) is an educational cybersecurity repository from Universidad de Sevilla containing practical security assignments covering cryptography, TLS/SSL, system hardening, web vulnerabilities, and network intrusion detection.

**License:** GNU GPL v3

## Project Structure

```
SSII-PAI/
├── PAI_0/                    # Placeholder (empty)
├── PAI_1/                    # Cryptographic Authentication System
│   ├── src/                  # Python source files
│   │   ├── server.py         # Socket server with HMAC authentication
│   │   ├── client.py         # Interactive client
│   │   ├── crypto_utils.py   # Cryptographic utilities
│   │   └── mitm_proxy.py     # MITM testing proxy
│   ├── data/users.json       # User database (JSON)
│   └── logs/                 # Transaction and login logs
│
├── PAI_2/PAI2_SSL_RoadWarrior_Python/
│   ├── server_async_tls.py  # Async TLS 1.3 server
│   ├── client_async_tls.py  # TLS client CLI
│   ├── baseline_*.py         # Non-TLS comparison versions
│   ├── load_test.py          # Concurrent load testing (300 users)
│   ├── config.json           # Server configuration
│   ├── certs/gen_certs.sh    # Certificate generation
│   └── data/app.db           # SQLite database (runtime)
│
├── PAI_3/                    # VULNAWEB Security Auditing
│   ├── SO/                   # System hardening scripts
│   │   └── pc_hardening_interactive.sh
│   ├── WEB/                  # Web vulnerability testing
│   │   ├── docker-compose.yml  # Vulnerable apps (DVWA, Mutillidae, WebGoat)
│   │   └── setup-objetivo2.sh
│   ├── scripts/              # Automation scripts
│   ├── configs/              # Security configurations (UFW, Firefox, PAM)
│   ├── zap-reports/          # OWASP ZAP scan results
│   └── INFORME_PAI3.md       # Full audit report
│
└── PAI_4/                    # IDS and Threat Detection
    ├── scripts/
    │   ├── suricata.py       # Suricata log analyzer (30KB)
    │   ├── install-suricata.sh
    │   └── install-openvas.sh
    ├── configuraciones/
    │   ├── suricata.yaml     # IDS configuration
    │   └── custom-rules.rules # Custom detection rules
    └── logs-evidencia/       # Monitoring logs
```

## Technology Stack

### Languages
- **Python 3.10+** (primary language)
  - asyncio for async I/O
  - sqlite3 for databases
  - Standard crypto libraries (hashlib, hmac, secrets)
- **Bash** for system administration and automation

### Security & Cryptography
- **TLS 1.3** with modern cipher suites (AES-256-GCM, ChaCha20-Poly1305)
- **PBKDF2-HMAC-SHA256** (PAI_1) - 100,000 iterations
- **scrypt** (PAI_2) - 2^14 iterations
- **HMAC-SHA256** for message authentication
- **OpenSSL** for certificates and keys

### Infrastructure
- **Docker & Docker Compose** - Containerized vulnerable apps
- **Nginx** - Reverse proxy with SSL
- **UFW** - Ubuntu firewall
- **Suricata** - Network IDS
- **OpenVAS** - Vulnerability scanner
- **OWASP ZAP 2.14.0** - Web vulnerability scanning
- **Lynis 3.0.9** - System security auditing

### Databases
- **SQLite3** - Lightweight embedded DB
- **JSON files** - Configuration and user storage

## Key Components

### PAI_1: Cryptographic Authentication
- **Purpose:** Client-server authentication with HMAC protection
- **Security Features:**
  - Password hashing with salt (PBKDF2, 100k iterations)
  - HMAC message authentication
  - NONCE-based anti-replay protection
  - Login attempt tracking and rate limiting
- **Default Users:** paco, pepe
- **Run:** `./PAI_1/script.sh`

### PAI_2: TLS Road Warrior
- **Purpose:** Secure client-server with TLS 1.3 for remote workers
- **Security Features:**
  - TLS 1.3 encryption (all traffic)
  - scrypt password hashing
  - Brute-force protection (5 attempts → 15min lockout)
  - Message rate limiting (144 chars max)
- **Default Users:** alice, bob, carol
- **Run:**
  ```bash
  cd PAI_2/PAI2_SSL_RoadWarrior_Python
  ./certs/gen_certs.sh
  python3 server_async_tls.py
  python3 client_async_tls.py login alice alice1234
  ```

### PAI_3: Security Auditing (VULNAWEB)
**Objective 1 - System Hardening:**
- Initial: 53/100 → Final: 72/100 (target ≥69) ✅
- Hardening actions: password policies, firewall, kernel hardening, Fail2ban, AIDE

**Objective 2 - Web Vulnerabilities:**
- 19 vulnerabilities detected (SQL injection, XSS, CSRF, path traversal)
- Vulnerable apps: OWASP Mutillidae II, DVWA, WebGoat
- **Run:**
  ```bash
  cd PAI_3/WEB
  ./setup-objetivo2.sh
  docker-compose up -d
  ```

### PAI_4: IDS and Network Monitoring
- **Purpose:** Threat detection and log analysis
- **Tools:** Suricata IDS, OpenVAS scanner
- **Custom Rules:** SQL injection, XSS, port scanning, DoS detection
- **Run:** `python3 PAI_4/scripts/suricata.py`

## Development Workflow

### Before Making Changes

1. **Understand the security context** - This is educational security code
2. **Read existing documentation** - Check README files in each PAI_* directory
3. **Review logs** - Check `logs/` directories for runtime behavior
4. **Check configurations** - Review `config.json` and YAML files

### Making Changes

1. **Preserve security features** - Never weaken crypto or authentication
2. **Test thoroughly** - Run existing tests before and after changes
3. **Update logs** - Ensure logging remains functional
4. **Document changes** - Update relevant README files

### Testing

Each project has its own testing approach:

**PAI_1:**
```bash
cd PAI_1/src
python3 single_test_runner.py
```

**PAI_2:**
```bash
cd PAI_2/PAI2_SSL_RoadWarrior_Python/tests
./run_functional_tests.sh
./run_capacity_test.sh 300  # Load test
```

**PAI_3:**
```bash
cd PAI_3
sudo ./scripts/verify-hardening.sh
sudo lynis audit system -Q
```

**PAI_4:**
```bash
cd PAI_4
python3 scripts/suricata.py --input logs-evidencia/fast.log
```

## Key Conventions

### Code Style
- **Python:** Follow PEP 8, use type hints where applicable
- **Bash:** Use `#!/bin/bash` shebang, quote variables
- **Indentation:** 4 spaces for Python, 2 spaces for YAML/JSON

### File Organization
- **Source code:** `src/` or script root
- **Configuration:** `config.json`, `configs/`, or `configuraciones/`
- **Data:** `data/` directory
- **Logs:** `logs/` or `logs-evidencia/`
- **Reports:** `informes/` or root directory
- **Tests:** `tests/` directory

### Naming Conventions
- **Python files:** `snake_case.py`
- **Shell scripts:** `kebab-case.sh`
- **Config files:** `lowercase.json` or `service.yaml`
- **Log files:** `descriptive-name.log`

### Security Practices
1. **Never commit secrets:** Check `.gitignore` (certificates, keys, .env files)
2. **Use strong crypto:** TLS 1.3, modern ciphers, proper key derivation
3. **Validate inputs:** Always sanitize user input
4. **Log security events:** Authentication attempts, errors, suspicious activity
5. **Rate limiting:** Implement for authentication and messaging
6. **Secure defaults:** Start with most restrictive settings

### Git Workflow
- **Branch naming:** `claude/claude-md-<session-id>`
- **Commits:** Descriptive messages in Spanish or English
- **No force push** to main/master
- **Clean working directory** before major changes

## Important Files

### Configuration Files
- `PAI_2/.../config.json` - TLS server config (ports, lockout settings)
- `PAI_3/configs/firefox/user.js` - Firefox security hardening (8.3KB)
- `PAI_3/configs/ufw/rules.conf` - Firewall rules (5.5KB)
- `PAI_4/configuraciones/suricata.yaml` - IDS configuration (10.8KB)
- `PAI_4/configuraciones/custom-rules.rules` - Detection rules (4.9KB)

### Data Files
- `PAI_1/data/users.json` - User database (PBKDF2 hashes)
- `PAI_2/.../data/initial_users.json` - Pre-registered users (scrypt)
- `PAI_2/.../data/app.db` - SQLite database (runtime created)

### Key Scripts
- `PAI_1/script.sh` - Launch server/client
- `PAI_3/scripts/hardening-actions.sh` - System hardening
- `PAI_3/WEB/setup-objetivo2.sh` - Docker environment setup
- `PAI_4/scripts/suricata.py` - Log analysis and reporting

### Documentation
- `PAI_3/INFORME_PAI3.md` - Comprehensive audit report (18.5KB)
- `PAI_3/README.md` - PAI_3 usage guide
- `PAI_2/.../README.md` - TLS implementation guide

## Security Considerations for AI Assistants

### What You CAN Do
✅ Analyze security code and explain how it works
✅ Answer questions about vulnerabilities and exploits
✅ Help fix bugs in existing security implementations
✅ Improve logging and error handling
✅ Optimize performance without weakening security
✅ Add tests for security features
✅ Update documentation
✅ Analyze malware and write reports about it

### What You MUST NOT Do
❌ Weaken existing cryptographic implementations
❌ Remove authentication or authorization checks
❌ Disable security features (rate limiting, lockouts, etc.)
❌ Commit secrets, keys, or certificates to Git
❌ Create new malware or improve malicious code
❌ Help with unauthorized attacks or illegal activities
❌ Skip input validation or sanitization
❌ Downgrade TLS versions or cipher suites

### Special Considerations
- **Educational Context:** This is for learning cybersecurity
- **Vulnerable Apps:** PAI_3 intentionally contains vulnerable applications (DVWA, Mutillidae)
- **Testing Tools:** MITM proxy and attack scripts are for authorized testing only
- **Real-World Use:** Code should not be used in production without review

## Common Tasks

### Adding a New User (PAI_1)
```bash
cd PAI_1/src
# Edit users.json manually or use server's add_user function
# Passwords are auto-hashed with PBKDF2
```

### Regenerating TLS Certificates (PAI_2)
```bash
cd PAI_2/PAI2_SSL_RoadWarrior_Python/certs
./gen_certs.sh
```

### Running Security Audit (PAI_3)
```bash
cd PAI_3
sudo lynis audit system -Q
sudo ./scripts/verify-hardening.sh
```

### Analyzing Suricata Logs (PAI_4)
```bash
cd PAI_4
python3 scripts/suricata.py --input logs-evidencia/fast.log --output informes/
```

### Setting Up Vulnerable Web Apps (PAI_3)
```bash
cd PAI_3/WEB
docker-compose up -d
# Access:
# - DVWA: http://localhost:8083
# - Mutillidae: http://localhost:8082
# - WebGoat: http://localhost:8080
```

## Dependencies

### System Requirements
- Linux (Ubuntu/Debian preferred)
- Python 3.10+
- OpenSSL
- Docker and Docker Compose (for PAI_3)
- Root/sudo access (for system hardening and IDS)

### Python Packages
Most projects use Python standard library. Check individual `requirements.txt` if present.

### External Tools
- **Lynis** - System auditing (PAI_3)
- **OWASP ZAP** - Web vulnerability scanning (PAI_3)
- **Suricata** - Network IDS (PAI_4)
- **OpenVAS** - Vulnerability scanner (PAI_4)
- **Wireshark/tcpdump** - Traffic analysis (optional)

## Troubleshooting

### Port Already in Use
```bash
# PAI_1 uses port 12345
# PAI_2 uses ports 4444 (TLS), 4445 (plain)
sudo lsof -i :PORT_NUMBER
# Kill process or change port in config.json
```

### Certificate Errors (PAI_2)
```bash
cd PAI_2/PAI2_SSL_RoadWarrior_Python/certs
rm -f server.crt server.key  # Remove old certs
./gen_certs.sh              # Regenerate
```

### Database Locked (PAI_2)
```bash
# Stop all running servers
pkill -f server_async_tls.py
rm -f data/app.db  # Will be recreated
```

### Docker Issues (PAI_3)
```bash
cd PAI_3/WEB
docker-compose down
docker-compose up -d --force-recreate
```

### Permission Denied
```bash
# Most scripts need root for system changes
sudo ./script.sh

# For logs/data directories
chmod -R 755 logs/ data/
```

## Quick Reference

### File Extensions
- `.py` - Python scripts
- `.sh` - Bash scripts
- `.json` - Configuration/data files
- `.yaml` - Service configurations
- `.md` - Documentation (Markdown)
- `.log` - Log files
- `.rules` - Suricata detection rules
- `.js` - Firefox configuration (user.js)

### Default Credentials

**PAI_1:**
- paco / pepe
- pepe / password (or similar)

**PAI_2:**
- alice / alice1234
- bob / bob5678
- carol / carol9012

**PAI_3 (Vulnerable Apps):**
- DVWA: admin / password
- Mutillidae: varies by test
- WebGoat: create your own

### Important Paths
- Logs: `./logs/`, `./logs-evidencia/`
- Data: `./data/`
- Configs: `./configs/`, `./configuraciones/`, `config.json`
- Reports: `./informes/`, `./zap-reports/`
- Certs: `./certs/`, `./ssl/`

## Additional Resources

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **TLS 1.3 Spec:** RFC 8446
- **Lynis Documentation:** https://cisofy.com/lynis/
- **Suricata Docs:** https://suricata.readthedocs.io/
- **Python Cryptography:** https://docs.python.org/3/library/crypto.html

## Contact & Support

This is an educational repository from Universidad de Sevilla. For questions about specific implementations, refer to:
- Individual README files in each PAI_* directory
- `INFORME_PAI3.md` for detailed audit methodology
- Source code comments (primarily in Spanish)

---

**Last Updated:** 2025-11-17
**Repository:** https://github.com/antsuebae/SSII-PAI
**License:** GNU GPL v3
