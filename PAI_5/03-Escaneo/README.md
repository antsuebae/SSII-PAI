# Fase de Escaneo de Vulnerabilidades

**MITRE ATT&CK**: T1595.002 (Active Scanning: Vulnerability Scanning)

## Objetivo

Identificar vulnerabilidades explotables en la aplicación web mediante herramientas automatizadas y análisis manual. Esta fase se enfoca en detectar debilidades de seguridad que puedan ser explotadas en la siguiente fase.

## Subdirectorios

```
03-Escaneo/
├── README.md                      # Este archivo
├── vulnerability-reports/         # Reportes consolidados de vulnerabilidades
├── nikto-output/                  # Resultados de Nikto
└── sqlmap-output/                 # Resultados de SQLMap
```

## Técnicas MITRE ATT&CK Aplicables

| ID | Técnica | Descripción |
|----|---------|-------------|
| T1595.002 | Vulnerability Scanning | Escaneo activo de vulnerabilidades |
| T1190 | Exploit Public-Facing Application | Identificación de apps vulnerables |

## 1. Escaneo con Nikto

### 1.1. Escaneo Básico

```bash
# Target
TARGET="http://localhost:80"

# Escaneo básico con output en texto
nikto -h $TARGET -o nikto-output/nikto-scan.txt

# Escaneo con output HTML (más legible)
nikto -h $TARGET -o nikto-output/nikto-scan.html -Format html

# Escaneo con ambos formatos
nikto -h $TARGET -o nikto-output/nikto-scan.html -Format html | tee nikto-output/nikto-scan.txt
```

**Mapeo ATT&CK**: T1595.002 (Vulnerability Scanning)

### 1.2. Escaneo con Tuning

```bash
# Tuning específico para diferentes tipos de tests
# 0: File Upload
# 1: Interesting File / Seen in logs
# 2: Misconfiguration / Default File
# 3: Information Disclosure
# 4: Injection (XSS/Script/HTML)
# 5: Remote File Retrieval - Inside Web Root
# 6: Denial of Service
# 7: Remote File Retrieval - Server Wide
# 8: Command Execution / Remote Shell
# 9: SQL Injection
# a: Authentication Bypass
# b: Software Identification
# c: Remote Source Inclusion
# x: Reverse Tuning Options

# Escaneo solo para inyecciones
nikto -h $TARGET -Tuning 489 -o nikto-output/nikto-injection-scan.txt

# Escaneo solo para autenticación
nikto -h $TARGET -Tuning ab -o nikto-output/nikto-auth-scan.txt
```

### 1.3. Nikto con Plugins Específicos

```bash
# Listar plugins disponibles
nikto -list-plugins

# Ejecutar plugin específico
nikto -h $TARGET -Plugins cookies -o nikto-output/nikto-cookies.txt
```

### 1.4. Analizar Resultados de Nikto

```bash
# Ver vulnerabilidades encontradas
grep "+ " nikto-output/nikto-scan.txt

# Buscar vulnerabilidades críticas
grep -i "sql\|xss\|injection\|exec\|upload" nikto-output/nikto-scan.txt

# Contar hallazgos
grep -c "+ " nikto-output/nikto-scan.txt
```

## 2. SQLMap - SQL Injection Detection

### 2.1. Preparación para SQLMap

DVWA requiere autenticación. Primero obtén la cookie de sesión:

```bash
# 1. Login en DVWA (navegador)
# 2. Abrir DevTools (F12)
# 3. Application > Cookies > localhost
# 4. Copiar valor de PHPSESSID y security

# Guardar cookie en variable
PHPSESSID="tu-session-id-aqui"
SECURITY="low"  # o medium, high
```

### 2.2. SQLMap - Módulo SQL Injection

```bash
# URL del módulo vulnerable
SQLI_URL="http://localhost:80/vulnerabilities/sqli/?id=1&Submit=Submit"

# Test básico
sqlmap -u "$SQLI_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    --batch \
    --output-dir="sqlmap-output/"

# Test con nivel y riesgo específicos
sqlmap -u "$SQLI_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    --level=5 \
    --risk=3 \
    --batch \
    --output-dir="sqlmap-output/"
```

**Opciones importantes**:
- `--batch`: No hacer preguntas interactivas
- `--level=1-5`: Profundidad de tests (1=básico, 5=exhaustivo)
- `--risk=1-3`: Nivel de riesgo (3 puede afectar datos)

### 2.3. SQLMap - Enumeración de Base de Datos

```bash
# Listar bases de datos
sqlmap -u "$SQLI_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    --dbs \
    --batch

# Listar tablas de una base de datos
sqlmap -u "$SQLI_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    -D dvwa \
    --tables \
    --batch

# Listar columnas de una tabla
sqlmap -u "$SQLI_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    -D dvwa \
    -T users \
    --columns \
    --batch

# Volcar datos de una tabla
sqlmap -u "$SQLI_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    -D dvwa \
    -T users \
    --dump \
    --batch
```

**Mapeo ATT&CK**: T1213 (Data from Information Repositories)

### 2.4. SQLMap - Blind SQL Injection

```bash
# URL del módulo blind SQLi
BLIND_URL="http://localhost:80/vulnerabilities/sqli_blind/?id=1&Submit=Submit"

# Test de blind SQLi
sqlmap -u "$BLIND_URL" \
    --cookie="PHPSESSID=$PHPSESSID; security=$SECURITY" \
    --technique=B \
    --batch \
    --output-dir="sqlmap-output/blind/"

# Opciones de técnica:
# B: Boolean-based blind
# E: Error-based
# U: Union query-based
# S: Stacked queries
# T: Time-based blind
# Q: Inline queries
```

## 3. Security Headers Analysis

### 3.1. Análisis de Headers HTTP

```bash
# Obtener todos los headers
curl -I $TARGET | tee vulnerability-reports/http-headers.txt

# Verificar headers de seguridad específicos
curl -I $TARGET | grep -E "X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Strict-Transport-Security|Content-Security-Policy"
```

### 3.2. Headers de Seguridad Importantes

**Headers que DEBERÍAN estar presentes**:

| Header | Propósito | Estado en DVWA |
|--------|-----------|----------------|
| `X-Frame-Options` | Protección clickjacking | ❌ MISSING |
| `X-Content-Type-Options` | Prevenir MIME sniffing | ❌ MISSING |
| `X-XSS-Protection` | Protección XSS básica | ❌ MISSING |
| `Content-Security-Policy` | Política de seguridad de contenido | ❌ MISSING |
| `Strict-Transport-Security` | Forzar HTTPS | ❌ N/A (no HTTPS) |
| `Referrer-Policy` | Control de referrer | ❌ MISSING |

### 3.3. Information Disclosure

```bash
# Headers que revelan información sensible
curl -I $TARGET | grep -E "Server:|X-Powered-By:|Via:"

# Ejemplo de output vulnerable:
# Server: Apache/2.4.41 (Ubuntu)
# X-Powered-By: PHP/7.4.3
```

**Vulnerabilidad**: CWE-200 (Exposure of Sensitive Information)

## 4. HTTP Methods Testing

### 4.1. Enumeración de Métodos

```bash
# Test con OPTIONS
curl -X OPTIONS -I $TARGET

# Test de cada método
for method in GET POST PUT DELETE TRACE CONNECT OPTIONS HEAD; do
    echo "Testing $method:"
    curl -X $method -s -o /dev/null -w "%{http_code}\n" $TARGET
done
```

### 4.2. Métodos Peligrosos

**TRACE (XST - Cross-Site Tracing)**:
```bash
# Test de TRACE
curl -X TRACE -I $TARGET

# Si devuelve 200, es vulnerable a XST
```

**PUT (File Upload)**:
```bash
# Test de PUT
curl -X PUT -d "test" $TARGET/test.txt -I

# Si devuelve 201/204, puede permitir upload arbitrario
```

## 5. Directory & File Enumeration

### 5.1. Enumeración Manual

```bash
# Directorios comunes en DVWA
DIRS=(
    "admin"
    "config"
    "database"
    "docs"
    "dvwa"
    "includes"
    "login"
    "setup"
    "security"
    "vulnerabilities"
    ".git"
    ".env"
    "backup"
    "phpinfo.php"
)

# Verificar cada directorio
for dir in "${DIRS[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$dir")
    if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "302" ]; then
        echo "[+] FOUND: $TARGET/$dir [$status]"
    fi
done
```

**Mapeo ATT&CK**: T1083 (File and Directory Discovery)

### 5.2. Gobuster - Enumeración Avanzada

```bash
# Instalar si no está disponible
sudo apt-get install gobuster

# Wordlist común
WORDLIST="/usr/share/wordlists/dirb/common.txt"

# Escaneo básico
gobuster dir -u $TARGET -w $WORDLIST -o vulnerability-reports/gobuster-dirs.txt

# Escaneo con extensiones PHP
gobuster dir -u $TARGET -w $WORDLIST -x php,txt,html,bak -o vulnerability-reports/gobuster-extended.txt

# Escaneo con status codes específicos
gobuster dir -u $TARGET -w $WORDLIST -s "200,204,301,302,307,401,403" -o vulnerability-reports/gobuster-all-codes.txt
```

### 5.3. Archivos Sensibles

```bash
# Lista de archivos sensibles a buscar
SENSITIVE_FILES=(
    ".env"
    ".git/config"
    "config.php"
    "database.sql"
    "phpinfo.php"
    "robots.txt"
    "sitemap.xml"
    "backup.zip"
    "db_backup.sql"
    ".htaccess"
    "web.config"
)

# Verificar existencia
for file in "${SENSITIVE_FILES[@]}"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$file")
    if [ "$status" != "404" ]; then
        echo "[!] SENSITIVE FILE FOUND: $TARGET/$file [$status]"
    fi
done
```

## 6. SSL/TLS Vulnerability Testing

### 6.1. TestSSL.sh

Si DVWA usa HTTPS:

```bash
# Instalar testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# Test completo
./testssl.sh https://target.com

# Test solo de vulnerabilidades
./testssl.sh --vulnerable https://target.com

# Test rápido
./testssl.sh --fast https://target.com
```

### 6.2. SSLScan

```bash
# Alternativa a testssl
sslscan --show-certificate target.com:443
```

## 7. OWASP ZAP (Opcional)

### 7.1. ZAP con Docker

```bash
# Baseline scan con Docker
docker run --rm -v $(pwd):/zap/wrk/:rw \
    -t owasp/zap2docker-stable \
    zap-baseline.py -t $TARGET \
    -r vulnerability-reports/zap-baseline.html

# Full scan (más agresivo)
docker run --rm -v $(pwd):/zap/wrk/:rw \
    -t owasp/zap2docker-stable \
    zap-full-scan.py -t $TARGET \
    -r vulnerability-reports/zap-full.html
```

### 7.2. ZAP GUI

```bash
# Iniciar ZAP GUI
zaproxy

# Pasos:
# 1. Automated Scan > URL: http://localhost:80
# 2. Attack > Active Scan
# 3. Report > Generate HTML Report
```

## 8. Identificación de Vulnerabilidades DVWA

### 8.1. Vulnerabilidades Esperadas

**Critical (CVSS 9.0+)**:

1. **SQL Injection** (CWE-89)
   - Módulos: `/vulnerabilities/sqli/`, `/vulnerabilities/sqli_blind/`
   - CVSS: 9.8
   - MITRE: T1213

2. **Command Injection** (CWE-78)
   - Módulo: `/vulnerabilities/exec/`
   - CVSS: 9.8
   - MITRE: T1059.004

3. **File Upload** (CWE-434)
   - Módulo: `/vulnerabilities/upload/`
   - CVSS: 9.8
   - MITRE: T1505.003

**High (CVSS 7.0-8.9)**:

4. **Stored XSS** (CWE-79)
   - Módulo: `/vulnerabilities/xss_s/`
   - CVSS: 8.8
   - MITRE: T1059.007

5. **File Inclusion** (CWE-98)
   - Módulo: `/vulnerabilities/fi/`
   - CVSS: 8.6
   - MITRE: T1083

6. **Brute Force** (CWE-307)
   - Módulo: `/vulnerabilities/brute/`
   - CVSS: 7.5
   - MITRE: T1110.001

**Medium (CVSS 4.0-6.9)**:

7. **CSRF** (CWE-352)
   - Módulo: `/vulnerabilities/csrf/`
   - CVSS: 6.5
   - MITRE: T1185

8. **Reflected XSS** (CWE-79)
   - Módulo: `/vulnerabilities/xss_r/`
   - CVSS: 6.1
   - MITRE: T1059.007

9. **Weak Session IDs** (CWE-330)
   - Módulo: `/vulnerabilities/weak_id/`
   - CVSS: 5.3
   - MITRE: T1539

**Low (CVSS < 4.0)**:

10. **Insecure CAPTCHA** (CWE-804)
    - Módulo: `/vulnerabilities/captcha/`
    - CVSS: 4.3
    - MITRE: T1110

## 9. Script Automatizado

### 9.1. Ejecutar Escaneo Completo

```bash
# Con logging
bash ../07-Scripts/logger.sh start escaneo-vulnerabilidades
bash ../07-Scripts/escaneo-vulnerabilidades.sh http://localhost:80
# (escribir 'exit' al terminar)

# Sin logging
bash ../07-Scripts/escaneo-vulnerabilidades.sh http://localhost:80
```

## 10. Documentación de Hallazgos

### 10.1. Plantilla de Hallazgo

```markdown
## Vulnerabilidad: [Nombre]

**Severidad**: Critical/High/Medium/Low
**CVSS Score**: X.X (CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X)
**CWE**: CWE-XXX
**CVE**: CVE-XXXX-XXXX (si aplica)
**MITRE ATT&CK**: TXXXX

**Ubicación**: /path/to/vuln

**Descripción**: [Descripción técnica]

**Evidencia**: [Screenshot/Log]

**Impacto**: [Impacto potencial]

**Recomendación**: [Cómo mitigar]
```

### 10.2. Captura de Evidencias

```bash
# Capturar screenshot de vulnerabilidad
bash ../07-Scripts/capture-evidence.sh --screenshot escaneo sqli "nikto-findings" T1595.002

# Guardar log de comando
bash ../07-Scripts/capture-evidence.sh --command-log escaneo nikto "nikto -h localhost" "$(cat nikto-output/nikto-scan.txt)" T1595.002
```

## 11. Análisis de Resultados

### 11.1. Priorización de Vulnerabilidades

Criterios de priorización:

1. **CVSS Score** (9.0+ = Critical, 7.0-8.9 = High, 4.0-6.9 = Medium, <4.0 = Low)
2. **Facilidad de explotación** (Simple, Moderada, Compleja)
3. **Impacto** (RCE > SQLi > XSS > Info Disclosure)
4. **Accesibilidad** (Sin auth > Con auth)

### 11.2. Mapeo a OWASP Top 10 2021

| OWASP Category | Vulnerabilidades DVWA |
|----------------|---------------------|
| A01:2021 - Broken Access Control | CSRF, Insecure CAPTCHA |
| A03:2021 - Injection | SQL Injection, Command Injection |
| A05:2021 - Security Misconfiguration | Headers, PHP errors |
| A07:2021 - XSS | Reflected XSS, Stored XSS |
| A08:2021 - Data Integrity Failures | File Upload |

## 12. Próximos Pasos

Una vez completado el escaneo:

1. ✅ Revisar todos los reportes generados
2. ✅ Documentar cada vulnerabilidad encontrada
3. ✅ Priorizar según CVSS y impacto
4. ✅ Preparar payloads para explotación
5. ✅ Proceder con **Fase de Explotación**:

```bash
cd ../04-Explotacion
cat README.md
```

## 13. Referencias

- **Nikto**: https://github.com/sullo/nikto
- **SQLMap**: https://sqlmap.org/
- **OWASP ZAP**: https://www.zaproxy.org/
- **Gobuster**: https://github.com/OJ/gobuster
- **TestSSL**: https://github.com/drwetter/testssl.sh
- **OWASP Top 10 2021**: https://owasp.org/Top10/
- **CWE Database**: https://cwe.mitre.org/
- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1

## 14. Checklist

- [ ] Escaneo con Nikto completado
- [ ] SQLMap ejecutado en módulos SQLi
- [ ] Security headers analizados
- [ ] HTTP methods testeados
- [ ] Enumeración de directorios completada
- [ ] SSL/TLS testing (si aplica)
- [ ] OWASP ZAP scan ejecutado (opcional)
- [ ] Todas las vulnerabilidades documentadas
- [ ] Evidencias capturadas (screenshots, logs)
- [ ] Vulnerabilidades priorizadas por CVSS
- [ ] Mapeo a MITRE ATT&CK completado
- [ ] Mapeo a OWASP Top 10 realizado
- [ ] Reporte consolidado generado

---

**Última actualización**: 2024-12-03
**Fase siguiente**: 04-Explotacion (Exploitation)
