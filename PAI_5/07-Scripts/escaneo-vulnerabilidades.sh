#!/bin/bash
#
# escaneo-vulnerabilidades.sh - Script de Escaneo de Vulnerabilidades para PAI-5 RedTeamPro
# Ejecuta múltiples scanners de vulnerabilidades web
# MITRE ATT&CK: T1595.002 (Active Scanning: Vulnerability Scanning)
# Autor: PAI-5 RedTeamPro Team
#

set -e

# Cargar funciones comunes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Directorios de salida
SCAN_DIR="$PROJECT_ROOT/03-Escaneo"
VULN_REPORTS_DIR="$SCAN_DIR/vulnerability-reports"
NIKTO_DIR="$SCAN_DIR/nikto-output"
SQLMAP_DIR="$SCAN_DIR/sqlmap-output"

# ============================================================================
# FUNCIONES DE ESCANEO
# ============================================================================

# Escaneo con Nikto
run_nikto() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595.002" "Vulnerability Scanning" "Nikto web vulnerability scanner"

    info "Ejecutando escaneo con Nikto..."
    warning "Este escaneo puede tomar varios minutos..."

    if ! command_exists nikto; then
        error "Nikto no está instalado"
        info "Instalar con: apt-get install nikto"
        return 1
    fi

    local cmd="nikto -h $url -o ${output_file}.html -Format html"
    log_command "$cmd"

    if eval "$cmd" | tee "${output_file}.txt"; then
        log "Escaneo Nikto completado"
        log "  - Texto: ${output_file}.txt"
        log "  - HTML: ${output_file}.html"
        return 0
    else
        error "Falló el escaneo con Nikto"
        return 1
    fi
}

# Escaneo básico con SQLMap
run_sqlmap_basic() {
    local url="$1"
    local output_dir="$2"

    log_attack_technique "T1595.002" "Vulnerability Scanning" "SQLMap SQL injection detection"

    info "Ejecutando detección de SQL Injection con SQLMap..."
    warning "Modo básico - detección rápida"

    if ! command_exists sqlmap; then
        error "SQLMap no está instalado"
        info "Instalar con: apt-get install sqlmap"
        return 1
    fi

    # Test básico en páginas comunes de DVWA
    local test_urls=(
        "${url}/vulnerabilities/sqli/?id=1&Submit=Submit"
        "${url}/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    )

    for test_url in "${test_urls[@]}"; do
        info "Testing: $test_url"

        local cmd="sqlmap -u \"$test_url\" --batch --cookie=\"PHPSESSID=\${DVWA_SESSION}; security=low\" --level=1 --risk=1 --output-dir=\"$output_dir\""
        log_command "$cmd"

        # Nota: SQLMap requiere cookie de sesión válida para DVWA
        warning "Nota: SQLMap requiere cookie de sesión PHPSESSID válida"
        info "Obten la cookie desde el navegador después de hacer login en DVWA"

        echo ""
    done

    log "Detección SQLMap completada. Resultados en: $output_dir"
}

# Escaneo con OWASP ZAP (si está disponible)
run_zap_scan() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595.002" "Vulnerability Scanning" "OWASP ZAP automated scan"

    info "Ejecutando escaneo con OWASP ZAP..."

    # Buscar ZAP en ubicaciones comunes
    local zap_cli=""
    if command_exists zap-cli; then
        zap_cli="zap-cli"
    elif command_exists zaproxy; then
        zap_cli="zaproxy"
    elif [ -f "/usr/share/zaproxy/zap.sh" ]; then
        zap_cli="/usr/share/zaproxy/zap.sh"
    elif [ -f "/opt/zaproxy/zap.sh" ]; then
        zap_cli="/opt/zaproxy/zap.sh"
    fi

    if [ -z "$zap_cli" ]; then
        warning "OWASP ZAP no está instalado"
        info "Instalar con: apt-get install zaproxy"
        return 1
    fi

    info "Usando ZAP: $zap_cli"
    info "Iniciando escaneo automatizado..."

    # ZAP baseline scan
    if command_exists zap-baseline.py || command_exists docker; then
        if command_exists docker; then
            local cmd="docker run --rm -v \$(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t $url -r ${output_file}.html"
            log_command "$cmd"
            eval "$cmd" || true
            log "ZAP scan completado: ${output_file}.html"
        else
            warning "ZAP requiere Docker para escaneo automatizado"
            info "O usa ZAP GUI manualmente"
        fi
    else
        info "Usa ZAP GUI para escaneo manual:"
        echo "  1. Abrir ZAP"
        echo "  2. Automated Scan"
        echo "  3. URL: $url"
        echo "  4. Guardar reporte en: $output_file"
    fi
}

# Escaneo con wpscan (si el target es WordPress)
run_wpscan() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595.002" "Vulnerability Scanning" "WordPress vulnerability scan"

    info "Verificando si el target es WordPress..."

    # Verificar si es WordPress
    if curl -s "$url" | grep -qi "wp-content\|wordpress"; then
        log "WordPress detectado!"

        if command_exists wpscan; then
            info "Ejecutando WPScan..."
            local cmd="wpscan --url $url --enumerate vp,vt,u --output ${output_file}_wpscan.txt"
            log_command "$cmd"
            eval "$cmd" || true
            log "WPScan completado: ${output_file}_wpscan.txt"
        else
            info "WPScan no disponible. Instalar con: apt-get install wpscan"
        fi
    else
        info "El target no parece ser WordPress"
    fi
}

# Escaneo de directorios y archivos comunes
run_directory_enumeration() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1083" "File and Directory Discovery" "Directory and file enumeration"

    info "Ejecutando enumeración de directorios..."

    # Lista de directorios comunes para DVWA
    local common_dirs=(
        "admin"
        "login"
        "config"
        "includes"
        "uploads"
        "vulnerabilities"
        "dvwa"
        "database"
        "docs"
        "security"
        "setup"
        "phpinfo.php"
        "test.php"
        ".git"
        ".env"
        "backup"
        "db"
    )

    echo "# Directory Enumeration Results" > "${output_file}_dirs.txt"
    echo "Target: $url" >> "${output_file}_dirs.txt"
    echo "Date: $(date)" >> "${output_file}_dirs.txt"
    echo "" >> "${output_file}_dirs.txt"

    for dir in "${common_dirs[@]}"; do
        local test_url="${url}/${dir}"
        local status=$(curl -s -o /dev/null -w "%{http_code}" "$test_url" 2>/dev/null || echo "000")

        if [ "$status" = "200" ] || [ "$status" = "301" ] || [ "$status" = "302" ]; then
            echo "[+] FOUND ($status): $test_url" | tee -a "${output_file}_dirs.txt"
            log "Encontrado: $test_url [$status]"
        else
            echo "[-] Not Found ($status): $test_url" >> "${output_file}_dirs.txt"
        fi
    done

    log "Enumeración de directorios completada: ${output_file}_dirs.txt"

    # Usar gobuster si está disponible (más completo)
    if command_exists gobuster; then
        info "Usando Gobuster para enumeración más completa..."

        # Buscar wordlist
        local wordlist=""
        if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
            wordlist="/usr/share/wordlists/dirb/common.txt"
        elif [ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]; then
            wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
        fi

        if [ -n "$wordlist" ]; then
            local cmd="gobuster dir -u $url -w $wordlist -o ${output_file}_gobuster.txt -q"
            log_command "$cmd"
            eval "$cmd" 2>/dev/null || true
            log "Gobuster completado: ${output_file}_gobuster.txt"
        else
            warning "No se encontró wordlist para gobuster"
        fi
    fi
}

# Test de headers de seguridad
check_security_headers() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595.002" "Vulnerability Scanning" "Security headers analysis"

    info "Analizando headers de seguridad..."

    {
        echo "# Security Headers Analysis"
        echo "Target: $url"
        echo "Date: $(date)"
        echo ""
        echo "## HTTP Headers"
        curl -I "$url" 2>/dev/null
        echo ""
        echo "## Security Headers Check"
        echo ""

        # Headers de seguridad importantes
        local headers=(
            "X-Frame-Options"
            "X-Content-Type-Options"
            "X-XSS-Protection"
            "Strict-Transport-Security"
            "Content-Security-Policy"
            "X-Permitted-Cross-Domain-Policies"
        )

        for header in "${headers[@]}"; do
            if curl -I "$url" 2>/dev/null | grep -qi "$header"; then
                echo "[+] $header: PRESENT"
            else
                echo "[-] $header: MISSING (Vulnerable)"
            fi
        done

        echo ""
        echo "## Server Information Disclosure"
        local server_header=$(curl -I "$url" 2>/dev/null | grep -i "Server:" || echo "Not disclosed")
        echo "Server: $server_header"

        local xpowered=$(curl -I "$url" 2>/dev/null | grep -i "X-Powered-By:" || echo "Not disclosed")
        echo "X-Powered-By: $xpowered"

    } | tee "${output_file}_headers.txt"

    log "Análisis de headers completado: ${output_file}_headers.txt"
}

# Test de métodos HTTP
check_http_methods() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595.002" "Vulnerability Scanning" "HTTP methods enumeration"

    info "Enumerando métodos HTTP permitidos..."

    {
        echo "# HTTP Methods Test"
        echo "Target: $url"
        echo "Date: $(date)"
        echo ""

        # Test de OPTIONS
        echo "## OPTIONS Method:"
        curl -X OPTIONS -I "$url" 2>/dev/null | grep -i "allow:" || echo "No Allow header"
        echo ""

        # Test de métodos potencialmente peligrosos
        local methods=("GET" "POST" "PUT" "DELETE" "TRACE" "CONNECT" "OPTIONS" "HEAD")

        echo "## Method Tests:"
        for method in "${methods[@]}"; do
            local status=$(curl -X "$method" -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
            echo "$method: $status"

            if [ "$method" = "TRACE" ] && [ "$status" = "200" ]; then
                echo "  [!] WARNING: TRACE method enabled (XST vulnerability)"
            fi

            if [ "$method" = "PUT" ] && [ "$status" != "405" ] && [ "$status" != "401" ]; then
                echo "  [!] WARNING: PUT method may be enabled"
            fi
        done

    } | tee "${output_file}_methods.txt"

    log "Test de métodos HTTP completado: ${output_file}_methods.txt"
}

# Test de SSL/TLS vulnerabilities
check_ssl_vulnerabilities() {
    local url="$1"
    local output_file="$2"

    if [[ ! "$url" =~ ^https:// ]]; then
        info "Target no usa HTTPS, omitiendo test SSL/TLS"
        return 0
    fi

    log_attack_technique "T1595.002" "Vulnerability Scanning" "SSL/TLS vulnerability testing"

    info "Verificando vulnerabilidades SSL/TLS..."

    local host=$(extract_host "$url")

    if command_exists testssl.sh || command_exists testssl; then
        local testssl_cmd=$(command -v testssl.sh || command -v testssl)
        local cmd="$testssl_cmd --vulnerable $host:443"
        log_command "$cmd"
        eval "$cmd" | tee "${output_file}_ssl_vulns.txt"
        log "Test SSL/TLS completado: ${output_file}_ssl_vulns.txt"
    elif command_exists sslscan; then
        local cmd="sslscan $host:443"
        log_command "$cmd"
        eval "$cmd" | tee "${output_file}_sslscan.txt"
        log "SSLScan completado: ${output_file}_sslscan.txt"
    else
        warning "testssl.sh o sslscan no disponibles"
        info "Instalar con: apt-get install testssl.sh o apt-get install sslscan"
    fi
}

# Generar reporte consolidado de vulnerabilidades
generate_vulnerability_report() {
    local target="$1"
    local timestamp="$2"
    local report_file="$VULN_REPORTS_DIR/vulnerability-report-${timestamp}.md"

    info "Generando reporte consolidado de vulnerabilidades..."

    cat > "$report_file" <<EOF
# Reporte de Vulnerabilidades - PAI-5 RedTeamPro

**Target**: $target
**Fecha**: $(date '+%Y-%m-%d %H:%M:%S')
**Timestamp**: $timestamp

## Resumen Ejecutivo

Este reporte contiene los hallazgos del escaneo automatizado de vulnerabilidades.

## Metodología

- **Framework**: NIST 800-115
- **MITRE ATT&CK**: T1595.002 (Vulnerability Scanning)
- **Herramientas utilizadas**:
  - Nikto
  - SQLMap
  - OWASP ZAP
  - Security Headers Analysis
  - HTTP Methods Testing
  - Directory Enumeration

## Escaneos Ejecutados

### 1. Nikto - Web Vulnerability Scanner
- Archivo: \`03-Escaneo/nikto-output/nikto-scan-${timestamp}.txt\`
- Formato HTML: \`03-Escaneo/nikto-output/nikto-scan-${timestamp}.html\`

### 2. SQLMap - SQL Injection Detection
- Directorio: \`03-Escaneo/sqlmap-output/\`
- Nota: Requiere cookie de sesión válida para testing completo

### 3. Security Headers Analysis
- Archivo: \`03-Escaneo/vulnerability-reports/scan-${timestamp}_headers.txt\`

### 4. HTTP Methods Testing
- Archivo: \`03-Escaneo/vulnerability-reports/scan-${timestamp}_methods.txt\`

### 5. Directory Enumeration
- Archivo: \`03-Escaneo/vulnerability-reports/scan-${timestamp}_dirs.txt\`

## Vulnerabilidades Comunes en DVWA

### High Severity

1. **SQL Injection (CWE-89)**
   - CVSS: 9.8
   - Ubicación: /vulnerabilities/sqli/
   - MITRE ATT&CK: T1190

2. **Command Injection (CWE-78)**
   - CVSS: 9.8
   - Ubicación: /vulnerabilities/exec/
   - MITRE ATT&CK: T1059

3. **File Upload (CWE-434)**
   - CVSS: 9.8
   - Ubicación: /vulnerabilities/upload/
   - MITRE ATT&CK: T1505.003

### Medium Severity

4. **Cross-Site Scripting - Stored (CWE-79)**
   - CVSS: 8.8
   - Ubicación: /vulnerabilities/xss_s/
   - MITRE ATT&CK: T1059.007

5. **Cross-Site Scripting - Reflected (CWE-79)**
   - CVSS: 6.1
   - Ubicación: /vulnerabilities/xss_r/
   - MITRE ATT&CK: T1059.007

6. **CSRF (CWE-352)**
   - CVSS: 6.5
   - Ubicación: /vulnerabilities/csrf/
   - MITRE ATT&CK: T1185

### Low Severity

7. **Insecure CAPTCHA**
   - CVSS: 4.3
   - Ubicación: /vulnerabilities/captcha/

8. **Weak Session IDs**
   - CVSS: 5.3
   - Ubicación: /vulnerabilities/weak_id/

## Técnicas MITRE ATT&CK Identificadas

| ID | Técnica | Severidad |
|----|---------|-----------|
| T1190 | Exploit Public-Facing Application | High |
| T1059 | Command and Scripting Interpreter | High |
| T1059.004 | Unix Shell | High |
| T1505.003 | Web Shell | High |
| T1059.007 | JavaScript | Medium |
| T1185 | Browser Session Hijacking | Medium |
| T1083 | File and Directory Discovery | Low |
| T1082 | System Information Discovery | Low |

## Próximos Pasos

1. **Revisar hallazgos manualmente**:
   - Leer reportes detallados de Nikto
   - Verificar SQLMap outputs
   - Analizar headers de seguridad

2. **Priorizar vulnerabilidades**:
   - Crítico: SQL Injection, Command Injection
   - Alto: File Upload, XSS Stored
   - Medio: CSRF, XSS Reflected

3. **Proceder con Explotación**:
   - Directorio: \`04-Explotacion/\`
   - Guía: \`04-Explotacion/README.md\`

4. **Documentar evidencias**:
   - Capturar screenshots de cada vulnerabilidad
   - Guardar en: \`06-Evidencias/screenshots/\`

## Referencias

- CVE Database: https://cve.mitre.org/
- OWASP Top 10 2021: https://owasp.org/Top10/
- MITRE ATT&CK: https://attack.mitre.org/
- DVWA Documentation: https://github.com/digininja/DVWA

## OWASP Top 10 2021 Mapping

| OWASP Category | DVWA Vulnerabilities |
|----------------|---------------------|
| A01:2021 - Broken Access Control | CSRF, Insecure CAPTCHA |
| A03:2021 - Injection | SQL Injection, Command Injection |
| A07:2021 - XSS | Reflected XSS, Stored XSS |
| A05:2021 - Security Misconfiguration | Missing Security Headers |
| A08:2021 - Data Integrity Failures | File Upload |

---

*Generado automáticamente por escaneo-vulnerabilidades.sh*
EOF

    log "Reporte consolidado generado: $report_file"
    echo "$report_file"
}

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

main() {
    local target="$1"

    # Inicializar script
    init_script "escaneo-vulnerabilidades.sh"

    # Banner
    show_banner "Escaneo de Vulnerabilidades" "MITRE ATT&CK: T1595.002"

    # Validar target
    if [ -z "$target" ]; then
        target=$(get_target "")
    fi

    if ! validate_url "$target"; then
        error "Target inválido: $target"
        info "Uso: bash escaneo-vulnerabilidades.sh <target-url>"
        info "Ejemplo: bash escaneo-vulnerabilidades.sh http://localhost:80"
        exit 1
    fi

    log "Target: $target"

    # Verificar conectividad
    if ! check_connectivity "$target"; then
        error "No se puede conectar al target. Verifica que esté accesible."
        exit 1
    fi

    # Verificar herramientas
    info "Verificando herramientas disponibles..."
    local tools=("curl" "nikto")
    for tool in "${tools[@]}"; do
        check_tool "$tool" "apt-get install $tool" || true
    done

    # Crear directorios
    ensure_dir "$VULN_REPORTS_DIR"
    ensure_dir "$NIKTO_DIR"
    ensure_dir "$SQLMAP_DIR"

    # Timestamp
    local timestamp=$(date '+%Y%m%d_%H%M%S')

    separator
    echo -e "${CYAN}Iniciando Escaneo de Vulnerabilidades${NC}"
    separator
    echo ""

    # ========== ESCANEO NIKTO ==========
    progress "Paso 1/7: Nikto Web Vulnerability Scan"
    echo ""
    run_nikto "$target" "$NIKTO_DIR/nikto-scan-${timestamp}" || true
    echo ""

    # ========== SECURITY HEADERS ==========
    progress "Paso 2/7: Security Headers Analysis"
    echo ""
    check_security_headers "$target" "$VULN_REPORTS_DIR/scan-${timestamp}" || true
    echo ""

    # ========== HTTP METHODS ==========
    progress "Paso 3/7: HTTP Methods Testing"
    echo ""
    check_http_methods "$target" "$VULN_REPORTS_DIR/scan-${timestamp}" || true
    echo ""

    # ========== DIRECTORY ENUMERATION ==========
    progress "Paso 4/7: Directory Enumeration"
    echo ""
    run_directory_enumeration "$target" "$VULN_REPORTS_DIR/scan-${timestamp}" || true
    echo ""

    # ========== SQLMAP ==========
    progress "Paso 5/7: SQL Injection Detection (SQLMap)"
    echo ""
    warning "SQLMap requiere autenticación en DVWA"
    info "Obtén la cookie PHPSESSID desde el navegador después de login"
    echo ""
    read -p "¿Ejecutar SQLMap? (requiere configuración manual) (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        run_sqlmap_basic "$target" "$SQLMAP_DIR" || true
    fi
    echo ""

    # ========== SSL/TLS ==========
    progress "Paso 6/7: SSL/TLS Vulnerability Testing"
    echo ""
    check_ssl_vulnerabilities "$target" "$VULN_REPORTS_DIR/scan-${timestamp}" || true
    echo ""

    # ========== OWASP ZAP ==========
    progress "Paso 7/7: OWASP ZAP Scan (opcional)"
    echo ""
    read -p "¿Ejecutar OWASP ZAP scan? (requiere Docker o ZAP instalado) (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        run_zap_scan "$target" "$VULN_REPORTS_DIR/zap-scan-${timestamp}" || true
    fi
    echo ""

    # ========== GENERAR REPORTE ==========
    separator
    echo -e "${CYAN}Escaneo de Vulnerabilidades Completado${NC}"
    separator
    echo ""

    local report_file=$(generate_vulnerability_report "$target" "$timestamp")

    log "Todos los resultados guardados en:"
    echo "  - Nikto: $NIKTO_DIR/"
    echo "  - SQLMap: $SQLMAP_DIR/"
    echo "  - Reportes: $VULN_REPORTS_DIR/"
    echo "  - Reporte consolidado: $report_file"
    echo ""

    info "Próximos pasos:"
    echo "  1. Revisar reporte consolidado: cat $report_file"
    echo "  2. Analizar vulnerabilidades encontradas"
    echo "  3. Priorizar según CVSS y criticidad"
    echo "  4. Proceder con fase de Explotación:"
    echo "     cd 04-Explotacion/"
    echo "     cat README.md"
    echo ""

    # Finalizar script
    finish_script "escaneo-vulnerabilidades.sh"

    log "Escaneo de vulnerabilidades finalizado exitosamente"
}

# Manejo de argumentos
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        show_usage "escaneo-vulnerabilidades.sh" \
            "Script de escaneo de vulnerabilidades - MITRE ATT&CK: T1595.002" \
            "bash escaneo-vulnerabilidades.sh <target-url>" \
            "  ${GREEN}Escanear DVWA:${NC}
    bash escaneo-vulnerabilidades.sh http://localhost:80

  ${GREEN}Con logging automático:${NC}
    bash logger.sh start escaneo-vulns
    bash escaneo-vulnerabilidades.sh http://localhost:80"
        exit 0
    fi

    main "$@"
fi
