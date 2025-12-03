#!/bin/bash
#
# utils.sh - Funciones Comunes para Scripts de PAI-5 RedTeamPro
# Proporciona funciones de utilidad reutilizables para todos los scripts
# Autor: PAI-5 RedTeamPro Team
# Fecha: $(date +%Y-%m-%d)
#

# Colores para output
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export MAGENTA='\033[0;35m'
export CYAN='\033[0;36m'
export NC='\033[0m' # Sin color

# Variables globales
export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export LOG_DIR="$PROJECT_ROOT/06-Evidencias/logs"
export SCREENSHOTS_DIR="$PROJECT_ROOT/06-Evidencias/screenshots"
export NETWORK_CAPTURES_DIR="$PROJECT_ROOT/06-Evidencias/network-captures"

# Cargar variables de entorno si existen
if [ -f "$SCRIPT_DIR/.env" ]; then
    source "$SCRIPT_DIR/.env"
fi

# ============================================================================
# FUNCIONES DE LOGGING
# ============================================================================

# Logging con nivel INFO
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[✓]${NC} $1"
    echo "[$timestamp] [INFO] $1" >> "$LOG_DIR/main.log" 2>/dev/null || true
}

# Logging con nivel ERROR
error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[✗]${NC} $1" >&2
    echo "[$timestamp] [ERROR] $1" >> "$LOG_DIR/main.log" 2>/dev/null || true
}

# Logging con nivel WARNING
warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$timestamp] [WARNING] $1" >> "$LOG_DIR/main.log" 2>/dev/null || true
}

# Logging con nivel INFO (icono de información)
info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[i]${NC} $1"
    echo "[$timestamp] [INFO] $1" >> "$LOG_DIR/main.log" 2>/dev/null || true
}

# Logging de comandos ejecutados
log_command() {
    local cmd="$1"
    local logfile="${2:-$LOG_DIR/commands.log}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] COMMAND: $cmd" >> "$logfile"
}

# Logging de resultados de comandos
log_result() {
    local result="$1"
    local logfile="${2:-$LOG_DIR/results.log}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo "[$timestamp] RESULT:" >> "$logfile"
    echo "$result" >> "$logfile"
    echo "----------------------------------------" >> "$logfile"
}

# ============================================================================
# FUNCIONES DE BANNER Y UI
# ============================================================================

# Mostrar banner principal
show_banner() {
    local title="$1"
    local subtitle="$2"

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  PAI-5 RedTeamPro - $title"
    [ -n "$subtitle" ] && echo "║  $subtitle"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Mostrar separador
separator() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
}

# Mostrar mensaje de progreso
progress() {
    echo -e "${MAGENTA}[→]${NC} $1"
}

# ============================================================================
# FUNCIONES DE VALIDACIÓN
# ============================================================================

# Verificar si un comando existe
command_exists() {
    command -v "$1" &> /dev/null
}

# Verificar si una herramienta está instalada
check_tool() {
    local tool="$1"
    local install_hint="$2"

    if command_exists "$tool"; then
        log "$tool: instalado ✓"
        return 0
    else
        error "$tool: NO instalado"
        [ -n "$install_hint" ] && info "Instalar con: $install_hint"
        return 1
    fi
}

# Verificar múltiples herramientas
check_tools() {
    local tools=("$@")
    local missing=()

    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            missing+=("$tool")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        error "Herramientas faltantes: ${missing[*]}"
        return 1
    fi

    return 0
}

# Validar URL
validate_url() {
    local url="$1"

    if [[ "$url" =~ ^https?:// ]]; then
        return 0
    else
        error "URL inválida: $url"
        return 1
    fi
}

# Validar dirección IP
validate_ip() {
    local ip="$1"

    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        error "IP inválida: $ip"
        return 1
    fi
}

# Verificar conectividad con target
check_connectivity() {
    local target="$1"

    info "Verificando conectividad con $target..."

    if curl -s --max-time 5 "$target" > /dev/null 2>&1; then
        log "Conectividad verificada: $target responde"
        return 0
    else
        error "No se puede conectar a $target"
        return 1
    fi
}

# ============================================================================
# FUNCIONES DE ARCHIVOS Y DIRECTORIOS
# ============================================================================

# Crear directorio si no existe
ensure_dir() {
    local dir="$1"

    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        log "Directorio creado: $dir"
    fi
}

# Generar nombre de archivo único con timestamp
generate_filename() {
    local prefix="$1"
    local extension="$2"
    local timestamp=$(date '+%Y%m%d_%H%M%S')

    echo "${prefix}_${timestamp}.${extension}"
}

# Guardar output a archivo
save_output() {
    local output="$1"
    local filename="$2"
    local dir="$3"

    ensure_dir "$dir"
    local filepath="$dir/$filename"

    echo "$output" > "$filepath"
    log "Output guardado en: $filepath"
    echo "$filepath"
}

# ============================================================================
# FUNCIONES DE EVIDENCIA
# ============================================================================

# Capturar screenshot
capture_screenshot() {
    local description="$1"
    local filename=$(generate_filename "$description" "png")
    local filepath="$SCREENSHOTS_DIR/$filename"

    ensure_dir "$SCREENSHOTS_DIR"

    # Intentar diferentes herramientas de captura
    if command_exists "scrot"; then
        scrot "$filepath" 2>/dev/null
        log "Screenshot capturado: $filepath"
        return 0
    elif command_exists "gnome-screenshot"; then
        gnome-screenshot -f "$filepath" 2>/dev/null
        log "Screenshot capturado: $filepath"
        return 0
    elif command_exists "import"; then  # ImageMagick
        import -window root "$filepath" 2>/dev/null
        log "Screenshot capturado: $filepath"
        return 0
    else
        warning "No hay herramienta de captura disponible (instalar: scrot o gnome-screenshot)"
        return 1
    fi
}

# Iniciar captura de tráfico
start_packet_capture() {
    local description="$1"
    local interface="${2:-any}"
    local filename=$(generate_filename "$description" "pcap")
    local filepath="$NETWORK_CAPTURES_DIR/$filename"

    ensure_dir "$NETWORK_CAPTURES_DIR"

    if command_exists "tcpdump"; then
        info "Iniciando captura de tráfico en $interface..."
        sudo tcpdump -i "$interface" -w "$filepath" &> /dev/null &
        local pid=$!
        echo "$pid" > "/tmp/packet_capture_${description}.pid"
        log "Captura iniciada (PID: $pid): $filepath"
        echo "$filepath"
    else
        warning "tcpdump no disponible"
        return 1
    fi
}

# Detener captura de tráfico
stop_packet_capture() {
    local description="$1"
    local pidfile="/tmp/packet_capture_${description}.pid"

    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        if ps -p "$pid" > /dev/null 2>&1; then
            sudo kill "$pid" 2>/dev/null
            log "Captura detenida (PID: $pid)"
        fi
        rm "$pidfile"
    else
        warning "No se encontró captura activa para: $description"
    fi
}

# ============================================================================
# FUNCIONES DE MITRE ATT&CK
# ============================================================================

# Logging con técnica ATT&CK
log_attack_technique() {
    local technique_id="$1"
    local technique_name="$2"
    local description="$3"
    local logfile="$LOG_DIR/attack-techniques.log"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    ensure_dir "$LOG_DIR"

    cat >> "$logfile" <<EOF
[$timestamp] MITRE ATT&CK Technique
  ID: $technique_id
  Name: $technique_name
  Description: $description
  Timestamp: $timestamp
----------------------------------------
EOF

    info "Técnica ATT&CK logged: $technique_id - $technique_name"
}

# ============================================================================
# FUNCIONES DE REPORTES
# ============================================================================

# Generar resumen de hallazgos
generate_finding_summary() {
    local title="$1"
    local severity="$2"
    local description="$3"
    local cvss="$4"
    local cve="$5"
    local attack_technique="$6"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    cat <<EOF
# Hallazgo: $title

**Severidad**: $severity
**CVSS Score**: $cvss
**CVE**: ${cve:-N/A}
**MITRE ATT&CK**: $attack_technique
**Fecha**: $timestamp

## Descripción
$description

---
EOF
}

# Agregar hallazgo al reporte
add_finding() {
    local title="$1"
    local severity="$2"
    local description="$3"
    local cvss="$4"
    local cve="$5"
    local attack_technique="$6"
    local findings_file="$PROJECT_ROOT/08-Informe/findings.md"

    ensure_dir "$(dirname "$findings_file")"

    generate_finding_summary "$title" "$severity" "$description" "$cvss" "$cve" "$attack_technique" >> "$findings_file"
    log "Hallazgo agregado al reporte: $title"
}

# ============================================================================
# FUNCIONES DE TARGETS
# ============================================================================

# Obtener target de .env o parámetro
get_target() {
    local param_target="$1"

    if [ -n "$param_target" ]; then
        echo "$param_target"
    elif [ -n "$TARGET_URL" ]; then
        echo "$TARGET_URL"
    else
        error "No se especificó target"
        exit 1
    fi
}

# Extraer host de URL
extract_host() {
    local url="$1"
    echo "$url" | sed -E 's|^https?://([^:/]+).*|\1|'
}

# Extraer puerto de URL
extract_port() {
    local url="$1"

    if echo "$url" | grep -q ":[0-9]\+"; then
        echo "$url" | sed -E 's|^https?://[^:]+:([0-9]+).*|\1|'
    else
        if [[ "$url" =~ ^https:// ]]; then
            echo "443"
        else
            echo "80"
        fi
    fi
}

# ============================================================================
# FUNCIONES DE TIMER
# ============================================================================

# Iniciar timer
start_timer() {
    TIMER_START=$(date +%s)
    export TIMER_START
}

# Detener timer y mostrar duración
stop_timer() {
    local timer_end=$(date +%s)
    local duration=$((timer_end - TIMER_START))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    log "Duración: ${minutes}m ${seconds}s"
}

# ============================================================================
# FUNCIONES DE LIMPIEZA
# ============================================================================

# Limpiar archivos temporales
cleanup() {
    info "Limpiando archivos temporales..."

    # Limpiar archivos PID de capturas
    rm -f /tmp/packet_capture_*.pid 2>/dev/null

    log "Limpieza completada"
}

# Handler de señales para limpieza
trap_cleanup() {
    echo ""
    warning "Recibida señal de interrupción"
    cleanup
    exit 130
}

# Configurar traps
setup_traps() {
    trap trap_cleanup INT TERM
}

# ============================================================================
# FUNCIONES DE AYUDA
# ============================================================================

# Mostrar uso de script
show_usage() {
    local script_name="$1"
    local description="$2"
    local usage="$3"
    local examples="$4"

    cat <<EOF
${BLUE}PAI-5 RedTeamPro - $script_name${NC}

${description}

${YELLOW}Uso:${NC}
  $usage

${YELLOW}Ejemplos:${NC}
$examples

${YELLOW}Variables de entorno (.env):${NC}
  TARGET_URL        - URL del target (por defecto)
  TARGET_IP         - IP del target
  LOG_DIR           - Directorio de logs
  SCREENSHOTS_DIR   - Directorio de screenshots

${YELLOW}Para más información:${NC}
  Consulta la documentación en: $PROJECT_ROOT/README.md
EOF
}

# ============================================================================
# FUNCIÓN DE INICIALIZACIÓN
# ============================================================================

# Inicializar entorno del script
init_script() {
    local script_name="$1"

    # Configurar traps
    setup_traps

    # Crear directorios necesarios
    ensure_dir "$LOG_DIR"
    ensure_dir "$SCREENSHOTS_DIR"
    ensure_dir "$NETWORK_CAPTURES_DIR"

    # Logging de inicio
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] ========== $script_name INICIADO ==========" >> "$LOG_DIR/main.log"

    # Iniciar timer
    start_timer
}

# Finalizar script
finish_script() {
    local script_name="$1"

    # Detener timer
    stop_timer

    # Logging de finalización
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] ========== $script_name FINALIZADO ==========" >> "$LOG_DIR/main.log"

    # Limpieza
    cleanup
}

# ============================================================================
# EXPORTAR FUNCIONES
# ============================================================================

# Hacer funciones disponibles para otros scripts
export -f log error warning info
export -f log_command log_result
export -f show_banner separator progress
export -f command_exists check_tool check_tools
export -f validate_url validate_ip check_connectivity
export -f ensure_dir generate_filename save_output
export -f capture_screenshot start_packet_capture stop_packet_capture
export -f log_attack_technique
export -f generate_finding_summary add_finding
export -f get_target extract_host extract_port
export -f start_timer stop_timer
export -f cleanup trap_cleanup setup_traps
export -f show_usage
export -f init_script finish_script

# Mensaje de carga
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    # Script siendo sourced
    log "utils.sh cargado correctamente"
fi
