#!/bin/bash
#
# logger.sh - Sistema de Logging Automático para PAI-5 RedTeamPro
# Captura automáticamente todos los comandos ejecutados y sus salidas
# Autor: PAI-5 RedTeamPro Team
# Fecha: $(date +%Y-%m-%d)
#
# Uso:
#   bash logger.sh start <session-name>     # Iniciar sesión con logging
#   bash logger.sh stop                     # Detener sesión actual
#   bash logger.sh status                   # Ver estado de logging
#   bash logger.sh list                     # Listar sesiones disponibles
#

set -e

# Cargar funciones comunes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Directorios específicos para logging
SESSION_DIR="$LOG_DIR/sessions"
CURRENT_SESSION_FILE="/tmp/pai5_current_session"

# ============================================================================
# FUNCIONES DE SESIÓN
# ============================================================================

# Generar nombre de sesión único
generate_session_id() {
    local session_name="$1"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    echo "${session_name}_${timestamp}"
}

# Iniciar nueva sesión de logging
start_session() {
    local session_name="$1"

    if [ -z "$session_name" ]; then
        error "Debe especificar un nombre de sesión"
        show_usage "logger.sh" \
            "Sistema de logging automático para pentesting" \
            "bash logger.sh start <session-name>" \
            "  bash logger.sh start reconocimiento
  bash logger.sh start explotacion-sqli
  bash logger.sh start post-explotacion"
        exit 1
    fi

    # Verificar si ya hay una sesión activa
    if [ -f "$CURRENT_SESSION_FILE" ]; then
        local active_session=$(cat "$CURRENT_SESSION_FILE")
        error "Ya hay una sesión activa: $active_session"
        info "Detén la sesión actual con: bash logger.sh stop"
        exit 1
    fi

    # Generar ID de sesión
    local session_id=$(generate_session_id "$session_name")
    local session_dir="$SESSION_DIR/$session_id"

    # Crear directorios de sesión
    ensure_dir "$session_dir"

    # Archivos de log de la sesión
    local command_log="$session_dir/commands.log"
    local output_log="$session_dir/output.log"
    local terminal_log="$session_dir/terminal.log"
    local metadata="$session_dir/metadata.json"

    # Crear metadata de sesión
    cat > "$metadata" <<EOF
{
  "session_id": "$session_id",
  "session_name": "$session_name",
  "start_time": "$(date '+%Y-%m-%d %H:%M:%S')",
  "start_timestamp": $(date +%s),
  "user": "$USER",
  "hostname": "$HOSTNAME",
  "target_url": "${TARGET_URL:-N/A}",
  "target_ip": "${TARGET_IP:-N/A}",
  "working_directory": "$(pwd)",
  "status": "active"
}
EOF

    # Guardar sesión actual
    echo "$session_id" > "$CURRENT_SESSION_FILE"

    show_banner "Logger - Sesión Iniciada" "Session ID: $session_id"

    log "Sesión de logging iniciada: $session_name"
    log "Session ID: $session_id"
    log "Directorio: $session_dir"
    echo ""

    info "Todos los comandos se están registrando automáticamente"
    info "Archivos de log:"
    echo "  - Comandos: $command_log"
    echo "  - Output: $output_log"
    echo "  - Terminal completo: $terminal_log"
    echo ""

    warning "Recuerda ejecutar 'bash logger.sh stop' cuando termines"
    echo ""

    # Iniciar script command para capturar terminal completo
    info "Iniciando captura de terminal..."
    echo ""

    # Guardar la sesión en variable de entorno
    export PAI5_SESSION_ID="$session_id"
    export PAI5_SESSION_DIR="$session_dir"
    export PAI5_COMMAND_LOG="$command_log"
    export PAI5_OUTPUT_LOG="$output_log"

    # Iniciar subshell con logging
    bash --rcfile <(cat <<'RCFILE'
# Cargar .bashrc original si existe
if [ -f ~/.bashrc ]; then
    source ~/.bashrc
fi

# Cargar variables de sesión
SESSION_ID="${PAI5_SESSION_ID}"
SESSION_DIR="${PAI5_SESSION_DIR}"
COMMAND_LOG="${PAI5_COMMAND_LOG}"
OUTPUT_LOG="${PAI5_OUTPUT_LOG}"
TERMINAL_LOG="${SESSION_DIR}/terminal.log"

# Modificar prompt para indicar logging activo
PS1="[\033[1;32mLOGGING\033[0m] $PS1"

# Función para loggear comandos
log_command_execution() {
    local cmd="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # No loggear comandos internos de logging
    if [[ "$cmd" =~ ^(history|log_command_execution) ]]; then
        return
    fi

    # Loggear comando
    echo "[$timestamp] COMMAND: $cmd" >> "$COMMAND_LOG"

    # Agregar separador visual
    echo "" >> "$COMMAND_LOG"
}

# Función para ejecutar y loggear
run_with_log() {
    local cmd="$*"
    log_command_execution "$cmd"

    # Ejecutar comando y capturar output
    eval "$cmd" 2>&1 | tee -a "$OUTPUT_LOG"
}

# Hook PROMPT_COMMAND para loggear después de cada comando
if [ -n "$PROMPT_COMMAND" ]; then
    PROMPT_COMMAND="log_command_execution \"\$(history 1 | sed 's/^[ ]*[0-9]*[ ]*//')\" ; $PROMPT_COMMAND"
else
    PROMPT_COMMAND='log_command_execution "$(history 1 | sed \"s/^[ ]*[0-9]*[ ]*//\")"'
fi

# Mensaje de bienvenida en la sesión
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   PAI-5 RedTeamPro - Sesión de Logging Activa          ║"
echo "║   Session ID: $SESSION_ID"
echo "║   Todos los comandos están siendo registrados           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Para detener el logging, escribe: exit"
echo ""

# Iniciar script para capturar terminal completo
script -q -f "$TERMINAL_LOG" -c "bash"

# Al salir, actualizar metadata
echo "Finalizando sesión de logging..."
RCFILE
)

    # La sesión ha terminado (usuario hizo exit)
    stop_session
}

# Detener sesión actual
stop_session() {
    if [ ! -f "$CURRENT_SESSION_FILE" ]; then
        warning "No hay ninguna sesión activa"
        return 0
    fi

    local session_id=$(cat "$CURRENT_SESSION_FILE")
    local session_dir="$SESSION_DIR/$session_id"
    local metadata="$session_dir/metadata.json"

    if [ -f "$metadata" ]; then
        # Actualizar metadata con tiempo de finalización
        local start_timestamp=$(jq -r '.start_timestamp' "$metadata" 2>/dev/null || echo "0")
        local end_timestamp=$(date +%s)
        local duration=$((end_timestamp - start_timestamp))

        # Actualizar archivo JSON
        jq --arg end_time "$(date '+%Y-%m-%d %H:%M:%S')" \
           --arg end_timestamp "$end_timestamp" \
           --arg duration "$duration" \
           --arg status "completed" \
           '. + {end_time: $end_time, end_timestamp: $end_timestamp, duration: $duration, status: $status}' \
           "$metadata" > "${metadata}.tmp" && mv "${metadata}.tmp" "$metadata"
    fi

    # Eliminar sesión actual
    rm "$CURRENT_SESSION_FILE"

    echo ""
    show_banner "Logger - Sesión Finalizada" "Session ID: $session_id"

    log "Sesión de logging finalizada: $session_id"
    log "Logs guardados en: $session_dir"

    # Mostrar resumen
    show_session_summary "$session_id"

    echo ""
    log "Puedes revisar los logs con:"
    echo "  less $session_dir/commands.log"
    echo "  less $session_dir/output.log"
    echo "  less $session_dir/terminal.log"
    echo ""
}

# Mostrar resumen de sesión
show_session_summary() {
    local session_id="$1"
    local session_dir="$SESSION_DIR/$session_id"
    local metadata="$session_dir/metadata.json"

    if [ ! -f "$metadata" ]; then
        error "No se encontró metadata para sesión: $session_id"
        return 1
    fi

    echo ""
    separator
    echo -e "${CYAN}Resumen de Sesión${NC}"
    separator

    if command_exists jq; then
        local session_name=$(jq -r '.session_name' "$metadata")
        local start_time=$(jq -r '.start_time' "$metadata")
        local end_time=$(jq -r '.end_time // "N/A"' "$metadata")
        local duration=$(jq -r '.duration // "N/A"' "$metadata")
        local status=$(jq -r '.status' "$metadata")

        echo "Session ID: $session_id"
        echo "Nombre: $session_name"
        echo "Inicio: $start_time"
        echo "Fin: $end_time"

        if [ "$duration" != "N/A" ]; then
            local minutes=$((duration / 60))
            local seconds=$((duration % 60))
            echo "Duración: ${minutes}m ${seconds}s"
        fi

        echo "Estado: $status"
    else
        cat "$metadata"
    fi

    # Estadísticas de logs
    if [ -f "$session_dir/commands.log" ]; then
        local num_commands=$(grep -c "COMMAND:" "$session_dir/commands.log" 2>/dev/null || echo "0")
        echo "Comandos ejecutados: $num_commands"
    fi

    separator
}

# Ver estado actual
show_status() {
    show_banner "Logger - Estado Actual"

    if [ -f "$CURRENT_SESSION_FILE" ]; then
        local session_id=$(cat "$CURRENT_SESSION_FILE")
        log "Sesión activa: $session_id"

        show_session_summary "$session_id"
    else
        info "No hay ninguna sesión de logging activa"
        echo ""
        info "Iniciar nueva sesión con: bash logger.sh start <nombre>"
    fi
}

# Listar todas las sesiones
list_sessions() {
    show_banner "Logger - Sesiones Disponibles"

    if [ ! -d "$SESSION_DIR" ] || [ -z "$(ls -A "$SESSION_DIR" 2>/dev/null)" ]; then
        info "No hay sesiones registradas"
        return 0
    fi

    echo ""
    echo -e "${CYAN}Sesiones registradas:${NC}"
    echo ""

    local count=0
    for session_path in "$SESSION_DIR"/*; do
        if [ -d "$session_path" ]; then
            local session_id=$(basename "$session_path")
            local metadata="$session_path/metadata.json"

            if [ -f "$metadata" ] && command_exists jq; then
                count=$((count + 1))
                local session_name=$(jq -r '.session_name' "$metadata")
                local start_time=$(jq -r '.start_time' "$metadata")
                local status=$(jq -r '.status' "$metadata")

                echo -e "${GREEN}[$count]${NC} $session_id"
                echo "    Nombre: $session_name"
                echo "    Inicio: $start_time"
                echo "    Estado: $status"
                echo ""
            fi
        fi
    done

    if [ $count -eq 0 ]; then
        info "No hay sesiones válidas"
    else
        log "Total de sesiones: $count"
    fi
}

# Ver logs de una sesión específica
view_session() {
    local session_id="$1"

    if [ -z "$session_id" ]; then
        error "Debe especificar un session_id"
        info "Lista de sesiones: bash logger.sh list"
        exit 1
    fi

    local session_dir="$SESSION_DIR/$session_id"

    if [ ! -d "$session_dir" ]; then
        error "Sesión no encontrada: $session_id"
        exit 1
    fi

    show_banner "Logger - Visualizando Sesión" "$session_id"

    show_session_summary "$session_id"

    echo ""
    separator
    echo -e "${CYAN}Archivos de log disponibles:${NC}"
    separator
    echo ""

    if [ -f "$session_dir/commands.log" ]; then
        echo "1. Comandos ejecutados: $session_dir/commands.log"
    fi

    if [ -f "$session_dir/output.log" ]; then
        echo "2. Output de comandos: $session_dir/output.log"
    fi

    if [ -f "$session_dir/terminal.log" ]; then
        echo "3. Terminal completo: $session_dir/terminal.log"
    fi

    echo ""
    info "Ver logs con: less <archivo>"
}

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

main() {
    local command="${1:-help}"
    shift || true

    case "$command" in
        start)
            start_session "$@"
            ;;
        stop)
            stop_session
            ;;
        status)
            show_status
            ;;
        list)
            list_sessions
            ;;
        view)
            view_session "$@"
            ;;
        help|--help|-h)
            show_usage "logger.sh" \
                "Sistema de logging automático para pentesting" \
                "bash logger.sh <comando> [opciones]" \
                "  ${GREEN}Iniciar sesión:${NC}
    bash logger.sh start reconocimiento
    bash logger.sh start explotacion-sqli
    bash logger.sh start post-explotacion

  ${GREEN}Ver estado:${NC}
    bash logger.sh status

  ${GREEN}Listar sesiones:${NC}
    bash logger.sh list

  ${GREEN}Ver logs de sesión:${NC}
    bash logger.sh view <session-id>

  ${GREEN}Detener sesión actual:${NC}
    bash logger.sh stop"
            ;;
        *)
            error "Comando desconocido: $command"
            info "Usa 'bash logger.sh help' para ver ayuda"
            exit 1
            ;;
    esac
}

# Ejecutar función principal
main "$@"
