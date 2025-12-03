#!/bin/bash
#
# capture-evidence.sh - Script de Captura de Evidencias para PAI-5 RedTeamPro
# Captura screenshots, logs y tráfico de red automáticamente
# Autor: PAI-5 RedTeamPro Team
#

set -e

# Cargar funciones comunes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Contador global para numeración de evidencias
EVIDENCE_COUNTER_FILE="/tmp/pai5_evidence_counter"

# ============================================================================
# FUNCIONES DE EVIDENCIA
# ============================================================================

# Obtener siguiente número de evidencia
get_next_evidence_number() {
    if [ -f "$EVIDENCE_COUNTER_FILE" ]; then
        local counter=$(cat "$EVIDENCE_COUNTER_FILE")
    else
        local counter=0
    fi

    counter=$((counter + 1))
    echo "$counter" > "$EVIDENCE_COUNTER_FILE"

    printf "%03d" "$counter"
}

# Resetear contador de evidencias
reset_evidence_counter() {
    echo "0" > "$EVIDENCE_COUNTER_FILE"
    log "Contador de evidencias reseteado"
}

# Capturar screenshot con numeración automática
capture_screenshot_auto() {
    local phase="$1"
    local technique="$2"
    local description="$3"
    local attack_id="${4:-}"

    if [ -z "$phase" ] || [ -z "$technique" ] || [ -z "$description" ]; then
        error "Uso: capture_screenshot_auto <fase> <tecnica> <descripcion> [attack-id]"
        exit 1
    fi

    local number=$(get_next_evidence_number)
    local filename="${number}_${phase}_${technique}_${description}.png"
    local filepath="$SCREENSHOTS_DIR/$filename"

    ensure_dir "$SCREENSHOTS_DIR"

    info "Capturando screenshot: $filename"

    # Intentar captura con diferentes herramientas
    local captured=false

    if command_exists "scrot"; then
        if scrot "$filepath" 2>/dev/null; then
            captured=true
        fi
    elif command_exists "gnome-screenshot"; then
        if gnome-screenshot -f "$filepath" 2>/dev/null; then
            captured=true
        fi
    elif command_exists "import"; then  # ImageMagick
        if import -window root "$filepath" 2>/dev/null; then
            captured=true
        fi
    elif command_exists "maim"; then
        if maim "$filepath" 2>/dev/null; then
            captured=true
        fi
    fi

    if [ "$captured" = true ]; then
        log "Screenshot capturado: $filepath"

        # Crear metadata
        create_evidence_metadata "$filepath" "screenshot" "$phase" "$technique" "$description" "$attack_id"

        echo "$filepath"
        return 0
    else
        error "No se pudo capturar screenshot"
        warning "Instalar: apt-get install scrot (o gnome-screenshot, maim, imagemagick)"
        return 1
    fi
}

# Capturar screenshot de ventana específica
capture_window_screenshot() {
    local phase="$1"
    local technique="$2"
    local description="$3"

    local number=$(get_next_evidence_number)
    local filename="${number}_${phase}_${technique}_${description}.png"
    local filepath="$SCREENSHOTS_DIR/$filename"

    ensure_dir "$SCREENSHOTS_DIR"

    info "Capturando screenshot de ventana..."
    info "Haz clic en la ventana que deseas capturar..."

    if command_exists "scrot"; then
        scrot -s "$filepath" 2>/dev/null
        log "Screenshot de ventana capturado: $filepath"
        create_evidence_metadata "$filepath" "screenshot-window" "$phase" "$technique" "$description" ""
        echo "$filepath"
        return 0
    elif command_exists "gnome-screenshot"; then
        gnome-screenshot -w -f "$filepath" 2>/dev/null
        log "Screenshot de ventana capturado: $filepath"
        create_evidence_metadata "$filepath" "screenshot-window" "$phase" "$technique" "$description" ""
        echo "$filepath"
        return 0
    else
        error "No hay herramienta de captura disponible"
        return 1
    fi
}

# Iniciar captura de tráfico de red
start_network_capture() {
    local phase="$1"
    local description="$2"
    local interface="${3:-any}"

    if [ -z "$phase" ] || [ -z "$description" ]; then
        error "Uso: start_network_capture <fase> <descripcion> [interfaz]"
        exit 1
    fi

    local number=$(get_next_evidence_number)
    local filename="${number}_${phase}_${description}.pcap"
    local filepath="$NETWORK_CAPTURES_DIR/$filename"

    ensure_dir "$NETWORK_CAPTURES_DIR"

    if ! command_exists tcpdump; then
        error "tcpdump no está instalado"
        info "Instalar con: apt-get install tcpdump"
        return 1
    fi

    info "Iniciando captura de tráfico en interfaz $interface..."

    # Archivo PID para tracking
    local pid_file="/tmp/pai5_pcap_${phase}_${description}.pid"

    # Iniciar tcpdump en background
    sudo tcpdump -i "$interface" -w "$filepath" &> /dev/null &
    local pid=$!

    echo "$pid" > "$pid_file"
    echo "$filepath" > "/tmp/pai5_pcap_${phase}_${description}.file"

    log "Captura iniciada (PID: $pid): $filepath"
    info "Detener con: bash capture-evidence.sh --stop-capture $phase $description"

    # Crear metadata
    create_evidence_metadata "$filepath" "network-capture" "$phase" "network" "$description" ""

    echo "$filepath"
}

# Detener captura de tráfico de red
stop_network_capture() {
    local phase="$1"
    local description="$2"

    if [ -z "$phase" ] || [ -z "$description" ]; then
        error "Uso: stop_network_capture <fase> <descripcion>"
        exit 1
    fi

    local pid_file="/tmp/pai5_pcap_${phase}_${description}.pid"
    local file_path_file="/tmp/pai5_pcap_${phase}_${description}.file"

    if [ ! -f "$pid_file" ]; then
        error "No se encontró captura activa para: $phase/$description"
        return 1
    fi

    local pid=$(cat "$pid_file")
    local filepath=$(cat "$file_path_file" 2>/dev/null || echo "unknown")

    if ps -p "$pid" > /dev/null 2>&1; then
        sudo kill "$pid" 2>/dev/null
        log "Captura detenida (PID: $pid)"

        # Esperar a que el archivo se escriba completamente
        sleep 2

        if [ -f "$filepath" ]; then
            local filesize=$(stat -f%z "$filepath" 2>/dev/null || stat -c%s "$filepath" 2>/dev/null)
            log "Archivo guardado: $filepath (${filesize} bytes)"

            # Actualizar metadata con tamaño final
            update_evidence_metadata "$filepath" "size" "$filesize"
        fi

        # Limpiar archivos temporales
        rm "$pid_file" "$file_path_file" 2>/dev/null || true

        return 0
    else
        warning "El proceso de captura ya no está corriendo"
        rm "$pid_file" "$file_path_file" 2>/dev/null || true
        return 1
    fi
}

# Guardar log de comando con evidencia
save_command_log() {
    local phase="$1"
    local technique="$2"
    local command="$3"
    local output="$4"
    local attack_id="${5:-}"

    if [ -z "$phase" ] || [ -z "$technique" ] || [ -z "$command" ]; then
        error "Uso: save_command_log <fase> <tecnica> <comando> <output> [attack-id]"
        exit 1
    fi

    local number=$(get_next_evidence_number)
    local filename="${number}_${phase}_${technique}_command.log"
    local filepath="$LOG_DIR/$filename"

    ensure_dir "$LOG_DIR"

    {
        echo "# Command Log - PAI-5 RedTeamPro"
        echo "Number: $number"
        echo "Phase: $phase"
        echo "Technique: $technique"
        if [ -n "$attack_id" ]; then
            echo "MITRE ATT&CK: $attack_id"
        fi
        echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "User: $USER"
        echo ""
        echo "## Command Executed"
        echo "\`\`\`bash"
        echo "$command"
        echo "\`\`\`"
        echo ""
        echo "## Output"
        echo "\`\`\`"
        echo "$output"
        echo "\`\`\`"
    } > "$filepath"

    log "Log guardado: $filepath"

    # Crear metadata
    create_evidence_metadata "$filepath" "command-log" "$phase" "$technique" "command-execution" "$attack_id"

    echo "$filepath"
}

# Capturar HTTP request/response
capture_http_traffic() {
    local phase="$1"
    local description="$2"
    local request_file="$3"

    if [ -z "$phase" ] || [ -z "$description" ]; then
        error "Uso: capture_http_traffic <fase> <descripcion> [request-file]"
        exit 1
    fi

    local number=$(get_next_evidence_number)
    local filename="${number}_${phase}_${description}_http.txt"
    local filepath="$LOG_DIR/$filename"

    ensure_dir "$LOG_DIR"

    if [ -n "$request_file" ] && [ -f "$request_file" ]; then
        # Copiar archivo de request si se proporciona
        cp "$request_file" "$filepath"
        log "HTTP request/response guardado: $filepath"
    else
        info "Guarda manualmente el HTTP request/response en: $filepath"
        touch "$filepath"
    fi

    create_evidence_metadata "$filepath" "http-traffic" "$phase" "web" "$description" ""

    echo "$filepath"
}

# Crear metadata de evidencia
create_evidence_metadata() {
    local filepath="$1"
    local type="$2"
    local phase="$3"
    local technique="$4"
    local description="$5"
    local attack_id="$6"

    local metadata_file="${filepath}.meta.json"

    cat > "$metadata_file" <<EOF
{
  "file": "$(basename "$filepath")",
  "type": "$type",
  "phase": "$phase",
  "technique": "$technique",
  "description": "$description",
  "attack_id": "${attack_id:-N/A}",
  "timestamp": "$(date '+%Y-%m-%d %H:%M:%S')",
  "unix_timestamp": $(date +%s),
  "user": "$USER",
  "hostname": "$HOSTNAME",
  "full_path": "$filepath"
}
EOF

    log "Metadata creada: $metadata_file"
}

# Actualizar metadata existente
update_evidence_metadata() {
    local filepath="$1"
    local key="$2"
    local value="$3"

    local metadata_file="${filepath}.meta.json"

    if [ -f "$metadata_file" ] && command_exists jq; then
        jq --arg key "$key" --arg value "$value" '. + {($key): $value}' \
            "$metadata_file" > "${metadata_file}.tmp" && \
            mv "${metadata_file}.tmp" "$metadata_file"
    fi
}

# Listar todas las evidencias
list_evidences() {
    show_banner "Lista de Evidencias Capturadas"

    local total=0

    # Screenshots
    if [ -d "$SCREENSHOTS_DIR" ] && [ -n "$(ls -A "$SCREENSHOTS_DIR" 2>/dev/null | grep -v '\.meta\.json$')" ]; then
        echo -e "${CYAN}Screenshots:${NC}"
        echo ""
        for file in "$SCREENSHOTS_DIR"/*.png 2>/dev/null; do
            if [ -f "$file" ]; then
                total=$((total + 1))
                local basename=$(basename "$file")
                local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
                echo "  [$total] $basename ($(numfmt --to=iec-i --suffix=B $size 2>/dev/null || echo "$size bytes"))"

                # Mostrar metadata si existe
                if [ -f "${file}.meta.json" ] && command_exists jq; then
                    local phase=$(jq -r '.phase' "${file}.meta.json" 2>/dev/null)
                    local attack_id=$(jq -r '.attack_id' "${file}.meta.json" 2>/dev/null)
                    echo "      Fase: $phase | ATT&CK: $attack_id"
                fi
            fi
        done
        echo ""
    fi

    # Network captures
    if [ -d "$NETWORK_CAPTURES_DIR" ] && [ -n "$(ls -A "$NETWORK_CAPTURES_DIR" 2>/dev/null | grep -v '\.meta\.json$')" ]; then
        echo -e "${CYAN}Capturas de Red:${NC}"
        echo ""
        for file in "$NETWORK_CAPTURES_DIR"/*.pcap 2>/dev/null; do
            if [ -f "$file" ]; then
                total=$((total + 1))
                local basename=$(basename "$file")
                local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
                echo "  [$total] $basename ($(numfmt --to=iec-i --suffix=B $size 2>/dev/null || echo "$size bytes"))"
            fi
        done
        echo ""
    fi

    # Command logs
    if [ -d "$LOG_DIR" ]; then
        local log_count=$(find "$LOG_DIR" -name "*_command.log" 2>/dev/null | wc -l)
        if [ "$log_count" -gt 0 ]; then
            echo -e "${CYAN}Logs de Comandos:${NC}"
            echo "  Total: $log_count archivos"
            echo ""
        fi
    fi

    if [ $total -eq 0 ]; then
        info "No se han capturado evidencias aún"
    else
        log "Total de evidencias: $total"
    fi
}

# Ver detalles de una evidencia
show_evidence_details() {
    local evidence_file="$1"

    if [ ! -f "$evidence_file" ]; then
        error "Archivo no encontrado: $evidence_file"
        return 1
    fi

    local metadata_file="${evidence_file}.meta.json"

    show_banner "Detalles de Evidencia" "$(basename "$evidence_file")"

    if [ -f "$metadata_file" ]; then
        if command_exists jq; then
            jq '.' "$metadata_file"
        else
            cat "$metadata_file"
        fi
    else
        info "No hay metadata disponible para esta evidencia"
    fi

    echo ""
    echo "Archivo: $evidence_file"
    echo "Tamaño: $(stat -f%z "$evidence_file" 2>/dev/null || stat -c%s "$evidence_file" 2>/dev/null) bytes"
    echo "Última modificación: $(stat -f%Sm "$evidence_file" 2>/dev/null || stat -c%y "$evidence_file" 2>/dev/null)"
}

# Generar índice de evidencias
generate_evidence_index() {
    local output_file="$PROJECT_ROOT/06-Evidencias/INDICE-EVIDENCIAS.md"

    info "Generando índice de evidencias..."

    cat > "$output_file" <<EOF
# Índice de Evidencias - PAI-5 RedTeamPro

**Generado**: $(date '+%Y-%m-%d %H:%M:%S')

## Resumen

Este documento indexa todas las evidencias capturadas durante el pentesting.

EOF

    # Screenshots
    echo "## Screenshots" >> "$output_file"
    echo "" >> "$output_file"
    echo "| # | Archivo | Fase | Técnica | Descripción | ATT&CK |" >> "$output_file"
    echo "|---|---------|------|---------|-------------|--------|" >> "$output_file"

    local count=1
    for file in "$SCREENSHOTS_DIR"/*.png 2>/dev/null; do
        if [ -f "$file" ]; then
            local basename=$(basename "$file")
            local meta="${file}.meta.json"

            if [ -f "$meta" ] && command_exists jq; then
                local phase=$(jq -r '.phase' "$meta" 2>/dev/null || echo "N/A")
                local technique=$(jq -r '.technique' "$meta" 2>/dev/null || echo "N/A")
                local description=$(jq -r '.description' "$meta" 2>/dev/null || echo "N/A")
                local attack_id=$(jq -r '.attack_id' "$meta" 2>/dev/null || echo "N/A")

                echo "| $count | \`$basename\` | $phase | $technique | $description | $attack_id |" >> "$output_file"
            else
                echo "| $count | \`$basename\` | - | - | - | - |" >> "$output_file"
            fi

            count=$((count + 1))
        fi
    done

    echo "" >> "$output_file"

    # Network captures
    echo "## Capturas de Red" >> "$output_file"
    echo "" >> "$output_file"
    echo "| # | Archivo | Fase | Tamaño |" >> "$output_file"
    echo "|---|---------|------|--------|" >> "$output_file"

    count=1
    for file in "$NETWORK_CAPTURES_DIR"/*.pcap 2>/dev/null; do
        if [ -f "$file" ]; then
            local basename=$(basename "$file")
            local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            local meta="${file}.meta.json"

            if [ -f "$meta" ] && command_exists jq; then
                local phase=$(jq -r '.phase' "$meta" 2>/dev/null || echo "N/A")
            else
                local phase="N/A"
            fi

            echo "| $count | \`$basename\` | $phase | $size bytes |" >> "$output_file"
            count=$((count + 1))
        fi
    done

    echo "" >> "$output_file"
    echo "---" >> "$output_file"
    echo "*Índice generado automáticamente por capture-evidence.sh*" >> "$output_file"

    log "Índice generado: $output_file"
    echo "$output_file"
}

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

main() {
    local action="${1:-help}"
    shift || true

    case "$action" in
        --screenshot|-s)
            if [ $# -lt 3 ]; then
                error "Uso: --screenshot <fase> <tecnica> <descripcion> [attack-id]"
                exit 1
            fi
            capture_screenshot_auto "$@"
            ;;
        --window|-w)
            if [ $# -lt 3 ]; then
                error "Uso: --window <fase> <tecnica> <descripcion>"
                exit 1
            fi
            capture_window_screenshot "$@"
            ;;
        --start-capture|-sc)
            if [ $# -lt 2 ]; then
                error "Uso: --start-capture <fase> <descripcion> [interfaz]"
                exit 1
            fi
            start_network_capture "$@"
            ;;
        --stop-capture|-ec)
            if [ $# -lt 2 ]; then
                error "Uso: --stop-capture <fase> <descripcion>"
                exit 1
            fi
            stop_network_capture "$@"
            ;;
        --command-log|-cl)
            if [ $# -lt 3 ]; then
                error "Uso: --command-log <fase> <tecnica> <comando> <output> [attack-id]"
                exit 1
            fi
            save_command_log "$@"
            ;;
        --http|-h)
            if [ $# -lt 2 ]; then
                error "Uso: --http <fase> <descripcion> [request-file]"
                exit 1
            fi
            capture_http_traffic "$@"
            ;;
        --list|-l)
            list_evidences
            ;;
        --index|-i)
            generate_evidence_index
            ;;
        --reset-counter|-r)
            reset_evidence_counter
            ;;
        --details|-d)
            if [ $# -lt 1 ]; then
                error "Uso: --details <archivo>"
                exit 1
            fi
            show_evidence_details "$@"
            ;;
        help|--help)
            show_usage "capture-evidence.sh" \
                "Sistema de captura de evidencias para pentesting" \
                "bash capture-evidence.sh <accion> [opciones]" \
                "  ${GREEN}Capturar screenshot completo:${NC}
    bash capture-evidence.sh --screenshot recon nmap \"full-scan\" T1046

  ${GREEN}Capturar ventana específica:${NC}
    bash capture-evidence.sh --window exploit sqli \"database-dump\"

  ${GREEN}Iniciar captura de red:${NC}
    bash capture-evidence.sh --start-capture exploit sql-injection eth0

  ${GREEN}Detener captura de red:${NC}
    bash capture-evidence.sh --stop-capture exploit sql-injection

  ${GREEN}Guardar log de comando:${NC}
    bash capture-evidence.sh --command-log recon nmap \"nmap -sV\" \"\$output\" T1046

  ${GREEN}Listar evidencias:${NC}
    bash capture-evidence.sh --list

  ${GREEN}Generar índice:${NC}
    bash capture-evidence.sh --index

  ${GREEN}Reset contador:${NC}
    bash capture-evidence.sh --reset-counter"
            ;;
        *)
            error "Acción desconocida: $action"
            info "Usa 'bash capture-evidence.sh help' para ver ayuda"
            exit 1
            ;;
    esac
}

# Ejecutar función principal
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
