#!/bin/bash
#
# reconocimiento.sh - Script de Reconocimiento Automatizado para PAI-5 RedTeamPro
# Ejecuta múltiples tipos de escaneos y fingerprinting
# MITRE ATT&CK: T1046 (Network Service Scanning), T1595 (Active Scanning)
# Autor: PAI-5 RedTeamPro Team
#

set -e

# Cargar funciones comunes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Directorios de salida
RECON_DIR="$PROJECT_ROOT/02-Reconocimiento"
NMAP_DIR="$RECON_DIR/nmap-results"
FINGERPRINT_DIR="$RECON_DIR/fingerprinting"

# ============================================================================
# FUNCIONES DE RECONOCIMIENTO
# ============================================================================

# Escaneo rápido de puertos (Top 1000)
nmap_quick_scan() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1046" "Network Service Scanning" "Quick port scan on top 1000 ports"

    info "Ejecutando escaneo rápido de puertos (Top 1000)..."

    local cmd="nmap -T4 -F $target -oA $output_file"
    log_command "$cmd"

    if eval "$cmd"; then
        log "Escaneo rápido completado: ${output_file}.nmap"
        return 0
    else
        error "Falló el escaneo rápido"
        return 1
    fi
}

# Escaneo completo de puertos
nmap_full_scan() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1046" "Network Service Scanning" "Full TCP port scan"

    info "Ejecutando escaneo completo de todos los puertos..."
    warning "Esto puede tomar varios minutos..."

    local cmd="nmap -p- -T4 $target -oA $output_file"
    log_command "$cmd"

    if eval "$cmd"; then
        log "Escaneo completo finalizado: ${output_file}.nmap"
        return 0
    else
        error "Falló el escaneo completo"
        return 1
    fi
}

# Escaneo de servicios y versiones
nmap_service_scan() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1046" "Network Service Scanning" "Service and version detection"

    info "Detectando servicios y versiones..."

    local cmd="nmap -sV -sC -T4 $target -oA $output_file"
    log_command "$cmd"

    if eval "$cmd"; then
        log "Detección de servicios completada: ${output_file}.nmap"
        return 0
    else
        error "Falló la detección de servicios"
        return 1
    fi
}

# Detección de sistema operativo
nmap_os_detection() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1082" "System Information Discovery" "OS detection"

    info "Detectando sistema operativo..."
    warning "Requiere privilegios de root/sudo"

    local cmd="sudo nmap -O -T4 $target -oA $output_file"
    log_command "$cmd"

    if eval "$cmd" 2>/dev/null; then
        log "Detección de OS completada: ${output_file}.nmap"
        return 0
    else
        warning "Falló la detección de OS (puede requerir sudo)"
        return 1
    fi
}

# Escaneo de vulnerabilidades con scripts NSE
nmap_vuln_scan() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1595" "Active Scanning" "Vulnerability scanning with NSE scripts"

    info "Ejecutando escaneo de vulnerabilidades con NSE scripts..."

    local cmd="nmap --script vuln -T4 $target -oA $output_file"
    log_command "$cmd"

    if eval "$cmd"; then
        log "Escaneo de vulnerabilidades completado: ${output_file}.nmap"
        return 0
    else
        error "Falló el escaneo de vulnerabilidades"
        return 1
    fi
}

# Escaneo UDP de puertos comunes
nmap_udp_scan() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1046" "Network Service Scanning" "UDP port scan"

    info "Ejecutando escaneo UDP de puertos comunes..."
    warning "Escaneo UDP puede ser lento..."

    local cmd="sudo nmap -sU --top-ports 100 -T4 $target -oA $output_file"
    log_command "$cmd"

    if eval "$cmd" 2>/dev/null; then
        log "Escaneo UDP completado: ${output_file}.nmap"
        return 0
    else
        warning "Falló el escaneo UDP (puede requerir sudo)"
        return 1
    fi
}

# Fingerprinting de aplicación web
web_fingerprinting() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595.002" "Active Scanning: Vulnerability Scanning" "Web application fingerprinting"

    info "Ejecutando fingerprinting de aplicación web..."

    # whatweb
    if command_exists whatweb; then
        info "Usando whatweb..."
        local cmd="whatweb -v $url"
        log_command "$cmd"
        eval "$cmd" | tee "${output_file}_whatweb.txt"
        log "Whatweb completado: ${output_file}_whatweb.txt"
    else
        warning "whatweb no disponible"
    fi

    # curl para headers
    info "Obteniendo headers HTTP..."
    local cmd="curl -I $url"
    log_command "$cmd"
    eval "$cmd" > "${output_file}_headers.txt" 2>&1 || true
    log "Headers guardados: ${output_file}_headers.txt"

    # Robots.txt
    info "Verificando robots.txt..."
    local robots_url="${url}/robots.txt"
    curl -s "$robots_url" > "${output_file}_robots.txt" 2>&1 || true
    if [ -s "${output_file}_robots.txt" ]; then
        log "robots.txt encontrado: ${output_file}_robots.txt"
    else
        info "No se encontró robots.txt"
        rm "${output_file}_robots.txt" 2>/dev/null || true
    fi
}

# Enumeración de tecnologías web
enumerate_technologies() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1593" "Search Open Websites/Domains" "Technology enumeration"

    info "Enumerando tecnologías web..."

    # Wappalyzer CLI (si está disponible)
    if command_exists wappalyzer; then
        local cmd="wappalyzer $url"
        log_command "$cmd"
        eval "$cmd" > "${output_file}_technologies.json" 2>&1 || true
        log "Tecnologías detectadas: ${output_file}_technologies.json"
    fi

    # Nikto básico para detección
    if command_exists nikto; then
        info "Ejecutando detección básica con Nikto..."
        local cmd="nikto -h $url -maxtime 60s"
        log_command "$cmd"
        eval "$cmd" > "${output_file}_nikto.txt" 2>&1 || true
        log "Nikto básico completado: ${output_file}_nikto.txt"
    fi
}

# Detección de WAF/IDS/IPS
detect_waf() {
    local url="$1"
    local output_file="$2"

    log_attack_technique "T1595" "Active Scanning" "WAF/IDS/IPS detection"

    info "Detectando WAF/IDS/IPS..."

    # wafw00f
    if command_exists wafw00f; then
        local cmd="wafw00f $url"
        log_command "$cmd"
        eval "$cmd" | tee "${output_file}_waf.txt"
        log "Detección de WAF completada: ${output_file}_waf.txt"
    else
        warning "wafw00f no disponible (instalar con: pip install wafw00f)"

        # Detección manual básica con curl
        info "Intentando detección manual de WAF..."
        local test_url="${url}/?id=1%27%20OR%201=1"
        curl -I "$test_url" > "${output_file}_waf_manual.txt" 2>&1 || true
        log "Test manual de WAF guardado: ${output_file}_waf_manual.txt"
    fi
}

# DNS enumeration
dns_enumeration() {
    local target="$1"
    local output_file="$2"

    log_attack_technique "T1590.002" "Gather Victim Network Information: DNS" "DNS enumeration"

    info "Ejecutando enumeración DNS..."

    # host command
    if command_exists host; then
        info "Resolviendo nombre con host..."
        host "$target" | tee "${output_file}_host.txt"
    fi

    # dig command
    if command_exists dig; then
        info "Consultas DNS con dig..."
        {
            echo "=== A Records ==="
            dig "$target" A +short
            echo ""
            echo "=== MX Records ==="
            dig "$target" MX +short
            echo ""
            echo "=== TXT Records ==="
            dig "$target" TXT +short
            echo ""
            echo "=== NS Records ==="
            dig "$target" NS +short
        } > "${output_file}_dig.txt"
        log "Enumeración DNS completada: ${output_file}_dig.txt"
    fi

    # nslookup
    if command_exists nslookup; then
        nslookup "$target" > "${output_file}_nslookup.txt" 2>&1 || true
    fi
}

# SSL/TLS enumeration
ssl_enumeration() {
    local target="$1"
    local port="${2:-443}"
    local output_file="$3"

    log_attack_technique "T1595" "Active Scanning" "SSL/TLS enumeration"

    info "Ejecutando enumeración SSL/TLS..."

    # testssl.sh si está disponible
    if command_exists testssl.sh || command_exists testssl; then
        local testssl_cmd=$(command -v testssl.sh || command -v testssl)
        local cmd="$testssl_cmd --fast $target:$port"
        log_command "$cmd"
        eval "$cmd" > "${output_file}_ssl.txt" 2>&1 || true
        log "Análisis SSL/TLS completado: ${output_file}_ssl.txt"
    elif command_exists sslscan; then
        local cmd="sslscan $target:$port"
        log_command "$cmd"
        eval "$cmd" | tee "${output_file}_sslscan.txt"
        log "SSLScan completado: ${output_file}_sslscan.txt"
    else
        # OpenSSL básico
        info "Usando openssl para info básica..."
        echo | openssl s_client -connect "$target:$port" 2>/dev/null | \
            openssl x509 -noout -text > "${output_file}_openssl.txt" 2>&1 || true
        log "Info SSL básica guardada: ${output_file}_openssl.txt"
    fi
}

# Generar resumen de reconocimiento
generate_recon_summary() {
    local target="$1"
    local timestamp="$2"
    local summary_file="$RECON_DIR/reconocimiento-summary-${timestamp}.md"

    info "Generando resumen de reconocimiento..."

    cat > "$summary_file" <<EOF
# Resumen de Reconocimiento - PAI-5 RedTeamPro

**Target**: $target
**Fecha**: $(date '+%Y-%m-%d %H:%M:%S')
**Timestamp**: $timestamp

## Escaneos Ejecutados

### 1. Escaneo de Puertos (Nmap)
- Escaneo rápido (Top 1000 puertos)
- Escaneo completo (todos los puertos)
- Detección de servicios y versiones
- Detección de sistema operativo
- Escaneo de vulnerabilidades con NSE
- Escaneo UDP

### 2. Fingerprinting Web
- WhatWeb
- Headers HTTP
- Robots.txt
- Tecnologías detectadas

### 3. Enumeración DNS
- Resolución de nombres
- Registros A, MX, TXT, NS

### 4. Detección de Seguridad
- WAF/IDS/IPS detection
- SSL/TLS enumeration

## Archivos Generados

\`\`\`
02-Reconocimiento/
├── nmap-results/
│   ├── nmap-quick-${timestamp}.*
│   ├── nmap-full-${timestamp}.*
│   ├── nmap-service-${timestamp}.*
│   ├── nmap-os-${timestamp}.*
│   ├── nmap-vuln-${timestamp}.*
│   └── nmap-udp-${timestamp}.*
└── fingerprinting/
    ├── fingerprint-${timestamp}_*
    └── [varios archivos de enumeración]
\`\`\`

## Técnicas MITRE ATT&CK Aplicadas

- **T1046**: Network Service Scanning
- **T1595**: Active Scanning
- **T1595.002**: Vulnerability Scanning
- **T1082**: System Information Discovery
- **T1590.002**: Gather Victim Network Information: DNS
- **T1593**: Search Open Websites/Domains

## Próximos Pasos

1. Revisar resultados de nmap para identificar servicios expuestos
2. Analizar versiones de software para buscar CVEs conocidos
3. Proceder con fase de Escaneo de Vulnerabilidades (03-Escaneo/)
4. Ejecutar: \`bash 07-Scripts/escaneo-vulnerabilidades.sh $target\`

## Referencias

- NIST 800-115: Section 7.1 - Network Discovery
- MITRE ATT&CK: Reconnaissance & Discovery tactics
- OWASP Testing Guide: Information Gathering

---

*Generado automáticamente por reconocimiento.sh*
EOF

    log "Resumen generado: $summary_file"
    echo "$summary_file"
}

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

main() {
    local target="$1"

    # Inicializar script
    init_script "reconocimiento.sh"

    # Banner
    show_banner "Reconocimiento Automatizado" "MITRE ATT&CK: T1046, T1595"

    # Validar target
    if [ -z "$target" ]; then
        target=$(get_target "")
    fi

    if ! validate_url "$target" && ! validate_ip "$target"; then
        error "Target inválido: $target"
        info "Uso: bash reconocimiento.sh <target-url-or-ip>"
        info "Ejemplo: bash reconocimiento.sh http://localhost:80"
        exit 1
    fi

    log "Target: $target"

    # Verificar conectividad
    if ! check_connectivity "$target"; then
        error "No se puede conectar al target. Verifica que esté accesible."
        exit 1
    fi

    # Verificar herramientas necesarias
    info "Verificando herramientas necesarias..."
    local required_tools=("nmap" "curl")
    if ! check_tools "${required_tools[@]}"; then
        error "Faltan herramientas requeridas"
        exit 1
    fi

    # Herramientas opcionales
    local optional_tools=("whatweb" "nikto" "wafw00f" "dig" "host" "sslscan")
    for tool in "${optional_tools[@]}"; do
        check_tool "$tool" "apt-get install $tool" || true
    done

    # Crear directorios
    ensure_dir "$NMAP_DIR"
    ensure_dir "$FINGERPRINT_DIR"

    # Timestamp para nombres de archivo
    local timestamp=$(date '+%Y%m%d_%H%M%S')

    # Extraer host para nmap
    local host=$(extract_host "$target")
    log "Host extraído: $host"

    separator
    echo -e "${CYAN}Iniciando Fase de Reconocimiento${NC}"
    separator
    echo ""

    # ========== ESCANEOS NMAP ==========
    progress "Fase 1/4: Escaneos Nmap"
    echo ""

    # Escaneo rápido
    nmap_quick_scan "$host" "$NMAP_DIR/nmap-quick-${timestamp}" || true
    echo ""

    # Escaneo de servicios
    nmap_service_scan "$host" "$NMAP_DIR/nmap-service-${timestamp}" || true
    echo ""

    # Escaneo de vulnerabilidades
    nmap_vuln_scan "$host" "$NMAP_DIR/nmap-vuln-${timestamp}" || true
    echo ""

    # Escaneo completo (opcional, puede ser lento)
    read -p "¿Ejecutar escaneo completo de todos los puertos? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        nmap_full_scan "$host" "$NMAP_DIR/nmap-full-${timestamp}" || true
        echo ""
    fi

    # Detección de OS
    read -p "¿Ejecutar detección de OS? (requiere sudo) (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        nmap_os_detection "$host" "$NMAP_DIR/nmap-os-${timestamp}" || true
        echo ""
    fi

    # Escaneo UDP
    read -p "¿Ejecutar escaneo UDP? (puede ser lento, requiere sudo) (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        nmap_udp_scan "$host" "$NMAP_DIR/nmap-udp-${timestamp}" || true
        echo ""
    fi

    # ========== FINGERPRINTING WEB ==========
    progress "Fase 2/4: Fingerprinting Web"
    echo ""

    web_fingerprinting "$target" "$FINGERPRINT_DIR/fingerprint-${timestamp}" || true
    echo ""

    enumerate_technologies "$target" "$FINGERPRINT_DIR/fingerprint-${timestamp}" || true
    echo ""

    # ========== DETECCIÓN DE SEGURIDAD ==========
    progress "Fase 3/4: Detección de Seguridad"
    echo ""

    detect_waf "$target" "$FINGERPRINT_DIR/fingerprint-${timestamp}" || true
    echo ""

    # SSL/TLS si es HTTPS
    if [[ "$target" =~ ^https:// ]]; then
        ssl_enumeration "$host" "443" "$FINGERPRINT_DIR/fingerprint-${timestamp}" || true
        echo ""
    fi

    # ========== ENUMERACIÓN DNS ==========
    progress "Fase 4/4: Enumeración DNS"
    echo ""

    dns_enumeration "$host" "$FINGERPRINT_DIR/dns-${timestamp}" || true
    echo ""

    # ========== RESUMEN ==========
    separator
    echo -e "${CYAN}Reconocimiento Completado${NC}"
    separator
    echo ""

    # Generar resumen
    local summary_file=$(generate_recon_summary "$target" "$timestamp")

    log "Todos los resultados guardados en:"
    echo "  - Nmap: $NMAP_DIR/"
    echo "  - Fingerprinting: $FINGERPRINT_DIR/"
    echo "  - Resumen: $summary_file"
    echo ""

    info "Próximos pasos:"
    echo "  1. Revisar resultados de escaneos"
    echo "  2. Identificar servicios y versiones vulnerables"
    echo "  3. Ejecutar fase de escaneo de vulnerabilidades:"
    echo "     bash 07-Scripts/escaneo-vulnerabilidades.sh $target"
    echo ""

    # Finalizar script
    finish_script "reconocimiento.sh"

    log "Reconocimiento finalizado exitosamente"
}

# Manejo de argumentos
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        show_usage "reconocimiento.sh" \
            "Script de reconocimiento automatizado - MITRE ATT&CK: T1046, T1595" \
            "bash reconocimiento.sh <target-url-or-ip>" \
            "  ${GREEN}Escanear DVWA local:${NC}
    bash reconocimiento.sh http://localhost:80

  ${GREEN}Escanear por IP:${NC}
    bash reconocimiento.sh 192.168.1.100

  ${GREEN}Con logging automático:${NC}
    bash logger.sh start reconocimiento
    bash reconocimiento.sh http://localhost:80"
        exit 0
    fi

    main "$@"
fi
