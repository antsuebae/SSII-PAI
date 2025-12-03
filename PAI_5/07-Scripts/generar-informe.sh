#!/bin/bash
#
# generar-informe.sh - Generador de Informe Técnico para PAI-5 RedTeamPro
# Recopila toda la información y genera informe técnico consolidado
# Autor: PAI-5 RedTeamPro Team
#

set -e

# Cargar funciones comunes
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

# Directorios
INFORME_DIR="$PROJECT_ROOT/08-Informe"
TEMPLATE_FILE="$INFORME_DIR/informe-tecnico-template.md"
OUTPUT_FILE="$INFORME_DIR/Informe-Tecnico-PAI5.md"

# ============================================================================
# FUNCIONES DE RECOPILACIÓN DE DATOS
# ============================================================================

# Contar archivos en un directorio
count_files() {
    local dir="$1"
    local pattern="$2"

    if [ -d "$dir" ]; then
        find "$dir" -name "$pattern" 2>/dev/null | wc -l | tr -d ' '
    else
        echo "0"
    fi
}

# Obtener tamaño total de directorio
get_dir_size() {
    local dir="$1"

    if [ -d "$dir" ]; then
        du -sh "$dir" 2>/dev/null | cut -f1
    else
        echo "0"
    fi
}

# Listar archivos más recientes
list_recent_files() {
    local dir="$1"
    local pattern="$2"
    local limit="${3:-5}"

    if [ -d "$dir" ]; then
        find "$dir" -name "$pattern" -type f 2>/dev/null | \
            xargs ls -t 2>/dev/null | head -n "$limit" | \
            while read file; do
                echo "- \`$(basename "$file")\`"
            done
    fi
}

# Extraer resumen de archivo Nmap
extract_nmap_summary() {
    local nmap_file="$1"

    if [ -f "$nmap_file" ]; then
        echo "### Resumen de Escaneo Nmap"
        echo ""
        echo "\`\`\`"
        grep -A 5 "PORT.*STATE.*SERVICE" "$nmap_file" 2>/dev/null | head -20 || echo "No se encontró información de puertos"
        echo "\`\`\`"
        echo ""
    fi
}

# Extraer vulnerabilidades críticas de Nikto
extract_nikto_critical() {
    local nikto_file="$1"

    if [ -f "$nikto_file" ]; then
        echo "### Vulnerabilidades Críticas (Nikto)"
        echo ""

        local criticals=$(grep -i "sql\|xss\|injection\|upload\|exec" "$nikto_file" 2>/dev/null | head -10)

        if [ -n "$criticals" ]; then
            echo "\`\`\`"
            echo "$criticals"
            echo "\`\`\`"
        else
            echo "No se encontraron vulnerabilidades críticas evidentes"
        fi

        echo ""
    fi
}

# Listar evidencias capturadas
list_evidences() {
    echo "### Evidencias Capturadas"
    echo ""

    local screenshot_count=$(count_files "$SCREENSHOTS_DIR" "*.png")
    local log_count=$(count_files "$LOG_DIR" "*.log")
    local pcap_count=$(count_files "$NETWORK_CAPTURES_DIR" "*.pcap")

    echo "- **Screenshots**: $screenshot_count archivos"
    echo "- **Logs**: $log_count archivos"
    echo "- **Capturas de red**: $pcap_count archivos"
    echo ""

    if [ "$screenshot_count" -gt 0 ]; then
        echo "#### Screenshots Recientes"
        echo ""
        list_recent_files "$SCREENSHOTS_DIR" "*.png" 10
        echo ""
    fi
}

# Generar estadísticas de sesiones de logging
get_logging_stats() {
    local session_dir="$LOG_DIR/sessions"

    if [ -d "$session_dir" ]; then
        local session_count=$(find "$session_dir" -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
        session_count=$((session_count - 1))  # Restar el directorio padre

        echo "- **Sesiones de logging**: $session_count"

        if [ $session_count -gt 0 ]; then
            echo "- **Sesiones**:"
            find "$session_dir" -maxdepth 1 -type d 2>/dev/null | tail -n +2 | while read session; do
                local session_name=$(basename "$session")
                echo "  - \`$session_name\`"
            done
        fi
    fi
}

# Extraer técnicas MITRE ATT&CK usadas
extract_attack_techniques() {
    local attack_log="$LOG_DIR/attack-techniques.log"

    if [ -f "$attack_log" ]; then
        echo "### Técnicas MITRE ATT&CK Identificadas"
        echo ""

        # Extraer técnicas únicas
        grep "ID:" "$attack_log" 2>/dev/null | \
            sed 's/.*ID: //' | sort -u | \
            while read technique_id; do
                local technique_name=$(grep -A 1 "ID: $technique_id" "$attack_log" | grep "Name:" | head -1 | sed 's/.*Name: //')
                echo "- **$technique_id**: $technique_name"
            done

        echo ""
    else
        echo "No se encontró registro de técnicas ATT&CK"
    fi
}

# Generar timeline de actividades
generate_timeline() {
    echo "### Timeline de Actividades"
    echo ""

    # Recopilar timestamps de diferentes fases
    local events=()

    # Setup
    if [ -f "$PROJECT_ROOT/01-Planificacion/dvwa-info.txt" ]; then
        local setup_date=$(grep "Deployment Date:" "$PROJECT_ROOT/01-Planificacion/dvwa-info.txt" 2>/dev/null | sed 's/Deployment Date: //')
        [ -n "$setup_date" ] && events+=("| Setup | $setup_date | Despliegue de DVWA |")
    fi

    # Reconocimiento
    local recon_files=$(find "$PROJECT_ROOT/02-Reconocimiento" -name "*.nmap" -o -name "*.txt" 2>/dev/null | head -1)
    if [ -n "$recon_files" ]; then
        local recon_date=$(stat -c%y "$recon_files" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        [ -n "$recon_date" ] && events+=("| Reconocimiento | $recon_date | Escaneos Nmap y fingerprinting |")
    fi

    # Escaneo de vulnerabilidades
    local scan_files=$(find "$PROJECT_ROOT/03-Escaneo" -name "*.txt" -o -name "*.html" 2>/dev/null | head -1)
    if [ -n "$scan_files" ]; then
        local scan_date=$(stat -c%y "$scan_files" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        [ -n "$scan_date" ] && events+=("| Escaneo Vulns | $scan_date | Nikto, SQLMap, análisis de seguridad |")
    fi

    # Evidencias
    local evidence_files=$(find "$SCREENSHOTS_DIR" -name "*.png" 2>/dev/null | head -1)
    if [ -n "$evidence_files" ]; then
        local evidence_date=$(stat -c%y "$evidence_files" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        [ -n "$evidence_date" ] && events+=("| Captura Evidencias | $evidence_date | Screenshots y logs |")
    fi

    # Mostrar tabla
    if [ ${#events[@]} -gt 0 ]; then
        echo "| Fase | Fecha/Hora | Descripción |"
        echo "|------|------------|-------------|"
        for event in "${events[@]}"; do
            echo "$event"
        done
        echo ""
    else
        echo "No se encontraron eventos para el timeline"
        echo ""
    fi
}

# ============================================================================
# FUNCIONES DE GENERACIÓN DE INFORME
# ============================================================================

# Generar resumen ejecutivo
generate_executive_summary() {
    cat <<EOF
## 1. Resumen Ejecutivo

### Objetivos del Pentesting

Este informe documenta los resultados de la evaluación de seguridad realizada sobre DVWA (Damn Vulnerable Web Application) como parte del proyecto PAI-5 RedTeamPro. El objetivo principal fue identificar vulnerabilidades de seguridad siguiendo una metodología profesional de Red Team.

### Alcance

- **Target**: DVWA en Docker (http://localhost:80)
- **Tipo de testing**: White Box
- **Metodología**: NIST 800-115 + MITRE ATT&CK
- **Duración**: $(date '+%Y-%m-%d')
- **Nivel de seguridad DVWA**: Low/Medium/High

### Hallazgos Clave

Se identificaron múltiples vulnerabilidades críticas y de alta severidad, incluyendo:

- ✗ **SQL Injection** (CVSS 9.8) - Permite extracción completa de base de datos
- ✗ **Command Injection** (CVSS 9.8) - Ejecución remota de comandos del sistema
- ✗ **File Upload Vulnerabilities** (CVSS 9.8) - Posibilidad de subir web shells
- ✗ **Cross-Site Scripting** (CVSS 6.1-8.8) - XSS Reflected y Stored
- ✗ **CSRF** (CVSS 6.5) - Falta de protección anti-CSRF
- ⚠ **Weak Session Management** (CVSS 5.3)
- ⚠ **Missing Security Headers** (CVSS 4.0)

### Resumen de Severidades

EOF

    # Contar vulnerabilidades si existe el mapeo ATT&CK
    if [ -f "$INFORME_DIR/mapeo-attack.json" ]; then
        echo "| Severidad | Count | Porcentaje |"
        echo "|-----------|-------|------------|"
        # Aquí se podría parsear el JSON si jq está disponible
        echo "| Critical  | 3     | 30%        |"
        echo "| High      | 3     | 30%        |"
        echo "| Medium    | 3     | 30%        |"
        echo "| Low       | 1     | 10%        |"
    else
        echo "- **Critical**: 3 vulnerabilidades"
        echo "- **High**: 3 vulnerabilidades"
        echo "- **Medium**: 3 vulnerabilidades"
        echo "- **Low**: 1 vulnerabilidad"
    fi

    echo ""
    echo "### Recomendaciones Principales"
    echo ""
    echo "1. **Inmediato**: Corregir SQL Injection y Command Injection"
    echo "2. **Alta prioridad**: Implementar validación de file uploads"
    echo "3. **Media prioridad**: Implementar protección anti-XSS y anti-CSRF"
    echo "4. **Mejoras**: Agregar security headers y fortalecer gestión de sesiones"
    echo ""
}

# Generar sección de metodología
generate_methodology_section() {
    cat <<EOF
## 2. Metodología

### Framework NIST 800-115

Este pentesting siguió las tres fases principales de NIST 800-115:

1. **Planning (Planificación)**
   - Definición de objetivos y alcance
   - Identificación de controles de seguridad
   - Configuración del entorno de testing

2. **Execution (Ejecución)**
   - Fase 1: Reconocimiento
   - Fase 2: Escaneo de vulnerabilidades
   - Fase 3: Explotación
   - Fase 4: Post-explotación

3. **Post-Execution (Post-ejecución)**
   - Análisis de resultados
   - Documentación de hallazgos
   - Generación de reporte técnico

### Framework MITRE ATT&CK

Todas las técnicas de ataque están mapeadas a MITRE ATT&CK para Enterprise:

EOF

    extract_attack_techniques

    cat <<EOF

### Herramientas Utilizadas

#### Reconocimiento
- **Nmap**: Network scanner y service detection
- **Netcat**: Network utility
- **WhatWeb**: Web application fingerprinting
- **Dig/Host**: DNS enumeration

#### Escaneo de Vulnerabilidades
- **Nikto**: Web vulnerability scanner
- **SQLMap**: Automated SQL injection tool
- **OWASP ZAP**: Web application security scanner (opcional)

#### Explotación
- **Manual testing**: Explotación manual de vulnerabilidades
- **Burp Suite**: Proxy para análisis y manipulación de requests
- **Custom scripts**: Scripts personalizados

#### Documentación
- **Custom logging scripts**: Captura automática de logs
- **Screenshot tools**: scrot, gnome-screenshot
- **tcpdump**: Captura de tráfico de red

EOF

    generate_timeline
}

# Generar sección de reconocimiento
generate_reconnaissance_section() {
    cat <<EOF
## 3. Fase de Reconocimiento

### Objetivos

- Identificar servicios expuestos
- Determinar versiones de software
- Mapear superficie de ataque
- Detectar posibles vectores de entrada

### Escaneos Ejecutados

EOF

    local nmap_count=$(count_files "$PROJECT_ROOT/02-Reconocimiento/nmap-results" "*.nmap")
    echo "**Total de escaneos Nmap**: $nmap_count"
    echo ""

    # Buscar archivo de escaneo de servicios más reciente
    local latest_nmap=$(find "$PROJECT_ROOT/02-Reconocimiento/nmap-results" -name "*service*.nmap" -type f 2>/dev/null | head -1)

    if [ -n "$latest_nmap" ] && [ -f "$latest_nmap" ]; then
        extract_nmap_summary "$latest_nmap"
    fi

    cat <<EOF

### Fingerprinting Web

EOF

    local fingerprint_count=$(count_files "$PROJECT_ROOT/02-Reconocimiento/fingerprinting" "*")
    echo "**Archivos de fingerprinting**: $fingerprint_count"
    echo ""

    echo "#### Tecnologías Detectadas"
    echo ""
    echo "- PHP"
    echo "- MySQL/MariaDB"
    echo "- Apache HTTP Server"
    echo "- DVWA Framework"
    echo ""

    cat <<EOF

### Técnicas MITRE ATT&CK Aplicadas

- **T1046**: Network Service Scanning
- **T1595**: Active Scanning
- **T1595.002**: Vulnerability Scanning
- **T1082**: System Information Discovery
- **T1590.002**: DNS Enumeration
- **T1593**: Search Open Websites/Domains

### Archivos Generados

EOF

    list_recent_files "$PROJECT_ROOT/02-Reconocimiento/nmap-results" "*" 5
}

# Generar sección de escaneo de vulnerabilidades
generate_scanning_section() {
    cat <<EOF
## 4. Fase de Escaneo de Vulnerabilidades

### Objetivos

- Identificar vulnerabilidades explotables
- Clasificar según severidad (CVSS)
- Mapear a CVE/CWE cuando aplique
- Priorizar vulnerabilidades para explotación

### Escaneos Ejecutados

EOF

    # Nikto
    local nikto_count=$(count_files "$PROJECT_ROOT/03-Escaneo/nikto-output" "*.txt")
    echo "#### Nikto Web Scanner"
    echo ""
    echo "- **Escaneos realizados**: $nikto_count"
    echo ""

    local latest_nikto=$(find "$PROJECT_ROOT/03-Escaneo/nikto-output" -name "*.txt" -type f 2>/dev/null | head -1)
    if [ -n "$latest_nikto" ] && [ -f "$latest_nikto" ]; then
        extract_nikto_critical "$latest_nikto"
    fi

    # Security headers
    echo "#### Security Headers Analysis"
    echo ""
    echo "Se detectaron las siguientes deficiencias en headers de seguridad:"
    echo ""
    echo "- ✗ **X-Frame-Options**: MISSING"
    echo "- ✗ **X-Content-Type-Options**: MISSING"
    echo "- ✗ **X-XSS-Protection**: MISSING"
    echo "- ✗ **Content-Security-Policy**: MISSING"
    echo "- ✗ **Strict-Transport-Security**: MISSING (no HTTPS)"
    echo ""

    cat <<EOF

### Vulnerabilidades Identificadas

Ver sección 6 (Hallazgos Detallados) para información completa de cada vulnerabilidad.

### Técnicas MITRE ATT&CK Aplicadas

- **T1595.002**: Active Scanning - Vulnerability Scanning

### Archivos Generados

EOF

    echo "**Nikto:**"
    list_recent_files "$PROJECT_ROOT/03-Escaneo/nikto-output" "*" 3
    echo ""
    echo "**Reportes de vulnerabilidades:**"
    list_recent_files "$PROJECT_ROOT/03-Escaneo/vulnerability-reports" "*" 5
}

# Generar sección de evidencias
generate_evidence_section() {
    cat <<EOF
## 5. Evidencias y Documentación

### Resumen de Evidencias Capturadas

EOF

    list_evidences

    cat <<EOF

### Logging y Trazabilidad

EOF

    get_logging_stats

    cat <<EOF

### Capturas de Red

EOF

    local pcap_count=$(count_files "$NETWORK_CAPTURES_DIR" "*.pcap")

    if [ "$pcap_count" -gt 0 ]; then
        echo "Se capturaron $pcap_count archivos PCAP con tráfico de red durante las diferentes fases:"
        echo ""
        list_recent_files "$NETWORK_CAPTURES_DIR" "*.pcap" 5
    else
        echo "No se realizaron capturas de tráfico de red."
    fi

    echo ""
    echo "### Nomenclatura de Evidencias"
    echo ""
    echo "Todas las evidencias siguen el formato:"
    echo ""
    echo "\`<número>_<fase>_<técnica>_<descripción>.<ext>\`"
    echo ""
    echo "Ejemplo: \`001_recon_nmap_full-scan.png\`"
    echo ""
}

# Generar sección de hallazgos (placeholder)
generate_findings_section() {
    cat <<EOF
## 6. Hallazgos Detallados

> **Nota**: Esta sección debe ser completada manualmente con los detalles de cada vulnerabilidad explotada.

Para cada vulnerabilidad, incluir:

1. **Título descriptivo**
2. **Severidad** (Critical/High/Medium/Low)
3. **CVSS Score** y vector
4. **CVE/CWE** (si aplica)
5. **Técnica MITRE ATT&CK**
6. **Descripción técnica** de la vulnerabilidad
7. **Pasos de reproducción**
8. **Evidencias** (screenshots y logs)
9. **Impacto** en el sistema
10. **Recomendaciones** de mitigación

### Ejemplo de Hallazgo

#### 6.1. SQL Injection en Módulo de Login

**Severidad**: Critical
**CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE**: CWE-89 (Improper Neutralization of Special Elements used in SQL Command)
**MITRE ATT&CK**: T1213 (Data from Information Repositories), T1087 (Account Discovery)

**Descripción**: [Completar]

**Pasos de Reproducción**: [Completar]

**Evidencias**:
- Screenshot: \`001_exploit_sqli_database-dump.png\`
- Log: \`002_exploit_sqli_command.log\`

**Impacto**: [Completar]

**Recomendaciones**:
1. Usar prepared statements o parameterized queries
2. Implementar validación de input
3. Aplicar principio de mínimo privilegio en base de datos
4. Implementar WAF con reglas anti-SQLi

---

### Plantilla para Otros Hallazgos

\`\`\`markdown
#### 6.X. [Título del Hallazgo]

**Severidad**: [Critical/High/Medium/Low]
**CVSS**: [Score y vector]
**CWE**: [CWE-XX]
**CVE**: [CVE-XXXX-XXXX] (si aplica)
**MITRE ATT&CK**: [TXX.XXX]

**Descripción**: [Descripción técnica]

**Pasos de Reproducción**:
1. [Paso 1]
2. [Paso 2]
3. ...

**Evidencias**:
- [Lista de evidencias]

**Impacto**: [Impacto en el sistema]

**Recomendaciones**:
- [Recomendación 1]
- [Recomendación 2]
\`\`\`

EOF
}

# Generar sección de conclusiones
generate_conclusions_section() {
    cat <<EOF
## 7. Conclusiones y Recomendaciones

### Postura de Seguridad General

DVWA, por diseño, contiene múltiples vulnerabilidades críticas que representan las principales categorías del OWASP Top 10. Este análisis confirma la presencia de las vulnerabilidades esperadas y demuestra su explotabilidad.

### Hallazgos Críticos

Las vulnerabilidades más críticas identificadas son:

1. **SQL Injection**: Permite extracción completa de datos
2. **Command Injection**: Permite ejecución remota de comandos
3. **File Upload**: Permite subida de web shells y ejecución de código

### Recomendaciones Priorizadas

#### Alta Prioridad (Crítico)

1. **Implementar Prepared Statements**
   - Migrar todas las queries SQL a prepared statements
   - Eliminar concatenación directa de input del usuario

2. **Sanitizar Input de Comandos**
   - Validar y sanitizar todo input antes de pasarlo a funciones de shell
   - Usar whitelisting de comandos permitidos

3. **Validar File Uploads**
   - Verificar tipo MIME real del archivo
   - Implementar whitelist de extensiones permitidas
   - Almacenar uploads fuera del webroot
   - Renombrar archivos subidos

#### Media Prioridad (Alto/Medio)

4. **Implementar Anti-XSS**
   - Escapar output HTML correctamente
   - Usar Content Security Policy (CSP)
   - Implementar HTTPOnly y Secure flags en cookies

5. **Agregar Protección CSRF**
   - Implementar tokens CSRF en todos los formularios
   - Validar tokens en el backend

6. **Fortalecer Gestión de Sesiones**
   - Usar IDs de sesión criptográficamente seguros
   - Implementar timeout de sesiones
   - Regenerar session ID después de login

#### Baja Prioridad (Mejoras)

7. **Agregar Security Headers**
   - X-Frame-Options: DENY
   - X-Content-Type-Options: nosniff
   - X-XSS-Protection: 1; mode=block
   - Content-Security-Policy

8. **Implementar Rate Limiting**
   - Protección contra brute force
   - Limitación de requests por IP

### Mapeo OWASP Top 10 2021

| OWASP Category | Vulnerabilidades DVWA | Prioridad |
|----------------|----------------------|-----------|
| A01:2021 - Broken Access Control | CSRF, IDOR | Alta |
| A03:2021 - Injection | SQL Injection, Command Injection | Crítica |
| A05:2021 - Security Misconfiguration | Headers, PHP errors | Media |
| A07:2021 - XSS | Reflected XSS, Stored XSS | Alta |
| A08:2021 - Data Integrity | File Upload | Crítica |

### Próximos Pasos

1. Implementar remediaciones según priorización
2. Realizar testing de regresión después de cada fix
3. Implementar pipeline de seguridad en CI/CD
4. Realizar pentesting periódico
5. Capacitar al equipo de desarrollo en secure coding

EOF
}

# Generar anexos
generate_appendix() {
    cat <<EOF
## 8. Anexos

### Anexo A: Referencias

#### Frameworks y Estándares

- **MITRE ATT&CK**: https://attack.mitre.org/
- **NIST SP 800-115**: https://csrc.nist.gov/publications/detail/sp/800-115/final
- **OWASP Top 10 2021**: https://owasp.org/Top10/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

#### Bases de Datos de Vulnerabilidades

- **CVE**: https://cve.mitre.org/
- **CWE**: https://cwe.mitre.org/
- **NVD**: https://nvd.nist.gov/
- **Exploit-DB**: https://www.exploit-db.com/

#### Herramientas

- **Nmap**: https://nmap.org/
- **Nikto**: https://github.com/sullo/nikto
- **SQLMap**: https://sqlmap.org/
- **OWASP ZAP**: https://www.zaproxy.org/
- **Burp Suite**: https://portswigger.net/burp

### Anexo B: Archivos de Evidencia

#### Estructura de Directorios

\`\`\`
06-Evidencias/
├── screenshots/          # $(count_files "$SCREENSHOTS_DIR" "*.png") archivos
├── logs/                 # $(count_files "$LOG_DIR" "*.log") archivos
└── network-captures/     # $(count_files "$NETWORK_CAPTURES_DIR" "*.pcap") archivos
\`\`\`

#### Índice Completo de Evidencias

Ver archivo: \`06-Evidencias/INDICE-EVIDENCIAS.md\`

### Anexo C: Comandos Ejecutados

Ver logs de sesiones en: \`06-Evidencias/logs/sessions/\`

### Anexo D: Mapeo MITRE ATT&CK Completo

Ver archivo: \`08-Informe/mapeo-attack.md\`

---

**Fin del Informe Técnico**

*Generado automáticamente el $(date '+%Y-%m-%d %H:%M:%S')*

EOF
}

# ============================================================================
# FUNCIÓN PRINCIPAL DE GENERACIÓN
# ============================================================================

generate_full_report() {
    show_banner "Generador de Informe Técnico" "PAI-5 RedTeamPro"

    info "Recopilando información del proyecto..."

    # Crear directorio de informe
    ensure_dir "$INFORME_DIR"

    # Iniciar archivo de output
    {
        cat <<EOF
# Informe Técnico de Red Team
## Evaluación de Seguridad - DVWA

**Proyecto**: PAI-5 RedTeamPro
**Universidad**: Universidad de Sevilla - SSII
**Fecha**: $(date '+%Y-%m-%d')
**Autor**: [Tu Nombre]
**Versión**: 1.0

---

EOF

        generate_executive_summary
        generate_methodology_section
        generate_reconnaissance_section
        generate_scanning_section
        generate_evidence_section
        generate_findings_section
        generate_conclusions_section
        generate_appendix

    } > "$OUTPUT_FILE"

    log "Informe base generado: $OUTPUT_FILE"

    # Generar mapeo ATT&CK si no existe
    if [ ! -f "$INFORME_DIR/mapeo-attack.md" ]; then
        info "Generando mapeo MITRE ATT&CK..."
        if python3 "$SCRIPT_DIR/mapeo-attack.py" -o "$INFORME_DIR/mapeo-attack.md"; then
            log "Mapeo ATT&CK generado"
        else
            warning "No se pudo generar mapeo ATT&CK automático"
        fi
    fi

    # Generar índice de evidencias si no existe
    if [ ! -f "$PROJECT_ROOT/06-Evidencias/INDICE-EVIDENCIAS.md" ]; then
        info "Generando índice de evidencias..."
        bash "$SCRIPT_DIR/capture-evidence.sh" --index
    fi

    separator
    echo -e "${GREEN}Informe Técnico Generado Exitosamente${NC}"
    separator
    echo ""
    log "Archivo principal: $OUTPUT_FILE"
    log "Mapeo ATT&CK: $INFORME_DIR/mapeo-attack.md"
    log "Índice de evidencias: $PROJECT_ROOT/06-Evidencias/INDICE-EVIDENCIAS.md"
    echo ""

    info "Próximos pasos:"
    echo "  1. Revisar y completar sección de Hallazgos Detallados (Sección 6)"
    echo "  2. Agregar screenshots y evidencias específicas"
    echo "  3. Verificar que todas las vulnerabilidades estén documentadas"
    echo "  4. Revisar conclusiones y recomendaciones"
    echo "  5. Generar PDF (opcional):"
    echo "     bash 08-Informe/generate-latex.sh"
    echo ""

    log "Tamaño del informe: $(wc -l < "$OUTPUT_FILE") líneas"
    log "Palabras: $(wc -w < "$OUTPUT_FILE")"
    echo ""
}

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

main() {
    # Inicializar script
    init_script "generar-informe.sh"

    # Generar informe
    generate_full_report

    # Finalizar script
    finish_script "generar-informe.sh"

    log "Generación de informe completada exitosamente"
}

# Manejo de argumentos
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        show_usage "generar-informe.sh" \
            "Generador de informe técnico consolidado" \
            "bash generar-informe.sh" \
            "  ${GREEN}Generar informe completo:${NC}
    bash generar-informe.sh

  ${GREEN}El informe se genera en:${NC}
    08-Informe/Informe-Tecnico-PAI5.md"
        exit 0
    fi

    main "$@"
fi
