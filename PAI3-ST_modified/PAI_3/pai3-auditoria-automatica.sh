#!/bin/bash
################################################################################
# PAI-3 VULNAWEB - Script de Auditoría Automatizada
# Security Team INSEGUS
#
# Este script automatiza completamente la auditoría de seguridad:
# 1. Verifica requisitos del sistema
# 2. Ejecuta auditoría inicial con Lynis
# 3. Aplica hardening del sistema
# 4. Ejecuta auditoría final con Lynis
# 5. Realiza pruebas de vulnerabilidades web (SQL, XSS, Path Traversal)
# 6. Genera reportes consolidados
#
# Uso: sudo ./pai3-auditoria-automatica.sh
################################################################################

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Configuración
OUTPUT_DIR="$(pwd)/resultados-auditoria-$(date +%Y%m%d_%H%M%S)"
MUTILLIDAE_URL="http://localhost/mutillidae"
BACKUP_DIR="${OUTPUT_DIR}/backups"

# Funciones de logging
log_info() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() {
    echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD} $1${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}\n"
}

# Banner
clear
echo -e "${CYAN}${BOLD}"
cat << 'EOF'
╔═══════════════════════════════════════════════════════════╗
║   PAI-3 VULNAWEB - AUDITORÍA AUTOMATIZADA                ║
║   Security Team INSEGUS                                   ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}\n"

# Verificar root
if [[ $EUID -ne 0 ]]; then
    log_error "Este script debe ejecutarse como root (sudo)"
    exit 1
fi

# Crear directorios
mkdir -p "$OUTPUT_DIR"/{logs,configs,payloads}
mkdir -p "$BACKUP_DIR"

################################################################################
# FASE 1: VERIFICACIÓN DE REQUISITOS
################################################################################

log_step "FASE 1: VERIFICACIÓN DE REQUISITOS"

# Verificar herramientas esenciales
for tool in lynis ufw curl; do
    if ! command -v "$tool" &> /dev/null; then
        log_warning "$tool no está instalado, instalando..."
        apt-get update -qq && apt-get install -y "$tool" >/dev/null 2>&1
    fi
    log_info "$tool disponible"
done

log_info "Todos los requisitos cumplidos"
sleep 2

################################################################################
# FASE 2: AUDITORÍA INICIAL CON LYNIS
################################################################################

log_step "FASE 2: AUDITORÍA INICIAL DEL SISTEMA"

log_info "Ejecutando Lynis audit system..."
lynis audit system -Q --no-colors > "${OUTPUT_DIR}/logs/lynis-inicial.log" 2>&1 || true

hardening_inicial=$(grep "Hardening index" "${OUTPUT_DIR}/logs/lynis-inicial.log" | grep -oP '\d+' | head -1 || echo "0")
echo "$hardening_inicial" > "${OUTPUT_DIR}/hardening-inicial.txt"

log_info "Hardening Index Inicial: ${hardening_inicial}/100"
sleep 2

################################################################################
# FASE 3: HARDENING DEL SISTEMA
################################################################################

log_step "FASE 3: APLICANDO HARDENING AL SISTEMA"

echo -e "${YELLOW}Este proceso aplicará mejoras de seguridad al sistema.${NC}"
echo -e "${YELLOW}Se crearán backups automáticos en: ${BACKUP_DIR}${NC}\n"
sleep 3

# 1. Políticas de contraseñas
log_info "1/8 Configurando políticas de contraseñas..."
apt-get install -y libpam-pwquality >/dev/null 2>&1
cp /etc/pam.d/common-password "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null || true

if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/common-password
fi

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# 2. Umask restrictivo
log_info "2/8 Configurando umask restrictivo..."
cp /etc/profile "$BACKUP_DIR/" 2>/dev/null || true
if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs

# 3. Firewall UFW
log_info "3/8 Configurando firewall UFW..."
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow 443/tcp comment 'HTTPS' >/dev/null 2>&1
ufw allow 80/tcp comment 'HTTP' >/dev/null 2>&1
ufw allow 22/tcp comment 'SSH' >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# 4. Deshabilitar módulos
log_info "4/8 Deshabilitando módulos innecesarios..."
if ! grep -q "blacklist usb-storage" /etc/modprobe.d/blacklist.conf 2>/dev/null; then
    echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
    echo "blacklist firewire-core" >> /etc/modprobe.d/blacklist.conf
fi

# 5. Banners legales
log_info "5/8 Configurando banners legales..."
cp /etc/issue "$BACKUP_DIR/" 2>/dev/null || true
cat > /etc/issue << 'EOF'
***************************************************************************
ADVERTENCIA: Acceso autorizado únicamente.
Todas las actividades son monitoreadas y registradas.
***************************************************************************
EOF
cp /etc/issue /etc/issue.net

# 6. Actualizaciones automáticas
log_info "6/8 Configurando actualizaciones automáticas..."
apt-get install -y unattended-upgrades >/dev/null 2>&1
dpkg-reconfigure -plow unattended-upgrades >/dev/null 2>&1

# 7. Kernel hardening
log_info "7/8 Aplicando kernel hardening..."
cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
cat >> /etc/sysctl.conf << 'EOF'

# PAI-3 Security Hardening
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
EOF
sysctl -p >/dev/null 2>&1

# 8. Fail2ban
log_info "8/8 Configurando fail2ban..."
apt-get install -y fail2ban >/dev/null 2>&1
systemctl enable fail2ban >/dev/null 2>&1
systemctl start fail2ban >/dev/null 2>&1

# Guardar configuraciones aplicadas
ufw status verbose > "${OUTPUT_DIR}/configs/ufw-rules.txt"
cp /etc/login.defs "${OUTPUT_DIR}/configs/"
cp /etc/pam.d/common-password "${OUTPUT_DIR}/configs/"

log_info "Hardening completado exitosamente"
sleep 2

################################################################################
# FASE 4: AUDITORÍA FINAL CON LYNIS
################################################################################

log_step "FASE 4: AUDITORÍA FINAL DEL SISTEMA"

log_info "Ejecutando Lynis audit system..."
lynis audit system -Q --no-colors > "${OUTPUT_DIR}/logs/lynis-final.log" 2>&1 || true

hardening_final=$(grep "Hardening index" "${OUTPUT_DIR}/logs/lynis-final.log" | grep -oP '\d+' | head -1 || echo "0")
echo "$hardening_final" > "${OUTPUT_DIR}/hardening-final.txt"

mejora=$((hardening_final - hardening_inicial))

echo -e "\n${CYAN}═══════════════════════════════════════════${NC}"
echo -e "${CYAN}    COMPARACIÓN DE HARDENING INDEX${NC}"
echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo -e "${YELLOW}Inicial:${NC}  ${hardening_inicial}/100"
echo -e "${GREEN}Final:${NC}    ${hardening_final}/100"
echo -e "${GREEN}Mejora:${NC}   +${mejora} puntos"

if [ $hardening_final -ge 69 ]; then
    echo -e "${GREEN}${BOLD}✓ OBJETIVO ALCANZADO (≥69)${NC}"
else
    echo -e "${YELLOW}⚠ Objetivo no alcanzado (objetivo: ≥69)${NC}"
fi
echo -e "${CYAN}═══════════════════════════════════════════${NC}\n"

sleep 3

################################################################################
# FASE 5: PRUEBAS DE VULNERABILIDADES WEB
################################################################################

log_step "FASE 5: PRUEBAS DE VULNERABILIDADES WEB"

# Verificar Mutillidae
if ! curl -s "$MUTILLIDAE_URL" > /dev/null 2>&1; then
    log_warning "Mutillidae II no accesible en $MUTILLIDAE_URL"
    log_warning "Saltando pruebas web..."
else
    log_info "Mutillidae II accesible, ejecutando pruebas..."
    
    # Pruebas de SQL Injection
    log_info "Probando SQL Injection..."
    
    payloads_sql=(
        "' OR '1'='1"
        "' OR '1'='1'--"
        "admin'--"
        "' UNION SELECT NULL--"
    )
    
    vuln_sql=0
    for payload in "${payloads_sql[@]}"; do
        response=$(curl -s -X POST "${MUTILLIDAE_URL}/index.php?page=login.php" \
            -d "username=${payload}&password=${payload}&login-php-submit-button=Login" \
            -w "%{http_code}" -o /dev/null 2>/dev/null)
        
        if [ "$response" = "302" ] || [ "$response" = "200" ]; then
            echo "$payload" >> "${OUTPUT_DIR}/payloads/sql-injection-exitosos.txt"
            vuln_sql=$((vuln_sql + 1))
        fi
    done
    
    printf '%s\n' "${payloads_sql[@]}" > "${OUTPUT_DIR}/payloads/sql-injection-todos.txt"
    log_info "SQL Injection: $vuln_sql vulnerabilidades detectadas"
    
    # Pruebas de XSS
    log_info "Probando Cross-Site Scripting (XSS)..."
    
    payloads_xss=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "<svg/onload=alert('XSS')>"
    )
    
    vuln_xss=0
    for payload in "${payloads_xss[@]}"; do
        response=$(curl -s "${MUTILLIDAE_URL}/index.php?page=dns-lookup.php&target_host=${payload}")
        if echo "$response" | grep -q "<script>"; then
            echo "$payload" >> "${OUTPUT_DIR}/payloads/xss-exitosos.txt"
            vuln_xss=$((vuln_xss + 1))
        fi
    done
    
    printf '%s\n' "${payloads_xss[@]}" > "${OUTPUT_DIR}/payloads/xss-todos.txt"
    log_info "XSS: $vuln_xss vulnerabilidades detectadas"
    
    # Pruebas de Path Traversal
    log_info "Probando Path Traversal..."
    
    payloads_path=(
        "../../../../etc/passwd"
        "../../../etc/passwd"
        "../../../../etc/hosts"
    )
    
    vuln_path=0
    for payload in "${payloads_path[@]}"; do
        response=$(curl -s "${MUTILLIDAE_URL}/index.php?page=${payload}")
        if echo "$response" | grep -q "root:x:0:0"; then
            echo "$payload" >> "${OUTPUT_DIR}/payloads/path-traversal-exitosos.txt"
            echo "$response" > "${OUTPUT_DIR}/logs/path-traversal-evidencia.txt"
            vuln_path=$((vuln_path + 1))
        fi
    done
    
    printf '%s\n' "${payloads_path[@]}" > "${OUTPUT_DIR}/payloads/path-traversal-todos.txt"
    log_info "Path Traversal: $vuln_path vulnerabilidades detectadas"
    
    total_vuln=$((vuln_sql + vuln_xss + vuln_path))
fi

sleep 2

################################################################################
# FASE 6: GENERACIÓN DE REPORTES
################################################################################

log_step "FASE 6: GENERACIÓN DE REPORTES"

# Crear resumen
cat > "${OUTPUT_DIR}/RESUMEN.txt" << EOF
═══════════════════════════════════════════════════════════
    PAI-3 VULNAWEB - RESUMEN DE AUDITORÍA
═══════════════════════════════════════════════════════════

FECHA: $(date '+%Y-%m-%d %H:%M:%S')

HARDENING DE SISTEMAS:
- Índice Inicial:  ${hardening_inicial}/100
- Índice Final:    ${hardening_final}/100
- Mejora:          +${mejora} puntos
- Objetivo (≥69):  $([ $hardening_final -ge 69 ] && echo "✓ ALCANZADO" || echo "✗ NO ALCANZADO")

ACCIONES DE HARDENING APLICADAS:
✓ Políticas de contraseñas robustas (PAM + aging)
✓ Umask restrictivo (027)
✓ Firewall UFW configurado (puertos 22, 80, 443)
✓ Módulos innecesarios deshabilitados
✓ Banners legales implementados
✓ Actualizaciones automáticas habilitadas
✓ Kernel hardening aplicado (sysctl)
✓ Fail2ban configurado y activo

VULNERABILIDADES WEB DETECTADAS:
$(if [ -n "$total_vuln" ]; then
echo "- SQL Injection:    $vuln_sql vulnerabilidades"
echo "- XSS:              $vuln_xss vulnerabilidades"
echo "- Path Traversal:   $vuln_path vulnerabilidades"
echo "─────────────────────────────────────────────"
echo "TOTAL:              $total_vuln vulnerabilidades"
else
echo "No se ejecutaron pruebas web (Mutillidae no disponible)"
fi)

ARCHIVOS GENERADOS:
- logs/lynis-inicial.log           (Auditoría inicial)
- logs/lynis-final.log             (Auditoría final)
- configs/                         (Configuraciones aplicadas)
- payloads/                        (Payloads utilizados)
- backups/                         (Backups de configs originales)

UBICACIÓN:
$OUTPUT_DIR

═══════════════════════════════════════════════════════════
EOF

log_info "Resumen generado: ${OUTPUT_DIR}/RESUMEN.txt"

# Mostrar resumen en pantalla
clear
cat "${OUTPUT_DIR}/RESUMEN.txt"

echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}         ✓ AUDITORÍA COMPLETADA EXITOSAMENTE${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}\n"

echo -e "${CYAN}Resultados guardados en:${NC}"
echo -e "${BOLD}$OUTPUT_DIR${NC}\n"

echo -e "${YELLOW}Para ver el resumen:${NC}"
echo -e "  cat ${OUTPUT_DIR}/RESUMEN.txt\n"

echo -e "${YELLOW}Logs detallados en:${NC}"
echo -e "  ${OUTPUT_DIR}/logs/\n"

exit 0
