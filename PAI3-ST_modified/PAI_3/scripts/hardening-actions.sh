#!/bin/bash
################################################################################
# PAI-3 VULNAWEB - Script de Hardening
# Security Team INSEGUS
# Fecha: Noviembre 2024
# 
# ADVERTENCIA: Este script realiza cambios significativos en la configuración
# del sistema. Revisar antes de ejecutar en producción.
################################################################################

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función de logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar que se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   log_error "Este script debe ejecutarse como root (sudo)"
   exit 1
fi

log_info "========================================="
log_info "Iniciando proceso de hardening"
log_info "========================================="

# Crear directorio de respaldos
BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
log_info "Directorio de respaldo: $BACKUP_DIR"

################################################################################
# 1. ACTUALIZACIONES DEL SISTEMA
################################################################################
log_info "1. Actualizando el sistema..."

apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y
apt-get autoremove -y
apt-get autoclean

log_info "✓ Sistema actualizado"

################################################################################
# 2. INSTALACIÓN DE HERRAMIENTAS DE SEGURIDAD
################################################################################
log_info "2. Instalando herramientas de seguridad..."

apt-get install -y \
    libpam-pwquality \
    ufw \
    apt-show-versions \
    unattended-upgrades \
    aide \
    rkhunter \
    fail2ban

log_info "✓ Herramientas instaladas"

################################################################################
# 3. CONFIGURACIÓN DE POLÍTICAS DE CONTRASEÑAS
################################################################################
log_info "3. Configurando políticas de contraseñas..."

# Backup de configuración original
cp /etc/pam.d/common-password "$BACKUP_DIR/common-password.bak"
cp /etc/login.defs "$BACKUP_DIR/login.defs.bak"

# Configurar pam_pwquality
if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' /etc/pam.d/common-password
fi

# Configurar aging de contraseñas
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

log_info "✓ Políticas de contraseñas configuradas"

################################################################################
# 4. CONFIGURACIÓN DE UMASK
################################################################################
log_info "4. Configurando umask restrictivo..."

# Backup
cp /etc/profile "$BACKUP_DIR/profile.bak"
cp /etc/bash.bashrc "$BACKUP_DIR/bash.bashrc.bak"

# Configurar umask en /etc/profile
if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi

# Configurar umask en /etc/bash.bashrc
if ! grep -q "umask 027" /etc/bash.bashrc; then
    echo "umask 027" >> /etc/bash.bashrc
fi

# Configurar umask en /etc/login.defs
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs

log_info "✓ Umask configurado a 027"

################################################################################
# 5. CONFIGURACIÓN DE FIREWALL (UFW)
################################################################################
log_info "5. Configurando firewall..."

# Resetear configuración
ufw --force reset

# Políticas por defecto
ufw default deny incoming
ufw default allow outgoing

# Reglas para comercio electrónico
ufw allow 443/tcp comment 'HTTPS'
ufw allow 80/tcp comment 'HTTP'
ufw allow 22/tcp comment 'SSH'

# Habilitar firewall
ufw --force enable

# Verificar estado
ufw status verbose

log_info "✓ Firewall configurado y activado"

################################################################################
# 6. DESHABILITACIÓN DE MÓDULOS INNECESARIOS
################################################################################
log_info "6. Deshabilitando módulos innecesarios..."

# Backup
cp /etc/modprobe.d/blacklist.conf "$BACKUP_DIR/blacklist.conf.bak" 2>/dev/null || true

# Deshabilitar USB storage
if ! grep -q "blacklist usb-storage" /etc/modprobe.d/blacklist.conf; then
    echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
fi

# Deshabilitar firewire
if ! grep -q "blacklist firewire-core" /etc/modprobe.d/blacklist.conf; then
    echo "blacklist firewire-core" >> /etc/modprobe.d/blacklist.conf
    echo "blacklist firewire-ohci" >> /etc/modprobe.d/blacklist.conf
    echo "blacklist firewire-sbp2" >> /etc/modprobe.d/blacklist.conf
fi

log_info "✓ Módulos deshabilitados"

################################################################################
# 7. BANNERS LEGALES
################################################################################
log_info "7. Configurando banners legales..."

# Backup
cp /etc/issue "$BACKUP_DIR/issue.bak"
cp /etc/issue.net "$BACKUP_DIR/issue.net.bak"

# Banner para /etc/issue
cat > /etc/issue << 'EOF'
***************************************************************************
                            ADVERTENCIA
***************************************************************************

Este sistema es para uso autorizado únicamente. 

Todas las actividades en este sistema son monitoreadas y registradas.
El uso no autorizado de este sistema está prohibido y puede estar 
sujeto a sanciones civiles y penales.

Al continuar, usted acepta que:
- Tiene autorización explícita para acceder a este sistema
- Sus actividades pueden ser monitoreadas
- No tiene expectativa de privacidad
- Las evidencias pueden ser usadas en procedimientos legales

***************************************************************************
EOF

# Copiar a issue.net
cp /etc/issue /etc/issue.net

log_info "✓ Banners legales configurados"

################################################################################
# 8. CONFIGURACIÓN DE ACTUALIZACIONES AUTOMÁTICAS
################################################################################
log_info "8. Configurando actualizaciones automáticas de seguridad..."

# Configurar unattended-upgrades
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

# Habilitar actualizaciones automáticas
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

log_info "✓ Actualizaciones automáticas configuradas"

################################################################################
# 9. CONFIGURACIÓN DE SYSCTL (KERNEL HARDENING)
################################################################################
log_info "9. Aplicando hardening del kernel..."

# Backup
cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak"

# Agregar configuraciones de seguridad
cat >> /etc/sysctl.conf << 'EOF'

# PAI-3 Security Hardening
# Network Security
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# Disable IPv6 if not needed
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Kernel hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
EOF

# Aplicar cambios
sysctl -p

log_info "✓ Hardening del kernel aplicado"

################################################################################
# 10. CONFIGURACIÓN DE FAIL2BAN
################################################################################
log_info "10. Configurando fail2ban..."

# Configurar jail local
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = security@example.com
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log

[apache-badbots]
enabled = true
port = http,https
logpath = /var/log/apache*/*access.log
bantime = 172800
maxretry = 1

[apache-noscript]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log

[apache-overflows]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
maxretry = 2
EOF

# Reiniciar fail2ban
systemctl enable fail2ban
systemctl restart fail2ban

log_info "✓ Fail2ban configurado"

################################################################################
# 11. LIMPIEZA Y PERMISOS DE ARCHIVOS SENSIBLES
################################################################################
log_info "11. Ajustando permisos de archivos sensibles..."

# Permisos restrictivos para archivos críticos
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/security/opasswd
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 644 /etc/group

# Permisos para directorios home
chmod 750 /home/*

log_info "✓ Permisos ajustados"

################################################################################
# AUDITORÍA FINAL
################################################################################
log_info "========================================="
log_info "Proceso de hardening completado"
log_info "========================================="

log_info "Ejecutando auditoría final con Lynis..."

if command -v lynis &> /dev/null; then
    lynis audit system -Q --report-file /root/lynis-report-post-hardening.dat
    log_info "✓ Informe de Lynis generado: /root/lynis-report-post-hardening.dat"
else
    log_warning "Lynis no está instalado. Instalar con: apt-get install lynis"
fi

log_info ""
log_info "Resumen de cambios:"
log_info "- Políticas de contraseñas reforzadas"
log_info "- Umask configurado a 027"
log_info "- Firewall UFW activado"
log_info "- Módulos innecesarios deshabilitados"
log_info "- Banners legales configurados"
log_info "- Actualizaciones automáticas habilitadas"
log_info "- Kernel hardening aplicado"
log_info "- Fail2ban configurado y activo"
log_info ""
log_info "Archivos de respaldo en: $BACKUP_DIR"
log_info ""
log_warning "IMPORTANTE: Se recomienda reiniciar el sistema para aplicar todos los cambios"
log_info ""
log_info "Para reiniciar ahora: sudo reboot"
log_info "========================================="

exit 0
