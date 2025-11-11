#!/bin/bash

# ========================================================================
# Script de Backup Automatizado
# PAI-4: Plan de Mitigación - Contingencia y Recuperación
# ========================================================================

# Configuración
BACKUP_DIR="/backups"
RETENTION_DAYS=30
MYSQL_USER="backup_user"
MYSQL_PASS="SecurePass@2024"
WEB_DIR="/var/www/html"
CONFIG_DIR="/etc"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/backup.log"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Función de logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} [$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} [$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Crear directorio de backup si no existe
mkdir -p "$BACKUP_DIR"

log_message "========================================="
log_message "INICIANDO PROCESO DE BACKUP"
log_message "========================================="

# ========================================================================
# 1. BACKUP DE BASE DE DATOS MYSQL
# ========================================================================
log_message "Realizando backup de MySQL..."

if command -v mysqldump &> /dev/null; then
    MYSQL_BACKUP="$BACKUP_DIR/mysql_$DATE.sql.gz"
    
    if mysqldump -u "$MYSQL_USER" -p"$MYSQL_PASS" --all-databases --single-transaction 2>/dev/null | gzip > "$MYSQL_BACKUP"; then
        MYSQL_SIZE=$(du -h "$MYSQL_BACKUP" | cut -f1)
        log_success "Backup MySQL completado: $MYSQL_BACKUP ($MYSQL_SIZE)"
    else
        log_error "Error en backup de MySQL"
    fi
else
    log_message "MySQL no encontrado, omitiendo backup de base de datos"
fi

# ========================================================================
# 2. BACKUP DE APLICACIÓN WEB
# ========================================================================
log_message "Realizando backup de aplicación web..."

if [ -d "$WEB_DIR" ]; then
    WEBAPP_BACKUP="$BACKUP_DIR/webapp_$DATE.tar.gz"
    
    if tar -czf "$WEBAPP_BACKUP" -C "$(dirname $WEB_DIR)" "$(basename $WEB_DIR)" 2>/dev/null; then
        WEBAPP_SIZE=$(du -h "$WEBAPP_BACKUP" | cut -f1)
        log_success "Backup aplicación web completado: $WEBAPP_BACKUP ($WEBAPP_SIZE)"
    else
        log_error "Error en backup de aplicación web"
    fi
else
    log_message "Directorio $WEB_DIR no encontrado"
fi

# ========================================================================
# 3. BACKUP DE CONFIGURACIONES
# ========================================================================
log_message "Realizando backup de configuraciones..."

CONFIG_BACKUP="$BACKUP_DIR/config_$DATE.tar.gz"

# Lista de directorios de configuración importantes
CONFIG_DIRS=(
    "/etc/apache2"
    "/etc/nginx"
    "/etc/mysql"
    "/etc/php"
    "/etc/ssh"
    "/etc/suricata"
)

# Crear array de directorios existentes
EXISTING_DIRS=()
for dir in "${CONFIG_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        EXISTING_DIRS+=("$dir")
    fi
done

if [ ${#EXISTING_DIRS[@]} -gt 0 ]; then
    if tar -czf "$CONFIG_BACKUP" "${EXISTING_DIRS[@]}" 2>/dev/null; then
        CONFIG_SIZE=$(du -h "$CONFIG_BACKUP" | cut -f1)
        log_success "Backup configuraciones completado: $CONFIG_BACKUP ($CONFIG_SIZE)"
    else
        log_error "Error en backup de configuraciones"
    fi
fi

# ========================================================================
# 4. VERIFICACIÓN DE INTEGRIDAD
# ========================================================================
log_message "Generando checksums MD5..."

MD5_FILE="$BACKUP_DIR/checksums_$DATE.md5"
cd "$BACKUP_DIR"
md5sum *_$DATE.* > "$MD5_FILE" 2>/dev/null
log_success "Checksums generados: $MD5_FILE"

# ========================================================================
# 5. LIMPIEZA DE BACKUPS ANTIGUOS
# ========================================================================
log_message "Limpiando backups antiguos (>$RETENTION_DAYS días)..."

DELETED_COUNT=$(find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -type f -delete -print | wc -l)
DELETED_MD5=$(find "$BACKUP_DIR" -name "*.md5" -mtime +$RETENTION_DAYS -type f -delete -print | wc -l)

log_success "Archivos eliminados: $DELETED_COUNT backups, $DELETED_MD5 checksums"

# ========================================================================
# 6. RESUMEN DEL BACKUP
# ========================================================================
log_message "========================================="
log_message "RESUMEN DEL BACKUP"
log_message "========================================="

TOTAL_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)
BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/*_$DATE.* 2>/dev/null | wc -l)

log_message "Archivos de backup generados: $BACKUP_COUNT"
log_message "Tamaño total del directorio: $TOTAL_SIZE"
log_message "Ubicación: $BACKUP_DIR"

# Listar backups del día
log_message ""
log_message "Backups generados hoy:"
ls -lh "$BACKUP_DIR"/*_$DATE.* 2>/dev/null | awk '{print "  - " $9 " (" $5 ")"}'

log_message "========================================="
log_success "PROCESO DE BACKUP COMPLETADO"
log_message "========================================="

# ========================================================================
# 7. ENVÍO DE NOTIFICACIÓN (OPCIONAL)
# ========================================================================
# Descomentar para enviar email de notificación
# if command -v mail &> /dev/null; then
#     echo "Backup completado exitosamente en $(hostname)" | \
#         mail -s "Backup Status - $(date '+%Y-%m-%d')" admin@company.com
# fi

exit 0
