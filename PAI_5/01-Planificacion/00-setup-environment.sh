#!/bin/bash
#
# Script de Setup del Entorno - PAI-5 RedTeamPro
# Configura el entorno completo para pentesting de DVWA
# Autor: Security Team
# Fecha: $(date +%Y-%m-%d)
#

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     PAI-5 RedTeamPro - Environment Setup Script         ║"
echo "║     DVWA (Damn Vulnerable Web Application) Setup        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Función para logging
log() {
    echo -e "${GREEN}[✓]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Verificar si se ejecuta como root
if [ "$EUID" -eq 0 ]; then
    warning "No ejecutar como root. Usa tu usuario normal (con sudo disponible)"
    exit 1
fi

# 1. Verificar/Instalar Docker
info "Verificando instalación de Docker..."
if command -v docker &> /dev/null; then
    log "Docker ya está instalado: $(docker --version)"
else
    info "Docker no encontrado. Instalando Docker..."

    # Detectar distribución
    if [ -f /etc/fedora-release ]; then
        info "Detectado: Fedora Linux"
        sudo dnf -y install dnf-plugins-core
        sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif [ -f /etc/debian_version ]; then
        info "Detectado: Debian/Ubuntu/Kali Linux"
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl gnupg
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
        echo \
          "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
          "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
          sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
        sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        error "Distribución no soportada. Instala Docker manualmente."
        exit 1
    fi

    log "Docker instalado correctamente"
fi

# 2. Verificar/Instalar Docker Compose
info "Verificando Docker Compose..."
if command -v docker compose &> /dev/null || command -v docker-compose &> /dev/null; then
    log "Docker Compose ya está instalado"
else
    info "Instalando Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    log "Docker Compose instalado"
fi

# 3. Configurar usuario para Docker (sin sudo)
info "Configurando permisos de Docker para usuario actual..."
if groups | grep -q docker; then
    log "Usuario ya está en el grupo docker"
else
    sudo usermod -aG docker $USER
    warning "Se ha añadido el usuario al grupo docker. DEBES CERRAR SESIÓN Y VOLVER A ENTRAR o ejecutar: newgrp docker"
fi

# 4. Iniciar servicio Docker
info "Iniciando servicio Docker..."
sudo systemctl start docker
sudo systemctl enable docker
log "Servicio Docker iniciado y habilitado"

# 5. Verificar herramientas de Kali
info "Verificando herramientas de pentesting..."

tools=(
    "nmap:Network scanner"
    "nikto:Web vulnerability scanner"
    "sqlmap:SQL injection tool"
    "metasploit-framework:Exploitation framework"
    "burpsuite:Web security testing"
    "zaproxy:OWASP ZAP"
    "hydra:Password cracker"
    "john:Password cracker"
    "netcat:Network utility"
    "curl:HTTP client"
    "wget:HTTP downloader"
    "git:Version control"
)

missing_tools=()

for tool_desc in "${tools[@]}"; do
    IFS=':' read -r tool description <<< "$tool_desc"
    if command -v $tool &> /dev/null; then
        log "$description ($tool): ✓"
    else
        warning "$description ($tool): No encontrado"
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    warning "Herramientas faltantes: ${missing_tools[*]}"
    info "En Kali Linux, instala con: sudo apt-get install ${missing_tools[*]}"
fi

# 6. Crear estructura de directorios si no existe
info "Verificando estructura de directorios..."
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

dirs=(
    "01-Planificacion"
    "02-Reconocimiento/nmap-results"
    "02-Reconocimiento/fingerprinting"
    "03-Escaneo/vulnerability-reports"
    "03-Escaneo/nikto-output"
    "03-Escaneo/sqlmap-output"
    "04-Explotacion/exploits-used"
    "04-Explotacion/payloads"
    "05-Post-Explotacion/privilege-escalation"
    "05-Post-Explotacion/persistence"
    "06-Evidencias/screenshots"
    "06-Evidencias/logs"
    "06-Evidencias/network-captures"
    "07-Scripts"
    "08-Informe"
)

for dir in "${dirs[@]}"; do
    mkdir -p "$PROJECT_ROOT/$dir"
done

log "Estructura de directorios verificada"

# 7. Desplegar DVWA con Docker Compose
info "Desplegando DVWA en Docker..."

cd "$PROJECT_ROOT/01-Planificacion"

if [ -f "docker-compose.yml" ]; then
    log "Archivo docker-compose.yml encontrado"

    info "Descargando e iniciando contenedores DVWA..."
    docker compose pull
    docker compose up -d

    # Esperar a que DVWA esté listo
    info "Esperando a que DVWA esté listo..."
    sleep 10

    # Obtener IP del contenedor
    DVWA_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dvwa 2>/dev/null || echo "localhost")

    echo ""
    log "DVWA desplegado correctamente!"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  DVWA está disponible en: http://${DVWA_IP}${NC}"
    echo -e "${GREEN}  O también en: http://localhost:80${NC}"
    echo -e "${GREEN}  Credenciales por defecto:${NC}"
    echo -e "${GREEN}    Usuario: admin${NC}"
    echo -e "${GREEN}    Password: password${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Guardar configuración
    cat > "$PROJECT_ROOT/01-Planificacion/dvwa-info.txt" <<EOF
DVWA Configuration
==================
Deployment Date: $(date)
Container IP: $DVWA_IP
Access URL: http://$DVWA_IP or http://localhost:80
Default Credentials:
  Username: admin
  Password: password

First Steps:
1. Access DVWA web interface
2. Click on "Create / Reset Database" button
3. Login with admin/password
4. Set security level in "DVWA Security" page

Docker Commands:
  Start: docker compose -f $(pwd)/docker-compose.yml up -d
  Stop: docker compose -f $(pwd)/docker-compose.yml down
  Logs: docker compose -f $(pwd)/docker-compose.yml logs -f
  Status: docker compose -f $(pwd)/docker-compose.yml ps
EOF

    log "Información guardada en: $PROJECT_ROOT/01-Planificacion/dvwa-info.txt"

else
    error "docker-compose.yml no encontrado. Debes crearlo primero."
    info "Consulta el archivo docker-compose.yml del plan."
    exit 1
fi

# 8. Test de conectividad
info "Probando conectividad con DVWA..."
if curl -s http://localhost:80 > /dev/null; then
    log "DVWA responde correctamente en http://localhost:80"
else
    warning "No se puede conectar a DVWA. Verifica el estado con: docker compose ps"
fi

# 9. Crear archivo de configuración para scripts
cat > "$PROJECT_ROOT/07-Scripts/.env" <<EOF
# Configuración del entorno - PAI-5 RedTeamPro
TARGET_IP=$DVWA_IP
TARGET_URL=http://localhost:80
PROJECT_ROOT=$PROJECT_ROOT
LOG_DIR=$PROJECT_ROOT/06-Evidencias/logs
SCREENSHOTS_DIR=$PROJECT_ROOT/06-Evidencias/screenshots
NETWORK_CAPTURES_DIR=$PROJECT_ROOT/06-Evidencias/network-captures
EOF

log "Archivo de configuración creado en 07-Scripts/.env"

# Resumen final
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Setup Completado Exitosamente!              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Próximos pasos:${NC}"
echo "1. Accede a http://localhost:80"
echo "2. Haz clic en 'Create / Reset Database'"
echo "3. Login con admin/password"
echo "4. Comienza el pentesting siguiendo las guías en cada directorio"
echo ""
echo -e "${YELLOW}Comandos útiles:${NC}"
echo "  Ver logs de DVWA:     docker compose -f 01-Planificacion/docker-compose.yml logs -f"
echo "  Detener DVWA:         docker compose -f 01-Planificacion/docker-compose.yml down"
echo "  Reiniciar DVWA:       docker compose -f 01-Planificacion/docker-compose.yml restart"
echo ""

log "Setup completado. ¡Feliz pentesting!"
