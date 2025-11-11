#!/bin/bash

# ========================================================================
# Script de instalación y configuración de Suricata IDS
# PAI-4: Detección de Intrusos
# ========================================================================

set -e  # Salir si hay error

echo "========================================="
echo "INSTALACIÓN DE SURICATA IDS"
echo "========================================="

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Verificar Docker
print_message "Verificando Docker..."
if ! command -v docker &> /dev/null; then
    print_error "Docker no está instalado"
    exit 1
fi

# Configuración
CONTAINER_NAME="suricata-ids"
IMAGE_NAME="jasonish/suricata:6.0.15"
WORK_DIR="$HOME/suricata"

# Detectar interfaz de red
print_message "Detectando interfaz de red..."
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    print_error "No se pudo detectar la interfaz de red"
    read -p "Por favor, ingrese el nombre de la interfaz (ej: eth0): " INTERFACE
fi
print_message "Usando interfaz: $INTERFACE"

# Crear estructura de directorios
print_message "Creando estructura de directorios..."
mkdir -p "$WORK_DIR"/{rules,config,logs}

# Copiar reglas personalizadas si existen
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
if [ -f "$SCRIPT_DIR/../configuraciones/custom-rules.rules" ]; then
    print_message "Copiando reglas personalizadas..."
    cp "$SCRIPT_DIR/../configuraciones/custom-rules.rules" "$WORK_DIR/rules/"
fi

# Copiar configuración si existe
if [ -f "$SCRIPT_DIR/../configuraciones/suricata.yaml" ]; then
    print_message "Copiando configuración..."
    cp "$SCRIPT_DIR/../configuraciones/suricata.yaml" "$WORK_DIR/config/"
fi

# Detener contenedor existente si existe
if [ "$(docker ps -aq -f name=$CONTAINER_NAME)" ]; then
    print_warning "Contenedor existente encontrado. Eliminando..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
fi

# Descargar imagen
print_message "Descargando imagen de Suricata..."
docker pull $IMAGE_NAME

# Inicializar configuración
print_message "Inicializando configuración..."
docker run --rm -it \
    -v "$WORK_DIR/config":/etc/suricata \
    $IMAGE_NAME -V

# Desplegar contenedor
print_message "Desplegando Suricata IDS..."
docker run -d \
    --name $CONTAINER_NAME \
    --network host \
    --cap-add=net_admin \
    --cap-add=sys_nice \
    -v "$WORK_DIR/logs":/var/log/suricata \
    -v "$WORK_DIR/rules":/var/lib/suricata/rules \
    -v "$WORK_DIR/config":/etc/suricata \
    $IMAGE_NAME \
    -i $INTERFACE

sleep 5

# Verificar estado
if [ "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
    print_message "Contenedor iniciado correctamente"
    
    # Obtener ID del contenedor
    CONTAINER_ID=$(docker ps -q -f name=$CONTAINER_NAME)
    
    # Descargar reglas base
    print_message "Descargando reglas base de Suricata..."
    docker exec -it --user suricata $CONTAINER_ID suricata-update -f
    
    # Recargar reglas
    print_message "Recargando reglas..."
    docker exec -it --user suricata $CONTAINER_ID suricatasc -c reload-rules
    
else
    print_error "El contenedor no está corriendo"
    docker logs $CONTAINER_NAME
    exit 1
fi

echo ""
echo "========================================="
echo "INSTALACIÓN COMPLETADA"
echo "========================================="
echo ""
echo "Suricata IDS configurado en:"
echo "  Interfaz: $INTERFACE"
echo "  Directorio logs: $WORK_DIR/logs"
echo "  Directorio reglas: $WORK_DIR/rules"
echo ""
echo "Archivos de logs:"
echo "  Fast log: $WORK_DIR/logs/fast.log"
echo "  EVE JSON: $WORK_DIR/logs/eve.json"
echo "  Stats: $WORK_DIR/logs/stats.log"
echo ""
echo "Comandos útiles:"
echo "  Ver alertas en vivo:"
echo "    tail -f $WORK_DIR/logs/fast.log"
echo ""
echo "  Recargar reglas:"
echo "    docker exec -it $CONTAINER_ID suricatasc -c reload-rules"
echo ""
echo "  Ver estadísticas de reglas:"
echo "    docker exec -it $CONTAINER_ID suricatasc -c ruleset-stats"
echo ""
echo "  Detener Suricata:"
echo "    docker stop $CONTAINER_NAME"
echo ""
