#!/bin/bash

# ========================================================================
# Script de instalación y configuración de OpenVAS/Greenbone
# PAI-4: Gestión de Vulnerabilidades
# ========================================================================

set -e  # Salir si hay error

echo "========================================="
echo "INSTALACIÓN DE OPENVAS/GREENBONE"
echo "========================================="

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Verificar que Docker está instalado
print_message "Verificando Docker..."
if ! command -v docker &> /dev/null; then
    print_error "Docker no está instalado. Por favor, instale Docker primero."
    exit 1
fi
print_message "Docker encontrado: $(docker --version)"

# Configuración
CONTAINER_NAME="openvas"
IMAGE_NAME="immauss/openvas"
ADMIN_PASSWORD="Admin@OpenVAS2024!"
PORT="9392"
VOLUME_NAME="openvas-data"

# Preguntar por contraseña personalizada
echo ""
read -p "¿Desea usar la contraseña por defecto (Admin@OpenVAS2024!)? (s/n): " use_default
if [ "$use_default" != "s" ]; then
    read -sp "Ingrese contraseña para admin: " ADMIN_PASSWORD
    echo ""
fi

# Detener y eliminar contenedor existente si existe
if [ "$(docker ps -aq -f name=$CONTAINER_NAME)" ]; then
    print_warning "Contenedor existente encontrado. Eliminando..."
    docker stop $CONTAINER_NAME 2>/dev/null || true
    docker rm $CONTAINER_NAME 2>/dev/null || true
fi

# Crear volumen persistente
print_message "Creando volumen persistente..."
docker volume create $VOLUME_NAME || true

# Descargar imagen
print_message "Descargando imagen de OpenVAS..."
docker pull $IMAGE_NAME

# Desplegar contenedor
print_message "Desplegando contenedor OpenVAS..."
docker run --detach \
    --publish $PORT:9392 \
    -e PASSWORD="$ADMIN_PASSWORD" \
    --volume $VOLUME_NAME:/data \
    --name $CONTAINER_NAME \
    $IMAGE_NAME

# Esperar a que el contenedor inicie
print_message "Esperando a que OpenVAS inicie (esto puede tomar 2-3 minutos)..."
sleep 30

# Verificar estado
if [ "$(docker ps -q -f name=$CONTAINER_NAME)" ]; then
    print_message "Contenedor iniciado correctamente"
else
    print_error "El contenedor no está corriendo"
    docker logs $CONTAINER_NAME
    exit 1
fi

# Actualizar feeds
print_message "Actualizando feeds de vulnerabilidades..."
print_warning "Esto puede tomar 15-20 minutos. Por favor, espere..."
docker exec -it $CONTAINER_NAME /scripts/sync.sh

echo ""
echo "========================================="
echo "INSTALACIÓN COMPLETADA"
echo "========================================="
echo ""
echo "OpenVAS está disponible en:"
echo "  URL: http://localhost:$PORT"
echo "  Usuario: admin"
echo "  Contraseña: $ADMIN_PASSWORD"
echo ""
echo "Comandos útiles:"
echo "  Ver logs:        docker logs $CONTAINER_NAME"
echo "  Reiniciar:       docker restart $CONTAINER_NAME"
echo "  Detener:         docker stop $CONTAINER_NAME"
echo "  Actualizar feeds: docker exec -it $CONTAINER_NAME /scripts/sync.sh"
echo ""
echo "NOTA: El sistema estará completamente operativo en ~15-20 minutos"
echo "      después de la actualización de feeds."
echo ""
