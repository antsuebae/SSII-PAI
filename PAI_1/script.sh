#!/bin/bash

SRC_DIR="./src"
SERVER_LOG="server.log"

# Verificar que existan los archivos
if [ ! -f "$SRC_DIR/server.py" ] || [ ! -f "$SRC_DIR/client.py" ]; then
    echo "❌ Error: No se encontraron server.py o client.py en $SRC_DIR"
    exit 1
fi

# Buscar y matar procesos anteriores en el puerto 8888 (opcional pero recomendado)
echo "🔍 Verificando si el puerto 8888 está en uso..."
if command -v lsof >/dev/null 2>&1; then
    if lsof -Pi :8888 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️  Matando proceso anterior en el puerto 8888..."
        lsof -Pi :8888 -sTCP:LISTEN -t | xargs kill -9 2>/dev/null
        sleep 1
    fi
elif command -v ss >/dev/null 2>&1; then
    if ss -tuln | grep -q ':8888.*LISTEN'; then
        echo "⚠️  Puerto 8888 en uso. Por favor, cierra el proceso manualmente o reinicia."
        echo "   Puedes usar: 'sudo ss -tulnp | grep :8888' para identificarlo."
    fi
fi

# Iniciar el servidor en segundo plano y guardar salida en un archivo
echo "🚀 Iniciando servidor en segundo plano (salida en $SERVER_LOG)..."
python3 "$SRC_DIR/server.py" > "$SERVER_LOG" 2>&1 &

SERVER_PID=$!

# Esperar un poco para que el servidor se inicie
sleep 2

# Verificar si el servidor sigue en ejecución
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ El servidor falló al iniciar. Revisa $SERVER_LOG"
    exit 1
fi

echo "✅ Servidor iniciado (PID: $SERVER_PID)"
echo "📄 Salida del servidor: tail -f $SERVER_LOG"
echo ""

# Iniciar el cliente en primer plano (interactivo)
echo "💬 Iniciando cliente..."
python3 "$SRC_DIR/client.py"

# Opcional: al salir del cliente, preguntar si se quiere detener el servidor
echo ""
read -p "¿Quieres detener el servidor (PID $SERVER_PID)? [Y/n]: " -n 1 -r
echo
# Si no se ingresó nada (solo Enter), asumimos "Y"
if [[ -z "$REPLY" || "$REPLY" =~ ^[Yy]$ ]]; then
    kill $SERVER_PID 2>/dev/null
    echo "🛑 Servidor detenido."
fi
