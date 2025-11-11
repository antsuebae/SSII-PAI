#!/bin/bash

# ========================================================================
# Script de Análisis de Logs de Suricata
# PAI-4: Monitorización de IDS
# ========================================================================

# Configuración
SURICATA_LOGS="$HOME/suricata/logs"
FAST_LOG="$SURICATA_LOGS/fast.log"
EVE_LOG="$SURICATA_LOGS/eve.json"
REPORT_FILE="$SURICATA_LOGS/report_$(date +%Y%m%d).txt"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================="
echo "ANÁLISIS DE LOGS DE SURICATA IDS"
echo "========================================="
echo ""

# Verificar que existen los logs
if [ ! -f "$FAST_LOG" ]; then
    echo -e "${RED}ERROR:${NC} No se encuentra el archivo $FAST_LOG"
    exit 1
fi

# Función para contar alertas
count_alerts() {
    if [ -f "$FAST_LOG" ]; then
        wc -l < "$FAST_LOG"
    else
        echo "0"
    fi
}

# Función para extraer top IPs atacantes
get_top_ips() {
    if [ -f "$FAST_LOG" ]; then
        grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$FAST_LOG" | \
        sort | uniq -c | sort -rn | head -n 10
    fi
}

# Función para contar alertas por SID
get_alerts_by_sid() {
    if [ -f "$FAST_LOG" ]; then
        grep -oP '\[1:\K[0-9]+(?=:)' "$FAST_LOG" | \
        sort | uniq -c | sort -rn
    fi
}

# Función para obtener alertas críticas
get_critical_alerts() {
    if [ -f "$FAST_LOG" ]; then
        grep -i "CRITICA\|CRITICAL\|ATAQUE" "$FAST_LOG" | tail -n 20
    fi
}

# Generar reporte
{
    echo "========================================="
    echo "INFORME DE SEGURIDAD - SURICATA IDS"
    echo "Fecha: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================="
    echo ""
    
    echo "--- RESUMEN GENERAL ---"
    TOTAL_ALERTS=$(count_alerts)
    echo "Total de alertas: $TOTAL_ALERTS"
    echo ""
    
    if [ "$TOTAL_ALERTS" -gt 0 ]; then
        echo "--- TOP 10 IPs ATACANTES ---"
        echo "Cantidad | IP Address"
        echo "---------|------------------"
        get_top_ips
        echo ""
        
        echo "--- ALERTAS POR TIPO (SID) ---"
        echo "Cantidad | SID"
        echo "---------|------"
        get_alerts_by_sid
        echo ""
        
        echo "--- ÚLTIMAS 20 ALERTAS CRÍTICAS ---"
        get_critical_alerts
        echo ""
    fi
    
    echo "========================================="
    echo "FIN DEL INFORME"
    echo "========================================="
    
} | tee "$REPORT_FILE"

echo ""
echo -e "${GREEN}Reporte guardado en:${NC} $REPORT_FILE"

# Análisis en tiempo real opcional
echo ""
echo -e "${YELLOW}¿Desea monitorizar alertas en tiempo real? (Ctrl+C para salir)${NC}"
read -p "Presione ENTER para continuar o Ctrl+C para cancelar..."

echo ""
echo "Monitorizando alertas en vivo..."
echo "========================================="
tail -f "$FAST_LOG" | while read line; do
    if echo "$line" | grep -qi "CRITICA\|CRITICAL"; then
        echo -e "${RED}$line${NC}"
    elif echo "$line" | grep -qi "ATAQUE\|ATTACK"; then
        echo -e "${YELLOW}$line${NC}"
    else
        echo "$line"
    fi
done
