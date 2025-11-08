#!/bin/bash

echo "=== Probando conectividad básica ==="

# Test WebGoat
if curl -s "http://localhost:8080" > /dev/null; then
    echo "✓ WebGoat accesible en puerto 8080"
else
    echo "✗ WebGoat no accesible"
fi

# Test Mutillidae
if curl -s "http://localhost:8082" > /dev/null; then
    echo "✓ Mutillidae accesible en puerto 8082"
else
    echo "✗ Mutillidae no accesible"
fi

# Test DVWA
if curl -s "http://localhost:8083" > /dev/null; then
    echo "✓ DVWA accesible en puerto 8083"
else
    echo "✗ DVWA no accesible"
fi

# Test Nginx
if curl -s "http://localhost" > /dev/null; then
    echo "✓ Nginx accesible en puerto 80"
else
    echo "✗ Nginx no accesible"
fi

echo "=== Prueba básica completada ==="
