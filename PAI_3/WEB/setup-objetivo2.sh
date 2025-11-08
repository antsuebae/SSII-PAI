#!/bin/bash
################################################################################
# PAI-3 VULNAWEB - Objetivo 2: Auditoría de Aplicaciones Web
# Script de instalación y configuración completa - VERSIÓN CORREGIDA
# Security Team INSEGUS - Universidad de Sevilla
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Configuración del proyecto
PROJECT_DIR="$(pwd)/pai3-objetivo2"
RESULTS_DIR="$PROJECT_DIR/resultados-$(date +%Y%m%d-%H%M%S)"

log_info() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[⚠]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() {
    echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD} $1${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}\n"
}

check_dependencies() {
    log_info "Verificando dependencias..."
    
    # Verificar Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker no está instalado"
        log_info "Instalando Docker..."
        
        if command -v dnf &> /dev/null; then
            dnf install -y docker docker-compose-plugin
        elif command -v apt &> /dev/null; then
            apt update && apt install -y docker.io docker-compose-plugin
        else
            log_error "No se puede instalar Docker automáticamente"
            exit 1
        fi
        
        systemctl enable docker
        systemctl start docker
        usermod -aG docker $SUDO_USER 2>/dev/null || true
        log_warning "Es necesario reiniciar la sesión para usar Docker sin sudo"
    else
        log_info "✓ Docker disponible"
    fi
    
    # Verificar Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_warning "Docker Compose no está disponible"
        if command -v dnf &> /dev/null; then
            dnf install -y docker-compose
        elif command -v apt &> /dev/null; then
            apt install -y docker-compose
        fi
    else
        log_info "✓ Docker Compose disponible"
    fi
    
    # Verificar curl
    if ! command -v curl &> /dev/null; then
        log_info "Instalando curl..."
        if command -v dnf &> /dev/null; then
            dnf install -y curl
        else
            apt install -y curl
        fi
    fi
    
    log_info "✓ Todas las dependencias verificadas"
}

create_project_structure() {
    log_info "Creando estructura del proyecto..."
    
    mkdir -p "$PROJECT_DIR"
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$PROJECT_DIR/nginx"
    mkdir -p "$PROJECT_DIR/nginx/html"
    mkdir -p "$PROJECT_DIR/nginx/ssl"
    mkdir -p "$PROJECT_DIR/scripts"
    mkdir -p "$PROJECT_DIR/payloads"
    mkdir -p "$PROJECT_DIR/logs"
    mkdir -p "$PROJECT_DIR/evidencias"
    mkdir -p "$PROJECT_DIR/screenshots"
    
    log_info "✓ Estructura de directorios creada"
}

generate_ssl_certificates() {
    log_info "Generando certificados SSL para HTTPS..."
    
    cd "$PROJECT_DIR/nginx/ssl"
    
    # Generar clave privada
    openssl genrsa -out key.pem 2048 2>/dev/null || {
        log_warning "Error generando clave SSL, continuando sin HTTPS"
        return 0
    }
    
    # Generar certificado auto-firmado
    openssl req -new -x509 -key key.pem -out cert.pem -days 365 \
        -subj "/C=ES/ST=Sevilla/L=Sevilla/O=Universidad de Sevilla/OU=Security Team INSEGUS/CN=pai3-audit.local" 2>/dev/null || {
        log_warning "Error generando certificado SSL, continuando sin HTTPS"
        return 0
    }
    
    chmod 644 cert.pem 2>/dev/null || true
    chmod 600 key.pem 2>/dev/null || true
    
    log_info "✓ Certificados SSL generados"
}

setup_docker_environment() {
    log_info "Configurando entorno Docker..."
    
    cd "$PROJECT_DIR"
    
    # Crear archivo docker-compose.yml
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  # OWASP WebGoat
  webgoat:
    image: webgoat/goatandwolf:latest
    container_name: pai3-webgoat
    ports:
      - "8080:8080"
      - "9001:9001"
    environment:
      - WEBGOAT_PORT=8080
      - WEBWOLF_PORT=9001
    volumes:
      - webgoat-data:/home/webgoat/.webgoat
    restart: unless-stopped
    networks:
      - pai3-network

  # OWASP Mutillidae II
  mutillidae:
    image: citizenstig/nowasp:latest
    container_name: pai3-mutillidae
    ports:
      - "8082:80"
    environment:
      - MYSQL_ROOT_PASSWORD=mutillidae
      - MYSQL_DATABASE=mutillidae
    restart: unless-stopped
    networks:
      - pai3-network

  # DVWA
  dvwa:
    image: vulnerables/web-dvwa:latest
    container_name: pai3-dvwa
    ports:
      - "8083:80"
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
    restart: unless-stopped
    networks:
      - pai3-network

  # Nginx Proxy
  nginx:
    image: nginx:alpine
    container_name: pai3-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/html:/usr/share/nginx/html:ro
      - ./logs:/var/log/nginx
    depends_on:
      - webgoat
      - mutillidae
      - dvwa
    restart: unless-stopped
    networks:
      - pai3-network

volumes:
  webgoat-data:

networks:
  pai3-network:
    driver: bridge
EOF

    log_info "✓ Docker Compose configurado"
}

create_nginx_config() {
    log_info "Creando configuración Nginx..."
    
    cat > "$PROJECT_DIR/nginx/nginx.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Configuración de logs
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Configuración del servidor principal
    server {
        listen 80;
        server_name localhost pai3-audit.local;
        
        # Página principal
        location / {
            root /usr/share/nginx/html;
            index index.html;
        }

        # Proxy para WebGoat
        location /webgoat/ {
            proxy_pass http://webgoat:8080/WebGoat/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Proxy para WebWolf
        location /webwolf/ {
            proxy_pass http://webgoat:9001/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Proxy para Mutillidae
        location /mutillidae/ {
            proxy_pass http://mutillidae:80/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Proxy para DVWA
        location /dvwa/ {
            proxy_pass http://dvwa:80/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
EOF

    log_info "✓ Configuración Nginx creada"
}

create_index_page() {
    log_info "Creando página principal..."
    
    cat > "$PROJECT_DIR/nginx/html/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PAI-3 VULNAWEB - Entorno de Auditoría</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(45deg, #ff6b6b, #ee5a52);
            color: white;
            text-align: center;
            padding: 40px 20px;
        }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            padding: 40px;
        }
        .app-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border: 1px solid #eee;
            transition: transform 0.3s ease;
        }
        .app-card:hover { transform: translateY(-5px); }
        .app-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5rem;
            margin-bottom: 15px;
        }
        .app-card h3 { color: #333; margin-bottom: 10px; font-size: 1.4rem; }
        .app-card p { color: #666; line-height: 1.6; margin-bottom: 20px; }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            margin-right: 10px;
        }
        .btn-primary {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
        }
        .btn-secondary {
            background: #f8f9fa;
            color: #495057;
            border: 1px solid #dee2e6;
        }
        .btn:hover { transform: scale(1.05); }
        .footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 20px;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
            background: #28a745;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ PAI-3 VULNAWEB</h1>
            <p>Entorno de Auditoría de Seguridad Web - Security Team INSEGUS</p>
        </header>

        <div class="grid">
            <div class="app-card">
                <div class="app-icon">🐐</div>
                <h3>OWASP WebGoat</h3>
                <p>Aplicación web intencionalmente vulnerable con lecciones interactivas sobre diferentes tipos de vulnerabilidades de seguridad.</p>
                <a href="http://localhost:8080/WebGoat" class="btn btn-primary" target="_blank">Abrir WebGoat</a>
                <a href="http://localhost:9001" class="btn btn-secondary" target="_blank">WebWolf</a>
                <p style="margin-top: 15px;"><span class="status-indicator"></span>Puerto 8080 | OWASP Top 10</p>
            </div>

            <div class="app-card">
                <div class="app-icon">🔍</div>
                <h3>OWASP Mutillidae II</h3>
                <p>Aplicación PHP/MySQL vulnerable que incluye SQL Injection, XSS, CSRF, Command Injection y más.</p>
                <a href="http://localhost:8082" class="btn btn-primary" target="_blank">Abrir Mutillidae</a>
                <a href="http://localhost:8082/set-up-database.php" class="btn btn-secondary" target="_blank">Setup DB</a>
                <p style="margin-top: 15px;"><span class="status-indicator"></span>Puerto 8082 | PHP/MySQL</p>
            </div>

            <div class="app-card">
                <div class="app-icon">⚡</div>
                <h3>DVWA</h3>
                <p>Damn Vulnerable Web Application - Entorno con diferentes niveles de seguridad para practicar técnicas de pentesting.</p>
                <a href="http://localhost:8083" class="btn btn-primary" target="_blank">Abrir DVWA</a>
                <a href="http://localhost:8083/setup.php" class="btn btn-secondary" target="_blank">Setup</a>
                <p style="margin-top: 15px;"><span class="status-indicator"></span>Puerto 8083 | Multi-nivel</p>
            </div>

            <div class="app-card">
                <div class="app-icon">🔧</div>
                <h3>OWASP ZAP</h3>
                <p>Configura tu navegador para usar ZAP como proxy y realizar intercepción de tráfico HTTP/HTTPS.</p>
                <a href="#" onclick="showZAPConfig()" class="btn btn-primary">Ver Configuración</a>
                <p style="margin-top: 15px;"><span class="status-indicator"></span>Puerto 8081 | Proxy Manual</p>
            </div>
        </div>

        <footer class="footer">
            <p>&copy; 2024 Security Team INSEGUS - Universidad de Sevilla</p>
        </footer>
    </div>

    <script>
        function showZAPConfig() {
            alert(`Configuración de OWASP ZAP:

1. Instalar: sudo dnf install zaproxy
2. Abrir OWASP ZAP
3. Tools → Options → Local Proxies
4. Address: localhost, Port: 8081
5. Configurar Firefox:
   - Proxy HTTP: 127.0.0.1:8081
6. Importar certificado ZAP

¡Después intercepta todo el tráfico!`);
        }
    </script>
</body>
</html>
EOF

    log_info "✓ Página principal creada"
}

create_vulnerability_payloads() {
    log_info "Generando payloads para pruebas de vulnerabilidades..."
    
    # SQL Injection Payloads
    cat > "$PROJECT_DIR/payloads/sql-injection.txt" << 'EOF'
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' #
admin'--
admin'#
') OR '1'='1--
' UNION SELECT 1,2,3--
' AND 1=0 UNION SELECT user(),version()--
EOF

    # XSS Payloads
    cat > "$PROJECT_DIR/payloads/xss.txt" << 'EOF'
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')>
EOF

    # Path Traversal Payloads
    cat > "$PROJECT_DIR/payloads/path-traversal.txt" << 'EOF'
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
....//....//....//etc/passwd
../../../proc/version
EOF

    # Command Injection Payloads
    cat > "$PROJECT_DIR/payloads/command-injection.txt" << 'EOF'
; ls -la
; cat /etc/passwd
; whoami
| whoami
&& whoami
`whoami`
$(whoami)
EOF

    log_info "✓ Payloads generados"
}

create_test_script() {
    log_info "Creando script de pruebas..."
    
    cat > "$PROJECT_DIR/scripts/test-basic.sh" << 'EOF'
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
EOF

    chmod +x "$PROJECT_DIR/scripts/test-basic.sh"
    log_info "✓ Script de pruebas creado"
}

start_environment() {
    log_step "INICIANDO ENTORNO DE AUDITORÍA"
    
    cd "$PROJECT_DIR"
    
    log_info "Descargando imágenes Docker (puede tomar varios minutos)..."
    
    # Intentar docker-compose o docker compose
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        COMPOSE_CMD="docker compose"
    fi
    
    $COMPOSE_CMD pull || {
        log_warning "Error descargando imágenes, intentando con imágenes locales"
    }
    
    log_info "Iniciando servicios..."
    $COMPOSE_CMD up -d
    
    log_info "Esperando a que los servicios estén listos..."
    sleep 30
    
    # Verificar servicios
    log_info "Verificando servicios..."
    
    for port in 8080 8082 8083 80; do
        if curl -s "http://localhost:$port" > /dev/null; then
            log_info "✓ Puerto $port disponible"
        else
            log_warning "⚠ Puerto $port no responde aún"
        fi
    done
}

generate_final_report() {
    log_step "GENERANDO INFORME INICIAL"
    
    REPORT_FILE="$RESULTS_DIR/INFORME_OBJETIVO2.md"
    
    cat > "$REPORT_FILE" << EOF
# PAI-3 VULNAWEB - Objetivo 2: Auditoría de Aplicaciones Web

## Información General
- **Fecha:** $(date '+%d/%m/%Y %H:%M:%S')
- **Security Team:** INSEGUS
- **Universidad:** Universidad de Sevilla
- **Entorno:** Docker + Nginx + Aplicaciones Vulnerables

## Aplicaciones Instaladas

### 1. OWASP WebGoat
- **URL:** http://localhost:8080/WebGoat
- **Puerto:** 8080
- **Descripción:** Aplicación educativa con lecciones de seguridad

### 2. OWASP Mutillidae II
- **URL:** http://localhost:8082
- **Puerto:** 8082
- **Descripción:** Aplicación PHP/MySQL vulnerable

### 3. DVWA
- **URL:** http://localhost:8083
- **Puerto:** 8083
- **Descripción:** Aplicación con niveles de seguridad configurables

## Configuración de Trazabilidad

### OWASP ZAP
1. Instalar: \`sudo dnf install zaproxy\`
2. Configurar proxy: localhost:8081
3. Configurar Firefox para usar ZAP
4. Importar certificados SSL

### Navegador
- Proxy HTTP: 127.0.0.1:8081
- Proxy HTTPS: 127.0.0.1:8081
- Use proxy for all protocols: ✓

## Vulnerabilidades a Probar

- **SQL Injection**: Authentication bypass
- **XSS**: Reflected y stored
- **Path Traversal**: File inclusion
- **Command Injection**: OS commands
- **CSRF**: Missing tokens

## Comandos de Control

\`\`\`bash
# Ver estado de servicios
$COMPOSE_CMD ps

# Ver logs
$COMPOSE_CMD logs

# Detener entorno
$COMPOSE_CMD down

# Pruebas básicas
./scripts/test-basic.sh
\`\`\`

## Próximos Pasos

1. Configurar OWASP ZAP según instrucciones
2. Navegar por las aplicaciones con proxy configurado
3. Realizar pruebas de vulnerabilidades
4. Documentar hallazgos con screenshots
5. Generar informe final

EOF

    log_info "✓ Informe inicial generado en: $REPORT_FILE"
}

show_final_summary() {
    log_step "RESUMEN FINAL - PAI-3 OBJETIVO 2 COMPLETADO"
    
    echo -e "${GREEN}${BOLD}🎉 ¡Entorno configurado exitosamente!${NC}\n"
    
    echo -e "${CYAN}📋 URLs de Acceso:${NC}"
    echo -e "  🏠 Panel Principal: ${BOLD}http://localhost${NC}"
    echo -e "  🐐 WebGoat: ${BOLD}http://localhost:8080/WebGoat${NC}"
    echo -e "  🔍 Mutillidae II: ${BOLD}http://localhost:8082${NC}"
    echo -e "  ⚡ DVWA: ${BOLD}http://localhost:8083${NC}"
    
    echo -e "\n${YELLOW}🔧 Directorios del Proyecto:${NC}"
    echo -e "  📁 Proyecto: ${BOLD}$PROJECT_DIR${NC}"
    echo -e "  📊 Resultados: ${BOLD}$RESULTS_DIR${NC}"
    echo -e "  🎯 Payloads: ${BOLD}$PROJECT_DIR/payloads/${NC}"
    echo -e "  🔨 Scripts: ${BOLD}$PROJECT_DIR/scripts/${NC}"
    
    echo -e "\n${PURPLE}🎯 Próximos Pasos:${NC}"
    echo -e "  1. Instalar OWASP ZAP: ${BOLD}sudo dnf install zaproxy${NC}"
    echo -e "  2. Configurar ZAP como proxy (puerto 8081)"
    echo -e "  3. Configurar Firefox para usar ZAP"
    echo -e "  4. Navegar por las aplicaciones vulnerables"
    echo -e "  5. Documentar vulnerabilidades encontradas"
    
    echo -e "\n${BLUE}📊 Comandos Útiles:${NC}"
    echo -e "  📊 Estado: ${BOLD}cd $PROJECT_DIR && $COMPOSE_CMD ps${NC}"
    echo -e "  📝 Logs: ${BOLD}$COMPOSE_CMD logs${NC}"
    echo -e "  🛑 Detener: ${BOLD}$COMPOSE_CMD down${NC}"
    echo -e "  🧪 Pruebas: ${BOLD}./scripts/test-basic.sh${NC}"
    
    echo -e "\n${GREEN}🛡️ Objetivo 2 PAI-3 VULNAWEB: ${BOLD}LISTO PARA AUDITORÍA${NC} ✅\n"
}

# Función principal
main() {
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║         PAI-3 VULNAWEB - OBJETIVO 2                         ║
║        Auditoría de Aplicaciones Web con Docker             ║
║          Security Team INSEGUS - Univ. Sevilla              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}\n"
    
    check_dependencies
    create_project_structure
    generate_ssl_certificates
    setup_docker_environment
    create_nginx_config
    create_index_page
    create_vulnerability_payloads
    create_test_script
    start_environment
    generate_final_report
    show_final_summary
}

# Manejo de errores
trap 'log_error "Error en línea $LINENO. Abortando."; exit 1' ERR

# Ejecutar función principal
main "$@"
