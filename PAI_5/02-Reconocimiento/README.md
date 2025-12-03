# Fase de Reconocimiento

**MITRE ATT&CK**: T1046 (Network Service Scanning), T1595 (Active Scanning)

## Objetivo

El objetivo de esta fase es recopilar la máxima información posible sobre el target sin necesariamente explotarlo. Esta información servirá para identificar vectores de ataque potenciales en las fases posteriores.

## Subdirectorios

```
02-Reconocimiento/
├── README.md                   # Este archivo
├── nmap-results/               # Resultados de escaneos Nmap
└── fingerprinting/             # Fingerprinting de aplicación web
```

## Técnicas MITRE ATT&CK Aplicables

| ID | Técnica | Descripción |
|----|---------|-------------|
| T1046 | Network Service Scanning | Escaneo de puertos y servicios |
| T1595 | Active Scanning | Escaneo activo de vulnerabilidades |
| T1595.002 | Vulnerability Scanning | Escaneo específico de vulnerabilidades |
| T1082 | System Information Discovery | Detección de sistema operativo |
| T1590.002 | Gather Victim Network Information: DNS | Enumeración DNS |
| T1593 | Search Open Websites/Domains | Fingerprinting web |

## 1. Reconocimiento Pasivo

### 1.1. Información Inicial del Target

Para DVWA desplegado en Docker local:

```bash
# Target URL
TARGET="http://localhost:80"

# O usar IP del contenedor
TARGET_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dvwa)
echo "Target IP: $TARGET_IP"
```

### 1.2. Resolución DNS (si aplica)

Para entornos no locales:

```bash
# Resolución básica
host example.com

# Información DNS completa
dig example.com ANY

# Registros específicos
dig example.com A
dig example.com MX
dig example.com TXT
dig example.com NS

# nslookup alternativo
nslookup example.com
```

**Mapeo ATT&CK**: T1590.002 (Gather Victim Network Information: DNS)

## 2. Escaneo de Puertos con Nmap

### 2.1. Escaneo Rápido (Top 1000 puertos)

```bash
nmap -T4 -F $TARGET_IP -oA nmap-results/nmap-quick-scan

# Explicación de opciones:
# -T4: Timing aggressive (más rápido)
# -F: Fast scan (solo top 1000 puertos)
# -oA: Output en todos los formatos (normal, XML, grepable)
```

**Tiempo estimado**: 1-2 minutos

### 2.2. Escaneo Completo de Todos los Puertos

```bash
nmap -p- -T4 $TARGET_IP -oA nmap-results/nmap-full-scan

# -p-: Escanear todos los 65535 puertos
```

**Tiempo estimado**: 10-30 minutos (puede ser más lento)

**Nota**: Para DVWA típicamente solo están abiertos puertos 80 (HTTP) y 3306 (MySQL).

### 2.3. Detección de Servicios y Versiones

```bash
nmap -sV -sC -T4 $TARGET_IP -oA nmap-results/nmap-service-scan

# Explicación:
# -sV: Version detection (detecta versiones de servicios)
# -sC: Scripts por defecto (ejecuta scripts NSE comunes)
```

**Output esperado**:
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.x
3306/tcp open  mysql   MySQL 5.7.x
```

### 2.4. Detección de Sistema Operativo

```bash
sudo nmap -O -T4 $TARGET_IP -oA nmap-results/nmap-os-detection

# -O: OS detection (requiere privilegios root/sudo)
```

**Mapeo ATT&CK**: T1082 (System Information Discovery)

### 2.5. Escaneo de Vulnerabilidades con NSE

```bash
nmap --script vuln -T4 $TARGET_IP -oA nmap-results/nmap-vuln-scan

# --script vuln: Ejecuta todos los scripts de categoría "vuln"
```

Scripts NSE útiles para web:
- `http-sql-injection`
- `http-stored-xss`
- `http-csrf`
- `http-enum` (enumeración de directorios)

**Mapeo ATT&CK**: T1595.002 (Vulnerability Scanning)

### 2.6. Escaneo UDP (Opcional)

```bash
sudo nmap -sU --top-ports 100 -T4 $TARGET_IP -oA nmap-results/nmap-udp-scan

# -sU: UDP scan
# --top-ports 100: Solo los 100 puertos UDP más comunes
```

**Nota**: Los escaneos UDP son más lentos y menos confiables que TCP.

## 3. Fingerprinting de Aplicación Web

### 3.1. Identificación de Tecnologías con WhatWeb

```bash
whatweb -v $TARGET

# -v: Verbose (más información)
```

Guarda el output:
```bash
whatweb -v $TARGET | tee fingerprinting/whatweb-output.txt
```

**Información detectada típicamente**:
- Servidor web (Apache, Nginx, etc.)
- Lenguaje (PHP, Python, etc.)
- Frameworks y CMS
- Librerías JavaScript
- Headers de seguridad (o su ausencia)

### 3.2. Headers HTTP

```bash
# Con curl
curl -I $TARGET | tee fingerprinting/http-headers.txt

# Con nmap
nmap --script http-headers -p 80 $TARGET
```

**Headers importantes a revisar**:
- `Server`: Identifica el servidor web
- `X-Powered-By`: Identifica tecnología backend
- `X-Frame-Options`: Protección clickjacking
- `X-XSS-Protection`: Protección XSS
- `Content-Security-Policy`: CSP
- `Strict-Transport-Security`: HSTS

### 3.3. Robots.txt y Sitemap

```bash
# Verificar robots.txt
curl $TARGET/robots.txt

# Verificar sitemap
curl $TARGET/sitemap.xml
```

**Mapeo ATT&CK**: T1593 (Search Open Websites/Domains)

### 3.4. Detección de WAF/IDS/IPS

```bash
# Con wafw00f (si está instalado)
wafw00f $TARGET

# Instalación si no está disponible
pip install wafw00f
```

Detección manual con curl:
```bash
# Request normal
curl -I $TARGET

# Request con payload sospechoso
curl -I "$TARGET/?id=1' OR 1=1--"

# Si hay WAF, puede haber diferencias en respuesta
```

## 4. Enumeración de Directorios y Archivos

### 4.1. Enumeración Manual de Directorios Comunes

```bash
# Script básico para verificar directorios comunes en DVWA
for dir in admin config includes setup docs security vulnerabilities login; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$dir/")
    echo "$dir: $status"
done
```

### 4.2. Con Gobuster (Enumeración Avanzada)

```bash
# Instalar gobuster si no está disponible
sudo apt-get install gobuster

# Escaneo básico
gobuster dir -u $TARGET -w /usr/share/wordlists/dirb/common.txt -o fingerprinting/gobuster-scan.txt

# Escaneo más agresivo
gobuster dir -u $TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,html -o fingerprinting/gobuster-extended.txt

# Opciones:
# -u: URL target
# -w: Wordlist
# -x: Extensiones de archivo
# -o: Output file
```

### 4.3. Con DirBuster (GUI)

Si prefieres interfaz gráfica:
```bash
dirbuster
```

Configuración recomendada:
- Target: http://localhost:80
- Wordlist: `/usr/share/wordlists/dirb/common.txt`
- Extensions: php, txt, html
- Threads: 10

## 5. Reconocimiento Específico para DVWA

### 5.1. Módulos DVWA

DVWA tiene los siguientes módulos vulnerables:

```
/vulnerabilities/
├── brute/              # Brute Force
├── captcha/            # Insecure CAPTCHA
├── csrf/               # Cross Site Request Forgery
├── exec/               # Command Injection
├── fi/                 # File Inclusion
├── sqli/               # SQL Injection
├── sqli_blind/         # SQL Injection (Blind)
├── upload/             # File Upload
├── weak_id/            # Weak Session IDs
├── xss_d/              # DOM Based XSS
├── xss_r/              # Reflected XSS
└── xss_s/              # Stored XSS
```

### 5.2. Verificar Niveles de Seguridad

DVWA permite configurar 4 niveles de seguridad:
- **Low**: Sin protecciones
- **Medium**: Protecciones básicas
- **High**: Protecciones avanzadas
- **Impossible**: Código seguro (no vulnerable)

Verificar nivel actual:
```bash
# Requiere estar autenticado
curl -b "PHPSESSID=your-session-id" "$TARGET/security.php"
```

### 5.3. Información de la Base de Datos

DVWA usa MySQL. Info de conexión (en modo white box):
- **Host**: db (contenedor Docker)
- **Puerto**: 3306
- **Database**: dvwa
- **Usuario**: dvwa
- **Password**: dvwa_password

## 6. Documentación de Hallazgos

### 6.1. Plantilla de Documentación

Para cada servicio/puerto encontrado:

```markdown
## Puerto XX/TCP - Servicio

- **Estado**: Abierto
- **Servicio**: [nombre del servicio]
- **Versión**: [versión detectada]
- **Banner**: [banner si disponible]
- **Vulnerabilidades potenciales**: [CVEs conocidos]
- **Notas**: [observaciones adicionales]
```

### 6.2. Captura de Evidencias

```bash
# Capturar screenshot de resultados
bash ../07-Scripts/capture-evidence.sh --screenshot recon nmap "full-scan-results" T1046

# Guardar logs
bash ../07-Scripts/capture-evidence.sh --command-log recon nmap "nmap -sV localhost" "$(cat nmap-results/nmap-service-scan.nmap)" T1046
```

## 7. Script de Reconocimiento Automatizado

Para ejecutar todo el reconocimiento de forma automatizada:

```bash
cd /home/suero/Escritorio/SSII/SSII-PAI/PAI_5

# Con logging automático
bash 07-Scripts/logger.sh start reconocimiento
bash 07-Scripts/reconocimiento.sh http://localhost:80
# (escribir 'exit' al terminar para detener logging)

# O sin logging
bash 07-Scripts/reconocimiento.sh http://localhost:80
```

El script ejecuta:
1. Escaneo rápido de puertos
2. Detección de servicios y versiones
3. Escaneo de vulnerabilidades con NSE
4. Fingerprinting web (WhatWeb, headers, robots.txt)
5. Detección de WAF
6. Enumeración DNS (si aplica)

## 8. Análisis de Resultados

### 8.1. Revisar Archivos Nmap

```bash
# Ver resultado en formato normal
less nmap-results/nmap-service-scan.nmap

# Ver resultado en formato XML (más parsing-friendly)
less nmap-results/nmap-service-scan.xml

# Buscar puertos abiertos
grep "open" nmap-results/nmap-service-scan.nmap
```

### 8.2. Identificar Vectores de Ataque

Para cada servicio abierto:
1. ✅ Buscar CVEs conocidos para la versión
2. ✅ Identificar configuraciones inseguras
3. ✅ Documentar posibles vectores de explotación

Ejemplo para Apache 2.4:
```bash
# Buscar exploits con searchsploit
searchsploit apache 2.4

# O consultar Exploit-DB online
xdg-open "https://www.exploit-db.com/search?q=apache+2.4"
```

### 8.3. Priorización de Targets

Para DVWA, los vectores más interesantes son:

1. **Puerto 80 (HTTP)**:
   - SQL Injection
   - Command Injection
   - File Upload
   - XSS
   - CSRF

2. **Puerto 3306 (MySQL)**:
   - Acceso directo a BD (si está expuesto externamente)
   - Brute force de credenciales

## 9. Próximos Pasos

Una vez completado el reconocimiento:

1. ✅ Revisar todos los resultados de escaneos
2. ✅ Documentar servicios y versiones encontradas
3. ✅ Identificar superficie de ataque
4. ✅ Proceder con **Fase de Escaneo de Vulnerabilidades**:

```bash
cd ../03-Escaneo
cat README.md
bash ../07-Scripts/escaneo-vulnerabilidades.sh http://localhost:80
```

## 10. Referencias

- **Nmap Documentation**: https://nmap.org/book/man.html
- **NSE Scripts**: https://nmap.org/nsedoc/
- **WhatWeb**: https://github.com/urbanadventurer/WhatWeb
- **Gobuster**: https://github.com/OJ/gobuster
- **MITRE ATT&CK - Discovery**: https://attack.mitre.org/tactics/TA0007/
- **MITRE ATT&CK - Reconnaissance**: https://attack.mitre.org/tactics/TA0043/

## 11. Checklist de Reconocimiento

- [ ] Escaneo rápido de puertos completado
- [ ] Escaneo de servicios y versiones completado
- [ ] OS detection ejecutado
- [ ] Escaneo de vulnerabilidades NSE ejecutado
- [ ] Fingerprinting web realizado (WhatWeb)
- [ ] Headers HTTP analizados
- [ ] Robots.txt y sitemap verificados
- [ ] WAF/IDS detection realizado
- [ ] Enumeración de directorios completada
- [ ] Módulos DVWA identificados
- [ ] Evidencias capturadas (screenshots, logs)
- [ ] Resultados documentados
- [ ] Vectores de ataque identificados
- [ ] Resumen de reconocimiento generado

---

**Última actualización**: 2024-12-03
**Fase siguiente**: 03-Escaneo (Vulnerability Scanning)
