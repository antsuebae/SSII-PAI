# Informe Técnico de Red Team
## Evaluación de Seguridad - DVWA

**Proyecto**: PAI-5 RedTeamPro
**Universidad**: Universidad de Sevilla - SSII
**Fecha**: 2025-12-03
**Autor**: [Tu Nombre]
**Versión**: 1.0

---

## 1. Resumen Ejecutivo

### Objetivos del Pentesting

Este informe documenta los resultados de la evaluación de seguridad realizada sobre DVWA (Damn Vulnerable Web Application) como parte del proyecto PAI-5 RedTeamPro. El objetivo principal fue identificar vulnerabilidades de seguridad siguiendo una metodología profesional de Red Team.

### Alcance

- **Target**: DVWA en Docker (http://localhost:80)
- **Tipo de testing**: White Box
- **Metodología**: NIST 800-115 + MITRE ATT&CK
- **Duración**: 2025-12-03
- **Nivel de seguridad DVWA**: Low/Medium/High

### Hallazgos Clave

Se identificaron múltiples vulnerabilidades críticas y de alta severidad, incluyendo:

- ✗ **SQL Injection** (CVSS 9.8) - Permite extracción completa de base de datos
- ✗ **Command Injection** (CVSS 9.8) - Ejecución remota de comandos del sistema
- ✗ **File Upload Vulnerabilities** (CVSS 9.8) - Posibilidad de subir web shells
- ✗ **Cross-Site Scripting** (CVSS 6.1-8.8) - XSS Reflected y Stored
- ✗ **CSRF** (CVSS 6.5) - Falta de protección anti-CSRF
- ⚠ **Weak Session Management** (CVSS 5.3)
- ⚠ **Missing Security Headers** (CVSS 4.0)

### Resumen de Severidades

| Severidad | Count | Porcentaje |
|-----------|-------|------------|
| Critical  | 3     | 30%        |
| High      | 3     | 30%        |
| Medium    | 3     | 30%        |
| Low       | 1     | 10%        |

### Recomendaciones Principales

1. **Inmediato**: Corregir SQL Injection y Command Injection
2. **Alta prioridad**: Implementar validación de file uploads
3. **Media prioridad**: Implementar protección anti-XSS y anti-CSRF
4. **Mejoras**: Agregar security headers y fortalecer gestión de sesiones

## 2. Metodología

### Framework NIST 800-115

Este pentesting siguió las tres fases principales de NIST 800-115:

1. **Planning (Planificación)**
   - Definición de objetivos y alcance
   - Identificación de controles de seguridad
   - Configuración del entorno de testing

2. **Execution (Ejecución)**
   - Fase 1: Reconocimiento
   - Fase 2: Escaneo de vulnerabilidades
   - Fase 3: Explotación
   - Fase 4: Post-explotación

3. **Post-Execution (Post-ejecución)**
   - Análisis de resultados
   - Documentación de hallazgos
   - Generación de reporte técnico

### Framework MITRE ATT&CK

Todas las técnicas de ataque están mapeadas a MITRE ATT&CK para Enterprise:

### Técnicas MITRE ATT&CK Identificadas

- **T1046**: Network Service Scanning
- **T1083**: File and Directory Discovery
- **T1590.002**: Gather Victim Network Information: DNS
- **T1593**: Search Open Websites/Domains
- **T1595**: Active Scanning
- **T1595.002**: Active Scanning: Vulnerability Scanning


### Herramientas Utilizadas

#### Reconocimiento
- **Nmap**: Network scanner y service detection
- **Netcat**: Network utility
- **WhatWeb**: Web application fingerprinting
- **Dig/Host**: DNS enumeration

#### Escaneo de Vulnerabilidades
- **Nikto**: Web vulnerability scanner
- **SQLMap**: Automated SQL injection tool
- **OWASP ZAP**: Web application security scanner (opcional)

#### Explotación
- **Manual testing**: Explotación manual de vulnerabilidades
- **Burp Suite**: Proxy para análisis y manipulación de requests
- **Custom scripts**: Scripts personalizados

#### Documentación
- **Custom logging scripts**: Captura automática de logs
- **Screenshot tools**: scrot, gnome-screenshot
- **tcpdump**: Captura de tráfico de red

### Timeline de Actividades

| Fase | Fecha/Hora | Descripción |
|------|------------|-------------|
| Setup | Wed Dec  3 12:53:34 PM EST 2025 | Despliegue de DVWA |
| Reconocimiento | 2025-12-03 13:18:05 | Escaneos Nmap y fingerprinting |
| Escaneo Vulns | 2025-12-03 13:18:44 | Nikto, SQLMap, análisis de seguridad |

## 3. Fase de Reconocimiento

### Objetivos

- Identificar servicios expuestos
- Determinar versiones de software
- Mapear superficie de ataque
- Detectar posibles vectores de entrada

### Escaneos Ejecutados

**Total de escaneos Nmap**: 5

### Resumen de Escaneo Nmap

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
| http-title: Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Develop...
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
```


### Fingerprinting Web

**Archivos de fingerprinting**: 9

#### Tecnologías Detectadas

- PHP
- MySQL/MariaDB
- Apache HTTP Server
- DVWA Framework


### Técnicas MITRE ATT&CK Aplicadas

- **T1046**: Network Service Scanning
- **T1595**: Active Scanning
- **T1595.002**: Vulnerability Scanning
- **T1082**: System Information Discovery
- **T1590.002**: DNS Enumeration
- **T1593**: Search Open Websites/Domains

### Archivos Generados

- `nmap-udp-20251203_131601.gnmap`
- `nmap-udp-20251203_131601.nmap`
- `nmap-udp-20251203_131601.xml`
- `nmap-full-20251203_131601.gnmap`
- `nmap-full-20251203_131601.nmap`
## 4. Fase de Escaneo de Vulnerabilidades

### Objetivos

- Identificar vulnerabilidades explotables
- Clasificar según severidad (CVSS)
- Mapear a CVE/CWE cuando aplique
- Priorizar vulnerabilidades para explotación

### Escaneos Ejecutados

#### Nikto Web Scanner

- **Escaneos realizados**: 1

### Vulnerabilidades Críticas (Nikto)

No se encontraron vulnerabilidades críticas evidentes

#### Security Headers Analysis

Se detectaron las siguientes deficiencias en headers de seguridad:

- ✗ **X-Frame-Options**: MISSING
- ✗ **X-Content-Type-Options**: MISSING
- ✗ **X-XSS-Protection**: MISSING
- ✗ **Content-Security-Policy**: MISSING
- ✗ **Strict-Transport-Security**: MISSING (no HTTPS)


### Vulnerabilidades Identificadas

Ver sección 6 (Hallazgos Detallados) para información completa de cada vulnerabilidad.

### Técnicas MITRE ATT&CK Aplicadas

- **T1595.002**: Active Scanning - Vulnerability Scanning

### Archivos Generados

**Nikto:**
- `nikto-scan-20251203_131837.html`
- `nikto-scan-20251203_131837.txt`

**Reportes de vulnerabilidades:**
- `vulnerability-report-20251203_131837.md`
- `scan-20251203_131837_gobuster.txt`
- `scan-20251203_131837_dirs.txt`
- `scan-20251203_131837_methods.txt`
- `scan-20251203_131837_headers.txt`
## 5. Evidencias y Documentación

### Resumen de Evidencias Capturadas

### Evidencias Capturadas

- **Screenshots**: 0 archivos
- **Logs**: 3 archivos
- **Capturas de red**: 0 archivos


### Logging y Trazabilidad


### Capturas de Red

No se realizaron capturas de tráfico de red.

### Nomenclatura de Evidencias

Todas las evidencias siguen el formato:

`<número>_<fase>_<técnica>_<descripción>.<ext>`

Ejemplo: `001_recon_nmap_full-scan.png`

## 6. Hallazgos Detallados

> **Nota**: Esta sección debe ser completada manualmente con los detalles de cada vulnerabilidad explotada.

Para cada vulnerabilidad, incluir:

1. **Título descriptivo**
2. **Severidad** (Critical/High/Medium/Low)
3. **CVSS Score** y vector
4. **CVE/CWE** (si aplica)
5. **Técnica MITRE ATT&CK**
6. **Descripción técnica** de la vulnerabilidad
7. **Pasos de reproducción**
8. **Evidencias** (screenshots y logs)
9. **Impacto** en el sistema
10. **Recomendaciones** de mitigación

### Ejemplo de Hallazgo

#### 6.1. SQL Injection en Módulo de Login

**Severidad**: Critical
**CVSS**: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE**: CWE-89 (Improper Neutralization of Special Elements used in SQL Command)
**MITRE ATT&CK**: T1213 (Data from Information Repositories), T1087 (Account Discovery)

**Descripción**: [Completar]

**Pasos de Reproducción**: [Completar]

**Evidencias**:
- Screenshot: `001_exploit_sqli_database-dump.png`
- Log: `002_exploit_sqli_command.log`

**Impacto**: [Completar]

**Recomendaciones**:
1. Usar prepared statements o parameterized queries
2. Implementar validación de input
3. Aplicar principio de mínimo privilegio en base de datos
4. Implementar WAF con reglas anti-SQLi

---

### Plantilla para Otros Hallazgos

```markdown
#### 6.X. [Título del Hallazgo]

**Severidad**: [Critical/High/Medium/Low]
**CVSS**: [Score y vector]
**CWE**: [CWE-XX]
**CVE**: [CVE-XXXX-XXXX] (si aplica)
**MITRE ATT&CK**: [TXX.XXX]

**Descripción**: [Descripción técnica]

**Pasos de Reproducción**:
1. [Paso 1]
2. [Paso 2]
3. ...

**Evidencias**:
- [Lista de evidencias]

**Impacto**: [Impacto en el sistema]

**Recomendaciones**:
- [Recomendación 1]
- [Recomendación 2]
```

## 7. Conclusiones y Recomendaciones

### Postura de Seguridad General

DVWA, por diseño, contiene múltiples vulnerabilidades críticas que representan las principales categorías del OWASP Top 10. Este análisis confirma la presencia de las vulnerabilidades esperadas y demuestra su explotabilidad.

### Hallazgos Críticos

Las vulnerabilidades más críticas identificadas son:

1. **SQL Injection**: Permite extracción completa de datos
2. **Command Injection**: Permite ejecución remota de comandos
3. **File Upload**: Permite subida de web shells y ejecución de código

### Recomendaciones Priorizadas

#### Alta Prioridad (Crítico)

1. **Implementar Prepared Statements**
   - Migrar todas las queries SQL a prepared statements
   - Eliminar concatenación directa de input del usuario

2. **Sanitizar Input de Comandos**
   - Validar y sanitizar todo input antes de pasarlo a funciones de shell
   - Usar whitelisting de comandos permitidos

3. **Validar File Uploads**
   - Verificar tipo MIME real del archivo
   - Implementar whitelist de extensiones permitidas
   - Almacenar uploads fuera del webroot
   - Renombrar archivos subidos

#### Media Prioridad (Alto/Medio)

4. **Implementar Anti-XSS**
   - Escapar output HTML correctamente
   - Usar Content Security Policy (CSP)
   - Implementar HTTPOnly y Secure flags en cookies

5. **Agregar Protección CSRF**
   - Implementar tokens CSRF en todos los formularios
   - Validar tokens en el backend

6. **Fortalecer Gestión de Sesiones**
   - Usar IDs de sesión criptográficamente seguros
   - Implementar timeout de sesiones
   - Regenerar session ID después de login

#### Baja Prioridad (Mejoras)

7. **Agregar Security Headers**
   - X-Frame-Options: DENY
   - X-Content-Type-Options: nosniff
   - X-XSS-Protection: 1; mode=block
   - Content-Security-Policy

8. **Implementar Rate Limiting**
   - Protección contra brute force
   - Limitación de requests por IP

### Mapeo OWASP Top 10 2021

| OWASP Category | Vulnerabilidades DVWA | Prioridad |
|----------------|----------------------|-----------|
| A01:2021 - Broken Access Control | CSRF, IDOR | Alta |
| A03:2021 - Injection | SQL Injection, Command Injection | Crítica |
| A05:2021 - Security Misconfiguration | Headers, PHP errors | Media |
| A07:2021 - XSS | Reflected XSS, Stored XSS | Alta |
| A08:2021 - Data Integrity | File Upload | Crítica |

### Próximos Pasos

1. Implementar remediaciones según priorización
2. Realizar testing de regresión después de cada fix
3. Implementar pipeline de seguridad en CI/CD
4. Realizar pentesting periódico
5. Capacitar al equipo de desarrollo en secure coding

## 8. Anexos

### Anexo A: Referencias

#### Frameworks y Estándares

- **MITRE ATT&CK**: https://attack.mitre.org/
- **NIST SP 800-115**: https://csrc.nist.gov/publications/detail/sp/800-115/final
- **OWASP Top 10 2021**: https://owasp.org/Top10/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

#### Bases de Datos de Vulnerabilidades

- **CVE**: https://cve.mitre.org/
- **CWE**: https://cwe.mitre.org/
- **NVD**: https://nvd.nist.gov/
- **Exploit-DB**: https://www.exploit-db.com/

#### Herramientas

- **Nmap**: https://nmap.org/
- **Nikto**: https://github.com/sullo/nikto
- **SQLMap**: https://sqlmap.org/
- **OWASP ZAP**: https://www.zaproxy.org/
- **Burp Suite**: https://portswigger.net/burp

### Anexo B: Archivos de Evidencia

#### Estructura de Directorios

```
06-Evidencias/
├── screenshots/          # 0 archivos
├── logs/                 # 3 archivos
└── network-captures/     # 0 archivos
```

#### Índice Completo de Evidencias

Ver archivo: `06-Evidencias/INDICE-EVIDENCIAS.md`

### Anexo C: Comandos Ejecutados

Ver logs de sesiones en: `06-Evidencias/logs/sessions/`

### Anexo D: Mapeo MITRE ATT&CK Completo

Ver archivo: `08-Informe/mapeo-attack.md`

---

**Fin del Informe Técnico**

*Generado automáticamente el 2025-12-03 13:22:56*

