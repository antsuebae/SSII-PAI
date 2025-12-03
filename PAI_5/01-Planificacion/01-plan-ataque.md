# Plan de Ataque - Red Team PAI-5

## Información del Proyecto

**Organización Cliente**: Entidad pública educativa (simulación académica)
**Proyecto**: PAI-5 - RedTeamPro
**Red Team**: Security Team - Universidad de Sevilla
**Fecha**: Diciembre 2025
**Tipo de Evaluación**: White Box Penetration Testing
**Sistema Objetivo**: DVWA (Damn Vulnerable Web Application)

---

## 1. Resumen Ejecutivo

Este documento establece el plan detallado para la evaluación de seguridad de una aplicación web mediante técnicas de Red Team. El objetivo es identificar, explotar y documentar vulnerabilidades de seguridad en DVWA siguiendo metodologías profesionales (NIST 800-115) y frameworks de clasificación de amenazas (MITRE ATT&CK).

### 1.1. Objetivos del Red Team

1. **Evaluar la postura de seguridad** de la aplicación web DVWA
2. **Identificar vulnerabilidades** críticas, altas, medias y bajas
3. **Demostrar impacto real** mediante explotación controlada
4. **Mapear técnicas** utilizando framework MITRE ATT&CK
5. **Documentar hallazgos** con evidencias reproducibles
6. **Proporcionar recomendaciones** de mitigación y remediación

### 1.2. Alcance del Proyecto

**En Alcance (In-Scope)**:
- Aplicación web DVWA en contenedor Docker
- Todos los módulos de vulnerabilidades DVWA:
  * Brute Force
  * Command Injection
  * CSRF (Cross-Site Request Forgery)
  * File Inclusion
  * File Upload
  * SQL Injection
  * SQL Injection (Blind)
  * Weak Session IDs
  * XSS (DOM)
  * XSS (Reflected)
  * XSS (Stored)
  * CSP Bypass
  * JavaScript
- Base de datos MySQL asociada
- Contenedor Docker y su configuración

**Fuera de Alcance (Out-of-Scope)**:
- Host sistema (Fedora Linux 43 del usuario)
- Otras aplicaciones del sistema
- Red local más allá del bridge Docker
- Ataques de Denegación de Servicio (DoS)
- Ingeniería social
- Ataques físicos

### 1.3. Autorizaciones

**Nota**: Este es un proyecto académico con entorno controlado. En un escenario real, se requeriría:
- Autorización formal por escrito del propietario del sistema
- Alcance claramente definido y aprobado
- Ventana de tiempo específica para las pruebas
- Contactos de emergencia
- Acuerdos de confidencialidad (NDA)

---

## 2. Metodología

### 2.1. Framework: NIST 800-115

Seguiremos la guía técnica NIST SP 800-115 "Technical Guide to Information Security Testing and Assessment":

```
┌─────────────┐      ┌──────────┐      ┌───────────────┐
│ Planificar  │─────>│ Ejecutar │─────>│ Post-Ejecución│
└─────────────┘      └──────────┘      └───────────────┘
       │                   │                    │
       │                   │                    │
       ▼                   ▼                    ▼
   Definir            Técnicas de          Análisis de
   objetivos          evaluación           resultados
   y alcance          y pruebas            e informe
```

**Fases**:
1. **Planificación**: Definir scope, objetivos, herramientas
2. **Ejecución**:
   - Reconocimiento
   - Escaneo de vulnerabilidades
   - Explotación
   - Post-explotación
3. **Post-Ejecución**: Análisis, documentación, informe técnico

### 2.2. Framework: MITRE ATT&CK

Mapearemos todas las técnicas utilizadas al framework [MITRE ATT&CK](https://attack.mitre.org/):

**Tácticas Aplicables**:
- **TA0001 - Initial Access**: Explotación de aplicación web pública
- **TA0002 - Execution**: Ejecución de comandos arbitrarios
- **TA0006 - Credential Access**: Obtención de credenciales
- **TA0007 - Discovery**: Reconocimiento y escaneo
- **TA0010 - Exfiltration**: Extracción de información
- **TA0040 - Impact**: Impacto en confidencialidad/integridad

**Técnicas Específicas** (ver matriz-attack.md para detalle completo):
- T1190: Exploit Public-Facing Application
- T1059: Command and Scripting Interpreter
- T1078: Valid Accounts
- T1110: Brute Force
- T1213: Data from Information Repositories
- etc.

### 2.3. Estándares de Vulnerabilidades

**CVE (Common Vulnerabilities and Exposures)**:
- Identificaremos CVEs asociados a las vulnerabilidades encontradas
- Base de datos: [cve.mitre.org](https://cve.mitre.org)

**CWE (Common Weakness Enumeration)**:
- Clasificaremos debilidades según CWE
- Ejemplos: CWE-89 (SQL Injection), CWE-79 (XSS), CWE-78 (OS Command Injection)

**CVSS (Common Vulnerability Scoring System)**:
- Calcularemos scores CVSS 3.1 para cada hallazgo
- Clasificación: Crítico (9.0-10.0), Alto (7.0-8.9), Medio (4.0-6.9), Bajo (0.1-3.9)

**OWASP Top 10 2021**:
- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)

---

## 3. Fases de Ejecución

### Fase 1: Reconocimiento (Reconnaissance)

**Objetivo**: Recopilar máxima información sobre el objetivo

**Actividades**:
- Identificación de servicios activos (puertos, protocolos)
- Fingerprinting de sistema operativo
- Enumeración de servicios web (servidor, versiones)
- Mapeo de estructura de aplicación
- Identificación de tecnologías utilizadas

**Herramientas**:
- `nmap`: Escaneo de puertos y servicios
- `nikto`: Escáner de vulnerabilidades web
- `whatweb`: Identificación de tecnologías web
- `wafw00f`: Detección de WAF
- Burp Suite: Crawling y spidering

**Técnicas MITRE ATT&CK**:
- T1046: Network Service Scanning
- T1595: Active Scanning

**Entregables**:
- Resultados de nmap (todos los formatos)
- Informe de nikto
- Mapa de aplicación web
- Lista de servicios y versiones

### Fase 2: Escaneo de Vulnerabilidades (Scanning)

**Objetivo**: Identificar vulnerabilidades explotables

**Actividades**:
- Escaneo automatizado de vulnerabilidades web
- Búsqueda de vulnerabilidades OWASP Top 10
- Identificación de configuraciones inseguras
- Análisis de código fuente JavaScript client-side
- Prueba de vectores de inyección

**Herramientas**:
- `nikto`: Escaneo de vulnerabilidades web
- `sqlmap`: Detección de SQL Injection
- `OWASP ZAP`: Escaneo automatizado
- `wapiti`: Web application vulnerability scanner
- Burp Suite Scanner (versión Community)
- `wpscan`, `joomscan` (si aplica)

**Entregables**:
- Reportes de scanners (JSON/HTML/XML)
- Lista priorizada de vulnerabilidades
- Análisis de explotabilidad

### Fase 3: Explotación (Exploitation)

**Objetivo**: Demostrar impacto real de vulnerabilidades

**Actividades por módulo DVWA**:

1. **Brute Force**
   - Ataque de fuerza bruta a formulario de login
   - Técnica: T1110.001 (Password Guessing)
   - Herramienta: Hydra, Burp Intruder

2. **Command Injection**
   - Inyección de comandos del sistema operativo
   - Técnica: T1059.004 (Unix Shell)
   - Herramienta: Manual, Burp Repeater

3. **CSRF**
   - Prueba de concepto de CSRF
   - Técnica: T1659 (Content Injection)
   - Herramienta: Manual, generador de PoC

4. **File Inclusion (LFI/RFI)**
   - Local File Inclusion para leer archivos sensibles
   - Técnica: T1083 (File and Directory Discovery)
   - Herramienta: Manual, Burp

5. **File Upload**
   - Upload de shell PHP malicioso
   - Técnica: T1505.003 (Web Shell)
   - Herramienta: Manual, Weevely

6. **SQL Injection**
   - Extracción de base de datos completa
   - Técnica: T1213 (Data from Information Repositories)
   - Herramienta: sqlmap, manual

7. **SQL Injection (Blind)**
   - Boolean-based blind SQL injection
   - Técnica: T1213
   - Herramienta: sqlmap

8. **XSS (Reflected/Stored/DOM)**
   - Inyección de JavaScript malicioso
   - Técnica: T1059.007 (JavaScript)
   - Herramienta: Manual, XSSer

**Entregables**:
- PoC (Proof of Concept) para cada vulnerabilidad
- Screenshots de explotación exitosa
- Payloads utilizados documentados
- Logs de todas las pruebas

### Fase 4: Post-Explotación (Post-Exploitation)

**Objetivo**: Evaluar alcance del compromiso

**Actividades**:
- Escalada de privilegios en contenedor Docker
- Dump de base de datos MySQL completo
- Búsqueda de información sensible
- Establecimiento de persistencia (backdoor)
- Análisis de movimiento lateral (limitado por scope)
- Evaluación de impacto en CIA (Confidencialidad, Integridad, Disponibilidad)

**Herramientas**:
- `LinPEAS`: Enumeración de escalada de privilegios Linux
- `pspy`: Monitoreo de procesos sin root
- MySQL client para dump
- `netcat`: Shell reversa
- Scripts personalizados

**Técnicas MITRE ATT&CK**:
- T1068: Exploitation for Privilege Escalation
- T1078: Valid Accounts
- T1505: Server Software Component
- T1552: Unsecured Credentials
- T1213: Data from Information Repositories

**Entregables**:
- Evidencia de escalada de privilegios
- Dump de base de datos
- Logs de persistencia
- Análisis de impacto

### Fase 5: Documentación y Reporting

**Objetivo**: Informe técnico profesional completo

**Actividades**:
- Consolidación de todos los hallazgos
- Cálculo de CVSS para cada vulnerabilidad
- Mapeo completo a MITRE ATT&CK
- Recomendaciones de mitigación
- Redacción de informe técnico
- Revisión y validación

**Entregables**:
- Informe Técnico PDF completo (ver plantilla)
- Anexos con logs y evidencias
- Código fuente de scripts desarrollados
- Presentación ejecutiva (opcional)

---

## 4. Controles de Seguridad Esperados

### 4.1. Controles Implementados (Esperado)

DVWA tiene niveles de seguridad configurables:
- **Low**: Sin protecciones (objetivo principal)
- **Medium**: Validaciones básicas
- **High**: Controles avanzados
- **Impossible**: Código seguro (referencia)

### 4.2. Controles Ausentes o Débiles

Lista de controles que se espera encontrar débiles o ausentes:
- Validación de entrada insuficiente
- Sanitización de output inadecuada
- Gestión de sesiones débil
- Ausencia de tokens anti-CSRF
- Sin WAF (Web Application Firewall)
- Sin Rate Limiting
- Errores SQL detallados
- Almacenamiento inseguro de passwords
- Falta de headers de seguridad (CSP, X-Frame-Options, etc.)
- Configuración insegura de PHP

---

## 5. Gestión de Riesgos

### 5.1. Riesgos del Pentesting

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| Caída del servicio DVWA | Baja | Medio | Backup del contenedor, monitoreo continuo |
| Pérdida de datos durante pruebas | Baja | Bajo | Snapshots antes de cada fase |
| Corrupción de base de datos | Media | Medio | Backup de MySQL antes de SQLi |
| Falsos positivos | Alta | Bajo | Validación manual de cada hallazgo |

### 5.2. Contingencias

- **Si DVWA no responde**: Reiniciar contenedor con `docker compose restart`
- **Si BD se corrompe**: Recrear con botón "Setup/Reset DB" en DVWA
- **Si no hay acceso a herramientas**: Usar alternativas open-source
- **Si no se puede instalar Docker**: Usar VirtualBox con VM

---

## 6. Timeline del Proyecto

```
Día 1-2: Setup y Reconocimiento
├─ Despliegue de DVWA
├─ Verificación de entorno
├─ Reconocimiento activo
└─ Documentación inicial

Día 3-4: Escaneo y Análisis
├─ Escaneo automatizado
├─ Análisis manual
├─ Priorización de vectores
└─ Preparación de exploits

Día 5-6: Explotación
├─ SQL Injection
├─ XSS (todos los tipos)
├─ Command Injection
├─ File Upload
├─ Resto de módulos DVWA
└─ Documentación de PoCs

Día 7: Post-Explotación
├─ Escalada de privilegios
├─ Dump de BD
├─ Persistencia
└─ Análisis de impacto

Día 8-9: Documentación
├─ Redacción de informe
├─ Revisión de evidencias
├─ Generación de anexos
└─ Preparación de entregable

Día 10: Entrega
├─ Revisión final
├─ Empaquetado ZIP
└─ Entrega en plataforma
```

**Fecha límite**: 16 de diciembre 2025, 23:59h

---

## 7. Equipo y Responsabilidades

**Red Team**:
- Pentester Lead: Responsable de ejecución y coordinación
- Documentador: Captura de evidencias y redacción
- Revisor: Quality Assurance de hallazgos

**Nota**: En este proyecto académico, una sola persona puede asumir todos los roles.

---

## 8. Herramientas y Entorno

### 8.1. Entorno de Pentesting

**Sistema Operador**: Kali Linux 2024.x
**Ubicación**: VM o instalación nativa
**Requisitos mínimos**:
- 4GB RAM
- 20GB disco
- Conectividad de red
- Docker instalado

### 8.2. Herramientas Principales

**Reconocimiento**:
- nmap 7.94+
- nikto 2.5.0+
- whatweb
- wafw00f

**Escaneo**:
- OWASP ZAP
- Burp Suite Community
- sqlmap 1.7+
- wapiti

**Explotación**:
- Metasploit Framework
- Manual exploitation
- Custom scripts

**Post-Explotación**:
- LinPEAS
- pspy
- netcat
- Docker CLI

**Documentación**:
- scrot / gnome-screenshot
- asciinema
- script (command logging)
- Markdown editors

---

## 9. Criterios de Éxito

El proyecto será considerado exitoso si:

✅ DVWA está desplegado y funcionando correctamente
✅ Todas las 5 fases de pentesting están completadas
✅ Al menos 8 vulnerabilidades diferentes han sido explotadas
✅ Cada hallazgo tiene evidencia (screenshot + logs)
✅ Todas las técnicas están mapeadas a MITRE ATT&CK
✅ El informe técnico está completo y profesional
✅ Todo es reproducible siguiendo la documentación
✅ El entregable cumple con requisitos del enunciado

---

## 10. Referencias

- [NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CVE Database](https://cve.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [DVWA GitHub](https://github.com/digininja/DVWA)

---

**Documento aprobado por**: Red Team Lead
**Fecha de aprobación**: Inicio del proyecto
**Versión**: 1.0
**Próxima revisión**: Post-ejecución

---

## Apéndice A: Checklist de Preparación

- [ ] Docker y Docker Compose instalados
- [ ] DVWA desplegado y accesible
- [ ] Herramientas de Kali verificadas
- [ ] Estructura de directorios creada
- [ ] Scripts de logging preparados
- [ ] Captura de evidencias configurada
- [ ] Backup inicial de DVWA realizado
- [ ] Plan de ataque revisado y aprobado

## Apéndice B: Contactos de Emergencia

**Nota**: En un proyecto real, incluir:
- Contacto técnico del cliente
- Contacto de seguridad
- Contacto de emergencia 24/7
- Procedimientos de escalación
