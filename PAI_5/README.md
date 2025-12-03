# PAI-5: RedTeamPro - Evaluación de Seguridad DVWA

[![Universidad de Sevilla](https://img.shields.io/badge/Universidad-Sevilla-red.svg)](https://www.us.es/)
[![DVWA](https://img.shields.io/badge/Target-DVWA-orange.svg)](https://github.com/digininja/DVWA)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-blue.svg)](https://attack.mitre.org/)
[![NIST 800-115](https://img.shields.io/badge/Standard-NIST%20800--115-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-115/final)

> **Proyecto de Red Team profesional** siguiendo metodología NIST 800-115 y framework MITRE ATT&CK para evaluación de seguridad de aplicaciones web vulnerables.

## 📋 Tabla de Contenidos

- [Descripción del Proyecto](#descripción-del-proyecto)
- [Principios del Proyecto](#principios-del-proyecto)
- [Arquitectura y Estructura](#arquitectura-y-estructura)
- [Requisitos Previos](#requisitos-previos)
- [Instalación y Setup](#instalación-y-setup)
- [Uso del Proyecto](#uso-del-proyecto)
- [Fases de Pentesting](#fases-de-pentesting)
- [Scripts de Automatización](#scripts-de-automatización)
- [Metodología](#metodología)
- [Evidencias y Documentación](#evidencias-y-documentación)
- [Generación del Informe](#generación-del-informe)
- [Entrega del Proyecto](#entrega-del-proyecto)
- [Referencias y Recursos](#referencias-y-recursos)
- [Licencia y Ética](#licencia-y-ética)

## 🎯 Descripción del Proyecto

**PAI-5 RedTeamPro** es un proyecto académico de evaluación de seguridad mediante técnicas de Red Team aplicadas a DVWA (Damn Vulnerable Web Application). El proyecto implementa un enfoque profesional y realista de pentesting siguiendo estándares de la industria.

### Características Principales

- ✅ **Metodología profesional**: NIST 800-115 (Technical Guide to Information Security Testing)
- ✅ **Framework de tácticas**: MITRE ATT&CK para mapeo de técnicas
- ✅ **Automatización completa**: Scripts para logging, escaneo y generación de evidencias
- ✅ **Documentación exhaustiva**: Guías paso a paso para cada fase
- ✅ **Informe técnico**: Plantilla profesional siguiendo estándares de Red Team
- ✅ **Reproducibilidad total**: Todo el proceso está documentado y automatizado

### Objetivo Académico

Este proyecto forma parte de la asignatura **Seguridad en Sistemas de Información (SSII)** de la Universidad de Sevilla, con el propósito de:

1. Comprender el ciclo completo de un pentesting profesional
2. Aplicar frameworks y metodologías de la industria
3. Documentar hallazgos con rigor técnico
4. Practicar explotación ética en entornos controlados
5. Generar informes ejecutivos y técnicos de calidad

## 🚀 Principios del Proyecto

### "No Toy Pentesting"

Este proyecto se basa en el principio de **profesionalismo y realismo**:

- ❌ NO usar exploits sin entender el contexto
- ❌ NO ejecutar herramientas sin analizar resultados
- ❌ NO documentar sin rigor técnico
- ❌ NO omitir fases del pentesting

- ✅ SÍ seguir metodologías estándar de la industria
- ✅ SÍ mapear todas las técnicas a MITRE ATT&CK
- ✅ SÍ documentar exhaustivamente cada hallazgo
- ✅ SÍ generar evidencias reproducibles
- ✅ SÍ escribir informes de calidad profesional

## 📁 Arquitectura y Estructura

```
PAI_5/
├── 01-Planificacion/              # Fase de Planificación
│   ├── 00-setup-environment.sh    # Script de setup automatizado
│   ├── 01-plan-ataque.md          # Plan de ataque detallado
│   ├── 02-matriz-attack.md        # Matriz MITRE ATT&CK
│   ├── docker-compose.yml         # Configuración DVWA
│   └── dvwa-info.txt              # Info de despliegue (generado)
│
├── 02-Reconocimiento/             # Fase 1: Reconnaissance
│   ├── README.md                  # Guía de reconocimiento
│   ├── nmap-results/              # Resultados de escaneos nmap
│   └── fingerprinting/            # Fingerprinting de servicios
│
├── 03-Escaneo/                    # Fase 2: Vulnerability Scanning
│   ├── README.md                  # Guía de escaneo
│   ├── vulnerability-reports/     # Reportes de vulnerabilidades
│   ├── nikto-output/              # Salidas de Nikto
│   └── sqlmap-output/             # Resultados de SQLMap
│
├── 04-Explotacion/                # Fase 3: Exploitation
│   ├── README.md                  # Guía de explotación
│   ├── exploits-used/             # Exploits ejecutados
│   └── payloads/                  # Payloads utilizados
│
├── 05-Post-Explotacion/           # Fase 4: Post-Exploitation
│   ├── README.md                  # Guía de post-explotación
│   ├── privilege-escalation/      # Técnicas de escalada
│   └── persistence/               # Mecanismos de persistencia
│
├── 06-Evidencias/                 # Evidencias del Pentesting
│   ├── README.md                  # Guía de captura de evidencias
│   ├── screenshots/               # Capturas de pantalla
│   ├── logs/                      # Logs de comandos y salidas
│   └── network-captures/          # Capturas de tráfico (PCAP)
│
├── 07-Scripts/                    # Scripts de Automatización
│   ├── README.md                  # Documentación de scripts
│   ├── logger.sh                  # Logging automático
│   ├── reconocimiento.sh          # Reconocimiento automatizado
│   ├── escaneo-vulnerabilidades.sh # Escaneo automatizado
│   ├── capture-evidence.sh        # Captura de evidencias
│   ├── mapeo-attack.py            # Mapeo a ATT&CK
│   ├── generar-informe.sh         # Generador de informe
│   ├── utils.sh                   # Funciones comunes
│   └── .env                       # Variables de entorno (generado)
│
├── 08-Informe/                    # Informe Técnico Final
│   ├── informe-tecnico-template.md # Plantilla de informe
│   ├── generate-latex.sh          # Generador LaTeX
│   ├── referencias.bib            # Referencias bibliográficas
│   └── Informe-Tecnico-Final.pdf  # Informe final (generado)
│
├── CLAUDE.md                      # Documentación para Claude Code
└── README.md                      # Este archivo
```

## 🔧 Requisitos Previos

### Sistema Operativo

- **Recomendado**: Kali Linux 2023.x o superior
- **Alternativas**: Debian 11+, Ubuntu 22.04+, Fedora 38+

### Herramientas Esenciales

**Obligatorias**:
- Docker (20.10+) y Docker Compose (2.0+)
- Bash shell (versión 4.0+)
- Python 3.9+
- curl / wget
- git

**Herramientas de Pentesting** (instaladas en Kali por defecto):
- `nmap` - Network scanner
- `nikto` - Web vulnerability scanner
- `sqlmap` - SQL injection tool
- `hydra` - Password cracker
- `john` - Password cracker (John the Ripper)
- `netcat` - Network utility
- `burpsuite` - Web security testing (opcional)
- `zaproxy` - OWASP ZAP (opcional)
- `metasploit-framework` - Exploitation framework (opcional)

### Verificar Instalación

```bash
# Verificar versiones
docker --version
docker compose version
python3 --version
nmap --version
```

## 🚀 Instalación y Setup

### Método 1: Setup Automatizado (Recomendado)

```bash
# 1. Clonar o descomprimir el proyecto
cd /home/suero/Escritorio/SSII/SSII-PAI/PAI_5

# 2. Ejecutar script de setup
bash 01-Planificacion/00-setup-environment.sh

# 3. Si se requiere, aplicar permisos de grupo Docker
newgrp docker

# 4. Verificar que DVWA esté corriendo
docker compose -f 01-Planificacion/docker-compose.yml ps
```

El script automáticamente:
- ✅ Detecta tu distribución Linux
- ✅ Instala Docker y Docker Compose si es necesario
- ✅ Configura permisos de usuario para Docker
- ✅ Despliega DVWA en contenedores
- ✅ Verifica herramientas de pentesting
- ✅ Crea estructura de directorios
- ✅ Genera archivos de configuración

### Método 2: Setup Manual

```bash
# 1. Instalar Docker (Kali Linux)
sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# 2. Configurar usuario para Docker
sudo usermod -aG docker $USER
newgrp docker

# 3. Iniciar servicio Docker
sudo systemctl start docker
sudo systemctl enable docker

# 4. Desplegar DVWA
cd 01-Planificacion
docker compose up -d

# 5. Verificar despliegue
docker compose ps
curl http://localhost:80
```

### Acceso a DVWA

Una vez desplegado:

- **URL**: http://localhost:80 o http://172.20.0.3
- **Usuario**: `admin`
- **Password**: `password`

**Primeros pasos en DVWA**:
1. Acceder a la URL
2. Hacer clic en "Create / Reset Database"
3. Login con credenciales por defecto
4. Configurar nivel de seguridad en "DVWA Security"

## 💻 Uso del Proyecto

### Workflow Completo

```bash
# 1. Setup inicial (solo una vez)
bash 01-Planificacion/00-setup-environment.sh

# 2. Fase de Reconocimiento
cd 02-Reconocimiento
# Seguir instrucciones en README.md
bash ../07-Scripts/reconocimiento.sh

# 3. Fase de Escaneo
cd ../03-Escaneo
# Seguir instrucciones en README.md
bash ../07-Scripts/escaneo-vulnerabilidades.sh

# 4. Fase de Explotación
cd ../04-Explotacion
# Seguir instrucciones en README.md
# (Manual con guía detallada)

# 5. Fase de Post-Explotación
cd ../05-Post-Explotacion
# Seguir instrucciones en README.md

# 6. Generar informe final
bash 07-Scripts/generar-informe.sh
```

### Comandos Docker Útiles

```bash
# Ver estado de contenedores
docker compose -f 01-Planificacion/docker-compose.yml ps

# Ver logs de DVWA
docker compose -f 01-Planificacion/docker-compose.yml logs -f dvwa

# Detener DVWA
docker compose -f 01-Planificacion/docker-compose.yml down

# Reiniciar DVWA
docker compose -f 01-Planificacion/docker-compose.yml restart

# Resetear completamente DVWA
docker compose -f 01-Planificacion/docker-compose.yml down -v
docker compose -f 01-Planificacion/docker-compose.yml up -d
```

## 🎯 Fases de Pentesting

### Fase 0: Planificación

- **Objetivo**: Definir scope, objetivos y metodología
- **Archivos clave**: `01-Planificacion/01-plan-ataque.md`
- **Duración estimada**: 1-2 días

### Fase 1: Reconocimiento

- **Objetivo**: Recopilar información sobre el objetivo
- **Técnicas**: Port scanning, service enumeration, OS fingerprinting
- **Herramientas**: nmap, netdiscover, whatweb, nikto
- **MITRE ATT&CK**: T1046 (Network Service Scanning), T1595 (Active Scanning)
- **Guía**: `02-Reconocimiento/README.md`

### Fase 2: Escaneo de Vulnerabilidades

- **Objetivo**: Identificar vulnerabilidades explotables
- **Técnicas**: Web vulnerability scanning, SQL injection detection
- **Herramientas**: nikto, OWASP ZAP, sqlmap, Burp Suite
- **MITRE ATT&CK**: T1595 (Active Scanning)
- **Guía**: `03-Escaneo/README.md`

### Fase 3: Explotación

- **Objetivo**: Explotar vulnerabilidades identificadas
- **Técnicas**: SQL Injection, XSS, Command Injection, File Upload, CSRF
- **Herramientas**: sqlmap, Metasploit, exploits manuales
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1059 (Command Injection)
- **Guía**: `04-Explotacion/README.md`

### Fase 4: Post-Explotación

- **Objetivo**: Mantener acceso y escalar privilegios
- **Técnicas**: Privilege escalation, persistence, lateral movement
- **Herramientas**: LinPEAS, pspy, custom scripts
- **MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation), T1053 (Scheduled Task)
- **Guía**: `05-Post-Explotacion/README.md`

### Fase 5: Reporte

- **Objetivo**: Documentar hallazgos y recomendaciones
- **Entregables**: Informe técnico completo en PDF
- **Plantilla**: `08-Informe/informe-tecnico-template.md`

## 🤖 Scripts de Automatización

### logger.sh - Logging Automático

Captura automáticamente todos los comandos ejecutados y sus salidas.

```bash
# Iniciar sesión con logging
bash 07-Scripts/logger.sh start "reconocimiento"

# Ejecutar comandos (se loggean automáticamente)
nmap -sV localhost

# Finalizar sesión
bash 07-Scripts/logger.sh stop
```

### reconocimiento.sh - Reconocimiento Automatizado

Ejecuta múltiples tipos de escaneos nmap y fingerprinting.

```bash
bash 07-Scripts/reconocimiento.sh http://localhost:80
```

### escaneo-vulnerabilidades.sh - Escaneo Automatizado

Ejecuta nikto, sqlmap y otros scanners automáticamente.

```bash
bash 07-Scripts/escaneo-vulnerabilidades.sh http://localhost:80
```

### capture-evidence.sh - Captura de Evidencias

Captura screenshots, logs y tráfico de red automáticamente.

```bash
bash 07-Scripts/capture-evidence.sh --screenshot "sql-injection-success"
bash 07-Scripts/capture-evidence.sh --pcap "attack-traffic"
```

### mapeo-attack.py - Mapeo a MITRE ATT&CK

Mapea vulnerabilidades encontradas a técnicas ATT&CK.

```bash
python3 07-Scripts/mapeo-attack.py --input 03-Escaneo/vulnerability-reports/
```

### generar-informe.sh - Generador de Informe

Recopila toda la información y genera el informe final.

```bash
bash 07-Scripts/generar-informe.sh
```

## 📚 Metodología

### NIST 800-115: Technical Guide to Information Security Testing

Este proyecto sigue las tres fases principales de NIST 800-115:

1. **Planning**: Definición de objetivos, scope y reglas de engagement
2. **Execution**: Reconocimiento, escaneo, explotación y post-explotación
3. **Post-Execution**: Análisis de resultados y reporte

### MITRE ATT&CK Framework

Todas las técnicas están mapeadas al framework ATT&CK:

- **Reconnaissance**: Técnicas de recopilación de información
- **Initial Access**: T1190 (Exploit Public-Facing Application)
- **Execution**: T1059 (Command and Scripting Interpreter)
- **Persistence**: T1543 (Create or Modify System Process)
- **Privilege Escalation**: T1068 (Exploitation for Privilege Escalation)
- **Credential Access**: T1110 (Brute Force), T1555 (Credentials from Password Stores)
- **Discovery**: T1046 (Network Service Scanning), T1087 (Account Discovery)
- **Collection**: T1213 (Data from Information Repositories)
- **Exfiltration**: T1041 (Exfiltration Over C2 Channel)

**Consultar**: `01-Planificacion/02-matriz-attack.md` para el mapeo completo.

### OWASP Top 10 2021

Las vulnerabilidades de DVWA cubren varias categorías del OWASP Top 10:

- **A01:2021 - Broken Access Control**: IDOR, CSRF
- **A03:2021 - Injection**: SQL Injection, Command Injection
- **A05:2021 - Security Misconfiguration**: Exposición de información
- **A07:2021 - Identification and Authentication Failures**: Brute force
- **A08:2021 - Software and Data Integrity Failures**: Insecure deserialization

## 📸 Evidencias y Documentación

### Captura de Evidencias

Toda evidencia se organiza en `06-Evidencias/`:

```
06-Evidencias/
├── screenshots/           # Capturas de pantalla
│   ├── 001_recon_nmap.png
│   ├── 002_sqli_success.png
│   └── 003_shell_access.png
│
├── logs/                  # Logs de comandos
│   ├── reconocimiento.log
│   ├── explotacion-sqli.log
│   └── post-explotacion.log
│
└── network-captures/      # Capturas de red
    ├── initial-scan.pcap
    └── exploitation.pcap
```

### Nomenclatura de Archivos

**Screenshots**:
```
<número>_<fase>_<técnica>_<descripción>.png

Ejemplos:
001_recon_nmap_full_scan.png
002_exploit_sqli_user_dump.png
003_postexp_shell_whoami.png
```

**Logs**:
```
<fase>-<técnica>-<fecha>.log

Ejemplos:
reconocimiento-nmap-2024-12-03.log
explotacion-sqli-2024-12-03.log
```

**Capturas de red**:
```
<fase>-<descripción>-<fecha>.pcap

Ejemplos:
recon-initial-scan-2024-12-03.pcap
exploit-sql-injection-2024-12-03.pcap
```

## 📝 Generación del Informe

### Usar Plantilla

1. Copiar plantilla base:
```bash
cp 08-Informe/informe-tecnico-template.md 08-Informe/Informe-Tecnico-PAI5.md
```

2. Completar secciones con información recopilada

3. Generar PDF (si tienes pandoc/LaTeX):
```bash
bash 08-Informe/generate-latex.sh
```

### Estructura del Informe

El informe debe incluir:

1. **Resumen Ejecutivo** (1-2 páginas)
   - Objetivos del pentesting
   - Hallazgos críticos
   - Recomendaciones principales

2. **Metodología** (2-3 páginas)
   - Frameworks utilizados (NIST 800-115, MITRE ATT&CK)
   - Herramientas empleadas
   - Timeline de actividades

3. **Fases de Pentesting** (10-15 páginas)
   - Planificación
   - Reconocimiento
   - Escaneo de vulnerabilidades
   - Explotación
   - Post-explotación

4. **Hallazgos Detallados** (5-10 páginas)
   - Para cada vulnerabilidad:
     * Descripción técnica
     * Severidad (CVSS)
     * CVE/CWE
     * Técnica MITRE ATT&CK
     * Evidencias (screenshots)
     * Pasos de reproducción
     * Impacto
     * Recomendaciones de mitigación

5. **Conclusiones y Recomendaciones** (2-3 páginas)

6. **Anexos**
   - Logs completos
   - Comandos ejecutados
   - Referencias

## 📦 Entrega del Proyecto

### Formato de Entrega

**Archivo**: `PA5-ST<NUM>.zip`

**Ejemplo**: `PA5-ST01.zip`

### Contenido del ZIP

```bash
# Crear archivo de entrega
cd /home/suero/Escritorio/SSII/SSII-PAI/

# Comprimir proyecto
zip -r PA5-ST01.zip PAI_5/ \
  -x "PAI_5/.git/*" \
  -x "PAI_5/06-Evidencias/screenshots/.gitkeep" \
  -x "PAI_5/*.tmp"
```

### Checklist de Entrega

- [ ] Informe técnico completo en PDF (`08-Informe/Informe-Tecnico-Final.pdf`)
- [ ] Todos los scripts implementados y funcionales
- [ ] Evidencias organizadas en `06-Evidencias/`
- [ ] Logs de todas las fases
- [ ] Plan de ataque y matriz ATT&CK completos
- [ ] README.md actualizado con instrucciones
- [ ] Código fuente de scripts comentado
- [ ] Referencias bibliográficas incluidas
- [ ] CLAUDE.md con contexto para Claude Code

### Fecha de Entrega

**Deadline**: 16 de diciembre de 2024, 23:59h

**Plataforma**: Enseñanza Virtual (Universidad de Sevilla)

## 📚 Referencias y Recursos

### Frameworks y Estándares

- **MITRE ATT&CK**: https://attack.mitre.org/
- **NIST 800-115**: https://csrc.nist.gov/publications/detail/sp/800-115/final
- **OWASP Top 10 2021**: https://owasp.org/Top10/
- **CVE Database**: https://cve.mitre.org/
- **CWE Database**: https://cwe.mitre.org/
- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Herramientas

- **DVWA**: https://github.com/digininja/DVWA
- **Nmap**: https://nmap.org/
- **Nikto**: https://github.com/sullo/nikto
- **SQLMap**: https://sqlmap.org/
- **Metasploit**: https://www.metasploit.com/
- **OWASP ZAP**: https://www.zaproxy.org/
- **Burp Suite**: https://portswigger.net/burp

### Documentación Técnica

- **Kali Linux Tools**: https://www.kali.org/tools/
- **Docker Documentation**: https://docs.docker.com/
- **DVWA Documentation**: https://github.com/digininja/DVWA/blob/master/README.md

### Papers y Guías

- NIST SP 800-115: Technical Guide to Information Security Testing and Assessment
- OWASP Testing Guide v4.2
- PTES (Penetration Testing Execution Standard)
- MITRE ATT&CK for Enterprise

## ⚖️ Licencia y Ética

### Uso Ético

Este proyecto es **exclusivamente para fines educativos** y debe ser utilizado en entornos controlados:

- ✅ **Permitido**: Testing en DVWA local en Docker
- ✅ **Permitido**: Práctica en labs personales
- ✅ **Permitido**: Entornos de prueba con autorización explícita

- ❌ **PROHIBIDO**: Usar estas técnicas contra sistemas sin autorización
- ❌ **PROHIBIDO**: Atacar infraestructura de terceros
- ❌ **PROHIBIDO**: Explotación con fines maliciosos

### Responsabilidad Legal

El uso no autorizado de técnicas de pentesting puede constituir un delito según el Código Penal español:

- **Artículo 197**: Acceso no autorizado a sistemas informáticos
- **Artículo 264**: Daños informáticos

**Los autores de este proyecto NO se responsabilizan del uso indebido de estas técnicas.**

### Código de Conducta

Al usar este proyecto, aceptas:

1. Usar las técnicas solo en entornos controlados y autorizados
2. Documentar todos los hallazgos de forma responsable
3. No realizar actividades maliciosas o ilegales
4. Seguir las políticas de la Universidad de Sevilla
5. Respetar la privacidad y seguridad de terceros

## 👥 Autores

**Universidad de Sevilla - SSII**
Proyecto académico PAI-5: RedTeamPro

## 📞 Soporte

Para dudas o problemas:

1. Consultar `CLAUDE.md` para información detallada
2. Revisar los README.md de cada fase
3. Consultar documentación de herramientas
4. Contactar con profesores de la asignatura SSII

---

**Última actualización**: 3 de diciembre de 2024

**Versión**: 1.0.0

**Estado**: ✅ Proyecto base completo - Listo para ejecutar pentesting
