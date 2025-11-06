# PAI-3 VULNAWEB - Auditoría de Seguridad
## Security Team INSEGUS

---

## Contenido del Entregable

Este archivo ZIP contiene todos los elementos solicitados para el proyecto PAI-3 VULNAWEB:

```
PAI3-VULNAWEB/
├── INFORME_PAI3.pdf                    # Informe principal (7-8 páginas)
├── INFORME_PAI3.md                     # Versión Markdown del informe
├── README.md                           # Este archivo
├── scripts/
│   ├── hardening-actions.sh            # Script principal de hardening
│   ├── browser-hardening.sh            # Configuración segura del navegador
│   └── verify-hardening.sh             # Script de verificación
├── logs/
│   ├── lynis-initial.log               # Auditoría inicial (Hardening: 53)
│   ├── lynis-final.log                 # Auditoría final (Hardening: 72)
│   ├── malwarebytes-scan.log           # Escaneo del dispositivo móvil
│   ├── zap-session.log                 # Log de sesión OWASP ZAP
│   └── fuzzer-results.log              # Resultados del fuzzing
├── configs/
│   ├── firefox/
│   │   ├── user.js                     # Configuración Firefox hardened
│   │   └── policies.json               # Políticas empresariales
│   ├── ufw/
│   │   └── rules.conf                  # Reglas del firewall
│   ├── fail2ban/
│   │   └── jail.local                  # Configuración fail2ban
│   ├── pam.d/
│   │   └── common-password             # Políticas de contraseñas
│   └── sysctl.d/
│       └── 99-hardening.conf           # Hardening del kernel
├── zap-reports/
│   ├── zap-full-report.html            # Reporte completo de ZAP
│   ├── vulnerabilities-summary.md      # Resumen de vulnerabilidades
│   └── payloads/
│       ├── sql-injection-payloads.txt  # Payloads SQL usados
│       ├── xss-payloads.txt            # Payloads XSS usados
│       └── path-traversal-payloads.txt # Payloads Path Traversal
└── screenshots/
    ├── lynis-before.png                # Captura inicial Lynis
    ├── lynis-after.png                 # Captura final Lynis
    ├── mobile-analysis.png             # Análisis del móvil
    ├── zap-proxy-config.png            # Configuración del proxy
    ├── zap-certificate.png             # Importación de certificado
    ├── sql-injection-poc.png           # Prueba de concepto SQL Injection
    ├── xss-reflected-poc.png           # Prueba de concepto XSS Reflejado
    ├── xss-stored-poc.png              # Prueba de concepto XSS Almacenado
    ├── path-traversal-poc.png          # Prueba de concepto Path Traversal
    └── csrf-poc.png                    # Prueba de concepto CSRF
```

---

## Resumen Ejecutivo

### Objetivo 1: Auditoría de Sistemas Informáticos

**Resultados Hardening:**
- **Índice Inicial:** 53/100
- **Índice Final:** 72/100
- **Mejora:** +19 puntos (+36%)
- **Objetivo (≥69):** ✅ ALCANZADO

**Acciones Implementadas:**
1. Políticas de contraseñas robustas (PAM + aging)
2. Umask restrictivo (027)
3. Firewall UFW configurado
4. Módulos innecesarios deshabilitados
5. Banners legales implementados
6. Actualizaciones automáticas activadas
7. Kernel hardening aplicado
8. Fail2ban configurado
9. Navegador Firefox fortificado

**Dispositivo Móvil:**
- **Puntuación Inicial:** 78/100
- **Puntuación Final:** 86/100
- Aplicaciones maliciosas eliminadas
- Permisos revisados y optimizados
- Configuraciones de seguridad aplicadas

### Objetivo 2: Auditoría de Aplicaciones Web

**Entorno de Pruebas:** OWASP Mutillidae II v2.6.36

**Vulnerabilidades Detectadas:**

| Tipo | Severidad | Cantidad | OWASP Top 10 |
|------|-----------|----------|--------------|
| SQL Injection | CRÍTICA | 3 | A03:2021 |
| XSS Reflejado | ALTA | 5 | A03:2021 |
| XSS Almacenado | ALTA | 2 | A03:2021 |
| Path Traversal | CRÍTICA | 2 | A01:2021 |
| CSRF | MEDIA | 4 | A01:2021 |
| Info Sensible | MEDIA | 3 | A05:2021 |

**Total:** 19 vulnerabilidades (5 críticas, 7 altas, 7 medias)

---

## Instrucciones de Uso

### 1. Ejecutar el Script de Hardening

```bash
# Dar permisos de ejecución
chmod +x scripts/hardening-actions.sh

# Ejecutar como root
sudo ./scripts/hardening-actions.sh

# El script creará respaldos automáticamente
# Ubicación: /root/hardening_backup_YYYYMMDD_HHMMSS/
```

**IMPORTANTE:** Revisar el script antes de ejecutar en producción.

### 2. Verificar el Hardening

```bash
# Ejecutar auditoría con Lynis
sudo lynis audit system -Q

# Verificar con el script de verificación
sudo ./scripts/verify-hardening.sh
```

### 3. Configurar el Navegador

```bash
# Copiar configuración de Firefox
cp configs/firefox/user.js ~/.mozilla/firefox/[tu-perfil]/

# Reiniciar Firefox para aplicar cambios
```

### 4. Revisar Configuraciones Aplicadas

Todos los archivos de configuración modificados están en el directorio `configs/` organizados por servicio:

- **Firefox:** Configuración de seguridad y privacidad
- **UFW:** Reglas del firewall
- **Fail2ban:** Protección contra ataques de fuerza bruta
- **PAM:** Políticas de autenticación
- **Sysctl:** Hardening del kernel

### 5. Análisis de Vulnerabilidades Web

Los reportes de OWASP ZAP están en `zap-reports/`:

- **zap-full-report.html:** Reporte visual completo
- **vulnerabilities-summary.md:** Resumen ejecutivo en Markdown
- **payloads/:** Archivos con los payloads utilizados

---

## Herramientas Utilizadas

### Auditoría de Sistemas
- **Lynis 3.0.9:** Auditoría de seguridad Unix/Linux
- **Malwarebytes Mobile:** Análisis de dispositivos Android
- **UFW:** Firewall
- **Fail2ban:** Protección contra ataques
- **PAM pwquality:** Política de contraseñas

### Auditoría Web
- **OWASP ZAP 2.14.0:** Escáner de vulnerabilidades DAST
- **Mozilla Firefox ESR:** Navegador para pruebas
- **OWASP Mutillidae II v2.6.36:** Aplicación web vulnerable de pruebas
- **jbrofuzz:** Payloads para fuzzing

---

## Plan de Mitigación

### Fase 1 (Inmediato - 0-2 semanas) ⚠️ CRÍTICO

**Prioridad Alta:**
1. Implementar prepared statements para SQL
2. Sanitizar todas las salidas HTML
3. Validar estrictamente rutas de archivos
4. Aplicar principio de mínimo privilegio en BD

### Fase 2 (Corto plazo - 2-4 semanas) 

**Prioridad Media:**
1. Tokens CSRF en todos los formularios
2. Content Security Policy (CSP)
3. Flags HTTPOnly y Secure en cookies
4. Validación de entrada del lado del servidor

### Fase 3 (Medio plazo - 1-2 meses)

**Mejora Continua:**
1. Auditoría de código completa (SAST)
2. Implementación de WAF
3. Programa de bug bounty interno
4. Capacitación del equipo de desarrollo

---

## Mejores Prácticas Implementadas

### Defensa en Profundidad
✅ Validación en cliente Y servidor  
✅ Sanitización de entrada Y salida  
✅ Autenticación Y autorización  
✅ Firewall + IDS/IPS (fail2ban)

### Principio de Mínimo Privilegio
✅ Usuario de BD con permisos limitados  
✅ Aplicación sin privilegios root  
✅ Segregación de funciones  
✅ Permisos de archivos restrictivos (umask 027)

### Seguridad por Diseño
✅ Revisiones de código de seguridad  
✅ Threat modeling  
✅ Tests automatizados  
✅ Actualizaciones automáticas

---

## Advertencias Importantes

⚠️ **USO EDUCATIVO:** Este proyecto es para fines educativos y de aprendizaje.

⚠️ **AUTORIZACIÓN REQUERIDA:** Nunca realizar auditorías de seguridad en sistemas en producción sin autorización explícita por escrito.

⚠️ **RESPALDOS:** Siempre crear respaldos antes de aplicar cambios de hardening.

⚠️ **TESTING:** Probar todas las configuraciones en entorno de desarrollo antes de producción.

⚠️ **CUMPLIMIENTO LEGAL:** El uso indebido de herramientas de seguridad puede constituir un delito. Usar solo en sistemas autorizados.

---

## Referencias

- **OWASP Top 10 2021:** https://owasp.org/Top10/
- **CIS Benchmarks:** https://www.cisecurity.org/cis-benchmarks/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **Lynis Documentation:** https://cisofy.com/documentation/lynis/
- **OWASP ZAP Documentation:** https://www.zaproxy.org/docs/
- **Mozilla Security Guidelines:** https://infosec.mozilla.org/guidelines/

---

## Contacto

**Security Team INSEGUS**  
Universidad de Sevilla  
Grupo de Investigación IDEA Research Group

**Fecha de Entrega:** 04 de noviembre de 2024  
**Clasificación:** CONFIDENCIAL

---

## Licencia y Uso

Este documento y los archivos adjuntos son material educativo desarrollado en el contexto del curso "Seguridad en Sistemas Informáticos e Internet" de la Universidad de Sevilla.

**Uso permitido:**
- Fines educativos y de aprendizaje
- Referencia para implementar medidas de seguridad
- Pruebas en entornos controlados y autorizados

**Uso NO permitido:**
- Pruebas en sistemas sin autorización
- Distribución sin atribución apropiada
- Uso malicioso o para actividades ilegales

---

## Changelog

**v1.0 - 2024-11-04**
- Entrega inicial completa
- Hardening de sistemas (Índice: 53 → 72)
- Auditoría de seguridad móvil (78 → 86)
- Análisis de vulnerabilidades web (19 encontradas)
- Documentación completa
- Scripts y configuraciones
- Evidencias y capturas de pantalla

---

**END OF README**
