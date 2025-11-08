# PAI-3 VULNAWEB - Objetivo 2: Auditoría de Aplicaciones Web

## 🎯 Descripción

Este proyecto implementa el **Objetivo 2** del PAI-3 VULNAWEB usando un entorno completamente containerizado con **Docker + Nginx**, evitando los problemas de configuración de Apache nativo.

**🔥 NOVEDAD:** Arquitectura basada en contenedores para máxima estabilidad y reproducibilidad.

---

## 🚀 Instalación Rápida (Un Solo Comando)

```bash
# Descargar y ejecutar instalación completa
chmod +x setup-objetivo2.sh
sudo ./setup-objetivo2.sh
```

¡Y listo! Todo configurado automáticamente en ~10 minutos.

---

## 🐳 Arquitectura del Entorno

```
┌─────────────────────────────────────────────────────────────┐
│                        Docker Host                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   WebGoat   │  │ Mutillidae  │  │    DVWA     │         │
│  │  Port 8080  │  │  Port 8082  │  │  Port 8083  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│           │              │              │                  │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Nginx Reverse Proxy                        ││
│  │            HTTP:80 / HTTPS:443                          ││
│  └─────────────────────────────────────────────────────────┘│
│                          │                                  │
└──────────────────────────│──────────────────────────────────┘
                           │
                    ┌─────────────┐
                    │ OWASP ZAP   │
                    │ Proxy 8081  │
                    └─────────────┘
```

---

## 📦 Componentes Incluidos

### 🎯 Aplicaciones Vulnerables

| Aplicación | Puerto | Descripción |
|------------|--------|-------------|
| **OWASP WebGoat** | 8080 | Lecciones interactivas de vulnerabilidades |
| **WebWolf** | 9001 | Companion de WebGoat para ataques |
| **OWASP Mutillidae II** | 8082 | Aplicación PHP/MySQL vulnerable |
| **DVWA** | 8083 | Niveles configurables de seguridad |
| **Nginx Proxy** | 80/443 | Panel principal con SSL |

### 🔧 Herramientas de Auditoría

- **OWASP ZAP**: Proxy de intercepción configurado en puerto 8081
- **Payloads automáticos**: SQL Injection, XSS, Path Traversal, Command Injection
- **Scripts de pruebas**: Automatización de tests de vulnerabilidades
- **Reportes automáticos**: Generación de informes de hallazgos

---

## 🎮 Uso Básico

### 1. **Acceso al Entorno**

```bash
# Panel principal
http://localhost

# Aplicaciones directas
http://localhost:8080/WebGoat    # WebGoat
http://localhost:8082            # Mutillidae
http://localhost:8083            # DVWA
```

### 2. **Configuración de OWASP ZAP**

```bash
# Ver instrucciones de configuración
cd pai3-objetivo2
./scripts/configure-zap.sh

# Configuración manual:
# ZAP: Tools → Options → Local Proxies
#   - Address: localhost
#   - Port: 8081
# Firefox: Network Settings
#   - Manual Proxy: 127.0.0.1:8081
```

### 3. **Ejecutar Pruebas Automáticas**

```bash
# Pruebas rápidas automáticas
cd pai3-objetivo2
./scripts/test-vulnerabilities.sh

# Pruebas manuales detalladas
chmod +x test-vulnerabilidades.sh
./test-vulnerabilidades.sh
```

---

## 🔍 Vulnerabilidades Cubiertas

### ✅ SQL Injection
- **Authentication Bypass**: `admin' OR '1'='1--`
- **Union-based**: `UNION SELECT user(), version()`
- **Error-based**: Exposición de errores de MySQL

### ✅ Cross-Site Scripting (XSS)
- **Reflected**: `<script>alert('XSS')</script>`
- **Stored**: Persistente en base de datos
- **Vectores alternativos**: `<img onerror>`, `<svg onload>`

### ✅ Path Traversal
- **File Inclusion**: `../../../etc/passwd`
- **Configuration Files**: Apache, PHP configs
- **System Information**: `/proc/version`, `/proc/cmdline`

### ✅ Command Injection
- **OS Commands**: `; ls -la`, `; whoami`
- **Information Gathering**: `; cat /etc/passwd`
- **System Control**: `; ps aux`

### ✅ CSRF (Cross-Site Request Forgery)
- **Token Verification**: Ausencia de tokens CSRF
- **PoC Generation**: Formularios maliciosos automáticos

### ✅ Information Disclosure
- **HTTP Headers**: Exposición de versiones
- **phpinfo()**: Información completa del sistema
- **Sensitive Files**: robots.txt, .htaccess

---

## 📊 Ejemplo de Resultados

```
PAI-3 VULNAWEB - RESUMEN DE VULNERABILIDADES
============================================

VULNERABILIDADES CRÍTICAS:
• [CRÍTICO] SQL Injection Authentication Bypass exitoso
• [CRÍTICO] Path Traversal - /etc/passwd accesible
• [CRÍTICO] Command Injection - comando 'ls' ejecutado

VULNERABILIDADES ALTAS:
• [ALTO] XSS Reflejado en Mutillidae - script ejecutándose
• [ALTO] phpinfo() accesible - información completa expuesta

TOTAL DE VULNERABILIDADES: 12
```

---

## 🔨 Comandos de Control

```bash
# Directorio del proyecto
cd pai3-objetivo2

# Iniciar entorno
docker-compose up -d

# Ver estado
docker-compose ps

# Ver logs
docker-compose logs -f

# Detener entorno
docker-compose down

# Reiniciar servicios
docker-compose restart

# Limpiar todo
docker-compose down -v
```

---

## 📁 Estructura de Archivos Generados

```
pai3-objetivo2/
├── docker-compose.yml          # Configuración principal
├── nginx/
│   ├── nginx.conf             # Configuración Nginx
│   ├── ssl/                   # Certificados SSL
│   └── html/                  # Página principal
├── scripts/
│   ├── test-vulnerabilities.sh  # Pruebas automáticas
│   └── configure-zap.sh       # Configuración ZAP
├── payloads/
│   ├── sql-injection.txt      # Payloads SQL
│   ├── xss.txt               # Payloads XSS
│   ├── path-traversal.txt    # Payloads Path Traversal
│   └── command-injection.txt # Payloads Command Injection
└── resultados-YYYYMMDD-HHMMSS/
    ├── evidencias/           # Archivos HTML de evidencias
    ├── logs/                # Logs de pruebas
    └── RESUMEN_VULNERABILIDADES.txt
```

---

## 🎯 Para el Informe PAI-3

### Capturas de Pantalla Requeridas

1. **Panel principal** mostrando las 3 aplicaciones disponibles
2. **OWASP ZAP configurado** como proxy interceptando tráfico
3. **SQL Injection exitoso** con bypass de autenticación
4. **XSS funcionando** con alert() ejecutándose
5. **Path Traversal** mostrando contenido de `/etc/passwd`
6. **Fuzzer de ZAP** ejecutándose con payloads

### Documentación Automática

```bash
# El script genera automáticamente:
# - Informe técnico en formato Markdown
# - Resumen de vulnerabilidades
# - Evidencias en HTML
# - Logs detallados de pruebas
```

---

## 🚨 Consideraciones de Seguridad

### ⚠️ IMPORTANTE

- **Solo para uso educativo** en entornos aislados
- **NO exponer a Internet** - solo localhost
- **Aplicaciones intencionalmente vulnerables**
- **Detener servicios** cuando no se usen

### 🛡️ Aislamiento

```bash
# Los contenedores están aislados en red propia
# Solo puertos específicos expuestos al host
# Sin acceso a internet desde las aplicaciones vulnerables
```

---

## 🔧 Solución de Problemas

### Servicios no inician

```bash
# Verificar Docker
sudo systemctl status docker
sudo systemctl start docker

# Verificar permisos
sudo usermod -aG docker $USER
# Reiniciar sesión después
```

### Puertos ocupados

```bash
# Ver qué usa el puerto
sudo netstat -tlnp | grep :8080

# Cambiar puerto en docker-compose.yml
# Ejemplo: "8090:8080" para usar puerto 8090
```

### ZAP no intercepta

```bash
# Verificar configuración Firefox
# Verificar certificados SSL importados
# Reiniciar ZAP y Firefox
```

### Aplicaciones no responden

```bash
# Ver logs de contenedores
docker-compose logs mutillidae
docker-compose logs dvwa
docker-compose logs webgoat

# Reiniciar servicios específicos
docker-compose restart mutillidae
```

---

## 🎓 Ventajas de Esta Aproximación

### ✅ **Vs. Apache Nativo**

- **Sin errores de configuración** (php_flag, modules, etc.)
- **Sin problemas de permisos** complejos
- **Sin conflictos con el sistema** host
- **Reproducible** en cualquier sistema con Docker

### ✅ **Vs. Instalación Manual**

- **Setup en 1 comando** vs. horas de configuración
- **Entorno aislado** y seguro
- **Fácil limpieza** completa
- **Documentación automática**

### ✅ **Para el PAI-3**

- **Cumple 100%** con los requisitos del Objetivo 2
- **Genera evidencias** automáticamente
- **Reportes** listos para entregar
- **Screenshots** específicos para el informe

---

## 📞 Soporte

Si tienes problemas:

1. **Verifica Docker** está funcionando
2. **Lee los logs** con `docker-compose logs`
3. **Ejecuta diagnóstico** con `./test-vulnerabilidades.sh`
4. **Revisa puertos** no estén ocupados

---

## ✅ Resultado Final

Al completar este setup tendrás:

- ✅ **Entorno Docker** funcionando completamente
- ✅ **3 aplicaciones vulnerables** listas para auditar
- ✅ **OWASP ZAP** configurado para intercepción
- ✅ **Vulnerabilidades detectadas** automáticamente
- ✅ **Evidencias documentadas** para el informe
- ✅ **Objetivo 2 PAI-3** completado exitosamente

**🎉 ¡Listo para comenzar la auditoría de seguridad!** 🛡️
