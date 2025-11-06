# PAI-4: AUDITVUL - Análisis de Vulnerabilidades y Detección de Intrusos

## 📋 Descripción

Este proyecto implementa una política integral de seguridad mediante:
- **OpenVAS/Greenbone**: Análisis de vulnerabilidades
- **Suricata IDS**: Sistema de detección de intrusos

## 📁 Estructura del Proyecto

```
PAI4-Project/
├── PAI4-Informe-Tecnico.md      # Informe técnico principal (PDF generado)
├── scripts/
│   ├── install-openvas.sh       # Instalación automatizada de OpenVAS
│   ├── install-suricata.sh      # Instalación automatizada de Suricata
│   ├── backup-system.sh         # Script de backups automatizados
│   └── analyze-suricata-logs.sh # Análisis de logs del IDS
├── configuraciones/
│   ├── custom-rules.rules       # Reglas personalizadas de Suricata
│   └── suricata.yaml            # Configuración completa de Suricata
└── logs-evidencia/
    └── (logs de pruebas realizadas)
```

## 🚀 Instalación Rápida

### Requisitos Previos

- Docker instalado y funcionando
- Sistema operativo: Linux, macOS o Windows con WSL2
- Mínimo 8GB RAM
- 20GB espacio en disco

### 1. OpenVAS/Greenbone

```bash
cd scripts
chmod +x install-openvas.sh
./install-openvas.sh
```

Acceso:
- URL: http://localhost:9392
- Usuario: admin
- Contraseña: (la que configuraste en el script)

**Nota**: La primera inicialización toma 15-20 minutos.

### 2. Suricata IDS

```bash
cd scripts
chmod +x install-suricata.sh
./install-suricata.sh
```

Los logs se guardarán en: `~/suricata/logs/`

## 📖 Guía de Uso

### OpenVAS - Escaneo de Vulnerabilidades

1. **Acceder a la interfaz web**: http://localhost:9392

2. **Crear un Target**:
   - Configuration → Targets → New Target
   - Ingresar nombre, IP y lista de puertos
   - Guardar

3. **Crear una Tarea de Escaneo**:
   - Scans → Tasks → New Task
   - Seleccionar Target creado
   - Tipo de escaneo: "Full and Fast"
   - Iniciar escaneo

4. **Ver Resultados**:
   - Esperar finalización (45-60 min aprox.)
   - Scans → Reports → Ver informe
   - Exportar en PDF/XML/CSV

### Suricata - Detección de Intrusos

1. **Ver alertas en tiempo real**:
```bash
tail -f ~/suricata/logs/fast.log
```

2. **Analizar logs**:
```bash
cd scripts
chmod +x analyze-suricata-logs.sh
./analyze-suricata-logs.sh
```

3. **Modificar reglas**:
- Editar: `configuraciones/custom-rules.rules`
- Copiar a: `~/suricata/rules/`
- Recargar: 
```bash
docker exec -it suricata-ids suricatasc -c reload-rules
```

## 🧪 Pruebas de Validación

### Probar Detección de Acceso HTTP No Autorizado

```bash
# Desde otra máquina o usando VPN externa
curl http://192.168.1.10:8083/
```

Debe generar alerta con SID 1000001.

### Probar Detección de SQL Injection

```bash
curl "http://192.168.1.10:8083/login.php?id=1%20OR%201=1;SELECT%20*%20FROM%20users"
```

Debe generar alerta con SID 1000003.

### Probar Detección de Escaneo de Puertos

```bash
nmap -sS -p 8083,8443,3336,2288 192.168.1.10
```

Debe generar alerta con SID 1000010.

## 🛡️ Plan de Mitigación

### Backup Automatizado

```bash
cd scripts
chmod +x backup-system.sh

# Ejecutar manualmente
sudo ./backup-system.sh

# O configurar en crontab para ejecución diaria a las 2 AM
sudo crontab -e
# Agregar: 0 2 * * * /ruta/completa/backup-system.sh
```

Los backups se guardan en `/backups` con retención de 30 días.

## 📊 Generación del Informe Final

El informe técnico está en formato Markdown. Para convertirlo a PDF:

### Opción 1: Con Pandoc
```bash
pandoc PAI4-Informe-Tecnico.md -o PAI4-Informe-Tecnico.pdf \
  --pdf-engine=xelatex \
  -V geometry:margin=2.5cm
```

### Opción 2: Con VSCode
- Instalar extensión "Markdown PDF"
- Abrir archivo .md
- Clic derecho → "Markdown PDF: Export (pdf)"

### Opción 3: Online
- Usar servicios como https://www.markdowntopdf.com/

## 🔧 Solución de Problemas

### OpenVAS no inicia
```bash
docker logs openvas
docker restart openvas
```

### Suricata no detecta tráfico
- Verificar interfaz de red: `ip link show`
- Verificar permisos: contenedor necesita `--cap-add=net_admin`
- Revisar logs: `docker logs suricata-ids`

### Reglas no se cargan
```bash
# Verificar sintaxis
docker exec -it suricata-ids suricata -T -c /etc/suricata/suricata.yaml

# Recargar reglas
docker exec -it suricata-ids suricatasc -c reload-rules
```

## 📝 Personalización

### Modificar Redes Monitorizadas

Editar `configuraciones/suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[TU_RED/24]"
    EXTERNAL_NET: "!$HOME_NET"
```

### Agregar Nuevas Reglas

Editar `configuraciones/custom-rules.rules`:

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET PUERTO \
  (msg:"TU MENSAJE"; \
  flow:to_server,established; \
  classtype:policy-violation; \
  sid:1000XXX; rev:1;)
```

Incrementar SID desde 1000013 en adelante.

## 📚 Referencias

- [Documentación OpenVAS](https://docs.greenbone.net/)
- [Documentación Suricata](https://suricata.readthedocs.io/)
- [Base de datos CVE](https://cve.mitre.org/)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)

## ⚠️ Notas Importantes

1. **Uso Ético**: Estas herramientas solo deben usarse en sistemas propios o con autorización explícita.

2. **Rendimiento**: OpenVAS consume recursos significativos durante escaneos. Planificar ejecución en horarios de bajo tráfico.

3. **Actualizaciones**: Actualizar feeds de vulnerabilidades semanalmente:
```bash
docker exec -it openvas /scripts/sync.sh
docker exec -it --user suricata suricata-ids suricata-update -f
```

4. **Falsos Positivos**: Revisar y ajustar reglas de Suricata según el entorno para reducir falsos positivos.

## 👥 Equipo

**Security Team:** ST-XX
- Miembro 1
- Miembro 2
- Miembro 3

## 📅 Fecha de Entrega

**Deadline:** 25 de Noviembre 2025, 23:59h

## 📦 Entrega

Comprimir todo el proyecto:

```bash
cd ..
zip -r PAI4-ST-XX.zip PAI4-Project/
```

Subir a la plataforma de Enseñanza Virtual.

---

**¿Preguntas?** Consultar documentación oficial o contactar al profesor.
