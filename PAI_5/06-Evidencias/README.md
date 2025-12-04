# Gestión de Evidencias

## Objetivo

Documentar y organizar todas las evidencias recopiladas durante el pentesting para:
- Demostrar la ejecución de cada técnica
- Proporcionar pruebas reproducibles
- Facilitar la generación del informe técnico
- Cumplir con estándares profesionales de documentación

## Subdirectorios

```
06-Evidencias/
├── README.md                # Este archivo
├── INDICE-EVIDENCIAS.md     # Índice auto-generado
├── screenshots/             # Capturas de pantalla
├── logs/                    # Logs de comandos y sesiones
└── network-captures/        # Capturas de tráfico (PCAP)
```

## 1. Tipos de Evidencias

### 1.1. Screenshots

**Propósito**: Prueba visual de vulnerabilidades y explotaciones exitosas.

**Cuándo capturar**:
- Resultados de escaneos (nmap, nikto)
- Vulnerabilidades identificadas
- Explotaciones exitosas
- Acceso obtenido (shells)
- Datos sensibles extraídos
- Escalada de privilegios
- Cualquier hallazgo relevante

**Herramientas**:
- `scrot` - Captura de pantalla en CLI
- `gnome-screenshot` - Captura en GNOME
- `import` - ImageMagick
- Browser DevTools - F12 para capturas web

### 1.2. Logs

**Propósito**: Registro completo de comandos ejecutados y sus resultados.

**Incluye**:
- Comandos ejecutados
- Output de herramientas
- Sesiones de terminal completas
- Logs de sesiones de logging automático
- HTTP requests/responses

### 1.3. Network Captures

**Propósito**: Captura de tráfico de red para análisis forense.

**Cuándo capturar**:
- Durante escaneos de red
- Explotación de vulnerabilidades web
- Ataques de inyección
- Exfiltración de datos
- Cualquier comunicación con el target

**Formato**: PCAP (compatible con Wireshark)

## 2. Nomenclatura de Archivos

### 2.1. Formato Estándar

Todos los archivos de evidencia siguen este formato:

```
<número>_<fase>_<técnica>_<descripción>.<extensión>
```

**Componentes**:
- `<número>`: Número secuencial de 3 dígitos (001, 002, ...)
- `<fase>`: recon, escaneo, exploit, postexp
- `<técnica>`: nmap, nikto, sqli, cmdi, xss, etc.
- `<descripción>`: Descripción breve sin espacios (usar guiones)
- `<extensión>`: png, log, pcap, txt, etc.

### 2.2. Ejemplos

**Screenshots**:
```
001_recon_nmap_full-scan.png
002_escaneo_nikto_vulns-found.png
003_exploit_sqli_users-extracted.png
004_exploit_cmdi_reverse-shell.png
005_postexp_privesc_root-shell.png
```

**Logs**:
```
001_recon_nmap_command.log
002_escaneo_sqlmap_database-dump.log
003_exploit_sqli_query-results.log
```

**Network Captures**:
```
001_recon_initial-scan.pcap
002_exploit_sqli-attack.pcap
003_exploit_file-upload.pcap
```

## 3. Uso del Script de Captura

### 3.1. Capturar Screenshots

**Screenshot de pantalla completa**:
```bash
bash ../07-Scripts/capture-evidence.sh --screenshot <fase> <técnica> <descripción> [attack-id]

# Ejemplos:
bash ../07-Scripts/capture-evidence.sh --screenshot recon nmap "service-scan-results" T1046
bash ../07-Scripts/capture-evidence.sh --screenshot exploit sqli "database-users-dump" T1213
bash ../07-Scripts/capture-evidence.sh --screenshot postexp privesc "root-shell-obtained" T1068
```

**Screenshot de ventana específica**:
```bash
bash ../07-Scripts/capture-evidence.sh --window <fase> <técnica> <descripción>

# Ejemplo:
bash ../07-Scripts/capture-evidence.sh --window exploit sqli "burp-suite-request"
# Luego hacer clic en la ventana a capturar
```

### 3.2. Guardar Logs de Comandos

```bash
bash ../07-Scripts/capture-evidence.sh --command-log <fase> <técnica> <comando> <output> [attack-id]

# Ejemplo:
OUTPUT=$(nmap -sV localhost)
bash ../07-Scripts/capture-evidence.sh --command-log recon nmap "nmap -sV localhost" "$OUTPUT" T1046
```

### 3.3. Capturar Tráfico de Red

**Iniciar captura**:
```bash
bash ../07-Scripts/capture-evidence.sh --start-capture <fase> <descripción> [interfaz]

# Ejemplos:
bash ../07-Scripts/capture-evidence.sh --start-capture exploit "sql-injection" eth0
bash ../07-Scripts/capture-evidence.sh --start-capture exploit "file-upload-attack" any
```

**Detener captura**:
```bash
bash ../07-Scripts/capture-evidence.sh --stop-capture <fase> <descripción>

# Ejemplo:
bash ../07-Scripts/capture-evidence.sh --stop-capture exploit "sql-injection"
```

### 3.4. Guardar HTTP Requests/Responses

```bash
bash ../07-Scripts/capture-evidence.sh --http <fase> <descripción> [archivo-request]

# Ejemplo con Burp Suite:
# 1. Guardar request desde Burp Suite
# 2. Ejecutar:
bash ../07-Scripts/capture-evidence.sh --http exploit "sqli-request" /tmp/burp-request.txt
```

### 3.5. Listar Evidencias

```bash
# Ver todas las evidencias capturadas
bash ../07-Scripts/capture-evidence.sh --list

# Generar índice de evidencias
bash ../07-Scripts/capture-evidence.sh --index
```

### 3.6. Ver Detalles de Evidencia

```bash
bash ../07-Scripts/capture-evidence.sh --details <ruta-archivo>

# Ejemplo:
bash ../07-Scripts/capture-evidence.sh --details screenshots/001_recon_nmap_full-scan.png
```

### 3.7. Resetear Contador

```bash
# Resetear contador de evidencias (volver a 001)
bash ../07-Scripts/capture-evidence.sh --reset-counter
```

## 4. Metadata de Evidencias

Cada evidencia capturada con el script tiene un archivo `.meta.json` asociado:

```json
{
  "file": "001_recon_nmap_full-scan.png",
  "type": "screenshot",
  "phase": "recon",
  "technique": "nmap",
  "description": "full-scan",
  "attack_id": "T1046",
  "timestamp": "2024-12-03 14:30:15",
  "unix_timestamp": 1701615015,
  "user": "kali",
  "hostname": "kali",
  "full_path": "/home/kali/PAI_5/06-Evidencias/screenshots/001_recon_nmap_full-scan.png"
}
```

**Utilidad**:
- Búsqueda rápida de evidencias
- Filtrado por fase o técnica
- Generación automática de índices
- Trazabilidad completa

## 5. Mejores Prácticas

### 5.1. Durante el Pentesting

**DO**:
- ✅ Capturar evidencias en tiempo real
- ✅ Usar nomenclatura consistente
- ✅ Incluir timestamps
- ✅ Capturar antes y después de cada ataque
- ✅ Documentar comandos exactos
- ✅ Guardar outputs completos
- ✅ Capturar errores también (son informativos)

**DON'T**:
- ❌ Esperar al final para capturar evidencias
- ❌ Usar nombres genéricos ("screenshot1.png")
- ❌ Olvidar incluir técnica ATT&CK
- ❌ Capturar solo éxitos (documentar fallos también)
- ❌ Editar o modificar evidencias originales

### 5.2. Screenshots

**Qué incluir en screenshots**:
- Ventana completa con contexto
- URL visible en navegador
- Comando y output en terminal
- Timestamp del sistema
- Resultado claramente visible

**Qué evitar**:
- Screenshots parciales
- Resolución muy baja
- Información cortada
- Falta de contexto

### 5.3. Logs

**Formato recomendado**:
```markdown
# Command Log - [Técnica]

Date: 2024-12-03 14:30:15
Phase: exploit
Technique: sqli
MITRE ATT&CK: T1213

## Command Executed
```bash
sqlmap -u "http://localhost/sqli?id=1" --dbs
```

## Output
```
[...]
available databases [2]:
[*] dvwa
[*] information_schema
[...]
```

## Impact
Successfully enumerated databases, confirmed SQL injection vulnerability.
```

## 6. Organización de Evidencias

### 6.1. Por Fase

```
06-Evidencias/
├── screenshots/
│   ├── 001_recon_*.png
│   ├── 002_recon_*.png
│   ├── 010_escaneo_*.png
│   ├── 020_exploit_*.png
│   └── 030_postexp_*.png
```

### 6.2. Por Técnica ATT&CK

El script automáticamente guarda metadata con ID ATT&CK, permitiendo filtrar:

```bash
# Filtrar por técnica (si tienes jq instalado)
for meta in screenshots/*.meta.json; do
    attack_id=$(jq -r '.attack_id' "$meta")
    if [ "$attack_id" = "T1213" ]; then
        jq -r '.file' "$meta"
    fi
done
```

### 6.3. Por Severidad

Puedes agregar severidad en la descripción:

```bash
bash ../07-Scripts/capture-evidence.sh --screenshot exploit sqli "critical-users-extracted" T1213
bash ../07-Scripts/capture-evidence.sh --screenshot exploit xss "medium-reflected-xss" T1059.007
```

## 7. Análisis de Capturas de Red

### 7.1. Abrir con Wireshark

```bash
wireshark network-captures/001_exploit_sqli-attack.pcap
```

### 7.2. Filtros Útiles de Wireshark

**HTTP requests**:
```
http.request
```

**SQL Injection patterns**:
```
http contains "UNION SELECT"
http contains "' OR '"
```

**File uploads**:
```
http.content_type contains "multipart/form-data"
```

**POST requests**:
```
http.request.method == "POST"
```

### 7.3. Extracción de Datos de PCAP

```bash
# Extraer HTTP requests
tshark -r network-captures/001_exploit_sqli-attack.pcap -Y http.request -T fields -e http.request.full_uri

# Extraer datos POST
tshark -r network-captures/001_exploit_sqli-attack.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

## 8. Índice de Evidencias

### 8.1. Generar Índice Automático

```bash
bash ../07-Scripts/capture-evidence.sh --index
```

Esto genera `INDICE-EVIDENCIAS.md` con formato:

```markdown
# Índice de Evidencias - PAI-5 RedTeamPro

**Generado**: 2024-12-03 14:30:15

## Screenshots

| # | Archivo | Fase | Técnica | Descripción | ATT&CK |
|---|---------|------|---------|-------------|--------|
| 1 | `001_recon_nmap_full-scan.png` | recon | nmap | full-scan | T1046 |
| 2 | `002_exploit_sqli_users-dump.png` | exploit | sqli | users-dump | T1213 |

## Capturas de Red

| # | Archivo | Fase | Tamaño |
|---|---------|------|--------|
| 1 | `001_exploit_sqli-attack.pcap` | exploit | 15234 bytes |
```

### 8.2. Índice Manual

Si prefieres crear el índice manualmente:

```markdown
# Índice de Evidencias

## Fase de Reconocimiento

### Nmap Scans
- 001_recon_nmap_quick-scan.png - Quick port scan
- 002_recon_nmap_service-scan.png - Service version detection
- 003_recon_nmap_vuln-scan.png - NSE vulnerability scripts

### Web Fingerprinting
- 010_recon_whatweb_fingerprint.png - Technology detection
- 011_recon_nikto_initial-scan.png - Nikto basic scan

## Fase de Escaneo

### Nikto
- 020_escaneo_nikto_full-report.png - Complete Nikto scan
- 021_escaneo_nikto_critical-vulns.png - Critical findings

### SQLMap
- 030_escaneo_sqlmap_detection.png - SQL injection detection
- 031_escaneo_sqlmap_database-enum.png - Database enumeration

## Fase de Explotación

### SQL Injection
- 040_exploit_sqli_users-table.png - Users table extraction
- 041_exploit_sqli_password-hashes.png - Password hashes
- 042_exploit_sqli_admin-access.log - Admin credentials

### Command Injection
- 050_exploit_cmdi_whoami.png - Initial command execution
- 051_exploit_cmdi_reverse-shell.png - Reverse shell obtained
- 052_exploit_cmdi_shell-session.log - Interactive shell session

### File Upload
- 060_exploit_upload_webshell.png - Web shell uploaded
- 061_exploit_upload_shell-access.png - Shell execution

## Fase de Post-Explotación

### Privilege Escalation
- 070_postexp_privesc_enumeration.png - LinPEAS output
- 071_postexp_privesc_root-shell.png - Root shell obtained
- 072_postexp_privesc_id-output.log - ID command as root

### Persistence
- 080_postexp_persist_backdoor-user.png - Backdoor user created
- 081_postexp_persist_cron-job.png - Cron job installed

## Network Captures

- 001_recon_initial-scan.pcap - Initial reconnaissance
- 002_exploit_sqli-attack.pcap - SQL injection attack
- 003_exploit_cmdi-shell.pcap - Command injection and reverse shell
- 004_postexp_lateral-movement.pcap - Internal network scan
```

## 9. Checklist de Evidencias

### Por Fase

**Fase 1: Reconocimiento**
- [ ] Screenshots de escaneos nmap
- [ ] Output de nmap en formato .nmap
- [ ] Screenshots de fingerprinting web
- [ ] Logs de herramientas de reconocimiento

**Fase 2: Escaneo**
- [ ] Screenshots de Nikto scan
- [ ] HTML report de Nikto
- [ ] Screenshots de SQLMap detection
- [ ] Logs de vulnerability scanning
- [ ] Security headers analysis

**Fase 3: Explotación**
- [ ] Screenshot de cada vulnerabilidad explotada
- [ ] Payloads utilizados guardados
- [ ] Outputs completos de exploits
- [ ] Screenshots de datos extraídos
- [ ] Evidencia de acceso obtenido

**Fase 4: Post-Explotación**
- [ ] Screenshot de escalada de privilegios
- [ ] Output de herramientas de enumeración
- [ ] Evidencia de persistencia instalada
- [ ] Screenshots de datos sensibles
- [ ] Evidencia de limpieza de rastros

**General**
- [ ] Todas las evidencias numeradas secuencialmente
- [ ] Metadata completa para cada evidencia
- [ ] Índice de evidencias generado
- [ ] Capturas de red para ataques clave
- [ ] Logs de sesiones de terminal

## 10. Entrega de Evidencias

Para la entrega final del proyecto:

```bash
# Verificar que todas las evidencias existen
bash ../07-Scripts/capture-evidence.sh --list

# Generar índice final
bash ../07-Scripts/capture-evidence.sh --index

# Comprimir evidencias (opcional, para backup)
cd 06-Evidencias
tar -czf ../evidencias-backup.tar.gz screenshots/ logs/ network-captures/ INDICE-EVIDENCIAS.md

# Verificar tamaño
du -sh screenshots/ logs/ network-captures/
```

## 11. Referencias

- **NIST 800-115**: Documentation requirements for penetration testing
- **PTES**: Penetration Testing Execution Standard - Reporting guidelines
- **OWASP Testing Guide**: Evidence collection best practices
- **Wireshark User Guide**: https://www.wireshark.org/docs/wsug_html/

## 12. Troubleshooting

### Screenshot no se captura

```bash
# Verificar herramientas disponibles
command -v scrot
command -v gnome-screenshot
command -v import

# Instalar si falta
sudo apt-get install scrot
# o
sudo apt-get install gnome-screenshot
```

### PCAP no captura tráfico

```bash
# Verificar permisos
sudo chmod +x ../07-Scripts/capture-evidence.sh

# Usar tcpdump directamente con sudo
sudo tcpdump -i eth0 -w test.pcap

# Verificar interfaces disponibles
ip link show
ifconfig -a
```

### Metadata no se genera

```bash
# Verificar que jq está instalado
command -v jq

# Instalar jq
sudo apt-get install jq
```

---

**Última actualización**: 2024-12-03
**Directorio**: 06-Evidencias/
