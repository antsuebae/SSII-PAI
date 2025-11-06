// PAI-3 VULNAWEB - Firefox Security Configuration
// Security Team INSEGUS
// Copiar este archivo a: ~/.mozilla/firefox/[perfil]/user.js

// =============================================================================
// PRIVACIDAD Y TRACKING
// =============================================================================

// Deshabilitar telemetría
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);

// Protección contra tracking
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.pbmode.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);

// Resist Fingerprinting
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);

// =============================================================================
// COOKIES
// =============================================================================

// Cookies solo del mismo sitio
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("network.cookie.sameSite.laxByDefault", true);
user_pref("network.cookie.sameSite.noneRequiresSecure", true);

// =============================================================================
// HTTPS Y TLS
// =============================================================================

// HTTPS-Only Mode
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);
user_pref("dom.security.https_only_mode_send_http_background_request", false);

// TLS Settings
user_pref("security.tls.version.min", 3); // TLS 1.3
user_pref("security.tls.version.enable-deprecated", false);
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);

// Deshabilitar SSL3 y versiones antiguas
user_pref("security.ssl3.rsa_des_ede3_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);

// OCSP Stapling
user_pref("security.ssl.enable_ocsp_stapling", true);
user_pref("security.OCSP.require", true);
user_pref("security.OCSP.enabled", 1);

// Certificate Transparency
user_pref("security.pki.certificate_transparency.mode", 1);

// =============================================================================
// CONTENIDO Y SCRIPTS
// =============================================================================

// WebRTC (desabilitar para evitar IP leaks)
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);

// WebGL (puede ser vector de ataques)
user_pref("webgl.disabled", true);
user_pref("webgl.enable-webgl2", false);

// Autoplay
user_pref("media.autoplay.default", 5);
user_pref("media.autoplay.blocking_policy", 2);

// =============================================================================
// SEGURIDAD DE CONTENIDO
// =============================================================================

// Deshabilitar WebAssembly si no es necesario
// user_pref("javascript.options.wasm", false);

// XSS Filter
user_pref("security.xssfilter.enable", true);

// Referrer Policy
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
user_pref("network.http.referer.trimmingPolicy", 2);

// =============================================================================
// DESCARGAS Y ARCHIVOS
// =============================================================================

// Preguntar dónde guardar cada archivo
user_pref("browser.download.useDownloadDir", false);
user_pref("browser.download.folderList", 2);

// Deshabilitar apertura automática de archivos
user_pref("browser.download.autohideButton", false);

// =============================================================================
// CACHE Y ALMACENAMIENTO
// =============================================================================

// Limpiar cache al cerrar
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", true);
user_pref("browser.cache.offline.enable", false);

// Limpiar datos al cerrar
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);

// =============================================================================
// ACTUALIZACIONES
// =============================================================================

// Actualizaciones automáticas de seguridad
user_pref("app.update.auto", true);
user_pref("extensions.update.autoUpdateDefault", true);

// =============================================================================
// DNS Y NETWORKING
// =============================================================================

// DNS over HTTPS
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://mozilla.cloudflare-dns.com/dns-query");

// IPv6 (deshabilitar si no se usa)
// user_pref("network.dns.disableIPv6", true);

// =============================================================================
// COMERCIO ELECTRÓNICO ESPECÍFICO
// =============================================================================

// Avisos de sitios no seguros
user_pref("security.warn_entering_secure", false);
user_pref("security.warn_entering_weak", true);
user_pref("security.warn_leaving_secure", false);

// Bloqueo de contenido mixto
user_pref("security.mixed_content.block_active_content", true);
user_pref("security.mixed_content.block_display_content", true);

// Phishing y Malware Protection
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);

// =============================================================================
// UI Y EXPERIENCIA
// =============================================================================

// Deshabilitar pocket
user_pref("extensions.pocket.enabled", false);

// Deshabilitar screenshots
user_pref("extensions.screenshots.disabled", true);

// Password manager (usar gestor externo recomendado)
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);

// =============================================================================
// AVANZADO
// =============================================================================

// Deshabilitar WebUSB
user_pref("dom.webusb.enabled", false);

// Deshabilitar Web Notifications
user_pref("dom.webnotifications.enabled", false);

// Deshabilitar geolocation
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");

// Deshabilitar clipboard access
user_pref("dom.event.clipboardevents.enabled", false);

// =============================================================================
// NOTAS IMPORTANTES
// =============================================================================

// ADVERTENCIA: Algunas de estas configuraciones pueden romper funcionalidad
// de ciertos sitios web. Ajustar según necesidades específicas.
//
// Para comercio electrónico:
// - Mantener cookies habilitadas para sitios de confianza
// - Permitir JavaScript (requerido para la mayoría de e-commerce)
// - No deshabilitar completamente el cache (puede afectar rendimiento)
//
// Después de aplicar estos cambios:
// 1. Reiniciar Firefox
// 2. Verificar que sitios de comercio electrónico funcionen correctamente
// 3. Ajustar excepciones según sea necesario
//
// Para más información:
// https://wiki.mozilla.org/Security/Referrer
// https://support.mozilla.org/en-US/kb/firefox-protection-against-fingerprinting
