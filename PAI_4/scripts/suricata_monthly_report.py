#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
========================================================================
Script de Análisis Mensual de Logs de Suricata IDS
PAI-4: Monitorización y Generación de Informes
========================================================================

Funcionalidades:
- Análisis de logs fast.log de Suricata
- Agrupación de alertas por servicio
- Identificación de IPs atacantes
- Clasificación por tipo de ataque
- Generación de informes TXT y HTML

Autor: Security Team ST-XX
Fecha: Noviembre 2025
"""

import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ========================================================================
# CONFIGURACIÓN
# ========================================================================

# Mapeo de puertos a servicios
SERVICE_PORTS = {"8083": "HTTP", "8443": "HTTPS", "3336": "MySQL", "2288": "SSH/SFTP"}

# Mapeo de SIDs a descripciones de reglas
RULE_DESCRIPTIONS = {
    "1000001": "Acceso HTTP no autorizado (puerto 8083)",
    "1000002": "Acceso HTTPS no autorizado (puerto 8443)",
    "1000003": "Intento de SQL Injection",
    "1000004": "Intento de Cross-Site Scripting (XSS)",
    "1000005": "Acceso MySQL no autorizado (puerto 3336)",
    "1000006": "Intento de fuerza bruta MySQL",
    "1000007": "Acceso SSH no autorizado (puerto 2288)",
    "1000008": "Intento de fuerza bruta SSH",
    "1000009": "Escaneo de puerto SSH",
    "1000010": "Escaneo Nmap SYN detectado",
    "1000011": "Posible ICMP Flood (DoS)",
    "1000012": "Intento de Path Traversal",
}

# Clasificación de severidad por SID
SEVERITY_MAP = {
    "1000003": "CRÍTICO",  # SQL Injection
    "1000004": "CRÍTICO",  # XSS
    "1000005": "CRÍTICO",  # MySQL no autorizado
    "1000006": "ALTO",  # Fuerza bruta MySQL
    "1000008": "ALTO",  # Fuerza bruta SSH
    "1000011": "ALTO",  # DoS
    "1000001": "MEDIO",  # HTTP no autorizado
    "1000002": "MEDIO",  # HTTPS no autorizado
    "1000007": "MEDIO",  # SSH no autorizado
    "1000009": "BAJO",  # Escaneo SSH
    "1000010": "BAJO",  # Escaneo Nmap
    "1000012": "MEDIO",  # Path Traversal
}


# ========================================================================
# CLASE PRINCIPAL DE ANÁLISIS
# ========================================================================


class SuricataLogAnalyzer:
    """Analizador de logs de Suricata con generación de informes"""

    def __init__(self, log_file_path):
        """
        Inicializa el analizador

        Args:
            log_file_path: Ruta al archivo fast.log de Suricata
        """
        self.log_file = Path(log_file_path)
        self.alerts = []
        self.stats = {
            "total_alerts": 0,
            "by_service": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_sid": defaultdict(int),
            "by_ip": defaultdict(int),
            "by_type": defaultdict(int),
            "by_target": defaultdict(int),
        }

        # Verificar que existe el archivo
        if not self.log_file.exists():
            raise FileNotFoundError(f"No se encuentra el archivo: {self.log_file}")

    def parse_log_line(self, line):
        """
        Parsea una línea del log de Suricata

        Formato esperado:
        MM/DD/YYYY-HH:MM:SS.microsec [**] [1:SID:REV] MESSAGE [**] [Classification: X] [Priority: Y] {PROTOCOL} SRC_IP:PORT -> DST_IP:PORT

        Args:
            line: Línea del log a parsear

        Returns:
            dict con los datos parseados o None si no se puede parsear
        """
        # Patrón regex para parsear el log
        pattern = r"(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[1:(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\].*?\{(\w+)\}\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)"

        match = re.search(pattern, line)
        if not match:
            return None

        timestamp, sid, rev, message, protocol, src_ip, src_port, dst_ip, dst_port = (
            match.groups()
        )

        # Determinar el servicio según el puerto destino
        service = SERVICE_PORTS.get(dst_port, "OTRO")

        # Determinar tipo de alerta
        alert_type = "ALERTA"
        if (
            "ATAQUE" in message
            or "SQL" in message
            or "XSS" in message
            or "bruta" in message
        ):
            alert_type = "ATAQUE"
        elif "RECONOCIMIENTO" in message or "Escaneo" in message or "Nmap" in message:
            alert_type = "RECONOCIMIENTO"
        elif "CRITICA" in message:
            alert_type = "CRÍTICO"

        # Determinar severidad
        severity = SEVERITY_MAP.get(sid, "MEDIO")

        return {
            "timestamp": timestamp,
            "sid": sid,
            "rev": rev,
            "message": message.strip(),
            "protocol": protocol,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "service": service,
            "type": alert_type,
            "severity": severity,
        }

    def analyze(self):
        """Analiza el archivo de logs y genera estadísticas"""
        print(f"[INFO] Analizando archivo: {self.log_file}")

        with open(self.log_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                alert = self.parse_log_line(line)
                if alert:
                    self.alerts.append(alert)
                    self.stats["total_alerts"] += 1
                    self.stats["by_service"][alert["service"]] += 1
                    self.stats["by_severity"][alert["severity"]] += 1
                    self.stats["by_sid"][alert["sid"]] += 1
                    self.stats["by_ip"][alert["src_ip"]] += 1
                    self.stats["by_type"][alert["type"]] += 1
                    self.stats["by_target"][alert["dst_ip"]] += 1

        print(f"[INFO] Total de alertas procesadas: {self.stats['total_alerts']}")
        return self.stats

    def get_top_attackers(self, n=10):
        """Obtiene las N IPs atacantes más frecuentes"""
        return Counter(self.stats["by_ip"]).most_common(n)

    def get_alerts_by_service(self):
        """Agrupa las alertas por servicio"""
        service_alerts = defaultdict(list)
        for alert in self.alerts:
            service_alerts[alert["service"]].append(alert)
        return service_alerts

    def generate_text_report(self, output_file):
        """
        Genera un informe en formato texto

        Args:
            output_file: Ruta del archivo de salida
        """
        with open(output_file, "w", encoding="utf-8") as f:
            # Encabezado
            f.write("=" * 80 + "\n")
            f.write("INFORME MENSUAL DE SEGURIDAD - SURICATA IDS\n")
            f.write("=" * 80 + "\n")
            f.write(
                f"Fecha de generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
            f.write(f"Archivo analizado: {self.log_file}\n")
            f.write("=" * 80 + "\n\n")

            # Resumen Ejecutivo
            f.write("1. RESUMEN EJECUTIVO\n")
            f.write("-" * 80 + "\n\n")
            f.write(f"Total de alertas detectadas: {self.stats['total_alerts']}\n\n")

            # Distribución por severidad
            f.write("Distribución por severidad:\n")
            for severity in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
                count = self.stats["by_severity"][severity]
                if count > 0:
                    percentage = (count / self.stats["total_alerts"]) * 100
                    f.write(
                        f"  • {severity:10s}: {count:4d} alertas ({percentage:5.1f}%)\n"
                    )
            f.write("\n")

            # Distribución por tipo
            f.write("Distribución por tipo de incidente:\n")
            for alert_type, count in sorted(
                self.stats["by_type"].items(), key=lambda x: x[1], reverse=True
            ):
                percentage = (count / self.stats["total_alerts"]) * 100
                f.write(
                    f"  • {alert_type:15s}: {count:4d} alertas ({percentage:5.1f}%)\n"
                )
            f.write("\n")

            # Alertas por servicio
            f.write("\n2. ALERTAS POR SERVICIO\n")
            f.write("-" * 80 + "\n\n")

            service_alerts = self.get_alerts_by_service()
            for service in ["HTTP", "HTTPS", "MySQL", "SSH/SFTP", "OTRO"]:
                alerts = service_alerts.get(service, [])
                if not alerts:
                    continue

                f.write(
                    f"2.{list(SERVICE_PORTS.values()).index(service) + 1 if service in SERVICE_PORTS.values() else 5}. Servicio: {service}\n"
                )
                f.write("-" * 40 + "\n")
                f.write(f"Total de alertas: {len(alerts)}\n\n")

                # Contar tipos de alerta para este servicio
                type_count = Counter(alert["type"] for alert in alerts)
                f.write("Distribución por tipo:\n")
                for alert_type, count in type_count.most_common():
                    f.write(f"  • {alert_type}: {count} alertas\n")
                f.write("\n")

                # Contar SIDs para este servicio
                sid_count = Counter(alert["sid"] for alert in alerts)
                f.write("Reglas activadas (SID):\n")
                for sid, count in sid_count.most_common():
                    rule_desc = RULE_DESCRIPTIONS.get(sid, f"Regla {sid}")
                    f.write(f"  • SID {sid}: {count} veces - {rule_desc}\n")
                f.write("\n")

                # IPs atacantes para este servicio
                ip_count = Counter(alert["src_ip"] for alert in alerts)
                f.write("Top 5 IPs atacantes:\n")
                for ip, count in ip_count.most_common(5):
                    f.write(f"  • {ip}: {count} intentos\n")
                f.write("\n\n")

            # Top IPs atacantes global
            f.write("\n3. TOP 10 IPs ATACANTES (GLOBAL)\n")
            f.write("-" * 80 + "\n\n")
            f.write(f"{'#':<4} {'IP Address':<18} {'Alertas':<10} {'Porcentaje'}\n")
            f.write("-" * 80 + "\n")

            for idx, (ip, count) in enumerate(self.get_top_attackers(10), 1):
                percentage = (count / self.stats["total_alerts"]) * 100
                f.write(f"{idx:<4} {ip:<18} {count:<10} {percentage:5.1f}%\n")
            f.write("\n")

            # Sistemas objetivo
            f.write("\n4. SISTEMAS OBJETIVO\n")
            f.write("-" * 80 + "\n\n")
            f.write(f"{'IP Objetivo':<18} {'Alertas':<10} {'Porcentaje'}\n")
            f.write("-" * 80 + "\n")

            for dst_ip, count in sorted(
                self.stats["by_target"].items(), key=lambda x: x[1], reverse=True
            ):
                percentage = (count / self.stats["total_alerts"]) * 100
                f.write(f"{dst_ip:<18} {count:<10} {percentage:5.1f}%\n")
            f.write("\n")

            # Recomendaciones
            f.write("\n5. RECOMENDACIONES\n")
            f.write("-" * 80 + "\n\n")

            critical_count = self.stats["by_severity"]["CRÍTICO"]
            high_count = self.stats["by_severity"]["ALTO"]

            if critical_count > 0:
                f.write("⚠️  ACCIÓN INMEDIATA REQUERIDA:\n")
                f.write(
                    f"   Se detectaron {critical_count} alertas de severidad CRÍTICA.\n"
                )
                f.write("   • Revisar intentos de SQL Injection y XSS\n")
                f.write("   • Verificar accesos no autorizados a MySQL\n")
                f.write("   • Implementar WAF si no está presente\n\n")

            if high_count > 5:
                f.write("⚠️  ATENCIÓN PRIORITARIA:\n")
                f.write(f"   Se detectaron {high_count} alertas de severidad ALTA.\n")
                f.write("   • Investigar intentos de fuerza bruta\n")
                f.write("   • Implementar rate limiting\n")
                f.write("   • Considerar bloqueo de IPs repetidoras\n\n")

            # Top IPs a bloquear
            top_ips = [ip for ip, count in self.get_top_attackers(5) if count > 5]
            if top_ips:
                f.write("📋 IPs RECOMENDADAS PARA BLOQUEO:\n")
                for ip in top_ips:
                    f.write(f"   • {ip}\n")
                f.write("\n")

            # Revisión de reglas
            f.write("🔧 MANTENIMIENTO:\n")
            f.write("   • Actualizar feeds de Suricata semanalmente\n")
            f.write("   • Revisar falsos positivos en logs\n")
            f.write("   • Ajustar thresholds si es necesario\n")
            f.write("   • Mantener backups de configuración\n\n")

            # Pie
            f.write("=" * 80 + "\n")
            f.write("FIN DEL INFORME\n")
            f.write("=" * 80 + "\n")

        print(f"[✓] Informe TXT generado: {output_file}")

    def generate_html_report(self, output_file):
        """
        Genera un informe en formato HTML con estilos

        Args:
            output_file: Ruta del archivo de salida HTML
        """
        html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Informe Mensual Suricata IDS</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f4f4f4;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}

        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px 8px 0 0;
            margin: -30px -30px 30px -30px;
        }}

        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        h2 {{
            color: #667eea;
            margin: 30px 0 15px 0;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}

        h3 {{
            color: #764ba2;
            margin: 20px 0 10px 0;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}

        .stat-card h3 {{
            color: white;
            font-size: 0.9em;
            margin: 0 0 10px 0;
            opacity: 0.9;
        }}

        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
        }}

        .severity-critical {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .severity-high {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .severity-medium {{ background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); }}
        .severity-low {{ background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        thead {{
            background: #667eea;
            color: white;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}

        tr:hover {{
            background: #f5f5f5;
        }}

        .alert-box {{
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
            border-left: 5px solid;
        }}

        .alert-critical {{
            background: #fee;
            border-color: #f5576c;
        }}

        .alert-warning {{
            background: #fff3cd;
            border-color: #ffc107;
        }}

        .alert-info {{
            background: #d1ecf1;
            border-color: #17a2b8;
        }}

        .service-section {{
            background: #f9f9f9;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border-left: 5px solid #667eea;
        }}

        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }}

        .badge-critical {{ background: #f5576c; color: white; }}
        .badge-high {{ background: #ffc107; color: #333; }}
        .badge-medium {{ background: #17a2b8; color: white; }}
        .badge-low {{ background: #28a745; color: white; }}

        footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            text-align: center;
            color: #666;
        }}

        .progress-bar {{
            width: 100%;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}

        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 Informe Mensual de Seguridad</h1>
            <p>Sistema de Detección de Intrusos - Suricata IDS</p>
            <p><strong>Generado:</strong> {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}</p>
        </header>

        <section id="resumen">
            <h2>1. Resumen Ejecutivo</h2>

            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Alertas</h3>
                    <div class="value">{self.stats["total_alerts"]}</div>
                </div>

                <div class="stat-card severity-critical">
                    <h3>Críticas</h3>
                    <div class="value">{self.stats["by_severity"]["CRÍTICO"]}</div>
                </div>

                <div class="stat-card severity-high">
                    <h3>Altas</h3>
                    <div class="value">{self.stats["by_severity"]["ALTO"]}</div>
                </div>

                <div class="stat-card severity-medium">
                    <h3>Medias</h3>
                    <div class="value">{self.stats["by_severity"]["MEDIO"]}</div>
                </div>
            </div>

            <h3>Distribución por Tipo de Incidente</h3>
            <table>
                <thead>
                    <tr>
                        <th>Tipo</th>
                        <th>Cantidad</th>
                        <th>Porcentaje</th>
                        <th>Gráfico</th>
                    </tr>
                </thead>
                <tbody>
"""

        # Añadir distribución por tipo
        for alert_type, count in sorted(
            self.stats["by_type"].items(), key=lambda x: x[1], reverse=True
        ):
            percentage = (count / self.stats["total_alerts"]) * 100
            html_content += f"""
                    <tr>
                        <td><strong>{alert_type}</strong></td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                        <td>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {percentage}%">{percentage:.0f}%</div>
                            </div>
                        </td>
                    </tr>
"""

        html_content += """
                </tbody>
            </table>
        </section>

        <section id="servicios">
            <h2>2. Análisis por Servicio</h2>
"""

        # Añadir sección por cada servicio
        service_alerts = self.get_alerts_by_service()
        for service in ["HTTP", "HTTPS", "MySQL", "SSH/SFTP"]:
            alerts = service_alerts.get(service, [])
            if not alerts:
                continue

            # Determinar icono
            icon = {"HTTP": "🌐", "HTTPS": "🔒", "MySQL": "🗄️", "SSH/SFTP": "🔑"}.get(
                service, "📡"
            )

            html_content += f"""
            <div class="service-section">
                <h3>{icon} {service}</h3>
                <p><strong>Total de alertas:</strong> {len(alerts)}</p>
"""

            # Distribución por severidad en este servicio
            severity_count = Counter(alert["severity"] for alert in alerts)
            html_content += "<p><strong>Severidad:</strong> "
            for severity in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
                count = severity_count.get(severity, 0)
                if count > 0:
                    badge_class = f"badge-{severity.lower()}"
                    if severity == "CRÍTICO":
                        badge_class = "badge-critical"
                    html_content += (
                        f'<span class="badge {badge_class}">{severity}: {count}</span> '
                    )
            html_content += "</p>"

            # Top reglas activadas
            sid_count = Counter(alert["sid"] for alert in alerts)
            html_content += "<p><strong>Reglas más activadas:</strong></p><ul>"
            for sid, count in sid_count.most_common(3):
                rule_desc = RULE_DESCRIPTIONS.get(sid, f"Regla {sid}")
                html_content += f"<li>SID {sid} ({count}x): {rule_desc}</li>"
            html_content += "</ul>"

            # Top IPs atacantes
            ip_count = Counter(alert["src_ip"] for alert in alerts)
            html_content += "<p><strong>Top 3 IPs atacantes:</strong></p><ul>"
            for ip, count in ip_count.most_common(3):
                html_content += f"<li>{ip}: {count} intentos</li>"
            html_content += "</ul>"

            html_content += "</div>"

        html_content += """
        </section>

        <section id="atacantes">
            <h2>3. Top 10 IPs Atacantes</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Dirección IP</th>
                        <th>Alertas</th>
                        <th>Porcentaje</th>
                    </tr>
                </thead>
                <tbody>
"""

        for idx, (ip, count) in enumerate(self.get_top_attackers(10), 1):
            percentage = (count / self.stats["total_alerts"]) * 100
            html_content += f"""
                    <tr>
                        <td>{idx}</td>
                        <td><strong>{ip}</strong></td>
                        <td>{count}</td>
                        <td>{percentage:.1f}%</td>
                    </tr>
"""

        html_content += """
                </tbody>
            </table>
        </section>

        <section id="recomendaciones">
            <h2>4. Recomendaciones</h2>
"""

        # Generar alertas según severidad
        critical_count = self.stats["by_severity"]["CRÍTICO"]
        high_count = self.stats["by_severity"]["ALTO"]

        if critical_count > 0:
            html_content += f"""
            <div class="alert-box alert-critical">
                <h3>⚠️ ACCIÓN INMEDIATA REQUERIDA</h3>
                <p>Se detectaron <strong>{critical_count}</strong> alertas de severidad CRÍTICA.</p>
                <ul>
                    <li>Revisar y mitigar intentos de SQL Injection y XSS</li>
                    <li>Verificar accesos no autorizados a bases de datos</li>
                    <li>Implementar Web Application Firewall (WAF)</li>
                    <li>Revisar y parchear vulnerabilidades conocidas</li>
                </ul>
            </div>
"""

        if high_count > 5:
            html_content += f"""
            <div class="alert-box alert-warning">
                <h3>⚠️ ATENCIÓN PRIORITARIA</h3>
                <p>Se detectaron <strong>{high_count}</strong> alertas de severidad ALTA.</p>
                <ul>
                    <li>Investigar intentos de fuerza bruta</li>
                    <li>Implementar rate limiting en servicios expuestos</li>
                    <li>Considerar bloqueo temporal de IPs repetidoras</li>
                    <li>Habilitar autenticación de dos factores (2FA)</li>
                </ul>
            </div>
"""

        # IPs a considerar para bloqueo
        top_ips = [ip for ip, count in self.get_top_attackers(5) if count > 5]
        if top_ips:
            html_content += """
            <div class="alert-box alert-info">
                <h3>📋 IPs Recomendadas para Bloqueo</h3>
                <p>Las siguientes IPs han generado múltiples alertas:</p>
                <ul>
"""
            for ip in top_ips:
                html_content += f"                    <li><code>{ip}</code></li>\n"
            html_content += """
                </ul>
                <p><strong>Comando sugerido (iptables):</strong></p>
                <pre><code>"""
            for ip in top_ips:
                html_content += f"iptables -A INPUT -s {ip} -j DROP\n"
            html_content += """</code></pre>
            </div>
"""

        html_content += """
            <div class="alert-box alert-info">
                <h3>🔧 Mantenimiento Regular</h3>
                <ul>
                    <li>Actualizar feeds de Suricata semanalmente</li>
                    <li>Revisar y ajustar reglas según comportamiento observado</li>
                    <li>Realizar backups regulares de configuración</li>
                    <li>Documentar incidentes y acciones tomadas</li>
                    <li>Mantener logs archivados por al menos 90 días</li>
                </ul>
            </div>
        </section>

        <footer>
            <p><strong>Informe generado por Suricata Log Analyzer</strong></p>
            <p>Security Team ST-XX | PAI-4 Project</p>
            <p>Universidad de Sevilla - E.T.S. Ingeniería Informática</p>
        </footer>
    </div>
</body>
</html>
"""

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"[✓] Informe HTML generado: {output_file}")


# ========================================================================
# FUNCIÓN PRINCIPAL
# ========================================================================


def main():
    """Función principal del script"""

    print("=" * 80)
    print("ANALIZADOR DE LOGS DE SURICATA IDS")
    print("PAI-4: Generación de Informes Mensuales")
    print("=" * 80)
    print()

    # Determinar ruta del log
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        # Obtener directorio del script para buscar rutas relativas
        script_dir = Path(__file__).parent.parent

        # Intentar detectar automáticamente (PRIORIDAD: proyecto local)
        possible_paths = [
            script_dir / "logs-evidencia" / "suricata-fast.log",  # En el proyecto
            Path("logs-evidencia/suricata-fast.log"),  # Desde raíz proyecto
            Path("../logs-evidencia/suricata-fast.log"),  # Un nivel arriba
            Path.home() / "suricata" / "logs" / "fast.log",  # Docker default
            Path("/var/log/suricata/fast.log"),  # Sistema
        ]

        log_file = None
        for path in possible_paths:
            if path.exists():
                log_file = str(path)
                break

        if not log_file:
            print("[ERROR] No se pudo encontrar el archivo fast.log")
            print()
            print("Uso:")
            print(f"  {sys.argv[0]} [ruta/al/fast.log]")
            print()
            print("Rutas buscadas:")
            for path in possible_paths:
                print(f"  - {path}")
            print()
            print("TIP: Si Suricata está corriendo, ejecuta:")
            print("  docker logs suricata-ids")
            print("  tail -f ~/suricata/logs/fast.log")
            sys.exit(1)

    print(f"[INFO] Archivo de log: {log_file}")
    print()

    try:
        # Crear analizador
        analyzer = SuricataLogAnalyzer(log_file)

        # Analizar logs
        analyzer.analyze()

        # Determinar directorio de salida (dentro del proyecto)
        script_dir = Path(__file__).parent.parent
        output_dir = script_dir / "informes"

        if not output_dir.exists():
            output_dir.mkdir(parents=True)
            print(f"[INFO] Creado directorio: {output_dir}")

        # Generar nombres de archivo con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_report = output_dir / f"suricata_informe_{timestamp}.txt"
        html_report = output_dir / f"suricata_informe_{timestamp}.html"

        # Generar informes
        print()
        print("[INFO] Generando informes...")
        analyzer.generate_text_report(txt_report)
        analyzer.generate_html_report(html_report)

        print()
        print("=" * 80)
        print("✓ ANÁLISIS COMPLETADO")
        print("=" * 80)
        print()
        print("Informes generados:")
        print(f"  • Texto: {txt_report}")
        print(f"  • HTML:  {html_report}")
        print()
        print("Para visualizar el informe HTML, abre el archivo en tu navegador.")
        print()

    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error inesperado: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
