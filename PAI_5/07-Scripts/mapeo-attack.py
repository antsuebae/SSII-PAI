#!/usr/bin/env python3
"""
mapeo-attack.py - Script de Mapeo a MITRE ATT&CK para PAI-5 RedTeamPro
Mapea vulnerabilidades encontradas a técnicas MITRE ATT&CK
Autor: PAI-5 RedTeamPro Team
"""

import json
import os
import sys
import re
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

# Mapeo de vulnerabilidades DVWA a técnicas MITRE ATT&CK
DVWA_ATTACK_MAPPING = {
    "sql_injection": {
        "techniques": ["T1213", "T1087", "T1555"],
        "tactic": "Collection",
        "description": "SQL Injection para extracción de datos",
        "cwe": "CWE-89",
        "cvss": 9.8,
        "severity": "Critical"
    },
    "command_injection": {
        "techniques": ["T1059.004", "T1083", "T1082"],
        "tactic": "Execution",
        "description": "Inyección de comandos del sistema",
        "cwe": "CWE-78",
        "cvss": 9.8,
        "severity": "Critical"
    },
    "file_upload": {
        "techniques": ["T1505.003", "T1059.004"],
        "tactic": "Persistence",
        "description": "Upload de archivos maliciosos (web shell)",
        "cwe": "CWE-434",
        "cvss": 9.8,
        "severity": "Critical"
    },
    "xss_stored": {
        "techniques": ["T1059.007", "T1041"],
        "tactic": "Execution",
        "description": "Cross-Site Scripting persistente",
        "cwe": "CWE-79",
        "cvss": 8.8,
        "severity": "High"
    },
    "xss_reflected": {
        "techniques": ["T1059.007"],
        "tactic": "Execution",
        "description": "Cross-Site Scripting reflejado",
        "cwe": "CWE-79",
        "cvss": 6.1,
        "severity": "Medium"
    },
    "csrf": {
        "techniques": ["T1185"],
        "tactic": "Collection",
        "description": "Cross-Site Request Forgery",
        "cwe": "CWE-352",
        "cvss": 6.5,
        "severity": "Medium"
    },
    "brute_force": {
        "techniques": ["T1110.001", "T1110.003"],
        "tactic": "Credential Access",
        "description": "Ataque de fuerza bruta a credenciales",
        "cwe": "CWE-307",
        "cvss": 7.5,
        "severity": "High"
    },
    "file_inclusion": {
        "techniques": ["T1083", "T1005"],
        "tactic": "Discovery",
        "description": "File Inclusion (LFI/RFI)",
        "cwe": "CWE-98",
        "cvss": 8.6,
        "severity": "High"
    },
    "weak_session": {
        "techniques": ["T1539", "T1552.001"],
        "tactic": "Credential Access",
        "description": "IDs de sesión débiles",
        "cwe": "CWE-330",
        "cvss": 5.3,
        "severity": "Medium"
    },
    "insecure_captcha": {
        "techniques": ["T1110"],
        "tactic": "Credential Access",
        "description": "CAPTCHA inseguro o bypasseable",
        "cwe": "CWE-804",
        "cvss": 4.3,
        "severity": "Low"
    }
}

# Técnicas de reconocimiento y escaneo
RECON_SCAN_TECHNIQUES = {
    "nmap_scan": {
        "techniques": ["T1046"],
        "tactic": "Discovery",
        "description": "Network Service Scanning con Nmap"
    },
    "port_scan": {
        "techniques": ["T1046"],
        "tactic": "Discovery",
        "description": "Port Scanning"
    },
    "service_enum": {
        "techniques": ["T1046"],
        "tactic": "Discovery",
        "description": "Service Enumeration"
    },
    "os_detection": {
        "techniques": ["T1082"],
        "tactic": "Discovery",
        "description": "OS Detection"
    },
    "vuln_scan": {
        "techniques": ["T1595.002"],
        "tactic": "Reconnaissance",
        "description": "Vulnerability Scanning"
    },
    "dns_enum": {
        "techniques": ["T1590.002"],
        "tactic": "Reconnaissance",
        "description": "DNS Enumeration"
    },
    "web_fingerprint": {
        "techniques": ["T1593"],
        "tactic": "Reconnaissance",
        "description": "Web Application Fingerprinting"
    }
}

class AttackMapper:
    """Clase para mapear vulnerabilidades a MITRE ATT&CK"""

    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.findings: List[Dict] = []
        self.techniques_used: Dict[str, List[Dict]] = {}

    def parse_nikto_output(self, nikto_file: Path) -> List[Dict]:
        """Parsea output de Nikto y extrae vulnerabilidades"""
        findings = []

        try:
            with open(nikto_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Buscar líneas con vulnerabilidades (marcadas con +)
                for line in content.split('\n'):
                    if line.strip().startswith('+'):
                        # Clasificar vulnerabilidad
                        vuln_type = self._classify_nikto_line(line)
                        if vuln_type:
                            findings.append({
                                "source": "nikto",
                                "type": vuln_type,
                                "description": line.strip(),
                                "file": str(nikto_file.name)
                            })

        except Exception as e:
            print(f"Error parseando Nikto: {e}", file=sys.stderr)

        return findings

    def _classify_nikto_line(self, line: str) -> str:
        """Clasifica una línea de Nikto según el tipo de vulnerabilidad"""
        line_lower = line.lower()

        if "sql" in line_lower and ("injection" in line_lower or "error" in line_lower):
            return "sql_injection"
        elif "xss" in line_lower or "cross-site" in line_lower:
            return "xss_reflected"
        elif "csrf" in line_lower:
            return "csrf"
        elif "command" in line_lower and "injection" in line_lower:
            return "command_injection"
        elif "file" in line_lower and ("upload" in line_lower or "inclusion" in line_lower):
            return "file_upload"
        elif "session" in line_lower:
            return "weak_session"

        return None

    def parse_nmap_output(self, nmap_file: Path) -> List[Dict]:
        """Parsea output de Nmap"""
        findings = []

        try:
            with open(nmap_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Detectar tipo de scan
                if "PORT STATE SERVICE" in content:
                    findings.append({
                        "source": "nmap",
                        "type": "port_scan",
                        "description": "Port scanning executed",
                        "file": str(nmap_file.name)
                    })

                if "OS detection" in content or "OS:" in content:
                    findings.append({
                        "source": "nmap",
                        "type": "os_detection",
                        "description": "OS detection executed",
                        "file": str(nmap_file.name)
                    })

                if "version" in content.lower() or "VERSION" in content:
                    findings.append({
                        "source": "nmap",
                        "type": "service_enum",
                        "description": "Service enumeration executed",
                        "file": str(nmap_file.name)
                    })

                # Buscar vulnerabilidades en scripts NSE
                if "| vuln" in content or "|_vuln" in content:
                    findings.append({
                        "source": "nmap",
                        "type": "vuln_scan",
                        "description": "Vulnerability scanning with NSE scripts",
                        "file": str(nmap_file.name)
                    })

        except Exception as e:
            print(f"Error parseando Nmap: {e}", file=sys.stderr)

        return findings

    def parse_evidence_metadata(self, evidence_dir: Path) -> List[Dict]:
        """Parsea metadata de evidencias capturadas"""
        findings = []

        try:
            # Buscar archivos .meta.json
            for meta_file in evidence_dir.rglob("*.meta.json"):
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)

                    attack_id = metadata.get("attack_id", "")
                    if attack_id and attack_id != "N/A":
                        findings.append({
                            "source": "evidence",
                            "attack_id": attack_id,
                            "phase": metadata.get("phase", "unknown"),
                            "technique": metadata.get("technique", "unknown"),
                            "description": metadata.get("description", ""),
                            "file": metadata.get("file", "")
                        })

        except Exception as e:
            print(f"Error parseando metadata de evidencias: {e}", file=sys.stderr)

        return findings

    def map_finding_to_attack(self, finding: Dict) -> Dict:
        """Mapea un hallazgo a técnicas MITRE ATT&CK"""
        vuln_type = finding.get("type", "")

        # Buscar en mapeos DVWA
        if vuln_type in DVWA_ATTACK_MAPPING:
            mapping = DVWA_ATTACK_MAPPING[vuln_type]
            return {
                **finding,
                "techniques": mapping["techniques"],
                "tactic": mapping["tactic"],
                "cwe": mapping.get("cwe", "N/A"),
                "cvss": mapping.get("cvss", 0.0),
                "severity": mapping.get("severity", "Unknown"),
                "attack_description": mapping["description"]
            }

        # Buscar en técnicas de reconocimiento
        if vuln_type in RECON_SCAN_TECHNIQUES:
            mapping = RECON_SCAN_TECHNIQUES[vuln_type]
            return {
                **finding,
                "techniques": mapping["techniques"],
                "tactic": mapping["tactic"],
                "attack_description": mapping["description"]
            }

        # Si viene de evidencia con attack_id
        if "attack_id" in finding:
            return finding

        return finding

    def generate_attack_matrix(self) -> Dict:
        """Genera matriz MITRE ATT&CK con todas las técnicas usadas"""
        matrix = {
            "Reconnaissance": [],
            "Initial Access": [],
            "Execution": [],
            "Persistence": [],
            "Privilege Escalation": [],
            "Defense Evasion": [],
            "Credential Access": [],
            "Discovery": [],
            "Collection": [],
            "Exfiltration": []
        }

        for finding in self.findings:
            tactic = finding.get("tactic", "")
            techniques = finding.get("techniques", [])

            if tactic in matrix:
                for technique_id in techniques:
                    if technique_id not in [t["id"] for t in matrix[tactic]]:
                        matrix[tactic].append({
                            "id": technique_id,
                            "finding": finding.get("description", ""),
                            "source": finding.get("source", "unknown")
                        })

        return matrix

    def generate_report(self, output_file: Path):
        """Genera reporte de mapeo a MITRE ATT&CK"""
        matrix = self.generate_attack_matrix()

        report = []
        report.append("# Mapeo a MITRE ATT&CK - PAI-5 RedTeamPro\n")
        report.append(f"**Fecha de generación**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.append(f"**Total de hallazgos**: {len(self.findings)}\n")
        report.append("\n---\n")

        # Resumen por táctica
        report.append("\n## Resumen de Tácticas y Técnicas\n\n")
        report.append("| Táctica | Técnicas | Count |\n")
        report.append("|---------|----------|-------|\n")

        for tactic, techniques in matrix.items():
            if techniques:
                tech_ids = ", ".join([t["id"] for t in techniques])
                report.append(f"| {tactic} | {tech_ids} | {len(techniques)} |\n")

        # Detalle de hallazgos
        report.append("\n## Detalle de Hallazgos\n")

        for tactic, techniques in matrix.items():
            if not techniques:
                continue

            report.append(f"\n### {tactic}\n\n")

            for technique in techniques:
                report.append(f"#### {technique['id']}\n\n")
                report.append(f"- **Hallazgo**: {technique['finding']}\n")
                report.append(f"- **Fuente**: {technique['source']}\n")
                report.append(f"- **Referencia**: https://attack.mitre.org/techniques/{technique['id'].replace('.', '/')}/\n")
                report.append("\n")

        # Lista completa de hallazgos
        report.append("\n## Lista Completa de Hallazgos\n\n")
        report.append("| # | Tipo | Técnicas ATT&CK | Severidad | Fuente |\n")
        report.append("|---|------|-----------------|-----------|--------|\n")

        for idx, finding in enumerate(self.findings, 1):
            vuln_type = finding.get("type", finding.get("technique", "unknown"))
            techniques = ", ".join(finding.get("techniques", [finding.get("attack_id", "")]))
            severity = finding.get("severity", "N/A")
            source = finding.get("source", "unknown")

            report.append(f"| {idx} | {vuln_type} | {techniques} | {severity} | {source} |\n")

        # Guardar reporte
        with open(output_file, 'w') as f:
            f.writelines(report)

        print(f"[✓] Reporte generado: {output_file}")

        # Generar también JSON
        json_file = output_file.with_suffix('.json')
        with open(json_file, 'w') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "matrix": matrix,
                "findings": self.findings
            }, f, indent=2)

        print(f"[✓] JSON generado: {json_file}")

    def process(self, input_dir: Path):
        """Procesa todos los archivos de input"""
        print(f"[i] Procesando archivos en: {input_dir}")

        # Procesar Nikto
        nikto_dir = self.project_root / "03-Escaneo" / "nikto-output"
        if nikto_dir.exists():
            for nikto_file in nikto_dir.glob("*.txt"):
                print(f"[i] Procesando Nikto: {nikto_file.name}")
                self.findings.extend(self.parse_nikto_output(nikto_file))

        # Procesar Nmap
        nmap_dir = self.project_root / "02-Reconocimiento" / "nmap-results"
        if nmap_dir.exists():
            for nmap_file in nmap_dir.glob("*.nmap"):
                print(f"[i] Procesando Nmap: {nmap_file.name}")
                self.findings.extend(self.parse_nmap_output(nmap_file))

        # Procesar evidencias con metadata
        evidence_dir = self.project_root / "06-Evidencias"
        if evidence_dir.exists():
            print(f"[i] Procesando metadata de evidencias")
            self.findings.extend(self.parse_evidence_metadata(evidence_dir))

        # Mapear todos los hallazgos a ATT&CK
        mapped_findings = []
        for finding in self.findings:
            mapped = self.map_finding_to_attack(finding)
            mapped_findings.append(mapped)

        self.findings = mapped_findings

        print(f"[✓] Total de hallazgos procesados: {len(self.findings)}")


def main():
    parser = argparse.ArgumentParser(
        description="Mapea vulnerabilidades encontradas a técnicas MITRE ATT&CK"
    )
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        help="Directorio de input (por defecto: PROJECT_ROOT)"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Archivo de output (por defecto: 08-Informe/mapeo-attack.md)"
    )
    parser.add_argument(
        "--project-root",
        "-p",
        type=str,
        help="Directorio raíz del proyecto"
    )

    args = parser.parse_args()

    # Determinar PROJECT_ROOT
    if args.project_root:
        project_root = Path(args.project_root)
    else:
        # Asumir que estamos en 07-Scripts/
        script_dir = Path(__file__).parent
        project_root = script_dir.parent

    print(f"[i] Proyecto: {project_root}")

    # Crear mapper
    mapper = AttackMapper(str(project_root))

    # Determinar input directory
    if args.input:
        input_dir = Path(args.input)
    else:
        input_dir = project_root

    # Procesar archivos
    mapper.process(input_dir)

    # Generar reporte
    if args.output:
        output_file = Path(args.output)
    else:
        output_file = project_root / "08-Informe" / "mapeo-attack.md"

    # Crear directorio de output si no existe
    output_file.parent.mkdir(parents=True, exist_ok=True)

    mapper.generate_report(output_file)

    print("\n[✓] Mapeo a MITRE ATT&CK completado")
    print(f"[i] Reporte: {output_file}")


if __name__ == "__main__":
    main()
