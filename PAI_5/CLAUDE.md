# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **PAI-5 (RedTeamPro)** - a university assignment for the "Seguridad en Sistemas Informáticos e Internet" course at Universidad de Sevilla. The project focuses on conducting professional Red Team security assessments of public organizations following real-world methodologies.

**Key Principle**: "No Toy Pentesting" - Work with realistic approaches based on real threats, well-founded, and with strategic impact.

## Assignment Context

### Deliverables Required
1. **Technical Report (PDF)**: Comprehensive documentation covering all phases of the security assessment process, including:
   - Detailed results of all tasks performed
   - Evidence from all tests conducted
   - No page limit

2. **Source Code & Configurations**: Any implementations, scripts developed, or tool configurations used

3. **Logs & Evidence**: All logs and proof-of-concept evidence to ensure reproducibility

**Submission Format**: PA5-ST<NUM>.zip

### Frameworks & Standards

The project follows established security frameworks:

- **MITRE ATT&CK**: Tactics, techniques, and procedures (TTPs) based on real-world adversary behavior
  - Use ATT&CK Enterprise matrix for identifying tactics (WHY) and techniques (HOW)
  - Link techniques with unique identifiers (e.g., TA0006, T1110)
  - Reference specific procedures used by real attacker groups

- **MITRE CVE**: Common Vulnerabilities and Exposures database (276,000+ entries)
  - Identify practical, real attack vectors
  - Focus on exploitable vulnerabilities with available PoCs/exploits
  - Include CVSS severity scores and affected versions

- **CISA KEV**: Known Exploited Vulnerabilities catalog
  - Prioritize vulnerabilities actively exploited in the wild
  - Focus on immediate real-world risks
  - These represent what Blue Teams should patch first

- **NIST 800-115**: Technical Guide to Information Security Testing and Assessment
  - Follow the Plan → Execute → Post-execution cycle
  - Cover all pentesting phases: Reconnaissance, Scanning, Gaining Access, Maintaining Access, Clear Tracks, Reporting

### Methodology

#### Red Team Workflow (Pentesting Cycle)
1. **Reconnaissance**: Nmap, Recon-ng, Shodan, ZoomEye, Google Dorks, Maltego
2. **Scanning**: Nessus, OpenVAS, Nikto, Qualys
3. **Gaining Access**: Metasploit, SearchSploit, Empire, Social Engineering Toolkit
4. **Maintaining Access**: Netcat, PowerSploit
5. **Clear Tracks**: LinPEAS, Mimikatz
6. **Reporting**: Faraday, Dradis

#### Testing Approaches
- **Black Box**: No prior knowledge of internal infrastructure (simulates external attacker)
- **White Box**: Full knowledge and access to internal systems (comprehensive internal testing)

### Project Objectives

1. **Planning Phase**:
   - Define security testing scenario
   - Identify target services and applications
   - Analyze vulnerabilities and deployed security controls
   - Define specific security tests to perform

2. **Execution Phase** (Exploitation, Privilege Escalation, Post-exploitation):
   - Execute tests and identify potential security breaches
   - Capture evidence of all security tests

3. **Reporting Phase**:
   - Analyze security test results
   - Define mitigation plan
   - Generate technical report documenting the entire process and findings

## Tools & Technologies

### Open-Source Red Team Tools
- **MITRE Caldera**: ATT&CK-based automation with lightweight agent for Red Team operations
- **Uber Metta**: Lighter than Caldera, also ATT&CK-based
- **Atomic Red Team** (Red Canary): Execute small, specific "atomic" tests aligned with MITRE ATT&CK techniques

These tools support "security validation as code" and can be integrated into CI/CD pipelines.

### Standard Pentesting Toolkit
- Reconnaissance: Nmap, Shodan, Maltego, Google Dorking
- Vulnerability Scanning: OpenVAS, Nessus, Nikto
- Exploitation: Metasploit Framework, SearchSploit
- Post-exploitation: Mimikatz, LinPEAS, PowerSploit
- Reporting: Faraday, Dradis

## Best Practices

### Evidence Collection
- Capture screenshots of all findings
- Save command outputs and logs
- Document exact steps for reproducibility
- Record timestamps of all activities

### Report Structure
Follow NIST 800-115 phases in documentation:
1. Planning and preparation
2. Execution details (techniques used with ATT&CK IDs)
3. Findings (vulnerabilities with CVE references)
4. Risk assessment (CVSS scores)
5. Mitigation recommendations
6. Appendices (logs, screenshots, tool outputs)

### Security & Ethics
- This is an **authorized educational assignment**
- All testing must be within assigned scope
- Follow responsible disclosure principles
- Do not perform DoS attacks or destructive actions without explicit permission
- Maintain confidentiality of findings

## Working with Scripts

When developing or using exploitation scripts:
- Always test in controlled environments first
- Document all dependencies and requirements
- Include usage instructions and safety warnings
- Reference relevant CVE and ATT&CK technique IDs in comments
- Ensure reproducibility for assessment grading

## Integration with Frameworks

### Linking CVE to ATT&CK
Example: CVE-2021-34527 (PrintNightmare) maps to:
- T1543.003: Create or Modify System Process (Windows Service)
- T1055: Process Injection
- T1068: Exploitation for Privilege Escalation

Always document these relationships in reports to demonstrate strategic understanding.
