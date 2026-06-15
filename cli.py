#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import json
import re

# Add the project root to sys.path to resolve imports correctly
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from app.services.scanner import RULES, remediation_for, detect_frameworks
    from app.services.cve_analyzer import analyze_for_cves
except ImportError as e:
    print(json.dumps({"error": f"Import error: {str(e)}"}), file=sys.stderr)
    sys.exit(1)

def scan_file(filepath):
    if not os.path.exists(filepath):
        return {"error": f"Archivo no encontrado: {filepath}"}
    if os.path.isdir(filepath):
        return {"error": f"La ruta especificada es un directorio, no un archivo: {filepath}"}

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            f.seek(0)
            lines = f.readlines()
    except Exception as e:
        return {"error": f"No se pudo leer el archivo: {str(e)}"}

    findings = []
    frameworks = detect_frameworks(content)

    # 1. Analizar reglas estándar línea por línea para ubicar la posición exacta
    for line_num, line_content in enumerate(lines, start=1):
        for rule in RULES:
            for pattern in rule["patterns"]:
                match = re.search(pattern, line_content, re.IGNORECASE)
                if match:
                    findings.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "evidence": match.group(0).strip(),
                        "line": line_num,
                        "character": match.start(),
                        "remediation": remediation_for(rule["rule_id"], frameworks)
                    })
                    break  # solo reportar una coincidencia de esta regla por línea

    # 2. Analizar vulnerabilidades de dependencias (CVEs)
    cve_findings = analyze_for_cves(content)
    for cve in cve_findings:
        # Intentar mapear a la línea del import o declaración de dependencia
        matched_line = 1
        matched_char = 0
        package_name = cve.title.replace("Componente vulnerable: ", "").strip()
        
        for line_num, line_content in enumerate(lines, start=1):
            if re.search(r"\bimport\s+" + re.escape(package_name) + r"\b", line_content) or \
               re.search(r"\bfrom\s+" + re.escape(package_name) + r"\b", line_content) or \
               re.search(r"\b" + re.escape(package_name) + r"\s*==\s*", line_content):
                matched_line = line_num
                match = re.search(r"\b(import|from|" + re.escape(package_name) + r")\b", line_content)
                if match:
                    matched_char = match.start()
                break

        findings.append({
            "rule_id": cve.rule_id,
            "title": cve.title,
            "severity": cve.severity,
            "description": cve.description,
            "evidence": cve.evidence,
            "line": matched_line,
            "character": matched_char,
            "remediation": "Actualizar el paquete a una versión segura o remover el uso del módulo inseguro."
        })

    return findings

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Uso: python cli.py <ruta_del_archivo>"}), file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]
    
    # Check if we are running in help mode
    if filepath in ("-h", "--help"):
        print("OWASP Verificator CLI Scanner")
        print("Uso: python cli.py <ruta_del_archivo>")
        sys.exit(0)

    results = scan_file(filepath)
    print(json.dumps(results, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
