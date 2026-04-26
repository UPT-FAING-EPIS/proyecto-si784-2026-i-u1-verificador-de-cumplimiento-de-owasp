import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import requests


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str


RULES = [
    {
        "rule_id": "OWASP-A02",
        "title": "Posible exposición de secretos",
        "severity": "high",
        "patterns": [r"password\s*=", r"api[_-]?key", r"secret", r"token"],
        "description": "Se detectaron patrones que suelen corresponder a credenciales o secretos en el contenido analizado.",
    },
    {
        "rule_id": "OWASP-A03",
        "title": "Uso de funciones peligrosas",
        "severity": "high",
        "patterns": [r"eval\(", r"exec\(", r"pickle\.loads\(", r"subprocess\.Popen\("],
        "description": "Se detectaron llamadas que pueden facilitar inyección de código o ejecución insegura.",
    },
    {
        "rule_id": "OWASP-A04",
        "title": "Validación de entrada insuficiente",
        "severity": "medium",
        "patterns": [r"request\.args", r"request\.form", r"input\("],
        "description": "Se detectó manejo de entrada sin validación explícita visible en el texto analizado.",
    },
]


def scan_code(content: str) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        for pattern in rule["patterns"]:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        rule_id=rule["rule_id"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        evidence=f"Coincidencia encontrada: {match.group(0)}",
                    )
                )
                break
    return findings


def scan_url(target_url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="URL inválida",
                severity="medium",
                description="La URL debe usar HTTP o HTTPS.",
                evidence=target_url,
            )
        ]

    try:
        response = requests.get(target_url, timeout=15)
        headers = response.headers
    except requests.RequestException as exc:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="No se pudo conectar al objetivo",
                severity="medium",
                description="La URL no respondió correctamente durante el análisis.",
                evidence=str(exc),
            )
        ]

    required_headers = {
        "Content-Security-Policy": "Falta Content-Security-Policy.",
        "Strict-Transport-Security": "Falta Strict-Transport-Security.",
        "X-Frame-Options": "Falta X-Frame-Options.",
        "X-Content-Type-Options": "Falta X-Content-Type-Options.",
    }

    for header_name, message in required_headers.items():
        if header_name not in headers:
            findings.append(
                Finding(
                    rule_id="OWASP-A05",
                    title="Cabecera de seguridad ausente",
                    severity="medium",
                    description=message,
                    evidence=f"Respuesta HTTP sin {header_name}",
                )
            )

    if "Server" in headers:
        findings.append(
            Finding(
                rule_id="OWASP-A06",
                title="Divulgación de información",
                severity="low",
                description="La cabecera Server expone detalles de la infraestructura.",
                evidence=headers["Server"],
            )
        )

    return findings


def calculate_score(findings: Iterable[Finding]) -> int:
    score = 100
    for finding in findings:
        if finding.severity == "high":
            score -= 25
        elif finding.severity == "medium":
            score -= 15
        else:
            score -= 5
    return max(score, 0)
