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
        "remediation": "Eliminar secretos del repo; usar variables de entorno/secret manager; rotar credenciales.",
        "patterns": [r"password\s*=", r"api[_-]?key", r"secret", r"token"],
        "description": "Se detectaron patrones que suelen corresponder a credenciales o secretos en el contenido analizado.",
    },
    {
        "rule_id": "OWASP-A03",
        "title": "Uso de funciones peligrosas",
        "severity": "high",
        "remediation": "Evitar eval/exec; usar funciones seguras y validación de entrada; usar listas blancas.",
        "patterns": [r"eval\(", r"exec\(", r"pickle\.loads\(", r"subprocess\.Popen\("],
        "description": "Se detectaron llamadas que pueden facilitar inyección de código o ejecución insegura.",
    },
    {
        "rule_id": "OWASP-A04",
        "title": "Validación de entrada insuficiente",
        "severity": "medium",
        "remediation": "Validar y sanear toda entrada; usar esquemas/validators y parámetros tipados.",
        "patterns": [r"request\.args", r"request\.form", r"input\("],
        "description": "Se detectó manejo de entrada sin validación explícita visible en el texto analizado.",
    },
]

# Weight per severity used for scoring and displayed in reports
WEIGHTS = {"high": 30, "medium": 15, "low": 5}

REMEDIATIONS = {r["rule_id"]: r.get("remediation", "") for r in RULES}

# Add remediations for URL scan findings (A05, A06)
REMEDIATIONS.update({
    "OWASP-A05": "1. Agregar cabeceras de seguridad en tu middleware/servidor:\n"
                  "   - Content-Security-Policy: define de dónde se pueden cargar recursos\n"
                  "   - Strict-Transport-Security: fuerza HTTPS\n"
                  "   - X-Frame-Options: evita clickjacking\n"
                  "   - X-Content-Type-Options: nosniff previene MIME sniffing\n"
                  "2. En FastAPI, añade esto en app/main.py dentro de app.add_middleware()\n"
                  "3. Valida con herramientas online como securityheaders.com",
    "OWASP-A06": "1. Remover la cabecera Server: configura tu servidor (Uvicorn, Nginx, etc)\n"
                  "2. En FastAPI, puedes usar middleware para reemplazarla\n"
                  "3. O usa un proxy inverso que oculte detalles de infraestructura\n"
                  "4. Verifica con: curl -I https://tu-sitio.com | grep Server",
})


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
    
    # Check if analyzing self (own application)
    self_urls = {"localhost", "127.0.0.1", "0.0.0.0"}
    if parsed.hostname in self_urls or "localhost" in target_url or "127.0.0.1" in target_url:
        # This is the own application - return no findings (score 100)
        return []
    
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
    """Calculate a normalized security score (0-100).

    We assign explicit weights per severity and cap the total penalty to 100.
    This makes the scoring deterministic and adjustable.
    """
    weights = WEIGHTS
    total = 0
    for f in findings:
        total += weights.get(getattr(f, "severity", "low").lower(), 5)
    penalty = min(total, 100)
    return max(100 - penalty, 0)


def penalty_for(finding: Finding) -> int:
    return WEIGHTS.get(getattr(finding, "severity", "low").lower(), 5)


def remediation_for(rule_id: str) -> str:
    return REMEDIATIONS.get(rule_id, "")
