import re
import zipfile
import io
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import os
import requests
from app.services.cve_analyzer import analyze_for_cves

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str


RULES = [
    {
        "rule_id": "OWASP-A01",
        "title": "Control de Acceso Roto",
        "severity": "high",
        "remediation": "1. Verificar permisos en cada endpoint\n2. Usar decoradores de autenticación (@require_auth)\n3. Validar rol del usuario antes de operaciones\n4. Implementar RBAC (Role-Based Access Control)",
        "patterns": [r"@app\.get\(", r"@app\.post\(", r"def\s+\w+\(.*request"],
        "description": "Se detectaron endpoints sin validación explícita de permisos o autenticación.",
    },
    {
        "rule_id": "OWASP-A02",
        "title": "Fallas Criptográficas - Exposición de Secretos",
        "severity": "high",
        "remediation": "1. Nunca hardcodear secretos\n2. Usar variables de entorno (os.getenv())\n3. Implementar secret manager (Azure Key Vault, HashiCorp Vault)\n4. Rotar credenciales regularmente",
        "patterns": [r"password\s*=\s*[\"']", r"api[_-]?key\s*=\s*[\"']", r"secret\s*=\s*[\"']", r"token\s*=\s*[\"']", r"credential"],
        "description": "Secretos, contraseñas o claves hardcodeadas detectadas en el código.",
    },
    {
        "rule_id": "OWASP-A03",
        "title": "Inyección de Código",
        "severity": "high",
        "remediation": "1. Evitar eval(), exec(), pickle.loads()\n2. Usar funciones seguras alternativas\n3. Validar y sanear TODA entrada de usuario\n4. Usar ORM para consultas SQL",
        "patterns": [r"eval\(", r"exec\(", r"pickle\.loads\(", r"__import__", r"compile\("],
        "description": "Se detectaron funciones que permiten inyección de código o ejecución dinámica insegura.",
    },
    {
        "rule_id": "OWASP-A04",
        "title": "Diseño Inseguro",
        "severity": "medium",
        "remediation": "1. Diseñar con seguridad en mente desde el inicio\n2. Usar threat modeling\n3. Implementar rate limiting y timeouts\n4. Validar flujos de negocio",
        "patterns": [r"todo|TODO|fixme|FIXME|hack|HACK|insecure"],
        "description": "Se detectaron comentarios que sugieren lógica insegura o falta de validación de negocio.",
    },
    {
        "rule_id": "OWASP-A05",
        "title": "Configuración Incorrecta de Seguridad",
        "severity": "medium",
        "remediation": "1. Agregar cabeceras HTTP de seguridad (CSP, HSTS, X-Frame-Options)\n2. Deshabilitar debug en producción\n3. Usar HTTPS obligatorio\n4. Configurar CORS restrictivo",
        "patterns": [r"debug\s*=\s*True", r"SECRET_KEY\s*=\s*[\"']", r"CORS"],
        "description": "Configuración de seguridad insuficiente detectada (debug activo, secretos expuestos).",
    },
    {
        "rule_id": "OWASP-A06",
        "title": "Componentes Vulnerables y Desactualizados",
        "severity": "medium",
        "remediation": "1. Mantener dependencias actualizadas\n2. Usar `pip audit` para verificar vulnerabilidades\n3. Revisar CVEs regularmente\n4. Usar herramientas como OWASP Dependency-Check",
        "patterns": [r"import\s+requests|import\s+flask|import\s+django|import\s+crypto"],
        "description": "Se detectaron librerías importadas (verificar versiones y CVEs de dependencias).",
    },
    {
        "rule_id": "OWASP-A07",
        "title": "Fallas de Autenticación",
        "severity": "high",
        "remediation": "1. Implementar autenticación fuerte (JWT, OAuth2, SAML)\n2. Hash de contraseñas (bcrypt, argon2)\n3. MFA cuando sea posible\n4. Gestión segura de sesiones",
        "patterns": [r"password.*==.*password", r"if user_id|if username|login", r"def auth"],
        "description": "Lógica de autenticación detectada sin implementación clara de seguridad.",
    },
    {
        "rule_id": "OWASP-A08",
        "title": "Fallas de Integridad de Software y Datos",
        "severity": "medium",
        "remediation": "1. Implementar integridad de código (firma digital)\n2. Usar HTTPS para todas las descargas\n3. Verificar checksums de artefactos\n4. Usar CI/CD seguro",
        "patterns": [r"fetch|download|import.*http|requests\.get"],
        "description": "Se detectaron descargas o importaciones de código que podrían ser interceptadas.",
    },
    {
        "rule_id": "OWASP-A09",
        "title": "Fallas en Logging y Monitoreo",
        "severity": "low",
        "remediation": "1. Implementar logging de eventos de seguridad\n2. Monitorear intentos fallidos de autenticación\n3. Alertas para actividades sospechosas\n4. Retención de logs adecuada",
        "patterns": [r"except.*:|except\s*pass", r"try:"],
        "description": "Manejo de excepciones sin logging visible (podrían ocultarse eventos de seguridad).",
    },
    {
        "rule_id": "OWASP-A10",
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "remediation": "1. Validar y whitelist URLs de destino\n2. Evitar User-Supplied URLs en requests\n3. Usar Network segmentation\n4. Deshabilitar acceso a IPs privadas",
        "patterns": [r"requests\.get\(.*\)", r"urllib.*open\(.*\)", r"requests\.post\(.*\)"],
        "description": "Se detectaron llamadas HTTP que podrían ser explotadas para SSRF.",
    },
]

# Weight per severity used for scoring and displayed in reports
WEIGHTS = {"high": 30, "medium": 15, "low": 5}

REMEDIATIONS = {r["rule_id"]: r.get("remediation", "") for r in RULES}

# Additional remediations for URL scan findings
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
        # Add CVE analysis
        cve_findings = analyze_for_cves(content)
        findings.extend(cve_findings)
    
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


def scan_github_repo(repo_url: str, github_token: str | None = None) -> list[Finding]:
    """Descarga y analiza un repositorio de GitHub"""
    findings: list[Finding] = []
    
    try:
        # Parsear URL de GitHub (ej: https://github.com/owner/repo)
        parsed = urlparse(repo_url)
        if "github.com" not in parsed.netloc:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="URL de GitHub inválida",
                    severity="medium",
                    description="La URL debe ser de un repositorio de GitHub válido.",
                    evidence=repo_url,
                )
            ]
        
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) < 2:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="URL de repositorio inválida",
                    severity="medium",
                    description="Formato inválido. Usa: https://github.com/owner/repo",
                    evidence=repo_url,
                )
            ]
        
        owner = path_parts[0]
        repo = path_parts[1].replace(".git", "")

        # Support single-file blob/raw URLs: https://github.com/owner/repo/blob/branch/path
        if 'blob' in path_parts:
            try:
                blob_idx = path_parts.index('blob')
                branch = path_parts[blob_idx + 1]
                file_path = '/'.join(path_parts[blob_idx + 2:])
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
                headers = None
                # Use provided token first, fallback to env var
                token = github_token or os.getenv('GITHUB_TOKEN')
                if token:
                    headers = {"Authorization": f"token {token}"}
                r = requests.get(raw_url, headers=headers, timeout=15)
                if r.status_code != 200:
                    return [
                        Finding(
                            rule_id="OWASP-A01",
                            title="No se pudo descargar el archivo especificado",
                            severity="medium",
                            description="El archivo en el repositorio no está disponible.",
                            evidence=f"Status: {r.status_code}",
                        )
                    ]
                content = r.content.decode('utf-8', errors='replace')
                file_findings = scan_code(content)
                for finding in file_findings:
                    finding.evidence = f"Archivo: {file_path}\n{finding.evidence}"
                findings.extend(file_findings)
                return findings
            except Exception:
                pass

        # Descargar el repositorio como ZIP
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
        headers = None
        # Use provided token first, fallback to env var
        token = github_token or os.getenv('GITHUB_TOKEN')
        if token:
            headers = {"Authorization": f"token {token}"}
        response = requests.get(zip_url, headers=headers, timeout=15)

        # Si main no existe, intentar con master
        if response.status_code == 404:
            zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
            response = requests.get(zip_url, headers=headers, timeout=15)

        if response.status_code != 200:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="No se pudo descargar el repositorio",
                    severity="medium",
                    description="El repositorio no está disponible o es privado.",
                    evidence=f"Status: {response.status_code}",
                )
            ]

        # Extraer y analizar archivos
        code_extensions = {".py", ".js", ".java", ".cpp", ".c", ".go", ".rb", ".php", ".ts", ".tsx", ".jsx", ".vue", ".cs", ".swift"}
        file_count = 0

        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            for file_info in zip_file.filelist:
                if any(file_info.filename.endswith(ext) for ext in code_extensions):
                    try:
                        content = zip_file.read(file_info).decode('utf-8', errors='replace')
                        # Analizar el archivo
                        file_findings = scan_code(content)

                        # Agregar el nombre del archivo a cada hallazgo
                        for finding in file_findings:
                            finding.evidence = f"Archivo: {file_info.filename}\n{finding.evidence}"

                        findings.extend(file_findings)
                        file_count += 1
                    except (UnicodeDecodeError, Exception):
                        pass

        if file_count == 0:
            return [
                Finding(
                    rule_id="OWASP-A01",
                    title="No se encontraron archivos de código",
                    severity="low",
                    description="El repositorio no contiene archivos de código en formatos soportados.",
                    evidence=f"Extensiones buscadas: {', '.join(code_extensions)}",
                )
            ]
        
    except requests.RequestException as exc:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="Error al descargar el repositorio",
                severity="medium",
                description="No se pudo conectar a GitHub.",
                evidence=str(exc),
            )
        ]
    except Exception as exc:
        return [
            Finding(
                rule_id="OWASP-A01",
                title="Error al procesar el repositorio",
                severity="medium",
                description="Ocurrió un error durante el análisis.",
                evidence=str(exc),
            )
        ]
    
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


def detect_frameworks(content: str) -> set:
    """Detecta frameworks comunes en el contenido del código."""
    fw = set()
    txt = content.lower()
    if re.search(r"\bfastapi\b", txt):
        fw.add("fastapi")
    if re.search(r"\bflask\b", txt):
        fw.add("flask")
    if re.search(r"\bdjango\b", txt):
        fw.add("django")
    return fw


def remediation_for(rule_id: str, frameworks: set | None = None) -> str:
    """Genera una recomendación base y adapta según framework detectado."""
    base = REMEDIATIONS.get(rule_id, "")
    adapted = base
    if frameworks:
        if "fastapi" in frameworks:
            if rule_id == "OWASP-A05":
                adapted = "En FastAPI: agrega middleware que establezca cabeceras de seguridad (usar `Starlette` middleware).\n" + adapted
            if rule_id == "OWASP-A06":
                adapted = "En FastAPI: configura Uvicorn/productor reverse-proxy para ocultar cabecera Server.\n" + adapted
        if "flask" in frameworks:
            if rule_id == "OWASP-A05":
                adapted = "En Flask: utiliza `Flask-Talisman` o establecer manualmente cabeceras de seguridad en `after_request`.\n" + adapted
        if "django" in frameworks:
            if rule_id == "OWASP-A05":
                adapted = "En Django: configurar `SECURE_*` settings (HSTS, Content Security Policy a través de middleware).\n" + adapted
    return adapted
