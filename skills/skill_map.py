"""
skills/skill_map.py
Mapa de skills para tool calling en agentes de IA.

Cada skill está diseñado para ser usado directamente como tool definition
en frameworks como LangChain, OpenAI Functions, Anthropic Tool Use,
Google Gemini Function Calling, etc.

Expuesto en: GET /api/v1/skills
"""
from typing import List, Dict, Any


SKILL_MAP: Dict[str, Dict[str, Any]] = {

    # ──────────────────────────────────────────────────────────────────────────
    "skill_analyze_url": {
        "name": "skill_analyze_url",
        "description": (
            "Analiza una URL buscando vulnerabilidades de seguridad OWASP Top 10. "
            "Verifica la presencia de cabeceras HTTP de seguridad requeridas como "
            "Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, etc. "
            "Devuelve un score de seguridad (0-100) y lista de hallazgos con remediaciones. "
            "Úsalo cuando el usuario quiera verificar la seguridad de un sitio web."
        ),
        "endpoint": "POST /api/v1/analyze/url",
        "method": "POST",
        "tags": ["owasp", "url", "security", "headers"],
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL completa a analizar (debe incluir http:// o https://)",
                    "example": "https://example.com",
                }
            },
            "required": ["url"],
        },
        "output_description": (
            "APIResponse con data.score (0-100), data.findings_count, "
            "data.severity_summary y data.findings[] con rule_id, severity, "
            "description, evidence y remediation por cada hallazgo."
        ),
        "example_input": {"url": "https://example.com"},
        "example_output": {
            "success": True,
            "data": {
                "id": 1,
                "score": 40,
                "target_type": "url",
                "findings_count": 4,
                "severity_summary": {"high": 0, "medium": 4, "low": 0},
                "findings": [
                    {
                        "rule_id": "OWASP-A05",
                        "title": "Cabecera de seguridad ausente",
                        "severity": "medium",
                        "description": "Falta Content-Security-Policy.",
                        "evidence": "Respuesta HTTP sin Content-Security-Policy",
                        "remediation": "Agregar cabecera CSP en tu servidor web...",
                    }
                ],
            },
            "message": "Análisis de URL completado. Score: 40/100. Hallazgos: 4",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_analyze_code": {
        "name": "skill_analyze_code",
        "description": (
            "Analiza un fragmento de código fuente buscando las 10 categorías de "
            "vulnerabilidades OWASP Top 10: control de acceso roto, secretos hardcodeados, "
            "inyección de código, diseño inseguro, configuración incorrecta, dependencias "
            "vulnerables, fallas de autenticación, SSRF, y más. "
            "Soporta Python, JavaScript, Java, PHP, Go, Ruby, C/C++ y TypeScript. "
            "Úsalo cuando el usuario pegue código y quiera saber si tiene vulnerabilidades."
        ),
        "endpoint": "POST /api/v1/analyze/code",
        "method": "POST",
        "tags": ["owasp", "code", "sast", "security"],
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "Código fuente a analizar",
                },
                "language": {
                    "type": "string",
                    "description": "Lenguaje de programación (informativo)",
                    "example": "python",
                    "nullable": True,
                },
            },
            "required": ["code"],
        },
        "output_description": (
            "APIResponse con data.score (0-100), data.findings[] con hallazgos "
            "detallados incluyendo evidencia (el patrón exacto encontrado) y "
            "remediaciones específicas para el framework detectado."
        ),
        "example_input": {
            "code": "password = '12345'\napi_key = 'sk-abc123'\neval(user_input)",
            "language": "python",
        },
        "example_output": {
            "success": True,
            "data": {
                "id": 2,
                "score": 10,
                "findings_count": 3,
                "severity_summary": {"high": 2, "medium": 1, "low": 0},
            },
            "message": "Análisis de código completado. Score: 10/100. Hallazgos: 3",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_analyze_github": {
        "name": "skill_analyze_github",
        "description": (
            "Descarga y analiza todos los archivos de código de un repositorio GitHub "
            "buscando vulnerabilidades OWASP Top 10 en todos los archivos. "
            "Soporta repositorios públicos y privados (requiere github_token para privados). "
            "Opcionalmente crea GitHub Issues automáticamente por cada vulnerabilidad. "
            "Úsalo cuando el usuario quiera auditar un repositorio completo."
        ),
        "endpoint": "POST /api/v1/analyze/github",
        "method": "POST",
        "tags": ["owasp", "github", "repo", "security"],
        "input_schema": {
            "type": "object",
            "properties": {
                "repo_url": {
                    "type": "string",
                    "description": "URL del repositorio GitHub",
                    "example": "https://github.com/owner/repo",
                },
                "create_issues": {
                    "type": "boolean",
                    "description": "Crear GitHub Issues por cada vulnerabilidad",
                    "default": False,
                },
                "github_token": {
                    "type": "string",
                    "description": "Token GitHub para repos privados o crear issues",
                    "nullable": True,
                },
            },
            "required": ["repo_url"],
        },
        "output_description": (
            "APIResponse con score, hallazgos por archivo (el campo evidence "
            "incluye el nombre del archivo donde se encontró la vulnerabilidad)."
        ),
        "example_input": {
            "repo_url": "https://github.com/owner/repo",
            "create_issues": False,
        },
        "example_output": {
            "success": True,
            "data": {"id": 3, "score": 55, "findings_count": 5},
            "message": "Análisis de repositorio completado. Score: 55/100. Hallazgos: 5",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_get_report": {
        "name": "skill_get_report",
        "description": (
            "Obtiene el reporte completo de un escaneo de seguridad previo por su ID. "
            "Devuelve todos los hallazgos con severidad, evidencia y remediaciones detalladas. "
            "Úsalo para recuperar resultados de análisis anteriores o cuando el usuario "
            "pregunte por los detalles de un escaneo específico."
        ),
        "endpoint": "GET /api/v1/reports/{scan_id}",
        "method": "GET",
        "tags": ["reports", "owasp"],
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "integer",
                    "description": "ID del escaneo a recuperar",
                    "example": 1,
                }
            },
            "required": ["scan_id"],
        },
        "output_description": "Reporte completo con score, findings y resumen de severidades.",
        "example_input": {"scan_id": 1},
        "example_output": {
            "success": True,
            "data": {
                "id": 1,
                "score": 70,
                "target_type": "code",
                "findings_count": 2,
                "severity_summary": {"high": 1, "medium": 1, "low": 0},
            },
            "message": "Reporte #1. Score: 70/100. Hallazgos: 2",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_compare_scans": {
        "name": "skill_compare_scans",
        "description": (
            "Compara dos escaneos de seguridad para evaluar la evolución. "
            "Devuelve: delta de score, vulnerabilidades resueltas (fixed_rules), "
            "nuevas regresiones (added_rules), problemas persistentes y "
            "un resumen en texto natural para análisis inmediato. "
            "Úsalo para responder '¿mejoró la seguridad?' o '¿qué cambió entre versiones?'."
        ),
        "endpoint": "POST /api/v1/reports/compare",
        "method": "POST",
        "tags": ["reports", "compare", "owasp"],
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id_left": {
                    "type": "integer",
                    "description": "ID del escaneo base (más antiguo)",
                    "example": 1,
                },
                "scan_id_right": {
                    "type": "integer",
                    "description": "ID del escaneo a comparar (más reciente)",
                    "example": 5,
                },
            },
            "required": ["scan_id_left", "scan_id_right"],
        },
        "output_description": (
            "CompareOut con score_delta, fixed_rules[], added_rules[], "
            "persistent_rules[] y summary (texto natural para IA)."
        ),
        "example_input": {"scan_id_left": 1, "scan_id_right": 5},
        "example_output": {
            "success": True,
            "data": {
                "score_delta": 15,
                "fixed_rules": ["OWASP-A02", "OWASP-A03"],
                "added_rules": [],
                "persistent_rules": ["OWASP-A01"],
                "summary": "⬆️ Mejoró 15 puntos | ✅ Resueltas: OWASP-A02, OWASP-A03",
            },
            "message": "⬆️ Mejoró 15 puntos | ✅ Resueltas: OWASP-A02, OWASP-A03",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_export_pdf": {
        "name": "skill_export_pdf",
        "description": (
            "Genera y devuelve un reporte de seguridad en formato PDF profesional. "
            "El PDF incluye: portada, tabla de resumen, hallazgos detallados con "
            "evidencia y remediaciones paso a paso. "
            "Úsalo cuando el usuario quiera descargar o compartir el reporte formalmente."
        ),
        "endpoint": "GET /api/v1/exports/{scan_id}/pdf",
        "method": "GET",
        "tags": ["exports", "pdf"],
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "integer",
                    "description": "ID del escaneo a exportar como PDF",
                    "example": 1,
                }
            },
            "required": ["scan_id"],
        },
        "output_description": (
            "Archivo PDF binario (application/pdf). "
            "Headers: X-Scan-ID, X-Scan-Score, Content-Disposition."
        ),
        "example_input": {"scan_id": 1},
        "example_output": "(binario PDF — descarga automática)",
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_export_json": {
        "name": "skill_export_json",
        "description": (
            "Exporta el reporte de seguridad en formato JSON estructurado y enriquecido. "
            "Incluye metadata de exportación (timestamp), score, resumen de severidades "
            "y todos los hallazgos completos. "
            "Úsalo para integración con SIEM, dashboards, CI/CD o sistemas externos."
        ),
        "endpoint": "GET /api/v1/exports/{scan_id}/json",
        "method": "GET",
        "tags": ["exports", "json"],
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "integer",
                    "description": "ID del escaneo a exportar como JSON",
                    "example": 1,
                }
            },
            "required": ["scan_id"],
        },
        "output_description": (
            "APIResponse con data.exported_at, data.scan_id, data.score, "
            "data.severity_summary y data.findings[] completos."
        ),
        "example_input": {"scan_id": 1},
        "example_output": {
            "success": True,
            "data": {
                "exported_at": "2026-06-19T23:00:00Z",
                "scan_id": 1,
                "score": 70,
                "severity_summary": {"high": 1, "medium": 1, "low": 0},
                "findings": [],
            },
            "message": "Exportación JSON del escaneo #1 completada",
        },
    },

    # ──────────────────────────────────────────────────────────────────────────
    "skill_dashboard_stats": {
        "name": "skill_dashboard_stats",
        "description": (
            "Obtiene estadísticas globales de seguridad de todos los escaneos realizados. "
            "Devuelve: total de escaneos, total de hallazgos, score promedio, "
            "distribución de severidades (high/medium/low) y tendencia de los últimos 10 scans. "
            "Incluye un resumen en texto con el nivel de riesgo general (BAJO/MEDIO/ALTO). "
            "Úsalo para generar reportes ejecutivos o responder '¿cómo está la seguridad general?'."
        ),
        "endpoint": "GET /api/v1/stats",
        "method": "GET",
        "tags": ["stats", "dashboard"],
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
        "output_description": (
            "StatsOut con total_scans, total_findings, avg_score, "
            "high/medium/low_severity_count, score_trend[] y recent_scans[]. "
            "message contiene resumen de riesgo en texto natural."
        ),
        "example_input": {},
        "example_output": {
            "success": True,
            "data": {
                "total_scans": 10,
                "total_findings": 45,
                "avg_score": 62.5,
                "high_severity_count": 12,
                "medium_severity_count": 25,
                "low_severity_count": 8,
            },
            "message": "Riesgo general: 🟡 MEDIO. 10 escaneos. Score promedio: 62.5/100.",
        },
    },
}


def get_skills_list() -> List[Dict[str, Any]]:
    """Devuelve lista de skills en formato simplificado para tool calling."""
    return [
        {
            "name": skill["name"],
            "description": skill["description"],
            "endpoint": skill["endpoint"],
            "method": skill["method"],
            "tags": skill["tags"],
            "input_schema": skill["input_schema"],
            "output_description": skill["output_description"],
            "example_input": skill["example_input"],
        }
        for skill in SKILL_MAP.values()
    ]


def get_skill(name: str) -> Dict[str, Any] | None:
    """Obtiene un skill por nombre."""
    return SKILL_MAP.get(name)


# ─── OpenAI Function Calling format ──────────────────────────────────────────

def to_openai_tools() -> List[Dict[str, Any]]:
    """
    Convierte el SKILL_MAP al formato de tools para OpenAI / compatible APIs.
    Útil para integrar directamente en llamadas a gpt-4o, claude, gemini, etc.
    """
    tools = []
    for skill in SKILL_MAP.values():
        tools.append({
            "type": "function",
            "function": {
                "name": skill["name"],
                "description": skill["description"],
                "parameters": skill["input_schema"],
            },
        })
    return tools


if __name__ == "__main__":
    # Mostrar resumen al ejecutar directamente
    import json
    print(f"Total skills: {len(SKILL_MAP)}")
    for name, skill in SKILL_MAP.items():
        print(f"  • {name}: {skill['endpoint']}")
    print("\nOpenAI tools format:")
    print(json.dumps(to_openai_tools(), indent=2, ensure_ascii=False)[:500] + "...")
