"""
api/routes/analyze.py
Endpoints de análisis OWASP — skills: skill_analyze_url, skill_analyze_code, skill_analyze_github
Todos devuelven APIResponse con el resultado del escaneo.
"""
from fastapi import APIRouter, Depends

from api.core.security import get_current_user
from api.models.request_models import AnalyzeURLRequest, AnalyzeCodeRequest, AnalyzeGitHubRequest
from api.models.response_models import APIResponse, ScanOut, ok
from api.services import analyzer_service

router = APIRouter(prefix="/analyze", tags=["🔍 Análisis OWASP"])


@router.post(
    "/url",
    response_model=APIResponse,
    summary="skill_analyze_url — Analizar URL",
    description=(
        "**Skill para IA**: Analiza una URL buscando cabeceras de seguridad HTTP ausentes "
        "según OWASP Top 10 (A05 - Configuración Incorrecta, A06 - Componentes Vulnerables). "
        "Devuelve un score 0-100 y lista de hallazgos con remediaciones."
    ),
    operation_id="skill_analyze_url",
)
async def analyze_url(
    payload: AnalyzeURLRequest,
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Analiza una URL buscando vulnerabilidades OWASP en sus cabeceras HTTP.

    **Input**: `{"url": "https://example.com"}`

    **Output**: Scan con score 0-100 y lista de findings con severidad y remediación.
    """
    scan = analyzer_service.analyze_url(payload.url)
    return ok(
        data=ScanOut.from_scan(scan).model_dump(),
        message=f"Análisis de URL completado. Score: {scan.score}/100. "
                f"Hallazgos: {len(scan.findings)}",
    )


@router.post(
    "/code",
    response_model=APIResponse,
    summary="skill_analyze_code — Analizar código fuente",
    description=(
        "**Skill para IA**: Analiza un fragmento de código fuente buscando los 10 patrones "
        "de vulnerabilidades OWASP (inyección, secretos hardcodeados, auth insegura, etc.). "
        "Soporta Python, JavaScript, Java, PHP y más."
    ),
    operation_id="skill_analyze_code",
)
async def analyze_code(
    payload: AnalyzeCodeRequest,
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Analiza código fuente buscando vulnerabilidades OWASP Top 10.

    **Input**: `{"code": "password = '12345'", "language": "python"}`

    **Output**: Scan con score 0-100, hallazgos con evidencia y remediaciones específicas.
    """
    scan = analyzer_service.analyze_code(payload.code)
    return ok(
        data=ScanOut.from_scan(scan).model_dump(),
        message=f"Análisis de código completado. Score: {scan.score}/100. "
                f"Hallazgos: {len(scan.findings)}",
    )


@router.post(
    "/github",
    response_model=APIResponse,
    summary="skill_analyze_github — Analizar repositorio GitHub",
    description=(
        "**Skill para IA**: Descarga y analiza todos los archivos de código de un repositorio "
        "GitHub buscando vulnerabilidades OWASP. Soporta repos públicos y privados (con token). "
        "Opcionalmente crea GitHub Issues por cada vulnerabilidad encontrada."
    ),
    operation_id="skill_analyze_github",
)
async def analyze_github(
    payload: AnalyzeGitHubRequest,
    user: str = Depends(get_current_user),
) -> APIResponse:
    """
    Analiza un repositorio de GitHub buscando vulnerabilidades OWASP Top 10.

    **Input**: `{"repo_url": "https://github.com/owner/repo", "create_issues": false}`

    **Output**: Scan con score, hallazgos por archivo y remediaciones.
    """
    scan = analyzer_service.analyze_github(
        repo_url=payload.repo_url,
        create_issues=payload.create_issues,
        github_token=payload.github_token,
    )
    return ok(
        data=ScanOut.from_scan(scan).model_dump(),
        message=f"Análisis de repositorio completado. Score: {scan.score}/100. "
                f"Hallazgos: {len(scan.findings)}",
    )
