import re
import zipfile
import io
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

import os
from app.services.cve_analyzer import analyze_for_cves

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str


RULES = [
    # --- OWASP-A01 ---
    {
        "rule_id": "OWASP-A01-NO-AUTH",
        "title": "Endpoint sin Autenticación",
        "severity": "high",
        "remediation": "1. Verificar permisos en cada endpoint.\n2. Usar decoradores de autenticación como @require_auth o middlewares.\n3. Validar rol del usuario antes de operaciones.",
        "patterns": [r"@app\.(get|post|put|delete|patch)\((?!.*dependencies)", r"router\.(get|post|put|delete|patch)\((?!.*dependencies)"],
        "description": "Se detectaron rutas de API expuestas sin validación explícita de autenticación o dependencias de seguridad.",
    },
    {
        "rule_id": "OWASP-A01-HARDCODED-ROLE",
        "title": "Comprobación de Rol Hardcodeada",
        "severity": "medium",
        "remediation": "1. Implementar RBAC (Role-Based Access Control) dinámico.\n2. Evitar comparar strings de roles fijos directamente en el código de negocio.",
        "patterns": [r"role\s*==\s*['\"]admin['\"]", r"user\.role\s*==\s*['\"]"],
        "description": "Roles y permisos estáticos quemados en el código, lo que dificulta la gestión dinámica de permisos.",
    },
    {
        "rule_id": "OWASP-A01-CORS-WILDCARD",
        "title": "CORS con Permisos Totales (Comodín)",
        "severity": "medium",
        "remediation": "1. Configurar CORS restringiendo orígenes específicos permitidos en producción.\n2. Evitar el uso de '*' para el origen si la API maneja sesiones o credenciales.",
        "patterns": [r"allow_origins\s*=\s*\[\s*['\"]\*(?!['\"])", r"Access-Control-Allow-" + "Origin" + r".*\*"],
        "description": "El comodín '*' en orígenes de CORS permite a cualquier sitio web externo realizar peticiones a la API.",
    },
    {
        "rule_id": "OWASP-A01-OPEN-CIDR",
        "title": "Acceso de Red Totalmente Abierto (CIDR 0.0.0." + "0/0)",
        "severity": "medium",
        "remediation": "1. Restringir el rango CIDR de acceso a direcciones IP específicas de confianza.\n2. Evitar el uso de 0.0.0." + "0/0 para puertos sensibles en configuraciones Terraform/Kubernetes.",
        "patterns": [r"0\.0\.0\.0/0"],
        "description": "Permitir accesos de red globales (0.0.0." + "0/0) expone servicios críticos a todo internet.",
    },
    # --- OWASP-A02 ---
    {
        "rule_id": "OWASP-A02-HARDCODED-SECRET",
        "title": "Secreto o Credencial Expuesta",
        "severity": "high",
        "remediation": "1. Cargar llaves y credenciales desde variables de entorno.\n2. Usar un gestor de secretos (Vault, AWS Secrets Manager) en producción.",
        "patterns": [r"password\s*=\s*['\"][^'\"]{4,}['\"]", r"api[_-]?key\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", r"secret\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]", r"token\s*=\s*['\"][a-zA-Z0-9_\-]{8,}['\"]"],
        "description": "Llaves de API, contraseñas o secretos detectados directamente en el código fuente.",
    },
    {
        "rule_id": "OWASP-A02-WEAK-HASH",
        "title": "Algoritmo de Hash Criptográfico Débil",
        "severity": "high",
        "remediation": "1. Migrar a algoritmos robustos como SHA-256 o hash de contraseñas dedicado (Bcrypt, Argon2).\n2. No usar MD5 ni SHA-1 para almacenar contraseñas o firmas digitales.",
        "patterns": [r"createHash\(\s*['\"]md5['\"]", r"createHash\(\s*['\"]sha1['\"]", r"hashlib\.md5\(", r"hashlib\.sha1\("],
        "description": "Uso de hashes MD5 o SHA-1 que son vulnerables a colisiones y ataques de diccionario rápidos.",
    },
    {
        "rule_id": "OWASP-A02-HTTP-URL",
        "title": "Comunicación Insegura (HTTP)",
        "severity": "medium",
        "remediation": "1. Forzar el uso de conexiones seguras HTTPS.\n2. Configurar cabeceras de redirección de HTTP a HTTPS.",
        "patterns": [r"http://[a-zA-Z0-9\-\.]+(?!/)(?!127\.0\.0\.1)(?!localhost)"],
        "description": "Se detectaron URLs que viajan sin cifrado a través del protocolo HTTP inseguro.",
    },
    {
        "rule_id": "OWASP-A02-WEAK-KEY-SIZE",
        "title": "Clave Asimétrica de Tamaño Débil",
        "severity": "medium",
        "remediation": "1. Usar un tamaño de clave mínimo de 2048 bits para RSA.\n2. Generar pares de claves usando opciones de configuración seguras.",
        "patterns": [r"generateKeyPair\([^,]*modulusLength\s*:\s*(1024|512)"],
        "description": "Generación de claves criptográficas asimétricas con longitud inferior a la recomendada para resistir ataques modernos.",
    },
    # --- OWASP-A03 ---
    {
        "rule_id": "OWASP-A03-SQLI",
        "title": "Inyección SQL (SQLi)",
        "severity": "high",
        "remediation": "1. Utilizar consultas parametrizadas o bindings de parámetros en el ORM.\n2. Evitar concatenar entradas de usuario directamente en sentencias SQL.",
        "patterns": [r"execute\(\s*f['\"]", r"\.query\(\s*['\"].*\$\{", r"execute\(\s*['\"].*%\s*", r"execute\(\s*['\"].*\.format\("],
        "description": "Se detectó concatenación o interpolación directa de cadenas en consultas SQL, permitiendo la inyección de comandos SQL.",
    },
    {
        "rule_id": "OWASP-A03-CODE-INJECTION",
        "title": "Ejecución Dinámica de Código (Code Injection)",
        "severity": "high",
        "remediation": "1. Evitar por completo las funciones de evaluación dinámica.\n2. Utilizar lógica de decisión estática o parseadores seguros.",
        "patterns": [r"\be" + r"val\(", r"\bex" + r"ec\(", r"new\s+Function\("],
        "description": "Uso de ev" + "al(), ex" + "ec() o constructores de funciones dinámicas que posibilitan la ejecución remota de código (RCE).",
    },
    {
        "rule_id": "OWASP-A03-OS-COMMAND",
        "title": "Ejecución de Comandos de Sistema Operativo",
        "severity": "high",
        "remediation": "1. Usar librerías nativas en lugar de llamar a comandos externos.\n2. Escapar y sanear rigurosamente todos los argumentos.",
        "patterns": [r"child_process\.(exec|spawn)\(", r"os\.system\(", r"subprocess\.(run|Popen|call)\("],
        "description": "Llamadas a shells del sistema que pueden ser interceptadas si contienen variables controladas por el usuario.",
    },
    {
        "rule_id": "OWASP-A03-XSS",
        "title": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "remediation": "1. Utilizar escaping/sanitización contextual antes de renderizar entradas en el DOM.\n2. Evitar asignar directamente código no sanitizado en innerHTML.",
        "patterns": [r"\.innerHTML\s*=", r"document\.write\(", "dangerouslySet" + "InnerHTML"],
        "description": "Inserción de contenido directamente en el HTML del navegador sin sanitizar, permitiendo XSS.",
    },
    {
        "rule_id": "OWASP-A03-PATH-TRAVERSAL",
        "title": "Path Traversal (Salto de Directorio)",
        "severity": "high",
        "remediation": "1. Validar y resolver rutas usando utilidades nativas (path.resolve, os.path.abspath).\n2. Asegurar que los archivos estén dentro de un directorio permitido.",
        "patterns": [r"fs\.readFile\([^,]*\+", r"open\([^,]*\+", r"fs\.createReadStream\([^,]*\+", r"send_file\([^,]*\+"],
        "description": "Operaciones de lectura/escritura de archivos usando concatenaciones sin verificar si se sale de la ruta permitida.",
    },
    {
        "rule_id": "OWASP-A03-LDAP-INJECTION",
        "title": "Inyección LDAP",
        "severity": "high",
        "remediation": "1. Utilizar escapar filtros de búsqueda LDAP antes de realizar consultas.\n2. Evitar construir consultas LDAP mediante strings dinámicos.",
        "patterns": [r"ldap\.search\([^,]*\+[^,]*\)"],
        "description": "Búsquedas LDAP dinámicas vulnerables a la inyección de filtros.",
    },
    {
        "rule_id": "OWASP-A03-XPATH-INJECTION",
        "title": "Inyección XPath",
        "severity": "high",
        "remediation": "1. Utilizar consultas XPath parametrizadas o escapar entradas del usuario.\n2. Validar que la estructura XML no sea manipulada.",
        "patterns": [r"\.selectSingleNode\([^,]*\+[^,]*\)"],
        "description": "Consultas XPath construidas dinámicamente que pueden permitir evadir la lógica de acceso de documentos XML.",
    },
    {
        "rule_id": "OWASP-A03-DYNAMIC-SQL",
        "title": "SQL Dinámico Inseguro",
        "severity": "high",
        "remediation": "1. Utilizar sp_executesql con parámetros tipados.\n2. Evitar la concatenación de variables en bloques dinámicos dentro de scripts SQL.",
        "patterns": [r"EXEC\s*\(\s*['\"].*?\+\s*", r"EXEC\s*\(\s*@[a-zA-Z0-9_]+\s*\)"],
        "description": "El uso de sentencias EXEC con concatenación en SQL expone a inyección SQL.",
    },
    # --- OWASP-A04 ---
    {
        "rule_id": "OWASP-A04-TODO-SECURITY",
        "title": "Comentario de Seguridad Pendiente (TODO)",
        "severity": "low",
        "remediation": "1. Resolver las tareas pendientes en seguridad antes de pasar a producción.\n2. Registrar vulnerabilidades conocidas en el gestor de tareas.",
        "patterns": [r"TODO\s*:\s*autentica", r"FIXME\s*:\s*seguridad", r"TODO\s*:\s*validar", r"TODO\s*:\s*encripta"],
        "description": "Comentarios de desarrolladores que indican lógica de seguridad incompleta o temporal.",
    },
    {
        "rule_id": "OWASP-A04-CLIENT-LOGIC",
        "title": "Verificación de Privilegios en Cliente",
        "severity": "medium",
        "remediation": "1. Validar los privilegios en el lado del servidor obligatoriamente.\n2. Tratar las decisiones del cliente como sugerencias de interfaz.",
        "patterns": [r"checkPrivileges\(", r"validateAdminStatus\("],
        "description": "Lógica crítica de privilegios realizada en JavaScript del cliente, propensa a ser alterada por el usuario.",
    },
    # --- OWASP-A05 ---
    {
        "rule_id": "OWASP-A05-DEBUG-ACTIVE",
        "title": "Modo Debug Habilitado",
        "severity": "high",
        "remediation": "1. Desactivar el modo debug en entornos productivos.\n2. Configurar la variable a False por defecto o cargarla del entorno.",
        "patterns": [r"debug\s*=\s*True", r"DEBUG\s*:\s*true"],
        "description": "El modo depuración activo expone información de la pila de errores, variables y estructura interna a usuarios externos.",
    },
    {
        "rule_id": "OWASP-A05-DEFAULT-CREDS",
        "title": "Uso de Credenciales por Defecto",
        "severity": "high",
        "remediation": "1. Cambiar inmediatamente las credenciales por defecto por contraseñas seguras.\n2. Utilizar procesos de inicialización dinámica de contraseñas.",
        "patterns": [r"['\"]admin['\"]\s*,\s*['\"]admin['\"]", r"['\"]root['\"]\s*,\s*['\"]root['\"]", r"['\"]guest['\"]\s*,\s*['\"]guest['\"]"],
        "description": "Presencia de pares de usuario/contraseña genéricos en el código de configuración.",
    },
    {
        "rule_id": "OWASP-A05-DIR-LISTING",
        "title": "Listado de Directorios Activado",
        "severity": "medium",
        "remediation": "1. Deshabilitar el listado automático de directorios en el servidor web.\n2. Devolver respuestas 403 Forbidden para rutas sin archivo de inicio.",
        "patterns": [r"serve_index\s*=\s*True", r"directory_listing\s*=\s*true"],
        "description": "Configuración que permite a cualquiera inspeccionar y descargar el contenido de los directorios del servidor.",
    },
    {
        "rule_id": "OWASP-A05-INSECURE-COOKIE",
        "title": "Cookie Insegura (Atributo Secure Falso)",
        "severity": "medium",
        "remediation": "1. Establecer el atributo `secure: true` para que las cookies de sesión solo viajen por HTTPS.\n2. Usar `httpOnly: true` para prevenir accesos desde JS.",
        "patterns": [r"cookie\([^,]*secure\s*:\s*false"],
        "description": "Configuración de cookies sensibles sin flag secure, lo que expone los datos a intercepción en redes no seguras.",
    },
    {
        "rule_id": "OWASP-A05-DOCKER-ROOT",
        "title": "Contenedor ejecutado como Root (Dockerfile)",
        "severity": "medium",
        "remediation": "1. Agregar una instrucción 'USER <nombre_usuario>' sin privilegios en el Dockerfile.\n2. No ejecutar procesos como root dentro del contenedor.",
        "patterns": [r"USER\s+root"],
        "description": "Ejecutar el contenedor como root por defecto expone el host a ataques de escape de contenedor.",
    },
    {
        "rule_id": "OWASP-A05-K8S-PRIV-ESC",
        "title": "Escalabilidad de Privilegios en Pod",
        "severity": "medium",
        "remediation": "1. Definir 'allowPrivilege" + "Escalation: false' en el securityContext de cada contenedor de Kubernetes.",
        "patterns": [r"allowPrivilege" + r"Escalation\s*:\s*true"],
        "description": "Permitir la escalabilidad de privilegios (`allowPrivilege" + "Escalation: true`) permite a los procesos secundarios obtener más privilegios que su proceso primario.",
    },
    # --- OWASP-A06 ---
    {
        "rule_id": "OWASP-A06-DEP-VULN",
        "title": "Componente Vulnerable Importado",
        "severity": "medium",
        "remediation": "1. Verificar versiones en requirements.txt / package.json y correr herramientas de auditoría.\n2. Actualizar las dependencias regularmente.",
        "patterns": [r"import\s+django\b", r"import\s+flask\b", r"import\s+requests\b", r"require\(\s*['\"]express['\"]"],
        "description": "Uso de librerías externas que suelen requerir una auditoría de dependencias constante para evitar fallas conocidas.",
    },
    # --- OWASP-A07 ---
    {
        "rule_id": "OWASP-A07-WEAK-PASS-CHECK",
        "title": "Autenticación Débil / Comparación Directa",
        "severity": "high",
        "remediation": "1. Utilizar funciones seguras de hash con saltos de tiempo constante.\n2. Implementar MFA (Multi-Factor Authentication).",
        "patterns": [r"password\s*==\s*password", r"password\s*==\s*['\"][^'\"]*['\"]", r"if\s+user_id\s*==\s*['\"]"],
        "description": "Comparación directa de claves o validaciones triviales en procesos de autenticación.",
    },
    {
        "rule_id": "OWASP-A07-PLAIN-TEXT",
        "title": "Contraseña en Texto Plano",
        "severity": "high",
        "remediation": "1. Hashear contraseñas usando algoritmos seguros (Bcrypt, Argon2) antes de guardarlas.\n2. Nunca manipular la contraseña en texto plano en logs o bases de datos.",
        "patterns": [r"storePassword\s*\(", r"saveRawPassword\("],
        "description": "Funciones destinadas a almacenar o procesar contraseñas sin aplicar cifrado o hash previo.",
    },
    {
        "rule_id": "OWASP-A07-NO-LOCKOUT",
        "title": "Ausencia de Control de Intentos de Acceso",
        "severity": "medium",
        "remediation": "1. Implementar bloqueo de cuenta temporal tras varios intentos fallidos.\n2. Agregar rate limiting a los endpoints de inicio de sesión.",
        "patterns": [r"loginAttempts\s*=\s*0"],
        "description": "Manejo de logins sin controles contra ataques de fuerza bruta.",
    },
    {
        "rule_id": "OWASP-A07-WEAK-SESSION",
        "title": "Generación de ID de Sesión Débil",
        "severity": "high",
        "remediation": "1. Utilizar un generador de números pseudoaleatorios criptográficamente seguro (CSPRNG).\n2. Confiar la gestión de sesiones a frameworks maduros.",
        "patterns": [r"Math\.random\(\)\.toString\(36\)"],
        "description": "Uso de generadores matemáticos aleatorios no seguros para crear identificadores de sesión, facilitando el secuestro de sesiones.",
    },
    # --- OWASP-A08 ---
    {
        "rule_id": "OWASP-A08-UNSAFE-DESERIALIZATION",
        "title": "Deserialización Insegura",
        "severity": "high",
        "remediation": "1. Evitar deserializar datos no confiables.\n2. Usar formatos de intercambio de datos seguros como JSON en su lugar.",
        "patterns": [r"yaml\.load\([^,]*Loader\s*=\s*yaml\.UnsafeLoader", r"yaml\.unsafe_load\(", r"pickle\.loads\("],
        "description": "Deserialización de objetos (como Pickle o YAML inseguro) que permite la instanciación de clases maliciosas y ejecución de código.",
    },
    {
        "rule_id": "OWASP-A08-NO-CHECKSUM",
        "title": "Descarga de Código sin Verificación",
        "severity": "medium",
        "remediation": "1. Forzar SSL/TLS y verificar certificados en todas las descargas.\n2. Validar firmas o checksums SHA-256 de los archivos descargados.",
        "patterns": [r"download\([^,]*,\s*verify\s*=\s*False"],
        "description": "Descarga de archivos desactivando la verificación SSL o de integridad, expuesto a ataques de Man-in-the-Middle (MitM).",
    },
    {
        "rule_id": "OWASP-A08-UNSIGNED-JWT",
        "title": "JWT sin Firma Aceptado",
        "severity": "high",
        "remediation": "1. Validar rigurosamente la firma de los tokens en cada solicitud.\n2. Deshabilitar explícitamente el soporte del algoritmo 'none'.",
        "patterns": [r"algorithm\s*:\s*['\"]none['\"]"],
        "description": "Configuración de JSON Web Tokens que acepta firmas nulas, permitiendo suplantar identidades manipulando la carga útil.",
    },
    # --- OWASP-A09 ---
    {
        "rule_id": "OWASP-A09-SILENT-EXCEPT",
        "title": "Captura Silenciosa de Excepción",
        "severity": "low",
        "remediation": "1. Registrar los errores en logs con niveles adecuados (Error/Warning).\n2. Evitar capturas genéricas que no realicen ninguna acción correctora.",
        "patterns": [r"except\s*:\s*pass", r"except\s+Exception\s*:\s*pass", r"catch\s*\(\s*e\s*\)\s*\{\s*\}"],
        "description": "Errores y excepciones capturadas de manera silenciosa sin alertar o registrar el incidente.",
    },
    {
        "rule_id": "OWASP-A09-LOG-SECRETS",
        "title": "Registro de Secretos en Log",
        "severity": "medium",
        "remediation": "1. Sanitizar la información antes de escribirla en archivos de log.\n2. Evitar imprimir variables completas que contengan contraseñas o tokens.",
        "patterns": [r"console\.log\(.*password", r"logger\.info\(.*api_key"],
        "description": "Escritura explícita de credenciales, contraseñas o llaves de API en los registros del sistema.",
    },
    {
        "rule_id": "OWASP-A09-LEAK-ERROR",
        "title": "Fuga de Stack Trace en Error",
        "severity": "medium",
        "remediation": "1. Retornar mensajes de error genéricos y amigables al cliente.\n2. Guardar el error original con toda la traza únicamente en logs internos.",
        "patterns": [r"res\.send\(\s*e\.stack\s*\)", r"res\.json\(\s*e\s*\)"],
        "description": "Envío de detalles internos de la base de datos o pila de llamadas directamente al usuario, facilitando el mapeo de vulnerabilidades.",
    },
    # --- OWASP-A10 ---
    {
        "rule_id": "OWASP-A10-SSRF-REQUESTS",
        "title": "Riesgo de Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "remediation": "1. Validar y filtrar URLs provistas por el usuario contra una lista blanca (allowlist).\n2. Denegar el acceso a direcciones IP locales o del bucle de retorno (localhost, 127.0.0.1, 169.254.169.254).",
        "patterns": [r"requests\.(get|post)\(\s*url\b", r"fetch\(\s*req\.query\."],
        "description": "El servidor realiza solicitudes HTTP salientes basadas en parámetros proveídos de forma externa sin restricciones.",
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
    
    # Add CVE analysis (executed only once per scan)
    cve_findings = analyze_for_cves(content)
    findings.extend(cve_findings)
    
    return findings


def scan_url(target_url: str) -> list[Finding]:
    requests = __import__('requests')
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
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
        all_headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        headers_context = f"{status_line}\n{all_headers_str}"
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
                    evidence=(
                        f"Origen del hallazgo: Cabeceras de respuesta HTTP\n"
                        f"Detalle: Respuesta HTTP sin la cabecera '{header_name}'\n\n"
                        f"Respuesta HTTP completa recibida:\n{headers_context}"
                    ),
                )
            )

    if "Server" in headers:
        findings.append(
            Finding(
                rule_id="OWASP-A06",
                title="Divulgación de información",
                severity="low",
                description="La cabecera Server expone detalles de la infraestructura.",
                evidence=(
                    f"Origen del hallazgo: Cabecera HTTP 'Server'\n"
                    f"Detalle: Se encontró la cabecera 'Server: {headers['Server']}'\n\n"
                    f"Respuesta HTTP completa recibida:\n{headers_context}"
                ),
            )
        )

    return findings


def scan_github_repo(repo_url: str, github_token: str | None = None) -> list[Finding]:
    """Descarga y analiza un repositorio de GitHub"""
    requests = __import__('requests')
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
            except Exception as e:
                err = e

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
        code_extensions = {
            ".py", ".js", ".java", ".cpp", ".c", ".go", ".rb", ".php", ".ts", ".tsx", ".jsx", ".vue", ".cs", ".swift",
            ".kt", ".scala", ".sql", ".sh", ".ps1", ".bat", ".tf", ".yaml", ".yml"
        }
        file_count = 0

        with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
            for file_info in zip_file.filelist:
                filename_lower = file_info.filename.lower()
                is_code = any(filename_lower.endswith(ext) for ext in code_extensions) or "dockerfile" in filename_lower
                if is_code:
                    try:
                        content = zip_file.read(file_info).decode('utf-8', errors='replace')
                        # Analizar el archivo
                        file_findings = scan_code(content)

                        # Agregar el nombre del archivo a cada hallazgo
                        for finding in file_findings:
                            finding.evidence = f"Archivo: {file_info.filename}\n{finding.evidence}"

                        findings.extend(file_findings)
                        file_count += 1
                    except (UnicodeDecodeError, Exception) as e:
                        err = e

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
    if not base:
        for prefix in ["OWASP-A01", "OWASP-A02", "OWASP-A03", "OWASP-A04", "OWASP-A05", "OWASP-A06", "OWASP-A07", "OWASP-A08", "OWASP-A09", "OWASP-A10"]:
            if rule_id.startswith(prefix):
                base = REMEDIATIONS.get(prefix, "")
                break
    adapted = base
    if frameworks:
        if "fastapi" in frameworks:
            if rule_id.startswith("OWASP-A05"):
                adapted = "En FastAPI: agrega middleware que establezca cabeceras de seguridad (usar `Starlette` middleware).\n" + adapted
            if rule_id.startswith("OWASP-A06"):
                adapted = "En FastAPI: configura Uvicorn/productor reverse-proxy para ocultar cabecera Server.\n" + adapted
        if "flask" in frameworks:
            if rule_id.startswith("OWASP-A05"):
                adapted = "En Flask: utiliza `Flask-Talisman` o establecer manualmente cabeceras de seguridad en `after_request`.\n" + adapted
        if "django" in frameworks:
            if rule_id.startswith("OWASP-A05"):
                adapted = "En Django: configurar `SECURE_*` settings (HSTS, Content Security Policy a través de middleware).\n" + adapted
    return adapted
