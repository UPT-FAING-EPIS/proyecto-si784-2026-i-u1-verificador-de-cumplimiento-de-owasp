# FD04 - Informe de Arquitectura de Software (SAD)

**UNIVERSIDAD PRIVADA DE TACNA**

**FACULTAD DE INGENIERÍA**

**Escuela Profesional de Ingeniería de Sistemas**

**Proyecto:** Sistema Verificador de Cumplimiento OWASP

Curso: Calidad y Pruebas de Software

Docente: Patrick Jose Cuadros Quiroga

Integrantes:
- Andia Navarro, Diego Fabrizio - 2022073906
- Concha Llaca Gerardo Alejandro - 2017057849

Tacna – Perú

2026

---

## CONTROL DE VERSIONES

| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
|---|---|---|---|---|---|
| 1.0 | Equipo | Profesor | - | 25/04/2026 | Versión final inicial |
| 2.0 | Equipo | Profesor | - | 24/06/2026 | Re-diseño de la persistencia (SQLite3), inclusión de la arquitectura de la Extensión de VS Code y el escáner de CVEs |

---

## ÍNDICE GENERAL

1. Introducción
  1.1 Propósito
  1.2 Alcance
  1.3 Definiciones, siglas y abreviaturas
  1.4 Organización del documento
2. Objetivos y restricciones arquitectónicas
  2.1 Requerimientos funcionales
  2.2 Requerimientos no funcionales
  2.3 Restricciones
3. Representación de la arquitectura del sistema
  3.1 Vista de casos de uso
  3.2 Vista lógica
  3.3 Vista de implementación
  3.4 Vista de procesos
  3.5 Vista de despliegue
4. Atributos de calidad

---

## 1. Introducción

### 1.1 Propósito
El propósito de este documento es detallar el diseño y la arquitectura global del **Ecosistema Verificador de Cumplimiento OWASP**. Describe la organización lógica, física, de procesos y de implementación del sistema, facilitando la comprensión del flujo de datos entre la extensión del desarrollador en el IDE y el backend de auditoría.

### 1.2 Alcance
Este documento describe el sistema compuesto por el servidor web FastAPI y la extensión para VS Code. Cubre las vistas de arquitectura bajo una metodología simplificada basada en el modelo 4+1, analizando los diagramas de componentes, paquetes y despliegue del software.

### 1.3 Definiciones, siglas y abreviaturas
- **OWASP:** Open Web Application Security Project (Proyecto Abierto de Seguridad de Aplicaciones Web).
- **API:** Application Programming Interface (Interfaz de Programación de Aplicaciones).
- **SQLite3:** Motor de base de datos relacional ligero basado en archivos locales, sin proceso servidor independiente.
- **CVE:** Common Vulnerabilities and Exposures (Vulnerabilidades y Exposiciones Comunes).
- **IDE:** Integrated Development Environment (Entorno de Desarrollo Integrado, ej. VS Code).
- **JSON:** JavaScript Object Notation (Notación de Objetos de JavaScript).
- **HTTP/HTTPS:** Hypertext Transfer Protocol (Protocolo de Transferencia de Hipertexto).

### 1.4 Organización del documento
El documento se divide en cuatro capítulos principales: objetivos y restricciones, representación de las vistas de arquitectura, atributos de calidad del software y bibliografía.

---

## 2. Objetivos y restricciones arquitectónicas

### 2.1 Requerimientos funcionales
- **Análisis Multi-Objetivo:** Recibir solicitudes de análisis desde interfaces web, APIs o la extensión de desarrollo para escanear código, URLs o repositorios de GitHub.
- **Auditoría de Vulnerabilidades:** Identificar riesgos del OWASP Top 10 y dependencias desactualizadas o vulnerables (CVEs).
- **Persistencia de Resultados:** Guardar los escaneos y hallazgos en una base de datos local SQLite3 de manera transaccional.
- **Reportes Dinámicos:** Mostrar resultados de cumplimiento mediante un score (0-100) y descripciones detalladas con sugerencias de remediación.
- **Integración con IDE:** Detectar eventos de guardado de archivos de código en VS Code para mostrar diagnósticos en tiempo real en el editor.

### 2.2 Requerimientos no funcionales
- **Mantenibilidad:** El código debe estar estructurado de forma modular para permitir la adición de nuevas reglas de análisis sin alterar los routers.
- **Simplicidad de Despliegue:** El sistema debe operar con la menor cantidad de dependencias del sistema posibles (base de datos SQLite3 en un archivo local).
- **Rendimiento:** Tiempos de respuesta óptimos (menor a 5 segundos para código fuente en desarrollo).
- **Seguridad:** Aislamiento de tokens, control de sesiones en memoria y validación de endpoints administrativos mediante API Keys.

### 2.3 Restricciones
- El backend del sistema se implementa exclusivamente en Python 3.11+ utilizando el framework FastAPI.
- La extensión se desarrolla con JavaScript estándar para la API de extensiones de VS Code.
- La base de datos es local y utiliza **SQLite3** con persistencia en un archivo (`data/scans.sqlite3`).
- El análisis de dependencias (CVE) se limita a las librerías soportadas en la base de datos de firmas predefinida en la aplicación.

---

## 3. Representación de la arquitectura del sistema

### 3.0 Patrón Arquitectónico Principal: Arquitectura en Capas (Layered Architecture)

El sistema de software **OWASP Verificator** se ha diseñado y estructurado siguiendo de manera estricta el patrón arquitectónico de **Arquitectura en Capas (Layered Architecture)**. Este patrón divide el sistema en grupos de componentes con responsabilidades específicas, permitiendo que cada capa exponga servicios bien definidos a la capa superior inmediata, logrando un alto grado de desacoplamiento, facilidad de pruebas y mantenibilidad.

El sistema se organiza en las siguientes cuatro capas lógicas:

1. **Capa de Presentación (Interfaz de Usuario / Vista)**:
   * **Descripción**: Encargada de renderizar la información para el usuario final e interceptar sus acciones.
   * **Componentes**: Plantillas de renderizado de servidor con Jinja2 en `app/templates/` y recursos estáticos interactivos (hojas de estilo CSS, scripts JS, favicon SVG) en `app/static/`.

2. **Capa de Controladores (Ruteo / API Entrypoints)**:
   * **Descripción**: Define los endpoints de comunicación (REST API) y procesa/valida las solicitudes HTTP de entrada provenientes del cliente web o de la extensión del IDE.
   * **Componentes**: Archivos en `app/routers/` (`analysis.py`, `dashboard.py`, `reports.py`) y el punto de entrada principal en `app/main.py`. Utiliza DTOs definidos con Pydantic en `app/schemas.py`.

3. **Capa de Lógica de Negocio (Service Layer)**:
   * **Descripción**: Centraliza las reglas y algoritmos específicos del negocio, tales como el motor de análisis regex OWASP, el evaluador de CVEs y la integración externa.
   * **Componentes**: Módulos en `app/services/` (`scanner.py`, `cve_analyzer.py`, `github_integration.py`, `pdf_export.py`, `analysis_service.py`).

4. **Capa de Acceso a Datos / Persistencia (Data Layer)**:
   * **Descripción**: Gestiona el ciclo de vida y almacenamiento persistente de los registros (Scans, Findings, tokens de sesión).
   * **Componentes**: Administrado a través de `app/store.py` (`InMemoryScanStore`) que encapsula la base de datos local SQLite3 (`data/scans.sqlite3`). Representa las entidades mediante los modelos definidos en `app/models.py`.

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Capa de Presentación (Jinja2 Templates / CSS / JS)       │
└──────────────┬──────────────────────────────────────────────┘
               │ Envío de Formularios / Peticiones HTTP
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Capa de Controladores (app.routers / FastAPI API)        │
└──────────────┬──────────────────────────────────────────────┘
               │ Validación de Peticiones (DTOs Pydantic)
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Capa de Negocio / Servicios (app.services - Scanners)    │
└──────────────┬──────────────────────────────────────────────┘
               │ Ejecución de Lógica y Penalidades OWASP
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Capa de Datos (app.store / sqlite3 / app.models)         │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 Vista de casos de uso
Los casos de uso que guían la arquitectura son:
- Analizar código desde formulario web o API.
- Analizar URLs externas de forma segura.
- Analizar repositorio completo de GitHub.
- Recibir diagnósticos y soluciones en tiempo real en VS Code.

---

### 3.2 Vista lógica

#### Diagrama de paquetes del backend
El código del servidor FastAPI se organiza bajo la siguiente estructura modular:

- `app.routers`: Define los endpoints HTTP/REST de la API y el ruteo de las vistas web (dashboard, reports, analysis).
- `app.services`: Contiene los motores lógicos de escaneo (`scanner.py`), el evaluador de CVEs (`cve_analyzer.py`), y la integración con la API de GitHub.
- `app.models`: Define las estructuras de datos de negocio (`Scan` y `Finding`) basadas en Python dataclasses.
- `app.store`: Administra la persistencia transaccional de los datos en SQLite3 y la gestión de tokens de seguridad en memoria.

#### Flujo de Persistencia de Datos
A diferencia de los modelos ORM tradicionales que fragmentan la información en múltiples tablas unidas por llaves foráneas, el sistema utiliza un diseño simplificado para alta velocidad de lectura:

```
[Router / API] ──> [Analysis Service] ──> [InMemoryScanStore]
                                                   │
                                     ┌─────────────┴─────────────┐
                                     ▼                           ▼
                           [data/scans.sqlite3]          [data/scans.json]
                           (Tabla scans con             (Respaldo plano
                           findings_json TEXT)           de los análisis)
```

---

### 3.3 Vista de implementación

#### Diagrama de componentes
El ecosistema interactúa de la siguiente manera:

```
  ┌────────────────────────────────────────────────────────┐
  │                 Extensión de VS Code                   │
  │   ┌─────────────────────┐       ┌──────────────────┐   │
  │   │  Extension Host     │ <───> │ Webview Panel    │   │
  │   │  (JS/Diagnostics)   │       │ (Dashboard UI)   │   │
  │   └──────────┬──────────┘       └──────────────────┘   │
  └──────────────┼─────────────────────────────────────────┘
                 │
                 │ Solicitud HTTP POST (Análisis)
                 ▼
  ┌────────────────────────────────────────────────────────┐
  │                 Sistema Web Backend                    │
  │   ┌─────────────────────┐       ┌──────────────────┐   │
  │   │ FastAPI Router      │ <───> │ Jinja2 Templates │   │
  │   └──────────┬──────────┘       └──────────────────┘   │
  │              │                                         │
  │              ▼                                         │
  │   ┌─────────────────────┐       ┌──────────────────┐   │
  │   │ Services (Scanner)  │ <───> │ cve_analyzer     │   │
  │   └──────────┬──────────┘       └──────────────────┘   │
  │              │                                         │
  │              ▼                                         │
  │   ┌─────────────────────┐                              │
  │   │ app.store (Store)   │                              │
  │   └──────────┬──────────┘                              │
  └──────────────┼─────────────────────────────────────────┘
                 │
                 ▼
      [Base de Datos SQLite3]
```

---

### 3.4 Vista de procesos

#### Actividad de Escaneo
1. Un cliente (Web, API o Extensión) solicita el análisis enviando un payload con `target_type` y `target_value`.
2. El enrutador correspondiente valida la estructura de la petición (`AnalyzeRequest`).
3. Se invoca a `analysis_service.py`, el cual deriva el flujo al escáner adecuado (`scan_code`, `scan_url` o `scan_github_repo`).
4. Si es análisis de código, se corre en paralelo el motor de búsqueda regex de OWASP y el extractor de imports para confrontar contra `KNOWN_CVES`.
5. Se calcula la puntuación (`calculate_score`) restando penalidades por vulnerabilidad.
6. El servicio llama a `scan_store.create_scan()`, el cual inserta el registro en la base de datos SQLite y guarda los hallazgos en formato JSON dentro del campo `findings_json`.
7. Se retorna el reporte estructurado en formato JSON o se redirige a la plantilla de reporte web.

---

### 3.5 Vista de despliegue

El despliegue está diseñado para ser autoportante y se caracteriza por:
- **Servidor de Aplicaciones:** Un entorno Python con `FastAPI` servido localmente por `Uvicorn` o en contenedores/Azure App Service con `Gunicorn`.
- **Almacenamiento Local:** No requiere la instalación o administración de un motor de base de datos MySQL o PostgreSQL. La base de datos es un archivo local transaccional SQLite3 que se inicializa automáticamente al arrancar la aplicación por primera vez en la ruta `data/scans.sqlite3`.
- **Extensión de Editor:** Paquetizada en un archivo `.vsix` instalable directamente en VS Code, el cual se comunica vía solicitudes HTTP al backend (configurable).

---

## 4. Atributos de calidad del software

- **Mantenibilidad:** La incorporación de un archivo `store.py` centralizado e independiente de ORM pesados permite cambiar la tecnología de base de datos con un impacto mínimo en los routers y servicios de análisis.
- **Portabilidad:** Al utilizar SQLite3 nativo, el backend no tiene dependencias de infraestructura específicas, pudiendo correr de manera idéntica en Windows (desarrollo local de la extensión) o Linux (despliegue en Azure).
- **Usabilidad:** La extensión de VS Code responde de manera transparente en segundo plano sin interrumpir el flujo de escritura del desarrollador.
- **Seguridad:** El backend valida las URLs analizadas para evitar ataques de SSRF y valida los tokens de API con mecanismos de expiración en memoria.

---

## Bibliografía

- Bass, L., Clements, P., & Kazman, R. (2012). *Software Architecture in Practice* (3rd Edition). Addison-Wesley.
- FastAPI Official Reference. [https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/).
- SQLite Documentation. [https://www.sqlite.org/docs.html](https://www.sqlite.org/docs.html).
