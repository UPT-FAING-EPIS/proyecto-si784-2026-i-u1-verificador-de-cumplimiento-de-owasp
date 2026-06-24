# FD03 - Informe de Especificación de Requerimientos de Software (SRS)

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
| 2.0 | Equipo | Profesor | - | 24/06/2026 | Actualización por incorporación de Extensión de VS Code, análisis de repositorios de GitHub, escáner de CVEs y migración a SQLite3 |

---

## ÍNDICE GENERAL

1. Introducción
2. Alcance del proyecto
3. Análisis del problema
4. Objetivos
5. Requerimientos del sistema
  5.1 Requerimientos funcionales
  5.2 Requerimientos no funcionales
  5.3 Reglas de negocio
6. Perfiles y actores
7. Modelo conceptual
8. Casos de uso
9. Conclusiones
10. Bibliografía

---

## 1. Introducción

Este documento define los requisitos del **Sistema Verificador de Cumplimiento OWASP**, una plataforma integrada de herramientas diseñadas para evaluar y mejorar el cumplimiento de las directrices de seguridad de **OWASP Top 10** en el código de forma ágil, simple y ampliable.

El sistema consta de dos componentes principales:
1. **Extensión de VS Code (v0.1.8):** Un asistente de desarrollo en tiempo real con dashboard premium e integración directa con IA (Copilot/Gemini).
2. **Sistema Web API (FastAPI):** Un backend de análisis estático de código, escaneo de URLs de producción, análisis de repositorios de GitHub y base de datos persistente en SQLite3.

---

## 2. Alcance del proyecto

El proyecto abarca la implementación de un ecosistema de verificación de seguridad que ofrece:
- **Análisis de código fuente:** Escaneo de archivos en busca de patrones de riesgo (exposición de secretos, funciones peligrosas, inyecciones de código).
- **Análisis de dependencias (CVE):** Identificación de paquetes vulnerables conocidos (como Django, Flask, Requests, PyYAML) comparándolos con una base de datos integrada y analizando archivos `requirements.txt`.
- **Análisis de URLs:** Verificación de la presencia y correcta configuración de cabeceras HTTP de seguridad críticas (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
- **Escaneo de repositorios de GitHub:** Descarga automática y análisis completo de archivos de código desde repositorios públicos o privados (usando tokens de GitHub).
- **Persistencia de resultados:** Almacenamiento estructurado e histórico de cada análisis realizado y sus hallazgos en una base de datos local SQLite3.
- **Asistente de desarrollo en IDE (VS Code):** Diagnósticos visuales con subrayado de errores directamente en el código del editor, barra de estado integrada, panel de dashboard glassmorphic premium e integración de remediación guiada por IA con Copilot y Gemini.
- **API REST integrada:** Endpoints estructurados para ejecutar análisis, validar y generar tokens de acceso, y exportar reportes.

**Fuera del alcance:** No incluye explotación de vulnerabilidades (pentesting activo), análisis dinámico en tiempo de ejecución (DAST), ni escaneo automático de puertos y redes corporativas.

---

## 3. Análisis del problema

Las aplicaciones de software modernas están constantemente expuestas a riesgos de seguridad que comprometen la confidencialidad de la información y la disponibilidad de los servicios. A pesar de la existencia de guías como el **OWASP Top 10**, los desarrolladores a menudo cometen errores básicos debido a la falta de retroalimentación inmediata durante la etapa de codificación.

### Problemas actuales
- **Exposición involuntaria de secretos:** Credenciales, llaves de API y contraseñas escritas directamente en el código fuente.
- **Uso de funciones inseguras:** Invocación de rutinas peligrosas (`eval`, `exec`, `pickle.loads`) susceptibles de inyección de código.
- **Inexistencia de cabeceras de protección:** Servidores web y aplicaciones en producción desplegados sin cabeceras HTTP que mitiguen ataques como Cross-Site Scripting (XSS) y Clickjacking.
- **Uso de dependencias obsoletas:** Integración de librerías de terceros con vulnerabilidades conocidas y documentadas (CVEs).
- **Falta de retroalimentación en el IDE:** Retraso en la detección de fallos de seguridad hasta las etapas de integración continua o producción.

---

## 4. Objetivos

### Objetivo general
Diseñar e implementar un sistema verificador que permita evaluar de manera ágil y en tiempo real el cumplimiento de los controles de seguridad OWASP Top 10 en código, repositorios y URLs, integrando interfaces web, APIs y entornos de desarrollo (IDE).

### Objetivos específicos
- Proveer un motor de análisis estático basado en reglas regex extensibles para detectar vulnerabilidades en lenguajes de programación comunes.
- Detectar dependencias vulnerables y asociarlas a vulnerabilidades conocidas de la base de datos de CVE.
- Evaluar la configuración de cabeceras de seguridad HTTP en endpoints públicos.
- Desarrollar una extensión de VS Code que brinde soporte visual en tiempo real (diagnósticos y dashboard premium) para corregir vulnerabilidades durante el desarrollo.
- Integrar capacidades de Inteligencia Artificial para ofrecer guías automatizadas de remediación en el IDE.
- Almacenar y categorizar los hallazgos de seguridad en una base de datos SQLite3 persistente y estructurada.

---

## 5. Requerimientos del sistema

### 5.1 Requerimientos funcionales

| ID | Requerimiento | Descripción | Prioridad |
|---|---|---|---|
| **RF01** | Ingreso de objetivo | El sistema recibe código, archivo local, URL web o URL de repositorio de GitHub para su análisis. | Alta |
| **RF02** | Escaneo de código | El sistema analiza la sintaxis del código para detectar vulnerabilidades (secretos hardcodeados, funciones inseguras, etc.). | Alta |
| **RF03** | Escaneo de URL | El sistema realiza una consulta HTTP/HTTPS externa para verificar la presencia de cabeceras de seguridad indispensables. | Alta |
| **RF04** | Escaneo de GitHub | El sistema descarga repositorios públicos o privados (con token de acceso) en formato ZIP y analiza todos sus archivos. | Media |
| **RF05** | Detección de CVE | El sistema analiza las dependencias declaradas y usadas contra una lista predefinida de CVEs conocidos. | Media |
| **RF06** | Almacenamiento persistente | El sistema almacena de forma estructurada cada escaneo con sus metadatos e historial de hallazgos en SQLite3. | Alta |
| **RF07** | Reporte e Historial | El sistema renderiza un reporte interactivo con puntajes de cumplimiento y lista detallada de vulnerabilidades en la web y el IDE. | Alta |
| **RF08** | API REST de análisis | El sistema expone endpoints públicos y privados para interactuar con el motor desde herramientas de terceros o scripts. | Media |
| **RF09** | Diagnósticos en IDE | La extensión de VS Code subraya automáticamente las líneas vulnerables en el editor al guardar un archivo. | Alta |
| **RF10** | Dashboard en IDE | La extensión provee un panel gráfico interactivo con interfaz glassmorphic para buscar, filtrar y examinar los hallazgos. | Alta |
| **RF11** | Remediación por IA | El sistema adapta las soluciones al framework detectado (FastAPI, Flask, Django) y genera prompts listos para Copilot/Gemini. | Media |

---

### 5.2 Requerimientos no funcionales

| ID | Requerimiento | Descripción | Prioridad |
|---|---|---|---|
| **RNF01** | Rendimiento | El tiempo de respuesta de los análisis locales de código debe ser menor a 5 segundos, y el de URLs menor a 15 segundos. | Media |
| **RNF02** | Seguridad de Acceso | La API REST requiere validación de tokens de acceso (`X-API-Key`) para endpoints de generación de tokens o lectura de logs. | Alta |
| **RNF03** | Arquitectura Desacoplada | Separación estricta entre la lógica de negocio (servicios), la base de datos (store), la presentación (templates) y la extensión VS Code. | Alta |
| **RNF04** | Portabilidad y Dependencias | El sistema debe ejecutarse en Windows, macOS y Linux sin requerir configuraciones de bases de datos externas pesadas. | Alta |
| **RNF05** | Usabilidad e Interfaz | El frontend web y el panel de VS Code deben utilizar estilos modernos (variables CSS, HSL, glassmorphism) y responder adecuadamente. | Media |
| **RNF06** | Control de Diagnósticos | El desarrollador debe poder desactivar los subrayados del editor (`owaspVerificator.showDiagnostics`) y gestionar los errores solo en el panel. | Media |

---

### 5.3 Reglas de negocio

- **RB01 (Formatos Soportados):** Solo se aceptan escaneos con objetivos clasificados como `code` (código en texto), `url` (direcciones web), `archivo` (archivos locales) o `github_repo` (enlaces de repositorios).
- **RB02 (Protocolos de URL):** Toda URL ingresada debe corresponder a un protocolo válido HTTP o HTTPS. Se bloquea el análisis de direcciones que apunten a localhost o interfaces locales para evitar SSRF.
- **RB03 (Puntuación de Seguridad):** Cada escaneo se inicia con un puntaje de seguridad perfecto de 100 puntos. Por cada hallazgo de seguridad detectado, se descuentan puntos según su gravedad:
  - Severidad **Alta (High):** Descuento de 30 puntos por hallazgo (ej. secretos expuestos, inyecciones de código).
  - Severidad **Media (Medium):** Descuento de 15 puntos por hallazgo (ej. cabeceras ausentes, comentarios inseguros).
  - Severidad **Baja (Low):** Descuento de 5 puntos por hallazgo (ej. cabecera Server expuesta, falta de logging).
- **RB04 (Límite de Penalización):** El puntaje mínimo asignado a un escaneo es 0. Las penalizaciones acumuladas nunca superarán los 100 puntos totales.
- **RB05 (Expiración de Sesión Administrativa):** Los tokens de sesión web administrativa en memoria deben expirar y eliminarse automáticamente pasadas 6 horas de su creación.

---

## 6. Perfiles y actores

### Actores
- **Usuario Desarrollador:** Desarrollador que escribe código en su IDE y utiliza el escáner de manera local (extensión) para asegurar el cumplimiento de OWASP.
- **Usuario Auditor:** Evaluador de calidad o seguridad que consulta el dashboard web para analizar el historial de cumplimiento y exportar reportes (PDF).
- **API Cliente:** Sistemas de terceros (como pipelines de CI/CD) que envían código o URLs al backend para verificaciones automatizadas.
- **Sistema Verificador:** Componente automático interno encargado de descargar archivos de GitHub, realizar peticiones HTTP a las URLs y aplicar expresiones regulares.

---

## 7. Modelo conceptual

El modelo se basa en un diseño lógico de persistencia de datos liviana y optimizada:

- **Scan (Entidad Principal):** Representa una solicitud de auditoría. Contiene los metadatos de ejecución (tipo, valor, estado, puntaje, fecha de creación) y una lista de hallazgos vinculada.
- **Finding (Entidad de Detalle):** Representa una vulnerabilidad o advertencia detectada en un escaneo específico. Incluye el identificador de la regla OWASP, título, severidad, descripción técnica, evidencia exacta de coincidencia, penalidad de puntos aplicada y recomendaciones de remediación.

En el almacenamiento físico (SQLite3), para mantener un esquema plano y alta velocidad de lectura sin la sobrecarga de un ORM complejo, cada registro de la tabla `scans` guarda su colección de `Findings` serializada en formato de texto JSON dentro de la columna `findings_json`.

---

## 8. Casos de uso

### Caso de Uso 1: Analizar archivo de código en tiempo real
- **Actor:** Usuario Desarrollador
- **Descripción:** El desarrollador guarda un archivo de código (`.py`, `.js`, etc.) en VS Code. La extensión detecta el evento de guardado, invoca al backend en segundo plano, recibe los diagnósticos y resalta con subrayado de color (rojo/amarillo) las líneas vulnerables.

### Caso de Uso 2: Consultar Dashboard en el IDE
- **Actor:** Usuario Desarrollador
- **Descripción:** El desarrollador abre el panel de control de la extensión. El sistema renderiza un dashboard glassmorphic con estadísticas generales del proyecto, porcentaje de cumplimiento y la lista colapsable de archivos con hallazgos activos.

### Caso de Uso 3: Analizar Repositorio de GitHub
- **Actor:** Usuario Auditor / Desarrollador
- **Descripción:** El usuario ingresa la URL de un repositorio de GitHub público o privado. El backend descarga la rama principal en formato ZIP, extrae y escanea recursivamente todos los archivos de código fuente admitidos y guarda el historial de resultados en la base de datos.

### Caso de Uso 4: Autenticar API y Consumir Resultados
- **Actor:** API Cliente
- **Descripción:** La API envía una solicitud HTTP POST al backend con un fragmento de código y la cabecera `X-API-Key`. El sistema valida la clave, realiza la auditoría y retorna los hallazgos en formato JSON.

---

## 9. Conclusiones

El **Sistema Verificador de Cumplimiento OWASP** evoluciona de ser una herramienta web simple a un ecosistema completo de desarrollo seguro integrado. La incorporación de la extensión de VS Code cierra la brecha entre el momento en que se introduce un error de seguridad y el momento de su corrección, aportando calidad desde las etapas iniciales del ciclo de vida del software.

---

## 10. Bibliografía

- OWASP Foundation. (2021). OWASP Top 10. Recuperado de [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/).
- Microsoft. Documentación oficial de VS Code Extension API. Recuperado de [https://code.visualstudio.com/api](https://code.visualstudio.com/api).
- FastAPI official documentation. Recuperado de [https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/).
