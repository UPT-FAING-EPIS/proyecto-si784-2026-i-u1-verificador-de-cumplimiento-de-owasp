# FD05 - Informe del Proyecto Final

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

## CONTROL DE VERSIONES

| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
|---|---|---|---|---|---|
| 1.0 | Equipo | Profesor | - | 25/04/2026 | Versión final |

## ÍNDICE GENERAL

1. Antecedentes
2. Planteamiento del problema
3. Justificación
4. Alcance
5. Objetivos
6. Marco teórico
7. Desarrollo de la solución
8. Análisis de factibilidad
9. Tecnología de desarrollo
10. Metodología de implementación
11. Cronograma
12. Presupuesto
13. Conclusiones
14. Recomendaciones
15. Bibliografía
16. Anexos

## 1. Antecedentes

Las aplicaciones modernas requieren protección ante vulnerabilidades del OWASP Top 10. La identificación temprana de problemas de seguridad en el código y en la configuración HTTP ayuda a reducir riesgos de exposición y ataques.

## 2. Planteamiento del problema

Los desarrolladores y evaluadores no siempre cuentan con una herramienta ligera que detecte patrones básicos de riesgo en código fuente y páginas web. Esto provoca que fallos de seguridad simples permanezcan sin corregir.

## 3. Justificación

El Sistema Verificador de Cumplimiento OWASP contribuye a mejorar la calidad del software y la seguridad en el ciclo de desarrollo. Facilita la identificación de problemas comunes antes de publicar aplicaciones.

## 4. Alcance

Se implementa un prototipo funcional que ofrece:
- Interfaz web para análisis de código y URL.
- API REST para análisis automatizado.
- Almacenamiento de resultados en base de datos.
- Reportes con score y hallazgos.

No se cubre análisis completo de aplicaciones corporativas ni auditoría de red.

## 5. Objetivos

### Objetivo general

Implementar un sistema capaz de analizar código y páginas web para detectar riesgos de cumplimiento OWASP.

### Objetivos específicos

- Desarrollar reglas de detección para patrones peligrosos en código.
- Evaluar seguridad de cabeceras HTTP en URLs.
- Guardar y presentar resultados de los escaneos.
- Permitir el uso tanto desde web como desde API.

## 6. Marco teórico

### OWASP

OWASP es una organización que publica el Top 10 de riesgos de seguridad para aplicaciones web.

### FastAPI

FastAPI es un framework Python moderno para construir APIs de alto rendimiento.

### SQLAlchemy

SQLAlchemy permite mapear objetos Python a una base de datos relacional y manejar sesiones.

### Requests

Requests es una biblioteca Python para realizar solicitudes HTTP de forma sencilla.

## 7. Desarrollo de la solución

### Arquitectura general

El sistema se basa en la arquitectura MVC ligera de FastAPI con separación de capas:
- Rutas (`app.routers`).
- Lógica de negocio (`app.services`).
- Persistencia (`app.models`, `app.db`).
- Presentación (`app.templates`).

### Mecánica de análisis

- Si el usuario envía `target_type=code`, se analiza el texto en busca de patrones.
- Si envía `target_type=url`, se realiza una petición HTTP y se evalúan cabeceras de seguridad.
- Se calculan puntajes restando valores según la severidad de hallazgos.

### Resultados

Cada análisis genera un `Scan` y uno o más `Finding` almacenados en MySQL.

## 8. Análisis de factibilidad

### Factibilidad técnica

El proyecto es factible con las tecnologías existentes: Python, FastAPI, SQLAlchemy y Requests. El equipo tiene experiencia básica en Python y desarrollo web.

### Factibilidad económica

El costo de desarrollo es bajo, ya que usa herramientas de código abierto y recursos disponibles en el entorno académico.

### Factibilidad operativa

El sistema es sencillo de operar mediante un servidor Python y una base de datos. El mantenimiento es manejable.

### Factibilidad social

Contribuye a la formación de estudiantes y a la cultura de desarrollo seguro.

### Factibilidad legal

No hay restricciones legales específicas, pues el proyecto es un análisis estático orientado a pruebas de seguridad.

### Factibilidad ambiental

El impacto ambiental es mínimo, limitado al uso de energía de un servidor y de equipo de desarrollo.

## 9. Tecnología de desarrollo

- Python 3
- FastAPI
- SQLAlchemy
- Requests
- Jinja2
- MySQL o base de datos compatible

## 10. Metodología de implementación

Se siguió un enfoque incremental y orientado a entregas: análisis de requisitos, diseño de arquitectura, implementación de servicios, integración de rutas y pruebas.

## 11. Cronograma

| Fase | Actividad | Duración |
|---|---|---|
| 1 | Recolección de requisitos y análisis | 1 semana |
| 2 | Diseño de arquitectura y modelo de datos | 1 semana |
| 3 | Implementación de análisis y servicios | 1 semana |
| 4 | Integración web y API | 1 semana |
| 5 | Pruebas y ajustes | 1 semana |

## 12. Presupuesto

El presupuesto estimado se basa en recursos de desarrollo académico y software libre:
- Desarrollo: sin costo adicional (equipo de estudiantes).
- Infraestructura: uso de equipo académico o entorno de laboratorio.
- Licencias: no requeridas.

## 13. Conclusiones

El proyecto demuestra un prototipo funcional de verificador OWASP con análisis de código y URL, y una arquitectura modular adecuada para ampliar reglas de seguridad.

## 14. Recomendaciones

- Extender las reglas de análisis con OWASP Top 10 completo.
- Agregar autenticación para acceso a reportes.
- Incluir pruebas automáticas de regresión.

## 15. Bibliografía

- OWASP Foundation. OWASP Top Ten.
- FastAPI Documentation.
- SQLAlchemy Documentation.
- Requests Documentation.

## 16. Anexos

- Anexo 01: Informe de Factibilidad (FD01)
- Anexo 02: Documento de Visión (FD02)
- Anexo 03: Documento SRS (FD03)
- Anexo 04: Documento SAD (FD04)
- Anexo 05: Manuales y otros documentos
