# FD03 - Informe de Especificación de Requerimientos de Software

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

## 1. Introducción

Este documento define los requisitos del **Sistema Verificador de Cumplimiento OWASP**, una aplicación web que analiza código y páginas web para detectar vulnerabilidades relacionadas con patrones comunes del OWASP Top 10.

El sistema se desarrolla con FastAPI, SQLAlchemy, Jinja2 y Python, y ofrece una interfaz web y una API para el envío de código fuente o URLs.

## 2. Alcance del proyecto

El proyecto abarca la implementación de un verificador de seguridad para:
- Análisis de texto de código fuente en busca de patrones de riesgo.
- Análisis de un URL para verificar cabeceras de seguridad HTTP.
- Almacenamiento de resultados de escaneo en base de datos.
- Generación de reportes con hallazgos y calificación de seguridad.

No incluye análisis profundo de aplicaciones completas, explotación de vulnerabilidades ni escaneo automático de redes.

## 3. Análisis del problema

Las aplicaciones modernas requieren controles de seguridad básicos para evitar exposición de secretos, ejecución de código malicioso y malas configuraciones HTTP. Los desarrolladores y evaluadores necesitan una herramienta ligera que identifique problemas de seguridad tempranamente.

### Problemas actuales

- Exposición de credenciales en código.
- Uso de funciones peligrosas como `eval` o `exec`.
- Debido a la falta de validación de entrada, puede haber vectores de inyección.
- Páginas web sin cabeceras de seguridad críticas.

## 4. Objetivos

### Objetivo general

Diseñar e implementar un sistema que permita detectar riesgos básicos de seguridad OWASP en código y páginas web mediante análisis automático.

### Objetivos específicos

- Detectar patrones de exposición de secretos y credenciales.
- Identificar llamadas a funciones peligrosas en código.
- Evaluar la presencia de cabeceras de seguridad HTTP en URLs.
- Presentar hallazgos clasificados por gravedad.
- Registrar escaneos y resultados en una base de datos.

## 5. Requerimientos del sistema

### 5.1 Requerimientos funcionales

| ID | Requerimiento | Descripción | Prioridad |
|---|---|---|---|
| RF01 | Ingreso de objetivo | El sistema recibe código o URL para análisis. | Alta |
| RF02 | Escaneo de código | El sistema analiza texto de código en busca de patrones OWASP. | Alta |
| RF03 | Escaneo de URL | El sistema analiza cabeceras de respuesta HTTP de una URL. | Alta |
| RF04 | Guarda resultados | El sistema almacena cada escaneo y sus hallazgos. | Media |
| RF05 | Reporte de resultados | El sistema muestra un reporte con score y detalles. | Alta |
| RF06 | API de análisis | El sistema expone una API REST para análisis automático. | Media |

### 5.2 Requerimientos no funcionales

| ID | Requerimiento | Descripción | Prioridad |
|---|---|---|---|
| RNF01 | Rendimiento | El tiempo de respuesta del análisis debe ser menor a 15 segundos para URLs y 5 segundos para análisis de código. | Media |
| RNF02 | Seguridad | El sistema debe validar entradas para evitar análisis de URLs inválidas. | Alta |
| RNF03 | Usabilidad | La interfaz web debe permitir ingresar claramente el tipo de objetivo y su valor. | Media |
| RNF04 | Mantenibilidad | El código debe estar organizado en módulos de FastAPI, servicios, modelos y plantillas. | Alta |
| RNF05 | Configuración | La conexión a la base de datos debe ser configurable mediante variables de entorno. | Media |

### 5.3 Reglas de negocio

- RB01: Solo se aceptan análisis de tipo `code` o `url`.
- RB02: Las URLs deben usar HTTP o HTTPS.
- RB03: Cada escaneo genera un registro único en la base de datos.
- RB04: El sistema clasifica los hallazgos en `high`, `medium` o `low`.
- RB05: El cálculo de puntaje inicia en 100 y descuenta según severidad.

## 6. Perfiles y actores

### Actores

- Usuario final: persona que solicita el análisis de código o URL.
- Analista de seguridad: usuario responsable de revisar los hallazgos.
- Sistema: componente automático que ejecuta los escaneos.

### Perfiles

**Usuario desarrollador:** requiere verificar código y configuraciones de seguridad.

**Usuario auditor:** revisa reportes de cumplimiento y riesgos identificados.

## 7. Modelo conceptual

El modelo conceptual incluye las siguientes entidades:

- `Scan`: representa el análisis solicitado, con tipo, valor objetivo, estado, puntaje y fecha.
- `Finding`: representa cada hallazgo de seguridad asociado a un escaneo.

Las relaciones son:
- Un `Scan` tiene múltiples `Finding`.
- Cada `Finding` pertenece a un solo `Scan`.

## 8. Casos de uso

### Caso de uso 1: Analizar código

- Actor: Usuario
- Descripción: El usuario envía texto de código para el análisis.
- Resultado: Se detectan patrones riesgosos y se genera un reporte.

### Caso de uso 2: Analizar URL

- Actor: Usuario
- Descripción: El usuario envía una URL para verificar cabeceras HTTP.
- Resultado: Se identifican cabeceras faltantes y se genera un reporte.

### Caso de uso 3: Ver reporte

- Actor: Usuario
- Descripción: Consulta el resultado de un escaneo previo.
- Resultado: Muestra puntaje y detalles de hallazgos.

## 9. Conclusiones

El Sistema Verificador de Cumplimiento OWASP establece un conjunto de requisitos claros para una herramienta de revisión temprana de seguridad. El proyecto se ajusta a los objetivos del curso y a la necesidad de detectar riesgos básicos de OWASP en código y aplicaciones web.

## 10. Bibliografía

- OWASP Foundation. OWASP Top Ten.
- Documentación de FastAPI.
- Documentación de SQLAlchemy.
- Documentación de Python.
