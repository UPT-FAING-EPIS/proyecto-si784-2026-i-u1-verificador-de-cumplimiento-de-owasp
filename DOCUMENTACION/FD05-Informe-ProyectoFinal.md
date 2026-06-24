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

---

## CONTROL DE VERSIONES

| Versión | Hecha por | Revisada por | Aprobada por | Fecha | Motivo |
|---|---|---|---|---|---|
| 1.0 | Equipo | Profesor | - | 25/04/2026 | Versión final inicial |
| 2.0 | Equipo | Profesor | - | 24/06/2026 | Integración de la Extensión de VS Code, el motor de CVEs, el escáner de GitHub y la base de datos local SQLite3 |

---

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

---

## 1. Antecedentes

Las aplicaciones modernas requieren controles estrictos de seguridad para prevenir vulnerabilidades listadas en el **OWASP Top 10**. La detección temprana en la etapa de codificación ahorra costos de remediación en producción y disminuye la superficie de ataque.

---

## 2. Planteamiento del problema

Los desarrolladores de software carecen de herramientas integradas y ágiles que les adviertan en tiempo real mientras escriben código sobre malas prácticas de seguridad (secretos expuestos, dependencias desactualizadas o funciones vulnerables), lo que deriva en código de baja calidad expuesto a ataques cibernéticos.

---

## 3. Justificación

El **Ecosistema Verificador de Cumplimiento OWASP** proporciona una plataforma completa que evalúa código, repositorios y cabeceras de servidor en producción. Mediante su extensión para VS Code, se integra directamente en el ciclo de vida del desarrollo de software (DevSecOps), facilitando la corrección inmediata.

---

## 4. Alcance

El alcance final del proyecto incluye:
- **Análisis estático de código:** Detección de patrones de riesgo del OWASP Top 10.
- **Análisis de dependencias (CVE):** Identificación de librerías con vulnerabilidades conocidas y análisis del archivo `requirements.txt`.
- **Análisis de URLs de producción:** Evaluación de cabeceras HTTP de protección y divulgación de información en servidores web.
- **Escaneo de GitHub:** Análisis directo de repositorios mediante su URL y descarga automatizada.
- **Persistencia local:** Almacenamiento de auditorías históricas y hallazgos en una base de datos local SQLite3.
- **Extensión de VS Code:** Subrayados de error en el editor en tiempo real, panel interactivo y soporte de remediación con Copilot/Gemini.

---

## 5. Objetivos

### Objetivo general
Implementar un ecosistema de herramientas ágiles basadas en FastAPI y VS Code para verificar de manera automática el cumplimiento de las directrices OWASP Top 10.

### Objetivos específicos
- Desarrollar un motor de escaneo extensible con reglas regex para múltiples lenguajes.
- Proveer un análisis de dependencias basado en vulnerabilidades conocidas (CVEs).
- Desarrollar una extensión interactiva para VS Code con diagnósticos en caliente y remediación asistida por Inteligencia Artificial.
- Proveer almacenamiento histórico transaccional de los análisis en SQLite3 de forma ligera.

---

## 6. Marco teórico

- **OWASP Top 10:** Estándar global sobre las vulnerabilidades web más críticas.
- **FastAPI:** Framework de alto rendimiento en Python para construir APIs y vistas.
- **VS Code Extension API:** Entorno para extender las capacidades del editor e interactuar con el código del desarrollador.
- **SQLite3:** Motor de base de datos relacional rápido que se almacena en un archivo local sin requerir servicios externos.

---

## 7. Desarrollo de la solución

### Arquitectura general
El sistema se organiza bajo una arquitectura modular limpia en el backend (FastAPI + Servicios + SQLite3 de persistencia plana a través de [store.py](file:///c:/Users/Equipo/Downloads/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp-main/app/store.py)) y una extensión cliente JavaScript Vanilla en VS Code.

### Mecánica de análisis
- El usuario ingresa un objetivo (código, URL de servidor o URL de repositorio GitHub).
- El sistema procesa la solicitud mediante expresiones regulares (`scanner.py`) y análisis de dependencias (`cve_analyzer.py`).
- Se calcula un score restando penalizaciones según severidad (High: 30, Medium: 15, Low: 5) y se guarda el historial.

### Resultados
Cada escaneo genera un registro persistente en el archivo `data/scans.sqlite3`, guardando los hallazgos en formato JSON.

---

## 8. Análisis de factibilidad

- **Factibilidad técnica:** El proyecto es completamente viable, integrando librerías estándar en Python y el entorno autocontenido de extensiones de VS Code.
- **Factibilidad económica:** El costo es cero, empleando tecnologías libres y licencias académicas.
- **Factibilidad operativa:** Es altamente operable, instalándose la extensión con un archivo `.vsix` y requiriendo únicamente una instalación básica de Python en el backend.

---

## 9. Tecnología de desarrollo

- **Backend:** Python 3, FastAPI, Jinja2, Requests, SQLite3, Pytest.
- **IDE Cliente:** JavaScript Vanilla (VS Code Extension API), CSS3 (Efectos Glassmorphism, HSL), HTML5 Semántico.

---

## 10. Metodología de implementación

Se utilizó una metodología incremental con ciclos cortos de entrega: modelado de requisitos, desarrollo del motor de escaneo, diseño del almacén local, integración con VS Code API, pruebas de regresión y documentación final.

---

## 11. Cronograma

El proyecto se dividió en 4 semanas de trabajo intensivo abarcando desde la recolección de requisitos iniciales hasta las fases de empaquetado de la extensión `.vsix` e implementación de pruebas automáticas.

---

## 12. Presupuesto

La inversión se centró exclusivamente en horas de desarrollo académico de los estudiantes de ingeniería de sistemas, sin costos asociados de licencias o servidores comerciales.

---

## 13. Conclusiones

Se logró implementar con éxito un prototipo completo de verificación OWASP. La integración de la extensión de VS Code dota al desarrollador de retroalimentación inmediata, mejorando la calidad del código producido desde el primer momento.

---

## 14. Recomendaciones

- Extender la base de datos de firmas CVE locales con mayor volumen de paquetes.
- Añadir integración continua (CI/CD) para automatizar el análisis con herramientas como Semgrep.
- Aprovisionar encriptación en los datos JSON confidenciales guardados en la base de datos local SQLite.

---

## 15. Bibliografía

- OWASP Foundation. OWASP Top Ten.
- Microsoft VS Code Extension Documentation.
- FastAPI Reference Guide.

---

## 16. Anexos

- Anexo 01: Informe de Factibilidad (FD01)
- Anexo 02: Documento de Visión (FD02)
- Anexo 03: Documento SRS (FD03)
- Anexo 04: Documento SAD (FD04)
- Anexo 05: Diccionario de Datos (FD07)
- Anexo 06: Estándares de Programación (FD08)
