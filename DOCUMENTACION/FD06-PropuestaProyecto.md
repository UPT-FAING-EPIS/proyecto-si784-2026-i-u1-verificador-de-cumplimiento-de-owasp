# FD06 - Propuesta de Proyecto

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

## Tabla de contenido

1. Resumen ejecutivo
2. Propuesta narrativa
3. Planteamiento del problema
4. Justificación del proyecto
5. Objetivo general
6. Beneficios
7. Alcance
8. Requerimientos del sistema
9. Restricciones
10. Supuestos
11. Resultados esperados
12. Metodología de implementación
13. Actores clave
14. Papeles y responsabilidades
15. Plan de monitoreo y evaluación
16. Cronograma
17. Hitos de entregables
18. Presupuesto
19. Análisis de factibilidad
20. Evaluación financiera
21. Anexo de requerimientos

## 1. Resumen ejecutivo

- Nombre del proyecto: Sistema Verificador de Cumplimiento OWASP.
- Propósito: analizar código y URLs para detectar vulnerabilidades básicas del OWASP Top 10.
- Resultados esperados: herramienta web y API que produzca reportes de seguridad y almacenamiento de escaneos.
- Población objetivo: estudiantes, desarrolladores y evaluadores de calidad de software.
- Monto de inversión: S/. 0 (uso de software libre y recursos académicos).
- Duración: 1 mes.

## 2. Propuesta narrativa

El proyecto construye una herramienta de análisis de seguridad de software. El sistema permite ingresar código o una URL y obtiene un reporte automático de hallazgos de riesgo.

## 3. Planteamiento del problema

No existe una solución académica simple en el equipo para revisar rápidamente patrones de riesgo OWASP en código y configuraciones web.

## 4. Justificación del proyecto

La propuesta ayuda a mejorar la calidad del software, a educar en prácticas de desarrollo seguro y a preparar a los estudiantes para análisis de seguridad.

## 5. Objetivo general

Diseñar e implementar un sistema de análisis automático de seguridad OWASP para código y páginas web.

## 6. Beneficios

- Mejora de la seguridad temprana en desarrollos.
- Reducción de riesgos por exposición de secretos.
- Apoyo al aprendizaje de buenas prácticas OWASP.

## 7. Alcance

Incluye análisis de código y URLs, generación de reportes, almacenamiento de resultados y una interfaz web simple.

## 8. Requerimientos del sistema

- El sistema debe analizar texto de código en busca de secretos y funciones peligrosas.
- El sistema debe analizar URLs y verificar cabeceras de seguridad.
- El sistema debe almacenar escaneos y hallazgos.
- El sistema debe ofrecer API REST.
- El sistema debe mostrar reportes HTML.

## 9. Restricciones

- El análisis de URLs se limita a HTTP/HTTPS.
- El sistema no realiza análisis de red ni pruebas de penetración.
- La base de datos se conecta por variable de entorno.

## 10. Supuestos

- Los usuarios cuentan con acceso a un servidor Python.
- Las URLs de análisis son accesibles desde el entorno donde corre el servicio.
- La comunicación con la base de datos es estable.

## 11. Resultados esperados

- Prototipo funcional en FastAPI.
- Reportes de seguridad con puntaje y hallazgos.
- Anexos documentales de la factibilidad, visión, SRS y SAD.

## 12. Metodología de implementación

Se usará un enfoque incremental: análisis de requisitos, diseño arquitectónico, desarrollo de servicios y pruebas unitarias.

## 13. Actores clave

- Desarrolladores del proyecto.
- Docente asesor.
- Usuarios evaluadores.

## 14. Papeles y responsabilidades

- Integrantes: diseño, implementación y documentación.
- Docente: validación y revisión.

## 15. Plan de monitoreo y evaluación

- Revisar avances semanales.
- Validar funcionalidades con pruebas de análisis de código y URL.
- Evaluar cumplimiento de requisitos mediante ejecución de casos de uso.

## 16. Cronograma

| Semana | Actividad |
|---|---|
| 1 | Revisión de requisitos, investigación OWASP |
| 2 | Diseño arquitectónico y modelo de datos |
| 3 | Implementación de análisis y servicios |
| 4 | Integración web, pruebas y documentación |

## 17. Hitos de entregables

- Hito 1: Documento de visión y factibilidad.
- Hito 2: Documento de especificación de requisitos.
- Hito 3: Documento de arquitectura y prototipo inicial.
- Hito 4: Informe final y demostración.

## 18. Presupuesto

- Recursos tecnológicos: software libre.
- Tiempo de desarrollo: 4 semanas por el equipo.
- Inversión monetaria: mínima a nula.

## 19. Análisis de factibilidad

El proyecto es viable desde el punto de vista técnico, económico y operativo. Utiliza tecnología abierta y se ajusta al contexto académico.

## 20. Evaluación financiera

No se requiere inversión significativa. Se asume uso de infraestructura existente y herramientas de código abierto.

## 21. Anexo de requerimientos

Ver documento FD03 - Informe de Especificación de Requerimientos de Software.
