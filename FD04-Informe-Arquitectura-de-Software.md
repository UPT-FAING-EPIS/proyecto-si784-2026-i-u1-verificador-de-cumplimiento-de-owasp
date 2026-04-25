# FD04 - Informe de Arquitectura de Software

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
1.1 Propósito
1.2 Alcance
1.3 Definiciones, siglas y abreviaturas
1.4 Organización del documento
2. Objetivos y restricciones arquitectónicas
2.1 Requerimientos funcionales
2.2 Requerimientos no funcionales
3. Representación de la arquitectura del sistema
3.1 Vista de casos de uso
3.2 Vista lógica
3.3 Vista de implementación
3.4 Vista de procesos
3.5 Vista de despliegue
4. Atributos de calidad

## 1. Introducción

### 1.1 Propósito

El propósito de este documento es describir la arquitectura del Sistema Verificador de Cumplimiento OWASP utilizando un enfoque inspirado en el modelo 4+1. Se muestra cómo las decisiones arquitectónicas soportan los requisitos funcionales y de calidad.

### 1.2 Alcance

Este documento cubre las vistas relevantes del sistema: casos de uso, lógica, implementación, procesos y despliegue. Se describe la estructura de paquetes y las relaciones entre los componentes principales.

### 1.3 Definiciones, siglas y abreviaturas

- OWASP: Open Web Application Security Project.
- API: Interfaz de Programación de Aplicaciones.
- DB: Base de datos.
- MySQL: Sistema de gestión de bases de datos relacional.
- ORM: Mapeo Objeto-Relacional.
- HTTP: Protocolo de transferencia de hipertexto.

### 1.4 Organización del documento

El documento inicia con objetivos y restricciones, luego presenta la arquitectura en cinco vistas y concluye con atributos de calidad y escenarios.

## 2. Objetivos y restricciones arquitectónicas

### 2.1 Requerimientos funcionales

- El sistema debe recibir solicitudes de análisis por web y API.
- Debe ejecutar análisis de código y de URL.
- Debe guardar resultados en base de datos.
- Debe mostrar reportes con hallazgos y puntajes.

### 2.2 Requerimientos no funcionales

- Seguridad: validar entradas y manejar errores de red.
- Disponibilidad: mantener el servicio web operativo.
- Mantenibilidad: usar arquitectura modular y separación de responsabilidades.
- Escalabilidad: el diseño deberá permitir agregar nuevas reglas de análisis.
- Portabilidad: la configuración de base de datos y entornos debe ser variable.

### Restricciones

- El servicio se implementa en Python y FastAPI.
- La base de datos se conecta mediante SQLAlchemy.
- El análisis de URL usa `requests` y solo HTTP/HTTPS.
- El proyecto se despliega en un solo nodo con base de datos local.

## 3. Representación de la arquitectura del sistema

### 3.1 Vista de casos de uso

Los casos de uso principales son:
- Analizar código.
- Analizar URL.
- Consultar reporte de escaneo.

#### Diagrama de casos de uso (texto)

Actores: Usuario.
Casos: Ingresar objetivo, Ejecutar análisis, Ver reporte.

### 3.2 Vista lógica

#### Diagrama de paquetes

El sistema se organiza en los siguientes paquetes principales:
- `app.routers`: define las rutas web y API.
- `app.services`: contiene la lógica del análisis y reglas.
- `app.models`: define el modelo de datos para scans y findings.
- `app.db`: gestiona la conexión y sesiones de la base de datos.
- `app.templates`: presenta las páginas HTML.

#### Diagrama de secuencia

1. El usuario envía un formulario de análisis o una solicitud API.
2. `app.routers.analysis` recibe la petición y llama a `execute_scan`.
3. `execute_scan` determina el tipo y llama a `scan_code` o `scan_url`.
4. El servicio de análisis produce hallazgos.
5. Se calcula un puntaje con `calculate_score`.
6. Se guarda el `Scan` y cada `Finding` en la base de datos.
7. Se devuelve el resultado y se redirige a un reporte.

### 3.3 Vista de implementación

#### Diagrama de componentes

- FastAPI: servidor web.
- Jinja2: renderizado de plantillas HTML.
- SQLAlchemy: acceso a la base de datos.
- `requests`: acceso HTTP para análisis de URL.

#### Paquetes clave

- `main.py`: arranca la aplicación y monta rutas.
- `analysis.py`: maneja entradas de análisis.
- `reports.py`: expone vistas y endpoints de reportes.
- `scanner.py`: implementa reglas de detección.
- `analysis_service.py`: orquesta el proceso de escaneo.

### 3.4 Vista de procesos

#### Diagrama de actividad de proceso

- Entrada de solicitud.
- Validación de tipo (`code` o `url`).
- Ejecución de regla de escaneo.
- Almacenamiento de resultados.
- Retorno de reporte.

El proceso gestiona solicitudes HTTP de forma síncrona dentro de FastAPI.

### 3.5 Vista de despliegue

El despliegue previsto es:
- Servidor de aplicaciones Python con FastAPI.
- Base de datos MySQL/compatible.
- Carpeta `app/static` para recursos estáticos.

#### Topología física

- Nodo único: aplicación web + conexión a DB remota/local.
- Comunicación interna: FastAPI <-> MySQL.

## 4. Atributos de calidad del software

### Escenario de funcionalidad

El usuario envía código o URL y obtiene un reporte con hallazgos.

### Escenario de usabilidad

El usuario interactúa con un formulario web simple y comprende claramente el tipo de análisis.

### Escenario de confiabilidad

El sistema maneja entradas inválidas y errores de red de forma controlada.

### Escenario de rendimiento

Los análisis se procesan en tiempos razonables, con llamadas HTTP limitadas a 15 segundos.

### Escenario de mantenibilidad

La arquitectura modular permite agregar nuevas reglas de análisis sin modificar el router principal.

### Escenario de seguridad

Se validan entradas y se evita el análisis de URLs no permitidas fuera de HTTP/HTTPS.

### Escenario de disponibilidad

El servicio puede mantenerse disponible siempre que la base de datos y la red HTTP estén operativas.

## Bibliografía

- OWASP Top Ten.
- Documentación oficial de FastAPI.
- Documentación oficial de SQLAlchemy.
- Documentación oficial de Requests.
