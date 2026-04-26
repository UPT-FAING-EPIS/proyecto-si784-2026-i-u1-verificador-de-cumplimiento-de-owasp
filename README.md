[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/MQUb8mG3)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=23320843)

# Sistema Verificador de Cumplimiento OWASP

Este repositorio contiene el proyecto académico del curso *Calidad y Pruebas de Software* para la Universidad Privada de Tacna, desarrollado como un verificador de cumplimiento básico basado en OWASP.

## Contenido del repositorio

- `FD01-Informe-Factibilidad.md`: Informe de factibilidad del proyecto.
- `FD02-Informe-Vision .md`: Documento de visión del proyecto.
- `FD03-Informe-Especificacion-Requerimientos.md`: Documento de especificación de requerimientos (SRS).
- `FD04-Informe-Arquitectura-de-Software.md`: Documento de arquitectura de software (SAD).
- `FD05-Informe-ProyectoFinal.md`: Informe final del proyecto.
- `FD06-PropuestaProyecto.md`: Propuesta de proyecto.
- `OWASPVerificator/`: Aplicación web desarrollada en FastAPI para análisis básico de código y URLs.

## Descripción del proyecto

El sistema permite analizar:
- Código fuente en busca de patrones de riesgo comunes (ej.: secretos expuestos, uso de `eval`, validación de entrada insuficiente).
- URLs para identificar cabeceras de seguridad HTTP faltantes.

Los resultados se guardan en una base de datos y se muestran en reportes con hallazgos y puntaje de seguridad.

## Tecnologías usadas

- Python 3
- FastAPI
- SQLAlchemy
- Requests
- Jinja2
- MySQL o base de datos compatible

## Cómo ejecutar la aplicación

1. Instalar dependencias en el directorio `OWASPVerificator`:
   ```bash
   cd OWASPVerificator
   pip install -r requirements.txt
   ```
2. Configurar la variable de entorno `DATABASE_URL` si se usa una base de datos distinta a la predeterminada.
3. Ejecutar la aplicación:
   ```bash
   uvicorn app.main:app --reload
   ```
4. Abrir el navegador en `http://127.0.0.1:8000/analyze`.

## Notas

La aplicación es un prototipo académico que se puede extender con nuevas reglas OWASP y mejoras en el análisis.
