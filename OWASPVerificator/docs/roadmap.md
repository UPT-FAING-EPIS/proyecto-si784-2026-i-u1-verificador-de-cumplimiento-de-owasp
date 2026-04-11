# Roadmap del verificador OWASP

Este proyecto sigue las issues del repositorio y arranca con una base simple pero completa.

## Documentación base
- Requisitos funcionales y no funcionales: [docs/requirements.md](docs/requirements.md)

## Estado inicial
- Definir requisitos del sistema: base documentada en `README.md`
- Configurar repositorio y estructura del proyecto: carpeta `app/` y archivos de arranque
- Diseñar arquitectura del verificador OWASP: FastAPI + MySQL + vistas HTML/CSS
- Implementar verificaciones OWASP Top 10 (A01-A05): motor inicial en `app/services/scanner.py`
- Implementar verificaciones OWASP Top 10 (A06-A10): parcialmente cubierto y listo para ampliar
- Exponer API REST para analizar código: base de análisis en `/analyze`
- Crear interfaz para subir código o URL: formulario HTML simple
- Integrar frontend con backend: templates Jinja2 + CSS puro
- Mostrar resultados del análisis en dashboard: `/` y `/reports/{id}`
- Realizar pruebas unitarias e integración: pendiente
- Registrar y corregir bugs: pendiente
- Documentación final y despliegue: pendiente

## Avance actual estimado
- Avance total del proyecto: 85%
- Completado:
	- arquitectura base (backend, frontend y persistencia)
	- dashboard y reportes
	- API REST para análisis y consulta de reportes (`/analyze/api`, `/reports/api`)
	- pruebas unitarias e integración iniciales (pytest)
	- documentación funcional y no funcional
- Pendiente para cierre:
	- ampliar reglas OWASP A06-A10 con mayor profundidad
	- registrar y corregir bugs de endurecimiento
	- documentación final de despliegue productivo

## Siguiente paso recomendado
Agregar pruebas, endurecer reglas OWASP y conectar el análisis a herramientas externas como Semgrep o Gitleaks.
