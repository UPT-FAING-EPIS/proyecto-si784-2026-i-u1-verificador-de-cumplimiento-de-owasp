# OWASP Verificator

Proyecto base en Python para evaluar cumplimiento OWASP de forma simple y ampliable.

## Documentación
- Requisitos funcionales y no funcionales: [docs/requirements.md](docs/requirements.md)
- Roadmap del proyecto: [docs/roadmap.md](docs/roadmap.md)

## Stack
- FastAPI
- Uvicorn / Gunicorn
- Jinja2
- CSS puro

## Funcionalidad inicial
- Dashboard de ejecuciones
- Análisis por URL
- Análisis por texto de código
- Historial en memoria de scans y hallazgos
- Reglas iniciales para OWASP Top 10
- API REST para análisis y reportes

## Endpoints API
- `POST /analyze/api` para ejecutar análisis con JSON
- `GET /reports/api` para listar reportes
- `GET /reports/api/{scan_id}` para detalle de un reporte
- `GET /health` para estado del servicio

## Requisitos
- Python 3.11+

## Configuración
1. Copia `.env.example` a `.env`
2. Instala dependencias:

```bash
pip install -r requirements.txt
```

3. Ejecuta la app:

```bash
uvicorn app.main:app --reload
```

## Cómo probar que funciona

### 1. Prueba rápida del motor de análisis
Ejecuta un análisis de texto con una muestra que contenga patrones inseguros. Si el motor funciona, debe devolver hallazgos y un puntaje menor a 100.

### 2. Prueba de la interfaz web
1. Abre `http://127.0.0.1:8000`
2. Entra a la pantalla de análisis
3. Pega un fragmento de código con `password =` o `eval(`
4. Envía el formulario
5. Verifica que te redirige a un reporte con hallazgos

### 3. Historial temporal (sin base de datos)
1. Ejecuta más de un análisis desde la web
2. Vuelve al dashboard
3. Verifica que aparecen los análisis recientes
4. Reinicia la app y confirma que el historial se limpia (almacenamiento en memoria)

### 4. Resultado esperado
- El dashboard muestra el análisis realizado
- El reporte muestra hallazgos y score
- El historial existe mientras la app esté en ejecución

### 5. Pruebas automáticas
Ejecuta:

```bash
python -m pytest -q
```

Resultado actual esperado: `4 passed`

## Variables de entorno
- `APP_TITLE`: nombre de la aplicación
- `APP_ENV`: entorno de ejecución

Ejemplo:

```env
APP_TITLE=OWASP Verificator
APP_ENV=development
```

## Despliegue en Azure con GitHub Actions

El repositorio incluye workflow en `.github/workflows/azure-webapp.yml` para desplegar en Azure App Service cada vez que haces push a `main`.

### 1. Crear recursos en Azure
1. Crea un Web App (Linux, Python 3.11)
2. En el Web App configura Startup Command:

```bash
gunicorn -w 2 -k uvicorn.workers.UvicornWorker app.main:app
```

### 2. Configurar secretos en GitHub
En el repositorio, agrega estos secrets:
- `AZURE_WEBAPP_NAME`: nombre del Web App en Azure
- `AZURE_WEBAPP_PUBLISH_PROFILE`: contenido del Publish Profile descargado desde Azure

### 3. Ejecutar despliegue
1. Haz push a la rama `main`
2. Revisa la ejecución del workflow en la pestaña Actions
3. Verifica la app desplegada en la URL del Web App
