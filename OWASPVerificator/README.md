# OWASP Verificator

Proyecto base en Python para evaluar cumplimiento OWASP de forma simple y ampliable.

## Documentación
- Requisitos funcionales y no funcionales: [docs/requirements.md](docs/requirements.md)
- Roadmap del proyecto: [docs/roadmap.md](docs/roadmap.md)

## Stack
- FastAPI
- SQLAlchemy
- MySQL
- Jinja2
- CSS puro

## Funcionalidad inicial
- Dashboard de ejecuciones
- Análisis por URL
- Análisis por texto de código
- Persistencia de scans y hallazgos en MySQL
- Reglas iniciales para OWASP Top 10
- API REST para análisis y reportes

## Endpoints API
- `POST /analyze/api` para ejecutar análisis con JSON
- `GET /reports/api` para listar reportes
- `GET /reports/api/{scan_id}` para detalle de un reporte
- `GET /health` para estado del servicio

## Requisitos
- Python 3.11+
- MySQL accesible desde Heidi o cualquier cliente MySQL

## Configuración
1. Copia `.env.example` a `.env`
2. Ajusta credenciales de MySQL
3. Instala dependencias:

```bash
pip install -r requirements.txt
```

4. Ejecuta la app:

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

### 3. Prueba de persistencia en MySQL
1. Crea la base de datos `owasp_verificator`
2. Ejecuta un análisis desde la web
3. Revisa en MySQL las tablas `scans` y `findings`
4. Verifica que el análisis quedó guardado

### 4. Resultado esperado
- El dashboard muestra el análisis realizado
- El reporte muestra hallazgos y score
- La base de datos guarda el historial

### 5. Pruebas automáticas
Ejecuta:

```bash
python -m pytest -q
```

Resultado actual esperado: `4 passed`

## Variables de entorno
- `DATABASE_URL`: cadena SQLAlchemy para MySQL
- `APP_TITLE`: nombre de la aplicación
- `APP_ENV`: entorno de ejecución

Ejemplo:

```env
DATABASE_URL=mysql+pymysql://root:password@127.0.0.1:3306/owasp_verificator
APP_TITLE=OWASP Verificator
APP_ENV=development
```
