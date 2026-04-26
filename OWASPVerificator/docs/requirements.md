# Requisitos del Sistema

## 1. Objetivo
Construir un verificador de cumplimiento OWASP simple pero completo, capaz de analizar código o una URL, generar reportes y mostrar hallazgos en una interfaz web ligera.

## 2. Alcance
El sistema cubrirá el MVP con:
- análisis de texto de código
- análisis básico de URL
- historial de escaneos y hallazgos en memoria
- panel web para ejecutar análisis y revisar resultados
- reglas iniciales alineadas con OWASP Top 10

## 3. Requisitos funcionales

### RF-01. Acceder al sistema
- El sistema deberá permitir acceso al panel web desde un navegador.
- En el MVP no se exige inicio de sesión; el acceso será libre en red controlada.

### RF-02. Registrar análisis
- El sistema deberá permitir crear un análisis indicando el tipo de objetivo: código o URL.
- El sistema deberá guardar cada análisis con fecha, tipo, valor analizado, estado y puntaje.

### RF-03. Analizar código
- El sistema deberá aceptar texto de código pegado en un formulario web o enviado por la API.
- El sistema deberá detectar patrones básicos asociados a riesgos OWASP, como secretos expuestos, funciones peligrosas y validación de entrada insuficiente.

### RF-04. Analizar URL
- El sistema deberá analizar una URL usando solicitudes HTTP o HTTPS.
- El sistema deberá revisar cabeceras de seguridad mínimas y marcar ausencias relevantes.

### RF-05. Generar hallazgos
- El sistema deberá generar uno o más hallazgos por análisis cuando detecte riesgo.
- Cada hallazgo deberá incluir identificador de regla, título, severidad, descripción y evidencia.

### RF-06. Calcular puntaje
- El sistema deberá asignar un puntaje de cumplimiento a cada análisis.
- El puntaje deberá disminuir según la severidad y cantidad de hallazgos.

### RF-07. Mantener historial de análisis
- El sistema deberá conservar escaneos y hallazgos en memoria durante la ejecución del servicio.
- El sistema deberá permitir consultar el historial de análisis realizados.

### RF-08. Mostrar panel web
- El sistema deberá mostrar un dashboard con los últimos análisis.
- El sistema deberá mostrar el detalle de cada reporte con sus hallazgos.

### RF-09. Exponer API REST
- El sistema deberá exponer una API para ejecutar análisis y obtener reportes.
- La API deberá permitir integración futura con CI/CD y otras herramientas.

### RF-10. Agregar reglas nuevas
- El sistema deberá permitir incorporar nuevas reglas de verificación OWASP sin cambiar la arquitectura principal.
- Las reglas deberán poder ampliarse con nuevos patrones, nuevas validaciones o integración con herramientas externas.
- Ejemplo: agregar una nueva regla para detectar cabeceras HTTP faltantes, secretos expuestos o uso de funciones inseguras.

## 4. Requisitos no funcionales

### RNF-01. Simplicidad
- La solución deberá mantenerse simple de instalar, ejecutar y mantener.
- El stack principal será Python, FastAPI y HTML/CSS.

### RNF-02. Rendimiento
- El sistema deberá responder de forma aceptable para análisis pequeños y medianos.
- El análisis inicial deberá completar en pocos segundos en condiciones normales.

### RNF-03. Seguridad
- El sistema deberá evitar exponer credenciales en el código.
- El sistema deberá usar variables de entorno para la configuración sensible.
- El sistema deberá tratar la entrada del usuario como no confiable.

### RNF-04. Disponibilidad
- El sistema deberá poder ejecutarse localmente en desarrollo y en un servidor básico de despliegue.
- El servicio no deberá depender de componentes complejos para el MVP.

### RNF-05. Mantenibilidad
- El código deberá separarse en capas: rutas, servicios, modelos, plantillas y estilos.
- Las reglas OWASP deberán ubicarse en un módulo independiente.

### RNF-06. Escalabilidad funcional
- La arquitectura deberá permitir incorporar más reglas, más tipos de análisis y mejores integraciones sin rehacer el sistema.

### RNF-07. Usabilidad
- La interfaz deberá ser simple y clara.
- El usuario deberá poder iniciar un análisis y revisar resultados sin entrenamiento previo.

### RNF-08. Compatibilidad
- El sistema deberá funcionar en navegadores modernos.
- El backend deberá ejecutarse en entornos Windows y Linux sin dependencias de base de datos.

### RNF-09. Observabilidad
- El sistema deberá permitir identificar errores de análisis y fallos de conexión.
- Los errores relevantes deberán poder registrarse para diagnóstico.

### RNF-10. Portabilidad
- La solución deberá poder correr en Windows y en entornos Linux de despliegue.

## 5. Restricciones
- El frontend inicial será HTML con CSS puro, sin framework JavaScript pesado.
- El MVP no cubrirá certificación formal de cumplimiento OWASP; solo evaluación de alineación y hallazgos.

## 6. Criterios de aceptación del MVP
- Se puede ejecutar un análisis de código desde la web.
- Se puede ejecutar un análisis de URL desde la web.
- Los resultados quedan disponibles en memoria durante la ejecución del servicio.
- El dashboard muestra el historial de análisis.
- Cada reporte muestra hallazgos y puntaje.
