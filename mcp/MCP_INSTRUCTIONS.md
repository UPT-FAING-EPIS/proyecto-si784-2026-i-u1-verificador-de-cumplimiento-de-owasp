# Guía de Uso del Servidor MCP de OWASP Verificator

Esta guía explica cómo registrar y habilitar el servidor local MCP de **OWASP Verificator** para que cualquier asistente de IA compatible (como Cursor, Claude Desktop, Cline o Roo-Code) pueda utilizar el analizador estático como una herramienta nativa (`tool-calling`).

---

## Requisitos Previos

Asegúrate de tener instalado el paquete `mcp` en tu entorno virtual:
```bash
pip install mcp
# O usando el entorno virtual del proyecto:
.venv\Scripts\pip install mcp
```

---

## 1. Configuración en Cursor IDE

1. Abre Cursor y dirígete a: **Settings** -> **Features** -> **MCP**.
2. Haz clic en el botón **+ Add New MCP Server**.
3. Rellena los campos con los siguientes valores:
   - **Name**: `OWASP-Verificator`
   - **Type**: `command`
   - **Command**:
     ```bash
     c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp/.venv/Scripts/python "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp/mcp/mcp_server.py"
     ```
     *(Nota: Usar la ruta del `python` del entorno virtual `.venv` asegura que todas las dependencias estén disponibles).*
4. Haz clic en **Save**. ¡Listo! Verás un círculo verde indicando que está activo y listará la herramienta `scan_file_owasp`.

---

## 2. Configuración en Claude Desktop

1. Abre tu explorador de archivos y ve al archivo de configuración de Claude:
   - Presiona `Win + R`, escribe `%APPDATA%\Claude` y abre el archivo `claude_desktop_config.json`.
2. Reemplaza o agrega la configuración de servidores MCP en la sección `mcpServers`:
   ```json
   {
     "mcpServers": {
       "owasp-verificator": {
         "command": "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp/.venv/Scripts/python.exe",
         "args": [
           "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp/mcp/mcp_server.py"
         ],
         "cwd": "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp"
       }
     }
   }
   ```
3. Guarda el archivo y reinicia Claude Desktop. Verás el icono del enchufe en el chat que indica que la herramienta de escaneo de seguridad está activa.

---

## 3. Configuración en Cline / Roo-Code (Extensiones de VS Code)

1. En la pestaña de la extensión, haz clic en el icono de **Ajustes** (o en la sección de MCP).
2. Haz clic en **Configure MCP Servers** (esto abrirá el archivo `cline_mcp_settings.json` o `roocode_mcp_settings.json`).
3. Agrega la configuración del servidor en el objeto JSON principal:
   ```json
   {
     "mcpServers": {
       "owasp-verificator": {
         "command": "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp/.venv/Scripts/python.exe",
         "args": [
           "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp/mcp/mcp_server.py"
         ],
         "cwd": "c:/Users/Gerardo/Documents/GitHub/proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp"
       }
     }
   }
   ```
4. Guarda el archivo y la extensión cargará automáticamente la herramienta.

---

## ¿Cómo pedirle a la IA que use la herramienta?

Una vez conectado el servidor MCP, puedes hablarle a tu IA en el chat normalmente:
- *"Escanea el archivo app/main.py con el analizador OWASP"*
- *"Verifica la seguridad de este archivo usando la herramienta de escaneo local"*

La IA reconocerá que tiene la herramienta `scan_file_owasp` y la llamará automáticamente sin necesidad de que tú copies el código o ejecutes comandos manualmente.
