---
name: owasp-verificator
description: >-
  Analiza archivos y espacios de trabajo para verificar el cumplimiento del OWASP Top 10 utilizando el analizador estático CLI nativo del proyecto.
---

# OWASP Verificator

## Overview
Esta habilidad permite a un agente de IA analizar de forma estática archivos de código fuente y directorios en el espacio de trabajo actual, identificando vulnerabilidades asociadas al OWASP Top 10 (exposición de secretos, inyección de código, logging insuficiente, etc.).

## Dependencies
Ninguna.

## Quick Start
Para escanear un archivo de forma individual en español:
```bash
python cli.py <ruta_del_archivo> --lang es
```

## Utility Scripts (if CLI-based)
La herramienta CLI se ejecuta en la raíz del repositorio usando Python:

### Escaneo de Archivo Individual
```bash
python cli.py <ruta_archivo> --lang <es|en>
```

**Ejemplo:**
```bash
python cli.py app/main.py --lang es
```

### Parámetros
* `ruta_archivo`: La ruta absoluta o relativa al archivo que se desea analizar.
* `--lang`: Idioma de los resultados. Soporta `es` (Español, por defecto) y `en` (Inglés).

---

## Workflow
Cuando el usuario solicita analizar la seguridad del código o buscar vulnerabilidades en su proyecto, el agente debe seguir estos pasos:

1. **Identificación de Archivos:**
   Buscar archivos de código fuente en el espacio de trabajo actual. Las extensiones soportadas son: `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.html`, `.css`, `.json`, `.java`, `.php`, `.go`, `.cs`, `.cshtml`, `.aspx`, `.ascx`, `.asmx`, `.ashx`, `.master`, `.kt`, `.swift`, `.scala`, `.lua`, `.pl`, `.yaml`, `.yml`.
   
   *Importante: Excluir explícitamente directorios de dependencias o cachés como `node_modules`, `.venv`, `venv`, `env`, `.git`, `.pytest_cache`, `__pycache__`, `dist` o `build`.*

2. **Ejecución del Escaneo:**
   Para cada archivo relevante encontrado, ejecutar el comando:
   ```bash
   python cli.py <ruta_archivo> --lang es
   ```

3. **Interpretación de Resultados:**
   El comando imprimirá un JSON con la lista de hallazgos. Cada objeto contiene:
   * `rule_id`: ID de la regla OWASP (ej. `OWASP-A02`).
   * `title`: Título de la vulnerabilidad.
   * `severity`: Severidad (`high`, `medium`, `low`).
   * `description`: Explicación detallada de la vulnerabilidad.
   * `evidence`: La línea o segmento exacto donde se detectó el problema.
   * `line`: Número de línea (base 1).
   * `character`: Posición del carácter inicial.
   * `remediation`: Pasos específicos de remediación sugeridos.

4. **Reporte en el Chat:**
   Presentar los resultados al usuario final en una tabla estructurada de Markdown con el siguiente formato:
   
   | Archivo | Línea | Regla | Severidad | Descripción | Evidencia |
   | :--- | :--- | :--- | :--- | :--- | :--- |
   | `app/main.py` | 12 | `OWASP-A02` | 🔴 Crítico | Exposición de Secretos | `password = "123"` |

   Adicionalmente, detallar debajo de la tabla la **Remediación Sugerida** para cada hallazgo y ofrecer soluciones de código específicas.

---

## Common Mistakes
* **Olvidar excluir carpetas pesadas:** Intentar buscar o escanear archivos dentro de `node_modules` o `.venv`, lo cual causará demoras graves de rendimiento en el agente.
* **Ignorar el formato JSON:** Intentar analizar a mano expresiones regulares en el código del usuario en lugar de delegar el escaneo a `cli.py`, que ya tiene optimizadas todas las reglas de concordancia.
