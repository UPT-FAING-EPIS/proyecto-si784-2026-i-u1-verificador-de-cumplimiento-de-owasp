#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
from mcp.server.fastmcp import FastMCP

# Agregar el directorio padre (raíz del proyecto) a sys.path para importar cli.py
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)

# Importar la función scan_file de cli.py en la raíz
from cli import scan_file

# Inicializar FastMCP
mcp = FastMCP("OWASP-Verificator")

@mcp.tool()
def scan_file_owasp(filepath: str, lang: str = "es") -> str:
    """
    Analiza un archivo de código fuente para identificar vulnerabilidades del OWASP Top 10.
    
    :param filepath: La ruta absoluta o relativa al archivo que se desea escanear.
    :param lang: Idioma de los resultados. Puede ser 'es' (español, por defecto) o 'en' (inglés).
    :return: Una cadena en formato JSON con la lista de hallazgos de seguridad encontrados.
    """
    # Resolver ruta absoluta (si es relativa, la resuelve respecto al raíz del proyecto)
    if not os.path.isabs(filepath):
        abs_path = os.path.abspath(os.path.join(project_root, filepath))
    else:
        abs_path = filepath

    if not os.path.exists(abs_path):
        import json
        msg = f"Archivo no encontrado: {filepath}" if lang == "es" else f"File not found: {filepath}"
        return json.dumps({"error": msg}, indent=2, ensure_ascii=False)
        
    try:
        results = scan_file(abs_path, lang=lang)
        import json
        return json.dumps(results, indent=2, ensure_ascii=False)
    except Exception as e:
        import json
        return json.dumps({"error": f"Error inesperado al escanear: {str(e)}"}, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    mcp.run()
