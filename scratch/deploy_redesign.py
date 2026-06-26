import paramiko
import os
import time

host = '38.250.116.71'
user = 'root'
passwd = 'upt2026'

BASE_LOCAL = r'c:\Users\Gerardo\Documents\GitHub\proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp'
REMOTE_BASE = '/opt/owasp-verificador'

FILES = [
    # CSS
    (r'app\static\css\styles.css',          f'{REMOTE_BASE}/app/static/css/styles.css'),
    (r'app\static\css\analyze.css',         f'{REMOTE_BASE}/app/static/css/analyze.css'),
    (r'app\static\css\api_tutorial.css',    f'{REMOTE_BASE}/app/static/css/api_tutorial.css'),
    (r'app\static\css\report.css',          f'{REMOTE_BASE}/app/static/css/report.css'),
    (r'app\static\css\wiki.css',            f'{REMOTE_BASE}/app/static/css/wiki.css'),
    # Static
    (r'app\static\favicon.svg',             f'{REMOTE_BASE}/app/static/favicon.svg'),
    # Core Python
    (r'app\store.py',                       f'{REMOTE_BASE}/app/store.py'),
    (r'app\main.py',                        f'{REMOTE_BASE}/app/main.py'),
    # Routers
    (r'app\routers\dashboard.py',           f'{REMOTE_BASE}/app/routers/dashboard.py'),
    (r'app\routers\analysis.py',            f'{REMOTE_BASE}/app/routers/analysis.py'),
    (r'app\routers\reports.py',             f'{REMOTE_BASE}/app/routers/reports.py'),
    # Services
    (r'app\services\analysis_service.py',   f'{REMOTE_BASE}/app/services/analysis_service.py'),
    # Templates
    (r'app\templates\base.html',            f'{REMOTE_BASE}/app/templates/base.html'),
    (r'app\templates\dashboard.html',       f'{REMOTE_BASE}/app/templates/dashboard.html'),
    (r'app\templates\admin.html',           f'{REMOTE_BASE}/app/templates/admin.html'),
    (r'app\templates\admin_users.html',     f'{REMOTE_BASE}/app/templates/admin_users.html'),
    (r'app\templates\admin_login.html',     f'{REMOTE_BASE}/app/templates/admin_login.html'),
    (r'app\templates\admin_register.html',  f'{REMOTE_BASE}/app/templates/admin_register.html'),
    (r'app\templates\analyze.html',         f'{REMOTE_BASE}/app/templates/analyze.html'),
    (r'app\templates\about.html',           f'{REMOTE_BASE}/app/templates/about.html'),
    (r'app\templates\report.html',          f'{REMOTE_BASE}/app/templates/report.html'),
    (r'app\templates\owasp_wiki.html',      f'{REMOTE_BASE}/app/templates/owasp_wiki.html'),
    (r'app\templates\api_tutorial.html',    f'{REMOTE_BASE}/app/templates/api_tutorial.html'),
    (r'app\templates\monitoring.html',      f'{REMOTE_BASE}/app/templates/monitoring.html'),
    # Schema
    (r'schema.sql',                         f'{REMOTE_BASE}/schema.sql'),
]

def run(client, cmd, show=True):
    _, o, e = client.exec_command(cmd)
    out = o.read().decode('utf-8', 'replace').strip()
    err = e.read().decode('utf-8', 'replace').strip()
    if show:
        print(f"  $ {cmd}")
        if out:
            print(f"    {out}")
        if err:
            print(f"  ERR: {err}")
    return out

print("=" * 60)
print("  OWASP Verificador — Deploy a VM (puerto 8000)")
print("=" * 60)

print(f"\n[1/5] Conectando a {host}...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=passwd, timeout=15)
print("      Conectado OK")

print(f"\n[2/5] Creando directorios remotos necesarios...")
run(client, f"mkdir -p {REMOTE_BASE}/app/static/css {REMOTE_BASE}/app/templates {REMOTE_BASE}/app/routers {REMOTE_BASE}/app/services", show=False)
print("      Directorios listos")

print(f"\n[3/5] Subiendo {len(FILES)} archivos via SFTP...")
sftp = client.open_sftp()
for relative_local, remote in FILES:
    local_path = os.path.join(BASE_LOCAL, relative_local)
    if os.path.exists(local_path):
        print(f"      >> {relative_local}")
        sftp.put(local_path, remote)
    else:
        print(f"      SKIP (no existe): {relative_local}")
sftp.close()
print("      Todos los archivos subidos")

print(f"\n[4/5] Recreando base de datos MySQL...")
# Drop y recrear la BD completa con schema actualizado (incluye email en users)
db_cmd = f"mysql -u root -pupt2026 < {REMOTE_BASE}/schema.sql"
run(client, db_cmd)
# Verificar tablas
tables_out = run(client, "mysql -u root -pupt2026 -e 'USE owasp_verificador; SHOW TABLES;' 2>/dev/null")
print(f"      Tablas en BD: {tables_out.replace(chr(10), ', ')}")

print(f"\n[5/5] Reiniciando servicio en puerto 8000...")
run(client, "systemctl restart owasp-verificador.service")
time.sleep(4)

status = run(client, "systemctl is-active owasp-verificador.service")
print(f"\n  Estado servicio: {status}")

print("\n  Verificando endpoints (puerto 8000):")
run(client, "curl -s -o /dev/null -w '      / -> %{http_code}\\n' http://localhost:8000/")
run(client, "curl -s -o /dev/null -w '      /analyze -> %{http_code}\\n' http://localhost:8000/analyze")
run(client, "curl -s -o /dev/null -w '      /login -> %{http_code}\\n' http://localhost:8000/login")
run(client, "curl -s -o /dev/null -w '      /about -> %{http_code}\\n' http://localhost:8000/about")
run(client, "curl -s -o /dev/null -w '      /owasp -> %{http_code}\\n' http://localhost:8000/owasp")

client.close()
print("\n" + "=" * 60)
print("  Deploy completado exitosamente")
print("  URL: http://38.250.116.71:8000")
print("=" * 60)
