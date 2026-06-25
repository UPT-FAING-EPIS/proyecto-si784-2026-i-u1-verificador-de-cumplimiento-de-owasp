import paramiko

host = '38.250.116.71'
user = 'root'
passwd = 'upt2026'

FILES = [
    (r'app\static\css\styles.css', '/opt/owasp-verificador/app/static/css/styles.css'),
    (r'app\static\favicon.svg', '/opt/owasp-verificador/app/static/favicon.svg'),
    (r'app\templates\analyze.html', '/opt/owasp-verificador/app/templates/analyze.html'),
    (r'app\templates\api_tutorial.html', '/opt/owasp-verificador/app/templates/api_tutorial.html'),
    (r'app\templates\base.html', '/opt/owasp-verificador/app/templates/base.html'),
    (r'app\templates\dashboard.html', '/opt/owasp-verificador/app/templates/dashboard.html'),
    (r'app\templates\monitoring.html', '/opt/owasp-verificador/app/templates/monitoring.html'),
    (r'app\templates\owasp_wiki.html', '/opt/owasp-verificador/app/templates/owasp_wiki.html'),
    (r'app\templates\report.html', '/opt/owasp-verificador/app/templates/report.html')
]

import os
BASE_LOCAL = r'c:\Users\Gerardo\Documents\GitHub\proyecto-si784-2026-i-u1-verificador-de-cumplimiento-de-owasp'

print("Connecting to VM...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(host, username=user, password=passwd, timeout=15)

print("Uploading files via SFTP...")
sftp = client.open_sftp()
for relative_local, remote in FILES:
    local_path = os.path.join(BASE_LOCAL, relative_local)
    print(f"Uploading {relative_local} -> {remote}...")
    sftp.put(local_path, remote)
sftp.close()
print("Uploaded all files successfully!")

def run(cmd):
    _, o, e = client.exec_command(cmd)
    r = o.read().decode('utf-8', 'replace').strip()
    if r:
        print(f"$ {cmd}\n{r}")
    else:
        print(f"$ {cmd} (no output)")

print("Restarting service...")
run("systemctl restart owasp-verificador.service")

import time
time.sleep(3)

print("Checking service status...")
run("systemctl is-active owasp-verificador.service")

print("Checking endpoint responses...")
run("curl -s -o /dev/null -w 'Dashboard: %{http_code}\n' http://localhost:8000/")
run("curl -s -o /dev/null -w 'Analyze: %{http_code}\n' http://localhost:8000/analyze")
run("curl -s -o /dev/null -w 'API Tutorial: %{http_code}\n' http://localhost:8000/api-tutorial")
run("curl -s -o /dev/null -w 'Monitoring: %{http_code}\n' http://localhost:8000/monitoring")
run("curl -s -o /dev/null -w 'OWASP Wiki: %{http_code}\n' http://localhost:8000/owasp")

client.close()
print("Redesign deployment completed!")
