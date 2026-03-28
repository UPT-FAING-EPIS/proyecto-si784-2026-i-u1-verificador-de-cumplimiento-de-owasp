# ==============================================
# Script para crear issues del OWASP Checker
# Requiere: gh auth login (GitHub CLI)
# Uso: .\crear_issues.ps1 -Repo "usuario/repositorio"
# ==============================================

param(
    [Parameter(Mandatory=$true)]
    [string]$Repo
)

Write-Host "Creando labels..." -ForegroundColor Cyan

gh label create "planning"      --color "0075ca" --repo $Repo --force
gh label create "backend"       --color "e4e669" --repo $Repo --force
gh label create "frontend"      --color "d876e3" --repo $Repo --force
gh label create "testing"       --color "0e8a16" --repo $Repo --force
gh label create "bug"           --color "d73a4a" --repo $Repo --force
gh label create "documentation" --color "0052cc" --repo $Repo --force
gh label create "deployment"    --color "f9d0c4" --repo $Repo --force

Write-Host "Creando milestones..." -ForegroundColor Cyan

gh api repos/$Repo/milestones -f title="Semana 1 - Planificacion" | Out-Null
gh api repos/$Repo/milestones -f title="Semana 2 - Desarrollo"    | Out-Null
gh api repos/$Repo/milestones -f title="Semana 3 - Frontend"      | Out-Null
gh api repos/$Repo/milestones -f title="Semana 4 - Pruebas"       | Out-Null
gh api repos/$Repo/milestones -f title="Semana 5 - Cierre"        | Out-Null

Write-Host "Creando issues..." -ForegroundColor Cyan

# --- Semana 1: Planificacion ---
gh issue create --repo $Repo --title "Definir requerimientos del sistema"              --label "planning"      --milestone "Semana 1 - Planificacion" --body ""
gh issue create --repo $Repo --title "Disenar arquitectura del verificador OWASP"     --label "planning"      --milestone "Semana 1 - Planificacion" --body ""

# --- Semana 2: Desarrollo Backend ---
gh issue create --repo $Repo --title "Configurar repositorio y estructura del proyecto" --label "documentation" --milestone "Semana 2 - Desarrollo"    --body ""
gh issue create --repo $Repo --title "Implementar verificaciones OWASP Top 10 (A01-A05)" --label "backend"    --milestone "Semana 2 - Desarrollo"    --body ""
gh issue create --repo $Repo --title "Implementar verificaciones OWASP Top 10 (A06-A10)" --label "backend"    --milestone "Semana 2 - Desarrollo"    --body ""
gh issue create --repo $Repo --title "Exponer API REST para analizar codigo"           --label "backend"       --milestone "Semana 2 - Desarrollo"    --body ""

# --- Semana 3: Frontend ---
gh issue create --repo $Repo --title "Crear interfaz para subir codigo o URL"          --label "frontend"      --milestone "Semana 3 - Frontend"      --body ""
gh issue create --repo $Repo --title "Mostrar resultados del analisis en dashboard"    --label "frontend"      --milestone "Semana 3 - Frontend"      --body ""
gh issue create --repo $Repo --title "Integrar frontend con backend"                   --label "frontend"      --milestone "Semana 3 - Frontend"      --body ""

# --- Semana 4: Pruebas ---
gh issue create --repo $Repo --title "Realizar pruebas unitarias e integracion"        --label "testing"       --milestone "Semana 4 - Pruebas"       --body ""
gh issue create --repo $Repo --title "Registrar y corregir bugs"                       --label "bug"           --milestone "Semana 4 - Pruebas"       --body ""

# --- Semana 5: Cierre ---
gh issue create --repo $Repo --title "Documentacion final y despliegue"                --label "documentation" --milestone "Semana 5 - Cierre"        --body ""

Write-Host ""
Write-Host "Listo! 12 issues creados en $Repo" -ForegroundColor Green
