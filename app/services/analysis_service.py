from app.models import Finding, Scan
from app.services.scanner import (
    calculate_score,
    scan_code,
    scan_url,
    scan_github_repo,
    detect_frameworks,
    penalty_for,
    remediation_for,
)
from app.services.github_integration import create_issues_for_findings
from app.store import scan_store


def execute_scan(target_type: str, target_value: str, create_issues: bool = False, github_token: str | None = None) -> Scan:
    # Prefer request token, fallback to admin-configured token in memory.
    effective_github_token = github_token or scan_store.get_github_token()

    if target_type == "code":
        findings = scan_code(target_value)
    elif target_type == "url":
        findings = scan_url(target_value)
    elif target_type == "archivo":
        # Procesar archivo como código
        findings = scan_code(target_value)
    elif target_type == "github_repo":
        # Descargar y procesar repositorio de GitHub
        findings = scan_github_repo(target_value, github_token=effective_github_token)
    else:
        raise ValueError("target_type debe ser 'code', 'url', 'archivo' o 'github_repo'")

    score = calculate_score(findings)
    stored_findings = [
        Finding(
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            description=finding.description,
            evidence=finding.evidence,
        )
        for finding in findings
    ]

    # detect frameworks from content when possible
    frameworks = set()
    try:
        if target_type in ("code", "archivo") and target_value:
            frameworks = detect_frameworks(target_value)
        elif target_type == "github_repo" and target_value:
            try:
                # Attempt to fetch single-file raw content or a small sample from the repo to detect frameworks
                from urllib.parse import urlparse
                parsed = urlparse(target_value)
                parts = parsed.path.strip('/').split('/')
                combined = ""
                if 'blob' in parts:
                    # raw file URL
                    try:
                        blob_idx = parts.index('blob')
                        branch = parts[blob_idx + 1]
                        file_path = '/'.join(parts[blob_idx + 2:])
                        raw_url = f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{branch}/{file_path}"
                        import requests as _req
                        headers = None
                        if effective_github_token:
                            headers = {"Authorization": f"token {effective_github_token}"}
                        r = _req.get(raw_url, headers=headers, timeout=8)
                        if r.status_code == 200:
                            combined = r.text
                    except Exception:
                        combined = ""
                else:
                    # try downloading repo zip (main/master) and combine a subset of files for detection
                    import requests as _req, zipfile, io
                    owner = parts[0]
                    repo = parts[1].replace('.git', '')
                    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip"
                    headers = None
                    if effective_github_token:
                        headers = {"Authorization": f"token {effective_github_token}"}
                    r = _req.get(zip_url, headers=headers, timeout=8)
                    if r.status_code == 404:
                        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip"
                        r = _req.get(zip_url, headers=headers, timeout=8)
                    if r.status_code == 200:
                        try:
                            code_ext = {'.py', '.js', '.ts', '.jsx', '.tsx'}
                            with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
                                count = 0
                                for fi in zf.filelist:
                                    if any(fi.filename.endswith(ext) for ext in code_ext):
                                        try:
                                            txt = zf.read(fi).decode('utf-8', errors='replace')
                                            combined += '\n' + txt
                                            count += 1
                                            if count >= 10:
                                                break
                                        except Exception:
                                            continue
                        except Exception:
                            combined = ""
                if combined:
                    frameworks = detect_frameworks(combined)
            except Exception:
                frameworks = set()
    except Exception:
        frameworks = set()

    # attach penalty and remediation to stored findings (include framework-specific guidance)
    for sf in stored_findings:
        try:
            sf.penalty = penalty_for(sf)
            sf.remediation = remediation_for(sf.rule_id, frameworks)
        except Exception:
            sf.penalty = 0
            sf.remediation = ""

    scan = Scan(
        id=0,
        target_type=target_type,
        target_value=target_value,
        status="completed",
        score=score,
        findings=stored_findings,
    )
    created_scan = scan_store.create_scan(scan)

    # If requested and target was a GitHub repo, attempt to create issues
    try:
        if create_issues and target_type == "github_repo":
            # parse owner/repo
            parsed = __import__('urllib.parse').urlparse(target_value)
            parts = parsed.path.strip('/').split('/')
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace('.git', '')
                # create issues with token from store (if available)
                create_issues_for_findings(owner, repo, stored_findings, github_token=effective_github_token)
    except Exception:
        pass

    return created_scan
