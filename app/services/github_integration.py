import os
import requests


def create_github_issue(owner: str, repo: str, title: str, body: str, github_token: str | None = None) -> dict | None:
    # Use provided token first, fallback to env var
    token = github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        return None
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    payload = {"title": title, "body": body}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        if r.status_code in (200, 201):
            return r.json()
        else:
            return None
    except Exception:
        return None


def create_issues_for_findings(owner: str, repo: str, findings: list, github_token: str | None = None):
    """Crea un issue por cada finding. Devuelve la lista de issues creados."""
    # Use provided token first, fallback to env var
    token = github_token or os.getenv("GITHUB_TOKEN")
    if not token:
        return []
    created = []
    for f in findings:
        title = f"{f.rule_id}: {f.title}"
        body = f"**Descripción**: {f.description}\n\n**Evidencia**:\n{f.evidence}\n\n**Severidad**: {f.severity}\n"
        issue = create_github_issue(owner, repo, title, body, github_token=token)
        if issue:
            created.append(issue)
    return created
