from app.models import Finding, Scan
from app.services.scanner import calculate_score, scan_code, scan_url
from app.store import scan_store


def execute_scan(target_type: str, target_value: str) -> Scan:
    if target_type == "code":
        findings = scan_code(target_value)
    elif target_type == "url":
        findings = scan_url(target_value)
    else:
        raise ValueError("target_type debe ser 'code' o 'url'")

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

    scan = Scan(
        id=0,
        target_type=target_type,
        target_value=target_value,
        status="completed",
        score=score,
        findings=stored_findings,
    )
    return scan_store.create_scan(scan)
