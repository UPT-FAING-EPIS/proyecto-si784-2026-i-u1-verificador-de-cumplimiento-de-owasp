from sqlalchemy.orm import Session

from app.models import Finding, Scan
from app.services.scanner import calculate_score, scan_code, scan_url


def execute_scan(db: Session, target_type: str, target_value: str) -> Scan:
    if target_type == "code":
        findings = scan_code(target_value)
    elif target_type == "url":
        findings = scan_url(target_value)
    else:
        raise ValueError("target_type debe ser 'code' o 'url'")

    score = calculate_score(findings)
    scan = Scan(target_type=target_type, target_value=target_value, status="completed", score=score)
    db.add(scan)
    db.flush()

    for finding in findings:
        db.add(
            Finding(
                scan_id=scan.id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                evidence=finding.evidence,
            )
        )

    db.commit()
    db.refresh(scan)
    return scan
