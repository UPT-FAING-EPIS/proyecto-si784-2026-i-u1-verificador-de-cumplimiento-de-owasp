from app.services.scanner import calculate_score, scan_code


def test_scan_code_detects_risky_patterns():
    content = 'password = "abc123"\nvalue = eval(user_input)'
    findings = scan_code(content)

    rule_ids = {finding.rule_id for finding in findings}
    assert "OWASP-A02" in rule_ids
    assert "OWASP-A03" in rule_ids


def test_calculate_score_reduces_by_severity():
    content = 'password = "abc123"\nvalue = eval(user_input)'
    findings = scan_code(content)
    score = calculate_score(findings)

    # two high severity findings -> penalty 30+30 -> score 40 (weights: high=30)
    assert score == 40
