import json

from app.utils.secdebt_parsers import (
    estimate_reachability,
    normalize_severity,
    parse_bandit,
    parse_owasp,
    parse_pylint,
    parse_sonar,
    parse_trivy,
)


def test_normalize_severity_and_reachability():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity("moderate") == "MEDIUM"
    assert normalize_severity("unexpected") == "MEDIUM"
    assert estimate_reachability("bandit", "app/routes/auth.py") == 1.0
    assert estimate_reachability("bandit", "tests_fixed/test_auth.py") == 0.2
    assert estimate_reachability("trivy") == 0.7


def test_parse_bandit_report(tmp_path):
    report = tmp_path / "bandit-report.txt"
    report.write_text(
        """>> Issue: [B104:hardcoded_bind_all_interfaces] Possible binding.
   Severity: Medium   Confidence: Medium
   Location: app/utils/validators.py:85
""",
        encoding="utf-8",
    )

    findings = parse_bandit(report)

    assert len(findings) == 1
    assert findings[0]["tool"] == "bandit"
    assert findings[0]["vuln_id"] == "B104:hardcoded_bind_all_interfaces"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["file_path"] == "app/utils/validators.py"
    assert findings[0]["line_number"] == 85


def test_parse_pylint_report(tmp_path):
    report = tmp_path / "pylint-report.txt"
    report.write_text(
        "app/routes/secdebt.py:45:4: W1203: Use lazy % formatting in logging functions (logging-fstring-interpolation)\n",
        encoding="utf-8",
    )

    findings = parse_pylint(report)

    assert len(findings) == 1
    assert findings[0]["tool"] == "pylint"
    assert findings[0]["vuln_id"] == "W1203"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["line_number"] == 45


def test_parse_trivy_report(tmp_path):
    report = tmp_path / "trivy-results.txt"
    report.write_text(
        "│ cryptography (METADATA) │ GHSA-537c-gmf6-5ccf │ HIGH │ fixed │ 46.0.5 │ 48.0.1 │ title │\n",
        encoding="utf-8",
    )

    findings = parse_trivy(report)

    assert len(findings) == 1
    assert findings[0]["tool"] == "trivy"
    assert findings[0]["vuln_id"] == "GHSA-537c-gmf6-5ccf"
    assert findings[0]["severity"] == "HIGH"


def test_parse_owasp_report(tmp_path):
    report = tmp_path / "dependency-check-report.json"
    report.write_text(
        json.dumps({
            "dependencies": [{
                "fileName": "requests-2.0.dist-info",
                "vulnerabilities": [{
                    "name": "CVE-2026-0001",
                    "severity": "HIGH",
                    "description": "example",
                }],
            }],
        }),
        encoding="utf-8",
    )

    findings = parse_owasp(report)

    assert len(findings) == 1
    assert findings[0]["tool"] == "owasp"
    assert findings[0]["vuln_id"] == "CVE-2026-0001"
    assert findings[0]["file_path"] == "requests-2.0.dist-info"


def test_parse_sonar_report(tmp_path):
    report = tmp_path / "sonar-issues.json"
    report.write_text(
        json.dumps({
            "issues": [{
                "rule": "python:S2077",
                "message": "SQL query should not be built from user-controlled data",
                "severity": "CRITICAL",
                "component": "project:app/routes/vault.py",
                "line": 22,
            }],
        }),
        encoding="utf-8",
    )

    findings = parse_sonar(report)

    assert len(findings) == 1
    assert findings[0]["tool"] == "sonar"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["file_path"] == "app/routes/vault.py"
