import json
import logging
import os
import re

logger = logging.getLogger(__name__)


def normalize_severity(raw):
    return {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "moderate": "MEDIUM",
        "low": "LOW",
        "warning": "LOW",
        "info": "INFO",
        "informational": "INFO",
        "unknown": "MEDIUM",
    }.get(str(raw).lower().strip(), "MEDIUM")


def estimate_reachability(tool, file_path=None):
    if file_path:
        path = file_path.lower()
        if path.startswith("app/") or "/app/" in path:
            return 1.0
        if "test" in path:
            return 0.2
    if tool in ("trivy", "owasp"):
        return 0.7
    if tool == "sonar":
        return 0.8
    return 0.5


def parse_bandit(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()

    for block in re.split(r"(?=^>> Issue:)", content, flags=re.MULTILINE):
        block = block.strip()
        if not block.startswith(">> Issue:"):
            continue

        issue = re.search(r"\[(\w+:[^\]]+)\]\s*(.+)", block)
        if not issue:
            continue

        location = re.search(r"Location:\s*(.+?):(\d+)", block)
        severity = re.search(r"Severity:\s*(\w+)", block, re.IGNORECASE)
        file_path = location.group(1).strip() if location else None
        line_number = int(location.group(2)) if location else None

        findings.append({
            "tool": "bandit",
            "vuln_id": issue.group(1).strip(),
            "title": issue.group(2).strip(),
            "description": "Bandit static-analysis finding",
            "severity": normalize_severity(severity.group(1) if severity else "MEDIUM"),
            "reachability": estimate_reachability("bandit", file_path),
            "file_path": file_path,
            "line_number": line_number,
            "raw_snippet": block[:400],
        })

    logger.info("Bandit parsed %d findings", len(findings))
    return findings


def parse_pylint(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    pattern = re.compile(r"^(.+?):(\d+):\d+:\s+([EWCRIF]\d+):\s+(.+?)\s+\((\S+)\)")
    severity_by_type = {"F": "HIGH", "E": "HIGH", "W": "MEDIUM", "C": "INFO", "R": "INFO", "I": "INFO"}

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = pattern.match(line.strip())
            if not match:
                continue
            file_path = match.group(1).strip()
            code = match.group(3).strip()
            findings.append({
                "tool": "pylint",
                "vuln_id": code,
                "title": f"{code}: {match.group(5).strip()}",
                "description": match.group(4).strip(),
                "severity": severity_by_type.get(code[0], "INFO"),
                "reachability": estimate_reachability("pylint", file_path),
                "file_path": file_path,
                "line_number": int(match.group(2)),
                "raw_snippet": line.strip()[:400],
            })

    logger.info("Pylint parsed %d findings", len(findings))
    return findings


def parse_trivy(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = re.search(r"│\s*(\S.*?)\s*│\s*(CVE-[\d-]+|GHSA-[\w-]+)\s*│\s*(\w+)\s*│", line)
            if not match:
                continue
            package = match.group(1).strip()
            vuln_id = match.group(2).strip()
            findings.append({
                "tool": "trivy",
                "vuln_id": vuln_id,
                "title": f"{vuln_id} in {package}",
                "description": f"Trivy detected {vuln_id} in {package}",
                "severity": normalize_severity(match.group(3)),
                "reachability": estimate_reachability("trivy"),
                "file_path": None,
                "line_number": None,
                "raw_snippet": line.strip()[:400],
            })

    logger.info("Trivy parsed %d findings", len(findings))
    return findings


def parse_owasp(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to parse OWASP Dependency-Check report: %s", exc)
        return findings

    for dependency in data.get("dependencies", []):
        dep_name = dependency.get("fileName") or dependency.get("filePath") or "unknown"
        for vulnerability in dependency.get("vulnerabilities", []):
            vuln_id = vulnerability.get("name", "UNKNOWN")
            findings.append({
                "tool": "owasp",
                "vuln_id": vuln_id,
                "title": f"{vuln_id} in {dep_name}",
                "description": (vulnerability.get("description") or "")[:500],
                "severity": normalize_severity(vulnerability.get("severity", "MEDIUM")),
                "reachability": estimate_reachability("owasp"),
                "file_path": dep_name,
                "line_number": None,
                "raw_snippet": f"{vuln_id} | {dep_name}"[:400],
            })

    logger.info("OWASP Dependency-Check parsed %d findings", len(findings))
    return findings


def parse_sonar(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    try:
        with open(report_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return findings

    severity_map = {"BLOCKER": "CRITICAL", "CRITICAL": "HIGH", "MAJOR": "MEDIUM", "MINOR": "LOW", "INFO": "INFO"}
    for issue in data.get("issues", []):
        component = issue.get("component", "")
        file_path = component.split(":")[-1] if ":" in component else component
        findings.append({
            "tool": "sonar",
            "vuln_id": issue.get("rule", "UNKNOWN"),
            "title": issue.get("message", "Sonar issue")[:120],
            "description": issue.get("message", ""),
            "severity": severity_map.get(issue.get("severity", "MAJOR"), "MEDIUM"),
            "reachability": estimate_reachability("sonar", file_path),
            "file_path": file_path,
            "line_number": issue.get("line"),
            "raw_snippet": json.dumps(issue)[:400],
        })
    return findings
