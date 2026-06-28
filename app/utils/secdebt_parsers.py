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
        if path.startswith(("app/", "/app/")) or "/app/" in path:
            return 1.0
        if "test" in path:
            return 0.2
    if tool in ("trivy", "owasp"):
        return 0.7
    if tool == "sonar":
        return 0.8
    return 0.5


def _split_bandit_blocks(content):
    blocks = []
    current = []
    for line in content.splitlines():
        if line.startswith(">> Issue:"):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def _parse_bandit_heading(first_line):
    start = first_line.find("[")
    end = first_line.find("]", start + 1)
    if start == -1 or end == -1:
        return None, None
    return first_line[start + 1:end].strip(), first_line[end + 1:].strip()


def _parse_bandit_metadata(block):
    file_path = None
    line_number = None
    severity_value = "MEDIUM"

    for line in block.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("severity:"):
            severity_value = stripped.split(":", 1)[1].strip().split()[0]
        elif stripped.startswith("Location:"):
            location_value = stripped.split(":", 1)[1].strip()
            path_value, separator, line_value = location_value.rpartition(":")
            if separator and line_value.isdigit():
                file_path = path_value.strip()
                line_number = int(line_value)

    return file_path, line_number, severity_value


def parse_bandit(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()

    for block in _split_bandit_blocks(content):
        block = block.strip()
        vuln_id, title = _parse_bandit_heading(block.splitlines()[0])
        if not vuln_id:
            continue

        file_path, line_number, severity_value = _parse_bandit_metadata(block)

        findings.append({
            "tool": "bandit",
            "vuln_id": vuln_id,
            "title": title,
            "description": "Bandit static-analysis finding",
            "severity": normalize_severity(severity_value),
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

    severity_by_type = {"F": "HIGH", "E": "HIGH", "W": "MEDIUM", "C": "INFO", "R": "INFO", "I": "INFO"}

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            parts = stripped.split(":", 3)
            if len(parts) != 4 or not parts[1].isdigit():
                continue

            file_path = parts[0].strip()
            line_number = int(parts[1])
            message_part = parts[3].strip()
            code_part, separator, description_part = message_part.partition(":")
            code = code_part.strip()
            if not separator or len(code) < 2 or code[0] not in severity_by_type:
                continue

            description = description_part.strip()
            symbol = ""
            if description.endswith(")") and "(" in description:
                description, _, symbol = description.rpartition("(")
                description = description.strip()
                symbol = symbol[:-1].strip()

            findings.append({
                "tool": "pylint",
                "vuln_id": code,
                "title": f"{code}: {symbol or 'pylint'}",
                "description": description,
                "severity": severity_by_type.get(code[0], "INFO"),
                "reachability": estimate_reachability("pylint", file_path),
                "file_path": file_path,
                "line_number": line_number,
                "raw_snippet": stripped[:400],
            })

    logger.info("Pylint parsed %d findings", len(findings))
    return findings


def parse_trivy(report_path):
    findings = []
    if not os.path.exists(report_path):
        return findings

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            columns = [column.strip() for column in line.split("│")]
            if len(columns) < 5:
                continue

            package = columns[1]
            vuln_id = columns[2]
            severity = columns[3]
            if not vuln_id.startswith(("CVE-", "GHSA-")):
                continue

            findings.append({
                "tool": "trivy",
                "vuln_id": vuln_id,
                "title": f"{vuln_id} in {package}",
                "description": f"Trivy detected {vuln_id} in {package}",
                "severity": normalize_severity(severity),
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
    except (json.JSONDecodeError, OSError):
        logger.exception("Failed to parse OWASP Dependency-Check report")
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


def parse_pytest(report_path):
    findings = []

    if not os.path.exists(report_path):
        return findings

    failed_pattern = re.compile(
        r"^(?P<test>.+?)\s+FAILED(?:\s+\[[^\]]+\])?$"
    )

    with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()

            match = failed_pattern.match(line)
            if not match:
                continue

            test_name = match.group("test")

            if "::" in test_name:
                file_path, _, test_case = test_name.partition("::")
            else:
                file_path = ""
                test_case = test_name

            findings.append({
                "tool": "pytest",
                "vuln_id": f"PYTEST::{test_case}",
                "title": f"Failed Test: {test_case}",
                "description": f"Pytest test '{test_case}' failed.",
                "severity": "MEDIUM",
                "reachability": estimate_reachability("pytest", file_path),
                "file_path": file_path,
                "line_number": None,
                "raw_snippet": line[:400],
            })

    logger.info("Pytest parsed %d failed tests", len(findings))
    return findings
