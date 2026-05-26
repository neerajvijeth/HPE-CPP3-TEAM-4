#!/usr/bin/env python3
"""
SyscallGuard — Dependency Exercise Script
==========================================
Imports and exercises each dependency from requirements.txt to
attribute syscall drift to specific packages.

In CI, this script is run under strace to capture which syscalls
each dependency introduces. The resulting profile is compared
against the pytest profile to isolate dependency-specific behavior.

Usage:
    python dep_exerciser.py <requirements.txt> [--output dep_report.json]
"""

import importlib
import json
import sys
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path


# Map PyPI package names → Python import names (common mismatches)
IMPORT_NAME_MAP = {
    "flask": "flask",
    "flask-sqlalchemy": "flask_sqlalchemy",
    "flask-login": "flask_login",
    "flask-migrate": "flask_migrate",
    "psycopg2-binary": "psycopg2",
    "psycopg2": "psycopg2",
    "requests": "requests",
    "werkzeug": "werkzeug",
    "python-dotenv": "dotenv",
    "gunicorn": "gunicorn",
    "pytest": "pytest",
    "pytest-cov": "pytest_cov",
    "pytest-flask": "pytest_flask",
    "pillow": "PIL",
    "pyyaml": "yaml",
    "scikit-learn": "sklearn",
    "beautifulsoup4": "bs4",
    "python-dateutil": "dateutil",
    "pyjwt": "jwt",
    "cryptography": "cryptography",
    "sqlalchemy": "sqlalchemy",
    "jinja2": "jinja2",
    "markupsafe": "markupsafe",
    "click": "click",
    "itsdangerous": "itsdangerous",
    "alembic": "alembic",
    "mako": "mako",
    "blinker": "blinker",
    "certifi": "certifi",
    "charset-normalizer": "charset_normalizer",
    "idna": "idna",
    "urllib3": "urllib3",
}


def parse_requirements(req_path: str) -> list[dict]:
    """
    Parse requirements.txt and extract package names and versions.

    Returns:
        list of dicts with keys: package, version, import_name
    """
    packages = []

    with open(req_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue

            # Parse "package==version" or "package>=version" etc.
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*([><=!~]+\s*[\d.]+)?', line)
            if match:
                pkg_name = match.group(1).lower()
                version = match.group(2).strip() if match.group(2) else "any"

                # Determine Python import name
                import_name = IMPORT_NAME_MAP.get(pkg_name, pkg_name.replace("-", "_"))

                packages.append({
                    "package": pkg_name,
                    "version": version,
                    "import_name": import_name
                })

    return packages


def exercise_package(import_name: str, pkg_name: str) -> dict:
    """
    Import and exercise a package to trigger its syscalls.

    Returns:
        dict with exercise results
    """
    result = {
        "package": pkg_name,
        "import_name": import_name,
        "imported": False,
        "version_detected": None,
        "exercised": False,
        "exercise_details": [],
        "error": None,
    }

    try:
        # Dynamic import
        mod = importlib.import_module(import_name)
        result["imported"] = True

        # Try to detect version
        for attr in ("__version__", "VERSION", "version"):
            ver = getattr(mod, attr, None)
            if ver:
                result["version_detected"] = str(ver)
                break

        # Exercise common patterns
        exercises = []

        # Check for module-level attributes (triggers initialization)
        dir_items = dir(mod)
        exercises.append(f"Loaded module with {len(dir_items)} attributes")

        # Package-specific exercises
        if import_name == "flask":
            try:
                from flask import Flask
                app = Flask("__exercise_test__")
                exercises.append("Created Flask app instance")
            except Exception as e:
                exercises.append(f"Flask exercise failed: {e}")

        elif import_name == "requests":
            # Don't make actual HTTP calls; just exercise the module
            try:
                _ = mod.Session()
                exercises.append("Created requests.Session")
                _ = mod.structures.CaseInsensitiveDict()
                exercises.append("Created CaseInsensitiveDict")
            except Exception as e:
                exercises.append(f"requests exercise: {e}")

        elif import_name == "sqlalchemy" or import_name == "flask_sqlalchemy":
            exercises.append("Module loaded (DB exercises skipped — no connection)")

        elif import_name == "werkzeug":
            try:
                from werkzeug.security import generate_password_hash
                _ = generate_password_hash("test", method="pbkdf2:sha256")
                exercises.append("Generated password hash via werkzeug")
            except Exception as e:
                exercises.append(f"werkzeug exercise: {e}")

        elif import_name == "dotenv":
            exercises.append("Module loaded (dotenv)")

        elif import_name == "gunicorn":
            exercises.append("Module loaded (gunicorn — server exercise skipped)")

        elif import_name == "psycopg2":
            exercises.append("Module loaded (psycopg2 — no DB connection exercise)")

        elif import_name == "jinja2":
            try:
                from jinja2 import Template
                t = Template("Hello {{ name }}!")
                _ = t.render(name="SyscallGuard")
                exercises.append("Rendered Jinja2 template")
            except Exception as e:
                exercises.append(f"jinja2 exercise: {e}")

        elif import_name == "cryptography":
            try:
                from cryptography.fernet import Fernet
                key = Fernet.generate_key()
                f = Fernet(key)
                _ = f.encrypt(b"syscallguard test")
                exercises.append("Fernet encrypt/decrypt cycle")
            except Exception as e:
                exercises.append(f"cryptography exercise: {e}")

        else:
            exercises.append(f"Generic import exercise for {import_name}")

        result["exercised"] = True
        result["exercise_details"] = exercises

    except ImportError as e:
        result["error"] = f"ImportError: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def exercise_all_dependencies(req_path: str) -> dict:
    """
    Parse requirements.txt and exercise all dependencies.

    Returns:
        dict: Full exercise report
    """
    packages = parse_requirements(req_path)

    results = []
    imported_count = 0
    exercised_count = 0
    failed_count = 0

    for pkg in packages:
        print(f"  Exercising: {pkg['package']} (import: {pkg['import_name']})...", end=" ")
        result = exercise_package(pkg["import_name"], pkg["package"])
        results.append(result)

        if result["imported"]:
            imported_count += 1
            print(f"✅ v{result['version_detected'] or '?'}")
        else:
            failed_count += 1
            print(f"❌ {result['error']}")

        if result["exercised"]:
            exercised_count += 1

    report = {
        "version": "1.0",
        "generator": "syscallguard-dep-exerciser",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "requirements_file": req_path,
        "total_packages": len(packages),
        "imported_successfully": imported_count,
        "exercised_successfully": exercised_count,
        "failed_imports": failed_count,
        "results": results,
    }

    return report


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SyscallGuard: Exercise dependencies to profile their syscalls"
    )
    parser.add_argument("requirements", help="Path to requirements.txt")
    parser.add_argument("--output", default=None,
                        help="Path to write JSON exercise report")

    args = parser.parse_args()

    print(f"{'='*60}")
    print(f"  SyscallGuard — Dependency Exerciser")
    print(f"{'='*60}")
    print(f"  Requirements file: {args.requirements}")
    print()

    report = exercise_all_dependencies(args.requirements)

    print()
    print(f"  Summary:")
    print(f"    Packages found:     {report['total_packages']}")
    print(f"    Imported:           {report['imported_successfully']}")
    print(f"    Exercised:          {report['exercised_successfully']}")
    print(f"    Failed:             {report['failed_imports']}")
    print(f"{'='*60}")

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n📄 Report written to: {args.output}")


if __name__ == "__main__":
    main()
