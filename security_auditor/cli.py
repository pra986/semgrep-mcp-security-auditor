"""Runnable CLI demo entrypoint for Semgrep MCP Security Auditor."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_auditor.engine import SemgrepMCPSecurityAuditor

_DEMO_VULNERABLE_SNIPPET = """def get_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return cursor.execute(query).fetchall()
"""

_DEMO_CLEAN_SNIPPET = """def get_user_safe(cursor, user_id: str):
    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security-auditor",
        description="Run Semgrep MCP Security Auditor against a file or built-in demo snippets.",
    )
    parser.add_argument("--file", type=Path, help="Path to a source file to audit.")
    parser.add_argument("--language", default="python", help="Target language (default: python).")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Scan timeout in seconds (default: 10.0).",
    )
    args = parser.parse_args(argv)

    auditor = SemgrepMCPSecurityAuditor(timeout_seconds=args.timeout)

    if args.file:
        code = args.file.read_bytes()
        report = auditor.audit(code, language=args.language)
        print(json.dumps(report.model_dump(mode="json"), indent=2))
        return 0 if report.status == "ok" else 1

    print("=== Demo 1: Vulnerable Snippet ===")
    vuln_report = auditor.audit(_DEMO_VULNERABLE_SNIPPET, language="python")
    print(json.dumps(vuln_report.model_dump(mode="json"), indent=2))

    print("\n=== Demo 2: Clean Snippet (0-Hit Anti-Hallucination Lock) ===")
    clean_report = auditor.audit(_DEMO_CLEAN_SNIPPET, language="python")
    print(json.dumps(clean_report.model_dump(mode="json"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
