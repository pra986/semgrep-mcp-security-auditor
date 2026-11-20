"""Pytest suite for SemgrepMCPSecurityAuditor production controls."""

from __future__ import annotations

import json
from pathlib import Path

from security_auditor.engine import SemgrepMCPSecurityAuditor
from security_auditor.models import RemediationAdvisory, SemgrepFinding

EVAL_CASES_PATH = Path(__file__).resolve().parent.parent / "evaluation" / "eval_cases.json"


def test_vulnerable_eval_cases_rule_detection() -> None:
    cases = json.loads(EVAL_CASES_PATH.read_text(encoding="utf-8"))
    auditor = SemgrepMCPSecurityAuditor()

    vulnerable_cases = [case for case in cases if case["should_flag"]]
    assert vulnerable_cases, "Expected at least one vulnerable eval case."

    for case in vulnerable_cases:
        report = auditor.audit(case["code"], language=case["language"])
        assert report.status == "ok"
        detected_rules = {finding.rule_id for finding in report.findings}
        assert case["expected_rule_id"] in detected_rules


def test_clean_snippet_zero_hit_anti_hallucination() -> None:
    called = False

    def hallucinating_llm(
        language: str, findings: tuple[SemgrepFinding, ...]
    ) -> list[RemediationAdvisory]:
        nonlocal called
        del language, findings
        called = True
        return [
            RemediationAdvisory(
                rule_id="fake.hallucinated.rule",
                summary="Invented finding on clean code.",
            )
        ]

    auditor = SemgrepMCPSecurityAuditor(advisory_generator=hallucinating_llm)
    clean_code = (
        "def add_numbers(a: int, b: int) -> int:\n"
        "    return a + b\n"
    )
    report = auditor.audit(clean_code, language="python")

    assert report.status == "ok"
    assert report.findings == ()
    assert report.advisories == []
    assert called is False


def test_semgrep_timeout_explicit_error_state() -> None:
    def slow_scanner(code: str, language: str, timeout_seconds: float) -> list[SemgrepFinding]:
        del code, language, timeout_seconds
        raise TimeoutError("Semgrep MCP timed out")

    auditor = SemgrepMCPSecurityAuditor(timeout_seconds=2.5, semgrep_scanner=slow_scanner)
    report = auditor.audit("x = 1\n", language="python")

    assert report.status == "timeout"
    assert report.findings == ()
    assert report.advisories == []
    assert report.error_message is not None
    assert "timed out" in report.error_message.lower()


def test_high_entropy_api_key_redaction_in_audit_logs() -> None:
    secret_key = "sk-live-9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"
    snippet = f'API_KEY = "{secret_key}"\nprint("ok")\n'

    auditor = SemgrepMCPSecurityAuditor()
    report = auditor.audit(snippet, language="python")

    joined_logs = "\n".join(report.audit_log)
    assert secret_key not in joined_logs
    assert "[REDACTED_SECRET]" in joined_logs


def test_snippet_size_and_encoding_validation() -> None:
    auditor = SemgrepMCPSecurityAuditor(max_snippet_bytes=32)

    oversized_report = auditor.audit("x = '1234567890'\n" * 5, language="python")
    assert oversized_report.status == "error"
    assert oversized_report.error_message is not None

    invalid_utf8_report = auditor.audit(b"\xff\xfe\xfd", language="python")
    assert invalid_utf8_report.status == "error"
    assert invalid_utf8_report.error_message is not None
