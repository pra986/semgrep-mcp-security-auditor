"""Core Semgrep MCP Security Auditor engine with production controls."""

from __future__ import annotations

import math
import re
import subprocess
from collections import Counter
from typing import Callable, Sequence

import httpx

from security_auditor.models import (
    RemediationAdvisory,
    SecurityAuditReport,
    SemgrepFinding,
)

ScannerFn = Callable[[str, str, float], Sequence[SemgrepFinding]]
AdvisoryFn = Callable[[str, tuple[SemgrepFinding, ...]], list[RemediationAdvisory]]

_PREFIXED_SECRET_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9\-_]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{20,}|xox[baprs]-[A-Za-z0-9\-]{16,})\b"
)
_CANDIDATE_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-/+=]{20,}\b")


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact_high_entropy_secrets(text: str) -> str:
    """Redact known API key prefixes and high-entropy secret tokens from text."""
    redacted = _PREFIXED_SECRET_RE.sub("[REDACTED_SECRET]", text)

    def _replace_if_high_entropy(match: re.Match[str]) -> str:
        token = match.group(0)
        if _shannon_entropy(token) >= 3.5:
            return "[REDACTED_SECRET]"
        return token

    return _CANDIDATE_TOKEN_RE.sub(_replace_if_high_entropy, redacted)


def _default_semgrep_scan(
    code: str, language: str, timeout_seconds: float
) -> list[SemgrepFinding]:
    """Deterministic local Semgrep-compatible rule scanner for offline/demo use."""
    del timeout_seconds
    if language.lower() != "python":
        return []

    findings: list[SemgrepFinding] = []
    lines = code.splitlines()
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.search(r"""f["'].*\b(SELECT|INSERT|UPDATE|DELETE)\b""", line, re.IGNORECASE):
            findings.append(
                SemgrepFinding(
                    rule_id="python.lang.security.audit.formatted-sql-query",
                    severity="ERROR",
                    message="Detected formatted SQL query; use parameterized queries instead.",
                    line=idx,
                    code_snippet=stripped,
                )
            )
        if "subprocess." in line and "shell=True" in line:
            findings.append(
                SemgrepFinding(
                    rule_id="python.lang.security.audit.subprocess-shell-true",
                    severity="ERROR",
                    message="Avoid shell=True in subprocess calls to prevent command injection.",
                    line=idx,
                    code_snippet=stripped,
                )
            )
        if re.search(r"\beval\s*\(", line):
            findings.append(
                SemgrepFinding(
                    rule_id="python.lang.security.audit.eval-detected",
                    severity="WARNING",
                    message="Use of eval() can execute arbitrary code; use ast.literal_eval or a safe parser.",
                    line=idx,
                    code_snippet=stripped,
                )
            )
        if re.search(r"\bpickle\.loads?\s*\(", line):
            findings.append(
                SemgrepFinding(
                    rule_id="python.lang.security.audit.pickle-load",
                    severity="WARNING",
                    message="Avoid untrusted pickle deserialization; prefer JSON or signed payloads.",
                    line=idx,
                    code_snippet=stripped,
                )
            )
    return findings


def _default_advisory_generator(
    language: str, findings: tuple[SemgrepFinding, ...]
) -> list[RemediationAdvisory]:
    """Generate deterministic remediation advisories grounded in Semgrep findings."""
    del language
    advisories: list[RemediationAdvisory] = []
    seen_rules: set[str] = set()
    for finding in findings:
        if finding.rule_id in seen_rules:
            continue
        seen_rules.add(finding.rule_id)
        advisories.append(
            RemediationAdvisory(
                rule_id=finding.rule_id,
                summary=finding.message,
                remediation_steps=[
                    f"Inspect line {finding.line} for untrusted input flow.",
                    "Replace unsafe construct with parameterized or allowlisted API.",
                ],
                patched_example="# Apply parameterized / safe API pattern",
            )
        )
    return advisories


class SemgrepMCPSecurityAuditor:
    """Production security auditor with strict validation, redaction, and finding locks."""

    def __init__(
        self,
        max_snippet_bytes: int = 32_768,
        timeout_seconds: float = 10.0,
        semgrep_scanner: ScannerFn | None = None,
        advisory_generator: AdvisoryFn | None = None,
    ) -> None:
        self.max_snippet_bytes = max_snippet_bytes
        self.timeout_seconds = timeout_seconds
        self._scanner = semgrep_scanner or _default_semgrep_scan
        self._advisory_generator = advisory_generator or _default_advisory_generator

    def _log(self, audit_log: list[str], message: str) -> None:
        audit_log.append(redact_high_entropy_secrets(message))

    def audit(self, code: str | bytes, language: str = "python") -> SecurityAuditReport:
        audit_log: list[str] = []
        self._log(audit_log, f"Starting security audit (language={language}).")

        # Stage 1: Encoding & size validation
        if isinstance(code, bytes):
            try:
                decoded = code.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                msg = f"Invalid UTF-8 encoding in snippet: {exc}"
                self._log(audit_log, msg)
                return SecurityAuditReport(
                    status="error",
                    language=language,
                    audit_log=audit_log,
                    error_message=redact_high_entropy_secrets(msg),
                )
        else:
            try:
                code.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                msg = f"Invalid UTF-8 characters in snippet: {exc}"
                self._log(audit_log, msg)
                return SecurityAuditReport(
                    status="error",
                    language=language,
                    audit_log=audit_log,
                    error_message=redact_high_entropy_secrets(msg),
                )
            decoded = code

        if not decoded.strip():
            msg = "Snippet must not be empty."
            self._log(audit_log, msg)
            return SecurityAuditReport(
                status="error",
                language=language,
                audit_log=audit_log,
                error_message=msg,
            )

        byte_len = len(decoded.encode("utf-8"))
        if byte_len > self.max_snippet_bytes:
            msg = f"Snippet size ({byte_len} bytes) exceeds limit ({self.max_snippet_bytes} bytes)."
            self._log(audit_log, msg)
            return SecurityAuditReport(
                status="error",
                language=language,
                audit_log=audit_log,
                error_message=msg,
            )

        self._log(audit_log, f"Validated snippet ({byte_len} bytes, UTF-8). Preview: {decoded[:120]!r}")

        # Stage 2: Semgrep MCP deterministic scan with explicit timeout state
        try:
            raw_findings = self._scanner(decoded, language, self.timeout_seconds)
        except (TimeoutError, httpx.TimeoutException, subprocess.TimeoutExpired):
            msg = f"Semgrep MCP scan timed out after {self.timeout_seconds}s."
            self._log(audit_log, msg)
            return SecurityAuditReport(
                status="timeout",
                language=language,
                findings=(),
                advisories=[],
                audit_log=audit_log,
                error_message=msg,
            )
        except Exception as exc:
            msg = f"Semgrep MCP scan failed: {exc}"
            self._log(audit_log, msg)
            return SecurityAuditReport(
                status="error",
                language=language,
                findings=(),
                advisories=[],
                audit_log=audit_log,
                error_message=redact_high_entropy_secrets(msg),
            )

        # Stage 3: Lock findings as immutable tuple
        locked_findings: tuple[SemgrepFinding, ...] = tuple(raw_findings)
        self._log(audit_log, f"Semgrep MCP returned {len(locked_findings)} immutable finding(s).")

        # Stage 4: Anti-hallucination lock for LLM advisories
        if not locked_findings:
            self._log(
                audit_log,
                "0 Semgrep findings; LLM advisory generation skipped (anti-hallucination lock).",
            )
            return SecurityAuditReport(
                status="ok",
                language=language,
                findings=(),
                advisories=[],
                audit_log=audit_log,
            )

        valid_rule_ids = {finding.rule_id for finding in locked_findings}
        raw_advisories = self._advisory_generator(language, locked_findings)
        grounded_advisories = [
            adv for adv in raw_advisories if adv.rule_id in valid_rule_ids
        ]
        self._log(
            audit_log,
            f"Generated {len(grounded_advisories)} grounded remediation advisory/advisories.",
        )

        return SecurityAuditReport(
            status="ok",
            language=language,
            findings=locked_findings,
            advisories=grounded_advisories,
            audit_log=audit_log,
        )
