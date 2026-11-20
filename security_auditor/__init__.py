"""Semgrep MCP Security Auditor package."""

from security_auditor.engine import SemgrepMCPSecurityAuditor, redact_high_entropy_secrets
from security_auditor.models import (
    RemediationAdvisory,
    SecurityAuditReport,
    SemgrepFinding,
)

__all__ = [
    "SemgrepMCPSecurityAuditor",
    "SemgrepFinding",
    "RemediationAdvisory",
    "SecurityAuditReport",
    "redact_high_entropy_secrets",
]

__version__ = "0.1.0"
