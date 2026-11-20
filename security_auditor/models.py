from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class SemgrepFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Literal["INFO", "WARNING", "ERROR"] = "WARNING"
    message: str
    line: int = Field(ge=1)
    code_snippet: str = ""


class RemediationAdvisory(BaseModel):
    rule_id: str
    summary: str
    remediation_steps: list[str] = Field(default_factory=list)
    patched_example: str = ""


class SecurityAuditReport(BaseModel):
    status: Literal["ok", "timeout", "error"]
    language: str
    findings: tuple[SemgrepFinding, ...] = ()
    advisories: list[RemediationAdvisory] = Field(default_factory=list)
    audit_log: list[str] = Field(default_factory=list)
    error_message: str | None = None
