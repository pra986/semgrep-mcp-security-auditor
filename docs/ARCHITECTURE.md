# Architecture — Semgrep MCP Security Auditor

## 6-Stage Audit Workflow

1. **Input Validation**: Enforce UTF-8 encoding and maximum snippet byte size (`MAX_SNIPPET_BYTES`).
2. **Secret Redaction**: Mask high-entropy API keys and tokens before writing audit logs.
3. **Semgrep MCP Scan**: Execute deterministic static analysis via Semgrep MCP with explicit timeout handling.
4. **Immutable Finding Lock**: Freeze `SemgrepFinding` records (`frozen=True`) before any LLM call so the model cannot invent rule IDs on 0-hit scans or suppress real hits.
5. **LLM Remediation Advisory**: Generate structured `RemediationAdvisory` guidance strictly bound to locked finding IDs.
6. **Report Assembly**: Return `SecurityAuditReport` with scan status (`ok`, `timeout`, `error`), immutable findings, advisories, and redacted audit log.

## Production Controls

- **Zero-Hit Anti-Hallucination**: On 0-hit scans, LLM advisory generation is bypassed or constrained so no fabricated rule IDs can appear.
- **Explicit Timeout State**: Semgrep scan timeouts return an explicit `timeout` status rather than silently returning 0 findings.
- **Deployment**: Containerized FastAPI backend and Next.js frontend targeting Azure Container Apps and GCP Cloud Run.
