# Semgrep MCP Security Auditor

Project 28: Cybersecurity code auditor combining immutable Semgrep MCP static findings with LLM remediation advisory, secret redaction, and Azure/GCP container deployment.

## Architecture

The auditor separates deterministic static analysis (Semgrep via Model Context Protocol) from LLM-generated remediation guidance. Static findings are locked as immutable records before any LLM call so the model can explain and suggest fixes without inventing rule IDs or suppressing real hits.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed component diagrams and deployment notes.

## 6-Stage Workflow

1. **Input & Size/Encoding Validation**: Validates UTF-8 encoding and enforces maximum snippet byte limits before processing.
2. **Secret Redaction**: Scans code and audit logs for high-entropy API keys and tokens, redacting sensitive values prior to logging or LLM prompts.
3. **Semgrep MCP Scan**: Executes deterministic static analysis via Semgrep MCP with an explicit timeout boundary.
4. **Immutable Finding Lock**: Freezes `SemgrepFinding` objects; on 0-hit scans, LLM advisory is blocked from inventing rule IDs.
5. **LLM Remediation Advisory**: Generates `RemediationAdvisory` guidance strictly scoped to verified findings.
6. **Audit Report Assembly**: Outputs a structured `SecurityAuditReport` with status, findings, advisories, and redacted audit trail.

## Data Contract

- `SemgrepFinding`: Immutable static finding (`rule_id`, `severity`, `message`, `line`, `cwe`).
- `RemediationAdvisory`: Remediation guidance tied to an existing `rule_id` (`rule_id`, `summary`, `patched_snippet`).
- `SecurityAuditReport`: Top-level audit output (`status`, `findings`, `advisories`, `error`, `redacted_logs`).

## Production Controls

- **Snippet Size & Encoding Validation**: Rejects non-UTF-8 payloads and oversized snippets.
- **High-Entropy API Key Redaction**: Masks high-entropy secrets in audit logs and telemetry.
- **Anti-Hallucination Lock**: Immutable Semgrep MCP findings prevent the LLM from fabricating rule IDs on 0-hit scans.
- **Explicit Scan Timeout Error States**: Surfaces deterministic `timeout` error states instead of silent failures.
- **Azure / GCP Container Deployment**: Containerized FastAPI backend and Next.js frontend ready for Azure Container Apps or GCP Cloud Run.

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
python -m security_auditor.cli
```

## Attribution

Pinned attribution to [ed-donner/cyber](https://github.com/ed-donner/cyber) for foundational cybersecurity agent patterns and inspiration.
