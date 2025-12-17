# Threat Model

This document summarizes key security threats for the A+ System Audit Utility and how the project mitigates them through technical controls and operating assumptions. It is intentionally concise and complements (but does not replace) organizational governance.

## Overview

**What the tool does:** Collects local system configuration/security signals, aggregates findings, and optionally performs AI-assisted analysis and remediation script suggestion generation.

**What the tool does not do:** It does not autonomously apply changes to the host. It generates reports and (optionally) remediation scripts for human review.

## Assets

- Local host signals collected by collectors (system configuration, security posture data)
- Audit outputs on disk (JSON/HTML reports, optional remediation scripts)
- Optional API credentials for AI providers (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`)
- Audit history database (`audit_history.db`) when persistence is enabled

## Trust Boundaries

- **Local system boundary:** The CLI executes on the audited host and reads system state using platform-specific mechanisms.
- **Output boundary:** Reports/scripts are written to the configured output directory; access control is inherited from the OS/filesystem.
- **Optional AI boundary:** When AI is enabled, a subset of audit results and findings is sent to an external AI provider for analysis.

## Key Threats and Mitigations

### Data exfiltration via AI analysis (privacy / confidentiality)

- **Threat:** Sensitive host details could be included in prompts sent to an external AI provider.
- **Mitigations:** AI is optional (`--ai none` / `--quick`). Inputs and AI responses are schema-validated. Users control where outputs are written and whether persistence is enabled.
- **Residual risk:** Operator must decide whether their environment/data may be shared with a third-party AI service.

### Prompt/response injection impacting generated remediation scripts (integrity)

- **Threat:** Malicious or unexpected content in findings could influence generated scripts or recommendations.
- **Mitigations:** Remediation scripts are treated as suggestions; the project performs input validation and includes dangerous-pattern detection in remediation script handling.
- **Residual risk:** Human review is required before execution in all environments.

### Tampering with stored audit results (integrity / auditability)

- **Threat:** Local reports or database entries could be modified after generation.
- **Mitigations:** Results are integrity-hashed (SHA-256) for verification; audit outputs include timestamps and an `audit_id`.
- **Residual risk:** Local attackers with filesystem access can still delete or replace artifacts; use OS controls and backups as appropriate.

### Denial of service / cost runaway when AI is enabled (availability)

- **Threat:** Excessive AI calls could exhaust API quotas or degrade performance.
- **Mitigations:** Rate limiting and circuit breaker behavior are built in; remediation generation is limited to top findings.

## Governance Context

This project is intended to operate under a broader AI governance framework:

- The external **AI Operations and Governance Policy** (AI‑GOV‑007, v1.1, effective 2025‑12‑08) defines accountability, escalation paths, and prohibited uses for AI-influenced outputs.
- The tool provides **technical safety controls** (validation, rate limiting, provenance in outputs); the policy defines **human responsibility** for review, approvals, and appropriate use of AI-assisted content.
- AI-assisted outputs are advisory only and must not be treated as autonomous decisions or actions; remediation scripts require human review and change control before use.
