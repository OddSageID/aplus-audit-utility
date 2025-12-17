# Output Contract (Provenance & Interpretation)

This document describes the provenance of fields produced by the CLI so reviewers can distinguish measured facts from derived analysis and AI-assisted content. It is intended for auditability and governance alignment, not as a stability guarantee for every field name.

## Provenance Categories

### 1) Measured Facts (Collector Outputs)

**Definition:** Data measured/queried directly from the audited host by collectors.

**Where to find it (JSON paths):**

- `collector_results.<collector>.data` (raw collected signals)
- `collector_results.<collector>.findings[*]` (finding evidence produced by the collector from measured signals)
- `platform`, `platform_version`, `hostname`, `timestamp`, `audit_id`

**Interpretation:** Treat as evidence captured at the time of the run. Accuracy depends on host permissions, OS APIs, and collector coverage.

### 2) Derived Analysis (Deterministic Rules / Aggregation)

**Definition:** Tool-computed structure that aggregates or normalizes collector outputs without generative AI.

**Where to find it:**

- `all_findings[*]` (aggregated and severity-sorted list)
- `collector_results.<collector>.status`, `.errors`, `.warnings`, `.execution_time_ms`

**Interpretation:** Reproducible for the same inputs and tool version. Represents the tool’s rule-based interpretation of measured facts.

### 3) AI-Assisted Analysis (Clearly Marked)

**Definition:** Content produced with the assistance of an external AI provider when enabled.

**Where to find it:**

- `ai_config.provider` and `ai_config.model` (provenance marker)
- `ai_analysis` (executive summary / recommendations / risk score)
- `remediation_scripts` (suggested scripts and associated findings)

**Important nuance:** When `ai_config.provider` is `none`, the tool may still populate `ai_analysis` using a non-AI fallback; in that case it should be treated as derived analysis rather than AI-assisted content.

**Interpretation:** Non-authoritative decision support only. Treat as hypotheses and prioritization guidance requiring human judgment and verification.

## Governance Notes

- AI-assisted content has **no autonomous authority** and must not be used as an automated decision or action without human review.
- Remediation scripts are **never safe-by-default**: they require human review, testing, and change control before execution.
- Governing document: the external **AI Operations and Governance Policy** (AI‑GOV‑007, v1.1, effective 2025‑12‑08) defines accountability, escalation paths, and prohibited uses for AI-assisted outputs.
