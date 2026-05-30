---
description: Compliance + auditor flows. Framework attestation, walkthrough, buyer-facing badge, stack audits, PR augmentation.
argument-hint: "[--report <fw>|--walkthrough <fw>|--attestation|--audit <target>|--pr]"
---

# /compliance

Compliance + auditor flows dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--report <framework>` | Generate auditor-ready compliance attestation. Frameworks: `nist`, `asvs`, `llm`, `eu-ai-act` |
| `--walkthrough <framework>` | Step-by-step auditor narrative with evidence mapping per control. Frameworks: `nist-csf-2`, `nist-ai-600-1`, `owasp-asvs-5`, `owasp-llm-top-10`, `eu-ai-act`, `gdpr`, `hipaa-security-rule`, `ccpa` (or BYO at `.agentic-security/compliance/<id>/controls.json`) |
| `--attestation` | Render buyer-facing security posture artifact. `--format badge|onepager|page` |
| `--audit <target>` | Stack-specific security audits. Targets: `db`, `auth`, `rate-limit`, `webhook`, `env`, `csp-cors`, `deploy`, `launch`, `llm-cost`, `prompt` |
| `--pr` | Generate PR-description block (security delta vs base + ATT&CK + reviewers + artifacts) |
| `--gap` | Show only the **Not-Compliant** controls, each with the exact command that closes it |

Bare `/compliance` (no flag) prints this mode menu. `--report` and `--gap` accept `--format cli|json|oscal`.

## `--gap` (close the deltas)

`--gap` runs the attestation for `<framework>` but filters to controls scored **Not-Compliant** / **Partial**, and for each one prints the single command that closes it — e.g. a missing-rate-limit control maps to `/compliance --audit rate-limit`, a secrets control to `/fix --rotate-secret`, a coverage gap to `/fix --compliance`. The output is an actionable worklist, not a full report. `/fix --compliance` consumes the same mapping to batch-close them.

## `--format oscal` (machine-readable export)

`--report <fw> --format oscal` emits the attestation as an **OSCAL-aligned** JSON document (NIST's machine-readable assessment format): an `assessment-results`-shaped object with one `finding`/`observation` per control, each carrying the control id, status (`satisfied` / `not-satisfied`), and the evidence paths the scanner matched. `--format json` emits the same data in the plugin's native finding schema. Both are what GRC tooling and auditors ingest; `--format cli` (default) stays human-readable.

## Examples

```bash
/compliance --report nist                       # NIST AI 600-1 attestation
/compliance --walkthrough owasp-asvs-5          # OWASP ASVS auditor walkthrough
/compliance --attestation --format onepager     # buyer-facing one-pager
/compliance --audit db                          # database posture audit
/compliance --pr                                # PR-description block
```

## Implementation

Routes to the posture modules (`compliance-policy.js`, `auditor-walkthrough.js`, `pr-augment.js`) and the scanner CLI.
