---
description: Audit GitHub Actions workflows for supply-chain risk — floating tags, secret echoes, write-all permissions, OIDC misconfigurations, script-injection via github.event.*. Optionally emits a Pipeline Bill of Materials (PBOM).
argument-hint: "[--format pbom|cli|json]"
---

Run a focused audit of the project's CI/CD workflows.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format ${FORMAT:-cli}
```

The detector covers six canonical CI/CD security mistakes:

| Pattern | Severity | Why it matters |
|---|---|---|
| Floating action tag (`uses: foo/bar@main`) | medium | Tag re-pointable by publisher → silent supply-chain compromise |
| Major-version tag on third-party action (`@v3`) | medium | Major-version tags are mutable; pin to a 40-char SHA |
| `permissions: write-all` | high | Token blast-radius — any compromise lets the workflow modify any repo content |
| Secret echoed to logs (`echo ${{ secrets.X }}`) | high | Persistent leakage in workflow run logs |
| Untrusted `github.event.*` interpolated into shell | critical | Direct RCE in workflow context |
| `id-token: write` without `aud:` restriction | medium | OIDC token mintable for any audience |

For the **PBOM** (Pipeline Bill of Materials):

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format pbom --output pbom.json
```

The PBOM lists every workflow, every `uses:` step (with SHA pin status), every `secrets.*` reference, every `permissions:` block, and every workflow that enables OIDC. It pairs with the SBOM (`/security-sbom`) for full SDLC provenance.

## Why this exists

CI/CD pipelines are the highest-leverage attack surface in modern software supply chains. This command covers the six most commonly exploited CI/CD misconfigurations, with F1 = 1.00 against the labelled fixture set.
