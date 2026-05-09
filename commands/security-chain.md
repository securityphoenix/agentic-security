---
description: Synthesize multi-finding exploit chains from the last scan (e.g., IDOR + missing auth = account takeover). Surfaces vulnerabilities that combine into worse outcomes than any single finding suggests.
argument-hint: "[--severity critical|high|all]"
---

Read `.agentic-security/last-scan.json` and identify multi-finding **exploit chains** — combinations of individual findings that compose into worse outcomes than any single line item.

1. If `.agentic-security/last-scan.json` does not exist, run `/security-scan-all` first and stop. The user must have a scan before chains can be synthesised.

2. Load the findings list and filter to severity ≥ `${1:-high}` for the chaining input set. Lower-severity findings can still appear as *components* of a chain when paired with a high-severity partner.

3. Invoke the `security-chain-synthesizer` subagent with the filtered findings. It will:
   - Bucket findings by `file`, `route`, and `dataClass`.
   - Match canonical chain templates (Account Takeover via IDOR; Cloud-creds Exfiltration via SSRF + hardcoded cloud secret; LLM-driven RCE via Prompt Injection + Insecure Tool; Session Hijack; Stored Path Traversal; OAuth Token Theft; Indirect Prompt Injection → Data Exfiltration; Mass Assignment + Privilege Escalation; Weak Crypto + Stored PII).
   - Emit only chains where ≥2 component findings share a file / route / data class / source-sink linkage.

4. Print the chain report (Markdown sections) directly. Do not summarise. The synthesiser is tuned for high precision; if it returns "No multi-finding exploit chains identified", trust it and exit 0.

5. After printing, suggest the next step:
   - For each chain, recommend `/security-poc <chain-name>` to generate a working exploit payload (validates the chain is real).
   - Recommend `/security-fix <component-id>` for the suggested-first-fix component to break the chain at its weakest link.

## Strict mode

If invoked with `--strict`, drop any chain whose components carry `confidence < 0.8` on average, or where no component has a non-empty `chain[]` field. Strict mode trades recall for higher precision when feeding into automated remediation.
