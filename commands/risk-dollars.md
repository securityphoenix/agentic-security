---
description: Expected-value-of-exploitation in USD per finding — prioritize remediation by money, not severity tier.
argument-hint: "[--top <n>] [--by family|file] [--csv]"
---

# /risk-dollars

For each open finding, compute the expected value of exploitation in dollars:

```
EV = P(exploited) × Impact($) × Reachability discount × Confidence floor
```

Where:
- **P(exploited)** comes from EPSS if a CVE is mapped; else from a family-level base rate
- **Impact($)** comes from data-class mapping (PII / PHI / PCI / Confidential) or crown-jewel tagging; defaults to $50k
- **Reachability** discount: route-reachable 1.0 → unreachable 0.05
- **Confidence** floor: 0.4 minimum so low-confidence findings still count

## Example

```bash
/risk-dollars --top 10
```

Output:
```
Risk-in-dollars summary
  Total open EV: $1.42M
  Critical EV:   $890k
  High EV:       $420k

Top 10 findings by EV:

  $180k  CRITICAL  hardcoded-secret      src/auth/keys.js:14    AWS access key in source
  $145k  CRITICAL  prompt-injection      src/agent/handler.py:23 user input concatenated into system prompt
  $120k  CRITICAL  ssrf-cloud-metadata   src/proxy.js:55         169.254.169.254 reachable
  $ 95k  HIGH      sqli                  src/admin/users.js:42   raw query with template literal
  ...
```

## Defaults you can override

The defaults are public-domain industry estimates (Ponemon / Verizon-style rough averages). To tune them per-project:

`.agentic-security/risk-config.yml`:
```yaml
impactUSD:
  PII: 350000
  PHI: 500000
  default: 75000
```

## Regulatory triggers

Each finding family carries a hint about which regulatory frameworks the EV might invoke:

- **PII / customer data** → GDPR (EU 2016/679), CCPA (Cal. Civ. §1798.150)
- **PHI / health data** → HIPAA Security Rule (45 CFR §164.312)
- **PCI / cardholder data** → PCI-DSS (Council); fines per-incident
- **Financial data** → GLBA Safeguards Rule (16 CFR Part 314), state breach-notification laws

A common real-world anchor for cost: Capital One's 2019 SSRF → metadata-credential theft → 100M records → $190M settlement. SSRF-to-metadata findings carry that scenario in their `riskDollars.scenario` field when both the source (untrusted input) and the sink (169.254.169.254 / metadata.google.internal) are detected together.

## Disclaimer

This is an **order-of-magnitude estimate for prioritization**. It is NOT an actuarial / insurance assessment / legal advice. The defaults are rough averages from public breach-cost reports; use them as anchors, not authoritative figures. Real-world cost depends on data class, customer base, jurisdiction, insurance coverage, and how the breach gets handled.

## Implementation

The `annotateRiskDollars` annotator runs at scan time and stamps each finding with `riskDollars: { ev, prob, impact, discount }`. This command formats the existing data:

```js
import { annotateRiskDollars, fmtUsd } from '@clear-capabilities/agentic-security-scanner/posture/risk-dollars.js';

const scan = readLastScan(scanRoot);
annotateRiskDollars(scanRoot, scan.findings); // idempotent — adds if missing
const sorted = scan.findings.slice().sort((a, b) => (b.riskDollars?.ev || 0) - (a.riskDollars?.ev || 0));
// Render top-N as a table or CSV
```

## Opt-out

`AGENTIC_SECURITY_NO_RISK_DOLLARS=1` disables the annotator.
