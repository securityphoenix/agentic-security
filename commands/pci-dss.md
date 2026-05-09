---
description: Generate a PCI-DSS 4.0 code-testable controls attestation. Excludes pure-organisational controls.
argument-hint: "[path] [--format md|csv|json] [--output pci.md]"
---

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/pci-dss/scan.py ${1:-.} \
  --format ${FORMAT:-md} \
  --output ${OUTPUT:-pci-dss-attestation.md}
```

Edit `scripts/pci-dss/evidence-rules.json` to extend or refine controls. The default ruleset covers 12 high-impact code-testable controls — strong cryptography, TLS, MFA, audit logging, account lockout, vulnerability scanning automation. Pure-organisational controls (vendor due diligence, written policies) are out of scope by design.
