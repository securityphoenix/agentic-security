---
description: Generate an OWASP ASVS Level 1+2 compliance attestation. Multi-signal evidence (manifest deps, imports, paths, code/config/doc terms, with negation filter).
argument-hint: "[path] [--format md|csv|json] [--output asvs.md]"
---

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/owasp-asvs/scan.py ${1:-.} \
  --format ${FORMAT:-md} \
  --output ${OUTPUT:-owasp-asvs-attestation.md}
```

Mirrors the NIST AI 600-1 scanner's evidence model (manifest 5.0 → import 4.0 → test_path 3.0 → named_path 2.5 → code_term 2.0 → config_term 1.5 → doc_term 1.0 → comment 0.5). Status thresholds: weight ≥ 8 OR ≥ 3 distinct signal types = Compliant; > 0 = Partial; 0 = Not Compliant. Negation context (`we don't yet`, `future work`) discards matches.

Edit `scripts/owasp-asvs/evidence-rules.json` to add or tune controls for your project.
