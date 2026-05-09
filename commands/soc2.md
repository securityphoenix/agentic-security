---
description: Generate a SOC 2 Common Criteria (code-testable subset) attestation.
argument-hint: "[path] [--format md|csv|json] [--output soc2.md]"
---

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/scripts/soc2/scan.py ${1:-.} \
  --format ${FORMAT:-md} \
  --output ${OUTPUT:-soc2-attestation.md}
```

Covers 12 SOC 2 Common Criteria most evidenced from source (logical access, MFA, encryption in transit and at rest, monitoring + alerting, change management gates, vendor risk management via SBOM, incident-response runbooks). Edit `scripts/soc2/evidence-rules.json` to extend per the auditor's specific scope.

For a full vendor questionnaire, pair with:
- `/security-sbom --format cyclonedx` (CC9.2 evidence)
- `/security-pipeline --format pbom` (CC8.1 evidence)
- `/security-mttr` (CC7.x evidence — proves SLA tracking)
- `/security-api-inventory --format openapi` (CC6.x evidence — proves access surface is documented)
- `/nist-ai-600-1` (if the product uses GenAI)
