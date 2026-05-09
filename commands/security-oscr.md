---
description: Render the agentic-security coverage map against the OSC&R (Open Software supply Chain attack Reference) framework. Highlights covered techniques and gaps.
---

Print the OSC&R coverage table.

```bash
node -e "
const { toOSCRMarkdown } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/oscr.js');
process.stdout.write(toOSCRMarkdown());
"
```

The output is a Markdown table per OSC&R tactic (Recon → Resource Development → Initial Access → Execution → Persistence → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection/Impact → Compliance/Governance), with each technique showing:

- ✅ **full** — covered by ≥2 detectors
- 🟡 **partial** — covered by exactly 1 detector
- ❌ **none** — not covered

OSC&R (Open Software Supply Chain Attack Reference) is a MITRE-ATT&CK-style framework for software supply chain attacks. Showing your coverage map against it is a strong signal in customer security reviews and a useful gap-analysis tool when planning the next quarter's detection work.
