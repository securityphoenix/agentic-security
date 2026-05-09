---
description: Generate a standards-compliant SBOM (Software Bill of Materials) in CycloneDX 1.6 or SPDX 2.3 format from your dependency manifests. Required for customer security reviews, FedRAMP, EU CRA, and most SOC 2 / ISO 27001 audits.
argument-hint: "[--format cyclonedx|spdx] [--output sbom.json]"
---

Emit an SBOM for the current project.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . \
  --format ${FORMAT:-cyclonedx} \
  --output ${OUTPUT:-sbom.json}
```

The SBOM includes:

- **CycloneDX 1.6**: every component's `purl`, license, scope; `vulnerabilities[]` array with CVE IDs, CVSS vectors, EPSS scores, and `agentic-security:functionReachable` annotations from feature 0.6.0/F1.
- **SPDX 2.3**: every package as a `SPDXRef-Package-N` with `purl` external ref and CVE external refs in the `SECURITY` category; `relationships[]` linking each package to the document.

After generation, recommend uploading to the customer's TPRM portal or attaching to a security questionnaire response.

## Why this exists

Customer security reviews and most modern compliance regimes (FedRAMP Rev 5, EU Cyber Resilience Act, NIST SSDF, executive order EO 14028) now expect a machine-readable SBOM in either CycloneDX or SPDX. Both formats are emitted from the same parsed-manifest data we already use for SCA, so the cost is essentially zero per scan.
