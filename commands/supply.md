---
description: Supply chain. SCA + SBOM + CVE alerts + license analysis in one command.
argument-hint: "[--check|--sbom|--cve-alerts|--license]"
---

# /supply

Supply chain dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| (default) or `--check` | Full SCA pass: OSV + KEV + EPSS, function-level reachability, dependency confusion |
| `--sbom` | Conversational SBOM exploration — query deps, drift, transitive paths in natural language |
| `--cve-alerts` | Subscribe to a daemon that pings when a new CVE affects an installed dep |
| `--license` | License-graph view: per-component license, transitive copyleft, dual-license traps. Backed by `license-graph.js`. |

Add `--json` to any mode for machine-readable output.

## After `--check`: offer the safe-upgrade PR

When `--check` finishes, partition the vulnerable dependencies into:

- **Safe** — a patch- or minor-level bump exists that clears the advisory with no major-version jump (low regression risk).
- **Risky** — only a major-version bump fixes it, or no fix is published yet.

Bundle the **safe** set and offer to open one PR via `/fix --sca --pr`: a single branch + commit that bumps every safe dependency at once, with a summarized changelog and the cleared advisory IDs in the PR body. List the **risky** set separately for manual review — never auto-bump across a major version.

## Implementation

Routes to existing modules: SCA engine (built-in), `posture/sbom-diff.js`, `posture/cve-alert-daemon`, `posture/license-graph.js`.
