---
description: Generate CI workflow tuned to your CI provider — GitHub Actions, GitLab CI, CircleCI, or native shell.
argument-hint: "[--provider auto|github-actions|gitlab-ci|circleci|native] [--fail-on critical|high|medium]"
---

# /setup-ci

Auto-generates a CI workflow YAML for the chosen provider, tuned to scan on PR + push + weekly schedule.

## Providers

| ID | Generated file |
|---|---|
| `github-actions` | `.github/workflows/agentic-security.yml` |
| `gitlab-ci` | `.gitlab-ci-agentic-security.yml` |
| `circleci` | `.circleci/agentic-security.yml` |
| `native` | `ci/agentic-security.sh` (for self-hosted Jenkins/TeamCity/etc.) |

`--provider auto` (default) detects via existing artifacts and picks the right one.

## Example

```bash
/setup-ci --provider github-actions --fail-on critical
```

Output: a complete `.github/workflows/agentic-security.yml` with:
- Trigger on PR to main/master/develop + push to main/master + weekly Mon 09:00 UTC
- `permissions: { contents: read, security-events: write }` for SARIF upload
- `actions/checkout@v5 with: fetch-depth: 0` for diff baselining
- `actions/setup-node@v5 with: node-version: 'lts/*'`
- `npx -y @clear-capabilities/agentic-security-scanner scan --fail-on critical --sarif`
- `github/codeql-action/upload-sarif@v3` to surface findings in the GitHub Security tab

## Implementation

```js
import { detectProject, buildCiConfig } from '@clear-capabilities/agentic-security-scanner/posture/workflow-installer.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const detected = detectProject(cwd);
const { provider, files } = buildCiConfig(cwd, { provider: opts.provider, prSeverityFloor: opts.failOn });
for (const [rel, content] of Object.entries(files)) {
  const fp = path.join(cwd, rel);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, content);
}
console.log(`✓ Wrote ${provider} workflow.`);
```

## What you'll commit

Just the generated workflow file. No package.json changes; the scanner is fetched via `npx -y` at CI runtime.
