---
description: Install pre-commit security hook tuned to your project's stack (husky / pre-commit / lefthook / native).
argument-hint: "[--severity critical|high|medium] [--diff-only|--full] [--manager auto|husky|pre-commit|lefthook|native]"
---

# /install-hooks

Auto-installs an agentic-security pre-commit hook. Detects which hook manager your project already uses and adds the right configuration.

## Detection

| Found | Manager used |
|---|---|
| `.husky/` | husky |
| `.pre-commit-config.yaml` | pre-commit |
| `lefthook.yml` | lefthook |
| `.git/hooks/` only | native git hooks |

## What it does

1. Runs `detectProject(scanRoot)` to identify language / package manager / hook manager
2. Calls `buildHookConfig(scanRoot, { severity, diffOnly })` to render the config
3. Writes the files (or prints them if `--dry-run`)
4. Prints next-step instructions (e.g. `npx husky install` if husky)

## Example

```bash
/install-hooks --severity critical --diff-only
```

Output:
```
Detected: node project, npm, husky hook manager
Writing .husky/pre-commit:

#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

# agentic-security: refuse the commit if any new critical finding lands
npx --no-install agentic-security scan --diff --fail-on critical

✓ Hook installed. Test it by staging a vulnerable file and running git commit.
```

## Implementation

```js
import { detectProject, buildHookConfig } from '@clear-capabilities/agentic-security-scanner/posture/workflow-installer.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const detected = detectProject(cwd);
const { manager, files } = buildHookConfig(cwd, { severity, diffOnly });

for (const [rel, content] of Object.entries(files)) {
  const fp = path.join(cwd, rel);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, content);
  if (rel.endsWith('pre-commit') && !rel.endsWith('.yaml')) fs.chmodSync(fp, 0o755);
}
console.log(`✓ Installed ${manager} hook(s) in ${cwd}`);
```

## Removal

To uninstall: edit / delete the file the install added. The plugin does not currently provide a `/uninstall-hooks` command.

## Safety

- Hook only **scans** — never auto-fixes
- Default `--severity critical` means non-critical findings still let the commit through
- `--diff-only` (default) scans only changed files for fast feedback (~5s); `--full` runs a complete scan
