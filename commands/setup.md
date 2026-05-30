---
description: Workflow installers + on-write guards. Hooks, CI, bodyguard, destructive-command guard.
argument-hint: "[--hooks|--ci|--bodyguard|--destructive-guard]"
---

# /setup

Workflow + guard installer dispatcher.

## Modes

| Flag | Behaviour | Legacy alias |
|---|---|---|
| `--hooks` | Install pre-commit security hook tuned to your project's stack (husky / pre-commit / lefthook / native). `--severity critical|high|medium`, `--diff-only|--full`, `--manager auto|husky|pre-commit|lefthook|native` | `/install-hooks` |
| `--ci` | Generate CI workflow tuned to your CI provider. `--provider auto|github-actions|gitlab-ci|circleci|native`, `--fail-on critical|high|medium` | `/setup-ci` |
| `--bodyguard` | Configure the AI bodyguard PreToolUse hook. Modes: `warn`, `block`, `off`. Per-project forbidden APIs at `.agentic-security/forbidden-apis.yml` | `/ai-bodyguard` |
| `--destructive-guard` | Configure the destructive-Bash-command guard (rm -rf, force-push, etc.). Modes: `warn`, `block`, `off` | `/destructive-guard` |

## Examples

```bash
/setup --hooks --severity critical               # husky/pre-commit hook
/setup --ci --provider github-actions            # GitHub Actions workflow
/setup --bodyguard mode=block                    # block insecure edits
/setup --destructive-guard mode=warn             # warn on destructive bash
```

## Implementation

Routes to `posture/workflow-installer.js` (detectProject, buildHookConfig, buildCiConfig), the existing bodyguard hook, and the destructive-guard hook.
