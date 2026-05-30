---
description: Workflow installers + on-write guards. Hooks, CI, bodyguard, destructive-command guard.
argument-hint: "[--hooks|--ci|--bodyguard|--destructive-guard]"
---

# /setup

Workflow + guard installer dispatcher.

## Modes

| Flag | Behaviour |
|---|---|
| `--hooks` | Install pre-commit security hook tuned to your project's stack (husky / pre-commit / lefthook / native). `--severity critical|high|medium`, `--diff-only|--full`, `--manager auto|husky|pre-commit|lefthook|native` |
| `--ci` | Generate CI workflow tuned to your CI provider. `--provider auto|github-actions|gitlab-ci|circleci|native`, `--fail-on critical|high|medium` |
| `--bodyguard` | Configure the AI bodyguard PreToolUse hook. Modes: `warn`, `block`, `off`. Per-project forbidden APIs at `.agentic-security/forbidden-apis.yml` |
| `--destructive-guard` | Configure the destructive-Bash-command guard (rm -rf, force-push, etc.). Modes: `warn`, `block`, `off` |
| `--all` | One-pass setup: installs hooks + CI + bodyguard + destructive-guard with sensible defaults |

Bare `/setup` (no flag) prints this mode menu.

## `--all` (one-pass setup)

Runs the four installers in sequence with safe defaults, pausing for confirmation before anything that writes outside `.agentic-security/`:

1. `--hooks` — auto-detected manager, `--severity high`.
2. `--ci` — auto-detected provider, `--fail-on high`.
3. `--bodyguard` — `mode=warn` (non-blocking until the user opts into `block`).
4. `--destructive-guard` — `mode=warn`.

Prints a single summary of what was installed and the one command to harden each further.

## Examples

```bash
/setup                                           # show the mode menu
/setup --all                                     # hooks + CI + both guards, defaults
/setup --hooks --severity critical               # husky/pre-commit hook
/setup --ci --provider github-actions            # GitHub Actions workflow
/setup --bodyguard mode=block                    # block insecure edits
/setup --destructive-guard mode=warn             # warn on destructive bash
```

## Implementation

Routes to `posture/workflow-installer.js` (detectProject, buildHookConfig, buildCiConfig), the existing bodyguard hook, and the destructive-guard hook.
