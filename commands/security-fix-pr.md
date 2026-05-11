---
description: Bundle multiple security fixes into a feature branch and open a pull request via gh. Builds on /security-fix per finding; runs the project's tests after each fix and auto-reverts any fix that breaks the build.
argument-hint: "[--severity critical|high|all] [--apply] [--branch <name>]"
---

Apply fixes for every finding at or above `${SEVERITY:-critical}` severity, bundle them into a single PR, and open it.

**Default is dry-run.** You must pass `--apply` to actually modify code.

## Workflow

1. **Pre-flight checks**:
   - Verify the working tree is clean (`git status --porcelain` empty). If not, ask the user to commit or stash first.
   - Verify `gh auth status` succeeds. If not, fall back to local-branch-only mode.
   - Verify `.agentic-security/last-scan.json` exists. If not, run `/scan --all` first.

2. **Build the bundle plan**:
   - Read `.agentic-security/last-scan.json`.
   - Filter findings to those at or above `${SEVERITY:-critical}`, sorted by toxicity DESC then severity.
   - For each finding, classify the fix type via `security-fixer` agent's dry-run output.
   - Group findings that share the same `sharedHelper` (the engine's `bundles[]` array surfaces these).
   - Print the bundle plan: file × finding-id × what changes × test command.

3. **Confirm with the user** before proceeding. Show the plan and ask: "Apply these N fixes and open a PR? [y/N]".

4. **If `--apply`**:
   - Create branch `${BRANCH:-security/auto-fix-$(date +%Y%m%d)}`.
   - For each finding (toxicity DESC):
     - Invoke `security-fixer` agent with `--apply` for that finding.
     - Run the project's test command (auto-detected from `package.json`/`pyproject.toml`/`Cargo.toml`/`go.mod`).
     - **If tests pass**: commit with `security: fix <vuln> in <file>:<line> (finding <id>)`.
     - **If tests fail**: revert the working-tree change (`git checkout -- <file>`), label the finding `INDETERMINATE: tests failed after fix`, and continue with the next finding. Do not abort.
   - Push the branch.
   - Open a PR via:

```bash
gh pr create \
  --title "security: auto-bundle fix for ${COUNT} findings (severity ≥ ${SEVERITY:-critical})" \
  --body-file <(cat <<EOF
## Auto-generated security fix bundle

This PR bundles ${COUNT} findings remediated by \`agentic-security\`.

### Findings fixed

\${FIXED_LIST}

### Findings skipped (tests failed)

\${SKIPPED_LIST}

### Verification

- Each fix was validated by running the project's test command after the change.
- Any fix that broke tests was reverted; those findings remain open.
- Re-run \`/scan --all\` and \`/security-poc\` for any individual finding to verify.

🤖 Generated with [agentic-security](https://github.com/clearcapabilities/agentic-security)
EOF
  )
```

5. **Final report**: print a summary of what landed in the PR and what was skipped, with the PR URL.

## Hard rules

- **Never run without `--apply`** unless the user explicitly says so. Default to dry-run plan output.
- **Never amend or force-push** an existing branch. Create a fresh branch each invocation.
- **Never override a failing test** by widening assertions or skipping tests. If a fix breaks a test, the fix is reverted and the finding stays open with an INDETERMINATE label.
- **Don't bundle critical and routine fixes together.** A reviewer may approve the critical fixes but want to look at routine changes separately.
- **Skip findings labelled PROBABLE_FP by `/security-poc`** — they're already being tracked as suppressions, not bugs.

## Why this exists

Bundling security fixes into a single PR is the right developer experience for security debt: one PR, many fixes, validated by your existing test suite. `security-fixer` handles the per-finding patching work and your test runner validates before push.
