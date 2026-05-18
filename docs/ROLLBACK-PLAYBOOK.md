# Rule rollback playbook

When a scanner release ships a rule that causes a precision regression (unexpected false
positives on a customer codebase), use this playbook to roll back without waiting for a
full release.

## Quick reference

```bash
# Suppress a specific finding by ID in the current project
agentic-security rules suppress <finding-id>       # adds // agentic-security-ignore pragma

# Disable a rule for the current project (no code changes)
agentic-security rules disable <rule-id>            # writes .agentic-security/rules.yml

# Pin the scanner to a previous rule-pack revision
agentic-security rules pin --rev <version>          # writes .agentic-security/rules.lock.json

# Verify current rule-pack version
agentic-security rules status
```

## Step-by-step: suppress a finding immediately

Use when one specific finding is wrong and you need it gone before the next release:

1. Run `/scan` to get the finding ID (e.g. `sast:sql-injection:src/db.py:42`).
2. Add a suppression pragma on the offending line:
   ```python
   result = db.execute(query)  # agentic-security-ignore: sast:sql-injection
   ```
3. Re-run `/scan` to confirm the finding is gone.
4. File an issue: open a GitHub issue at https://github.com/agentic-security/agentic-security
   with the file content and why this is a false positive.

## Step-by-step: disable a rule project-wide

Use when a rule fires across many files and a pragma on each is impractical:

1. Identify the rule ID (visible in scan output or `last-scan.json`).
2. Edit `.agentic-security/rules.yml` (create if it doesn't exist):
   ```yaml
   rules:
     - id: <rule-id>
       disabled: true
   ```
3. Re-run `/scan`. The rule will not fire.
4. This file is project-local and should be committed so the team shares the override.

## Step-by-step: pin to a previous scanner rule-pack

Use when a full release caused widespread regressions and you need yesterday's rule set:

1. Check the current rule-pack version:
   ```bash
   agentic-security rules status
   ```
2. Pin to the previous version:
   ```bash
   agentic-security rules pin --rev 0.38.0
   ```
   This writes `.agentic-security/rules.lock.json` with the pinned version.
3. Subsequent scans use the pinned rules until the lock file is removed.
4. To unpin:
   ```bash
   agentic-security rules pin --unlock
   ```

## Step-by-step: emergency suppression for a CI gate failure

When the CI security gate is blocking a release due to a known FP:

1. Add a project-wide rule disable (see above) to `.agentic-security/rules.yml` and commit.
2. Re-run the CI gate — it should now pass.
3. File a bug report with full context (file, line, scanner version, why it's an FP).
4. Remove the disable once the fix lands in a scanner release.

## Escalation path

| Situation | Action |
|---|---|
| Single finding FP | Inline suppress pragma |
| Rule-wide FP on one project | `.agentic-security/rules.yml` disable |
| Release-wide regression on many projects | `rules pin --rev <prev>` + file bug |
| Critical FP on KEV-listed package | Contact ross@clearcapabilities.com directly |

## Testing a rollback

After applying any rollback, verify:

```bash
# Run the full local bench suite (fast, ~10s)
cd scanner && npm run bench

# Run the smoke suite against vulnerable fixtures
npm run smoke

# If you have the real-world bench cache:
npm run bench:realworld -- --app <affected-app> --no-wildcards
```

## Rule-pack release notes

Each scanner release documents which rules changed under `CHANGELOG.md` in the section
"Rule changes". If a regression correlates with a recent release, check the changelog first:

```bash
git log --oneline --follow scanner/src/sast/ scanner/src/posture/ | head -20
```

## Shadow mode (new in 0.39.x)

New rules are shipped in `shadowMode: true` for at least one release before becoming
active. Shadow findings appear in `.agentic-security/shadow-findings.json` but are
excluded from `/fix`, CI gates, and report grades.

To preview shadow findings:
```bash
agentic-security scan --show-shadow
```

To promote a shadow rule to active (project-local):
```bash
agentic-security rules promote <rule-id>
```
