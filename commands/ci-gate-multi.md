---
description: Deprecated alias — use /ci-gate --provider <name>. Kept one release for muscle-memory.
argument-hint: "[--provider gitlab|circleci|buildkite|jenkins|github] [--apply]"
---

# /ci-gate-multi (deprecated alias)

This command has been folded into `/ci-gate`. The behavior is identical — both
auto-detect the CI provider from the repo shape and accept `--provider <name>`
to override.

**Use `/ci-gate` going forward.** Examples:

```
/ci-gate                            # GitHub Actions (default)
/ci-gate --provider gitlab          # GitLab CI
/ci-gate --provider circleci --apply
/ci-gate --provider buildkite
/ci-gate --provider jenkins
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
