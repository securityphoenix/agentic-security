---
description: Find business-logic flaws that pattern matchers can't catch — broken authorization tier checks, race conditions, state-machine bypasses, intent vs. implementation gaps. Pairs with /scan --all.
argument-hint: "[path] [--max <N>]"
---

Run a semantic business-logic review of the route handlers in `${1:-.}`.

1. If `.agentic-security/last-scan.json` does not exist, run `/scan --all` first to populate the route inventory. The reviewer uses that list to pick targets.

2. Invoke the `security-logic-reviewer` subagent with:
   - The route list from `.agentic-security/last-scan.json` (`scan.routes` field).
   - Up to `${MAX:-8}` handler files to read (the reviewer chooses based on side-effect / money / role / state-machine signals).

3. The reviewer will emit Markdown sections — one per finding — each containing **quoted offending code, inferred intent, why it fails, attacker move, and fix**. Print the output verbatim. Do not summarise.

4. Cross-reference with the engine's pattern-based logic findings (`scan.logicVulns`) and merge by `(file, line)` — do not double-list the same flaw.

5. Suggest follow-ups:
   - For each high-severity finding, recommend `/security-poc` to generate a working exploit + regression test.
   - For each finding that pairs with another (e.g., a missing-auth flaw next to an IDOR), recommend `/security-chain` to surface the combined attack story.

## Why this command exists

Pattern matchers find SQL injection. They can't find "this `||` should be `&&`" — that requires reading what the code is *trying* to do. The reviewer agent compares inferred intent against actual implementation and reports the gaps. Findings are emitted only when the reviewer can quote the specific offending line, so the output is high-precision by construction.
