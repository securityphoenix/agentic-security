---
description: Render the project's security posture as a buyer-facing artifact. --format badge | onepager | page.
argument-hint: "[--format badge|onepager|page] [--apply]"
---

Single entry point for buyer-facing security artifacts. All three formats are
generated from the SAME source-of-truth (`.agentic-security/last-scan.json`),
which means a `B` grade in the badge equals a `B` grade in the one-pager and
on the trust page — no risk of three different numbers in three different
places.

## Format choice

| Format | Audience | Surface |
|--------|----------|---------|
| `badge`    | GitHub README shield | `[![Security](https://...)](...)` markdown badge + investor-ready text summary |
| `onepager` | enterprise security questionnaire | `SECURITY.md` with controls table, scan posture, last-audit date |
| `page`     | website `/security` route | `/.well-known/security.txt` + a live `/security` HTML page with current grade, streak, last scan |

If no `--format` is passed, default to `badge` (the smallest artifact;
opportunity for the user to upgrade).

## Dispatch

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
FORMAT="badge"
PASS_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --format)         NEXT_IS_FORMAT=1 ;;
    --format=*)       FORMAT="${arg#*=}" ;;
    *)
      if [ "${NEXT_IS_FORMAT:-}" = "1" ]; then FORMAT="$arg"; unset NEXT_IS_FORMAT
      else PASS_ARGS+=("$arg"); fi
      ;;
  esac
done
case "$FORMAT" in
  badge|"")    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs security-badge "${PASS_ARGS[@]}" ;;
  onepager)    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/security-onepager.py "${PASS_ARGS[@]}" ;;
  page)        python3 ${CLAUDE_PLUGIN_ROOT}/scripts/trust-page.py "${PASS_ARGS[@]}" ;;
  *)
    echo "security-attestation: --format must be one of: badge | onepager | page" >&2
    exit 2
    ;;
esac
```

## Migration

| Old command          | New form                           |
|----------------------|------------------------------------|
| `/security-badge`    | `/security-attestation --format badge` (default) |
| `/security-onepager` | `/security-attestation --format onepager` |
| `/trust-page`        | `/security-attestation --format page` |

## When to use each

- **badge** — first thing to add when you're publishing the repo. Sub-30-second setup. Drops a grade shield into the README.
- **onepager** — when a buyer asks for a security overview. Hand it over instead of writing custom prose.
- **page** — when you're scaling and need a public security disclosure surface. Establishes the `/.well-known/security.txt` contact and the `/security` page buyers check before signing.

The three artifacts are layered: every project gets a badge; growing
projects add the one-pager; production-grade projects publish the page.
