---
description: Trim unused bulk. --what code: dead code in src. --what deps: unused installed packages. Default: both.
argument-hint: "[--what code|deps|both] [--apply]"
---

Single entry point for cleanup of unused bulk in the project — replaces the
former `/trim-dead-code` and `/trim-dependencies` pair. Default mode runs
both passes; `--what code` or `--what deps` narrows the scope.

The dispatch is intentionally thin: each mode delegates to the canonical body
(unchanged behavior, same flags, same output) so existing scripts that
exercise the underlying logic don't need to be retouched.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
WHAT="both"
PASS_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --what)         NEXT_IS_WHAT=1 ;;
    --what=*)       WHAT="${arg#*=}" ;;
    *)
      if [ "${NEXT_IS_WHAT:-}" = "1" ]; then WHAT="$arg"; unset NEXT_IS_WHAT
      else PASS_ARGS+=("$arg"); fi
      ;;
  esac
done
case "$WHAT" in
  code)
    # Same body as the former /trim-dead-code: invoke the scanner's
    # dead-code surface on the working tree.
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs trim-dead-code "${PASS_ARGS[@]}"
    ;;
  deps)
    # Same body as the former /trim-dependencies — unused installed packages,
    # CVE check, removal commands.
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs trim-dependencies "${PASS_ARGS[@]}"
    ;;
  both|"")
    # The same combined surface the old /trim-dependencies --include-dead-code
    # already produced.
    node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs trim-dependencies --include-dead-code "${PASS_ARGS[@]}"
    ;;
  *)
    echo "trim: --what must be one of: code | deps | both" >&2
    exit 2
    ;;
esac
```

## Why this exists

Before this command, `/trim-dependencies --include-dead-code` already produced
the unified output, and `/trim-dead-code` produced the code-only output. They
were the same operation under two slash names. `/trim` is the single
canonical entry; the two old slashes stay as deprecated aliases for one
release.

## Migration

| Old command                                | New form                          |
|--------------------------------------------|-----------------------------------|
| `/trim-dead-code`                          | `/trim --what code`               |
| `/trim-dependencies`                       | `/trim --what deps`               |
| `/trim-dependencies --include-dead-code`   | `/trim --what both` (default)     |
| `/trim-dead-code --apply`                  | `/trim --what code --apply`       |
