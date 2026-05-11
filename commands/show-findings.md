---
description: Generate an interactive HTML report of every finding and open it in the default browser.
argument-hint: "[path]"
---

Render every finding from a scan as a self-contained interactive HTML report and try to open it in the default browser.

```bash
mkdir -p reports
REPORT="reports/findings-$(date +%Y%m%d-%H%M%S).html"
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format html --output "$REPORT"
ec=$?
if [ $ec -le 3 ]; then
  open "$REPORT" 2>/dev/null \
    || xdg-open "$REPORT" 2>/dev/null \
    || echo "Open $REPORT in your browser to view the report."
  exit 0
fi
exit $ec
```

The HTML report is self-contained (no external assets, no network required). It includes severity charts, a filterable findings list, per-finding evidence with the offending code snippet, and the proposed fix template. Each run writes a timestamped file to `reports/` so previous reports are preserved.

## How to respond to the user

After the command runs, tell the user the report was written to `reports/findings-<timestamp>.html`. If it didn't auto-open in their browser, give them the platform-specific open command:

- macOS: `open reports/findings-<timestamp>.html`
- Linux: `xdg-open reports/findings-<timestamp>.html`
- Windows: `start reports/findings-<timestamp>.html`

Don't list individual findings inline — the whole point is the HTML view.

🛡  agentic-security · created by ClearCapabilities.Com
