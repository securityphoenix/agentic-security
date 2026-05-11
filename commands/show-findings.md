---
description: Generate an interactive HTML report of every finding and open it in the default browser.
argument-hint: "[path]"
---

Render every finding from a scan as a self-contained interactive HTML report and try to open it in the default browser.

```bash
mkdir -p .agentic-security
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan ${1:-.} --format html --output .agentic-security/findings.html
ec=$?
if [ $ec -le 3 ]; then
  open .agentic-security/findings.html 2>/dev/null \
    || xdg-open .agentic-security/findings.html 2>/dev/null \
    || echo "Open .agentic-security/findings.html in your browser to view the report."
  exit 0
fi
exit $ec
```

The HTML report is self-contained (no external assets, no network required). It includes severity charts, a filterable findings list, per-finding evidence with the offending code snippet, and the proposed fix template.

## How to respond to the user

After the command runs, tell the user the report was written to `.agentic-security/findings.html`. If it didn't auto-open in their browser, give them the platform-specific open command:

- macOS: `open .agentic-security/findings.html`
- Linux: `xdg-open .agentic-security/findings.html`
- Windows: `start .agentic-security/findings.html`

Don't list individual findings inline — the whole point is the HTML view.

🛡  agentic-security · created by ClearCapabilities.Com
