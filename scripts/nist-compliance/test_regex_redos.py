#!/usr/bin/env python3
"""ReDoS regression test for the import-detection regexes (premortem 4R-14).

The original GO_IMPORT_RE used `(?:[^)]|\\n)+?` which was ambiguous —
`[^)]` already matches `\\n` in Python re, so each newline could match
either alternative. With a non-terminating `import (` + many newlines, the
engine backtracked exponentially.

This test asserts: every import regex in scan.py runs in linear time on a
pathological input of 5000 newlines. The 500ms bound is generous; the post-
fix regexes complete in ~100ms.
"""
from __future__ import annotations
import re
import sys
import time
from pathlib import Path


def _load_module():
    # Load scan.py as a module without running its CLI.
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    import scan  # type: ignore
    return scan


def _assert_linear(name: str, regex: re.Pattern[str], payload: str, budget_ms: int = 500) -> None:
    t0 = time.monotonic()
    regex.search(payload)
    elapsed_ms = (time.monotonic() - t0) * 1000
    assert elapsed_ms < budget_ms, (
        f"{name} took {elapsed_ms:.1f}ms on pathological input — possible ReDoS regression. "
        f"Budget {budget_ms}ms."
    )


def main() -> int:
    scan = _load_module()
    payload_go = " import (" + ("\n" * 5000)
    payload_py = ("from " + "a" * 100 + ".") * 200
    payload_js = "import { foo } from '" + ("x" * 1000) + "'"

    _assert_linear("GO_IMPORT_RE", scan.GO_IMPORT_RE, payload_go)
    _assert_linear("PY_IMPORT_RE", scan.PY_IMPORT_RE, payload_py)
    _assert_linear("JS_IMPORT_RE", scan.JS_IMPORT_RE, payload_js)
    _assert_linear("RUBY_IMPORT_RE", scan.RUBY_IMPORT_RE, payload_py)
    print("OK: all import regexes run in linear time on pathological input.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
