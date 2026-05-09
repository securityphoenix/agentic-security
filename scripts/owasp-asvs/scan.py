#!/usr/bin/env python3
"""OWASP ASVS Level 1+2 compliance scanner.

Reuses scripts/_compliance_lib.py. Edit evidence-rules.json to extend the
control set or tune the per-control vocabulary.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _compliance_lib import run

if __name__ == "__main__":
    run(framework="OWASP ASVS Level 1+2", rules_path=os.path.join(HERE, "evidence-rules.json"))
