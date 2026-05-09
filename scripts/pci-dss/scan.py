#!/usr/bin/env python3
"""PCI-DSS 4.0 code-testable controls scanner."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _compliance_lib import run

if __name__ == "__main__":
    run(framework="PCI-DSS 4.0 (code-testable)", rules_path=os.path.join(HERE, "evidence-rules.json"))
