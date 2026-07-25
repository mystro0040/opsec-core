#!/usr/bin/env python3
"""Convenience launcher so the tool runs from a checkout with no install:

    python3 opsec.py check
    python3 opsec.py check --hard

Equivalent to `python3 -m opsec` once the package is on sys.path.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from opsec.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
