"""
report.py — render findings for humans and for machines.

The text renderer sorts worst-first and always prints the remedy for anything that is not a pass.
A report that requires you to already know what to do about a failure has not finished its job.
"""
from __future__ import annotations

import json

from .model import Severity, Status

_COLOR = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m",
          "SKIP": "\033[90m", "ERROR": "\033[35m"}
_RESET = "\033[0m"


def _paint(text, status, color):
    return f"{_COLOR[status.name]}{text}{_RESET}" if color else text


def text(findings, counts=None, verbose=False, color=True, show_passes=True):
    """Human-readable report. Worst first, remedies always shown for non-passes."""
    lines = []
    order = sorted(findings,
                   key=lambda f: (-f.status.value, -f.severity.value, f.check_id))
    for f in order:
        if f.status is Status.PASS and not show_passes:
            continue
        head = f"  {_paint(f.status.symbol, f.status, color)} [{f.severity.name:8}] {f.check_id}"
        lines.append(f"{head}  {f.summary}")
        if f.detail and (verbose or f.status is not Status.PASS):
            for chunk in f.detail.splitlines():
                lines.append(f"        {chunk}")
        if f.remedy and f.status is not Status.PASS:
            lines.append(f"        → {f.remedy}")
        if verbose and f.evidence:
            lines.append(f"        evidence: {json.dumps(f.evidence, default=str)[:400]}")

    if counts:
        lines.append("")
        summary = "  ".join(f"{k.lower()}={v}" for k, v in counts.items() if v)
        lines.append(f"  {summary or 'nothing ran'}")
    return "\n".join(lines)


def as_json(findings, counts=None, meta=None):
    return json.dumps({
        "meta": meta or {},
        "counts": counts or {},
        "findings": [f.to_dict() for f in findings],
    }, indent=2, default=str)


def banner(ok, exit_code, mode, threshold=Severity.HIGH, color=True):
    """The one line someone reads if they read nothing else."""
    if exit_code == 2:
        msg = "ERRORED — one or more checks could not reach a conclusion. Treated as failure."
        col = "\033[35m"
    elif ok:
        msg = f"CLEAR — no blocking findings at or above {threshold.name}."
        col = "\033[32m"
    else:
        msg = f"BLOCKED — at least one finding at or above {threshold.name}. Do not proceed."
        col = "\033[31m"
    line = f"[{mode.upper()}] {msg}"
    return f"{col}{line}{_RESET}" if color else line
