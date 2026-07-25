"""
model.py — the vocabulary everything else is written in.

Three ideas, deliberately small:

    Status    what a check concluded
    Severity  how much it matters if the conclusion is bad
    Finding   one conclusion, with enough evidence to act on it

THE DESIGN RULE THAT MATTERS: **fail closed.**

A check that cannot reach a conclusion is NOT a pass. If a probe errors, a file is missing, or a
check raises an exception nobody anticipated, the result is ERROR and ERROR is treated as failure.
This is the opposite of the usual convention and it is deliberate: this framework exists to answer
"is it safe to send traffic?", and "I could not tell" must never be rendered as "yes".

If you find yourself wanting a check to return PASS when it could not actually verify something,
what you want is SKIP with a reason — and SKIP is reported loudly, not hidden.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Status(enum.Enum):
    """What a check concluded. Ordered worst-last so max() finds the worst."""
    SKIP = 0     # deliberately not run (wrong mode, unmet precondition) — reported, never silent
    PASS = 1     # verified good
    WARN = 2     # not wrong, but worth a human look
    FAIL = 3     # verified bad
    ERROR = 4    # could not determine — treated as failure, see module docstring

    @property
    def ok(self) -> bool:
        """True only for outcomes that permit proceeding. SKIP is ok; ERROR never is."""
        return self in (Status.PASS, Status.SKIP)

    @property
    def symbol(self) -> str:
        return {"PASS": "✓", "FAIL": "✗", "WARN": "!", "SKIP": "-", "ERROR": "E"}[self.name]


class Severity(enum.Enum):
    """How much a bad conclusion matters. Drives exit codes and ordering."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4     # a CRITICAL failure means: do not send traffic

    @classmethod
    def parse(cls, value):
        if isinstance(value, cls):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}; expected one of "
                             f"{', '.join(s.name.lower() for s in cls)}") from None


class Mode(enum.Enum):
    """When a check is allowed to run.

    SOFT  static only — reads files, parses config, never touches the network or spawns a probe.
    HARD  active — opens sockets, runs commands, talks to remote hosts.
    BOTH  meaningful either way; the check inspects ctx.mode and adapts.

    The split exists so `--soft` is safe to run anywhere, at any time, including on a machine that
    must not emit a packet. A SOFT check that reaches the network is a bug, and the runner enforces
    this rather than trusting the label (see runner.SoftModeViolation).
    """
    SOFT = "soft"
    HARD = "hard"
    BOTH = "both"

    def runs_in(self, mode: str) -> bool:
        return self is Mode.BOTH or self.value == mode


@dataclass
class Finding:
    """One conclusion from one check.

    `remedy` is not decoration — a failure the operator cannot act on is only half a finding, and
    the point of this tool is to be actionable at 2am.
    """
    check_id: str
    status: Status
    summary: str
    severity: Severity = Severity.MEDIUM
    detail: str = ""
    remedy: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        """A finding that should stop the operation, not merely be noted."""
        return not self.status.ok and self.severity.value >= Severity.HIGH.value

    def to_dict(self) -> dict:
        return {"check_id": self.check_id, "status": self.status.name,
                "severity": self.severity.name, "summary": self.summary,
                "detail": self.detail, "remedy": self.remedy, "evidence": self.evidence}


# Convenience constructors — these read better at the call site than Finding(...) with six kwargs.
def _mk(status):
    def make(check_id, summary, severity=Severity.MEDIUM, detail="", remedy="", **evidence):
        return Finding(check_id=check_id, status=status, summary=summary,
                       severity=Severity.parse(severity), detail=detail, remedy=remedy,
                       evidence=evidence)
    return make


passed = _mk(Status.PASS)
failed = _mk(Status.FAIL)
warned = _mk(Status.WARN)
skipped = _mk(Status.SKIP)
errored = _mk(Status.ERROR)
