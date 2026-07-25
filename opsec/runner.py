"""
runner.py — execute selected checks and collect findings, failing closed throughout.

Two properties this module is responsible for, both enforced rather than documented:

1. FAIL CLOSED. Any way a check can fail to reach a conclusion — raising, timing out, referencing a
   missing registered path — produces ERROR, and ERROR counts as failure. There is no path through
   this file that turns "I could not tell" into PASS.

2. SOFT REALLY MEANS SOFT. `--soft` is meant to be safe to run on a machine that must not emit a
   packet. Labelling a check SOFT does not make it so, so during soft runs the socket layer is
   swapped for one that raises. A SOFT check that tries to open a connection fails loudly with
   SoftModeViolation instead of quietly reaching the network.

   That guard is process-wide and monkeypatch-based, which is blunt. It is worth it: the label is
   the kind of thing that rots, and a check silently gaining a network call during a refactor is
   precisely the drift this framework exists to catch. It cannot stop a check that shells out to
   `curl` — see _SUBPROCESS_NOTE below for how that case is handled.
"""
from __future__ import annotations

import socket
import subprocess
import time

from .model import Finding, Mode, Severity, Status, errored
from .registry import CheckSpec, Context, RegistryError


class SoftModeViolation(RuntimeError):
    """A check declared SOFT attempted network or subprocess activity."""


# In soft mode we also block subprocess, because shelling out to curl/dig/ssh is the obvious way to
# reach the network without touching Python's socket module. Static checks legitimately need to read
# files, not to run programs — so the restriction costs nothing real.
_SUBPROCESS_NOTE = "soft mode blocks subprocess as well as sockets; use a HARD check to run commands"


class _SoftGuard:
    """Context manager that makes network and subprocess access raise for the duration."""

    def __init__(self, active=True):
        self.active = active
        self._saved = {}

    def __enter__(self):
        if not self.active:
            return self

        def deny(what):
            def _raise(*_a, **_k):
                raise SoftModeViolation(
                    f"soft mode attempted {what}. A SOFT check must be static only — it reads "
                    f"files and parses config, and never emits traffic or runs a program. "
                    f"Declare this check mode=Mode.HARD if it genuinely needs to probe.")
            return _raise

        self._saved = {
            "socket.socket": socket.socket,
            "socket.create_connection": socket.create_connection,
            "socket.getaddrinfo": socket.getaddrinfo,
            "subprocess.run": subprocess.run,
            "subprocess.Popen": subprocess.Popen,
        }
        socket.socket = deny("a socket() call")
        socket.create_connection = deny("an outbound connection")
        socket.getaddrinfo = deny("a DNS lookup")           # DNS is traffic, and the loudest kind
        subprocess.run = deny(f"a subprocess ({_SUBPROCESS_NOTE})")
        subprocess.Popen = deny(f"a subprocess ({_SUBPROCESS_NOTE})")
        return self

    def __exit__(self, *_exc):
        if not self.active:
            return False
        socket.socket = self._saved["socket.socket"]
        socket.create_connection = self._saved["socket.create_connection"]
        socket.getaddrinfo = self._saved["socket.getaddrinfo"]
        subprocess.run = self._saved["subprocess.run"]
        subprocess.Popen = self._saved["subprocess.Popen"]
        return False


def _as_findings(result, spec: CheckSpec) -> list[Finding]:
    """Normalise whatever a check returned into a list of Findings, failing closed on nonsense."""
    if result is None:
        return [errored(spec.id, "check returned nothing",
                        severity=spec.severity,
                        detail="A check must return a Finding or a list of Findings. Returning "
                               "None is ambiguous, so it is treated as an error rather than a pass.",
                        remedy=f"Fix {spec.id} to return an explicit Finding.")]
    findings = result if isinstance(result, (list, tuple)) else [result]
    out = []
    for f in findings:
        if not isinstance(f, Finding):
            out.append(errored(spec.id, "check returned a non-Finding value",
                               severity=spec.severity,
                               detail=f"got {type(f).__name__}: {str(f)[:120]}",
                               remedy=f"Fix {spec.id} to return Finding objects."))
        else:
            out.append(f)
    return out


def run_check(spec: CheckSpec, ctx: Context) -> list[Finding]:
    """Run one check. Never raises — every failure mode becomes an ERROR finding."""
    # Preconditions: a registered path that is missing means this check did not actually inspect
    # what it claims to inspect. That is an error, not a pass.
    for path_name in spec.requires_paths:
        try:
            ctx.paths.resolve(path_name)
        except RegistryError as exc:
            return [errored(spec.id, f"required path {path_name!r} unavailable",
                            severity=spec.severity, detail=str(exc),
                            remedy=f"Register or restore {path_name!r}, or mark it optional if its "
                                   f"absence is genuinely acceptable.")]

    soft = ctx.mode == "soft"
    started = time.monotonic()
    try:
        with _SoftGuard(active=soft):
            result = spec.fn(ctx)
        return _as_findings(result, spec)
    except SoftModeViolation as exc:
        return [errored(spec.id, "SOFT check attempted active probing", severity=Severity.HIGH,
                        detail=str(exc),
                        remedy="Change this check's mode to Mode.HARD, or remove the network call.")]
    except Exception as exc:                      # noqa: BLE001 — deliberate: unknown == failure
        return [errored(spec.id, f"check raised {type(exc).__name__}", severity=spec.severity,
                        detail=str(exc)[:500],
                        remedy="A check that cannot complete is reported as failure, never as a "
                               "pass. Fix the check or the condition it stumbled on.")]
    finally:
        ctx.extras.setdefault("_timings", {})[spec.id] = round(time.monotonic() - started, 4)


def run(ctx: Context, specs=None) -> list[Finding]:
    """Run the selected checks (default: everything valid for ctx.mode)."""
    specs = specs if specs is not None else ctx.checks.select(mode=ctx.mode)
    findings = []
    for spec in specs:
        findings.extend(run_check(spec, ctx))
    return findings


# --------------------------------------------------------------------------- verdict
def verdict(findings, threshold=Severity.HIGH):
    """(ok, exit_code, counts) for a set of findings.

    ok is False if ANY finding is not-ok at or above `threshold`. Default HIGH means MEDIUM issues
    are reported but do not block; CRITICAL and HIGH do. Exit code 0 clean, 1 blocked, 2 means
    something errored — distinguished because "the checks broke" and "the checks say no" call for
    different responses from a human.
    """
    counts = {s.name: 0 for s in Status}
    blocking = False
    any_error = False
    for f in findings:
        counts[f.status.name] += 1
        if f.status is Status.ERROR:
            any_error = True
        if not f.status.ok and f.severity.value >= threshold.value:
            blocking = True
    if any_error:
        return False, 2, counts
    return (not blocking), (1 if blocking else 0), counts
