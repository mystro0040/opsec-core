"""
A worked example campaign. Copy this directory, rename it, and edit.

Run it against this repo's own example config:

    python3 opsec.py --config examples/example-config.json \
                     --campaign-dir examples check
    python3 opsec.py --config examples/example-config.json \
                     --campaign-dir examples check --hard

It demonstrates the three things a campaign does: register paths, register declarative checks
built from the factories, and register a custom check that computes something itself.
"""
import shutil

from opsec import Mode, Severity, failed, forbid_pattern, passed, require_pattern, warned
from opsec.registry import CheckSpec

NAME = "example"
DESCRIPTION = "Worked example — shows paths, declarative checks, and a custom check."


def register(ctx):
    # 1. Name the files this campaign cares about. Registering is also a declaration that the file
    #    must exist: if it disappears, checks that need it ERROR rather than quietly passing.
    ctx.paths.register("example_app_config", "examples/app.conf", kind="config",
                       note="the application config this campaign audits")

    # 2. Declarative checks. Note the forbid_pattern is written as the DANGEROUS state — that is
    #    the shape most real safety rules take (a guard switched off, a limit commented out).
    ctx.checks.register(CheckSpec(source="campaign:example", **require_pattern(
        "example.rate_limit_set", "A rate limit is configured",
        "example_app_config", r"^\s*rate_limit\s*=\s*[1-9]",
        severity=Severity.HIGH,
        remedy="Set rate_limit to a positive integer in examples/app.conf.")))

    ctx.checks.register(CheckSpec(source="campaign:example", **forbid_pattern(
        "example.debug_off", "Debug mode is not left on",
        "example_app_config", r"^\s*debug\s*=\s*(true|yes|1)\b",
        severity=Severity.CRITICAL,
        remedy="Set debug = false before running against anything real.")))

    # 3. A custom check. Anything callable(ctx) -> Finding works.
    @ctx.checks.check("example.disk_headroom", "Enough disk for a long run",
                      mode=Mode.HARD, severity=Severity.MEDIUM,
                      tags=("host",), source="campaign:example")
    def _disk(ctx):
        free_gib = shutil.disk_usage("/").free // (1024 ** 3)
        if free_gib >= 5:
            return passed("example.disk_headroom", f"{free_gib} GiB free", free_gib=free_gib)
        if free_gib >= 1:
            return warned("example.disk_headroom", f"only {free_gib} GiB free",
                          remedy="Free space before starting a long unattended run.")
        return failed("example.disk_headroom", "less than 1 GiB free",
                      severity=Severity.HIGH,
                      remedy="Free space now — output will be truncated or lost.")
