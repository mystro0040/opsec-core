#!/usr/bin/env python3
"""
test_opsec_core.py — regression tests for the opsec core engine.

The properties worth defending are not "does it produce output" but:

  * FAIL CLOSED — every way a check can fail to conclude ends as ERROR, never PASS.
  * SOFT MEANS SOFT — a check labelled static that reaches the network is caught, not trusted.
  * REGISTRIES DON'T LIE — a missing path or a swapped check is visible, not silent.

Pure stdlib. Isolated: temp dirs only, no network, no writes to tracked files.
Run directly:  python3 test_opsec_core.py   (exit 0 = all pass)
"""
import os
import socket
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from opsec import (CheckRegistry, Context, Mode, PathRegistry, RegistryError,  # noqa: E402
                   Severity, Status, failed, passed, register_builtins, run, verdict)
from opsec import campaigns as campaigns_mod  # noqa: E402
from opsec import checks as checks_mod  # noqa: E402
from opsec.registry import CheckSpec  # noqa: E402
from opsec.runner import run_check  # noqa: E402

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def _ctx(mode="soft"):
    c = Context(paths=PathRegistry(), checks=CheckRegistry(), mode=mode)
    return c


def _spec(fn, cid="t.check", mode=Mode.SOFT, severity=Severity.HIGH, requires=()):
    return CheckSpec(id=cid, title="t", fn=fn, mode=mode, severity=severity,
                     requires_paths=tuple(requires))


# =============================================================================
def test_fail_closed():
    """Every route to 'could not determine' must end at ERROR, never at PASS."""
    print("[runner] fail closed — 'could not tell' is never 'yes'")
    ctx = _ctx()

    def raiser(_c):
        raise ValueError("boom")

    f = run_check(_spec(raiser), ctx)[0]
    chk("a raising check -> ERROR", f.status is Status.ERROR, f.status)
    chk("the exception text is preserved", "boom" in f.detail, f.detail)

    f = run_check(_spec(lambda c: None), ctx)[0]
    chk("a check returning None -> ERROR", f.status is Status.ERROR, f.status)

    f = run_check(_spec(lambda c: "looks fine to me"), ctx)[0]
    chk("a check returning a non-Finding -> ERROR", f.status is Status.ERROR, f.status)

    chk("ERROR is not 'ok'", Status.ERROR.ok is False)
    chk("FAIL is not 'ok'", Status.FAIL.ok is False)
    chk("SKIP IS 'ok' (deliberate, and reported)", Status.SKIP.ok is True)

    # An ERROR anywhere forces exit 2 even when nothing else is wrong, because "the checks broke"
    # and "the checks say no" need different human responses.
    findings = [passed("a", "fine", severity=Severity.LOW),
                run_check(_spec(raiser), ctx)[0]]
    ok, code, _ = verdict(findings)
    chk("any ERROR -> not ok, exit 2", (ok is False) and code == 2, (ok, code))


def test_missing_required_path():
    """A check whose input vanished did not inspect anything. That is an error, not a pass."""
    print("[runner] a missing required path fails the check, never passes it")
    ctx = _ctx()
    ctx.paths.register("gone", "/nonexistent/definitely/not/here.conf")
    f = run_check(_spec(lambda c: passed("t.check", "never reached"), requires=("gone",)), ctx)[0]
    chk("missing required path -> ERROR", f.status is Status.ERROR, f.status)
    chk("names the path in the summary", "gone" in f.summary, f.summary)

    # optional paths are allowed to be absent
    ctx2 = _ctx()
    ctx2.paths.register("maybe", "/nonexistent/ok.conf", optional=True)
    f2 = run_check(_spec(lambda c: passed("t.check", "ran"), requires=("maybe",)), ctx2)[0]
    chk("optional missing path does not block the check", f2.status is Status.PASS, f2.status)


def test_soft_guard_blocks_network():
    """SOFT is a promise the runner keeps, not a label it trusts."""
    print("[runner] soft mode physically cannot reach the network")
    ctx = _ctx(mode="soft")

    def opens_socket(_c):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return passed("t.check", "should never be reached")

    def resolves_dns(_c):
        socket.getaddrinfo("example.com", 80)
        return passed("t.check", "should never be reached")

    def shells_out(_c):
        subprocess.run(["curl", "https://example.com"], capture_output=True)
        return passed("t.check", "should never be reached")

    for fn, label in ((opens_socket, "socket()"), (resolves_dns, "DNS lookup"),
                      (shells_out, "subprocess")):
        f = run_check(_spec(fn), ctx)[0]
        chk(f"soft check attempting {label} -> ERROR", f.status is Status.ERROR, f.status)
        chk(f"...and is flagged as a soft violation ({label})",
            "SOFT" in f.summary or "soft" in f.detail.lower(), f.summary)

    # The same check in hard mode is allowed to try (it may still fail on its merits).
    hard_ctx = _ctx(mode="hard")
    f = run_check(_spec(opens_socket, mode=Mode.HARD), hard_ctx)[0]
    chk("the identical check is permitted in HARD mode", f.status is Status.PASS, f.status)


def test_soft_guard_restores():
    """The guard must not leak: a soft run followed by a hard run has to work."""
    print("[runner] the soft guard is fully restored afterwards")
    real_socket, real_run = socket.socket, subprocess.run
    ctx = _ctx(mode="soft")
    run_check(_spec(lambda c: passed("t.check", "ok")), ctx)
    chk("socket.socket restored after a clean soft run", socket.socket is real_socket)
    chk("subprocess.run restored after a clean soft run", subprocess.run is real_run)

    def raiser(_c):
        socket.socket()

    run_check(_spec(raiser), ctx)
    chk("socket.socket restored even when the check raised", socket.socket is real_socket)
    chk("subprocess.run restored even when the check raised", subprocess.run is real_run)


def test_path_registry():
    print("[registry] paths cannot be silently repointed")
    pr = PathRegistry()
    pr.register("a", "/tmp/a.conf")
    try:
        pr.register("a", "/tmp/somewhere-else.conf")
        chk("repointing a registered name raises", False, "no raise")
    except RegistryError:
        chk("repointing a registered name raises", True)
    pr.register("a", "/tmp/a.conf")          # same target is a harmless no-op
    chk("re-registering the same target is allowed", True)

    try:
        pr.resolve("never-registered")
        chk("resolving an unknown name raises", False, "no raise")
    except RegistryError:
        chk("resolving an unknown name raises", True)


def test_check_registry_overrides_and_select():
    print("[registry] overrides are recorded; selection is explicit")
    cr = CheckRegistry()
    cr.register(CheckSpec(id="x", title="orig", fn=lambda c: None, source="builtin"))
    chk("no overrides on first registration", cr.overrides == [])
    cr.register(CheckSpec(id="x", title="replacement", fn=lambda c: None, source="campaign:acme"))
    chk("replacing a check id is recorded", len(cr.overrides) == 1, cr.overrides)
    chk("...with both sources named", cr.overrides[0][1:] == ("builtin", "campaign:acme"),
        cr.overrides)

    cr.register(CheckSpec(id="net.a", title="a", fn=lambda c: None, mode=Mode.HARD, tags=("net",)))
    cr.register(CheckSpec(id="net.b", title="b", fn=lambda c: None, mode=Mode.SOFT, tags=("net",)))
    cr.register(CheckSpec(id="fs.a", title="c", fn=lambda c: None, mode=Mode.BOTH))
    # "x" was registered without an explicit mode, so it defaults to SOFT and must NOT appear here.
    chk("mode filter excludes the wrong mode (incl. the SOFT default)",
        {s.id for s in cr.select(mode="hard")} == {"net.a", "fs.a"},
        [s.id for s in cr.select(mode="hard")])
    chk("an unspecified mode defaults to SOFT, not BOTH",
        "x" in {s.id for s in cr.select(mode="soft")})
    chk("BOTH runs in either mode", "fs.a" in {s.id for s in cr.select(mode="soft")})
    chk("include glob narrows", [s.id for s in cr.select(include=["net.*"])] == ["net.a", "net.b"])
    chk("exclude glob removes", "net.a" not in {s.id for s in cr.select(exclude=["net.a"])})
    chk("tag filter selects", {s.id for s in cr.select(tags=["net"])} == {"net.a", "net.b"})


def test_pattern_factories():
    print("[checks] require_pattern / forbid_pattern")
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "conf.ini")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("rate_limit = 10\ndebug = false\n")

        ctx = _ctx()
        ctx.paths.register("conf", target)

        spec = checks_mod.require_pattern("c.req", "rate limit set", "conf", r"^rate_limit\s*=\s*\d+")
        f = run_check(CheckSpec(**spec), ctx)[0]
        chk("require_pattern passes when present", f.status is Status.PASS, f.summary)

        spec = checks_mod.require_pattern("c.req2", "tls pinning", "conf", r"^pinning\s*=")
        f = run_check(CheckSpec(**spec), ctx)[0]
        chk("require_pattern fails when absent", f.status is Status.FAIL, f.summary)
        chk("...and offers a remedy", bool(f.remedy))

        spec = checks_mod.forbid_pattern("c.forbid", "debug left on", "conf", r"^debug\s*=\s*true")
        f = run_check(CheckSpec(**spec), ctx)[0]
        chk("forbid_pattern passes when the bad state is absent", f.status is Status.PASS)

        spec = checks_mod.forbid_pattern("c.forbid2", "rate limit present", "conf", r"^rate_limit")
        f = run_check(CheckSpec(**spec), ctx)[0]
        chk("forbid_pattern fails when the bad state is present", f.status is Status.FAIL)
        chk("...and reports the offending line number", "line 1" in f.detail, f.detail)


def test_verdict_threshold():
    print("[runner] verdict honours the blocking threshold")
    med = [failed("a", "medium problem", severity=Severity.MEDIUM)]
    ok, code, _ = verdict(med, threshold=Severity.HIGH)
    chk("MEDIUM failure does not block at threshold HIGH", ok and code == 0, (ok, code))
    ok, code, _ = verdict(med, threshold=Severity.MEDIUM)
    chk("...but does block at threshold MEDIUM", (not ok) and code == 1, (ok, code))

    crit = [failed("a", "critical", severity=Severity.CRITICAL)]
    ok, code, _ = verdict(crit, threshold=Severity.HIGH)
    chk("CRITICAL failure blocks", (not ok) and code == 1, (ok, code))
    chk("a clean set passes", verdict([passed("a", "fine")])[1] == 0)


def test_campaign_contract():
    print("[campaigns] a campaign that will not load is a hard failure, never a short run")
    with tempfile.TemporaryDirectory() as tmp:
        # 1. no register() at all
        bad = os.path.join(tmp, "noreg")
        os.makedirs(bad)
        with open(os.path.join(bad, "campaign.py"), "w", encoding="utf-8") as fh:
            fh.write("NAME = 'noreg'\n")
        try:
            campaigns_mod.load(_ctx(), bad)
            chk("campaign without register() raises", False, "no raise")
        except campaigns_mod.CampaignError as exc:
            chk("campaign without register() raises", True)
            chk("...and explains the contract", "register" in str(exc))

        # 2. import blows up
        broken = os.path.join(tmp, "broken")
        os.makedirs(broken)
        with open(os.path.join(broken, "campaign.py"), "w", encoding="utf-8") as fh:
            fh.write("raise RuntimeError('cannot start')\n")
        try:
            campaigns_mod.load(_ctx(), broken)
            chk("campaign failing to import raises", False, "no raise")
        except campaigns_mod.CampaignError:
            chk("campaign failing to import raises", True)

        # 3. a good one registers, and load_all(strict=True) still propagates the bad one
        good = os.path.join(tmp, "good")
        os.makedirs(good)
        with open(os.path.join(good, "campaign.py"), "w", encoding="utf-8") as fh:
            fh.write("NAME='good'\n"
                     "def register(ctx):\n"
                     "    ctx.paths.register('p', '/tmp')\n")
        ctx = _ctx()
        loaded = campaigns_mod.load(ctx, good)
        chk("a valid campaign registers its paths", loaded.paths_added == 1, loaded)

        try:
            campaigns_mod.load_all(_ctx(), [tmp], strict=True)
            chk("load_all(strict) propagates a broken campaign", False, "silently continued")
        except campaigns_mod.CampaignError:
            chk("load_all(strict) propagates a broken campaign", True)

        chk("discover() finds all three", len(campaigns_mod.discover([tmp])) == 3,
            campaigns_mod.discover([tmp]))


def test_global_flags_survive_subcommand():
    """A flag given before the subcommand must not be discarded by the subcommand's default.

    Regression: --config, --campaign-dir etc. are defined on BOTH the root parser and (via a
    parents= copy) on each subparser, so a user can type them in either position. But a subparser
    writes into the same namespace as the root, so its default was applied ON TOP of the root's
    parsed value. `opsec --config x.json check` silently lost the config, loaded zero campaigns,
    ran two builtin checks against nothing, and printed CLEAR.

    A false all-clear is the worst output this tool can produce, so both positions are tested, and
    so is the precedence when the flag appears twice.
    """
    print("[cli] flags before the subcommand are not clobbered by subparser defaults")
    from opsec.cli import make_parser

    a = make_parser().parse_args(["--config", "X.json", "check"])
    chk("--config BEFORE the subcommand survives", a.config == "X.json", a.config)

    b = make_parser().parse_args(["check", "--config", "X.json"])
    chk("--config AFTER the subcommand works", b.config == "X.json", b.config)

    c = make_parser().parse_args(["--config", "X.json", "check", "--config", "Y.json"])
    chk("the later (explicit) one wins when given twice", c.config == "Y.json", c.config)

    d = make_parser().parse_args(["-v", "check"])
    chk("-v before the subcommand survives", d.verbose is True, d.verbose)
    e = make_parser().parse_args(["check", "-v"])
    chk("-v after the subcommand works", e.verbose is True, e.verbose)
    f = make_parser().parse_args(["check"])
    chk("an unset store_true still defaults to False", f.verbose is False, f.verbose)

    g = make_parser().parse_args(["--campaign-dir", "d1", "check"])
    chk("--campaign-dir before the subcommand survives", g.campaign_dir == ["d1"], g.campaign_dir)


def test_builtins_and_cli_default():
    print("[cli] soft is the default; hard is always opt-in")
    from opsec.cli import make_parser
    args = make_parser().parse_args(["check"])
    chk("`opsec check` defaults to soft", args.hard is False and args.all is False)

    ctx = _ctx()
    register_builtins(ctx.checks)
    soft_ids = {s.id for s in ctx.checks.select(mode="soft")}
    hard_ids = {s.id for s in ctx.checks.select(mode="hard")}
    chk("no builtin probe is reachable in soft mode",
        not (soft_ids & {"host.interfaces", "host.default_route", "host.listeners"}), soft_ids)
    chk("the probes exist in hard mode",
        {"host.interfaces", "host.default_route", "host.listeners"} <= hard_ids, hard_ids)

    # Every soft builtin must survive the guard — i.e. genuinely be static.
    ctx.mode = "soft"
    findings = run(ctx, ctx.checks.select(mode="soft"))
    violations = [f for f in findings if f.status is Status.ERROR]
    chk("every builtin soft check is genuinely static", not violations,
        [f.summary for f in violations])


def main():
    for t in (test_fail_closed, test_missing_required_path, test_soft_guard_blocks_network,
              test_soft_guard_restores, test_path_registry,
              test_check_registry_overrides_and_select, test_pattern_factories,
              test_verdict_threshold, test_campaign_contract,
              test_global_flags_survive_subcommand, test_builtins_and_cli_default):
        t()
    print(f"\n{_PASS}/{_PASS + _FAIL} passed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
