"""
cli.py — the command-line interface. Works with no AI agent, no campaigns, and no config.

    opsec check                 soft (static) checks — safe anywhere, emits nothing
    opsec check --hard          active probing — opens sockets, runs commands
    opsec check --all           both passes in one run
    opsec checks                list what is registered, and what overrode what
    opsec paths                 list registered paths and whether they exist
    opsec campaigns             list discovered campaigns

SOFT IS THE DEFAULT, deliberately. `opsec check` with no flags must be safe to run on a machine
that is not supposed to emit a packet, so active probing is opt-in every single time. There is no
config setting that makes hard the default — a file you edited last month should not be able to
turn a safe command into one that sends traffic.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import campaigns as campaigns_mod
from . import report, runner
from .checks import register_builtins
from .model import Severity
from .registry import CheckRegistry, Context, PathRegistry

ENV_CONFIG = "OPSEC_CONFIG"
ENV_CAMPAIGNS = "OPSEC_CAMPAIGN_DIRS"


def build_context(args) -> tuple[Context, list]:
    """Assemble the context: config, builtins, campaigns, registered paths."""
    config = campaigns_mod.load_config(args.config)
    ctx = Context(config=config, paths=PathRegistry(), checks=CheckRegistry(), mode="soft")

    if not args.no_builtins:
        register_builtins(ctx.checks)

    # Paths declared in the config file itself, before campaigns, so a campaign can depend on them.
    for name, spec in (config.get("paths") or {}).items():
        if isinstance(spec, str):
            ctx.paths.register(name, spec)
        else:
            ctx.paths.register(name, spec["path"], kind=spec.get("kind", "config"),
                               optional=bool(spec.get("optional", False)),
                               note=spec.get("note", ""))

    dirs = list(args.campaign_dir or [])
    dirs += config.get("campaign_dirs") or []
    if os.environ.get(ENV_CAMPAIGNS):
        dirs += [d for d in os.environ[ENV_CAMPAIGNS].split(os.pathsep) if d]
    loaded, _ = campaigns_mod.load_all(ctx, dirs, strict=True)
    return ctx, loaded


def cmd_check(args) -> int:
    ctx, loaded = build_context(args)
    threshold = Severity.parse(args.threshold)
    modes = ["soft", "hard"] if args.all else (["hard"] if args.hard else ["soft"])

    all_findings = []
    color = not args.no_color and sys.stdout.isatty()

    # Say what is actually loaded, every run. A run that checks almost nothing and prints CLEAR is
    # the most dangerous output this tool can produce, so the scope of the run is never implicit.
    if not args.json:
        camp = ", ".join(c.name for c in loaded) or "none"
        print(f"  context: {len(ctx.checks)} check(s) registered · {len(ctx.paths)} path(s) · "
              f"campaigns: {camp}")
        if args.config and not loaded and not len(ctx.paths):
            print(f"  [!] {args.config} was loaded but registered no campaigns and no paths. "
                  f"If that is unexpected, the config is not being read the way you think.")

    for mode in modes:
        ctx.mode = mode
        specs = ctx.checks.select(mode=mode, include=args.include or (),
                                  exclude=args.exclude or (), tags=args.tag or ())
        if not specs:
            if not args.json:
                print(f"\n[{mode}] no checks selected.")
            continue
        findings = runner.run(ctx, specs)
        all_findings.extend(findings)
        if not args.json:
            print(f"\n[{mode}] {len(specs)} check(s)")
            print(report.text(findings, verbose=args.verbose, color=color,
                              show_passes=not args.quiet))

    ok, code, counts = runner.verdict(all_findings, threshold)

    if args.json:
        print(report.as_json(all_findings, counts, meta={
            "modes": modes, "threshold": threshold.name,
            "campaigns": [c.name for c in loaded],
            "checks_registered": len(ctx.checks)}))
    else:
        print()
        print(report.banner(ok, code, "+".join(modes), threshold, color=color))
        if code == 0 and "hard" not in modes:
            print("  Note: static checks only. Nothing was probed — run --hard before relying "
                  "on this to say traffic is safe.")
    return code


def cmd_checks(args) -> int:
    ctx, _ = build_context(args)
    if args.json:
        import json
        print(json.dumps([{"id": s.id, "title": s.title, "mode": s.mode.value,
                           "severity": s.severity.name, "tags": list(s.tags),
                           "source": s.source} for s in ctx.checks.all()], indent=2))
        return 0
    print(f"{len(ctx.checks)} check(s) registered\n")
    for s in ctx.checks.all():
        print(f"  {s.mode.value:5} {s.severity.name:8} {s.id:38} {s.title}")
        if args.verbose and s.tags:
            print(f"        tags: {', '.join(s.tags)}   source: {s.source}")
    overrides = ctx.checks.overrides
    if overrides:
        print(f"\n  {len(overrides)} check(s) were REPLACED after first registration:")
        for cid, old, new in overrides:
            print(f"    {cid}: {old} -> {new}")
        print("  Replacement is legitimate (a campaign tightening a default), but it is shown "
              "because silently swapping a safety check is worth noticing.")
    return 0


def cmd_paths(args) -> int:
    ctx, _ = build_context(args)
    if not len(ctx.paths):
        print("no paths registered (register them in config, or via a campaign)")
        return 0
    missing = 0
    for p in ctx.paths.all():
        mark = "ok " if p.exists else ("opt" if p.optional else "MISS")
        if not p.exists and not p.optional:
            missing += 1
        print(f"  {mark:4} {p.kind:8} {p.name:28} {p.expanded}")
    print(f"\n  {len(ctx.paths)} registered, {missing} missing and required")
    return 1 if missing else 0


def cmd_campaigns(args) -> int:
    ctx, loaded = build_context(args)
    if not loaded:
        print("no campaigns loaded (use --campaign-dir, config campaign_dirs, or "
              f"{ENV_CAMPAIGNS})")
        return 0
    for c in loaded:
        print(f"  {c.name:24} +{c.checks_added} check(s) +{c.paths_added} path(s)   {c.path}")
        if c.description:
            print(f"      {c.description}")
    return 0


def _common_flags(parser, suppress=False):
    """Flags valid both before and after the subcommand.

    Argparse puts parent-parser options only where you attach them, so `opsec check -v` fails if -v
    lives solely on the root. Both positions are natural to type, so the flags go on BOTH.

    THE TRAP, and why `suppress` exists: a subparser parses into the same namespace as the root, so
    a flag defined in both places has its subparser DEFAULT applied on top of whatever the root
    already parsed. `opsec --config x.json check` silently lost the config, loaded no campaigns,
    ran two builtin checks against nothing, and printed CLEAR — a false all-clear, which is the
    worst output this tool can produce.

    Giving the subparser copies `default=SUPPRESS` means an unset flag sets no attribute at all, so
    the root's value survives and an explicitly-passed one still wins.
    """
    default = argparse.SUPPRESS if suppress else None
    env_default = argparse.SUPPRESS if suppress else os.environ.get(ENV_CONFIG)
    store_true_default = argparse.SUPPRESS if suppress else False

    parser.add_argument("--config", default=env_default,
                        help=f"config file (JSON, or TOML on 3.11+). Env: {ENV_CONFIG}")
    parser.add_argument("--campaign-dir", action="append", metavar="DIR", default=default,
                        help="directory holding campaign(s); repeatable")
    parser.add_argument("--no-builtins", action="store_true", default=store_true_default,
                        help="skip the default check library (campaigns only)")
    parser.add_argument("--json", action="store_true", default=store_true_default,
                        help="machine-readable output")
    parser.add_argument("-v", "--verbose", action="store_true", default=store_true_default)
    parser.add_argument("--no-color", action="store_true", default=store_true_default)
    return parser


def make_parser():
    p = argparse.ArgumentParser(
        prog="opsec",
        description="Verify that an operational setup is what it claims to be, before you rely "
                    "on it. Soft checks parse config; hard checks probe. Fails closed.")
    _common_flags(p)
    common = _common_flags(argparse.ArgumentParser(add_help=False), suppress=True)

    sub = p.add_subparsers(dest="command")

    c = sub.add_parser("check", parents=[common], help="run checks (soft by default)")
    g = c.add_mutually_exclusive_group()
    g.add_argument("--hard", action="store_true", help="active probing — sends traffic, runs commands")
    g.add_argument("--all", action="store_true", help="run soft then hard")
    c.add_argument("--threshold", default="high",
                   help="minimum severity that blocks: info|low|medium|high|critical (default high)")
    c.add_argument("--include", action="append", metavar="GLOB", help="only ids matching (repeatable)")
    c.add_argument("--exclude", action="append", metavar="GLOB", help="skip ids matching (repeatable)")
    c.add_argument("--tag", action="append", help="only checks carrying this tag (repeatable)")
    c.add_argument("-q", "--quiet", action="store_true", help="hide passing checks")
    c.set_defaults(func=cmd_check)

    for name, fn, helptext in (("checks", cmd_checks, "list registered checks"),
                               ("paths", cmd_paths, "list registered paths"),
                               ("campaigns", cmd_campaigns, "list loaded campaigns")):
        s = sub.add_parser(name, parents=[common], help=helptext)
        s.set_defaults(func=fn)
    return p


def main(argv=None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except campaigns_mod.CampaignError as exc:
        # A campaign that will not load means the checks it carries did not run. Reporting that as
        # anything other than a hard failure would let a short run masquerade as a clean one.
        print(f"\n[!] campaign error: {exc}", file=sys.stderr)
        print("    Refusing to report results from an incomplete check set.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
