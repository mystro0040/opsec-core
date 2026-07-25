"""
checks.py — the default check library, plus factories for building your own.

Everything here is GENERAL PURPOSE. Nothing knows about any particular provider, tool, or campaign.
Opinionated checks (does this VPN hold, is this scope respected, is this vendor's AUP satisfied)
belong in a campaign package, not here — that separation is what keeps this repo useful to someone
who shares none of your infrastructure.

The hard checks in this file are LOCAL INTROSPECTION ONLY: they read interfaces, routes, and
listening sockets on the machine they run on. They do not send traffic anywhere. Determining what
the outside world sees requires talking to something outside, which is a policy decision (which
service? do you trust it?) and therefore belongs to a campaign.
"""
from __future__ import annotations

import os
import re
import socket
import stat
import subprocess

from .model import Mode, Severity, failed, passed, skipped, warned
from .registry import CheckRegistry


# =============================================================================
# Factories — build a check from a declarative rule. Campaigns use these heavily.
# =============================================================================
def require_pattern(check_id, title, path_name, pattern, severity=Severity.HIGH,
                    remedy="", flags=re.MULTILINE, tags=("static",)):
    """Assert a regex IS present in a registered file. Absence is the failure."""
    rx = re.compile(pattern, flags)

    def _check(ctx):
        target = ctx.paths.resolve(path_name)
        with open(target, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        if rx.search(body):
            return passed(check_id, f"{title}: present", severity=severity, path=target)
        return failed(check_id, f"{title}: MISSING", severity=severity,
                      detail=f"pattern {pattern!r} not found in {target}",
                      remedy=remedy or f"Add the required setting to {target}.", path=target)

    _check.__name__ = check_id.replace(".", "_")
    return dict(id=check_id, title=title, fn=_check, mode=Mode.SOFT,
                severity=severity, tags=tags, requires_paths=(path_name,))


def forbid_pattern(check_id, title, path_name, pattern, severity=Severity.CRITICAL,
                   remedy="", flags=re.MULTILINE, tags=("static",)):
    """Assert a regex is NOT present. Presence is the failure.

    This is the shape most safety rules take: a disabled guard, a commented-out limit, a debug flag
    left on. Write the dangerous state as the pattern, not the safe one.
    """
    rx = re.compile(pattern, flags)

    def _check(ctx):
        target = ctx.paths.resolve(path_name)
        with open(target, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
        hits = [(i + 1, ln.strip()[:160]) for i, ln in enumerate(lines) if rx.search(ln)]
        if not hits:
            return passed(check_id, f"{title}: clean", severity=severity, path=target)
        return failed(check_id, f"{title}: FOUND ({len(hits)})", severity=severity,
                      detail="; ".join(f"line {n}: {t}" for n, t in hits[:5]),
                      remedy=remedy or f"Remove the offending line(s) from {target}.",
                      path=target, hits=hits[:20])

    _check.__name__ = check_id.replace(".", "_")
    return dict(id=check_id, title=title, fn=_check, mode=Mode.SOFT,
                severity=severity, tags=tags, requires_paths=(path_name,))


def require_config(check_id, title, dotted_key, expected=None, severity=Severity.HIGH,
                   remedy="", tags=("static",)):
    """Assert a config key exists, and optionally equals a value (or satisfies a callable)."""
    def _check(ctx):
        value = ctx.cfg(dotted_key, _MISSING)
        if value is _MISSING:
            return failed(check_id, f"{title}: config key {dotted_key!r} not set",
                          severity=severity, remedy=remedy or f"Set {dotted_key} in your config.")
        if expected is None:
            return passed(check_id, f"{title}: {dotted_key}={value!r}", severity=severity)
        ok = expected(value) if callable(expected) else (value == expected)
        if ok:
            return passed(check_id, f"{title}: {dotted_key}={value!r}", severity=severity)
        return failed(check_id, f"{title}: {dotted_key}={value!r}, expected {expected!r}",
                      severity=severity, remedy=remedy or f"Set {dotted_key} correctly.")

    _check.__name__ = check_id.replace(".", "_")
    return dict(id=check_id, title=title, fn=_check, mode=Mode.SOFT, severity=severity, tags=tags)


class _Missing:
    def __repr__(self):
        return "<unset>"


_MISSING = _Missing()


# =============================================================================
# Built-in checks
# =============================================================================
def register_builtins(registry: CheckRegistry, source="builtin"):
    """Install the default check library into a registry."""

    @registry.check("paths.exist", "All registered paths exist", mode=Mode.SOFT,
                    severity=Severity.HIGH, tags=("static", "hygiene"), source=source)
    def _paths_exist(ctx):
        missing = [p for p in ctx.paths.all() if not p.optional and not p.exists]
        if not missing:
            return passed("paths.exist", f"{len(ctx.paths)} registered path(s) present",
                          severity=Severity.HIGH)
        return failed("paths.exist", f"{len(missing)} registered path(s) MISSING",
                      severity=Severity.HIGH,
                      detail="; ".join(f"{p.name} -> {p.expanded}" for p in missing),
                      remedy="A registered path that vanished means some check is no longer "
                             "inspecting what it claims to. Restore the file, fix the "
                             "registration, or mark it optional if absence is genuinely fine.",
                      missing=[p.name for p in missing])

    @registry.check("paths.permissions", "Sensitive paths are not world-readable", mode=Mode.SOFT,
                    severity=Severity.HIGH, tags=("static", "hygiene"), source=source)
    def _paths_perms(ctx):
        loose = []
        for p in ctx.paths.all():
            if not p.exists or "secret" not in p.kind and p.kind != "key":
                continue
            mode = stat.S_IMODE(os.stat(p.expanded).st_mode)
            if mode & (stat.S_IRGRP | stat.S_IROTH):
                loose.append((p.name, oct(mode)))
        if not loose:
            return passed("paths.permissions", "secret/key paths are owner-only",
                          severity=Severity.HIGH)
        return failed("paths.permissions", f"{len(loose)} secret path(s) readable by others",
                      severity=Severity.HIGH,
                      detail="; ".join(f"{n} mode {m}" for n, m in loose),
                      remedy="chmod 600 the listed files.", loose=loose)

    @registry.check("host.interfaces", "Enumerate local network interfaces", mode=Mode.HARD,
                    severity=Severity.INFO, tags=("probe", "host"), source=source)
    def _interfaces(ctx):
        try:
            names = [n for _idx, n in socket.if_nameindex()]
        except (AttributeError, OSError) as exc:
            return skipped("host.interfaces", "interface enumeration unsupported here",
                           severity=Severity.INFO, detail=str(exc))
        tunnels = [n for n in names if re.match(r"^(tun|tap|wg|ppp|utun|ipsec)", n)]
        return passed("host.interfaces", f"{len(names)} interface(s); {len(tunnels)} tunnel-like",
                      severity=Severity.INFO,
                      detail=f"interfaces: {', '.join(names)}",
                      interfaces=names, tunnels=tunnels)

    @registry.check("host.default_route", "Determine the default route", mode=Mode.HARD,
                    severity=Severity.INFO, tags=("probe", "host"), source=source)
    def _default_route(ctx):
        info = _read_default_route()
        if info is None:
            return skipped("host.default_route", "no readable routing table on this platform",
                           severity=Severity.INFO,
                           detail="/proc/net/route absent; this check is Linux-specific.")
        iface, gateway = info
        return passed("host.default_route", f"default via {gateway} dev {iface}",
                      severity=Severity.INFO, interface=iface, gateway=gateway)

    @registry.check("host.listeners", "Enumerate listening sockets", mode=Mode.HARD,
                    severity=Severity.LOW, tags=("probe", "host"), source=source)
    def _listeners(ctx):
        listeners = _read_listeners()
        if listeners is None:
            return skipped("host.listeners", "no readable socket table on this platform",
                           severity=Severity.LOW)
        external = [l for l in listeners if l["addr"] not in ("127.0.0.1", "::1")]
        if not external:
            return passed("host.listeners", f"{len(listeners)} listener(s), all loopback-bound",
                          severity=Severity.LOW, listeners=listeners)
        return warned("host.listeners", f"{len(external)} listener(s) bound beyond loopback",
                      severity=Severity.LOW,
                      detail="; ".join(f"{l['addr']}:{l['port']}" for l in external[:10]),
                      remedy="Confirm each is intentional. A scanning host should generally not be "
                             "offering services to the network.",
                      external=external)

    return registry


# --------------------------------------------------------------------------- helpers
def _read_default_route():
    """(iface, gateway) from /proc/net/route, or None if unavailable."""
    try:
        with open("/proc/net/route", encoding="utf-8") as fh:
            rows = fh.read().splitlines()[1:]
    except OSError:
        return None
    for row in rows:
        parts = row.split()
        if len(parts) > 2 and parts[1] == "00000000":       # destination 0.0.0.0 == default
            gw_le = parts[2]
            octets = [int(gw_le[i:i + 2], 16) for i in (6, 4, 2, 0)]
            return parts[0], ".".join(str(o) for o in octets)
    return None


def _read_listeners():
    """Listening TCP sockets from /proc/net/tcp{,6}, or None if unavailable."""
    out = []
    found_any = False
    for path, family in (("/proc/net/tcp", 4), ("/proc/net/tcp6", 6)):
        try:
            with open(path, encoding="utf-8") as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        found_any = True
        for row in rows:
            parts = row.split()
            if len(parts) < 4 or parts[3] != "0A":          # 0A == TCP_LISTEN
                continue
            hexaddr, hexport = parts[1].split(":")
            out.append({"addr": _hex_to_ip(hexaddr, family), "port": int(hexport, 16),
                        "family": family})
    return out if found_any else None


def _hex_to_ip(hexaddr, family):
    if family == 4:
        octets = [int(hexaddr[i:i + 2], 16) for i in (6, 4, 2, 0)]
        return ".".join(str(o) for o in octets)
    # /proc renders v6 as four little-endian 32-bit words
    words = [hexaddr[i:i + 8] for i in range(0, 32, 8)]
    groups = []
    for w in words:
        b = bytes.fromhex(w)[::-1]
        groups += [f"{b[0]:02x}{b[1]:02x}", f"{b[2]:02x}{b[3]:02x}"]
    addr = ":".join(groups)
    return "::1" if addr == "0000:0000:0000:0000:0000:0000:0000:0001" else addr
