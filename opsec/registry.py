"""
registry.py — the two registries: paths to inspect, and checks to run.

PATH REGISTRY
    Names the files this framework cares about, so checks refer to "the executor config" rather
    than hardcoding a path. Registering a path is also a declaration that it MUST exist: a
    registered, non-optional path that is missing is itself a finding, not a silent skip. That is
    how a deleted or renamed config becomes visible instead of quietly disabling a check.

CHECK REGISTRY
    Holds check objects keyed by id. Checks come from three places, in increasing specificity:
    builtins, campaign packages, and the operator's own modules. Later registrations of the same id
    REPLACE earlier ones, which is what lets a campaign tighten a default — but replacement is
    recorded and surfaced by `opsec checks --overrides`, because silently swapping out a safety
    check is exactly the move this framework exists to catch.
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field

from .model import Mode, Severity


class RegistryError(RuntimeError):
    pass


# --------------------------------------------------------------------------- paths
@dataclass
class RegisteredPath:
    name: str
    path: str
    kind: str = "config"          # config | code | data | script | dir — free-form, for filtering
    optional: bool = False        # if False, absence is a finding
    note: str = ""

    @property
    def expanded(self) -> str:
        return os.path.expanduser(os.path.expandvars(self.path))

    @property
    def exists(self) -> bool:
        return os.path.exists(self.expanded)


class PathRegistry:
    def __init__(self):
        self._paths: dict[str, RegisteredPath] = {}

    def register(self, name, path, kind="config", optional=False, note=""):
        if name in self._paths and self._paths[name].expanded != os.path.expanduser(path):
            raise RegistryError(
                f"path {name!r} is already registered to {self._paths[name].path!r}; "
                f"refusing to silently repoint it to {path!r}. Use a different name, or "
                f"unregister the first one explicitly.")
        rp = RegisteredPath(name=name, path=path, kind=kind, optional=optional, note=note)
        self._paths[name] = rp
        return rp

    def get(self, name) -> RegisteredPath:
        try:
            return self._paths[name]
        except KeyError:
            raise RegistryError(
                f"no path registered under {name!r}. Registered: "
                f"{', '.join(sorted(self._paths)) or '(none)'}") from None

    def resolve(self, name) -> str:
        """Absolute path, or raise if the path is registered-but-missing and not optional.

        Raising (rather than returning a path that isn't there) is what makes a check ERROR instead
        of quietly passing over a file it never actually read.
        """
        rp = self.get(name)
        if not rp.exists and not rp.optional:
            raise RegistryError(f"registered path {name!r} does not exist: {rp.expanded}")
        return rp.expanded

    def all(self, kind=None) -> list[RegisteredPath]:
        vals = list(self._paths.values())
        return [p for p in vals if p.kind == kind] if kind else vals

    def __contains__(self, name):
        return name in self._paths

    def __len__(self):
        return len(self._paths)


# --------------------------------------------------------------------------- checks
@dataclass
class CheckSpec:
    id: str
    title: str
    fn: object                       # callable(ctx) -> Finding | list[Finding] | None
    mode: Mode = Mode.SOFT
    severity: Severity = Severity.MEDIUM
    tags: tuple = ()
    source: str = "builtin"          # where it came from, for --overrides
    requires_paths: tuple = ()       # path names that must resolve before the check runs


class CheckRegistry:
    def __init__(self):
        self._checks: dict[str, CheckSpec] = {}
        self._overrides: list[tuple[str, str, str]] = []   # (id, replaced_source, new_source)

    def register(self, spec: CheckSpec):
        prior = self._checks.get(spec.id)
        if prior is not None:
            self._overrides.append((spec.id, prior.source, spec.source))
        self._checks[spec.id] = spec
        return spec

    def check(self, id, title, mode=Mode.SOFT, severity=Severity.MEDIUM, tags=(),
              source="builtin", requires_paths=()):
        """Decorator form:  @registry.check("net.egress", "Egress IP", mode=Mode.HARD)"""
        def deco(fn):
            self.register(CheckSpec(id=id, title=title, fn=fn, mode=mode,
                                    severity=Severity.parse(severity), tags=tuple(tags),
                                    source=source, requires_paths=tuple(requires_paths)))
            return fn
        return deco

    def get(self, id) -> CheckSpec:
        try:
            return self._checks[id]
        except KeyError:
            raise RegistryError(f"no check registered with id {id!r}") from None

    def select(self, mode=None, include=(), exclude=(), tags=()) -> list[CheckSpec]:
        """Pick checks by mode, id glob, and tag. Selection is explicit and order is stable."""
        out = []
        for spec in sorted(self._checks.values(), key=lambda s: s.id):
            if mode and not spec.mode.runs_in(mode):
                continue
            if include and not any(fnmatch.fnmatch(spec.id, pat) for pat in include):
                continue
            if any(fnmatch.fnmatch(spec.id, pat) for pat in exclude):
                continue
            if tags and not (set(tags) & set(spec.tags)):
                continue
            out.append(spec)
        return out

    @property
    def overrides(self) -> list:
        """Checks that were replaced after first registration. Visible on purpose."""
        return list(self._overrides)

    def all(self) -> list[CheckSpec]:
        return sorted(self._checks.values(), key=lambda s: s.id)

    def __len__(self):
        return len(self._checks)


@dataclass
class Context:
    """What a check gets handed. Deliberately small.

    `extras` is the extension point: a campaign that needs an SSH runner, a rate-limit client, or a
    scope object puts it here at load time, and its own checks read it back out. Core never looks
    inside, which is what keeps core general-purpose.
    """
    config: dict = field(default_factory=dict)
    paths: PathRegistry = field(default_factory=PathRegistry)
    checks: CheckRegistry = field(default_factory=CheckRegistry)
    mode: str = "soft"
    extras: dict = field(default_factory=dict)

    def cfg(self, dotted, default=None):
        """Read nested config by dotted key: ctx.cfg("remote.host")."""
        node = self.config
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node
