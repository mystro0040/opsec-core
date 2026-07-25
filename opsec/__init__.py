"""
opsec — verify that an operational setup is what it claims to be, before you rely on it.

A small, dependency-free framework for asking "what actually enforces this?" and getting a
checkable answer. Two modes:

    soft    static — parses files and config, emits nothing, safe to run anywhere
    hard    active — opens sockets, runs commands, probes remote hosts

The library is general-purpose. Everything opinionated — which provider, which policy, which
target — lives in a campaign package that plugs in at runtime.

Fails closed everywhere: a check that cannot reach a conclusion reports ERROR, and ERROR counts as
failure. "I could not tell" is never rendered as "yes".
"""
from .campaigns import CampaignError, load_config
from .checks import forbid_pattern, register_builtins, require_config, require_pattern
from .model import (Finding, Mode, Severity, Status, errored, failed, passed, skipped, warned)
from .registry import CheckRegistry, CheckSpec, Context, PathRegistry, RegistryError
from .runner import SoftModeViolation, run, run_check, verdict

__version__ = "0.1.0"

__all__ = [
    "Finding", "Mode", "Severity", "Status",
    "passed", "failed", "warned", "skipped", "errored",
    "Context", "CheckRegistry", "CheckSpec", "PathRegistry", "RegistryError",
    "run", "run_check", "verdict", "SoftModeViolation",
    "register_builtins", "require_pattern", "forbid_pattern", "require_config",
    "load_config", "CampaignError",
    "__version__",
]
