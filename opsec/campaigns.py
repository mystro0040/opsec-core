"""
campaigns.py — config loading and pluggable campaign discovery.

A CAMPAIGN is a directory containing `campaign.py` that exposes:

    NAME = "my-campaign"                # optional, defaults to the directory name
    DESCRIPTION = "what this covers"    # optional

    def register(ctx):
        '''Register paths and checks for this campaign. Called once at load.'''
        ctx.paths.register("my_config", "~/.config/thing/config.json", kind="config")
        ctx.checks.register(...)

That is the entire contract. A campaign may register paths, register checks, and stash objects in
`ctx.extras` for its own checks to use later — an SSH runner, a scope object, a rate-limit client.

WHY LOADING IS NOISY ON FAILURE: a campaign that fails to import is not skipped quietly. Its checks
were presumably the ones that mattered, and a silently short check list reads exactly like a clean
run. Import failure surfaces as a loud error and a non-zero exit.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from dataclasses import dataclass, field


class CampaignError(RuntimeError):
    pass


# --------------------------------------------------------------------------- config
def load_config(path=None):
    """Load a config file. JSON always; TOML when the interpreter provides tomllib (3.11+).

    Returns {} when no path is given — a config file is optional, because core is usable with
    nothing but registered paths and builtin checks.
    """
    if not path:
        return {}
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        raise CampaignError(f"config file not found: {path}")
    with open(path, "rb") as fh:
        raw = fh.read()
    if path.endswith(".toml"):
        try:
            import tomllib
        except ImportError:
            raise CampaignError(
                f"{path} is TOML but this interpreter has no tomllib (needs Python 3.11+). "
                f"Convert it to JSON or run on a newer Python.") from None
        return tomllib.loads(raw.decode("utf-8"))
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise CampaignError(f"{path} is not valid JSON: {exc}") from None


# --------------------------------------------------------------------------- campaigns
@dataclass
class LoadedCampaign:
    name: str
    path: str
    description: str = ""
    checks_added: int = 0
    paths_added: int = 0
    errors: list = field(default_factory=list)


def discover(dirs):
    """Find campaign directories under each given root.

    A directory qualifies if it contains campaign.py. Roots are searched one level deep, and a root
    that is itself a campaign is accepted directly, so both layouts work:

        campaigns/            <- root holding several
            recon/campaign.py
            audit/campaign.py

        my_campaign/campaign.py   <- passed directly
    """
    found = []
    for root in dirs:
        root = os.path.expanduser(root)
        if not os.path.isdir(root):
            continue
        if os.path.isfile(os.path.join(root, "campaign.py")):
            found.append(root)
            continue
        for entry in sorted(os.listdir(root)):
            cand = os.path.join(root, entry)
            if os.path.isfile(os.path.join(cand, "campaign.py")):
                found.append(cand)
    return found


def load(ctx, campaign_dir) -> LoadedCampaign:
    """Import one campaign and let it register into ctx. Raises CampaignError on failure."""
    mod_path = os.path.join(campaign_dir, "campaign.py")
    name = os.path.basename(campaign_dir.rstrip("/"))
    before_checks, before_paths = len(ctx.checks), len(ctx.paths)

    spec = importlib.util.spec_from_file_location(f"opsec_campaign_{name}", mod_path)
    if spec is None or spec.loader is None:
        raise CampaignError(f"cannot load campaign at {mod_path}")
    module = importlib.util.module_from_spec(spec)

    # Put the campaign's own directory on sys.path so it can import its sibling modules, then take
    # it back off. Leaving it there would let one campaign's helpers shadow another's.
    sys.path.insert(0, campaign_dir)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:                       # noqa: BLE001 — report, never swallow
        raise CampaignError(f"campaign {name!r} failed to import: {type(exc).__name__}: {exc}") from exc
    finally:
        if sys.path and sys.path[0] == campaign_dir:
            sys.path.pop(0)

    register = getattr(module, "register", None)
    if not callable(register):
        raise CampaignError(
            f"campaign {name!r} at {mod_path} has no register(ctx) function. That function is the "
            f"whole contract — without it the campaign registers nothing and its checks would be "
            f"silently absent from every run.")
    try:
        register(ctx)
    except Exception as exc:                       # noqa: BLE001
        raise CampaignError(f"campaign {name!r} register() raised {type(exc).__name__}: {exc}") from exc

    return LoadedCampaign(
        name=getattr(module, "NAME", name),
        path=campaign_dir,
        description=getattr(module, "DESCRIPTION", ""),
        checks_added=len(ctx.checks) - before_checks,
        paths_added=len(ctx.paths) - before_paths,
    )


def load_all(ctx, dirs, strict=True):
    """Discover and load every campaign under `dirs`.

    strict=True (default) re-raises the first failure. There is no partial-success mode by default:
    a run missing the checks it was supposed to perform must not look like a clean run.
    """
    loaded, failures = [], []
    for cdir in discover(dirs):
        try:
            loaded.append(load(ctx, cdir))
        except CampaignError as exc:
            if strict:
                raise
            failures.append((cdir, str(exc)))
    return loaded, failures
