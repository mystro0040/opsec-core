# opsec-core

Verify that an operational setup is actually what it claims to be — before you rely on it.

A small, dependency-free Python framework for turning "this is configured safely" from an
assertion into something you can check and get an exit code for. It runs as an ordinary CLI. There
is no agent, no daemon, and no service.

```
pip install .          # or just run it from a checkout: python3 opsec.py
opsec check            # static checks — parses files, emits nothing
opsec check --hard     # active probing — opens sockets, runs commands
opsec check --all      # both, in one run
```

## Why it exists

Most operational safety lives in prose: a comment saying traffic is routed somewhere, a README
saying a limit is enforced, a config key that looks like it does something. Prose rots silently,
and it rots in the direction of sounding more confident than the code.

This tool exists to ask one question repeatedly and mechanically: **what actually enforces this?**

## The two modes

| Mode | What it does | Safe to run where |
|---|---|---|
| **soft** (default) | Parses files and config. Emits nothing. | Anywhere, any time, including a machine that must not send a packet. |
| **hard** | Opens sockets, runs commands, probes hosts. | Only where active probing is acceptable. |

`opsec check` is soft by default and **there is no config setting that changes that** — a file you
edited last month should not be able to turn a safe command into one that sends traffic. Hard mode
is opt-in on every invocation.

Soft mode is enforced, not merely labelled: during a soft run the socket and subprocess layers are
replaced with ones that raise. A check declared static that tries to reach the network fails loudly
instead of quietly succeeding. The label is the kind of thing that rots during a refactor; the
guard doesn't.

## Fails closed

A check that cannot reach a conclusion reports `ERROR`, and `ERROR` counts as failure. Raising,
returning nothing, returning the wrong type, or depending on a registered file that has gone
missing all end in the same place.

This is deliberate and it is the opposite of the usual convention. The question being answered is
"is it safe to proceed?", and *"I could not tell"* must never render as *"yes"*.

Exit codes: `0` clear · `1` blocked by a finding · `2` a check errored. The last two are
distinguished because "the checks say no" and "the checks are broken" call for different responses.

## The two registries

**Paths** name the files you care about, so checks say `"executor_config"` instead of hardcoding a
path. Registering a path also declares that it must exist — a registered file that vanishes becomes
a finding rather than a silently skipped check.

**Checks** are keyed by id and come from builtins, campaigns, and your own modules. A later
registration replaces an earlier one, which is how a campaign tightens a default — but every
replacement is recorded and shown by `opsec checks`, because silently swapping out a safety check
is exactly what this tool is for catching.

## Campaigns

A campaign is a directory containing `campaign.py`:

```python
NAME = "example"
DESCRIPTION = "what this covers"

def register(ctx):
    ctx.paths.register("app_config", "~/.config/app/config.json", kind="config")
    ctx.checks.register(CheckSpec(**require_pattern(
        "app.tls", "TLS is required", "app_config", r'"require_tls"\s*:\s*true',
        remedy="Set require_tls to true.")))
```

That is the whole contract. Point at it with `--campaign-dir`, `campaign_dirs` in config, or
`OPSEC_CAMPAIGN_DIRS`.

A campaign that fails to import is a **hard error**, not a skip. Its checks were presumably the
ones that mattered, and a run missing them looks identical to a clean run.

Campaigns may stash objects in `ctx.extras` — an SSH client, a policy object, a rate-limit handle —
for their own checks to read back. Core never looks inside, which is what keeps core general.

## Writing checks

```python
from opsec import passed, failed, Mode, Severity

@registry.check("disk.space", "Root filesystem has headroom",
                mode=Mode.HARD, severity=Severity.MEDIUM)
def _disk(ctx):
    free = shutil.disk_usage("/").free // (1024**3)
    if free >= 5:
        return passed("disk.space", f"{free} GiB free")
    return failed("disk.space", f"only {free} GiB free",
                  remedy="Free space before starting a long run.")
```

Return a `Finding` or a list of them. Always give a `remedy` for anything that isn't a pass — a
failure the reader can't act on is only half a finding.

Helpers for the common declarative cases: `require_pattern`, `forbid_pattern`, `require_config`.
Write the *dangerous* state as the pattern for `forbid_pattern` — disabled guards and
commented-out limits are the shape most real problems take.

## Built-in checks

Static: registered paths exist; secret-kind paths aren't group/world readable.

Active: local interface enumeration, default route, listening sockets. These are **local
introspection only** — they read this machine and send nothing. Determining what the outside world
sees requires trusting some external service, which is a policy decision and belongs in a campaign.

## Configuration

Optional. JSON always; TOML on Python 3.11+.

```json
{
  "campaign_dirs": ["~/opsec-campaigns"],
  "paths": {
    "app_config": {"path": "~/.config/app/config.json", "kind": "config"},
    "api_key":    {"path": "~/.config/app/key",         "kind": "key"}
  }
}
```

## Requirements

Python 3.9+. Standard library only. Some active checks read `/proc` and report `SKIP` with a
reason on platforms that don't have it, rather than pretending to have checked.

## Tests

```
python3 testing/test_opsec_core.py
```

Isolated — temp dirs, no network, no writes outside them.

## Licence

MIT. See `LICENSE`.
