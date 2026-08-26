# Test expectations (auto-generated — do not edit by hand)

Regenerate with `workspace.py test --write-expectations`. This lists the suites whose tests live in THIS directory, what each covers, how to run it, and the expected result.

> **Directive:** Tests are a REGRESSION FLOOR, not a substitute for exercising the real tool. ALWAYS do two things when you change a tool: (1) drive the actual application to confirm the change works, and (2) RUN the suites -- the whole registry is ~17s, there is no case for skipping it. Green tests on unchanged code prove nothing about code you just changed. AUTHORING a suite is the expensive part, so ration it by blast radius (amended 2026-07-29, operator's call): ALWAYS write/update a suite for anything that can fail SILENTLY or destroy work -- the scope wall, scope compilation, credentials, execution location, the rate ceiling, or anything that deletes/overwrites/syncs. DO NOT author suites for prose, docs, config text, naming, or one-off scripts. In between: run the suites, note the gap, batch it -- do not stop the work. Clear the backlog with `workspace.py test --drift` at a checkpoint, not mid-task.

## opsec-core  ·  safety  ·  CRITICAL

- **Run:** `python3 test_opsec_core.py` (from this directory)
- **Expected:** exit 0, all checks pass. Opsec verification engine: fails closed on every route to 'could not determine'; soft mode physically blocks sockets, DNS and subprocess rather than trusting the label; registries surface missing paths and overridden checks; CLI flags survive the subcommand (a false all-clear regression). ~61 checks.
- **Covers:** opsec/model.py, opsec/registry.py, opsec/runner.py, opsec/checks.py, opsec/campaigns.py, opsec/cli.py
- **Isolation:** isolated (temp dirs, no writes to tracked files).
