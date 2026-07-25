# Test expectations (auto-generated — do not edit by hand)

Regenerate with `workspace.py test --write-expectations`. This lists the suites whose tests live in THIS directory, what each covers, how to run it, and the expected result.

> **Directive:** Tests are a REGRESSION FLOOR, not a substitute for exercising the real tool. When you change or upgrade a tool you MUST do BOTH: (1) drive the actual application to confirm the change works, and (2) run AND update its suite here. Green tests on unchanged code prove nothing about code you just changed. Never skip the live app because tests pass; never skip updating tests because the app works.

## opsec-core  ·  safety  ·  CRITICAL

- **Run:** `python3 test_opsec_core.py` (from this directory)
- **Expected:** exit 0, all checks pass. Opsec verification engine: fails closed on every route to 'could not determine'; soft mode physically blocks sockets, DNS and subprocess rather than trusting the label; registries surface missing paths and overridden checks; CLI flags survive the subcommand (a false all-clear regression). ~61 checks.
- **Covers:** opsec/model.py, opsec/registry.py, opsec/runner.py, opsec/checks.py, opsec/campaigns.py, opsec/cli.py
- **Isolation:** isolated (temp dirs, no writes to tracked files).
