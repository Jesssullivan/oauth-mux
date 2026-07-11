---
name: Bug report
about: Report an oauth-mux bug with redacted diagnostics
title: "[bug] "
labels: bug
assignees: ""
---

## What happened?

Describe the command, expected behavior, and actual behavior.

## Environment

- oauth-mux version:
- install lane: Homebrew / GitHub Release / curl installer / deb/rpm / Nix / worktree / other
- OS and shell:
- harness/provider: Codex / Claude / Figma / GitHub / Linear / other

## Redacted diagnostics

Please include relevant output from diagnostic commands:

```bash
oauth-mux doctor --json
oauth-mux accounts list --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux codex status-latest --json
```

## Privacy check

Do not paste raw tokens, refresh tokens, account ids, emails, credential paths,
or session ids. Use route labels such as `codex:max-3#codex-max` and redact
local paths.
