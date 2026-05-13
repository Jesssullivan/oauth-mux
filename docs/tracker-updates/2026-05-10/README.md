# Tracker Updates - 2026-05-10

Local verification after the Codex resume/config/startup regression fix:

- `TIN-979`: managed session authority now bridges newer Codex
  `state_5.sqlite*` chooser state by reference when present, while keeping
  `auth.json` and generated `config.toml` mux-owned in the temporary overlay.
- `TIN-1079`: managed startup no longer runs broad pre-spawn Codex auth repair;
  explicit resume preflight uses targeted `state_5.sqlite*` /
  `session_index.jsonl` / filename evidence, and chooser mode reports authority
  readiness without scanning rollouts before spawn.
- Config regression: canonical config ending in `[tui.model_availability_nux]`
  with `"gpt-5.5" = 2` now survives, with
  `config_layout:"root_partitioned"` status.
- Config schema guard: migrated Codex 0.130-incompatible stdio MCP tables are
  made valid in the managed overlay by removing remote-only `url` and
  `bearer_token_env_var` fields from stdio tables only. HTTP MCP tables keep
  those fields. Status reports `mcp_stdio_unsupported_fields_removed`.
- Local install regression: macOS can kill a user-local dogfood binary with
  `SIGKILL` / `Taskgated Invalid Signature` when `cp` overwrites an existing
  Mach-O in place. The install lane now removes `~/.local/bin/oauth-mux`
  before copying so the fresh file has a fresh vnode and hash identity with the
  worktree binary is preserved.

Validation:

- `zig build test`
- `just build`
- `scripts/smoke-codex-cli-ux.sh`
- `scripts/smoke-codex-provider-degraded.sh`
- `scripts/smoke-codex-status-summary.sh`
- `nix develop --command just check-local`

Release hygiene:

- Source version advanced to `0.1.7` for the patch release candidate.
- QA helper defaults now follow `scripts/project-version.sh` instead of
  preserving the last published `0.1.6` literal.
- The hosted system-package install workflow still defaults to the last
  published release until `v0.1.7` assets exist, because it installs public
  release artifacts on PRs.
