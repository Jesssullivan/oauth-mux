# oauth-mux

`oauth-mux` is an OAuth/account broker for developer harnesses. The product
target is:

> The user runs `oauth-mux <harness>` such as `oauth-mux codex`. The harness
> behaves like the real one. The active subscription account exhausts quota.
> Another credited account is substituted in place. The harness process is not
> restarted. The user is not prompted.

Restart, supervised relaunch, route-warming, and `prepared_fallback` are not
product success. They are diagnostics or lower-level infrastructure.

## Use It Now

Functional today:

- Managed Codex sessions through `oauth-mux codex` and
  `oauth-mux codex resume ...`.
- Native Codex resume chooser and canonical session history inside the managed
  frame.
- Codex behavior config passthrough for user settings such as `[features]`,
  legacy `experimental_*`, MCP servers, approval/sandbox policy, profiles, and
  model defaults.
- Live managed Codex quota handoff across enrolled routes, with redacted
  installed-runtime proof.
- Agent-safe JSON diagnostics for accounts, runtime state, route selection, and
  Codex status artifacts.

Still scoped or pending:

- Same-thread provider semantics across account boundaries.
- Mid-turn streaming recovery.
- Unmanaged bare-`codex` hot-swap from a background daemon.
- Non-Codex harness stay-afloat claims.

Install:

```bash
npm install -g oauth-mux
# or
brew install jesssullivan/omux/oauth-mux
```

First Codex path:

```bash
oauth-mux init --codex-max
oauth-mux doctor
oauth-mux accounts list --provider codex --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux codex resume
```

If a route needs upstream auth, use the labeled handoff from `route explain`,
for example:

```bash
oauth-mux codex login-device max-3
```

Agent-safe diagnostics:

```bash
oauth-mux doctor runtime --profile codex-max --capability codex-max --json
oauth-mux accounts list --provider codex --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux codex status-latest --json
```

These commands do not spend provider calls. Live probes and revalidation stay
behind explicit confirmation.

## Current Codex State

`oauth-mux codex` is the current reference adapter. It runs Codex in a managed
frame with mux-owned auth/config, a proxy provider, and a canonical Codex
session-authority bridge. Installed-runtime evidence proves managed Codex quota
handoff; synthetic smokes cover the surrounding auth, tier, all-exhausted,
chooser, config-passthrough, child-refresh, concurrent-session, and cassette
paths.

Current account-state and handoff truth lives in `docs/qa-handoff-matrix.md`.
The reviewed proof bundles are
`docs/evidence/codex-managed-quota-handoff-20260508/` and
`docs/evidence/codex-engineered-quota-handoff-20260509/`.

## Where To Go Next

- `docs/README.md`: docs map.
- `docs/adoption.md`: first-run UX and agent-safe command paths.
- `docs/qa-handoff-matrix.md`: route states, handoff claims, account labels,
  and current Codex truth.
- `docs/release-install-lanes.md`: install, package, CI/CD, and dogfood lanes.
- `docs/spec/future-adapter-roadmap-2026-05-10.md`: future adapter proof gates.

The product anchor is
`docs/spec/broker-mcp-contract-2026-05-03.md`. The Codex adapter contract is
`docs/spec/codex-adapter-contract-2026-05-03.md`.

## Testing Ladder

Use `just` as the entrypoint.

```bash
just build
just test
just check-local
```

The evidence ladder is:

- Unit tests and deterministic PBT-style tests in Zig for parsers, route state,
  classification, session ids, credential handles, header copying, and overlay
  invariants.
- Shell e2e/smoke tests for broker MCP, Codex CLI UX, Codex synthetic swap,
  concurrent sessions, same-account child refresh, tier-insufficient handling,
  all-accounts-exhausted handling, 401 auth fallback, and cassette replay.
- Cassette replay infrastructure for scrubbed Codex wire captures.
- Live QA only after local and cassette layers are green, with explicit spend
  consent and redacted status artifacts.

The canonical handoff/account-state matrix is `docs/qa-handoff-matrix.md`.
Release and installer lane truth is `docs/release-install-lanes.md`.

Next P0: harden the engineered live handoff into deterministic regression
coverage and keep collecting evidence for same-thread provider semantics across
account boundaries. The 2026-05-08 installed-runtime artifact closes managed
load/resume quota handoff; the 2026-05-09 artifact closes the engineered
managed quota handoff shape; dogfood-9 remains failure evidence and
route-health input, not product acceptance.

Summarize a dogfood status artifact without overclaiming:

```bash
oauth-mux codex status-latest --json
oauth-mux codex status-latest --status-file dist/live-qa/<run>/status.ndjson --json
python3 scripts/summarize-codex-status.py dist/live-qa/<run>/status.ndjson --require-brokered
```

`oauth-mux codex status-latest` is the installed-binary operator surface. The
Python summarizer remains the repo regression oracle and should agree on
success/failure verdicts for tracked evidence.
Both summaries include `launch_timing.child_spawn_elapsed_ms` when the status
artifact contains startup phase events; these timings are diagnostics for
fast visible TUI, not product success evidence.
If Codex terminates by signal, managed status now records a typed
`session_aborted` terminal event with `term_kind`, `term_code`, and
`signal_name` such as `SIGKILL`; use that artifact evidence instead of relying
only on shell text like "terminated by signal".

Managed config status is intentionally class-based. `session_started` reports
`config_passthrough`, `user_config_present`, `config_overridden_keys`, and
`config_paths_printed:false`. Unsafe forwarded Codex config overrides emit
`config_passthrough_check` with counts and booleans such as
`model_provider_override:true`; raw paths, tokens, session ids, and user config
values are not printed.

Run managed Codex dogfood only through an installed `oauth-mux` executable on
PATH, after installing the current build into the operator environment:

```bash
oauth-mux codex resume <session-id>
```

For local dogfood, keep the provenance explicit:

```bash
which -a oauth-mux
scripts/project-version.sh
oauth-mux version
shasum -a 256 ./zig-out/bin/oauth-mux
shasum -a 256 "$(command -v oauth-mux)"
```

The worktree build and the installed PATH binary should match when testing
unreleased behavior. A Homebrew binary may legitimately lag the worktree until
the rendered formula from `dist/out/v<version>/homebrew/oauth-mux.rb` is
promoted to the public `jesssullivan/omux` tap.

Managed Codex runs write redacted status evidence by default under the
oauth-mux state directory (`$XDG_STATE_HOME/oauth-mux/codex/status/` on Linux,
`~/Library/Application Support/oauth-mux/codex/status/` on macOS, or
`$OMUX_STATE_DIR/codex/status/` when set). Passing `--json-status-file` is still
available for an explicit artifact path, but it is not required for the installed
dogfood command.

Repo-local `./zig-out/bin/oauth-mux`, extra dogfood wrapper scripts, and
arg-clad launch helpers are not acceptance evidence for live quota stay-afloat.

`verdict:"brokered_without_fallback"` means the session went through oauth-mux
but did not observe account exhaustion or substitution. The Level 3/4 evidence
shape requires a `quota_exhausted` proxy turn, a retry/swap event, and a
successful turn on a distinct fallback account.
`verdict:"brokered_auth_failed"` means the managed frame started, but upstream
returned unrecovered `401 auth_unauthorized` responses. That is an auth-health
failure, not quota fallback evidence. Status artifacts should also show an
`auth_writeback` frame; `changed:true,written:true,ok:true` means Codex updated
managed overlay auth and oauth-mux imported it back to the route's auth source.
`source_conflict:true` means another writer changed the mux source first, so
oauth-mux refused to overwrite it. When unrecovered 401s occur and no overlay
auth changed, oauth-mux records account-credential health for the next launch
and emits `auth_health_observed` with `quota_claim:false`; that does not prove
the subscription lacks quota.
`verdict:"auth_fallback_sequence_observed"` means the selected account produced
`401 auth_unauthorized`, oauth-mux retried the same buffered request against a
different account before Codex saw the 401, and the fallback account returned
200. That is a managed auth-continuity proof, not quota exhaustion evidence.
In the dogfood-9 artifact, that selected account was `codex:max-1` and the
successful live wire traffic moved to `codex:max-4`.
`verdict:"successful_live_quota_handoff"` means a provider-originated
`usage_limit_reached` quota event was observed, oauth-mux retried the same
request on a distinct fallback account before delivering the 429 to Codex, and
the fallback account returned 200.
`verdict:"quota_handoff_failed"` means a live quota event was observed, but
oauth-mux exhausted the eligible candidate set and could not complete a
substitution. That is the expected dogfood-9 verdict.
