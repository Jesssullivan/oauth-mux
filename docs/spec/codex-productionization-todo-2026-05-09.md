# Codex Productionization TODO
Date: 2026-05-09
Status: active productionization checklist; subordinate to `AGENTS.md`,
`docs/spec/broker-mcp-contract-2026-05-03.md`, and
`docs/spec/codex-adapter-contract-2026-05-03.md`.

## Current Truth

Proven:

- Installed `oauth-mux codex resume <session-id>` can enter a managed Codex
  session through the broker-owned app-server/proxy path.
- A real provider-originated `429 usage_limit_reached` on the selected Codex
  account can be classified as quota exhaustion, durably recorded, retried on a
  distinct fallback account, and completed with a fallback `200` before Codex
  sees the 429.
- The 2026-05-09 engineered proof shows the same managed handoff shape after
  successful primary-route traffic, from `codex:max-2` to `codex:max-3`.
- The preserved proof bundles are
  `docs/evidence/codex-managed-quota-handoff-20260508/` and
  `docs/evidence/codex-engineered-quota-handoff-20260509/`.
- 2026-05-10 local verification fixed the installed `0.1.6` runtime
  regressions in the managed launch path: generated `config.toml` is
  root-partitioned so trailing user tables such as
  `[tui.model_availability_nux]` cannot swallow the managed
  `model_provider` / `openai_base_url`; `state_5.sqlite*` and
  `logs_2.sqlite*` are bridged by reference when present for native chooser
  parity; canonical bridge mode sets `CODEX_SQLITE_HOME` to the canonical
  authority home for Codex 0.132+; and broad pre-spawn Codex auth repair has
  been removed from launch.

Not proven:

- Same-thread continuity across account swap.
- Mid-turn streaming recovery after partial response delivery.
- Bare `codex` plus a background oauth-mux daemon hot-swapping an unmanaged
  Codex process.
- Non-Codex harness stay-afloat behavior.

## P0 Operator Surfaces

- [ ] Provide a first-class installed-binary command to summarize the latest
  Codex status artifact, without requiring users to know the XDG/macOS state
  path or run a repo script directly.
- [x] Keep the Python status summarizer as a regression oracle, but stop making
  it the only operator-facing path.
- [x] Ensure status artifacts always include runtime identity: binary path,
  binary source, build id or git SHA, version, command spelling, and installed
  versus repo-local mismatch state.
- [x] Add startup phase timing to managed Codex status and summarize
  `child_spawn_elapsed_ms` through both native `status-latest --json` and the
  Python regression oracle.
- [x] Make stale installed-binary ambiguity impossible during dogfood: installed
  `oauth-mux` must report enough identity to prove which executable handled the
  run.
- [ ] Keep `oauth-mux codex resume <id>` as the only live acceptance entry path;
  repo-local `./zig-out/bin/oauth-mux`, wrappers, and arg-heavy launch helpers
  are diagnostics only.
- [x] Preserve native Codex config semantics in the managed overlay (#211
  initial slice):
  `/experimental` / `[features]`, MCP, hooks/rules, approval/sandbox, profiles,
  model defaults, and other user behavior settings must pass through while
  oauth-mux overrides only the proxy routing keys.
- [x] Default missing Codex experimental feature keys in the managed child
  config (`terminal_resize_reflow`, `memories`, `external_migration`, `goals`,
  and `prevent_idle_sleep`) while preserving explicit canonical values,
  including `false`.

## P0 Proof Work

- [x] Preserve any successful installed-runtime status artifact under
  `docs/evidence/` after redaction review.
- [x] Add a managed-resume chooser regression: canonical authority is checked
  before child spawn, missing authority fails with a redacted diagnostic, and
  chooser mode avoids recursive rollout snapshotting before launch.
- [x] Define the Codex session-store portability/import policy: canonical
  session authority is bridged by reference, isolated stores are explicit, and
  route-local silent import/copy remains rejected until a separate confirmed
  import command exists. See
  `docs/spec/codex-session-store-portability-policy-2026-05-18.md`.
- [x] Bridge newer Codex `state_5.sqlite*` and `logs_2.sqlite*` chooser
  authority by reference when canonical Codex has it. Treat `state_5.sqlite`
  or `logs_2.sqlite` as chooser authority when present, set
  `CODEX_SQLITE_HOME` to canonical authority in bridge mode, and fall back to
  legacy `sessions` / `history.jsonl` / `session_index.jsonl` /
  `shell_snapshots` authority for older Codex homes.
- [x] Add a managed config passthrough regression with a canonical
  `config.toml` fixture containing representative `[features]`,
  `experimental_*`, MCP, approval/sandbox, profile, custom provider, and model
  defaults. Include profile-scoped provider stripping and pre-spawn rejection
  for forwarded Codex `--config` / `-c` attempts to override mux-owned provider
  keys.
- [x] Add the trailing-table config regression for
  `[tui.model_availability_nux]` with `"gpt-5.5" = 2`; status now reports
  `config_layout:"root_partitioned"`.
- [x] Guard Codex 0.130 MCP schema drift in the managed overlay: stdio MCP
  tables with `command` drop unsupported `url` and `bearer_token_env_var`
  lines in the overlay only, while HTTP MCP tables preserve those fields.
  Status reports `mcp_stdio_unsupported_fields_removed`.
- [x] Remove launch-time broad `repairRefreshableCodexAuthFailures()` from the
  pre-spawn path. Status reports `pre_spawn_network_refresh:false`; refresh
  remains lazy during credential materialization or explicit repair/revalidate
  commands.
- [x] Capture the engineered in-session exhaustion proof:
  account A starts available, emits successful `200` turns, reaches
  provider-originated `usage_limit_reached`, then account B returns `200` in the
  same managed child process.
  - 2026-05-09 operator plan: use `codex:max-2` as the low-weekly primary and
    `codex:max-3` as the high-capacity fallback after user-mediated reauth.
    Keep `codex:max-1` and `codex:max-4` as quota-exhausted reset-window
    candidates until after the engineered run, unless the adapter is explicitly
    pinned with `--account codex:max-2`.
  - 2026-05-09 19:28 EDT installed route truth: `codex-max` is currently
    `not_afloat`; `max-2` and `max-3` are recorded auth-dead and need labeled
    `oauth-mux codex login-device max-2` / `max-3` handoffs before the burn.
  - The private identity mapping and calendar draft are intentionally local
    files under `/tmp/`; public tracker/docs should use route names and capacity
    labels only.
  - 2026-05-09 result:
    `docs/evidence/codex-engineered-quota-handoff-20260509/` preserves the
    redacted installed-runtime proof. The route labels are `codex:max-2` to
    `codex:max-3`; raw identities remain private operator state.
- [ ] Run the exhausted ChatGPT quota plus extra API credits permutation and
  verify API credits do not falsely make a subscription-backed Codex route
  selectable. No synthetic substitute currently proves this because it depends
  on a real account with separate API-credit and subscription-quota signals.
- [ ] Run provider-originated all-fallbacks-exhausted live or cassette-backed
  proof and verify the terminal event is
  `quota_handoff_failed_no_account_selectable` with a
  complete redacted rejection vector. The synthetic managed-run regression is
  covered by `scripts/smoke-codex-all-exhausted.sh`; the managed cassette
  harness is covered by `scripts/smoke-codex-cassette-all-exhausted.sh` and is
  part of `just check-local`. The remaining gap is publishable provider-originated
  cassette or live evidence.
- [ ] Run reset-window repair proof: exhausted route stays blocked until reset
  or spend-gated revalidation evidence repairs it. Synthetic stale-window
  routing is already covered in `scripts/e2e-local.sh`; the remaining gap is
  a live reset-window repair without manually clearing health.

## P0 Test Hardening

- [x] Assert terminal no-fallback evidence includes every rejected candidate and
  redacts sensitive fields in the synthetic all-fallbacks managed-run smoke and
  supporting unit coverage.
- [x] Assert `usage_not_included` is `tier_insufficient`, not quota, and does
  not trigger a same-turn quota retry.
- [x] Assert expired quota reset windows remain blocked as
  `revalidation_needed` until provider revalidation.
- [x] Add deterministic route-state coverage for 1-4 account pools and provider
  signal classification covering `200`, `401`, `429 usage_limit_reached`,
  generic `429`, `usage_not_included`, materialization failure, and
  provider/transport failure.
- [x] In the election matrix, assert no attempted, auth-dead, quota-exhausted,
  rate-limited, tier-insufficient, or credential-unavailable account is elected
  in the same request.
- [x] Assert quota evidence is recorded before retry in a small unit or cassette
  replay that does not depend on timing or status-line ordering.
- [ ] Add cassette replay for the redacted real `usage_limit_reached` shape from
  the 2026-05-08 proof when a publishable cassette is available.

## P0 Startup And Resume UX

- [x] Explicit `oauth-mux codex resume <id>` no longer recursively snapshots all
  rollouts before spawn. It resolves exact structured evidence from
  a bounded, no-follow `session_index.jsonl` regular file and reports
  `resume_lookup_source` plus evidence availability in redacted status. Raw
  SQLite, WAL, and SHM bytes and rollout filenames are explicitly excluded
  because this path has no parsed record boundary for them. The selected route
  is rechecked at the launch boundary; one route's index cannot authorize
  another route's child.
- [x] Bare `oauth-mux codex resume` reports authority readiness without scanning
  rollouts before child spawn. The `child_spawn_elapsed_ms` launch timing
  remains the primary startup UX metric.

## P1 Documentation And Website

- [x] Keep README, specs, issue comments, and website copy aligned on the same
  truth boundary: managed load/resume quota handoff is proven; engineered
  managed-session quota handoff is proven as of the 2026-05-09 evidence bundle;
  same-thread semantics and unmanaged-daemon hot-swap remain open. 2026-05-09
  pass updated README, onboarding/adoption docs, wrapper docs, tracker notes,
  and the website-copy plan; no standalone website source directory is present
  in this checkout.
- [ ] Add a public proof page or release note that cites only redacted evidence
  and does not imply same-thread or unmanaged-daemon success.
- [ ] Update flow charts and logic graphs to show route states:
  `available`, `auth_failed`, `quota_exhausted`, `rate_limited`,
  `tier_insufficient`, and `credential_unavailable`.
- [x] Link the live acceptance checklist from every public or internal page that
  discusses Codex closure criteria.
- [x] Draft the upstream Codex usage-limit handoff proposal that explains why
  same-thread quota handoff is not an oauth-mux public claim until Codex exposes
  a first-class usage-limit/account-switch contract. See
  `docs/spec/codex-upstream-usage-limit-handoff-proposal-2026-05-18.md`.

## P1 Release Hygiene

- [ ] Keep `just check-local` green in this repo before any release claim.
- [ ] Keep website `just check`, `just build`, and `just test-e2e` green after
  public-copy changes.
- [ ] Split product/code changes and website proof-copy changes into separate
  commits or PRs when publishing.
- [x] Close TIN-951/#177 and TIN-916/#131 only from live evidence, not
  synthetic tests alone. #177 closed from the managed Codex live account-swap
  acceptance; #131 closed from the May 9 engineered managed-session quota
  handoff proof, with remaining negative/permutation lanes tracked separately.
