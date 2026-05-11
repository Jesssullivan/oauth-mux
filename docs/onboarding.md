# oauth-mux Onboarding and Discovery

This document defines the user and agent onboarding path for `oauth-mux`.
The goal is that a user can make expected OAuth accounts muxable with one or
two intentional commands, and an AI agent can discover the safe command surface
without reading token files.

## User Stories

1. Multi-subscription Codex user.
   The user has several ChatGPT/Codex subscription accounts and wants Codex
   routes to fall through when one route is rate-limited, quota-exhausted, or
   auth-broken.

2. Agent harness operator.
   The operator wants Claude, Codex, GitHub, Linear, Figma, Vercel, FlakeHub,
   and MCP accounts represented as named accounts without storing raw OAuth
   tokens in `.env`.

3. AI agent.
   The agent needs to discover configured providers, profiles, health, and safe
   commands without opening credential stores or printing tokens.

4. Provider author.
   The author wants to add support for a new OAuth-backed harness through a
   JSON provider definition and fixtures before writing Zig.

5. Release operator.
   The operator wants local proof, self-hosted cache-first proof, registry
   dry-runs, and rollback instructions before any public package publication.

## First-Run Flow

Generic starter:

```bash
oauth-mux init
oauth-mux doctor
oauth-mux doctor runtime --json
oauth-mux config validate
oauth-mux accounts list --json
oauth-mux enroll plan <provider> --json
oauth-mux enroll codex --account <name> --confirm-enroll --json
oauth-mux enroll claude --account <name> --confirm-enroll --json
oauth-mux enroll figma --account <name> --mode pat --confirm-enroll --json
oauth-mux discover
```

Codex Max starter plus fourth-account enrollment:

```bash
oauth-mux init --codex-max
oauth-mux doctor
oauth-mux doctor runtime --json
oauth-mux accounts list --provider codex --json
oauth-mux enroll plan codex --account max-4 --json
oauth-mux enroll codex --account max-4 --confirm-enroll --json
oauth-mux enroll plan claude --account work --json
oauth-mux enroll claude --account work --confirm-enroll --json
oauth-mux enroll plan figma --account design --mode pat --json
oauth-mux enroll figma --account design --mode pat --secret-env OMUX_FIGMA_DESIGN_PAT --confirm-enroll --json
oauth-mux codex login-device max-4
oauth-mux setup codex
oauth-mux codex canary
oauth-mux codex live-qa
oauth-mux doctor runtime --profile codex-max --capability codex-max --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux repair-plan --profile codex-max --capability codex-max --json
oauth-mux repair run --profile codex-max --capability codex-max --json
```

`oauth-mux doctor` is the no-spend readiness report. It checks whether config is
present and valid, counts configured providers/accounts/profiles, reports
whether health state exists, and prints the next safe commands for the current
state.

`oauth-mux doctor runtime --json` is the no-spend runtime report. It checks
upstream binary availability, configured account store directories, local write
access via a temporary marker file, and expected session-file presence. It does
not read token values, run live probes, open auth flows, or create missing
account stores.

`oauth-mux accounts list --json` is the no-spend account inventory. It is the
first provider-neutral surface for N-account enrollment and stay-afloat
planning: it reports each configured provider/account, secret backend name,
runtime readiness, writeback admission, capability proof status, recorded
liveness, selectability, and safe next commands without reading credential
values.

`oauth-mux enroll plan <provider> --json` is the no-mutation enrollment planner.
It converts provider inventory into ordered setup steps and labels each step as
agent-safe, interactive, mutating, or provider-call-spending. Provider-neutral
enrollment mutation is only available where the provider-owned consent contract
has been implemented.

`oauth-mux enroll codex --account <name> --confirm-enroll --json`,
`oauth-mux enroll claude --account <name> --confirm-enroll --json`, and
`oauth-mux enroll figma --account <name> --mode <oauth|pat|plan>
--confirm-enroll --json` are the first provider-neutral enrollment mutations.
They update the active oauth-mux config and add provider routes; Codex and
Claude also create isolated account directories. Figma enrollment never creates
token material. These commands do not run upstream login, open browser/device
auth, or probe providers. The returned `next_commands` include explicit login,
secret, proof, runtime, and inventory handoffs as appropriate.

For profile-level stay-afloat checks, scope the runtime report:
`oauth-mux doctor runtime --profile codex-max --capability codex-max --json`.
That reports only the route set the user or agent intends to use, so unrelated
legacy accounts can be cleaned up separately without hiding a usable mux path.

`oauth-mux setup codex` is the user-facing alias for
`oauth-mux codex onboard` / `oauth-mux codex setup`. It creates the expected
isolated `CODEX_HOME` directories, runs `codex login` for accounts that are not
logged in, prints login status, and then prints `oauth-mux discover`. It does
not run live route probes unless the operator explicitly opts in:

```bash
oauth-mux setup codex --live
```

For device-code login instead of browser login:

```bash
oauth-mux setup codex --device
```

For status-only inspection:

```bash
oauth-mux setup codex --status-only
```

For a no-spend canary after onboarding:

```bash
oauth-mux codex canary
```

The canary validates config, prints redacted discovery, checks
`codex login status` for each expected account, reports scoped runtime
readiness for each Codex route profile, and summarizes whether route health has
already been recorded. It also prints the current non-mutating repair plan for
the configured Codex route profiles, so a user or agent can see whether the next
action is to fix runtime setup, run an explicit probe, wait for quota, or
reauthenticate through the upstream Codex CLI. It does not run live probes by
default.

For guarded live route QA, start with:

```bash
oauth-mux codex live-qa
```

That command explains the quota-spending confirmation requirement and exits
before creating stores or running provider calls. When real Codex calls are
intended, confirm explicitly:

```bash
oauth-mux codex live-qa --confirm-spend
```

To probe one route class across every expected Codex account:

```bash
oauth-mux codex probe-all --capability codex-mini --json
```

To inspect the stay-afloat decision loop without running a canary:

```bash
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux route select --profile codex-max --capability codex-max --json
oauth-mux stay-afloat next --profile codex-max --capability codex-max --json
oauth-mux stay-afloat launch --profile codex-max --capability codex-max -- codex
oauth-mux repair-plan --profile codex-max --capability codex-max --json
oauth-mux repair-plan --profile codex-mini --capability codex-mini --json
```

`route explain` and `route select` are no-spend commands. They read runtime
readiness plus recorded route liveness and do not probe providers or mutate auth
state. Unrecorded routes are reported as `probe_needed`, and `route select`
exits nonzero when no route has enough evidence to be selected.

`stay-afloat next --json` is the preferred agent mediation surface. It also
does not probe or mutate. If a route is selectable, it returns
`ready_for_exec:true` and an exact `exec_argv` that pins provider, account, and
capability for `oauth-mux exec`. If no route is selectable, it returns
`ready_for_exec:false` and embeds the typed repair action, mediation mode,
repair owner, and any user-facing command to run. The same response includes a
`claim` object. `claim.level:"prepared_fallback"` means oauth-mux can start the
next harness process through `claim.launch_argv`; it is not a current-process
hot swap, supervised restart, or per-request muxing claim.
Check `resilience.spare_fallback_ready` and `claim.single_route_at_risk` before
calling a profile comfortably afloat: if only one route is selectable, the next
quota/rate-limit failure may still need revalidation, waiting, or another
account.
Codex app-server auth brokering is tracked separately as a possible
current-process proof for mediated Codex sessions; unmanaged Codex launches
should still be treated as prepared fallback only.
For daily managed Codex use, prefer the first-class adapter spelling:

```bash
oauth-mux codex
oauth-mux codex resume
oauth-mux codex resume --last
oauth-mux codex resume <session-id>
```

The managed frame preserves native Codex session authority by reference while
oauth-mux owns auth and the proxy provider override. Resume chooser mode stays
native: oauth-mux checks the required session-authority entries before child
spawn and fails with a redacted diagnostic rather than opening an empty
chooser. Newer Codex `state_5.sqlite*` chooser state is bridged by reference
when present; older homes fall back to `sessions/`, `history.jsonl`,
`session_index.jsonl`, and `shell_snapshots/`.

The managed overlay also preserves normal Codex behavior config from the
canonical config authority (`OMUX_CODEX_CONFIG_HOME`, then parent
`CODEX_HOME`, then `~/.codex`). `[features]`, legacy `experimental_*`, MCP
servers, approval/sandbox policy, profiles, model defaults, and custom
non-managed provider definitions survive. oauth-mux strips only mux-owned
provider selection conflicts and rejects forwarded `--config` / `-c` provider
overrides before launching Codex. The generated TOML is root-partitioned, so a
canonical config ending inside a table such as `[tui.model_availability_nux]`
cannot capture the managed `model_provider` override.
Missing Codex experimental feature defaults are enabled only in the managed
child config: `terminal_resize_reflow`, `memories`, `external_migration`,
`goals`, and `prevent_idle_sleep`. Existing canonical values, including
explicit `false`, win, and oauth-mux does not rewrite the canonical
`config.toml`.

Managed Codex live quota handoff is proven for installed
`oauth-mux codex resume` status artifacts. The 2026-05-09 engineered evidence
shows successful primary-route traffic, provider-originated
`usage_limit_reached`, a same-request retry to a distinct fallback route, and a
fallback `200` before Codex sees the 429. Treat that as a managed-frame proof;
same-thread continuity semantics, mid-turn streaming recovery, unmanaged
bare-`codex` daemon handoff, and non-Codex adapters still require separate
evidence.

`oauth-mux codex managed-plan` and `oauth-mux codex managed` remain diagnostic
route-local launch surfaces from the earlier implementation path. They can
still inspect selected-route stores and fallback readiness, but they are not
the primary daily-use Codex entrypoint now that `oauth-mux codex resume ...`
owns the managed frame. Treat their resume checks as route-local diagnostics,
not canonical chooser parity or same-thread quota handoff proof.
Use
`oauth-mux codex broker-plan --profile codex-max --capability codex-max --json`
to inspect whether enrolled Codex stores can supply the app-server
external-auth tuple for that future broker path. It is local, redacted,
planning-only, does not read route liveness, and does not prove prepared
fallback or live hot-swap. Use `broker-session-plan` for route-aware broker
session selection.
Use
`oauth-mux codex broker-smoke --profile codex-max --capability codex-max
--confirm-broker --json` after broker-plan is ready to prove a broker-owned
Codex app-server stdio login. It sends the selected route token only to the
child app-server, verifies initialize/login/account-update milestones, and
prints no token, account-id, or raw protocol values. It is still not an
unmanaged current TUI hot-swap or quota-recovery claim.
Use
`oauth-mux codex broker-refresh-smoke --profile codex-max --capability
codex-max --confirm-broker --json` to prove that the same mediated app-server
session can answer `account/chatgptAuthTokens/refresh` after login with the
next ready route when a fallback account exists. This is the first local proof
for the live 401 repair primitive; it does not yet prove automatic repair of an
already-running unmanaged Codex process.
Use
`oauth-mux codex broker-401-smoke --profile codex-max --capability codex-max
--confirm-broker --json` to prove the no-spend mediated 401 retry loop. It
starts a disposable app-server with local mocked Responses and ChatGPT backend
URLs, forces the first turn Responses request to 401, answers app-server
refresh with the next ready route, and verifies the retried request used that
fallback token.
Use
`oauth-mux codex broker-quota-smoke --profile codex-max --capability codex-max
--confirm-broker --json` to prove the no-spend quota fallback boundary. It
simulates usage-limit 429, confirms that this is not the same hook as 401
auth-refresh, then verifies fallback Authorization on a new brokered thread.
That is useful stay-afloat evidence, but not same-thread quota recovery.
Use
`oauth-mux codex broker-session-plan --profile codex-max --capability codex-max
--json` when you need the user-facing broker-owned session plan without running
Codex or spending provider calls. It joins route liveness with broker token
readiness and reports which route would start the session plus which broker-ready
routes are immediate fallbacks. Check `resilience.spare_fallback_ready` and
`resilience.single_route_at_risk` before treating the session as comfortably
afloat. When the selected Codex route is single-route-at-risk, use the
broker-session, `route explain`, or `stay-afloat` next-action output as the
operator todo list: revalidate exhausted routes, enroll another account, or wait
for quota reset. JSON clients read `resilience_actions`; text output prints the
matching `next:` hint.
Use
`oauth-mux codex broker-session-smoke --profile codex-max --capability codex-max
--confirm-broker --json` to exercise that plan as a local multi-turn
broker-owned app-server session. It keeps provider traffic mocked, simulates
quota exhaustion on the first turn, and verifies fallback Authorization on a new
brokered thread selected from the session plan.
Use
`oauth-mux codex broker-run --profile codex-max --capability codex-max --prompt
... --confirm-spend --json` only after the operator explicitly approves live
provider spend. It runs one real broker-owned app-server turn from the session
plan and prints redacted evidence, not prompt text, assistant output, tokens,
account ids, or raw protocol output. If the live run reports quota or rate
limiting, oauth-mux records route-health evidence and shows the next selected
route plus the post-failure resilience state and actions.
For a bounded beta broker-owned session loop, pipe line-delimited prompts and
replace `--prompt ...` with `--stdin`. The same spend gate applies, and
transcript content remains suppressed in normal output. Add
`--continue-on-failure` to let oauth-mux record the failed route, rerun
planning, and start a fresh broker-owned session on the selected fallback. This
replays the failed prompt plus remaining queued prompts, but it is still
next-session continuation rather than same-thread recovery.
Use
`oauth-mux codex revalidate-exhausted --profile codex-max --capability
codex-max --confirm-spend --json` after credits, plan, or billing changes. It
re-probes only routes already recorded as exhausted or rate-limited for that
capability, updates route health from provider evidence, and avoids hand-resetting
health keys. If the provider still returns quota exhaustion, the route remains
blocked even if dashboard copy suggests credits are available elsewhere.
When a stored quota reset window is already in the past, planning surfaces mark
the route `revalidation_needed` instead of treating it as actively waiting or
silently selectable.
Use
`oauth-mux codex broker-fallback-drill --profile codex-max --capability
codex-max --from-account max-3 --confirm-drill --json` when you need to observe
fallback deliberately. It records the named route as quota-exhausted in local
route health, then verifies broker-owned selection moves to a distinct fallback
route. This is no-spend and useful for operator drills, but it is controlled
route-state evidence, not provider-originated quota exhaustion.

`stay-afloat launch -- <command>` is the user/wrapper startup boundary. It runs
the same preflight as `stay-afloat next`, then starts the target only when a
route is selectable. The launched command receives credentials through
`oauth-mux exec` with the selected provider, account, and capability pinned.
That exec path still validates token and runtime state before target startup;
if validation reclassifies the selected route, launch re-runs selection and
tries the next selectable account. If no route remains selectable, launch prints
refreshed mediation text and exits nonzero without starting the target. If the
route needs reauth, quota wait, runtime repair, or another handoff at
preflight, launch also prints mediation text and exits nonzero without starting
the target.

`oauth-mux repair run` is the explicit repair execution gate. It refuses
mutation unless `--confirm-repair` is present. Without confirmation, it is safe
for agents to run because it only reports that a route is already selectable,
that no admitted repair exists, or that a specific upstream CLI command would
need user approval. Confirmed interactive repair is a human foreground flow and
should be run without `--json`; JSON mode refuses interactive repair execution
so upstream CLI output cannot corrupt machine-readable output.

Each `repair run` call records a redacted event. Confirmed repair also takes an
account-scoped advisory lock before it launches an upstream repair command. A
second process sees that lock as `repair_in_progress` through `doctor runtime`,
`route explain`, `route select`, and `repair-plan`, so agents can back off
without guessing whether OAuth, quota, or local runtime state failed. Inspect
the audit trail with:

```bash
oauth-mux daemon events --json
```

The same event log also records `token_refresh` outcomes from the pipeline.
Those events include writeback capability and admission fields so dogfood runs
can explain whether refresh was refused, attempted, persisted, or failed
without exposing access tokens, refresh tokens, credential paths, or provider
response bodies.

Daemon policy is intentionally conservative. The default config admits only
`free_local` and `free_command` budgets for daemon/background work. Provider
calls, provider-spending probes, browser/device auth, and credential mutation
are refused in the admission report unless `policy.daemon` explicitly allows
them. `repair-plan --json` and `route explain --json` include both the effective
policy and per-route `daemon_probe` / `daemon_repair` decisions.

`oauth-mux stay-afloat --once --json` is the portable stay-afloat dogfood surface. It
loads the same route/runtime/liveness state, applies the daemon policy, and
prints what a future background loop would be allowed to do. Without
`--execute` it remains planning-only and reports `executed:false`.

Opt-in beta execution is explicit:

```bash
oauth-mux stay-afloat --once --execute --profile codex-max --capability codex-max --json
```

Execute mode runs at most one admitted non-interactive action per tick. The
default policy admits `free_command`, so command-backed probes can refresh
recorded route state without requiring a service manager. Provider-spending
probes, interactive browser/device auth, and credential mutation remain refused
unless policy explicitly admits them. Interactive reauth is not run in the
background; execute mode records a redacted `daemon_handoff` event with the
reviewable user command. Repeated execute ticks report an existing handoff as
pending instead of appending duplicate events. Agents and users can list those
pending handoffs with:

```bash
oauth-mux stay-afloat handoffs --json
```

The default handoff view is pending as of the daemon's last route evidence. Use
`oauth-mux stay-afloat handoffs --json --all` when you need the historical audit
trail instead. A user or agent can acknowledge that the handoff has been seen
without clearing it:

```bash
oauth-mux stay-afloat handoff ack --provider codex --account max-1 --profile codex-max --capability codex-max --json
```

The recovery loop after an auth expiry is:

```bash
oauth-mux stay-afloat --once --execute --profile codex-max --capability codex-max --json
# run the redacted upstream command printed in the handoff, such as:
oauth-mux codex login-device max-1
oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json
```

`stay-afloat refresh` is a named one-shot execute tick. It refreshes route
evidence after user-mediated login and clears the pending prompt when the route
becomes selectable. Use `stay-afloat handoff clear ... --json` only to dismiss a
stale pending prompt that the operator has decided is no longer actionable.

For a bounded foreground loop, use:

```bash
oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile codex-max --capability codex-max --json
```

Loop mode emits one JSON envelope containing repeated tick snapshots. Each tick
re-reads local health and runtime state and does not require launchd, systemd,
Homebrew services, cron, or a platform-specific
daemon manager. Per-route `tick.next_tick_after` and `tick.schedule_reason`,
plus `summary.next_tick_after` and `summary.next_tick_reason`, are the portable
sleep/backoff contract for wrappers and agents.

`oauth-mux daemon status --json` is socket-stub inspection, not the stay-afloat
supervisor. It reports `contract:"experimental_socket_stub"` and
`hosts_stay_afloat:false` until the socket daemon is deliberately aligned with
the foreground tick contract.

Route, runtime, repair-plan, and stay-afloat JSON include a `writeback` object.
That object separates the secret backend surface (`readonly`, `replace_file`,
`command_write`, `keychain_write`, `sops_write`, or `unsupported`) from whether
automatic refresh writeback is admitted for this provider. This matters for
Codex and Claude-style CLI-owned stores: a file-backed credential can be
readable and writable by the current user, while oauth-mux still refuses to
rewrite it because upstream login owns the session.

When a route needs local runtime repair before any provider call, the action
also includes `diagnostic_command`. Run that command in the process boundary
that actually owns the upstream store; for example, a sandboxed agent may need
the user or wrapper to run the diagnostic in a normal shell before deciding
whether the account is usable.
The fuller wrapper contract is
`docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md`.

The refresh path now uses that same admission gate. File-backed credentials can
be replaced atomically, but automatic refresh only runs for providers whose
definition declares `repair.owner = "oauth_mux_refresh"` and whose backend
reports `automatic_refresh_admitted: true`. Codex remains upstream-CLI-owned.

If `repair-plan --profile codex-max` reports a config validation error, the
active config is not the starter Codex Max shape. That usually means the
machine still has an older generic config with only `codex:default`. Generate a
safe sidecar candidate without modifying the active config:

```bash
oauth-mux codex config-candidate
```

`oauth-mux doctor --json` and `oauth-mux discover --json` also report
`codex_max_configured`. When Codex is present but that value is `false`, they
include `oauth-mux codex config-candidate --json` as the next action so agents
can surface the safe migration path instead of repeatedly probing a shape that
cannot stay afloat.

The command writes `codex-max.config.json` next to the active config, refuses to
overwrite an existing candidate, validates the generated JSON before writing,
and prints exact `OMUX_CONFIG=...` commands for `config validate`,
`setup codex --status-only`, `repair-plan`, and `codex canary`. It also prints
a merge command for after review:

```bash
oauth-mux codex config-merge --candidate ~/.config/oauth-mux/codex-max.config.json
```

`config-merge` validates the reviewed candidate, refuses invalid Codex Max
shapes, backs up the active config, and merges only the `codex` provider plus
the `codex-max` and `codex-mini` profiles. Existing non-Codex providers and
profiles remain in the active config.

Codex subcommand help is non-mutating. These commands print usage without
creating `CODEX_HOME` directories, checking login status, or running probes:

```bash
oauth-mux codex canary --help
oauth-mux codex live-qa --help
oauth-mux codex probe-all --help
oauth-mux setup codex --help
```

Source checkouts keep `just codex-max-onboard` and `just codex-max-canary` as
thin aliases for installed commands. `just codex-max-setup` is a thin alias for
`oauth-mux setup codex`, `just codex-max-repair-plan` is a thin alias for
`oauth-mux repair-plan --profile codex-max --capability codex-max --json`, and
`just codex-max-live-qa` / `just codex-max-live-qa-confirmed` wrap the guarded
installed live QA command. `just codex-max-probe-all` is likewise a thin alias
for `oauth-mux codex probe-all`. These source helpers intentionally share the
default oauth-mux state directory so dogfood probes feed later route selection.
Their default account list matches the three-route starter config; set
`OMUX_CODEX_ACCOUNTS=max-1,max-2,max-3,max-4` when running them against the
paid four-route cohort.
Set `OMUX_STATE_DIR=/tmp/<dir>` explicitly when a run should be isolated for CI
or artifact collection. Route selection and explanation should be run through
the installed CLI directly:

```bash
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux route select --profile codex-max --capability codex-max --json
```

The clean no-config first-run path is covered by:

```bash
just first-run-e2e
```

That harness runs with a temporary `HOME`, XDG config/state/data/runtime roots,
and no inherited `OMUX_*` overrides. It proves `init --codex-max`, JSON
diagnostics, redacted support output, repair-plan route explanation,
runtime diagnostics, no-spend route explanation and route-select refusal without
health evidence,
non-clobbering config-candidate generation, config-merge backup behavior, and
non-mutating Codex help plus the unconfirmed live-QA spend gate without touching
the operator's real OAuth stores.

## Agent Discovery Contract

Agents should start with:

```bash
oauth-mux doctor --json
oauth-mux report --redacted --json
oauth-mux providers list --json
oauth-mux accounts list --json
oauth-mux enroll plan <provider> --json
oauth-mux discover --json
oauth-mux status --json
oauth-mux health --json
oauth-mux doctor runtime --json
oauth-mux doctor runtime --profile <profile> --capability <capability> --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux repair run --profile <profile> --capability <capability> --json
```

Agents may run:

```bash
oauth-mux route select --profile <profile> --capability <capability> --json
oauth-mux probe --profile <profile> --capability <capability> --json
oauth-mux codex live-qa --json
oauth-mux codex probe-all --capability <capability> --json
oauth-mux env --profile <profile> --capability <capability> --shell <shell>
oauth-mux exec --profile <profile> --capability <capability> -- <command>
```

Probe JSON includes `ok`, `error`, and `exit_code` alongside typed
`liveness`. Route JSON includes `ok`, `selected`, `selectable`, `skip_reason`,
runtime readiness, liveness, probe evidence, and the same action object used by
`repair-plan`. `codex live-qa --json` is safe without confirmation: it exits
nonzero with `confirmation_required` and `spends_provider_calls: true` before
running provider calls. Once confirmed, its top-level `ok` means every
requested capability has at least one available account, not that every account
is currently available. Use `routes_available`, `routes_unavailable`,
`probe_errors`, `capabilities_covered`, and `capabilities_uncovered` for
automation. Agents should use route `liveness` to distinguish `rate_limited`,
`quota_exhausted`, `degraded`, and `dead` instead of treating every nonzero
probe exit as the same failure class.

Agents must not:

- read files referenced by `secret.path`;
- print token-shaped values;
- copy OAuth stores between accounts;
- run live probes or pass `--confirm-spend` unless the user explicitly
  authorized spend.

`discover --json` is intentionally redacted. It reports config path, state path,
providers, account names, secret backend names, tags, profiles, and safe command
templates. It does not include token material.

`accounts list --json` is the richer per-account state surface for agents. Use
it after `providers list --json` when deciding whether the next step is a
provider-specific setup command, a runtime diagnostic, a route explanation, a
handoff, or a live proof run.
For Codex, the optional `auth_identity` object is still redacted but can expose
enough auth-bound metadata to disambiguate named route stores: masked email
hint, short account-id hash, claim-source classes, and explicit booleans that
raw email, token material, and auth paths were not printed. Agents should use
that surface instead of opening Codex auth files when deciding whether `max-1`
or another route needs a labeled `oauth-mux codex login-device <account>`
handoff.

`enroll plan <provider> --json` is safe for agents because it only explains the
setup sequence. Agents may present steps with `agent_safe:false` to a user or
permission broker, but must not run those steps without explicit consent.

`enroll codex --account <name> --confirm-enroll --json`,
`enroll claude --account <name> --confirm-enroll --json`, and
`enroll figma --account <name> --confirm-enroll --json` are not agent-safe by
default because they mutate config. Agents may request them through a
permission broker, but must not infer that the account is authenticated until
the user has run the returned login/secret/proof handoffs and checks pass.

`report --redacted --json` is the support-bundle surface. It adds platform,
config shape, provider/account labels, command availability, health summaries,
and recent probe evidence. It never reads credential values and omits credential
paths unless the user explicitly passes `--include-paths`.

`providers list --json` separates support status from proof status. `codex` is
`live_proven`; shipped schemas are `built_in`; user JSON providers are
`schema_modeled`; non-Codex providers still carry provider-level
`needs_operator_proof` until live provider QA proves the full route family.
Capability entries expose narrower proof status in `capability_budgets`:
`live_proven` for hosted secret-scoped proof, `local_live_proven` for local
operator proof, `public_live_proven` for no-secret public metadata proof, and
`needs_operator_proof` for modeled-but-unproven capabilities. They also expose
non-secret `proof_requirements` so agents can ask for the right env var, CLI
login, plan token, file key, or consent gate without guessing.

## Provider Onboarding Checklist

1. Add or select a provider definition.
2. Add named accounts and secret backends.
3. Add profiles that encode provider/account/capability fallback order.
4. Run `oauth-mux config validate`.
5. Run `oauth-mux doctor --json`, `oauth-mux report --redacted --json`, and
   `oauth-mux accounts list --json` plus `oauth-mux discover --json`.
6. Run `oauth-mux enroll plan <provider> --json` before adding an N+1 account.
7. For Codex N+1, run
   `oauth-mux enroll codex --account <name> --confirm-enroll --json`, then the
   returned `oauth-mux codex login-device <name>` handoff.
8. For Claude N+1, run
   `oauth-mux enroll claude --account <name> --confirm-enroll --json`, then the
   returned `env CLAUDE_CONFIG_DIR=... claude auth login` handoff.
9. For Figma N+1, run
   `oauth-mux enroll figma --account <name> --mode <oauth|pat|plan>
   --confirm-enroll --json`, then set the returned secret env var before any
   proof probe.
10. Run no-spend checks first: `status`, `health`, and credential parse probes.
11. Run live probes only through `scripts/live-provider-qa.sh` or the manual
   Live Provider QA workflow.

## Operator Definition of Done

- Config validates.
- `accounts list --json` exposes every expected account with redacted runtime
  and liveness state, plus redacted auth-bound identity hints when available.
- `enroll plan <provider> --json` describes any remaining setup without running
  it.
- Confirmed Codex enrollment returns a user-mediated login handoff instead of
  silently running upstream auth.
- `discover --json` is usable by agents.
- `report --redacted --json` is usable for a support bundle without token
  material.
- `providers list --json` states provider support and proof status precisely.
- `status --json` shows expected providers and accounts.
- `health --json` is redacted.
- First live QA run is captured under `dist/live-qa/`.
- Rollback path is documented before registry publication.
