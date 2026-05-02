# oauth-mux

**Site:** https://omux.xoxd.ai — typed-fallback model, install paths, and the live provider matrix.  
**Source:** github.com/Jesssullivan/oauth-mux

`oauth-mux` is a compiled OAuth fallback mux for AI harness subscriptions and
connector auth. It selects among configured provider accounts, records typed
credential liveness, and falls through without poisoning an entire account when
only one route or capability is unavailable.

`oauth-mux` is a Jess Sullivan FOSS project built with Tinyland release
infrastructure.

The implementation is pure Zig with no external Zig dependencies.

## Current Shape

- Typed liveness model: `live`, `degraded`, `dead`.
- Route-scoped health keys: `provider:account#capability`.
- Provider definitions for credential parsing, env/config injection, failure
  rules, and HTTP or command probes.
- Built-in examples for Codex, Claude, GitHub, Linear, Vercel, Figma, FlakeHub,
  and MCP HTTP resource-server probes.
- Release graph for six targets:
  - `x86_64-linux-musl`
  - `aarch64-linux-musl`
  - `x86_64-macos`
  - `aarch64-macos`
  - `x86_64-windows`
  - `aarch64-windows`

## Development

Use `just` as the operator entrypoint:

```bash
just build
just test
just check
just release
```

`just check` enters the Nix dev shell and then runs `just check-local`, which
runs Zig tests, builds the binary, validates every example config, and runs the
synthetic local E2E harness.

## Quick Checks

Discover the redacted, agent-safe inventory:

```bash
oauth-mux doctor
oauth-mux report --redacted
oauth-mux providers list
oauth-mux accounts list --json
oauth-mux enroll plan codex --account max-4 --json
oauth-mux enroll codex --account max-4 --confirm-enroll --json
oauth-mux enroll plan claude --account work --json
oauth-mux enroll claude --account work --confirm-enroll --json
oauth-mux enroll plan figma --account design --mode pat --json
oauth-mux enroll figma --account design --mode pat --secret-env OMUX_FIGMA_DESIGN_PAT --confirm-enroll --json
oauth-mux discover --json
oauth-mux doctor runtime --json
```

Validate an example:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json ./zig-out/bin/oauth-mux config validate
```

Probe a configured account:

```bash
./zig-out/bin/oauth-mux probe --provider codex --account max-1 --capability codex-mini --json
```

Run the no-spend Codex Max canary:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex canary
```

Run guarded live route QA only when real Codex calls are intended:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex live-qa
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex live-qa --confirm-spend
```

`codex live-qa --json` reports both per-route liveness and mux coverage.
`routes_unavailable` can be nonzero while top-level `ok` remains true when
another account still covers each requested capability. If an entire requested
capability has no available account, `capabilities_uncovered` becomes nonzero
and the command exits nonzero.

Explain current Codex Max stay-afloat actions without running probes or
mutating auth state:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux route explain --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux route select --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux stay-afloat next --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux stay-afloat launch --profile codex-max --capability codex-max -- codex
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux repair-plan --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux accounts list --provider codex --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux doctor runtime --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-plan --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-session-smoke --profile codex-max --capability codex-max --confirm-broker --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-run --profile codex-max --capability codex-max --prompt 'Reply with oauth-mux broker-run ok.' --confirm-spend --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-smoke --profile codex-max --capability codex-max --confirm-broker --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-refresh-smoke --profile codex-max --capability codex-max --confirm-broker --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-401-smoke --profile codex-max --capability codex-max --confirm-broker --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex broker-quota-smoke --profile codex-max --capability codex-max --confirm-broker --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux repair run --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux stay-afloat --once --profile codex-max --capability codex-max --json
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile codex-max --capability codex-max --json
oauth-mux daemon events --json
```

`route select` and `route explain` are no-spend stay-afloat commands. They use
recorded route liveness plus runtime readiness; unrecorded routes are reported
as `probe_needed` instead of being treated as available.

`stay-afloat next --json` is the agent-facing bridge from route state to action.
When a route is selectable, it returns `ready_for_exec:true` plus an exact
`exec_argv` pinned to provider, account, and capability. When no route is
selectable, it returns `ready_for_exec:false` plus the typed repair or handoff
action without running probes, auth flows, provider calls, target commands, or
secret mutation. It also returns a `claim` object so agents can distinguish the
current product level: today `prepared_fallback` means a new process can be
launched through `claim.launch_argv`, while `current_process_hotswap`,
`supervised_restart`, and `per_request_muxing` remain false.
Codex app-server auth brokering is a separate proof track for mediated Codex
sessions, not a current public claim.
`codex broker-plan --json` is the no-spend first slice of that track: it reads
configured Codex stores locally and reports whether each route can supply the
external-auth tuple Codex app-server expects, without printing tokens, account
ids, credential paths, or provider-call evidence.
`codex broker-session-plan --json` combines that broker readiness with recorded
route liveness. It reports the selected broker-owned session route, immediate
selectable fallback routes, quota-blocked routes, and the explicit claim
boundary without starting Codex or probing providers.
`codex broker-session-smoke --confirm-broker --json` takes the next no-spend UX
step: it uses the session plan's selected and fallback routes, starts a local
broker-owned app-server session against mocked Responses/ChatGPT endpoints, and
proves new-thread fallback after simulated quota exhaustion.
`codex broker-run --prompt ... --confirm-spend --json` is the explicit live
one-turn proof for that UX path. It uses the session plan's selected route,
starts a broker-owned app-server against Codex's default live provider, sends
one prompt, and reports only redacted protocol evidence; prompt text, assistant
output, tokens, account ids, and raw protocol output are not printed.
For a bounded beta session loop, pipe line-delimited prompts to `codex
broker-run --stdin --confirm-spend --json`; the command keeps one broker-owned
app-server session open and reports prompt/turn counts without printing
transcript content.
`codex broker-smoke --confirm-broker --json` is the next local proof: it starts
a broker-owned Codex app-server stdio child, sends the selected route token to
that child only, and verifies initialize/login/account-update milestones while
still suppressing token, account-id, and raw protocol output.
`codex broker-refresh-smoke --confirm-broker --json` proves the next app-server
primitive: after external-auth login, oauth-mux can observe
`account/chatgptAuthTokens/refresh` and answer it with the next ready route
token tuple when a fallback account exists. This is still a local mediated
app-server protocol proof, not an unmanaged running Codex TUI hot-swap or
quota-recovery claim.
`codex broker-401-smoke --confirm-broker --json` closes the next local proof:
it starts a broker-owned Codex app-server, points both OpenAI Responses and
ChatGPT backend traffic at a local mock, returns a 401 to the first turn
Responses request, answers the app-server refresh request with the next ready
route, and verifies the retried Responses request uses that fallback token. It
still does not claim unmanaged TUI hot-swap.
`codex broker-quota-smoke --confirm-broker --json` proves the adjacent quota
boundary without overclaiming: a local mock returns a usage-limit 429 to the
first turn, Codex does not emit the 401 auth-refresh hook, oauth-mux applies a
fallback login, and a new brokered thread uses the fallback route. Same-thread
quota recovery is reported as not proven.

`stay-afloat launch -- <command>` is the target execution boundary for new
harness sessions. It uses the same no-spend preflight as `stay-afloat next`; if
a route is selectable, it launches the target through `oauth-mux exec` with the
selected provider/account/capability pinned. `exec` still performs normal
token/runtime validation before the target starts; if that validation
reclassifies the selected route, launch re-runs selection and tries the next
selectable account. If no route remains selectable, launch prints the refreshed
mediation text and exits nonzero without running the target. If no route is
selectable at preflight, launch also prints the mediated repair/handoff text
and exits nonzero without running the target.

`doctor runtime --json` is also no-spend. It checks local runtime prerequisites
such as upstream binaries, configured account store directories, write access,
and expected session files without reading token values or contacting providers.
Use `doctor runtime --profile <name> --capability <name> --json` when a user or
agent needs profile-level truth without letting a stale unrelated account poison
the stay-afloat decision.

`accounts list --json` is the provider-neutral account inventory. It reports
configured provider accounts, secret backend names, runtime readiness,
writeback admission, capability proof, recorded liveness, selectability, and
safe next commands without reading credential values.

`enroll plan <provider> --json` is also non-mutating. It turns the inventory
into an explicit provider-specific setup plan, marking which steps are
agent-safe, interactive, mutating, or provider-call-spending before anything is
run.

`enroll codex --account <name> --confirm-enroll --json`,
`enroll claude --account <name> --confirm-enroll --json`, and
`enroll figma --account <name> --mode <oauth|pat|plan> --confirm-enroll
--json` are the first consented provider-neutral enrollment mutations. They add
named accounts to the active oauth-mux config and return explicit login, secret,
or proof handoffs. They do not run provider login or provider probes.

`repair run` is the explicit mutation boundary. Without `--confirm-repair`, it
will not open auth flows or run upstream CLI repair commands; it only reports
whether a route is already selectable, whether no admitted repair exists, or
which command would require confirmation. Confirmed interactive repairs should
be run without `--json` so upstream CLI login output cannot corrupt machine
readable output.

Every `repair run` invocation appends a redacted local event under the
oauth-mux state directory. Confirmed repair uses an account-scoped advisory
lock so concurrent repair attempts surface as `repair_in_progress` in runtime
readiness instead of racing an upstream CLI login flow. Inspect recent events
with `oauth-mux daemon events --json`; this does not require the daemon to be
running. `oauth-mux daemon status --json` is local socket inspection only; it
reports `contract:"experimental_socket_stub"` and `hosts_stay_afloat:false` so
wrappers do not mistake the socket stub for the stay-afloat supervisor.

Refresh attempts use the same local event stream. `token_refresh` events record
only route identity, writeback capability, admission, outcome, and redacted
reason. They do not include access tokens, refresh tokens, credential paths, or
provider response bodies.

Daemon admission is policy-gated. By default, background/daemon planning admits
only `free_local` and `free_command` work; `cheap_provider`, `spend_provider`,
`interactive`, and `mutating` actions are reported as refused until the config
explicitly allows them. `route explain --json` and `repair-plan --json` include
the effective policy plus per-route admission decisions so agents can back off
without guessing. `stay-afloat --once --json` evaluates the same routes under
that policy. By default it is planning-only and reports `executed:false`.
`stay-afloat --once --execute --json` is the opt-in beta execution boundary: it
runs at most one admitted non-interactive action per tick, such as a
`free_command` probe, then re-reads route state. Interactive reauth is never run
silently; execute mode records a redacted `daemon_handoff` event with the user
command to run. Repeated ticks report an existing handoff as pending instead of
duplicating the event. Inspect those queued user-mediated repairs with
`oauth-mux stay-afloat handoffs --json`; add `--all` to include historical
handoff events after a later stay-afloat tick has refreshed route evidence.
`stay-afloat --loop --iterations <n> --interval-ms <ms> --json` repeats the same
portable foreground tick for dogfood and wrappers. No `systemctl`, `launchctl`,
service manager, browser auth, provider spend, or secret mutation is assumed
unless policy and CLI flags explicitly admit it. Tick JSON includes route-level
`next_tick_after` and `schedule_reason` fields, plus top-level summary wake-up
hints, so wrappers can sleep or back off without guessing. The built-in loop
uses the earliest summary wake-up hint between ticks, bounded by
`--interval-ms`, without changing daemon admission policy. Tick JSON and the
latest `daemon status --json` snapshot also include `claim.level`. A
`prepared_fallback` claim means the next mediated `stay-afloat launch` can pick
a route; it does not claim current-process hot-swap, supervised restart, or
per-request muxing. A provider-specific auth-broker path, starting with Codex
app-server external auth, must be proven before `current_process_hotswap` can
be true. `daemon status --json` also reports
`stay_afloat_snapshot` metadata with presence, parseability, `last_tick_at`,
`age_seconds`, active-loop correlation, a 300 second staleness threshold, and a
fresh/stale reason so wrappers can reject old prepared-fallback claims. When
`daemon run --stay-afloat` is active, `daemon status --json` also reports
`stay_afloat_loop.selector`, `interval_ms`, `iterations`, and `execution_mode`
so operators can verify which profile/capability the beta host is actually
supervising.

Secret read and writeback are also separate. Route and runtime JSON expose a
`writeback` object with the secret backend capability and whether automatic
refresh writeback is admitted. CLI-owned stores such as Codex can be readable
file stores while still refusing oauth-mux refresh mutation because repair is
owned by the upstream CLI. Automatic OAuth refresh is gated by that same
admission plan: today only `oauth_mux_refresh` providers with `replace_file`
secret backends can persist refreshed credentials.

First-run Codex subscription path:

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
oauth-mux codex broker-plan --profile codex-max --capability codex-max --json
oauth-mux codex broker-session-plan --profile codex-max --capability codex-max --json
oauth-mux codex broker-session-smoke --profile codex-max --capability codex-max --confirm-broker --json
oauth-mux codex broker-run --profile codex-max --capability codex-max --prompt 'Reply with oauth-mux broker-run ok.' --confirm-spend --json
oauth-mux codex broker-smoke --profile codex-max --capability codex-max --confirm-broker --json
oauth-mux codex broker-refresh-smoke --profile codex-max --capability codex-max --confirm-broker --json
oauth-mux codex broker-401-smoke --profile codex-max --capability codex-max --confirm-broker --json
oauth-mux codex broker-quota-smoke --profile codex-max --capability codex-max --confirm-broker --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux repair-plan --profile codex-max --capability codex-max --json
oauth-mux repair run --profile codex-max --capability codex-max --json
```

If an existing config only has a single `codex:default` account, create a safe
sidecar Codex Max candidate without overwriting it:

```bash
oauth-mux codex config-candidate
oauth-mux codex config-merge --candidate ~/.config/oauth-mux/codex-max.config.json
```

`oauth-mux doctor --json` and `oauth-mux discover --json` expose
`codex_max_configured`; when it is false for a Codex config, they recommend that
same candidate command. `config-merge` validates the candidate, backs up the
active config, and merges only the Codex Max provider/profiles into place so
other configured providers remain intact.

Run the deterministic no-secret E2E harness:

```bash
just e2e
```

That harness creates a temporary provider config and proves env injection,
command probes, route-scoped quota fallback, health persistence, and `exec`
target injection without contacting live OAuth providers.

## Release Staging

Build local release artifacts from one version:

```bash
just release-local 0.1.0
```

Outputs are written under `dist/out/v0.1.0/`:

- `artifacts/` for binary tarballs and `SHA256SUMS`
- `artifacts/install.sh` for checksum-verified `curl | sh` installs
- `homebrew/oauth-mux.rb`
- `npm/` package workspace
- `npm-tarballs/`
- `nfpm/` configs plus deb/rpm artifacts

Build and smoke-test the same release tree:

```bash
just release-proof 0.1.0
```

Generate the non-publishing operator handoff for the staged tree:

```bash
just release-handoff 0.1.0
```

The handoff is written under `dist/out/v0.1.0/handoff/` and lists GitHub
Release attachments, npm publish order, Homebrew tap input, deb/rpm files, and
full checksums.

See `docs/release-runbook.md` for release and CI details.
See `docs/adoption.md` for installation and external-user adoption goals.
See `docs/install-beta-matrix.md` for current clean-install dogfood evidence.
See `docs/onboarding.md` for human and agent onboarding.
See `docs/live-provider-qa.md` for manual secret-scoped provider probes.
See `docs/registry-dry-runs-and-rollback.md` for publication dry-runs and
rollback.
See `docs/daemon-boundary.md` for the current daemon decision.
See `docs/spec/development-timeline-2026-04-27.md` for the current
production-readiness timeline.
See `docs/spec/production-publication-sprint-2026-04-28.md` for the current
v0.1.0 sprint gates.
See `docs/spec/product-adoption-sprint-2026-04-28.md` for the current website,
onboarding, launch, and provider-adoption plan.
See `docs/spec/repository-ownership-and-url-2026-04-28.md` for the repository
ownership and canonical website URL decision.
