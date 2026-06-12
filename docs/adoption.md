# Adoption Path

`oauth-mux` should be usable by people who are not running the Tinyland lab
stack. Lab SOPS, GloriousFlywheel, and Codex Max canaries are proving grounds;
they must not become requirements for ordinary users.

## README And Site Entry

The first screen of the README and website should answer four questions before
deep evidence or architecture:

1. What works today?
   Managed Codex launch/resume, native chooser/session bridge, config
   passthrough, redacted status artifacts, and live managed Codex quota
   handoff across enrolled routes.
2. What is still not claimed?
   Same-thread provider semantics, mid-turn streaming recovery, unmanaged
   daemon hot-swap, and non-Codex harness stay-afloat.
3. How do I try it safely?
   Install, run diagnostics, follow labeled auth handoffs, then start
   `oauth-mux codex resume`.
4. How can an agent inspect state?
   Use JSON commands that do not read token values or spend provider calls.

Recommended first-screen command block:

```bash
npm install -g oauth-mux
oauth-mux init --codex-max
oauth-mux doctor
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux codex resume
```

Recommended agent-safe block:

```bash
oauth-mux doctor runtime --profile codex-max --capability codex-max --json
oauth-mux accounts list --provider codex --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux codex status-latest --json
```

Do not put raw emails, account ids, token claims, credential paths, or session
ids in public screenshots, web copy, or agent prompts.

Use `docs/README.md` as the docs landing page. Website navigation should mirror
that shape: start with user install/try paths, then agent/operator diagnostics,
then proof and provider-author material.

## Install Surfaces

Target install surfaces:

- npm: `npm install -g oauth-mux`
- Homebrew public tap:
  `brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git && brew install jesssullivan/omux/oauth-mux`
- curl installer: `curl -fsSL ... | sh`
- deb/rpm packages for Linux hosts
- raw release tarballs for air-gapped or policy-managed systems

The public Homebrew tap is `Jesssullivan/homebrew-omux`, documented in
`docs/spec/homebrew-public-lane-decision-2026-05-01.md`. The older
`tinyland-inc/homebrew-tools` tap remains private/staged Tinyland
infrastructure, not public adoption copy.
The DRY release/install lane contract is `docs/release-install-lanes.md`; keep
new UX/DX/AX installer copy aligned with that file rather than duplicating
package-state tables here. As of the 2026-06-12 v0.1.13 release, public GitHub
Release, Homebrew tap, curl installer assets, and system package assets resolve
to `0.1.13`; npm remains stale at `0.1.9` pending a registry token rotation
(see the productionization ledger for per-lane truth). Package-lane QA proves
installability and metadata, not live provider handoff behavior.

When validating unreleased source behavior, install or invoke the worktree build
deliberately and record provenance:

```bash
which -a oauth-mux
scripts/project-version.sh
oauth-mux version
shasum -a 256 ./zig-out/bin/oauth-mux
shasum -a 256 "$(command -v oauth-mux)"
```

PATH should resolve to the intended installed test binary. Homebrew install
checks remain package-lane QA and should not be used as evidence for unreleased
worktree behavior unless the local formula has been explicitly rebuilt and
installed.

Each release artifact should be derived from the same CI release tree. npm is
published only from CI tarballs; workstation `npm publish` is not supported.
Use npm provenance when the GitHub source repository is public.

## First User Experience

The happy path should stay small and should not ask users to learn every
diagnostic command before starting Codex.

Human Codex path:

```bash
oauth-mux init --codex-max
oauth-mux doctor
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux codex resume
```

Agent diagnostic path:

```bash
oauth-mux doctor runtime --profile <profile> --capability <capability> --json
oauth-mux accounts list --provider <provider> --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux repair-plan --profile <profile> --capability <capability> --json
```

Provider-enrollment path:

```bash
oauth-mux enroll plan <provider> --json
oauth-mux enroll codex --account <name> --confirm-enroll --json
oauth-mux enroll claude --account <name> --confirm-enroll --json
oauth-mux enroll figma --account <name> --mode pat --confirm-enroll --json
```

Source checkouts prove the first-run path without touching real operator state:

```bash
just first-run-e2e
```

When checking unreleased behavior from source, use the remote validation lanes
first (`just remote-build`, `just remote-check`, or `just remote-e2e`). Local
`just run -- ...`, `just build`, or `./zig-out/bin/oauth-mux` are debugging
tools only and should not be used as readiness proof on developer laptops.

Live probes remain explicit because they can spend subscription calls:

```bash
oauth-mux codex live-qa
oauth-mux codex live-qa --confirm-spend
oauth-mux codex probe-all --capability codex-mini --json
```

For daily Codex use, the first-class managed entrypoint is now:

```bash
oauth-mux codex
oauth-mux codex resume
oauth-mux codex resume --last
oauth-mux codex resume <session-id>
```

These commands launch the real Codex CLI inside an oauth-mux managed frame.
Auth and the proxy base URL are mux-owned in a managed `CODEX_HOME`, while Codex
session authority is bridged by reference to the canonical Codex home unless
`--isolated-session-store` is set. In canonical bridge mode the managed home is
durable under the authority home and scrubbed on exit; oauth-mux removes copied
auth/config material but keeps the bridge so native Codex rollout paths recorded
through the managed frame remain resumable. `oauth-mux codex resume` with no id
keeps native Codex chooser ownership; oauth-mux only checks before spawn that
the managed overlay exposes the same required session-authority entries so the
chooser does not open empty. When canonical Codex has `state_5.sqlite*` or
`logs_2.sqlite*`, those files are bridged by reference; in canonical bridge
mode `CODEX_SQLITE_HOME` points at the canonical authority home so Codex 0.132+
uses the same SQLite resume store as bare Codex. Older homes use the legacy
session/history/index/snapshot set.
The portability policy is
`docs/spec/codex-session-store-portability-policy-2026-05-18.md`: oauth-mux
does not silently copy or import unmanaged rollout stores into route-local
account homes.

Codex behavior config is preserved by default. The managed overlay reads the
canonical config authority from `OMUX_CODEX_CONFIG_HOME`, then parent
`CODEX_HOME`, then `~/.codex`, preserving settings such as `[features]`,
legacy `experimental_*`, MCP servers, approval/sandbox policy, profiles, model
defaults, and custom non-managed providers. oauth-mux strips the selected
`model_provider`, `openai_base_url`, and stale
`[model_providers.oauth_mux_openai]` entries before appending
`model_provider = "openai"` plus a localhost `openai_base_url`. Forwarded Codex
`--config` / `-c` assignments that try to override mux-owned provider/base-url
keys fail before child spawn with a redacted `config_passthrough_check` status
event. The generated config uses
`config_layout:"root_partitioned"` so managed root keys cannot land inside a
trailing user table.

If a resume chooser still appears different after upgrading, check the managed
status stream before editing Codex state. `resume_authority_check` reports
whether canonical SQLite authority is bridged and whether legacy
`oauth_mux_openai` provider-namespace residue was detected. oauth-mux does not
rewrite canonical `state_5.sqlite*` or `logs_2.sqlite*`; cleanup must be an
explicit, backed-up operator action.
When a Codex experimental feature key is absent, the managed overlay defaults
`terminal_resize_reflow`, `memories`, `external_migration`, `goals`, and
`prevent_idle_sleep` on for the child config only. Explicit canonical values,
including `false`, are preserved, and the canonical `config.toml` is not
mutated.

`doctor runtime`, `route explain`, `route select`, `codex preflight`,
`stay-afloat next`, `stay-afloat --once`, and bounded `stay-afloat --loop` are
diagnostic surfaces when run without `--execute`. They only use local runtime
checks plus recorded liveness, so they are safe for agents to run before
deciding whether a live probe or user-driven reauth is warranted. `codex
preflight` also classifies the visible `codex` PATH entries so operators can
see whether active `codex` is the managed oauth-mux shim and which native Codex
binary `OMUX_CODEX_BIN` should point at when bypassing the shim.
`stay-afloat --execute` is the beta foreground execution boundary: for Codex it
may run admitted provider-spend revalidation only for expired quota/rate windows
under the Codex stay-afloat policy, or queue an interactive handoff event.
Prefer scoped runtime checks such as `oauth-mux doctor runtime --profile
codex-max --capability codex-max --json` or `oauth-mux codex preflight --profile
codex-max --capability codex-max --json` when dogfooding a specific stay-afloat
route; global runtime doctor is still useful for support bundles and
full-machine cleanup.

`oauth-mux stay-afloat next --json` is the simplest agent handoff: it returns
an exact `exec_argv` when already afloat, otherwise it returns the typed repair
or user-handoff action to mediate before retrying. It also returns `claim`:
`prepared_fallback` means use `claim.launch_argv` for a fresh harness process,
while current-process hot swap, supervised restart, and per-request muxing are
explicitly false. Restart is not a product level; true active-session
stay-afloat requires the running harness to accept a live handoff without
logout, resume, restart, or lost thread.
`resilience.spare_fallback_ready:false` / `claim.single_route_at_risk:true`
means the selected route can launch but no other selectable route is currently
ready behind it. Codex app-server auth brokering is now tracked as the first
plausible current-process proof path for mediated Codex sessions, but it is not
a claim for unmanaged Codex TUI/CLI processes.

`oauth-mux codex managed-plan` and `oauth-mux codex managed` remain older
diagnostic/planning surfaces for route-local native launch experiments. They
are not the primary user spelling for managed Codex sessions. Prefer
`oauth-mux codex resume ...` for the broker-mediated frame that carries the
current resume chooser, config passthrough, startup timing, and status
artifact behavior. This is still managed process launch/resume, not an
unmanaged bare-`codex` in-place daemon handoff claim.

The managed Codex quota handoff claim is now live-proven for installed
`oauth-mux codex resume` artifacts. The strongest 2026-05-09 evidence shows a
successful primary route reaching provider-originated `usage_limit_reached`,
oauth-mux retrying the same buffered request on a distinct fallback route, and
the fallback returning 200. Public adoption copy may say managed Codex live
quota handoff is proven, but must not turn that into a same-thread continuity,
mid-turn streaming recovery, unmanaged daemon, or non-Codex provider claim.

`oauth-mux codex broker-plan --profile codex-max --capability codex-max --json`
is the diagnostic broker readiness check. It reads configured Codex auth stores
locally and reports whether each route can supply `accessToken`,
`chatgptAccountId`, and `chatgptPlanType` for a future app-server broker. Its
output is redacted and planning-only; it does not run Codex, contact OpenAI,
read route liveness, claim prepared fallback, or prove live hot-swap. Use
`broker-session-plan` for route-aware broker-owned session selection.

`oauth-mux codex broker-smoke --profile codex-max --capability codex-max
--confirm-broker --json` is the next proof step. It starts a broker-owned Codex
app-server child over stdio, initializes it with `experimentalApi`, sends the
selected route's ChatGPT auth token to that child, and verifies the external
auth login notifications. It still does not claim unmanaged TUI hot-swap,
per-request muxing, quota recovery, or live 401 repair; it is a local protocol
smoke for mediated app-server sessions and its output suppresses token,
account-id, and raw protocol values.

`oauth-mux codex broker-refresh-smoke --profile codex-max --capability
codex-max --confirm-broker --json` extends that local proof by answering an
app-server `account/chatgptAuthTokens/refresh` request with the next ready
route token tuple when a fallback account exists. This proves the
refresh-response selection primitive needed for future live 401 repair in
mediated sessions. It is still not an unmanaged current TUI hot-swap,
per-request mux, or quota-recovery claim.

`oauth-mux codex broker-401-smoke --profile codex-max --capability codex-max
--confirm-broker --json` proves the controlled diagnostic 401 retry loop for a
broker-owned Codex app-server session. oauth-mux points Responses and ChatGPT
backend traffic at a local mock, returns 401 to the first turn Responses
request, answers app-server refresh with the next ready route, and verifies the
retry uses the fallback token. This is the current strongest mediated Codex
proof; it still does not claim unmanaged TUI hot-swap.

`oauth-mux codex broker-quota-smoke --profile codex-max --capability codex-max
--confirm-broker --json` proves the diagnostic quota boundary. It returns a local
usage-limit 429 to the first turn, observes that Codex does not issue the 401
auth-refresh hook, applies a fallback app-server login, and verifies a new
brokered thread uses fallback Authorization. Same-thread quota recovery remains
explicitly unproven.

`oauth-mux codex broker-session-plan --profile codex-max --capability codex-max
--json` is the diagnostic UX planning surface for broker-owned Codex sessions. It
combines recorded route liveness with app-server auth-broker readiness, then
reports the selected route, immediate selectable fallbacks, quota-blocked broker
routes, and the same explicit no-hot-swap/no-same-thread quota boundary. Its
`resilience` object is the operator shortcut: `spare_fallback_ready:false` with
`single_route_at_risk:true` means the selected broker session can start, but no
second route is currently ready behind it. For Codex routes, the broker-session,
`route explain`, and `stay-afloat` surfaces expose the same todo list:
revalidate exhausted routes behind an explicit spend gate, enroll another Codex
account, or wait for quota reset. JSON clients read `resilience_actions`; text
output prints the matching `next:` hint.

`oauth-mux codex broker-session-smoke --profile codex-max --capability codex-max
--confirm-broker --json` is the matching diagnostic multi-turn UX smoke. It uses
the session plan's selected and fallback routes, starts a broker-owned
app-server against local mocked backend endpoints, simulates quota exhaustion on
turn one, and verifies a new brokered thread uses the fallback route.

`oauth-mux codex broker-run --profile codex-max --capability codex-max --prompt
... --confirm-spend --json` is the explicit live one-turn proof for the same
broker-owned UX. It starts the selected route against Codex's default live
provider and emits redacted protocol evidence without printing prompt text,
assistant output, tokens, account ids, or raw app-server protocol. A live
quota/rate-limit failure is recorded as route-health evidence and the output
reports the next selected route plus the post-failure broker-session resilience
state and actions.
For a bounded beta multi-turn session, pass `--stdin` instead of `--prompt` and
pipe one prompt per line. The session stays broker-owned and redacted; the
output reports prompt counts and completed turns, not transcript content. Add
`--continue-on-failure` to start a fresh broker-owned session on the next
selected route after a live quota/rate-limit failure. The command replays the
failed prompt plus remaining queued prompts and reports that this is
next-session continuation, not same-thread recovery.

Observed native Codex behavior reinforces that boundary: on 2026-05-03, a
provider-owned Codex session reported `You've hit your usage limit` and did not
offer an oauth-mux account handoff. Manual logout/login restored route readiness
for future mediated launches, but it did not prove in-place or same-thread
fallback.

`oauth-mux codex revalidate-exhausted --profile codex-max --capability
codex-max --confirm-spend --json` is the operator-safe post-billing-change
refresh. It targets Codex routes already recorded as quota-exhausted or
rate-limited, bypasses only those local route-health blocks, spends confirmed
provider probes, and persists the fresh provider evidence. Use it after credits
or plan changes instead of manually resetting health keys. It may make a route
selectable again, or it may confirm that the provider still rejects that exact
capability.
Expired local reset windows surface as `revalidation_needed`: the route is no
longer presented as an active wait, but it also is not trusted until a
spend-gated revalidation records fresh provider evidence.

`oauth-mux codex broker-fallback-drill --profile codex-max --capability
codex-max --from-account max-3 --confirm-drill --json` is the controlled
operator drill for observing fallback without waiting for a provider-originated
quota event. It mutates local route health by recording the named route as
quota-exhausted, then verifies the next broker-owned route selection chooses a
distinct fallback. It does not spend provider calls and does not claim
same-thread quota recovery or unmanaged TUI hot-swap.

`oauth-mux stay-afloat launch -- <command>` is the matching startup command for
users and wrappers. It executes the target only after a selectable route is
found from recorded evidence. The delegated `exec` path still validates local
runtime and token state before the target starts; if that reclassifies the
selected route, launch re-runs selection and tries the next selectable account.
If no route remains selectable, launch prints refreshed mediation text and exits
nonzero without starting the target. If no route is selectable at preflight, it
also prints mediation text and exits nonzero without starting the target.
`oauth-mux stay-afloat observe --classify-exit-code <code> -- <command>` is a diagnostic child-boundary
surface. It keeps oauth-mux as the parent process, injects the selected route
into a child, observes typed failure, and stops. The legacy restart-shaped flags
do not make restart an acceptable stay-afloat path; if used, JSON marks them as
`legacy_restart_aliases_used:true` and scopes their effect to compatibility
classification only.
For Codex dogfood, add `--classify-codex-usage-limit`. That mode captures
child output, classifies the native usage-limit screen, records the selected
route as quota-exhausted, appends a redacted `stay_afloat_observe` event, and
stops without relaunching a fallback child. Captured provider output remains hidden.
Add `--stream-capture` with that classifier when dogfood needs visible child
output: oauth-mux tees the child stream while keeping bounded classifier
buffers and redacted artifacts. In `--json` mode, the live child stream goes to
stderr so stdout stays machine-readable.

`oauth-mux accounts list --json` is the provider-neutral account inventory
surface. It reports configured accounts, runtime readiness, capability proof,
recorded liveness, and safe next commands without reading credential values.
`oauth-mux enroll plan <provider> --json` is the provider-neutral planning
surface. It does not mutate config or auth state; it marks each provider-specific
step as agent-safe, interactive, mutating, or provider-call-spending so users
and agents can ask for consent at the right boundary.
`oauth-mux enroll codex --account <name> --confirm-enroll --json`,
`oauth-mux enroll claude --account <name> --confirm-enroll --json`, and
`oauth-mux enroll figma --account <name> --mode <oauth|pat|plan>
--confirm-enroll --json` are the first consented provider-neutral enrollment
mutations. They update oauth-mux config, add provider routes, and return
explicit login, secret, or proof handoffs. They do not run upstream login, open
a browser, create token material, or spend provider calls.
After a user-mediated upstream login, `oauth-mux stay-afloat refresh --profile
<profile> --capability <capability> --json` is the concise evidence refresh
step that can clear pending handoffs.

`oauth-mux repair run --profile <profile> --capability <capability> --json` is
also safe without confirmation. It will not open a browser, run `codex login`,
or mutate credential stores unless the user supplies `--confirm-repair`.

Route, runtime, repair-plan, and stay-afloat JSON also report `writeback`. Use
that field when deciding whether a future repair loop can refresh in place:
`replace_file` means the backend has a provider-neutral file write surface, but
`automatic_refresh_admitted` can still be false when the provider owns repair
through its upstream CLI. Current automatic refresh follows that contract: it
will not call a token endpoint unless writeback is admitted, and admitted file
backends are replaced atomically.

Runtime repair actions also report `diagnostic_command`. That command is for
the user, wrapper, or permission broker to run in the correct process boundary;
it is not an automatic repair command and should not be treated as provider
failure evidence.

The wrapper contract lives in
`docs/spec/stay-afloat-permission-broker-contract-2026-05-01.md`. Use that
contract before adding a shell hook, CI wrapper, service unit, or agent
permission broker around stay-afloat.
The account enrollment and agent inventory contract lives in
`docs/spec/account-enrollment-agent-contract-2026-05-01.md`. Use that contract
before broadening provider-neutral enrollment commands or MCP mutation tools.

## Wrapper Author Experience

Wrappers should call the foreground command contract, not the socket daemon:

```bash
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --loop --iterations <n> --interval-ms <ms> --profile <profile> --capability <capability> --json
oauth-mux codex preflight --profile <profile> --capability <capability> --json
```

A wrapper may act automatically only on admitted, non-interactive,
non-mutating work, except for explicitly admitted Codex expired-window
revalidation under the Codex stay-afloat policy. For `codex preflight`, wrappers
should consume `agent_safe_next_actions` automatically and reserve
`spend_confirmed_next_actions` for a user-approved route-health repair step.
Interactive auth handoffs appear in `user_mediated_next_actions`; wrappers
should display those exact commands and let the human run the upstream CLI login
flow. When JSON reports
`repair_summary.route_repair_required:true`, wrappers can use
`repair_summary.dominant_blocker` and the route-state counters to decide whether
the next user-visible state is spend-confirmed revalidation, interactive auth
handoff, local runtime repair, or wait-only retry. When JSON reports
`action.kind:"fix_runtime"` with
`action.command:null`, the wrapper should display or broker
`action.diagnostic_command` in the user-owned process boundary, then rerun
`stay-afloat` or `route explain`. It must not infer credential liveness from a
runtime diagnostic, rewrite provider stores, or treat `systemd`, `launchd`,
Homebrew services, cron, Windows Services, containers, or CI as product
semantics.

## Provider Author Experience

A new provider should usually start as data, not Zig:

1. Write a JSON provider definition with credential parsing, injection, probes,
   and failure rules.
2. Add redacted fixtures for the provider's success, rate-limit, quota,
   degraded, and auth-dead responses.
3. Run `oauth-mux config validate` and the no-secret E2E harness.
4. Run live QA only with explicit account-scoped consent.

Compiled Zig changes should be reserved for new transports, parser primitives,
or core liveness algebra changes.

Provider authors should use `oauth-mux providers list --json` to verify whether
their provider is currently `built_in`, `schema_modeled`, `live_proven`, or still
waiting on `needs_operator_proof`. Capability entries can be promoted more
narrowly with `local_live_proven` or `public_live_proven` before the whole
provider family is proven. The same JSON includes non-secret
`proof_requirements`, which is the agent-safe handoff list for missing tokens,
provider CLI logins, file keys, and live proof consent.

## Non-Tinyland Deployments

External users may use any secret backend that fits their environment:

- env references
- files under XDG or platform config dirs
- keychain or `secret-tool`
- command backends
- SOPS/age
- stdin for short-lived automation

No adoption flow should require the lab repo, Tinyland SOPS keys,
GloriousFlywheel, or Codex Max accounts.

Clean-install proof is tracked in `docs/install-beta-matrix.md`. Keep that
matrix current whenever a published or staged install lane changes state.

Open adoption gaps are tracked in
`docs/spec/product-gap-issue-map-2026-05-01.md`. That map links the public
GitHub issues and Linear tickets for the remaining Homebrew distribution,
stay-afloat daemon, and non-Codex provider proof work.

## Product Adoption Sprint

The current adoption plan is tracked in
`docs/spec/product-adoption-sprint-2026-04-28.md`. The current dogfood and
real OAuth flow proof plan is tracked in
`docs/spec/dogfood-e2e-oauth-flow-plan-2026-04-30.md`. The stay-afloat runtime
and daemon gap plan is tracked in
`docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md`, and the portable
foreground supervisor contract is tracked in
`docs/spec/stay-afloat-supervisor-contract-2026-05-01.md`. Together they cover:

- website structure and public positioning;
- current onboarding/doctor/report scope;
- launch sequencing and outreach;
- provider-author feedback loops;
- follow-up Linear split from `TIN-491`;
- the `TIN-867` decision that the socket daemon remains non-product
  status/control plumbing for the current release line.

## Ownership And URL

The canonical public source repo is `Jesssullivan/oauth-mux`. The preferred
project URL is `https://omux.xoxd.ai`, with Tinyland remaining the development
and release-infrastructure partner. See
`docs/spec/repository-ownership-and-url-2026-04-28.md`.
