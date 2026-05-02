# Adoption Path

`oauth-mux` should be usable by people who are not running the Tinyland lab
stack. Lab SOPS, GloriousFlywheel, and Codex Max canaries are proving grounds;
they must not become requirements for ordinary users.

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

Each release artifact should be derived from the same CI release tree. npm is
published only from CI tarballs; workstation `npm publish` is not supported.
Use npm provenance when the GitHub source repository is public.

## First User Experience

The happy path should stay small:

```bash
oauth-mux init
oauth-mux doctor
oauth-mux report --redacted
oauth-mux providers list
oauth-mux accounts list
oauth-mux enroll plan <provider>
oauth-mux enroll codex --account <name> --confirm-enroll
oauth-mux enroll claude --account <name> --confirm-enroll
oauth-mux enroll figma --account <name> --mode pat --confirm-enroll
oauth-mux config validate
oauth-mux discover --json
oauth-mux doctor runtime --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux stay-afloat next --profile <profile> --capability <capability> --json
oauth-mux stay-afloat launch --profile <profile> --capability <capability> -- <command>
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat handoffs --json
oauth-mux stay-afloat refresh --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile <profile> --capability <capability> --json
```

Source checkouts prove this path without touching real operator state:

```bash
just first-run-e2e
```

For Codex subscription users working from a source checkout today:

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
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux route select --profile codex-max --capability codex-max --json
oauth-mux stay-afloat --once --profile codex-max --capability codex-max --json
oauth-mux stay-afloat handoffs --json
oauth-mux stay-afloat refresh --profile codex-max --capability codex-max --json
oauth-mux stay-afloat --loop --iterations 2 --interval-ms 0 --profile codex-max --capability codex-max --json
```

Those commands are installed CLI surface, not source-checkout-only helpers.
Users can override the default three-account shape with
`--accounts work,personal,team` and can point account stores somewhere explicit
with `--store-root <path>`.

Live probes remain explicit because they can spend subscription calls:

```bash
oauth-mux codex live-qa
oauth-mux codex live-qa --confirm-spend
oauth-mux codex probe-all --capability codex-mini --json
```

`doctor runtime`, `route explain`, `route select`, `stay-afloat next`,
`stay-afloat --once`, and bounded `stay-afloat --loop` are no-spend surfaces
when run without `--execute`. They only use local runtime checks plus recorded
liveness, so they are safe for agents to run before deciding whether a live
probe or user-driven reauth is warranted. `stay-afloat --execute` is the beta
foreground execution boundary: it can run one admitted non-interactive action
or queue an interactive handoff event. Prefer scoped runtime checks such as
`oauth-mux doctor runtime --profile codex-max --capability codex-max --json`
when dogfooding a specific stay-afloat route; global runtime doctor is still
useful for support bundles and full-machine cleanup.

`oauth-mux stay-afloat next --json` is the simplest agent handoff: it returns
an exact `exec_argv` when already afloat, otherwise it returns the typed repair
or user-handoff action to mediate before retrying. It also returns `claim`:
`prepared_fallback` means use `claim.launch_argv` for a fresh harness process,
while current-process hot swap, supervised restart, and per-request muxing are
explicitly false until those product levels are implemented and proven. Codex
app-server auth brokering is now tracked as the first plausible
current-process proof path for mediated Codex sessions, but it is not a claim
for unmanaged Codex TUI/CLI processes.

`oauth-mux codex broker-plan --profile codex-max --capability codex-max --json`
is the no-spend broker readiness check. It reads configured Codex auth stores
locally and reports whether each route can supply `accessToken`,
`chatgptAccountId`, and `chatgptPlanType` for a future app-server broker. Its
output is redacted and planning-only; it does not run Codex, contact OpenAI, or
prove live hot-swap.

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
--confirm-broker --json` proves the controlled no-spend 401 retry loop for a
broker-owned Codex app-server session. oauth-mux points Responses and ChatGPT
backend traffic at a local mock, returns 401 to the first turn Responses
request, answers app-server refresh with the next ready route, and verifies the
retry uses the fallback token. This is the current strongest mediated Codex
proof; it still does not claim unmanaged TUI hot-swap.

`oauth-mux stay-afloat launch -- <command>` is the matching startup command for
users and wrappers. It executes the target only after a selectable route is
found from recorded evidence. The delegated `exec` path still validates local
runtime and token state before the target starts; if that reclassifies the
selected route, launch re-runs selection and tries the next selectable account.
If no route remains selectable, launch prints refreshed mediation text and exits
nonzero without starting the target. If no route is selectable at preflight, it
also prints mediation text and exits nonzero without starting the target.

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
```

A wrapper may act automatically only on admitted, non-interactive,
non-mutating work. When JSON reports `action.kind:"fix_runtime"` with
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
- `v0.1.3` onboarding/doctor/report scope;
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
