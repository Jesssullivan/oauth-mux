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
oauth-mux discover
```

Codex Max three-account starter:

```bash
oauth-mux init --codex-max
oauth-mux doctor
oauth-mux doctor runtime --json
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
oauth-mux repair-plan --profile codex-max --capability codex-max --json
oauth-mux repair-plan --profile codex-mini --capability codex-mini --json
```

`route explain` and `route select` are no-spend commands. They read runtime
readiness plus recorded route liveness and do not probe providers or mutate auth
state. Unrecorded routes are reported as `probe_needed`, and `route select`
exits nonzero when no route has enough evidence to be selected.

`oauth-mux repair run` is the explicit repair execution gate. It refuses
mutation unless `--confirm-repair` is present. Without confirmation, it is safe
for agents to run because it only reports that a route is already selectable,
that no admitted repair exists, or that a specific upstream CLI command would
need user approval.

If `repair-plan --profile codex-max` reports a config validation error, the
active config is not the three-account Codex Max shape. That usually means the
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
for `oauth-mux codex probe-all`. Route selection and explanation should be run
through the installed CLI directly:

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

`report --redacted --json` is the support-bundle surface. It adds platform,
config shape, provider/account labels, command availability, health summaries,
and recent probe evidence. It never reads credential values and omits credential
paths unless the user explicitly passes `--include-paths`.

`providers list --json` separates support status from proof status. `codex` is
`live_proven`; shipped schemas are `built_in`; user JSON providers are
`schema_modeled`; non-Codex providers still carry `needs_operator_proof` until
live provider QA proves them.

## Provider Onboarding Checklist

1. Add or select a provider definition.
2. Add named accounts and secret backends.
3. Add profiles that encode provider/account/capability fallback order.
4. Run `oauth-mux config validate`.
5. Run `oauth-mux doctor --json`, `oauth-mux report --redacted --json`, and
   `oauth-mux discover --json`.
6. Run no-spend checks first: `status`, `health`, and credential parse probes.
7. Run live probes only through `scripts/live-provider-qa.sh` or the manual
   Live Provider QA workflow.

## Operator Definition of Done

- Config validates.
- `discover --json` is usable by agents.
- `report --redacted --json` is usable for a support bundle without token
  material.
- `providers list --json` states provider support and proof status precisely.
- `status --json` shows expected providers and accounts.
- `health --json` is redacted.
- First live QA run is captured under `dist/live-qa/`.
- Rollback path is documented before registry publication.
