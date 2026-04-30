# Dogfood E2E OAuth Flow Plan
Date: 2026-04-30

Issue context: `TIN-736` (Expand oauth-mux provider proof beyond Codex),
`TIN-812` (Dogfood install surfaces), `TIN-814` (non-mutating Codex help),
`TIN-734` (website launch truth), and `tinyland-inc/lab#197`.

## Current State

`oauth-mux` is no longer speculative for the first target lane. The repo has a
public canonical source, a public npm package, release assets, installed
diagnostic commands, typed liveness, route-scoped health, and a live-proven
three-account Codex path.

The next risk is not compiler correctness. The next risk is adoption truth:
whether a user can arrive from an advertised install command, configure expected
OAuth accounts without confusion, run safe diagnostics, and get useful fallback
behavior when one provider route is limited, degraded, or dead.

## Proven Surfaces

Install surfaces:

| Surface | Current proof |
| --- | --- |
| npm global install | `oauth-mux@0.1.3` installs from the public npm registry and returns `oauth-mux 0.1.3`. |
| npm one-shot | `npx -y oauth-mux@0.1.3 version` passed from `../lab`. |
| GitHub Release tarball | v0.1.3 macOS arm64 tarball verifies against `SHA256SUMS` and runs. |
| curl installer | v0.1.3 installer downloads public release assets, verifies checksums, and runs on macOS and `../lab`. |
| Homebrew | `just homebrew-qa 0.1.3` installs from `tinyland/tools`, runs `brew audit`, `brew test`, `version`, and `doctor --json`. The tap is still private. |
| deb/rpm | Hosted System Package Install QA run `25137323710`, job `73678810909`, installed published `.deb` and `.rpm` assets in Debian/Rocky containers. |
| lab dogfood | Installed CLI reports healthy `doctor --json` against the local config/state. |

OAuth and muxing surfaces:

| Surface | Current proof |
| --- | --- |
| Codex three-account stores | `max-1`, `max-2`, and `max-3` are isolated by `CODEX_HOME` and report logged-in ChatGPT status. |
| Codex route liveness | Hosted and local installed-binary live canaries have proven all three accounts across `codex-mini` and `codex-max`. Earlier proof also preserved the distinction between quota exhaustion and auth death. |
| Typed liveness | Unit and e2e tests cover `live`, `degraded`, `dead`, route-scoped `provider:account#capability`, and fallback decisions. |
| Agent-safe discovery | `doctor --json`, `doctor runtime --json`, scoped `doctor runtime`, `report --redacted --json`, `providers list --json`, `discover --json`, `status --json`, `health --json`, `route explain --json`, and `route select --json` exist and are documented. |
| Non-mutating help | `oauth-mux codex canary --help`, `oauth-mux codex probe-all --help`, and `oauth-mux setup codex --help` print help without creating stores or probing. |

## Not Yet Proven

These are the adoption blockers that should stay visible:

1. Non-Codex live provider proof is still mostly schema-level.
   Built-ins exist for Claude, GitHub, Vercel, Linear, Figma, FlakeHub, Gemini,
   and MCP, but only Codex is currently `live_proven`.

2. Clean first-run OAuth is not yet a single captured journey.
   We have install proof and Codex account proof, but we still need recorded
   flows that start from no config and end with named accounts, diagnostics,
   and a canary result.

3. Multi-provider fallback is not yet live-proven.
   The local e2e harness proves fallback with toy providers, and Codex proves
   multi-account fallback. We still need a real mixed-provider story such as
   Codex plus GitHub, Claude, Vercel, or Linear where each provider has a
   redacted live probe result.

4. Secret-backend breadth is uneven.
   File, command, and keychain-shaped paths are in active use. SOPS/age,
   stdin, and env references need explicit e2e proof before public copy implies
   they are equally dogfooded.

5. Homebrew is private-tap proven, not public-tap proven.
   This is fine for operator dogfood, but public website copy should either say
   the tap is private/staged or wait for a public tap stance.

6. The daemon remains deferred.
   Daemon start/stop/status exist, but background refresh/probe behavior is not
   a product surface until `TIN-738` defines provider ownership, budgets, and
   anti-surprise rules.

7. Stay-afloat automation is not yet built.
   The mux can fall through from a quota-exhausted Codex route to an available
   account, but it does not yet automatically repair stale credentials, persist
   refreshed tokens, or drive browser/device reauth. See
   `docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md`.

## User Story Gates

Each story should have a reproducible command path and a redacted evidence
artifact before broad adoption copy claims it.

### Story A: New User, No Existing Config

Goal: prove a user can install, initialize, inspect, and understand next steps.

Required path:

```bash
oauth-mux version
oauth-mux doctor --json
oauth-mux init --codex-max
oauth-mux config validate
oauth-mux doctor runtime --json
oauth-mux doctor runtime --profile codex-max --capability codex-max --json
oauth-mux discover --json
oauth-mux report --redacted --json
oauth-mux codex canary
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux route select --profile codex-max --capability codex-max --json
oauth-mux repair run --profile codex-max --capability codex-max --json
oauth-mux codex canary --help
```

Acceptance:

- no credential values are read or printed;
- help is non-mutating;
- diagnostics point to the next safe command;
- runtime diagnostics classify unbootstrapped account stores without creating
  them;
- route explanation does not probe or mutate;
- route selection refuses to select unrecorded health optimistically;
- generated config validates from a clean state.

Automated source-checkout proof:

```bash
just first-run-e2e
```

This lane runs the required path with a temporary `HOME`, XDG config/state/data
roots, and no inherited `OMUX_*` overrides. It also verifies the Codex Max
starter config uses the same resolved store root as Codex setup, so users with
`XDG_DATA_HOME` or `OMUX_CODEX_STORE_ROOT` do not get split-brain account paths.

### Story B: Codex Subscription User With Three Accounts

Goal: prove the flagship multi-account subscription use case.

Required path:

```bash
oauth-mux setup codex
oauth-mux codex canary
oauth-mux codex live-qa
OMUX_LIVE_QA_CONFIRM=spend-real-calls oauth-mux codex live-qa
oauth-mux codex probe-all --capability codex-mini --json
oauth-mux codex probe-all --capability codex-max --json
oauth-mux health --json
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux route select --profile codex-max --capability codex-max --json
```

Acceptance:

- each account is isolated by `CODEX_HOME`;
- login status is visible without printing token material;
- live probes classify available, rate-limited, quota-exhausted, degraded, and
  dead states distinctly;
- a bad `codex-max` route does not poison the same account for `codex-mini`.

2026-04-30 dogfood evidence:

- Running Codex probes inside a restricted sandbox produced false
  `degraded:unknown_4xx` results because Codex could not write its session
  files under the isolated `CODEX_HOME`.
- Running outside that sandbox proved the product path:
  `codex:max-1#codex-mini` was available, `codex:max-1#codex-max` was
  `live.quota_exhausted`, and `oauth-mux` selected
  `codex:max-2#codex-max` successfully.

This is fallback proof, not automatic reauth proof.

### Story C: Agent-Safe Discovery And Support Bundle

Goal: prove an AI harness can inspect what it may safely do.

Required path:

```bash
oauth-mux doctor --json
oauth-mux report --redacted --json
oauth-mux providers list --json
oauth-mux discover --json
oauth-mux status --json
oauth-mux health --json
oauth-mux doctor runtime --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux route select --profile <profile> --capability <capability> --json
```

Acceptance:

- output is parseable JSON where promised;
- account names, profiles, proof status, and safe commands are visible;
- no OAuth tokens, bearer headers, cookies, or raw credential paths are printed
  unless an explicit path-including flag is used;
- provider proof status distinguishes `live_proven`, `built_in`,
  `schema_modeled`, and `needs_operator_proof`.

### Story D: Provider Author Adds A Provider

Goal: prove the extensibility promise.

Required path:

1. add a JSON provider definition with credential parse paths, injection,
   probes, and failure rules;
2. add redacted fixtures for success, rate limit, quota exhaustion, degraded,
   auth-dead, and provider-degraded responses;
3. run `oauth-mux config validate`;
4. run no-secret e2e;
5. run live QA only with explicit account-scoped consent.

Acceptance:

- the provider can begin as data, not Zig;
- all failure rules have matchers;
- probe transport is admitted by the provider-probe admission matrix;
- live proof is captured before public `live_proven` status.

### Story E: Mixed OAuth Operator

Goal: prove oauth-mux is useful beyond one harness.

Candidate first mixed profile:

```json
{
  "providers": [
    "codex:max-1#codex-mini",
    "github:default#identity",
    "vercel:default#identity",
    "claude:personal#auth-status"
  ]
}
```

Acceptance:

- every route has a no-secret validation path;
- each live route produces typed liveness evidence;
- unavailable routes fall through without hiding the reason;
- `route explain` reports skipped routes without spending provider calls;
- command availability and missing upstream CLIs are reported as diagnostics,
  not silent failures.

## Provider Proof Sequence

Wave 1 should favor providers already present on the operator machine:

| Provider | Why first | Target proof |
| --- | --- | --- |
| GitHub | `gh` is available and `GET /user` has clear auth semantics. | command-backed token or `gh auth token`, `identity` probe, rate-limit classification. |
| Vercel | `vercel` is available and `/v2/user` is simple. | token source, `identity` probe, 401/403/degraded classification. |
| Claude | `claude` is available and auth status is a command probe. | isolated config-dir proof, `auth-status`, logged-out classification. |

Wave 2 should cover OAuth/MCP and plan-token complexity:

| Provider | Main risk |
| --- | --- |
| Linear | GraphQL viewer probe and OAuth/PAT distinction must be documented. |
| Figma | OAuth `/v1/me`, PAT, and plan-token file metadata have different auth envelopes. |
| FlakeHub | Determinate/FlakeHub CLI availability is partial on this host. |
| MCP HTTP | RFC 9728 protected-resource metadata and resource probes need real server fixtures. |
| Gemini | CLI is not available on this host, so install/setup truth comes first. |

## Claim Policy

Public copy should use these words precisely:

- `live_proven`: real credential or account store, explicit consent, redacted
  artifact, typed liveness, and successful hosted or local proof.
- `built_in`: compiled provider schema, probes, and failure rules exist, but
  live proof is not yet recorded.
- `schema_modeled`: user or example JSON provider definition validates.
- `planned`: no supported provider definition yet.

Do not call a provider "supported" without also exposing whether it is
`live_proven` or only `built_in`.

## Next Execution Order

1. Land M1 one-shot stay-afloat route selection and explanation.
2. Keep the clean first-run e2e script proving Story A without touching
   existing credentials, including runtime diagnostics, route explanation, and
   route-select refusal before health evidence exists.
3. Extend the live-provider QA harness to accept provider-specific lanes for
   GitHub, Vercel, and Claude.
4. Run and record Wave 1 live proof, then update provider proof status only for
   providers that pass.
5. Reconcile website copy with this matrix before launch traffic.
6. Defer daemon promotion until provider refresh ownership and live QA budgets
   are explicit.

## Linear Split

The immediate execution tickets are:

- `TIN-815`: clean first-run e2e harness for onboarding.
- `TIN-818`: provider proof Wave 1 for GitHub, Vercel, and Claude.
- `TIN-816`: provider proof Wave 2 for Linear, Figma, FlakeHub, MCP, and
  Gemini.

`TIN-736` is the parent lane for provider proof beyond Codex. Website launch
work should consume this proof matrix through `TIN-734`, `TIN-786`, and
`TIN-801` so public claims do not drift ahead of runtime evidence.
