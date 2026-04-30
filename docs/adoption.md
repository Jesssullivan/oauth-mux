# Adoption Path

`oauth-mux` should be usable by people who are not running the Tinyland lab
stack. Lab SOPS, GloriousFlywheel, and Codex Max canaries are proving grounds;
they must not become requirements for ordinary users.

## Install Surfaces

Target install surfaces:

- npm: `npm install -g oauth-mux`
- Homebrew: `brew tap tinyland/tools https://github.com/tinyland-inc/homebrew-tools.git && brew install tinyland/tools/oauth-mux`
- curl installer: `curl -fsSL ... | sh`
- deb/rpm packages for Linux hosts
- raw release tarballs for air-gapped or policy-managed systems

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
oauth-mux config validate
oauth-mux discover --json
oauth-mux doctor runtime --json
oauth-mux route explain --profile <profile> --capability <capability> --json
oauth-mux stay-afloat --once --profile <profile> --capability <capability> --json
oauth-mux stay-afloat handoffs --json
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
oauth-mux setup codex
oauth-mux codex canary
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux route select --profile codex-max --capability codex-max --json
oauth-mux stay-afloat --once --profile codex-max --capability codex-max --json
oauth-mux stay-afloat handoffs --json
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

`doctor runtime`, `route explain`, `route select`, `stay-afloat --once`, and
bounded `stay-afloat --loop` are no-spend surfaces when run without
`--execute`. They only use local runtime checks plus recorded liveness, so they
are safe for agents to run before deciding whether a live probe or user-driven
reauth is warranted. `stay-afloat --execute` is the beta foreground execution
boundary: it can run one admitted non-interactive action or queue an interactive
handoff event. Prefer scoped runtime checks such as
`oauth-mux doctor runtime --profile codex-max --capability codex-max --json`
when dogfooding a specific stay-afloat route; global runtime doctor is still
useful for support bundles and full-machine cleanup.

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
waiting on `needs_operator_proof`.

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

## Product Adoption Sprint

The current adoption plan is tracked in
`docs/spec/product-adoption-sprint-2026-04-28.md`. The current dogfood and
real OAuth flow proof plan is tracked in
`docs/spec/dogfood-e2e-oauth-flow-plan-2026-04-30.md`. The stay-afloat runtime
and daemon gap plan is tracked in
`docs/spec/stay-afloat-runtime-daemon-plan-2026-04-30.md`. Together they cover:

- website structure and public positioning;
- `v0.1.3` onboarding/doctor/report scope;
- launch sequencing and outreach;
- provider-author feedback loops;
- follow-up Linear split from `TIN-491`.

## Ownership And URL

The canonical public source repo is `Jesssullivan/oauth-mux`. The preferred
project URL is `https://omux.xoxd.ai`, with Tinyland remaining the development
and release-infrastructure partner. See
`docs/spec/repository-ownership-and-url-2026-04-28.md`.
