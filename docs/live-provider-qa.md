# Live Provider QA

Live provider QA is manual and secret-scoped because provider probes can spend
real subscription calls.
The canonical route-state and handoff matrix is `docs/qa-handoff-matrix.md`.

## Remote-First Run

Build/prove the checkout on the remote runner first:

```bash
just remote-build
```

Then probe a profile from the intended operator machine, because live provider
QA uses local account stores and may spend real subscription calls:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_LIVE_QA_PROFILE=codex-mini \
OMUX_LIVE_QA_CAPABILITIES=codex-mini \
just live-qa
```

Probe an account matrix:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_LIVE_QA_PROVIDER=codex \
OMUX_LIVE_QA_ACCOUNTS=max-1,max-2,max-3,max-4 \
OMUX_LIVE_QA_CAPABILITIES=codex-mini \
just live-qa
```

Escalate to higher-cost routes only after the cheaper route is healthy:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_LIVE_QA_PROVIDER=codex \
OMUX_LIVE_QA_ACCOUNTS=max-1,max-2,max-3,max-4 \
OMUX_LIVE_QA_CAPABILITIES=codex-max \
just live-qa
```

For the Codex Max starter path, prefer the canary before any spending run:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex canary
```

That command validates config, prints discovery/status evidence, and checks
`codex login status` for each account without running probes. Use the guarded
live QA command when the installed CLI should also invoke this live matrix:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex live-qa
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex live-qa --confirm-spend
```

For `codex live-qa --json`, top-level `ok` is a mux coverage result: every
requested capability must have at least one currently available account.
Individual exhausted, limited, degraded, or dead routes remain visible through
`routes_unavailable` and each route's typed `liveness`, so one spent account
does not hide the fact that another account can still carry the capability.

For a focused account matrix on one route class:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
  oauth-mux codex probe-all --capability codex-mini --json
```

Artifacts are written under `dist/live-qa/<timestamp>/`:

- `config-validate.txt`
- `discover.json`
- one valid JSON file plus one redacted log file per probe
- `health.json`

By default, live QA passes when a probe returns a typed, redacted liveness
result, even if the route is currently unavailable as `rate_limited`,
`quota_exhausted`, or `degraded`. That makes quota exhaustion useful evidence
rather than a false infrastructure failure. Set
`OMUX_LIVE_QA_REQUIRE_AVAILABLE=1` when the run must fail unless every probed
route is immediately selectable. Dead credentials fail by default; set
`OMUX_LIVE_QA_ALLOW_DEAD=1` only for negative test fixtures.

Probe artifacts include `ok`, `error`, and `exit_code` fields. A nonzero probe
exit with typed non-dead `liveness` is still accepted unless
`OMUX_LIVE_QA_REQUIRE_AVAILABLE=1`; missing or unreadable credentials classify
as `dead` and fail the run by default.

Historical operator-provided Codex state on 2026-04-28:

- `max-1#codex-max` and `max-2#codex-max` are expected to classify as
  `live/quota_exhausted` until weekly limits refresh.
- `max-3` is expected to remain active for API-backed usage.
- These are not auth-dead accounts; the useful proof is preserving the
  distinction between weekly quota exhaustion and usable fallback routes.
This three-route snapshot is retained only to explain earlier artifacts. Use
the current four-route section below for operator decisions and website copy.

Historical four-route Codex dogfood state on 2026-05-03:

- The source example remains the three-route starter config. Add `max-4` to the
  active operator config with `oauth-mux enroll codex --account max-4
  --confirm-enroll --json` before using the four-route account matrix.
- `max-1#codex-max` is selectable again after spend-gated exhausted-route
  revalidation.
- `max-4#codex-max` is the spare selectable fallback.
- `max-2#codex-max` and `max-3#codex-max` still return provider quota
  exhaustion from fresh probes.
- Dashboard credit or Spark/mini availability is not generalized to
  `codex-max`; trust provider execution evidence per route and capability.

Hosted evidence from run `25029923810`:

- `codex-mini`: all three accounts returned `live/available` and
  `decision=use_this`.
- `codex-max`: `max-1` and `max-2` returned `live/quota_exhausted` and
  `decision=try_next_account`; `max-3` returned `live/available` and
  `decision=use_this`.

Current post-handoff Codex Max route truth moves with operator auth and reset
windows. Use `docs/qa-handoff-matrix.md` as the canonical current-state matrix
and refresh diagnostic truth with:

```bash
oauth-mux route explain --profile codex-max --capability codex-max --json
oauth-mux accounts list --provider codex --json
```

After the 2026-05-09 engineered handoff burn, the important durable claim is
not any one account's later availability state; it is that managed Codex quota
handoff from `codex:max-2` to `codex:max-3` is preserved in
`docs/evidence/codex-engineered-quota-handoff-20260509/`. Do not describe the
pool as afloat unless current diagnostic route truth shows a selectable primary
and fallback.

Hosted evidence from PR-branch run `25134175687` on 2026-04-29:

- Branch `codex/v013-doctor-onboarding` at `06e1ab0`.
- `codex-mini`: `max-1`, `max-2`, and `max-3` returned
  `live/available`, HTTP 200, and `decision=use_this`.
- `codex-max`: `max-1`, `max-2`, and `max-3` returned
  `live/available`, HTTP 200, and `decision=use_this`.
- The first rerun failed before provider probing because
  `OMUX_LIVE_QA_CONFIG_B64` was missing after the repository transfer. The fix
  was to refresh `OMUX_LIVE_QA_CONFIG_B64` and set
  `OMUX_LIVE_QA_STORE_TGZ_B64` from a minimized credential bundle containing
  only `auth.json`, `installation_id`, and per-account `config.toml` files.

## Low-Impact Identity Probes

GitHub and Linear are the first non-Codex provider-proof lane because their
built-in `identity` capabilities use provider-owned identity endpoints and do
not send model prompts, create records, or mutate upstream state.

GitHub uses `GET https://api.github.com/user` with bearer auth. A fine-grained
token does not need explicit permissions for the endpoint; OAuth app tokens and
classic PATs may need `user` scope only for private profile fields. The probe
captures the `x-ratelimit-remaining` header as a classification hint and never
stores the raw token.

```bash
OMUX_CONFIG=$PWD/examples/github.config.json \
OMUX_GITHUB_WORK_TOKEN="$(gh auth token)" \
  ./zig-out/bin/oauth-mux probe --profile github --capability identity --json
```

Linear uses `POST https://api.linear.app/graphql` with
`query Me { viewer { id name email } }` and OAuth bearer auth. A GraphQL `200`
with an `errors` array is treated as degraded instead of live.

```bash
OMUX_CONFIG=$PWD/examples/linear.config.json \
OMUX_LINEAR_WORK_TOKEN="$LINEAR_ACCESS_TOKEN" \
  ./zig-out/bin/oauth-mux probe --profile linear --capability identity --json
```

Linear personal API keys use a raw `Authorization` header, not `Bearer`. Use
the explicit API-key capability when proving a personal key:

```bash
OMUX_CONFIG=$PWD/examples/linear-api-key.config.json \
  ./zig-out/bin/oauth-mux probe --profile linear-api-key --capability identity-api-key --json
```

Figma PAT identity uses `X-Figma-Token`, not bearer auth. Use the explicit PAT
profile when proving that mode:

```bash
OMUX_CONFIG=$PWD/examples/figma-pat.config.json \
OMUX_FIGMA_PAT="$FIGMA_ACCESS_TOKEN" \
  ./zig-out/bin/oauth-mux probe --profile figma-pat --capability identity-pat --json
```

To capture local artifacts through the same wrapper used by hosted provider QA:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_CONFIG=$PWD/examples/github.config.json \
OMUX_GITHUB_WORK_TOKEN="$(gh auth token)" \
OMUX_LIVE_QA_PROFILE=github \
OMUX_LIVE_QA_CAPABILITIES=identity \
  just live-qa

OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_CONFIG=$PWD/examples/linear.config.json \
OMUX_LINEAR_WORK_TOKEN="$LINEAR_ACCESS_TOKEN" \
OMUX_LIVE_QA_PROFILE=linear \
OMUX_LIVE_QA_CAPABILITIES=identity \
  just live-qa

OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_CONFIG=$PWD/examples/linear-api-key.config.json \
OMUX_LIVE_QA_PROFILE=linear-api-key \
OMUX_LIVE_QA_CAPABILITIES=identity-api-key \
  just live-qa

OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_CONFIG=$PWD/examples/figma-pat.config.json \
OMUX_FIGMA_PAT="$FIGMA_ACCESS_TOKEN" \
OMUX_LIVE_QA_PROFILE=figma-pat \
OMUX_LIVE_QA_CAPABILITIES=identity-pat \
  just live-qa
```

These probes are still explicit live provider calls. Keep them out of default
checks and scheduled daemon loops. A successful local artifact may promote the
specific capability to `local_live_proven`, but do not promote the whole GitHub
Linear, or Figma provider from `needs_operator_proof` until the provider's
intended auth modes have attached redacted evidence.

2026-05-01 local SOPS-backed evidence:

- GitHub `identity`: HTTP 200, `live.available`, `decision=use_this`.
- Vercel `identity`: HTTP 200, `live.available`, `decision=use_this`.
- Linear `identity-api-key`: HTTP 200, `live.available`, `decision=use_this`.
- Linear OAuth bearer `identity`: using the personal API key as bearer returned
  HTTP 400 and stays `needs_operator_proof`.
- Figma PAT `identity-pat`: HTTP 200, `live.available`,
  `decision=use_this`.
- MCP `resource-metadata`: HTTP 200, valid RFC 9728/MCP metadata,
  `live.available`.
- MCP `resource` with a Figma PAT as bearer candidate: HTTP 405,
  `degraded.unknown_4xx`; this is not resource-token proof.

## Paid Multi-Account Proof Cohort

The next dogfood lane is tracked in Linear `TIN-892` and specified in
`docs/spec/paid-multi-account-proof-cohort-2026-05-01.md`. It is a one-month
paid cohort, not a default CI lane.

Target shapes:

- Codex: the current dogfood lane has four Max-capable routes. Keep lower-tier
  OAuth as a separate contrast target; do not infer Max availability from
  dashboard or Spark/mini credit text.
- Claude Code: three isolated account/billing shapes across Pro, Max, and a
  team/API-billed route where available.
- Figma: three token/resource shapes across PAT, OAuth bearer, and
  Organization/Enterprise plan-token file metadata if that spend is approved.

The cohort uses the same explicit confirmation gates as other live QA:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
  just live-qa
```

Do not schedule the paid cohort. It is a manual artifact-producing lane for
provider proof and foreground stay-afloat soak evidence. The pass condition is
not "every account is available"; the pass condition is that every unavailable
account is typed correctly and at least one route can carry the requested
capability when the cohort is expected to stay afloat.
Use `docs/spec/paid-cohort-soak-claim-policy-2026-05-03.md` for the soak
cadence, required redacted artifacts, claim-state vocabulary, and promotion
blockers before website or README copy expands.

## GitHub Workflow

`.github/workflows/live-provider-qa.yml` is manual-only. It requires the
dispatch input `confirm=spend-real-calls`.

For private configs, store a base64-encoded config in the repository secret
`OMUX_LIVE_QA_CONFIG_B64`. The workflow decodes it into `$RUNNER_TEMP` and sets
`OMUX_CONFIG` for the job. Keep the config secret-scoped and prefer secret
backends such as command, keychain, sops, age, or env references. Do not put raw
tokens in the workflow file or repository.

For command-probe providers such as Codex, the hosted runner also needs the
provider CLI and account credential stores available at the paths named by the
secret-scoped config. The workflow can install the Codex CLI from
`@openai/codex` before probes. Pin the version with the `codex_cli_version`
dispatch input.

Hosted Codex credential stores are materialized from
`OMUX_LIVE_QA_STORE_TGZ_B64`, a base64-encoded `tar.gz` whose paths are relative
to `$HOME`. For the standard Codex Max config, include only the minimal files
needed by each account store:

```text
.local/share/oauth-mux/codex/max-1/auth.json
.local/share/oauth-mux/codex/max-1/config.toml        # when present
.local/share/oauth-mux/codex/max-1/installation_id
.local/share/oauth-mux/codex/max-2/auth.json
.local/share/oauth-mux/codex/max-2/config.toml        # when present
.local/share/oauth-mux/codex/max-2/installation_id
.local/share/oauth-mux/codex/max-3/auth.json
.local/share/oauth-mux/codex/max-3/config.toml        # when present
.local/share/oauth-mux/codex/max-3/installation_id
```

Omit caches and logs such as `models_cache.json` and `log/`. The workflow
rejects absolute paths and parent traversal entries before extraction, then
tightens permissions under `$HOME/.local/share/oauth-mux`.

## Policy

- Start with the lowest-cost capability.
- Use account-specific probes when validating fallback behavior.
- Treat `rate_limited`, `quota_exhausted`, `degraded`, and `dead` as distinct
  outcomes.
- Do not schedule this workflow until budgets and provider terms are explicit.
- Do not use live QA as a background daemon loop.
