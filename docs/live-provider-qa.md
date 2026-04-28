# Live Provider QA

Live provider QA is manual and secret-scoped because provider probes can spend
real subscription calls.

## Local Run

Build first:

```bash
just build
```

Probe a profile:

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
OMUX_LIVE_QA_ACCOUNTS=max-1,max-2,max-3 \
OMUX_LIVE_QA_CAPABILITIES=codex-mini \
just live-qa
```

Escalate to higher-cost routes only after the cheaper route is healthy:

```bash
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
OMUX_LIVE_QA_PROVIDER=codex \
OMUX_LIVE_QA_ACCOUNTS=max-1,max-2,max-3 \
OMUX_LIVE_QA_CAPABILITIES=codex-max \
just live-qa
```

For the Codex Max three-account path, prefer the canary before any spending
run:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json oauth-mux codex canary
```

That command validates config, prints discovery/status evidence, and checks
`codex login status` for each account without running probes. Add `--live` only
when the canary should also invoke this live QA matrix.

Artifacts are written under `dist/live-qa/<timestamp>/`:

- `config-validate.txt`
- `discover.json`
- one JSON file per probe
- `health.json`

By default, live QA passes when a probe returns a typed, redacted liveness
result, even if the route is currently unavailable as `rate_limited`,
`quota_exhausted`, or `degraded`. That makes quota exhaustion useful evidence
rather than a false infrastructure failure. Set
`OMUX_LIVE_QA_REQUIRE_AVAILABLE=1` when the run must fail unless every probed
route is immediately selectable. Dead credentials fail by default; set
`OMUX_LIVE_QA_ALLOW_DEAD=1` only for negative test fixtures.

Operator-provided Codex state on 2026-04-28:

- `max-1#codex-max` and `max-2#codex-max` are expected to classify as
  `live/quota_exhausted` until weekly limits refresh.
- `max-3` is expected to remain active for API-backed usage.
- These are not auth-dead accounts; the useful proof is preserving the
  distinction between weekly quota exhaustion and usable fallback routes.

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
secret-scoped config. A config secret alone is not enough if it points at
machine-local `CODEX_HOME` directories that only exist on a workstation.

## Policy

- Start with the lowest-cost capability.
- Use account-specific probes when validating fallback behavior.
- Treat `rate_limited`, `quota_exhausted`, `degraded`, and `dead` as distinct
  outcomes.
- Do not schedule this workflow until budgets and provider terms are explicit.
- Do not use live QA as a background daemon loop.
