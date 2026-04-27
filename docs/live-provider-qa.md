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

Current Codex behavior observed on 2026-04-27:

- `max-1`, `max-2`, and `max-3` are all logged in and remain
  `live/available` on `codex-mini`.
- `max-1#codex-max`, `max-2#codex-max`, and `max-3#codex-max` currently return
  `live/quota_exhausted` with distinct reset windows. The accounts are not
  auth-dead; only the max route is exhausted.

## GitHub Workflow

`.github/workflows/live-provider-qa.yml` is manual-only. It requires the
dispatch input `confirm=spend-real-calls`.

For private configs, store a base64-encoded config in the repository secret
`OMUX_LIVE_QA_CONFIG_B64`. The workflow decodes it into `$RUNNER_TEMP` and sets
`OMUX_CONFIG` for the job. Keep the config secret-scoped and prefer secret
backends such as command, keychain, sops, age, or env references. Do not put raw
tokens in the workflow file or repository.

## Policy

- Start with the lowest-cost capability.
- Use account-specific probes when validating fallback behavior.
- Treat `rate_limited`, `quota_exhausted`, `degraded`, and `dead` as distinct
  outcomes.
- Do not schedule this workflow until budgets and provider terms are explicit.
- Do not use live QA as a background daemon loop.
