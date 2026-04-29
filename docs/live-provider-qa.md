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

Operator-provided Codex state on 2026-04-28:

- `max-1#codex-max` and `max-2#codex-max` are expected to classify as
  `live/quota_exhausted` until weekly limits refresh.
- `max-3` is expected to remain active for API-backed usage.
- These are not auth-dead accounts; the useful proof is preserving the
  distinction between weekly quota exhaustion and usable fallback routes.

Hosted evidence from run `25029923810`:

- `codex-mini`: all three accounts returned `live/available` and
  `decision=use_this`.
- `codex-max`: `max-1` and `max-2` returned `live/quota_exhausted` and
  `decision=try_next_account`; `max-3` returned `live/available` and
  `decision=use_this`.
- The uploaded artifact contains valid per-probe JSON files and separate
  redacted probe logs.

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
