# Provider Proof: GitHub And Linear
Date: 2026-05-01

Issue context: Linear `TIN-862`, parent `TIN-736`; GitHub
`Jesssullivan/oauth-mux#68`.

## Baseline

Codex is live-proven. GitHub and Linear are schema-modeled with admitted
low-impact identity probes. Provider-level status should remain
`needs_operator_proof` until the intended auth modes have redacted evidence, but
individual capabilities can now carry narrower proof status when a local or
public proof exists.

## Provider Contracts

GitHub's admitted probe is `GET https://api.github.com/user` with bearer auth.
GitHub documents `200`, `401`, and `403` for the authenticated-user endpoint.
GitHub also documents `x-ratelimit-remaining` as the remaining primary-window
request count and says primary rate-limit exhaustion returns `403` or `429`
with that header set to `0`.

Linear's admitted probe is a GraphQL `viewer` query over
`POST https://api.linear.app/graphql`. Linear documents OAuth bearer auth for
GraphQL requests and documents OAuth access tokens, refresh tokens, expiry, and
the `viewer` access pattern. Because GraphQL can return semantic errors under
HTTP `200`, the provider rule must inspect the body hint and downgrade
`{"errors":[...]}` to degraded instead of live.

Linear personal API keys use the same GraphQL endpoint and viewer query, but
the provider-owned docs require `Authorization: <API_KEY>` instead of
`Authorization: Bearer <ACCESS_TOKEN>`. That is modeled as a separate
`identity-api-key` capability so OAuth bearer proof and personal-key proof do
not share an ambiguous auth mode.

## Classifier Decisions

- `401` remains generic OAuth death: `dead.token_revoked`.
- `429` remains generic provider availability: short `Retry-After` values are
  `rate_limited`; long values are `quota_exhausted`.
- GitHub `403` plus `x-ratelimit-remaining: 0` is `rate_limited`.
- GitHub `403` with any nonzero remaining count is not rate exhaustion and is
  classified as `degraded.scope_insufficient`.
- Linear `200` plus GraphQL `errors` is `degraded.unknown_4xx` until a narrower
  Linear error taxonomy is justified by fixtures.
- Linear `403` remains `degraded.scope_insufficient`.
- Linear OAuth proof uses `identity`; Linear personal API key proof uses
  `identity-api-key`.
- Provider `5xx` remains `provider_degraded`.

The GitHub distinction requires exact matching on the remaining-count hint.
Substring matching is wrong because values such as `10` contain `0` but still
mean remaining capacity exists.

## Proof Commands

Local GitHub proof, using the installed GitHub CLI token without printing it:

```bash
OMUX_CONFIG=$PWD/examples/github.config.json \
OMUX_GITHUB_WORK_TOKEN="$(gh auth token)" \
  ./zig-out/bin/oauth-mux probe --profile github --capability identity --json
```

Local Linear proof, using an already-scoped OAuth access token:

```bash
OMUX_CONFIG=$PWD/examples/linear.config.json \
OMUX_LINEAR_WORK_TOKEN="$LINEAR_ACCESS_TOKEN" \
  ./zig-out/bin/oauth-mux probe --profile linear --capability identity --json
```

Local Linear proof, using a personal API key from `LINEAR_API_KEY`:

```bash
OMUX_CONFIG=$PWD/examples/linear-api-key.config.json \
  ./zig-out/bin/oauth-mux probe --profile linear-api-key --capability identity-api-key --json
```

Artifacted proof should run through `just live-qa` with
`OMUX_LIVE_QA_CONFIRM=spend-real-calls` even though these are low-impact
identity calls. That keeps provider-proof evidence under `dist/live-qa/` with
the same redaction and pass/fail semantics as Codex.

## Promotion Gate

Do not mark GitHub or Linear provider-level `live_proven` in `src/main.zig`
until all of these are true:

1. Unit tests cover provider-specific classification and generic OAuth fallback.
2. A local or hosted live artifact shows `live.available` for the identity
   probe without leaking token or raw profile response data.
3. GitHub issue `#68` and Linear `TIN-862` link the proof artifact or a redacted
   summary of the run.
4. The docs keep `schema_modeled`, `needs_operator_proof`,
   `local_live_proven`, and `live_proven` separate.

Capability-level promotion is narrower:

- GitHub `identity`: `local_live_proven` after the local redacted artifact.
- Linear `identity-api-key`: `local_live_proven` after the local redacted
  artifact.
- Linear `identity`: stays `needs_operator_proof` until OAuth bearer proof
  exists.

## Current Evidence

- GitHub local live QA passed on 2026-05-01 through
  `scripts/live-provider-qa.sh` using `examples/github.config.json` and a token
  supplied by `gh auth token`. The redacted result was
  `github:work#identity`, `probe_status=200`, `live.available`, and
  `decision=use_this`.
- Linear personal API key live QA passed on 2026-05-01 through
  `scripts/live-provider-qa.sh` using `examples/linear-api-key.config.json` and
  the existing `LINEAR_API_KEY` environment variable. The redacted result was
  `linear:work#identity-api-key`, `probe_status=200`, `live.available`, and
  `decision=use_this`.
- Linear OAuth bearer live QA is still pending. The current shell did not expose
  `LINEAR_ACCESS_TOKEN`.
- A 2026-05-01 SOPS recheck of `../lab/nix/secrets/common.yaml` found
  `api.linear`, but it is the same personal API key already exposed as
  `LINEAR_API_KEY`, not a Linear OAuth bearer. Sourcing that key through SOPS
  proves `linear:work#identity-api-key` as `live.available`; using the same
  value against the OAuth-bearer `identity` route returns HTTP 400 and stays
  `degraded.unknown_4xx`. This confirms the SOPS path is useful for API-key
  proof but does not unblock OAuth proof.

This is enough to prove the GitHub path locally and the Linear personal API-key
path locally, but not enough to claim that every Linear auth mode is live-proven.
TIN-862 should record the OAuth bearer proof separately before changing public
provider support status.

## Sources

- GitHub REST authenticated user endpoint:
  <https://docs.github.com/en/rest/users/users#get-the-authenticated-user>
- GitHub REST rate-limit headers:
  <https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>
- Linear GraphQL authentication:
  <https://linear.app/developers/graphql>
- Linear OAuth token and viewer request examples:
  <https://linear.app/developers/oauth-2-0-authentication>
