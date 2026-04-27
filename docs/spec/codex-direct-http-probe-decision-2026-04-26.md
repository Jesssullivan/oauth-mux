# Codex Direct HTTP Probe Decision

Updated: 2026-04-26

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Decision

Do not add a direct Codex HTTP status or route-probe endpoint yet.

Codex subscription-backed routes remain command-probe-first through
`codex exec --json` under the selected account's `CODEX_HOME`. The mux may
classify those JSONL results into typed route liveness, but it must not assume
that a ChatGPT subscription OAuth token is a general OpenAI API bearer token or
that an undocumented Codex resource endpoint is safe to call.

## Evidence

Official OpenAI Codex docs currently cover Codex CLI usage, authentication
through ChatGPT or API key, and the command-line interface. They do not document
a subscription-backed HTTP endpoint whose method, request shape, response
schema, retry semantics, and quota impact are stable enough for `oauth-mux` to
use as a direct health probe.

Local CLI evidence from this workstation:

```text
codex --version -> codex-cli 0.125.0
codex login --help -> login status, --with-api-key, --device-auth
codex debug --help -> models, app-server, prompt-input
codex exec --help -> --json, --ephemeral, --ignore-user-config; auth still uses CODEX_HOME
```

Live mux evidence already exists for the command transport:

```text
just codex-max-login-status-all
max-1 -> Logged in using ChatGPT
max-2 -> Logged in using ChatGPT
max-3 -> Logged in using ChatGPT

just codex-max-probe-all
codex-mini: max-1, max-2, max-3 -> 200/use_this/live/available

just codex-max-probe-all codex-max
codex-max: max-1, max-2, max-3 -> 200/use_this/live/available
```

OpenAI's MCP and connector docs are relevant to provider authoring, but they
describe passing application-managed OAuth access tokens to MCP connectors. That
does not establish a Codex subscription-account health endpoint.

Sources:

- <https://developers.openai.com/codex/cli>
- <https://developers.openai.com/codex/cli/reference>
- <https://developers.openai.com/codex/auth>
- <https://developers.openai.com/api/docs/guides/tools-connectors-mcp>

## Admission Gate

Revisit a direct Codex HTTP probe only when an official or provider-owned source
documents all of the following:

- endpoint and method
- required request body, headers, and token audience
- whether subscription-backed Codex accepts the token directly
- success response schema
- status, header, and body mappings for revoked auth, inactive subscription,
  insufficient tier, scope failure, short rate limit, quota exhaustion, and
  provider outage
- retry-after or reset-window semantics
- evidence that probing does not spend meaningful user quota
- redaction requirements for fixtures, logs, health state, and issue comments

Until those facts are pinned, a direct HTTP probe is considered unadmitted.

## Implications

- Built-in Codex route probes stay command-based.
- `CODEX_HOME` remains the account boundary for Codex subscription stores.
- The mux must never export ChatGPT subscription OAuth tokens as generic API
  keys unless OpenAI documents that exact behavior.
- Schema-defined HTTP probes remain valid for other providers when their
  endpoint semantics pass the admission gate.
- Unsupported model, tier mismatch, quota exhaustion, rate limit, and revoked
  auth remain typed liveness outcomes, not generic circuit-breaker penalties.
