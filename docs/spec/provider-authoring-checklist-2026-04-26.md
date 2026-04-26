# Provider Authoring Checklist

Updated: 2026-04-26

This checklist defines the acceptance bar for adding a new OAuth-backed AI
harness to `oauth-mux` without changing the selection core. The goal is a
schema-first provider shape that lets an operator add support for a new tool in
one deliberate pass: identity boundary, credential parser, secret backend,
injection shape, probes, failure rules, and privacy constraints.

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

## Current Research Finding

For Codex subscription accounts, keep command probes as the primary live route
probe. As of 2026-04-26:

- OpenAI's current Codex CLI docs describe local CLI use, ChatGPT/API-key
  sign-in, and plan inclusion, but do not document a subscription-account HTTP
  status endpoint suitable for direct probing.
- The installed Codex CLI 0.125.0 exposes `login status`, `debug models`, and
  `exec`, but no direct auth-health endpoint.
- `oauth-mux` has verified three isolated Codex stores through `CODEX_HOME` and
  live `codex exec --json` command probes for `codex-mini` and `codex-max`.

Do not add a direct Codex HTTP probe until the endpoint, method, request body,
auth semantics, status/header/body classes, and quota impact are all verified
from an official or provider-owned source.

## Standards Baseline

Provider definitions must be consistent with the current OAuth and MCP floor:

- OAuth 2.1 draft-ietf-oauth-v2-1-15 for the framework baseline while OAuth
  2.1 remains an Internet-Draft.
- RFC 9700 for OAuth security BCP.
- RFC 8414 for authorization server metadata.
- RFC 7591 for dynamic client registration when a provider supports it.
- RFC 9728 for protected resource metadata, especially MCP HTTP servers.
- RFC 8707 resource indicators for audience-bound MCP access tokens.
- RFC 9449 DPoP only when the provider advertises sender-constrained tokens.
- MCP authorization 2025-11-25 for HTTP MCP authorization behavior.

For MCP specifically:

- HTTP transports are OAuth resource-server surfaces and should follow the MCP
  authorization profile.
- Stdio transports should get credentials from environment/config injection,
  not the HTTP authorization flow.
- Runtime `insufficient_scope`, step-up, or pending-verification conditions are
  degraded route states, not dead credentials.

## Authoring Steps

1. Name the provider identity.

Use a short stable provider name and an account name that describes the local
identity boundary, not the token value.

```text
provider:account
provider:account#capability
codex:max-1#codex-max
figma:design#tools/get-design-context
```

The account boundary must be explicit: config directory, keychain namespace,
SOPS path, env var, command output, or another secret backend. Do not rely on a
provider's global default auth path unless the tool is intentionally
single-account.

2. Choose the secret backend.

Allowed backends map to `src/types.zig` and `src/config.zig`:

```text
file
env
keychain
sops
age
command
stdin
```

The backend stores or returns raw secret material. It does not define provider
logic. Provider logic belongs in `provider_definitions` or a compiled adapter
only when data is insufficient.

3. Parse the credential shape.

Fill `credential` paths for the provider's local JSON or command output:

```json
{
  "credential": {
    "access_token_path": "tokens.access_token",
    "refresh_token_path": "tokens.refresh_token",
    "expires_at_path": "expires_at",
    "api_key_path": "api_key"
  }
}
```

Only structure may be documented. Do not copy token values into fixtures,
docs, logs, issues, or commits.

4. Define the injection shape.

Use config-directory injection when the harness owns refresh/session behavior:

```json
{
  "injection": {
    "config_dir_env": "CODEX_HOME",
    "credential_filename": "auth.json"
  }
}
```

Use direct env injection only when the target harness expects a bearer token or
API key in an environment variable:

```json
{
  "injection": {
    "direct_env": [["GH_TOKEN", "access_token"]]
  }
}
```

Never export a ChatGPT subscription OAuth token as a generic API key unless the
provider documents that exact behavior.

5. Define capability routes.

Model separate task/model/tool lanes as capabilities:

```json
{
  "capabilities": [
    {
      "name": "codex-max",
      "aliases": ["max", "gpt-5.3-codex"],
      "probe": {
        "transport": "command",
        "auth": "none",
        "timeout_ms": 120000,
        "command": [
          "codex",
          "exec",
          "--json",
          "--ephemeral",
          "--ignore-rules",
          "-m",
          "gpt-5.3-codex",
          "Reply exactly: OMUX_CODEX_MAX_PROBE"
        ]
      }
    }
  ]
}
```

Capability state must not poison the account globally. A failed
`provider:account#expensive-route` may skip that route while
`provider:account#cheap-route` remains selectable.

6. Select the probe transport.

Use `http` only when all probe facts are known:

- endpoint and method
- required body and headers
- auth scheme
- success status range
- retry-after or reset signal
- status/body/header mappings for revoked auth, insufficient tier, quota,
  rate limit, scope, step-up, and provider outage
- confirmation that the probe does not spend meaningful user quota

Use `command` when the harness already owns OAuth refresh/session semantics or
when no safe public HTTP probe is documented. Command probes must be bounded by
`timeout_ms`, must not log secrets, and should have cassettes for success and
typed failure cases.

`config validate` rejects probe URLs or command argv entries that embed obvious
token material such as bearer authorization headers, access tokens, refresh
tokens, ID tokens, or token-template placeholders. The mux injects credentials
at execution time; provider schemas describe only how to run the probe.

7. Map failures into liveness.

Every provider should define the smallest useful `failure_rules` set:

```json
[
  { "status": 401, "class": { "dead": "token_revoked" } },
  { "status": 403, "class": { "degraded": "scope_insufficient" } },
  { "status": 429, "retry_after_lt": 3601, "class": "rate_limited" },
  { "status": 429, "retry_after_gte": 3601, "class": "quota_exhausted" },
  { "status_min": 500, "status_max": 599, "class": "provider_degraded" }
]
```

`config validate` requires schema-defined providers with capability probes to
include failure rules. It also rejects catch-all failure rules: every rule must
include at least one matcher such as `status`, `status_min`, `status_max`,
`retry_after_gte`, `retry_after_lt`, or `hint_contains`. Empty
`hint_contains` values are invalid.

Routing semantics:

- `dead`: user action required; do not automatically retry.
- `degraded`: try the next account for this route; retry only after a long
  window or explicit step-up.
- `rate_limited`: skip briefly or wait and retry after the short window.
- `quota_exhausted`: skip until the quota window resets.
- `provider_degraded`: try the next provider, not only the next account.

8. Add proof fixtures and tests.

At minimum, add redacted fixtures or synthetic tests for:

- credential parse success
- missing secret or parse failure
- route success
- route-level rate limit
- route-level quota exhaustion
- route-level degraded state
- account-level dead credential
- provider-level outage
- JSON/status output that omits token material

For command probes, store cassettes under `test/fixtures/cassettes/<provider>/`
with all secrets removed.

`zig build test` walks `test/fixtures` and rejects common OAuth/API secret
markers, including access tokens, refresh tokens, ID tokens, bearer
authorization material, cookies, OpenAI-style `sk-` keys, and session-token
prefixes. This is intentionally a high-signal guard, not a substitute for
operator review before committing a new cassette.

9. Validate the operator surface.

Before merging a provider definition:

```bash
just check
OMUX_CONFIG=/path/to/config.json oauth-mux config validate
oauth-mux probe --provider <provider> --account <account> --capability <capability> --json
```

For live subscription probes, record only:

- account label
- capability label
- mux decision
- liveness state
- availability or degraded/dead reason
- redacted status or hint class

Do not record access tokens, refresh tokens, ID tokens, cookies, authorization
headers, raw provider responses, or full credential JSON.

## Acceptance Gate

A new schema-only provider is acceptable when:

- `config validate` catches broken provider/account/profile/probe references.
- The provider can be selected through `exec`, `env`, and `probe`.
- Account-level failures dominate route state.
- Route-level failures do not poison unrelated capabilities.
- At least one positive and one negative probe path are covered by tests or
  redacted cassettes.
- The docs identify the official provider/OAuth/MCP source used for each
  auth, refresh, and probe decision.

Compiled adapter code is justified only when the provider requires behavior the
schema cannot safely express, such as a non-JSON credential format, a custom
command-output parser, DPoP signing, or provider-specific refresh behavior.

## References

- OpenAI Codex CLI: https://developers.openai.com/codex/cli
- OpenAI MCP and Connectors: https://developers.openai.com/api/docs/guides/tools-connectors-mcp
- MCP authorization 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- OAuth 2.1 draft 15: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-15
- RFC 9700 OAuth Security BCP: https://www.rfc-editor.org/rfc/rfc9700.html
- RFC 8414 Authorization Server Metadata: https://www.rfc-editor.org/rfc/rfc8414.html
- RFC 7591 Dynamic Client Registration: https://www.rfc-editor.org/rfc/rfc7591
- RFC 9728 Protected Resource Metadata: https://www.rfc-editor.org/rfc/rfc9728
- RFC 8707 Resource Indicators: https://www.rfc-editor.org/rfc/rfc8707
- RFC 9449 DPoP: https://www.rfc-editor.org/rfc/rfc9449
