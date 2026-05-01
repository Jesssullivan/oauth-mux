# OAuth Mux Formal Model

Updated: 2026-04-25

This document defines the working model for `oauth-mux`: a small compiled
credential mux for AI harnesses that can select, validate, refresh, and inject
the right OAuth-backed account without leaking secrets or collapsing separate
accounts into one global login.

## Goals

- Support multiple accounts per provider, starting with Codex / OpenAI
  subscription accounts.
- Keep secrets backend-agnostic: keychain, SOPS, age, env, file, command, and
  stdin are storage details, not provider logic.
- Prefer config-directory isolation for tools that already own refresh and
  login state, such as Codex through `CODEX_HOME`.
- Classify failures with typed state rather than one generic health penalty.
- Let new provider support be mostly declarative, with compiled adapters only
  for provider-specific behavior that cannot be described safely in JSON.
- Keep the implementation pure Zig and `std`-only.

## Standards Baseline

The implementation should track the current OAuth and MCP substrate instead of
copying one vendor's local auth cache shape.

- OAuth governance: IETF OAuth Working Group. The WG is active in the IETF
  Security Area, with public work on the datatracker, `oauth@ietf.org`, and
  the IETF OAuth Zulip stream.
- OAuth framework: OAuth 2.1 while it remains a draft, with OAuth 2.0
  compatibility where providers require it. The MCP 2025-11-25 authorization
  spec references `draft-ietf-oauth-v2-1-13`; the IETF OAuth WG document list
  currently shows `draft-ietf-oauth-v2-1-15` as active.
- OAuth security: RFC 9700, PKCE S256, strict redirect handling, no implicit
  flow, no resource-owner-password flow.
- Discovery: RFC 8414 authorization server metadata and OpenID Connect
  discovery where the MCP spec requires fallback.
- Device login: RFC 8628 where a provider supports headless login.
- Dynamic registration: RFC 7591 where available.
- Protected resources: RFC 9728 for MCP protected resource metadata.
- Audience binding: RFC 8707 resource indicators for MCP.
- Sender-constrained tokens: RFC 9449 DPoP where a provider advertises it.

MCP HTTP authorization is treated as an OAuth profile. MCP stdio authorization
is treated as environment or config injection because the MCP spec explicitly
keeps stdio credentials outside the HTTP authorization flow.

Primary references:

- IETF OAuth WG: <https://datatracker.ietf.org/wg/oauth/about/>
- OAuth WG document list: <https://datatracker.ietf.org/wg/oauth/>
- OAuth 2.1 draft: <https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/>
- RFC 9700, OAuth 2.0 Security BCP: <https://www.rfc-editor.org/rfc/rfc9700>
- RFC 8414, authorization server metadata: <https://www.rfc-editor.org/rfc/rfc8414>
- RFC 8628, device authorization grant: <https://www.rfc-editor.org/rfc/rfc8628>
- RFC 9449, DPoP: <https://www.rfc-editor.org/rfc/rfc9449>
- RFC 9728, protected resource metadata: <https://www.rfc-editor.org/rfc/rfc9728>
- MCP authorization 2025-11-25:
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>

## Agent Harness Observations

Codex, Claude Code, and MCP expose three distinct auth surfaces, so the mux
must not collapse them into one credential model:

- Codex uses ChatGPT subscription access for local CLI and IDE use. OpenAI's
  current help docs say Codex is included with Plus, Pro, Business,
  Enterprise/Edu, and currently Free/Go for a limited period; usage limits
  depend on plan and task shape. The docs also distinguish subscription-backed
  Codex use from API-key use and tell existing API-key users to log out and
  sign back in to switch to subscription access.
- Claude Code supports browser login for Claude.ai Pro/Max and organization
  accounts, plus Console/API-key and cloud-provider auth. Official Claude Code
  docs say local credentials can live in macOS Keychain and that custom API key
  helpers may refresh on a TTL or after HTTP 401.
- MCP HTTP authorization is an OAuth profile. Its spec says auth is optional,
  HTTP transports should follow the MCP authorization spec, stdio transports
  should use environment credentials instead, and clients must handle protected
  resource metadata plus resource indicators. This is why `oauth-mux` models
  HTTP MCP as route/capability liveness but stdio MCP as injection.

Vendor references:

- OpenAI Codex with ChatGPT plan:
  <https://help.openai.com/en/articles/11369540-codex-in-chatgpt>
- OpenAI Codex CLI sign-in:
  <https://help.openai.com/en/articles/11381614>
- Claude Code authentication:
  <https://docs.anthropic.com/en/docs/claude-code/getting-started>,
  <https://docs.anthropic.com/en/docs/claude-code/team>

## Account Identity

An account is not a token. An account is a stable local reference to a provider
identity and its isolation boundary:

```text
provider:account
codex:max-1
codex:max-2
codex:max-3
claude:personal
linear:work
figma:design
```

The mux never needs to print or persist the token value to prove selection. It
can expose non-secret breadcrumbs:

```text
OMUX_ACTIVE_PROVIDER=codex
OMUX_ACTIVE_ACCOUNT=max-2
OMUX_ACTIVE_PROFILE=research
```

For Codex, the account boundary should be a `CODEX_HOME` directory or keyring
namespace. Raw ChatGPT OAuth access tokens should not be exported as shell env.

Route-level health uses a suffix on the account key:

```text
provider:account
provider:account#capability
codex:max-1
codex:max-1#codex-max
mcp:figma#tools/design-context
```

Account state dominates route state. If `codex:max-1` is dead, every route on
that account is unusable. If only `codex:max-1#codex-max` is quota
exhausted, the same account can still be selected for another capability.
Profiles may also include the route suffix directly:

```json
{
  "profiles": {
    "codex-max": {
      "providers": [
        "codex:max-1#codex-max",
        "codex:max-2#codex-max",
        "codex:max-3#codex-max"
      ]
    }
  }
}
```

The CLI may pass an equivalent route selector with `--capability <name>` for
profiles that list only `provider:account`. The selected route is exposed as
`OMUX_ACTIVE_CAPABILITY`.

## Pipeline Algebra

The core pipeline remains a monadic `try` chain:

```text
Config
  -> Resolve Provider
  -> Select Account
  -> Read Secret
  -> Parse Credential
  -> Refresh If Needed
  -> Probe Capability
  -> Classify Liveness
  -> Inject Env / Config Dir
  -> Exec
```

Each stage either returns an updated context or a typed error. Provider-specific
code is limited to parsing, refresh construction, injection shape, and probe
classification.

## Liveness Algebra

The first split is credential liveness:

```zig
CredentialLiveness =
    live(Availability)
  | degraded(DegradedReason)
  | dead(DeadReason)
```

This is necessary but not sufficient. The mux also needs capability scope:

```zig
RouteState = {
    provider: ProviderRef,
    account: AccountRef,
    capability: CapabilityRef,
    proof: CredentialProof,
    liveness: CredentialLiveness,
    evidence: HealthEvidence,
}
```

A credential may be live for one capability and unusable for another. Examples:

- Codex ChatGPT login is present, but a specific model route rejects the
  subscription.
- Figma MCP auth is valid, but the tool schema is rejected by a client.
- Linear MCP OAuth is valid, but a tool call needs additional scopes.

Stay-afloat adds a separate runtime-readiness axis:

```zig
RuntimeReadiness =
    ready
  | missing_binary
  | permission_denied
  | unwritable_store
  | session_unavailable
  | sandbox_blocked
  | needs_reauth
  | repair_in_progress
```

This must stay separate from credential liveness. A provider CLI that cannot
write its session directory is not an OAuth-dead account. A revoked token is not
a platform service failure. Selection should require both an acceptable
credential state and `ready` runtime state.

## Availability Semantics

Availability describes capacity, not identity:

```zig
Availability =
    available
  | rate_limited(retry_after_s, window)
  | quota_exhausted(window_resets_at)
  | cooldown(until, reason)
```

Routing rules:

- `available`: use the account.
- `rate_limited`: skip it now, but allow it after the short retry window.
- `quota_exhausted`: skip it until the long quota window resets.
- `cooldown`: skip it until the explicit local cooldown expires.

Do not punish long-window quota exhaustion the same way as bad credentials.
Quota exhaustion is expected capacity state, not account corruption.

## Operability Semantics

Degraded state means the credential can authenticate but is not currently a
usable route for the requested work:

```zig
DegradedReason =
    tier_insufficient
  | subscription_paused
  | provider_degraded
  | scope_insufficient
  | schema_invalid
  | terms_required
  | step_up_required
  | pending_verification
  | unknown_4xx
```

Route-level `scope_insufficient`, `schema_invalid`, `terms_required`,
`step_up_required`, and `pending_verification` keep MCP step-up, client schema
failures, and account action requirements out of the generic auth-failure path.

## Dead Semantics

Dead state means automatic retry is unsafe or useless:

```zig
DeadReason =
    token_revoked
  | account_deleted
  | auth_permanently_failed
```

Dead credentials require user action: login again, rotate the secret, or remove
the account.

## Provider Definition Schema

Provider support is data first:

```json
{
  "name": "codex",
  "auth": {
    "token_endpoint": "https://auth0.openai.com/oauth/token",
    "pkce": true,
    "grant_types": ["authorization_code", "refresh_token"]
  },
  "credential": {
    "access_token_path": "tokens.access_token",
    "refresh_token_path": "tokens.refresh_token",
    "expires_in_path": "tokens.expires_in",
    "api_key_path": "OPENAI_API_KEY"
  },
  "injection": {
    "config_dir_env": "CODEX_HOME",
    "credential_filename": "auth.json"
  },
  "detection": {
    "binary_names": ["codex"],
    "env_markers": ["CODEX_HOME"]
  },
  "capabilities": [
    {
      "name": "chat:max",
      "aliases": ["codex-max"],
      "probe": {
        "transport": "command",
        "auth": "none",
        "command": [
          "codex",
          "exec",
          "--json",
          "--ephemeral",
          "--ignore-rules",
          "-m",
          "gpt-5.3-codex",
          "Reply exactly: OMUX_CODEX_MAX_PROBE"
        ],
        "timeout_ms": 120000,
        "success_status_min": 200,
        "success_status_max": 299
      }
    }
  ],
  "failure_rules": [
    { "status": 401, "class": { "dead": "token_revoked" } },
    { "status": 403, "class": { "degraded": "tier_insufficient" } },
    { "status": 429, "retry_after_lt": 3601, "class": { "rate_limited": {} } },
    { "status": 429, "retry_after_gte": 3601, "class": { "quota_exhausted": {} } },
    { "status_min": 500, "status_max": 599, "class": { "provider_degraded": {} } }
  ]
}
```

The compiled adapter may add provider probes, but the common shape should be
declarative enough for new OAuth-backed tools to be added without editing the
selection core. Capability probes are plans, not secrets: token material or
account-scoped env such as `CODEX_HOME` is added only when the probe executes.
HTTP probes use `method`, `url`, bearer auth, and optional hint headers.
Command probes use argv plus inherited environment overlays, must have a
positive `timeout_ms`, and are classified from stdout/stderr cassettes when the
provider supplies a parser. Failure rules are intentionally small: exact status
or status range, optional `retry_after` threshold, optional case-insensitive
exact or substring hint, and a typed liveness class. This keeps provider
extension friendly without introducing regex engines or plugin code.

## Health Evidence

Every liveness transition should be backed by redacted evidence:

```text
provider
account
capability
observed_at
source = parse | refresh | identity_probe | route_probe | mcp_initialize
http_status
retry_after_s
www_authenticate_class
body_class
decision
```

Never persist access tokens, refresh tokens, ID tokens, full authorization
headers, cookies, or raw provider responses that can contain secrets.

## Codex First Target

For three Codex Max accounts, the initial config should model three isolated
account stores:

```json
{
  "providers": {
    "codex": {
      "kind": "codex",
      "accounts": {
        "max-1": {
          "priority": 30,
          "secret": { "backend": "file", "path": "~/.config/oauth-mux/codex/max-1/auth.json" },
          "config_dir": "~/.config/oauth-mux/codex/max-1"
        },
        "max-2": {
          "priority": 20,
          "secret": { "backend": "file", "path": "~/.config/oauth-mux/codex/max-2/auth.json" },
          "config_dir": "~/.config/oauth-mux/codex/max-2"
        },
        "max-3": {
          "priority": 10,
          "secret": { "backend": "file", "path": "~/.config/oauth-mux/codex/max-3/auth.json" },
          "config_dir": "~/.config/oauth-mux/codex/max-3"
        }
      }
    }
  }
}
```

The first robust mux behavior should prove:

- plan 1 short rate limit skips to plan 2 and re-enters after retry;
- plan 2 quota exhaustion skips until reset;
- plan 3 auth failure becomes dead and requires login;
- no selection proof prints token material.
