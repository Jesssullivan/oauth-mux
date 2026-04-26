# Provider Probe Admission Matrix

Updated: 2026-04-26

Issue context: Linear `TIN-491`, GitHub `tinyland-inc/lab#197`.

This matrix converts provider research into an implementation gate for
`oauth-mux` provider definitions. "Admitted" means a provider has a documented
low-impact endpoint or command shape that can be modeled as a typed probe after
failure rules and redaction tests are added. It does not mean the provider is
implemented yet.

## Status Vocabulary

- `admitted_http`: provider-owned docs expose a low-impact HTTP identity or
  metadata endpoint suitable for schema-defined probing.
- `admitted_command`: provider-owned docs expose a CLI/status command or local
  session boundary that is safer than direct HTTP probing.
- `mcp_profile`: probe behavior is governed by the MCP HTTP authorization
  profile and must be discovered per resource server.
- `unadmitted`: do not probe directly until provider-owned docs pin endpoint,
  auth semantics, failure classes, reset behavior, and quota impact.

## Matrix

| Provider | Current Admission | Probe Shape | Required Classification |
| --- | --- | --- | --- |
| Codex / OpenAI subscription | `admitted_command`; direct HTTP `unadmitted` | `codex exec --json` under selected `CODEX_HOME` | JSONL success, unsupported model/tier, quota/rate, revoked auth |
| Claude Code subscription | `admitted_command`; built-in `auth-status` probe | `claude auth status --json` under selected `CLAUDE_CONFIG_DIR`; no prompt/model call | logged in, logged out, keychain/session missing; tier/rate/quota still require future route probes |
| Anthropic API key | `admitted_http`; not subscription equivalent | `GET https://api.anthropic.com/v1/models` with `x-api-key` and `anthropic-version`; avoid message probes that spend tokens | 200 live, 401 dead, 403/scope or workspace issue, 429 rate/quota, 5xx provider degraded |
| MCP HTTP server | `mcp_profile` | First request or metadata discovery via RFC 9728 protected resource metadata, then resource-bound bearer token requests | 401 auth required/dead, 403 insufficient_scope or step-up, malformed metadata, provider degraded |
| MCP stdio server | `admitted_command` / injection | Environment or config injection; MCP HTTP OAuth flow does not apply | missing secret, malformed env/config, child-process failure |
| GitHub | `admitted_http`; built-in `identity` probe | `GET https://api.github.com/user` with bearer token | 200 live, 401 dead, 403 forbidden/rate-limited, rate-limit headers |
| Linear | `admitted_http`; built-in `identity` probe | `POST https://api.linear.app/graphql` with `query { viewer { id name email } }` and OAuth bearer token | 200 plus GraphQL errors, 401 dead, 403/scope, 429/rate, 5xx degraded |
| Figma REST | `admitted_http`; built-in OAuth `identity`, PAT `identity-pat`, and plan-token `file-metadata-plan` probes | `GET https://api.figma.com/v1/me` with OAuth bearer token and `current_user:read`; PATs use `X-Figma-Token`; plan access tokens use `GET /v1/files/{{OMUX_FIGMA_PLAN_FILE_KEY}}/meta` with `file_metadata:read` | 200 live, 401 dead, 403 scope/tier, 404 resource not allowed/found, 429/rate, 5xx degraded |
| Figma Remote MCP | `mcp_profile` | Treat as MCP HTTP resource, not as Figma REST | MCP metadata, scope challenge, tool/schema errors |
| Vercel | `admitted_http`; built-in `identity` probe | `GET https://api.vercel.com/v2/user`; token metadata endpoint and semantic `softBlock` body checks are later optional refinements | 200 live, 401 dead, 403 forbidden/team/scope, 429/rate, 5xx degraded |
| FlakeHub / Determinate | `admitted_command`; direct HTTP `unadmitted` | `fh status` / Determinate-managed netrc and JWT boundary | logged in, token expiry, missing netrc, generated token expiry |

## Implementation Notes

1. Admitted HTTP probes must still pass the provider authoring checklist:
   explicit method, URL, auth scheme, success range, failure rules, redacted
   cassettes, and no token material in config.
2. Identity endpoints are preferred over work endpoints. Do not validate a
   provider by sending a model prompt, creating an issue, reading a design file,
   or triggering a build unless no lower-impact probe exists and the operator
   explicitly opts in.
3. GraphQL probes need semantic success checks. A 200 response with an `errors`
   array is not automatically live.
4. MCP HTTP probes must be audience-bound. A token minted for one MCP resource
   server must not be replayed to another server.
5. Subscription tools that own refresh/session state should remain command-first
   until the provider documents direct resource-server semantics.
6. Custom token-header probes are explicit. Use `auth = token_header` with a
   non-`Authorization` header name such as `X-Figma-Token`; use `auth = bearer`
   for OAuth Authorization headers.
7. URL templates are for non-secret resource identifiers only. Placeholder
   names must be env-var shaped (`A_Z0_9_`); runtime values must be URL-safe
   unreserved characters.

## Provider Source Links

- Codex CLI/auth:
  <https://developers.openai.com/codex/cli>,
  <https://developers.openai.com/codex/cli/reference>,
  <https://developers.openai.com/codex/auth>
- OpenAI MCP connectors:
  <https://developers.openai.com/api/docs/guides/tools-connectors-mcp>
- Claude Code setup/IAM:
  <https://docs.anthropic.com/en/docs/claude-code/getting-started>,
  <https://docs.anthropic.com/en/docs/claude-code/team>,
  <https://docs.anthropic.com/en/docs/claude-code/settings>
- Anthropic API auth:
  <https://docs.anthropic.com/en/api/getting-started>,
  <https://docs.anthropic.com/en/api/models-list>
- MCP authorization:
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- GitHub REST auth/user:
  <https://docs.github.com/v3/auth>,
  <https://docs.github.com/rest/users/users>
- Linear API/OAuth:
  <https://linear.app/developers/graphql>,
  <https://linear.app/developers/oauth-2-0-authentication>
- Figma REST API/OAuth/users:
  <https://developers.figma.com/docs/rest-api/>,
  <https://developers.figma.com/docs/rest-api/authentication/>,
  <https://developers.figma.com/docs/rest-api/users-endpoints/>
- Vercel REST API/tokens:
  <https://docs.vercel.com/docs/rest-api/reference/endpoints/user/get-the-user>,
  <https://vercel.com/docs/sign-in-with-vercel/tokens>
- FlakeHub/Determinate auth:
  <https://docs.determinate.systems/flakehub/concepts/authentication/>,
  <https://docs.determinate.systems/flakehub/cli/>

## Standards Source Links

- IETF OAuth 2.1 draft-ietf-oauth-v2-1-15:
  <https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/>
- RFC 9700, OAuth 2.0 Security BCP:
  <https://www.rfc-editor.org/rfc/rfc9700>
- RFC 8414, OAuth authorization server metadata:
  <https://www.rfc-editor.org/rfc/rfc8414>
- RFC 8707, OAuth resource indicators:
  <https://www.rfc-editor.org/rfc/rfc8707>
- RFC 9728, OAuth protected resource metadata:
  <https://www.rfc-editor.org/rfc/rfc9728>
