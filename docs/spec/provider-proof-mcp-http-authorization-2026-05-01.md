# Provider Proof: MCP HTTP Authorization
Date: 2026-05-01

Issue context: Linear `TIN-863`, parent `TIN-736`; GitHub
`Jesssullivan/oauth-mux#68`.

## Baseline

MCP HTTP authorization is not a generic bearer-token check. The MCP
authorization profile treats a protected MCP server as an OAuth resource server
and requires protected resource metadata for authorization-server discovery.
The oauth-mux MCP provider therefore needs two distinct proof surfaces:

- `resource-metadata`: a no-secret `GET` against the RFC 9728 metadata
  document.
- `resource`: a bearer-token probe against a concrete MCP resource URL using a
  token minted for that resource.

These are intentionally separate. A valid metadata document does not prove a
user token is live, and a live token for one MCP resource must not be replayed
against another MCP resource.

## Current Spec Truth

The current MCP spec revision found on 2026-05-01 is `2025-11-25`. Its
authorization page says MCP servers must implement OAuth 2.0 Protected Resource
Metadata and MCP clients must use it for authorization server discovery. The
same page says MCP clients must support both `WWW-Authenticate` resource
metadata discovery and well-known URI fallback.

For MCP specifically, the protected resource metadata document must include an
`authorization_servers` field with at least one authorization server. RFC 9728
defines the `resource` metadata parameter as required and defines
`authorization_servers` as the list of OAuth authorization server issuer
identifiers for the protected resource.

Relevant sources:

- MCP Authorization, 2025-11-25:
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- MCP 2025-11-25 changelog:
  <https://modelcontextprotocol.io/specification/2025-11-25/changelog>
- RFC 9728, OAuth 2.0 Protected Resource Metadata:
  <https://datatracker.ietf.org/doc/html/rfc9728>

## Implementation Decision

`oauth-mux` now treats successful MCP `resource-metadata` HTTP status as only
the transport-level result. It separately validates the body before recording
the probe as live:

- body must parse as JSON object;
- `resource` must be a non-fragment HTTPS URL string;
- `authorization_servers` must be a non-empty array;
- every authorization server entry must be a non-fragment HTTPS URL string.

Malformed or incomplete metadata is classified as `degraded.schema_invalid`.
This keeps MCP proof aligned with the formal liveness model instead of treating
any HTTP 200 response as usable authorization evidence.

MCP resource probes also classify explicit resource/audience mismatch evidence
as `degraded.audience_mismatch`, not `dead.token_revoked`. This is intentionally
narrow: `invalid_token` without a target/audience hint remains dead-token
evidence, while `invalid_target`, `audience`, or `resource mismatch` hints mean
the route needs a token minted for the selected resource.

The generic URL-template guard also now distinguishes full URL placeholders
from embedded path placeholders. Full HTTPS URLs are accepted only when the
entire probe URL template is a single placeholder such as
`{{OMUX_MCP_RESOURCE_METADATA_URL}}`; embedded placeholder values remain limited
to URL-safe unreserved path fragments. That keeps MCP's operator-selected
resource URLs possible without loosening every provider URL template.

## Public Metadata Proof

Figma's public remote MCP endpoint exposes protected resource metadata at both
the root and MCP-path well-known URLs:

```bash
curl -fsS https://mcp.figma.com/.well-known/oauth-protected-resource
curl -fsS https://mcp.figma.com/.well-known/oauth-protected-resource/mcp
```

The observed metadata on 2026-05-01 contained:

- `resource`: `https://mcp.figma.com/mcp`
- `authorization_servers`: `["https://api.figma.com"]`
- `bearer_methods_supported`: `["header"]`
- `scopes_supported`: `["mcp:connect"]`

That is enough to prove the no-secret metadata lane. The oauth-mux probe also
passes when pointed at that metadata URL:

```bash
tmp="$(mktemp -d)"
OMUX_STATE_DIR="$tmp" \
OMUX_CONFIG=$PWD/examples/mcp-http.config.json \
OMUX_MCP_RESOURCE_METADATA_URL=https://mcp.figma.com/.well-known/oauth-protected-resource \
  ./zig-out/bin/oauth-mux probe --profile mcp-metadata \
    --capability resource-metadata --json
```

Observed local result on 2026-05-01:

- selected route: `mcp:figma#resource-metadata`
- probe executed: `true`
- probe status: `200`
- decision: `use_this`
- liveness: `live.available`
- last probe source: `capability_probe`

This is not enough to prove resource-token liveness because that requires a
resource-bound access token.

## Remaining Work

- Add a resource-token proof only with a scoped MCP token minted for
  `https://mcp.figma.com/mcp` or another explicit test resource.
- Exercise `degraded.audience_mismatch` against a redacted resource-token
  cassette or a safe test MCP resource that rejects wrong-audience tokens.
- Keep `resource` bearer-token proof out of default daemon loops. MCP resource
  probes are provider calls and require an explicit operator-selected resource.
- Later: implement challenge discovery from `WWW-Authenticate:
  resource_metadata=...` so configs can start from a resource URL instead of a
  precomputed metadata URL.
