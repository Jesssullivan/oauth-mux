# Provider Proof: Figma REST Auth Shapes
Date: 2026-05-01

Issue context: Linear `TIN-877`, parent `TIN-736`; GitHub
`Jesssullivan/oauth-mux#68`.

## Baseline

Figma must not be modeled as one generic "Figma works" route. oauth-mux carries
three separate REST proof shapes:

- OAuth bearer `identity`, using `Authorization: Bearer <token>` against
  `GET https://api.figma.com/v1/me`.
- PAT `identity-pat`, using `X-Figma-Token: <token>` against the same endpoint.
- Plan/file-token `file-metadata-plan`, using `X-Figma-Token` against
  `GET /v1/files/{{OMUX_FIGMA_PLAN_FILE_KEY}}/meta`.

Those capabilities have different secret formats, scopes, and failure modes.
Provider-level status should stay conservative until all intended Figma modes
have redacted evidence.

## Local Proof

A low-impact PAT identity proof passed locally using the global SOPS-managed
`api.figma_token` value, injected only into the probe environment:

```bash
OMUX_STATE_DIR=dist/live-qa/local-20260501T222732Z/state \
OMUX_CONFIG=examples/figma-pat.config.json \
OMUX_FIGMA_PAT=<redacted> \
  ./zig-out/bin/oauth-mux probe --profile figma-pat \
    --capability identity-pat --json
```

Redacted result:

```json
{
  "provider": "figma-pat",
  "account": "work",
  "capability": "identity-pat",
  "ok": true,
  "probe_executed": true,
  "probe_status": 200,
  "decision": "use_this",
  "liveness": {
    "summary": "available",
    "state": "live",
    "availability": "available"
  }
}
```

The Figma `identity-pat` capability can now report `local_live_proven`.

## Negative Evidence

Earlier local proof attempted a Figma OAuth bearer token through
`examples/figma.config.json`. That route returned HTTP 403 and classified as
`degraded.scope_insufficient`. That is useful classifier evidence, but it is
not OAuth bearer live proof.

The same SOPS-managed Figma PAT was also tried against the Figma remote MCP
resource endpoint as an MCP bearer-resource candidate. The route returned HTTP
405 and classified as `degraded.unknown_4xx`. That confirms the PAT must not be
treated as a resource-bound MCP OAuth token.

## Current Proof Status

- Figma REST `identity-pat`: `local_live_proven`.
- Figma REST `identity`: `needs_operator_proof`.
- Figma REST `file-metadata-plan`: `needs_operator_proof`.
- MCP bearer-resource for `https://mcp.figma.com/mcp`: `needs_operator_proof`.

## Next

- Prove Figma OAuth bearer `identity` with a correctly scoped OAuth access
  token.
- Prove `file-metadata-plan` with an explicit file key and a token with
  file-metadata scope.
- Keep Figma PAT and Figma MCP resource tokens separate in docs, provider
  examples, and enrollment output.
