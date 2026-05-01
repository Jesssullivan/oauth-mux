# Provider Proof: Vercel Identity
Date: 2026-05-01

Issue context: GitHub `Jesssullivan/oauth-mux#68`; Linear `TIN-736`,
`TIN-876`.

## Boundary

Vercel is a bearer-token HTTP provider for the first proof slice. The proven
capability is `identity`, which maps to Vercel's authenticated user endpoint.
This proof does not claim team/project mutation, deploy behavior, billing
state, or OAuth repair.

The official Vercel REST API reference documents `GET /v2/user` as retrieving
the currently authenticated user and shows bearer-token authentication for that
request:

- Vercel "Get the User":
  <https://docs.vercel.com/docs/rest-api/reference/endpoints/user/get-the-user>

The same reference family documents token metadata separately under
`GET /v5/user/tokens/{tokenId}`, including the special `current` token id. That
may be useful for future expiry/scope evidence, but this slice does not call it
or promote it as a required probe:

- Vercel "Get Auth Token Metadata":
  <https://docs.vercel.com/docs/rest-api/reference/endpoints/authentication/get-auth-token-metadata>

## Local Live Proof

Low-impact local proof used the existing `examples/vercel.config.json` profile
with a scoped operator token supplied through `OMUX_VERCEL_WORK_TOKEN`. The run
used a temporary oauth-mux state directory and did not write provider state.

```bash
OMUX_STATE_DIR=$(mktemp -d) \
OMUX_CONFIG=$PWD/examples/vercel.config.json \
OMUX_VERCEL_WORK_TOKEN=$VERCEL_TOKEN \
./zig-out/bin/oauth-mux probe --profile vercel --capability identity --json
```

Redacted result:

```json
{
  "provider": "vercel",
  "account": "work",
  "capability": "identity",
  "ok": true,
  "probe_executed": true,
  "probe_status": 200,
  "decision": "use_this",
  "liveness": {
    "summary": "available",
    "state": "live",
    "availability": "available"
  },
  "last_probe": {
    "source": "capability_probe",
    "hint_class": "none",
    "decision": "use_this"
  }
}
```

The Vercel `identity` capability can now report `local_live_proven`. Provider
level status should remain conservative until broader Vercel token, team,
scope, and project/resource failure shapes have redacted fixture coverage.

## Adjacent Figma Findings

An earlier proof pass also tested a Figma OAuth bearer identity token through
`examples/figma.config.json`. That route returned HTTP 403 and correctly
classified as `degraded.scope_insufficient`.

That is useful evidence for the Figma classifier, but it is not a Figma live
proof and does not promote OAuth bearer identity.

A later SOPS-backed proof tested the Figma PAT route through
`examples/figma-pat.config.json`. That route returned HTTP 200,
`live.available`, and `decision=use_this`, so only `identity-pat` can now be
reported as `local_live_proven`. `TIN-877` remains open for Figma OAuth bearer
identity and plan/file-token metadata proof.

## Next

- Add Vercel fixture coverage for 401, 403 scope/tier/team, 429, and 5xx
  response shapes.
- Consider the token metadata endpoint only if it gives useful redacted expiry
  or scope evidence without widening the default probe.
- Keep Vercel probes out of default background loops unless daemon policy
  explicitly admits the provider budget.
