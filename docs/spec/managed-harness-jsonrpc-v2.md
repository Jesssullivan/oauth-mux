# Managed Harness JSON-RPC Surface v2

Status: **planned and unshipped**. This document and
`schemas/managed-harness-jsonrpc-v2.schema.json` declare a compatibility
contract only. They do not add a dispatcher, adapter process, Claude sidecar,
or managed harness launch.

Program authority remains:

1. `docs/spec/broker-mcp-contract-2026-05-03.md` for the product outcome;
2. `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` for v0.2;
3. `docs/security/omux-v0.2-threat-model-2026-07-11.md` for the managed boundary.

The shipped broker JSON-RPC surface remains version 1. Managed-harness surface
version 2 is a separate process-adapter contract and cannot be advertised as
implemented until an adapter satisfies its proof gates.

## Authority and projection

`src/managed_harness_contract.zig` owns the method registry, status, error
codes, exact-model rule, and two-attempt bound. Zig deterministically projects
that authority to:

```text
schemas/managed-harness-jsonrpc-v2.schema.json
```

Use `just managed-harness-schema-update` after an intentional contract change.
`just managed-harness-schema-check-local` is a local drift check; authoritative
completion proof uses the repository's remote `just check` lane.

The release declaration consumes the Zig-owned protocol name, version, and
status. Its status remains `planned_unshipped`.

## Envelope and compatibility

Requests use JSON-RPC 2.0 with a string or integer `id`, one declared method,
and an optional object `params`. Objects tolerate unknown fields so additive
minor changes remain forward-compatible. A semantic break requires a new
surface major.

Adapters and callers exchange opaque handles only. Handles identify harnesses,
sessions, routes, accounts, leases, and repair actions without exposing secret
material or provider-specific storage. The process boundary has no public
credential materialization, browser login, provider probe, restart, respawn,
or relaunch method. It carries no credential, token, environment, argument, or
prompt fields.

Unsupported declared methods return JSON-RPC error `-32099` (`method not
implemented`). Unknown methods return `-32601` (`method not found`). A method
cannot advertise support while returning the declared unsupported result.

## Lifecycle methods

| Method | Required request fields | Required result fields | Phase-1 status |
| --- | --- | --- | --- |
| `surface/info` | none | `surface_version`, `status`, `methods` | `not_implemented` |
| `harness/preflight` | `harness`, `model_demand` | `ready`, `harness_handle`, `reasons` | `not_implemented` |
| `session/launch` | `harness_handle`, `model_demand` | `session_handle`, `route_handle`, `state` | `not_implemented` |
| `route/lease_snapshot` | `session_handle` | `session_handle`, `leases`, `observed_at_ms` | `not_implemented` |
| `session/transition` | `session_handle`, `model_demand`, `proxy_attempts` | `state`, `selected_route_handle`, `action_required` | `not_implemented` |
| `repair/handoff` | `session_handle`, `reason` | `handoff_handle`, `action` | `not_implemented` |
| `session/teardown` | `session_handle` | `complete` | `not_implemented` |

`model_demand.preservation` is always `exact`. A transition records at most two
upstream attempts: the selected route and at most one alternate. Attempt
outcomes are `retained`, `switched`, `refused`, or `unproven`. These records are
redacted observations; they are not credentials and do not authorize replay.

The sidecar retry decision table, replay-memory budgets, fixed Anthropic origin,
capability-token boundary, streaming rules, and lease-file mechanics remain
owned by the v0.2 plan and threat model. This declaration does not weaken or
implement those rules.

## Promotion gates

The declaration may be described as shipped only as a checked compatibility
artifact. It does not support a managed-harness product claim.

The following remain independent gates under TIN-1798 and TIN-2057:

1. Codex round-trips the lifecycle and redacted status through surface v2.
2. Claude launches through the authenticated per-session sidecar and
   round-trips the same lifecycle.
3. OpenCode exercises the contract as an independent conformance adapter.
4. Unknown-field compatibility and explicit unsupported capability behavior
   pass integration tests.
5. The golden 2xClaude + 2xCodex evidence proves exact-model continuity in the
   same harness process without a login prompt or restart.

The canceled canonical-keychain hot-swap experiment remains historical
research for unmanaged sessions. It is not the v0.2 product mechanism and is
not required to prove this surface.
