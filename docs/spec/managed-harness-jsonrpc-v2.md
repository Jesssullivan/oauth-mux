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
codes, exact-model rule, two-attempt bound, capability carrier, replay and wait
budgets, lease record, and redaction policy. Zig deterministically projects
that authority to:

```text
schemas/managed-harness-jsonrpc-v2.schema.json
```

Use `just managed-harness-schema-update` after an intentional contract change.
`just managed-harness-schema-check-local` is a local drift check; authoritative
completion proof uses the repository's remote `just check` lane.
`just managed-harness-contract-check-local` validates positive and negative
Draft 2020-12 instances plus cross-attempt relationships that JSON Schema
cannot compare by value.

The release declaration consumes the Zig-owned protocol name, version, and
status. Its status remains `planned_unshipped`.

## Envelope and compatibility

Requests use JSON-RPC 2.0 with a string or integer `id`, one declared method,
and an object `params` (empty for `surface/info`). Objects tolerate only a
bounded extension namespace: `x_flag_*` booleans, nonnegative `x_count_*`
integers, and `x_ratio_*` numbers from zero through one. Arbitrary keys,
strings, arrays, objects, unbounded collections, and values outside the
interoperable JSON integer range are rejected. Redacted text and opaque handles
require typed named fields. A semantic break requires a new surface major.

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
| `surface/info` | none | `surface_version`, `status`, `methods`, `policy` | `not_implemented` |
| `harness/preflight` | `harness`, `model_demand` | `ready`, `harness_handle`, `reasons` | `not_implemented` |
| `session/launch` | `harness_handle`, `model_demand` | `session_handle`, `route_handle`, `state` | `not_implemented` |
| `route/lease_snapshot` | `session_handle` | `session_handle`, `leases`, `observed_at_ms` | `not_implemented` |
| `session/transition` | `session_handle`, `model_demand`, `proxy_attempts` | `state`, `selected_route_handle`, `action_required` | `not_implemented` |
| `repair/handoff` | `session_handle`, `reason` | `handoff_handle`, `action` | `not_implemented` |
| `session/teardown` | `session_handle` | typed `cleanup` | `not_implemented` |

`model_demand.preservation` is always `exact`. Attempts do not carry an
independent model field: they inherit the transition-level demand, making
model drift structurally invalid. A transition records one initial attempt and
at most one follow-up. The only follow-up shapes are:

1. one same-route retry after a confirmed pre-send transport failure; or
2. one cross-account alternate after a buffered pre-downstream 401, 403, or
   429 response, with explicit alternate account and route handles distinct
   from the initial handles.

A same-route retry inherits the initial account and route handles and cannot
carry replacements. The checked semantic validator rejects an alternate that
reuses either initial handle.

A follow-up can never represent a provider 5xx, ambiguous transport result, or
started downstream response. Provider 5xx passes through to the harness's
native retry behavior. Attempt outcomes are `retained`, `switched`, `refused`,
or `unproven`. These records are redacted observations; they are not credentials
and do not themselves authorize replay.

## Frozen managed policy

`surface/info.policy` exposes immutable compatibility constants without
exposing a session capability or account secret:

| Policy | Surface-v2 contract |
| --- | --- |
| Carrier | 256 bits from the operating-system CSPRNG; base64url without padding; memory-only and bound to the managed child; constant-time comparison; never logged and disposed at teardown; `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL`; bind `127.0.0.1:0`; bad capability is local 401 with zero upstream calls |
| Origin | Strip inbound auth/API-key headers and inject only the elected OAuth bearer; origin-form requests only; reject `CONNECT`, absolute-form, and caller-selected upstreams; fixed `https://api.anthropic.com` with system-root TLS; auth-carrying redirects rejected |
| Replay | At most two upstream attempts and one cross-account alternate; 401/403/429 only; 32 MiB/request, 64 MiB/sidecar, 256 MiB/host; reservations are atomic cross-process state owned by PID/heartbeat/expiry and stale owners are reclaimed; disk spooling forbidden |
| Overflow | Chunked or unknown-length bodies buffer only to the request limit, then stream once with backpressure and release the reservation; cancellation also releases reservations and cannot cross accounts |
| Exclusions | Ambiguous transport and started responses propagate the original failure or response unchanged without cross-account replay; provider 5xx passes through to native retry |
| Wait | At most one pre-attempt wait, no more than 30 seconds, only for a trusted reset that fits the request deadline; then re-elect; otherwise typed 429 using the best trusted `Retry-After`; loops forbidden |
| Lease | Atomic redacted cross-process state; sticky least-loaded then least-recent; PID, heartbeat, and expiry required; stale owners ignored and reclaimed; unavailable lease state never blocks reactive routing |
| Staleness | Exhaustion trusted through reset; available claims require a freshness deadline; unknown ranks below known-good and above dead |
| Redaction | Opaque handles and redacted labels only; account/user/email/organization identity names and credential-bearing names are reserved out; additive extensions are limited to typed `x_flag_*`, `x_count_*`, and `x_ratio_*` scalars; local evidence is typed and redacted; request-body persistence forbidden |

`route/lease_snapshot.leases` contains typed opaque lease records with session,
account, route, exact-model demand, owner PID, heartbeat, expiry, and owner
state. `session/transition.action_required` is either null or a typed
all-exact-model-routes-exhausted 429 carrying trusted reset evidence,
`Retry-After`, and the bounded wait actually consumed. `repair/handoff.action`
is a typed provider-owned re-enrollment action and freezes automatic stale
backup restoration as false.
`session/teardown.cleanup` succeeds only after the sidecar terminates, the
session capability is disposed, leases are released, and replay reservations
are released. Partial cleanup returns an error rather than a misleading
`complete` boolean.

The v0.2 plan and threat model continue to own implementation mechanics and
proof gates. The observable constants and outcomes above are frozen in surface
v2; this declaration does not implement them.

## Promotion gates

The declaration may be described only as a landed, checked compatibility
declaration. It does not support a managed-harness product claim.

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
