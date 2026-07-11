# omux v0.2 Managed Broker Threat Model

Status: active design authority; unshipped

Date: 2026-07-11

Program: GitHub #463; Linear TIN-2057

## Scope and Trust Assumptions

This model covers `omux claude` managed launches, their authenticated loopback
sidecars, the resident refresh/observation service, local state, and the release
supply chain. Accounts must be owned by or explicitly authorized for the local
operator. Hosted pools, federation, account sharing, and unmanaged `claude`
processes are outside the product boundary.

The operating-system user account is the security boundary. The sidecar resists
accidental or opportunistic requests from other local processes, but cannot
protect secrets from root, a debugger attached as the same user, or a fully
compromised host. Tokens and request bodies necessarily exist briefly in process
memory; they must never be persisted or emitted in diagnostics.

## Assets and Boundaries

- OAuth access/refresh tokens, token-family lineage, and provider identities.
- Claude prompts, tool inputs, streamed responses, and exact requested model.
- Per-session capability tokens and route/lease state.
- Redacted health, quota, evidence, and release metadata.
- Boundaries: Claude child to sidecar, sidecar to fixed Anthropic origin,
  sidecar to shared local state, resident service to credential stores, and
  source commit to signed release artifacts.

## Required Controls

### Local credential boundary

- Bind one sidecar to `127.0.0.1:0` per managed child.
- Generate a memory-only 256-bit random capability, base64url encode it into
  `ANTHROPIC_AUTH_TOKEN`, compare it in constant time, and revoke it at teardown.
- A missing or wrong capability returns local 401 with a typed redacted event and
  zero upstream calls. Strip the capability and every inbound auth/API-key header
  before injecting only the elected account's upstream OAuth credential.
- A fake-upstream launch test must prove Claude Code carries the token as the
  expected bearer credential. Until then, no authenticated-sidecar claim exists.

### Confused deputy, SSRF, and redirects

- Accept origin-form Anthropic requests only and compile-fix the upstream to
  `https://api.anthropic.com` with system TLS verification.
- Reject `CONNECT`, absolute-form URLs, arbitrary hosts, caller-selected
  upstreams, and redirects that could carry authentication.
- Never expose a generic forward proxy or accept resident-service request-body
  forwarding.

### Exact-once and memory exhaustion

- Preserve the exact requested model. Permit one cross-account alternate only
  after an explicit pre-body 401/403/429; pass 5xx through and never replay an
  ambiguous transport result or a started response.
- Hold at most 32 MiB per replayable request, 64 MiB per sidecar, and 256 MiB per
  host. Shared atomic reservations use PID/heartbeat expiry and stale-owner
  cleanup. Budget exhaustion degrades to stream-once, never disk spooling.
- For chunked or unknown-length bodies, buffer only through 32 MiB. Crossing the
  limit irrevocably disables replay and streams the buffered prefix plus the
  remaining body once with backpressure.

### Credential lineage and route state

- Request-boundary refresh and resident keepalive share the existing
  per-account flock. Hard rotating-refresh-token failure quarantines the lineage
  and requires provider-owned re-enrollment; never restore a stale token backup.
- Identity conflicts fail closed. Exhaustion is trusted through reset,
  availability expires, and unknown routes rank below known-good but above dead
  or quarantined routes.
- Cross-process leases contain opaque session IDs, PID/heartbeat/expiry, and
  redacted route keys only. Stale or unavailable lease state is advisory and
  cannot prevent reactive routing.

### Availability and bounded failure

- When no route is ready, wait once only if the best trusted reset is within 30
  seconds and the request deadline. Otherwise, or after expiry, return typed 429
  plus the best trusted `Retry-After`; never loop, restart, or invent capacity.
- Resident-service absence or restart cannot become a hidden session proxy or
  corrupt a one-shot managed session.

### Evidence, logs, and browser tooling

- Logs, JSON-RPC, snapshots, cassettes, crashes, and evidence contain opaque
  handles and redacted labels only. Never dump child environments, auth headers,
  cookies, raw account IDs, emails, prompts, or response bodies.
- Browser/cookie-picker automation is attended evidence/operator-assist tooling,
  never a credential source or runtime dependency.

### FOSS and release supply chain

- Untrusted fork pull requests never execute on privileged GF runners or receive
  secrets. A maintainer promotes reviewed commits to a trusted branch for
  authoritative remote proof.
- `build.zig.zon` and the Zig release graph emit/check one release manifest.
  Signed artifacts, checksums, SBOM, provenance, source commit, and manifest must
  agree before publication.

## Claim Gates

Before a live Claude broker claim, remote tests must prove capability-carrier
behavior, bad-token zero-call rejection, fixed-origin/redirect/SSRF negatives,
streaming cancellation, all replay exclusions, chunked/oversize transitions,
memory reservations and stale cleanup, refresh quarantine, redaction, sidecar
death, and resident-service absence. Performance proof covers p95/p99 overhead,
streaming throughput, idle RSS, and 20 sessions across 50 accounts. Live release
evidence remains a separate attended, redacted gate.
