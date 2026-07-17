# oauth-mux v0.2 Full Broker FOSS Program

Status: active design authority; unshipped

Date: 2026-07-11

Program: GitHub #463; Linear TIN-2057

Horizon: six-week beta

Security: `docs/security/omux-v0.2-threat-model-2026-07-11.md`

## 1. Outcome

v0.2 makes oauth-mux the full request broker for managed harness sessions. The
first implementation is a Claude request proxy. A managed Claude process talks
only to a per-session authenticated loopback sidecar through
`ANTHROPIC_BASE_URL`; that sidecar owns route choice and the narrowly bounded
alternate attempt. The harness process is never restarted and the user is not
prompted during handoff.

This program is a hard contract reset. It supersedes incremental valet,
restart, prepared-fallback, federation, and universal-provider directions. It
does not change what v0.1.15 has shipped or what its evidence proves.

## 2. Product Contract

### 2.1 Managed session boundary

- `omux` is the primary v0.2 CLI. `oauth-mux` remains a compatibility link.
- Broker guarantees apply only to a harness launched by `omux <harness>`.
- Managed launch preflight must prove a non-empty proxy configuration, a bound
  authenticated sidecar, fixed-upstream policy, and the child environment/state
  map before spawning Claude. Any failure aborts before child launch. Direct or
  unmanaged fallback is allowed only by explicit operator policy and is never
  silent.
- Every managed Claude launch creates one sidecar bound to loopback and one
  256-bit random capability token. The token is memory-only, passed to the
  child without logging, compared in constant time, and dies with the session.
  A missing or incorrect token returns a local 401 and makes no upstream call.
- The child receives a loopback `ANTHROPIC_BASE_URL` and the base64url token in
  `ANTHROPIC_AUTH_TOKEN`. A fake-upstream launch test must prove Claude Code
  carries it as the inbound bearer credential before an authenticated-sidecar
  claim. Direct, already-running, and unmanaged Claude processes are outside
  the broker contract.
- The sidecar accepts origin-form Anthropic requests and forwards only to the
  compiled `https://api.anthropic.com` upstream origin. It is not a general
  proxy: reject `CONNECT`, absolute-form requests, arbitrary destinations,
  caller-selected upstreams, and redirects that would carry authentication.
- The resident service never accepts or forwards session request bodies.

### 2.2 Routing and retry

- Route by the exact requested model identifier; no family inference or
  silent model substitution.
- Select an eligible account with sticky, least-loaded session leases. A lease
  remains stable for the session unless explicit reactive evidence makes the
  route unavailable. Load is the count of active leases, with deterministic
  tie-breaking.
- A request has at most two upstream attempts total. After the initial attempt,
  its one retry slot is consumed by either one same-route retry after a confirmed
  pre-send transport failure or one distinct-account alternate after an explicit
  401, 403, or 429 before any response body byte reaches the harness. It can
  never receive both.
- Retry requires a replayable request body held wholly in memory. The hard cap
  is 32 MiB. Requests above the cap stream once and cannot use an alternate.
- Replay reservations are capped at 64 MiB per sidecar and 256 MiB across
  managed sidecars on one host. The shared state view owns atomic reservations
  and stale-PID cleanup. If either budget is unavailable, the request streams
  once and is non-replayable. A chunked or length-unknown body may buffer to
  32 MiB; on the next byte it releases replay eligibility and streams the held
  prefix plus the remainder once with backpressure.
- Never spool prompts or request bodies to disk.
- A transport failure may consume the one same-route retry only when the proxy
  proves that no request byte was sent. Ambiguous send state, any partial write,
  or any response whose headers/body have begun downstream is never replayed.
  Transport failures never authorize a cross-account attempt. Return the
  original failure and record redacted local evidence.
- Provider 5xx responses pass through to Claude Code's native retry behavior;
  they never trigger a cross-account attempt.
- No third route, retry loop, mid-response failover, or cross-model downgrade.
- Before an upstream attempt, an exhausted pool may wait once only when the
  best trusted reset fits both a 30-second maximum and the remaining request
  deadline. Re-observe and re-elect after the wait without increasing the
  two-attempt budget. Otherwise, or when the wait expires, return a typed local
  429 with `Retry-After` from the best trusted evidence. Never loop, restart the
  harness, or invent capacity.
- Concurrent sidecars share an atomic, redacted lease view under the state
  directory. Each lease records an opaque session id, PID, heartbeat, expiry,
  account/model route, and supports stale-owner cleanup. Lease load is advisory:
  stale or unavailable lease state cannot block reactive routing.

### 2.3 Usage and health truth

- The OAuth usage reader is enabled by default for managed Claude sessions but
  remains advisory only. Every observation records
  source, capture time, account, exact model or account-wide scope, window, and
  whether it is observed or inferred.
- The resident service owns scheduled usage polling, coalescing, and the
  normalized cache. A session sidecar consumes that redacted snapshot; it does
  not create a second proactive polling loop. When the service or a fresh
  snapshot is unavailable, the sidecar stays correct through reactive
  request-path evidence.
- The reader calls only `GET /api/oauth/usage` at the fixed Anthropic origin and
  coalesces one in-flight read per account. Its normalized per-account cache is
  fresh for five minutes; raw provider payloads remain memory-only. Unknown JSON
  fields are tolerated, but a consumed row must provide a scope, quota window,
  bounded utilization or remaining value, and absolute reset time. A model-scoped
  row must also carry an exact model identifier. Invalid rows are ignored; zero
  valid rows disables that advisory observation and emits one typed redacted
  schema-validation event and a five-minute negative cache entry.
- Missing required top-level structure or an unsupported schema/version
  activates a per-account kill switch for that process lifetime and records one
  typed, redacted event per schema fingerprint. It disables only that advisory
  reader; it never stops the sidecar or managed harness. Request-path evidence
  and reactive routing continue.
- Advisory data may avoid a predictably bad first route, but it cannot justify
  replay or override direct request-path evidence.
- Missing, stale, malformed, or contradictory advisory data falls back to
  reactive 401/403/429 handling. The successful or failed request remains the
  strongest current route evidence.
- Staleness is asymmetric: an observed exhaustion remains trusted through its
  reset, an available claim expires at its freshness deadline, and unknown
  routes rank below known-good but above dead or quarantined routes.
- Credential refresh is account-wide. Quota and entitlement observations are
  routing inputs; they never trigger per-model credential refresh.

### 2.4 Process ownership

The per-session sidecar owns request authentication, exact-model route
selection, leases, bounded buffering, forwarding, and the single alternate.
The resident service owns only account refresh, advisory usage observation,
transition alerts, and redacted snapshots. It is optional for one-shot managed
launch correctness and is never a hidden session proxy.

The sidecar may invoke bounded request-boundary refresh; proactive refresh stays
with resident keepalive. Both serialize through the existing per-account flock.
Hard rotating-refresh-token failure quarantines that lineage
and requires provider-owned re-enrollment; stale token backups are never
restored automatically.

All telemetry is local-only and redacted. Alerts fire on state transitions, not
poll ticks: healthy to constrained, constrained to recovered, credential dead,
resident service stale, and sidecar terminal failure. No remote analytics or
prompt/body capture is in scope.

### 2.5 Setup and operator experience

- `omux setup` owns preflight, labeled account enrollment, provider-owned
  isolated login, identity/model-signal verification, explicit refresh and
  switching consent, user-service installation, and a final readiness proof.
- The managed harness remains the primary UI. Ship a compact statusline,
  transition notifications, and `omux repair <label>`; do not build a competing
  dashboard or TUI.
- Design a versioned, read-only redacted snapshot contract for a later macOS
  menu-bar companion. The companion never reads credentials or acts directly;
  it opens the CLI setup/repair flow. It does not block v0.2.
- Browser and cookie-picker automation is evidence/operator-assist tooling only.
  It may record redacted headed-flow cassettes, but never becomes an auth source
  or a provider-contract authority.

## 3. Program Ownership

The six-week initiative has five product projects: Core + Subtraction, Claude
Managed Broker, Adapter Contract + Codex/OpenCode Parity, Delivery + FOSS, and
Operator Trust + Evidence. Zig/Bazel/GF REAPI is a linked parallel workstream,
not a sixth product project and not a prerelease blocker.

## 4. Adapter and Platform Contract

- The reusable harness adapter contract is process-level and versioned. Control
  and diagnostics use JSON-RPC `surface_version: 2` with opaque session handles;
  raw credentials never cross that surface. There is no C ABI, shared-library
  ABI, or FFI SDK program.
- Claude is the first request-proxy adapter and the v0.2 golden path.
- OpenCode is the conformance adapter: it must exercise the same lifecycle,
  route/lease vocabulary, JSON-RPC control contract, redaction, and failure
  semantics without weakening the Claude contract.
- Gemini does not piggyback on Claude or Codex OAuth credentials. Any future
  Gemini adapter needs its own provider-authorized credential and evidence
  contract.
- Federation is canceled. Remote brokers, broker peering, fleet routing, and
  cross-host credential authority are out of scope.
- Remove built-in providers that are not part of a managed harness continuity
  path. Generic provider authoring may return later behind a proven adapter
  contract; v0.2 does not ship a broad provider catalog.

Platform target: macOS is GA, Linux is beta, and the Windows broker is
unsupported. Windows release artifacts may remain only where needed to preserve
v0.1.15 stable behavior until the v0.2 release graph explicitly removes them.

## 5. Release Authority

The v0.2 release graph is manifest-first at its consumer boundary, but Zig owns
product semantics. `build.zig.zon` remains the single human-edited version
source; the Zig release graph owns supported targets and deterministically emits
and checks `release-manifest.json` with version, build id, binary names,
compatibility links, artifact names, service assets, checksums/signing inputs,
SBOM/provenance, and adapter protocol versions. Packaging, installers, Nix,
Homebrew, Bazel, and GloriousFlywheel consume that generated projection; none
may carry an independent version or target list.

The parallel Bazel/GF lane pins one house-approved Bazel version and makes
`MODULE.bazel` consume the release version instead of duplicating it. Zig joins
GF worker/toolchain and target-class eligibility only after forced proof records
`remote_processes > 0`, the worker digest, and no local fallback. Do not adopt
the SvelteKit-shaped reusable `spoke-ci.yml`; Just/Nix/GF runner proof remains
authoritative until a generalized template is promoted.

Public fork pull requests execute no privileged CI. Contributors run documented
local checks; a maintainer explicitly promotes a reviewed commit to a trusted
branch before authoritative GF proof. The FOSS surface includes
`CONTRIBUTING.md`, `SECURITY.md`, support/privacy policy, issue/PR templates,
source-build and migration guidance, signing, SBOM, and provenance verification.

Prereleases are signed. v0.1.15 remains the stable channel until golden proof
passes. A v0.2 prerelease must not overwrite stable aliases or broaden public
claims. npm remains retired and is not part of the new graph.

## 6. Six-Week Delivery

1. Week 1 - contract reset and deletion guards: land authority, threat model,
   Zig-emitted `release-manifest.json` schema,
   CLI naming contract, adapter JSON-RPC schema, and characterization tests for
   v0.1.15 surfaces that must survive migration.
2. Week 2 - Claude sidecar skeleton: authenticated loopback lifecycle, fixed
   upstream validation, managed `ANTHROPIC_BASE_URL`, streaming pass-through,
   redaction, and 32 MiB memory boundary.
3. Week 3 - broker semantics: exact-model eligibility, sticky least-loaded
   leases, explicit pre-body classification, single-alternate state machine,
   and negative replay tests for every ambiguous case.
4. Week 4 - resident support plane: refresh integration, provenance-bearing
   advisory usage observations, reactive fallback, snapshots, and transition
   alerts. No request-body path enters the resident service.
5. Week 5 - release and conformance: `omux` primary CLI, compatibility link,
   manifest consumers, signed prerelease, macOS packaging, Linux beta package,
   and OpenCode conformance adapter.
6. Week 6 - beta and golden gate: soak, failure permutations, install/upgrade
   tests, documentation, and three clean non-maintainer beta users, including
   at least one Linux user.

Promotion is explicit: shadow observation, manual-route proof, automatic beta,
then default-managed mode. Daily checks are no-spend schema probes; a bounded,
attended micro-spend adapter matrix runs weekly and at release gates.

TIN-2989 owns making the evaluation ladder executable before any Stage 2 or G4
claim: its v0.2 proof dispatch will bind an immutable candidate SHA, reconcile
the checked-out tree and allowlist provenance, and run named fake-upstream
conformance and benchmark targets. Generic GF test/check and Public Source
remain required source proof, but neither substitutes for those matrices.
TIN-2050 owns a separate signed v0.2 prerelease profile. TIN-1759 must close
before any Stage 4 install, resident mutation, rollback, or attended live
dogfood surface becomes eligible.

## 7. Golden Gate

v0.2 can replace v0.1.15 as stable only when committed, redacted evidence proves:

- a managed Claude session keeps the same harness process through a
  provider-originated, pre-body `quota_exhausted` 429 account handoff and
  succeeds on exactly one alternate; pre-body 401/403 remain required
  synthetic negative coverage and earn no live continuity credit;
- no replay occurs for ambiguous transport failure, oversize body, or started
  response; per-request, per-sidecar, and host replay budgets fail to stream-once
  without writing prompt bytes to disk;
- exact-model routing and sticky least-loaded leases hold under concurrency;
- local routing/auth overhead is p95 <= 5 ms and p99 <= 10 ms before upstream
  I/O, sustained streaming throughput stays within 5% of direct, idle sidecar
  RSS is <= 20 MiB, and 20 sessions across 50 accounts show no lock starvation;
- sidecar authentication, loopback binding, fixed-host enforcement, redirect
  refusal, `ANTHROPIC_AUTH_TOKEN` carrier behavior, zero-upstream-call rejection,
  and secret redaction pass negative tests;
- resident service absence or restart cannot turn it into the session proxy;
- signed prerelease install/upgrade works on macOS and the beta path works on
  Linux; Windows broker invocation fails clearly as unsupported;
- the full matrix proves 2xClaude + 2xCodex continuity and OpenCode exercises
  the same adapter lifecycle and redacted control contract;
- all-accounts-exhausted and resident-service-unavailable paths terminate with
  bounded, actionable state instead of loops, restarts, or invented capacity;
- three clean non-maintainer users complete the beta, one on Linux, with local
  evidence covering install, enrollment, managed launch, handoff, and repair.

Until then, all v0.2 docs and prereleases must say future, experimental, or
unshipped, and v0.1.15 remains the honest stable release.

## 8. Explicit Non-Goals

Arbitrary HTTP proxying, provider redirects, disk replay queues, more than one
alternate, ambiguous-failure replay, mid-stream recovery, unmanaged-process
handoff, remote telemetry, federation, C ABI/FFI, Gemini credential piggybacking,
Windows broker support, and preservation of proof-only public verbs are not
v0.2 work.

The sequenced removals and evidence-preservation rules are normative in
`docs/plans/oauth-mux-v0.2-deletion-ledger-2026-07-11.md`.
