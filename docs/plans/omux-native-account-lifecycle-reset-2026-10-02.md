# Omux native account-lifecycle reset — 2026-10-02

Status: **active architecture, experimental and unshipped**. This document
supersedes the July managed-launch v0.2 program and its execution/deletion
policies. It does not broaden v0.1.15 claims. Implementation status and completed
proof are recorded separately below.

## Outcome and boundaries

Install Omux, authorize sources once, then run applications normally. Omux keeps
supported applications usable through compatible account handoff without process
restart, routine prompts or changes to native session/history authority.
Codex is the first native integration proof; Claude and Git HTTPS/GitHub follow.
Verified native attachment supports already-running processes. An application
without the required hook remains unsupported for live handoff.

The 2026-10-05 user reassertion assigns each application's authentication
integration contract and implementation to Omux. There is no vendor-provided
Omux/Codex hook to await. Use a sufficient existing extension mechanism or
develop the native boundary. Qualify delivery per application: plugin,
configuration, upstream contribution or explicitly maintained application
modification. Upstream acceptance is a gate for upstream delivery, not a universal
dependency. Experimental Codex candidates are valid evaluation artifacts;
unmodified Codex support remains unestablished and no candidate inherits live proof.

The product sequence is **install and activate → connect Chromium sources →
verify identities and usable authority → maintain renewal → integrate ordinary
applications → prove same-process handoff**. Other enrollment methods remain
available where supported; browser acquisition is not mandatory for every source.

Use a resident per-user Zig daemon and thin SwiftUI/macOS, Qt6/Linux, CLI and
browser clients. Local federation is the initial boundary. Generic resources
include calls, bytes, uploads, durations, throughput and scoped provider capacity.
Cross-host pools, Windows, Safari and speculative stream recovery are deferred.

## Domain and lifecycle contract

| Entity | Authority and independent state |
| --- | --- |
| Identity | Verified issuer/provider subject and organization associations; labels are presentation |
| Account | Identity, service/account type, lifecycle and user preferences |
| Source | Authorized native store, explicit credential input, enrollment flow or browser context |
| Grant | Audience, scopes, purposes, credential form, validity, renewal ownership and generation |
| Resource | Operation/model/repository/destination demand with provider-defined units and scope |
| Observation | Value, scope, units, window, provenance, timestamp and freshness |
| Binding | Native process/thread/session authority, active route and attachment capabilities |
| Lease | Bounded use of a grant for a purpose and application binding |

Authentication factors (password, OTP, security key, passkey) are enrollment
requirements, not interchangeable grant types. Browser read access does not
implicitly authorize API calls. Account lifecycle, grant validity, entitlement,
resource capacity and local readiness are independent; unknown never means ready.

Automatically enroll verified identities from authorized sources and deduplicate
by verified evidence. Quarantine ambiguous candidates. Source disappearance
means detachment: retain history and independently valid grants. Pause prevents
new admission; drain also lets existing bindings finish; forget erases retained
secrets and leaves a tombstone blocking automatic re-enrollment. Upstream
revocation is a distinct explicit operation. Re-enrollment clears a tombstone only
through an explicit authorized action.

All technically compatible accounts are eligible by default; users can narrow
policy. Keep routes sticky, maintain warm alternatives and switch at verified
safe boundaries. Aggregate only compatible units, scopes and windows. Multiple
grants sharing one quota bucket count once. Capacity observations carry freshness;
missing or stale data is visible rather than invented.

## Processes, custody and interfaces

The daemon owns lifecycle, custody, policy and route decisions. Supervised adapter
workers own application-specific protocol boundaries. Closing a thin UI leaves
the daemon running. Use bounded `std.Io.Threaded` work, a dedicated libcurl multi
owner for outbound transport and one SQLite writer queue. Cancellation executes
through the owner of the affected operation.

SQLite stores metadata and encrypted grant payloads, with durable operations and
transactional migrations. Encrypt before insertion so journals/backups contain
ciphertext. Keep the wrapping key in macOS Keychain or Linux Secret Service. A
locked/missing key returns a repair condition and never creates a replacement
for an existing database. No plaintext fallback exists.

One writer renews each adopted grant. Importing a native/browser grant does not
transfer refresh ownership. Verify identity and adoption authority before Omux
rotates its lineage. Reconcile external writers; quarantine ambiguous rotations
rather than retry spent refresh tokens. Provider validity, source custody
permission and observation freshness are separate. Omux leases do not extend
upstream validity.

Implement versioned local APIs, with private Unix sockets, peer-user checks,
bounded framing, opaque handles, idempotent operation IDs and revisioned
snapshots/events:

- **Control:** capability handshake, snapshots/events, source/account operations,
  enrollment/repair jobs, integration setup/removal, policy and grouped usage.
- **Adapter:** native attachment, resource demand, typed observations, route
  leases, renewal requests and completion reporting.
- **Browser:** source authorization, scoped grant import, observations and
  reconciliation through a native-messaging bridge.

The general control API never exports credentials. Trusted adapter channels may
materialize narrowly scoped credentials when required by their native protocol.
Keep secret payloads out of logs, argv, diagnostics and evidence.

### Native application integration

Install reversible native hooks during setup. Ordinary commands remain the user
entrypoints. Preserve native history and session stores in place; do not fork
homes to simulate account continuity.

These are Omux-owned application adapters, including any required native auth
boundary. Vendor OAuth support alone does not establish safe credential replacement
in a running application. Setup and capability reporting must identify the exact
adapter, application build, delivery method and current evidence level.

Codex needs a verified native hook for late broker registration and per-thread,
per-request external grants. Its general daemon/app-server controls alone do not
prove this capability. The hook must delegate adopted-grant renewal, report
proven pre-acceptance auth/quota failures before native error presentation, and
clear account-bound connections/incremental references after route change while
retaining transcript, tools and approvals. Reconstruct from native retained
context; never replay an accepted stream or repeat tool execution.

Until that hook and live proof exist, advertise Codex integration/attachment as
unavailable or experimental according to its actual implementation. A mock worker,
capability declaration or route-election test earns no live handoff claim.

### Browser acquisition

Use Chromium/Firefox extensions and native messaging, with permissions requested
for the connected provider. Import only adapter-declared cookie/storage fields.
Preserve origin, domain, path, store, partition, security attributes and expiry.
Verify candidates at a fixed declared identity endpoint before account binding.
Return opaque handles after encrypted persistence.

Browser closure does not revoke a genuinely exportable grant. Device/browser-bound
grants retain their signing authority and report `browser_required` when it is
absent. Prefer daemon fetches; use browser-context fetches where authorization
cannot leave that context. A page reader extracts only declared typed fields;
schema drift disables the reader without fabricating observations or disabling
otherwise valid application routes. Browser automation is absent.

### Clients and generated documentation

SwiftUI menu-bar and Qt6 tray/settings clients share the control API for sources,
accounts, active bindings, grouped capacity, policy and repair. Show freshness,
unknown states and missing native hooks. Notify on meaningful transitions.

The separate `omux.xoxd.ai` SvelteKit SPA renders download/documentation facts from
a versioned generated bundle: API schemas, CLI reference, adapter capabilities,
examples, support evidence and release metadata. Curated intent/lifecycle prose
remains hand-authored. Website rendering never creates runtime capability claims.

## Toolchain, deletion and delivery

Pin official Zig 0.17.0 (released 2026-10-01), verified against the
[official release index](https://ziglang.org/download/index.json), with its
release metadata and checksums. Pin the
external C translation tool needed by that compiler. Pin SQLite, libcurl and
transport/native client dependencies in locked Nix/Bazel inputs.

Bazel is the sole graph for binaries, libraries, tests, generators, native/UI
clients, extension/bridge artifacts and packaging. Rules invoke compiler actions
directly with declared inputs and per-action scratch caches. Nix contains the
compiler/tool closures, Qt/Swift/JS tools, test browsers and packaging tools;
the Apple SDK is an explicit authorized platform input.

```bash
nix develop --command bazelisk build //...
nix develop --command bazelisk test //...
```

Proof is local and sandboxed by default. Remove automatic CI build/test/check
workflows and obsolete required-check assumptions. Publication is explicit and
artifact-driven. Future RBE/REAPI uses the same action graph, digest-addressed
tool closures and execution platforms; only operator configuration changes.
Remote endpoints/credentials never belong in committed source.

### Installed product and development ownership

Native UI onboarding and CLI use one shared setup engine, reporting installation,
service activation, vault, source, verified identity, usable grant and native
capability independently. Home Manager owns fleet deployment of Bazel-produced
daemon, host, CLI and thin UI artifacts, service definitions and exact-ID browser
host manifests. Omux owns runtime custody and authorized enrollment. Setup detects
Nix-owned files and reports required declarative changes rather than overwriting
them. Closing controls does not stop the resident daemon.

Development has a stable separate extension ID, host name, service, installation
directory, socket, database and vault namespace. Never share a renewal writer or
custody database with release. One serialized Bazel entrypoint builds/stages the
real components into a stable private directory; Chromium reload and development
daemon restart are explicit. Before execution, establish bounded aggregate memory
and process use, an overall deadline, exclusive run ownership, cancellation and
verified descendant cleanup, including Nix bootstrap and qualified shared-builder
activity. These are implementation requirements, not completed containment proof.

Updates use guided explicit declarative deployment and compatibility checks before
activation. Nix generation rollback must not roll back credential generations,
tombstones or replay authority. Permanent vault-key loss preserves the failed
installation and offers explicit fresh enrollment into separate custody.

### Deletion and evidence map

Pre-reset baseline: `f5f83c1ad99c2920de6759791b327a99a02a2ec5`.
The successor compiles none of its legacy runtime. Historical release tags,
including `v0.1.15`, retain executable history.

| Baseline surface | Disposition |
| --- | --- |
| 96 tracked `src/` files | Removed; fresh runtime/types replace the old pipeline, proxies and provider modules |
| 93 tracked `scripts/` files | Removed; no legacy script-based build/test/dispatch path |
| 5 `dist/` files and 11 example configs | Removed; new installation/client artifacts use Bazel targets |
| Old managed-harness JSON schema | Removed; new local APIs derive from current source definitions |
| `build.zig`, `build.zig.zon`, alternate Zig build, Just and release manifest | Removed as executable/release authority |
| 9 CI workflows and private GF checkout action | Removed; no default remote/CI test execution |
| Legacy executable test roots | Removed; reviewed fixture/evidence data remains |
| 232 files under `docs/evidence/`, `test/evidence/`, `test/fixtures/` | Retained as baseline data, with original claim boundaries |
| Earlier specs/plans/runbooks | Select evidence references retained; 90 obsolete documents deleted and three research packets moved under `docs/history/`; disposition in `docs/history/retired-design-inventory.md` |

The retained file count is a baseline inventory, not a new proof count. Do not
copy secret-bearing captures into replacement fixtures. Reimplement useful
invariants against fresh types rather than importing old modules.

### Backlog disposition

The original multi-account intent (TIN-491) and user-efficiency program (TIN-2057)
remain intent/evidence references. Existing lifecycle, store, renewal,
re-enrollment and adapter tickets must be re-scoped to the new entity model.
Managed-launch-only, optional-daemon, wrapper/session-home and GF-required
execution proposals are superseded. Discovery/removal, generic capacity,
browser acquisition, native attachment and thin clients are distinct replacement
workstreams. Tracker status does not substitute for committed implementation or
live proof. The October 2 ratification push separately authorizes direct Linear
project/backlog reconciliation; its receipt is
`docs/tracker-updates/native-ratification-2026-10-02.md`.

## Acceptance and implementation status

The replacement is experimental source. An implemented method, accepted fixture
or successful synthetic test does not promote a planned integration to live
support. Completion reporting must distinguish source implementation, local
synthetic checks, native conformance and live-provider evidence.

Required local Bazel suites cover verified/ambiguous enrollment, detachment,
tombstones, drain/forget/revocation; encrypted journals and locked vaults; renewal
ownership and crash reconciliation; compatible/incompatible capacity totals and
shared buckets; browser scope/partition/identity/expiry handling; malformed local
messages; normal native launch/resume and existing-session attachment; concurrent
identities and handoff; packaging/uninstall restoration and generated-doc drift.

Golden promotion requires version-bound live evidence of ordinary application
launch/resume, quota exhaustion, compatible alternate admission, unchanged
application process, preserved native session/tool/approval authority and no
routine prompt. Unsupported existing processes and accepted-stream failures must
remain honest. No live support is inferred from the predecessor's evidence.

Implementation sequence reasserted 2026-10-05: (1) reconcile active authority,
tracker nouns and acceptance, then establish execution containment and isolated
development staging; (2) deliver Linux Home Manager installation/activation and
shared UI/CLI setup/readiness; (3) prove installed Chromium connection, scoped
consent, verified enrollment, reconnect and source lifecycle; (4) maintain verified
grant renewal and update/removal custody; (5) develop Codex's Omux-owned adapter
and qualify candidate ordinary launch/resume, attachment and same-process handoff;
(6) extend Claude/Git, derived SPA delivery metadata and remaining platform proof.
Parallel implementation may advance independent prerequisites; elapsed time does
not close a gate. This sequence supersedes the earlier Codex-before-browser order.
Mark each capability implemented only when its actual target and acceptance
evidence exist. Reliability targets remain SLO measurement targets, not an unstaffed
contractual SLA; timely safe refusals and successful user outcomes are separate.
