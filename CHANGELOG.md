# Changelog

Release discipline (adopted 2026-07-04): cuts are bound to committed evidence
under `docs/evidence/` — every release lists what its claims are proven by, and
claims stop at that evidence. The 61 PRs that sat unreleased between v0.1.13
and v0.1.14 motivated this file; a cut is now owed whenever a flagship evidence
dir lands.

## Unreleased

Everything below is on `main` but uncut. The v0.2 broker work in this
section is **future/experimental/unshipped** per the evaluation ladder's
promotion rule (`docs/runbooks/omux-v0.2-evaluation-ladder-2026-07-14.md`
§12): TIN-2057's golden scorecard is 0/11, no prerelease exists, and
v0.1.15 remains the honest stable release. Nothing here changes shipped
claims.

### Added — stable-lane surfaces (v0.1.16 material)

- `status --statusline` + `recommend` — compact valet render surfaces over
  the pure advisor core (TIN-2719 M0, #461). Contract:
  `claude: <status> → <acct|none> (<provenance>)`, unobserved-honest.
- `version --check [--online]` — offline-default staleness self-audit
  reusing the doctor binary walk; detects PATH shadowing live
  (TIN-2463, #462).

### Added — v0.2 broker program (experimental, unshipped, fail-closed CLI only)

- v0.2 authority chain: full-broker program plan, deletion ledger, threat
  model, authority map, and fail-closed supersedence docs
  (#464, #467, #476).
- Zig-owned release declaration manifest and its consumers: Nix identity,
  stable layout, and workflow versions all derive from the single Zig
  authority (TIN-2046/TIN-2050, #470–#474); `omux` becomes the primary
  executable with `oauth-mux` as compatibility alias (TIN-2799, #469).
- Managed harness JSON-RPC v2 declaration-only schema (TIN-1798, #475) —
  methods declared, none implemented.
- Managed-Claude adapter foundations (TIN-1829/TIN-2047, #477, #478, #480,
  #481, #483, #484, #485): fail-closed child authority + env scrubbing, 256-bit session
  capability carrier, deterministic fake upstream, authenticated loopback
  ingress with fixed-origin enforcement, and synthetic managed child
  lifecycle. `omux claude` now reaches only an explicit unshipped refusal;
  its path into managed-child composition and real upstream forwarding remains
  compile-disabled (`production_forwarding_enabled = false`). #485 repairs
  #484's sequencing defect: the disabled verb now refuses before constructing
  the full inherited launch environment or preparing managed argv/config/binary
  state. It still performs ordinary startup, logging initialization, and CLI
  parsing before that gate. #483 remotely proves one bounded synthetic
  composition of the generated memory-only session capability through the
  managed child environment and real loopback listener against only the
  deterministic fake upstream: missing/wrong carriers stay local, the valid
  carrier makes exactly one fake call, and the client is capped at 16 KiB/5 s.
  It reads no provider credential and makes no provider call. This is a partial
  Stage 2 predicate, not Stage 2 exit, and earns zero TIN-2057 rows.
- v0.2 evaluation and dogfood ladder runbook (TIN-2057, #479) — the
  operator contract for evidence, dogfood, rollback, and claim promotion.
- Pure advisory-usage normalization core (TIN-2400, #486): synthetic-only
  schema validation, freshness/negative-cache semantics, process-lifetime
  schema-drift kill switch, and reactive-evidence precedence. It performs no
  I/O, is not wired to an endpoint or resident service, and earns no Stage 2
  or TIN-2057 credit.
- v0.2 proof-and-candidate authority: source/proof reconciliation docs
  (#487, #490) and CI binding of every v0.2 proof run to an immutable
  candidate — exact commit and tree (TIN-2989, #489) — with named recipes
  `v02-stage1-local` / `v02-stage2-conformance` / `v02-benchmark`.
- Broker handle validation for active v2 and legacy handles
  (TIN-2992, #488).
- Exact-model single-route forwarding against the fake upstream
  (TIN-2400, #491; #492 grafts admission-scope docs and refusal coverage):
  full-document model admission (complete `std.json.Scanner` walk, exactly
  one top-level `model`, typed 400 with zero upstream attempts on
  violation) and incremental streaming (pre-body head forwarding, bounded
  pump, upstream-truncation detection). Observation is first-attempt
  admission only — no result-side model claim.
- Header-stripping observation at the fake upstream (TIN-2400, #493).
- §2.2 single-alternate retry state machine (TIN-2400, #494): two attempts
  total, the single retry slot consumed by either one proven-pre-send
  same-route retry or one distinct-identity alternate; structurally no
  third attempt; 32 MiB request-replay / 64 MiB per-sidecar reservation
  accounting with a one-way stream-once latch. Synthetic seams only; the
  production path remains single-attempt fail-closed.
- Candidate-bound Stage 2 observation emission (TIN-2400, #495 —
  `stage2_observer.zig` value-free facts) and request-counter
  reconciliation (TIN-3003, #497). The initial reduction was 11 pass / 0 fail /
  113 missing. Observer increments for routed wire behavior (#507), advisory
  usage (#508), and flock-owned refresh outcomes (#509), plus the remote
  runtime-dir containment fix (#510), produced the latest accepted exact-candidate
  result: 73 pass / 0 fail / 51 missing on `976fc15`. Later source changes do
  not inherit that packet; current `main` still needs a fresh Stage 2 recut and
  Stage 2 remains incomplete by design.
- Codex resume evidence hardening (TIN-2991, #496, #498): exact structured
  resume evidence and adapter resume preflight evidence are now required.
- Bounded v0.2 prerelease profile (TIN-3005, #499) — a nonpublishing gate;
  no v0.2 prerelease exists.
- Flock-owned refresh outcomes (TIN-2990, #500) — typed refresh-outcome
  model under the flock; earns no Stage 2 predicate.
- Launchd keepalive service environment containment, source only
  (TIN-3024, #501): `env -i` allowlist wrapper (HOME/USER/PATH/NO_COLOR),
  rendered-plist validation, value-free service status, and a synthetic
  containment smoke. A precursor to the R-TIN-1759 sequence — no live
  activation, restart, or rotation is performed; the gate remains closed.
- Bounded all-exhausted terminal, resident-absence invariant, and abrupt
  sidecar-death reclamation (TIN-2400, #502): exactly one typed 429
  carrying the minimum trusted `Retry-After` across exhausted routes
  (malformed values never propagated), comptime plus behavioral proof that
  the wire proxy holds no resident-service hooks, and deinit-mid-request
  reservation reclamation to zero.
- Additional synthetic Claude-sidecar invariants (#504): cancellation and
  overflow release reservations, abrupt teardown converges, and the exact
  admitted model is preserved byte-for-byte on both bounded attempts.
- Advisory-usage observations are wired after route decisions and remain
  inferred, non-authoritative, value-free, and unable to alter routing
  (TIN-2400, #505).
- Provider-neutral attempt-budget algebra (TIN-1790, #506): at most two
  attempts, with the second consumed by either one proven-not-sent same-route
  retry or one pre-body 401/403/429 distinct-account alternate. Provider 5xx,
  ambiguous sends, and started responses never authorize account replay.
- Planning-only `omux setup` and `omux repair` front doors (TIN-3006, #511).
  They inspect redacted metadata and emit plans; provider login, credential
  access, service enablement, and mutation remain deliberately unimplemented.
- Pure exact-model route core (TIN-1790, #512): typed model demand, merged
  reactive/advisory readiness, fail-closed identity conflicts, sticky routing,
  and deterministic least-loaded selection. It performs no adapter I/O and
  advances neither Stage 2 nor the 0/11 golden score.
- Pure serialized in-process lease state (TIN-1790, #513): injected clocks and
  owner observations drive acquire, renew, release, stale cleanup, atomic route
  transitions, exact-model pressure, and deterministic seeded schedule coverage.
  A post-merge adversarial reproduction found that continuous unrelated renewals
  can keep a revision-fenced admission returning `StateChanged`; no admission-
  liveness or no-starvation claim is available until that defect is corrected.
  Cross-process ownership, G4 fairness, adapter consumption, and Stage 2 movement
  remain explicitly unproven.

### Changed / fixed

- Zig test root fails closed on unregistered test files (#468).
- Claude enroll e2e assertion made platform-aware (TIN-2388, #466).
- Retired npm staging residue removed from release surfaces (#465).
- CI mints scoped GF checkout tokens via a dedicated GitHub App
  (TIN-2808, #473).

## v0.1.15 — 2026-07-10 — "valet"

First rungs of the stay-afloat valet ladder: a pure advisor core that ranks
which enrolled account should carry the next unit of work, wired into
`status --json` as an honesty-first advice block, plus the live Claude
capture that corrects the repo's quota-header schema from placeholder to
provider-proven truth. Alongside the advisor, this cut lands a batch of
operator-visibility and safety work: entitlement labels on `accounts list`,
binary version-truth in `doctor`, opt-in keepalive desktop alerts, and
announced/bounded lock waits. Keepalive itself (credential refresh) is
unchanged from v0.1.14 — this release advises and surfaces on top of it, it
does not replace it.

### Added

- `src/quota/advise.zig` — pure valet advisor core (TIN-2719 M0 PR1, #449).
  Given the per-`(provider × account × model-class)` liveness rows the
  HealthStore already persists, ranks which account should carry the next
  unit of work for a declared model demand, with provenance that never
  exceeds what the underlying row proves (`.proven` / `.inferred` /
  `.assumed` / `.unobserved`, never fabricated). No I/O, no clock read, no
  allocation, no net/refresh/secret seam.
- `oauth-mux status --json` advice block (TIN-2719 M0 PR2, #452) — renders
  the advisor's ranking inline with status output. Unobserved-first honesty:
  a model class with no liveness row never gets a fabricated ranking — it
  renders `unobserved`, distinct from a row that was checked and found
  unavailable.
- `anthropic-ratelimit-unified-*` header schema truth (TIN-2722, #448/#453) —
  a live capture against all 5 enrolled Claude accounts corrects
  `provider_schema.zig`'s placeholder `x-ratelimit-*` family to the real
  provider header names, and lands a pure fold over the two-window (5h
  rolling + 7-day) shape with absolute-epoch reset and utilization fraction.
  Claude model-class `CapabilityDefinition`s (opus/fable/sonnet/haiku) land
  on the real model ids observed live.
- `docs/spec/model-quota-granularity-2026-07-03.md` E1 experiment runbook
  (TIN-2721, #447) — the managed hot-swap experiment design; not yet an
  implemented experiment.
- `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md` valet
  ladder design of record (#450) — M0→M3 rung definitions for the advisor
  work above.
- Notification-delivery survey + statusline advice-block consumer docs
  (TIN-2061/TIN-2719, #451).
- Tracker/ledger truth batch: valet ladder rows, TIN-1830 close/split,
  #176 reconcile (#446).
- `oauth-mux accounts list` entitlement labels (TIN-2719, #456) — each Claude
  row surfaces its `subscription_type` / `rate_limit_tier`, each Codex row its
  `plan_type`, distilled from the stored credential blob. Read-only inventory:
  keychain is admitted (Claude's normal liveness path is keychain-backed) but a
  denied or locked read degrades to `null` rather than prompting, and
  sops/age/command/stdin backends are never invoked just to decorate a row. A
  no-token-leak invariant is test-enforced against a synthetic blob.
- `oauth-mux doctor` binary version-truth (TIN-2723, #455) — surfaces the
  resident-service binary's version/SHA against the PATH-winner, warns on a
  stale binary, and detects a shadowed install, so the operator can see which
  build is actually running the keepalive service.
- Keepalive desktop alerts, opt-in (TIN-2061, #458) — a notification seam
  (`osascript` on macOS / `notify-send` on Linux, a subprocess mirroring the
  `security(1)` pattern) that fires on refresh-failure / credential-dead only.
  Disabled by default; a min-interval dedupe throttles repeats; a watchdog
  SIGKILLs a hung notifier so it can never stall the keepalive tick.
- Lock-wait UX (TIN-2049, #457) — lock acquisition now announces the wait,
  bounds it, and names the contended lock on timeout, replacing silent blocks.

### Housekeeping

- Docs/evidence-only, merged the same day as v0.1.14 but not previously
  captured in a changelog entry: install-lane and adoption docs grounded to
  v0.1.14 reality (#442), README tightened for front-door concision (#443),
  and `docs/evidence/keepalive-service-residency-20260704T161515Z/` — a live
  launchd install rotating all 5 opted-in Claude accounts on first tick,
  surviving a kill/respawn cycle with `ThrottleInterval` honored (#444). No
  new claims beyond v0.1.14's keepalive scope.

### Evidence (what this release's claims are proven by)

- `test/evidence/quota-observation/claude-20260709T220705Z/` — live capture
  against all 5 enrolled Claude accounts (xoxd, sulliwood, columbari, coye,
  lmux), redacted, with a committed spend ledger
  (`SPEND-LEDGER.txt`: 5 × haiku 200s ≈ 130 output tokens total, every other
  probe a zero-spend 4xx). Proves the `anthropic-ratelimit-unified-*` header
  family, the 5h/7d two-window shape, and the 404-vs-429 status distinction
  on real traffic. Also proves the caveat this release does NOT claim past:
  a direct-probe 429 on fable/opus is a probe-path artifact (`overage`
  gating), not observed harness quota — advisor rendering for those classes
  stays `unobserved` until the harness-traffic or browser channel lands.
- `src/quota/advise_tests.zig` (A1–A6 property surface) — same-input
  determinism and permutation invariance, provenance-never-exceeds-input,
  all-unobserved-with-null-suggestion on empty input, i64-extreme no-panic,
  excluded/degraded-credential exclusion, and a negative control proving the
  order-invariance property actually fails when the reducer is broken.
- `src/quota/bucket_tests.zig` (P1–P8 property surface, still holding) —
  replay/snapshot idempotence, order-independence including equal-`at`
  collisions, quota-never-kills-credential (disjoint folds), monotone
  recovery at `resets_at`, warm-loop independence, no-clock/refresh/net
  seam, and total/saturating behavior at i64/u32 extremes.

### Honest bounds

Credential keepalive proven (unchanged since v0.1.14). Advice renders
per-model classes `unobserved` until a per-model signal exists for that
class — this release does not claim per-model quota knowledge it hasn't
observed. Managed hot-swap is NOT shipped (TIN-2721 experiment pending, design
only). No model-quota keepalive claim (TIN-2400 boundary holds: quota windows
reset on the provider's clock; keepalive keeps credentials fresh, it does not
create capacity). Per-model signal is gated on a harness-wire or browser
channel that does not exist yet — direct API probing cannot observe it (see
evidence caveat above). Alerting (TIN-2061) and usage export (TIN-2062)
remain open.

## v0.1.14 — 2026-07-04 — "keepalive"

First packaged release of credential keepalive: the warm loop that proactively
refreshes enrolled accounts before their tokens expire, so harness sessions see
never-expiring credentials. Everything below was already on `main`; this cut
makes it installable.

### Added

- `oauth-mux keepalive [--once] [--iterations N] [--interval-ms MS] [--json]` —
  proactive per-account credential refresh at ~75% token lifetime. Consent-gated
  per account (`allow_proactive_refresh`, default `false`) and grant-gated per
  provider; a fresh install warms nothing until the operator opts accounts in
  (#417, #418).
- Safety rails around the warm loop: shared-identity exclusion (two config
  entries backed by one OAuth identity are refused — single-use refresh-token
  family protection) with first-refresh stagger (#419, #435); broker identity
  dedupe before election so a duplicate slot is never counted as failover
  capacity (#431); an in-process actor gate on the repair-lock registry so a
  warm tick and a live session can never double-spend one refresh token (#430).
- launchd / systemd-user service unit templates with an operator-explicit
  install lane — `just keepalive-service-install|uninstall|status|verify`.
  Nothing installs or enables automatically (#433).
- Isolated-browser Claude login helpers (`scripts/claude-isolated-browser.sh` +
  `claude-open-shim/`) — a fresh browser profile per account login, preventing
  the shared-session bleed observed live during multi-account enrollment (#438).
- Pure quota-bucket core (`src/quota/bucket.zig`, #439) — substrate for the
  model-quota-granularity design (`docs/spec/model-quota-granularity-2026-07-03.md`);
  property-tested, not yet consumed by production paths.
- Delivery gates: `just endpoint-free-check` + `just secrets-scan-dir` (#429),
  Bzlmod-only Bazel posture + repo manifest (#426), PR-scoped CI concurrency
  (#434).

### Fixed

- Keepalive wait hardening: bounded sleep arithmetic against far-future wake
  sentinels, extracted pure and unit-tested (#438). The v0.1.13 binary could
  panic on the keepalive idle path; v0.1.14 cannot.

### Evidence (what this release's claims are proven by)

- `docs/evidence/keepalive-warm-loop-20260702T214211Z/` — refused-safely tick:
  every consent/identity gate firing, zero mutation without opt-in.
- `docs/evidence/keepalive-warm-loop-20260703T171242Z/` — 5-account isolated
  Claude fleet admission + bounded stability soak.
- `docs/evidence/keepalive-rotation-soak-20260703T213916Z/` — proactive rotation
  firing inside the running loop (2 accounts refreshed on the scheduler tick).

### Honest bounds

Credential keepalive only. Not claimed by this release: model/quota-class
keepalive (design of record only), the 2×Claude + 2×Codex golden-metric soak
(TIN-2057, open), live service-residency proof (TIN-1830, open). Quota windows
reset on the provider's clock; keepalive keeps credentials fresh — it does not
create capacity.

## v0.1.13 — 2026-06-12

Home-is-store managed-Codex session authority (canonical bridge opt-in), flock
unlink-on-release race fix + macOS runtime-dir move, default-mode native resume
chooser, corrected Claude OAuth endpoint constants. Pre-dates the `keepalive`
command. npm lane retired as of this release.
