# Changelog

Release discipline (adopted 2026-07-04): cuts are bound to committed evidence
under `docs/evidence/` — every release lists what its claims are proven by, and
claims stop at that evidence. The 61 PRs that sat unreleased between v0.1.13
and v0.1.14 motivated this file; a cut is now owed whenever a flagship evidence
dir lands.

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
