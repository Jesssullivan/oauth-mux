# Changelog

Release discipline (adopted 2026-07-04): cuts are bound to committed evidence
under `docs/evidence/` — every release lists what its claims are proven by, and
claims stop at that evidence. The 61 PRs that sat unreleased between v0.1.13
and v0.1.14 motivated this file; a cut is now owed whenever a flagship evidence
dir lands.

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
