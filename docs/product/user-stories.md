# Omux user journeys and acceptance

Status: **desired acceptance for the experimental, unshipped native reset**.
Recorded 2026-10-02; adapter ownership and installed lifecycle clarified 2026-10-05.
The [charter](charter.md) describes the outcome;
the [active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
owns architecture. These journeys make that outcome reviewable without asserting
new policy or shipped support. Acceptance IDs are stable tracker references;
their presence or a completed tracker item is not proof.

## People and compatibility

A contractor uses independently verified client, startup and personal accounts
while continuing an ordinary terminal session. A scientist uses institutional,
research and home accounts while working with model calls, uploads and repository
access. These are examples of one person's multiple identities, not authorization
classes. Renaming an account "research" or "client" never proves ownership,
scope, organization access or compatibility. Technically compatible accounts are
eligible by default; an explicit supported policy can narrow eligibility. No
persona-based policy crossover or additional organizational isolation rule is
ratified by these examples.

Each journey below states desired acceptance. The evidence column names current
source or local predicates and the missing gate. The
[reset evidence](../implementation/native-reset-evidence-2026-10-02.md) and
[safety evidence](../implementation/native-safety-evidence-2026-10-03.md),
[saved evening evidence](../implementation/native-evening-evidence-2026-10-03.md)
and [current admission evidence](../implementation/native-admission-evidence-2026-10-04.md),
with [installed native interoperability evidence](../implementation/native-interop-evidence-2026-10-04.md),
own receipts and exact limits; this file creates no new execution receipt.

## Install, authorize and use normally

| ID | Journey and desired acceptance | Current evidence and remaining gate |
| --- | --- | --- |
| US-INSTALL-01 | The user installs the per-user daemon and a thin control client on Linux or macOS, then completes reversible native integration setup. Setup reports the exact application/version capability and preserves native configuration, history and session stores in place. Closing the control client leaves the daemon running. | Private Linux archive installation/relocation, production daemon/CLI/offscreen Qt and genuine isolated Secret Service predicates passed locally and on Sting. Private macOS Keychain driver compilation/IO passed. Installed services, real desktop sessions, clean-machine delivery and production SwiftUI/daemon behavior require separate receipts. |
| US-SOURCE-01 | The contractor authorizes each intended account source once. Discovery automatically enrolls independently verified identities within that authorization, deduplicates verified identity evidence and quarantines ambiguous candidates. A source label or copied native account hint cannot activate a grant. | `source.connect`, reconciliation and provider identity verification paths exist in `src/engine.zig`; discovery/domain/engine fixtures establish bounded predicates. Real provider enrollment and full provider-owned enrollment flows remain unproved. |
| US-IDENTITY-01 | The scientist sees separate account, grant, entitlement, resource and readiness state for institutional and home identities. Only grants compatible with issuer/provider, audience, purpose, scopes, resource and native boundary can substitute. A home account does not gain access to an institutional repository because both belong to the same person. | Distinct domain types, admission checks and redacted snapshots exist. Fixtures cover compatibility; exact provider and native application evaluation remains required. |
| US-LAUNCH-01 | After setup, the user launches the ordinary native terminal command, uses its native session and later resumes that session normally. No Omux wrapper or alternate application home is required. Omux develops the application auth adapter and establishes its delivery and version compatibility. | Codex has a version-bound experimental Omux integration candidate; unmodified Codex support is unproved and `native_support` remains false. Ordinary launch and native resume against real accounts are unrun. |
| US-ATTACH-01 | A user already working in a terminal discovers and attaches a running process only when its exact native hook permits attachment. Idle, portable native state and attachment authority are verified. Unsupported versions or account-bound state explain the missing capability without presenting restart or interception as continuity. | The owner-V2 candidate has authenticated capability/thread inspection and owner admission paths. The installed app-server checkpoint proves configured registration with initialized zero-turn history; it does not prove automatic discovery or late attachment. Existing-process live attachment is unrun; account-bound reasoning, uploads or compaction can prevent safe attachment. |
| US-BROWSER-01 | The user can optionally authorize a narrow Chromium/Firefox conduit for a declared provider. Only declared fields and context metadata are acquired; identity verification precedes binding. Browser read permission never becomes API-call permission. Browser-bound authority reports `browser_required` when its context is absent. | Transport, native messaging and packaging exist. Production Codex, Claude and GitHub cookie/storage exports are disabled pending exact provider schema and identity proof; fixture acquisition is not a production option. Browser automation is outside the product. |

## Installed lifecycle and development

Chromium leads installation acceptance before provider enrollment, renewal,
ordinary launch/resume and handoff. These additional requirements describe the
installed product and development path, without creating execution receipts.

| ID | Journey and desired acceptance | Carrier and remaining gate |
| --- | --- | --- |
| US-SETUP-01 | Native UI onboarding and CLI invoke shared setup operations and independently report artifact installation, service activation, vault, browser source, identity, usable grant and application capability. Home Manager owns fleet packages, services and exact-ID native-host manifests. Setup recognizes managed files and guides declarative changes. | TIN-2063; installed UI/CLI equivalence and declarative ownership receipts required. |
| US-BROWSER-CONTEXT-01 | The user connects a selected Chromium context, sees persistent connection and identity/grant status, restarts the browser and reconnects without widening permission. Consent explains automatic enrollment of subsequently verified identities. Disconnect removes acquisition authority and secrets retained through that context while preserving independent grants/history. | TIN-2720; installed browser consent/restart/reconnect/context-specific disconnect required. |
| US-DEV-01 | The developer builds and stages through one serialized Bazel entry point, manually reloads Chromium and explicitly restarts the development daemon. Development and release have separate extension IDs, hosts, services, paths, sockets, databases and vault namespaces, with no shared renewal writer. | TIN-2063; actual staged-component provenance and coexistence receipts required. |
| US-UPDATE-01 | The user reviews compatibility and applies guided explicit core updates through declarative deployment. Managed files are preserved; failed activation has an ownership-safe recovery path. Nix generation rollback never restores spent credentials, old tombstones or replay authority. | TIN-2063; installed update/refusal/rollback receipts required. |
| US-KEY-LOSS-01 | After permanent key loss, the user can preserve the failed installation and explicitly start fresh enrollment into separate custody. Omux never generates a replacement key over the existing database or silently reconnects failed custody. | TIN-2063; installed permanent-loss and separate-custody recovery receipts required. |

## Continue through account and resource changes

| ID | Journey and desired acceptance | Current evidence and remaining gate |
| --- | --- | --- |
| US-HANDOFF-01 | A contractor's active compatible account reaches a proven pre-acceptance auth, entitlement or quota failure. At a verified safe boundary, Omux selects a compatible alternative without a routine prompt, keeps the same application process and preserves native transcript, session, tools and approval authority. The active route stays sticky while eligible. | Route/lease predicates and Codex hook fixtures exist. No live same-process handoff is proved; warming metadata and synthetic admission do not satisfy this acceptance. |
| US-NOREPLAY-01 | An accepted response fails after streaming begins, or an accepted tool has already executed. Omux reports the bounded failure and preserves native authority; it never repeats that tool or replays the accepted stream to manufacture a successful handoff. Unsafe account-bound state blocks substitution until an explicitly supported repair boundary exists. | Native acceptance/reporting and candidate safety fixtures exist. Live accepted-stream/tool behavior remains unrun; speculative mid-stream recovery is deferred. |
| US-RESOURCE-01 | The scientist exhausts a calls, bytes, uploads, duration, rate or provider-defined capacity window. Alternatives must satisfy that exact demand. Grouped totals combine only compatible units, scopes and windows; two grants sharing a quota bucket count once. No remaining compatible route produces a visible bounded failure or provider-required repair. | Generic demand, observations, aggregation and typed cooldown source exist with local predicates. Real capacity reads, provider exhaustion and live alternate admission remain unrun. |
| US-FRESHNESS-01 | An account has no quota observation, or its observation becomes stale. Controls show unknown/incomplete state, provenance and freshness instead of invented capacity. Unknown capacity alone does not establish exhaustion, while unknown grant or local readiness is never shown as ready. Routing uses applicable eligibility evidence without treating a stale total as a promise. | Observer, aggregate and snapshot source and fixtures exist. Real provider freshness behavior and user-facing installed-client evaluation remain unproved. |
| US-LOCAL-ADMISSION-01 | The user has healthy custody and a compatible ready grant, but the complete persisted metadata and reserved future outcomes cannot fit. Omux reports local admission refusal separately from provider quota. Remaining request/mutation partition space does not establish whole-snapshot headroom. Previously admitted terminal outcomes remain completable in their reserved space; freed space never replenishes the request's original attempt budget. | Whole-snapshot admission/completion requires its own source-bound actor, SQLite and restart receipts. Installed-client, native and provider behavior require separate gates; this acceptance does not promote them. |
| US-MISMATCH-01 | A discovered alternate has the wrong provider, audience, scope, purpose, resource units or native substitution capability. Omux rejects it even if its label, balance or persona looks suitable. A mismatched source cannot poison another account's valid route. | Engine/application demand guards and domain compatibility fixtures exist. Provider/application conformance must establish each supported combination. |
| US-RENEWAL-01 | A native application still owns renewal of an imported grant. Omux does not rotate that refresh lineage merely because import succeeded. Adoption requires independently verified identity and transfer authority with one renewal writer; external rotation or uncertain crash recovery quarantines ambiguity instead of retrying a spent token. Repair may require provider authentication. | Imported access grants are externally owned. Custody/rotation fixtures establish local invariants; refresh adoption, ownership transfer and provider renewal require completed implementation and version-bound evaluation. |

## Change sources, repair and return deliberately

| ID | Journey and desired acceptance | Current evidence and remaining gate |
| --- | --- | --- |
| US-DETACH-01 | A native source disappears or a browser closes. Source detachment retains history and independently valid grants; exportable authority may remain usable within its validity/custody limits. Context-bound authority becomes unavailable when its browser context is absent. Source disappearance is not account forget or upstream revoke. | Discovery detachment and retained-state predicates exist. Real native/browser source transitions remain unrun; disabled production browser exports cannot establish exportable authority. |
| US-DISCONNECT-01 | The user explicitly disconnects a source, ending its acquisition authorization. Controls explain that this invalidates grants retained through that source and deletes their retained secrets. Other independently valid sources/grants and account history retain their own authority. Disconnect does not claim upstream revocation. | `source.disconnect` in `src/control.zig` and `src/engine.zig` retains invalid grant metadata while deleting source-grant ciphertext. In-flight authority prevents unsafe removal. Installed-client/provider transition evaluation remains unrun. |
| US-PAUSE-01 | The user pauses an account to prevent new selection, or drains it so existing accepted bindings can finish without new leases. Resume restores eligibility only if the account's independent grant/readiness/resource checks permit it. Neither action claims deletion or upstream revoke. | Distinct pause/resume/drain operations and lifecycle predicates exist. Live in-flight application behavior remains unrun. |
| US-FORGET-01 | The user forgets a retained account. A successful atomic commit removes its retained secrets, leaves a tombstone for each associated source and records durable completion. If local admission refuses that expansion, retained secrets and previous tombstones remain intact and the user sees that erasure did not complete. Periodic discovery, daemon restart or the same source reappearing cannot silently re-enroll a forgotten identity. History and deletion effects must be described explicitly; local forget does not claim provider revocation. | Forget and durable tombstone source/fixtures exist. Whole-snapshot refusal and reserved-completion predicates require their own receipts. Real custody deletion and installed lifecycle evaluation remain required; upstream revocation is incomplete. |
| US-REENROLL-01 | The user deliberately returns a forgotten identity through an authorized acquisition path. Only explicit authorized re-enrollment followed by independent provider identity verification clears the applicable tombstone. An unverified hint, routine reconciliation or failed verification leaves it intact. | Adapter import's `allow_reenrollment` path applies permission after identity proof; routine reconciliation supplies false. This is not a public control re-enrollment command or a completed provider enrollment UI. Live verification remains unrun. |
| US-VAULT-01 | Startup cannot obtain authorized vault custody for an existing database. The user sees a repair condition. After normal platform unlock, a retained `Locked` condition permits explicit local `custody.reopen` in the same daemon. Unloaded account metadata has an unknown count; retained lock diagnostics do not assert the current OS-vault state. Omux never writes plaintext or regenerates a replacement key over the database; repair cannot resurrect expired or spent credentials. | Explicit same-actor custody retry and nullable unloaded account count are implemented source. Encrypted custody and fake-vault loss/lock/error predicates exist. Genuine isolated Linux Secret Service and private macOS Keychain driver IO passed; the new retry's validation, personal-session locked-vault existing-DB recovery and production Darwin runtime require separate receipts. |
| US-OUTAGE-01 | The daemon becomes unavailable while the user has native work open. Controls report the outage, reconnect with a fresh revisioned snapshot and avoid automatically replaying mutations. Recovery preserves already-admitted terminal-outcome authority under local metadata pressure without resetting request attempt limits. No lease is invented, no accepted work is repeated and no application restart is represented as transparent repair. Continued routing waits for valid daemon/native authority. | Local transport/reconnect, durable request/mutation fences and isolated installed production-daemon restart/lost-reply recovery passed. Whole-snapshot completion/recovery needs its own receipts. Live daemon crash/recovery with native applications and provider authorization remains unrun. |
| US-REPAIR-01 | The user requests repair and sees whether authorized sources are reconciling, a verified retained grant is ready, or provider action is needed. A `needs_user` job is visibly unfinished. Repair never restores a stale refresh token or silently widens source permissions. Account repair cannot compact/reset durable replay authority, reset attempts or clear tombstones to remedy local metadata saturation. | `repair.start` source reconciles authorized sources and reports concrete readiness/action. Complete provider-owned repair and real provider execution remain unproved. |

## Remove integration and uninstall

| ID | Journey and desired acceptance | Current evidence and remaining gate |
| --- | --- | --- |
| US-REMOVE-01 | The user removes an integration while native work exists. Omux restores only settings it owns and requires a verified safe detach before relinquishing reachable native threads. A failed detach reports pending removal while custody remains available; it does not discard credentials or alter native history to appear finished. | Fresh installed checkpoint `4b0fcf36` proved zero-acquire removal in the configured candidate app-server, preserving the same process and initialized zero-turn history, restoring configuration and retiring original custody. Accepted-work, ordinary CLI/resume and live detach/removal remain separate unproved gates. |
| US-UNINSTALL-01 | The user explicitly uninstalls Omux with a clear retained-data or erasure choice. Services, owned integration settings and browser registrations are removed/restored according to ownership receipts. Native stores remain in place. Closing a client is not uninstall, and local erasure is not upstream revocation. | Packaging, owned-setting/registration restoration and uninstall foundations have local predicates. Clean-machine installed uninstall, real vault cleanup and both platform delivery gates remain unrun. |

## Application scope and proof needed to close a journey

Codex is the first native integration proof target. The candidate is bound to
official `rust-v0.157.0`, commit
`00c972ed5d6ff6499317fd41b7f23605b8e6850d`. Omux develops this integration;
its distribution mechanism remains to be established, and unmodified Codex
support remains unproved. There is no vendor-supplied Omux-hook dependency.
Candidate compilation and focused Rust/protocol
fixtures establish only recorded predicates. Claude currently has configuration
foundations, not a proved native handoff integration. Git HTTPS/GitHub uses a
scoped native credential helper: verified username and repository context govern
selection; correlated erase cools down that context without forgetting the
account. Helper fixtures do not establish live provider continuity or replay
safety for a Git operation. OpenCode is deferred, with no support claim.

Closing a continuity acceptance requires exact application/version/commit,
ordinary native launch and resume, the applicable verified attachment boundary,
real failure and compatible alternate admission, unchanged process, preserved
native session/history/tools/approvals and no routine handoff prompt. Evidence
must show no accepted-stream replay or repeated tool execution and retain only
redacted metadata/opaque handles. Source implementation, local fixtures, native
conformance and live-provider proof are separate classifications. Historical
release evidence cannot close successor acceptance; unrun gates stay unrun.
