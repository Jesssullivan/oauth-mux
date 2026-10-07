# Support and completeness

Status: **acceptance definitions for the experimental, unshipped native reset**,
2026-10-02, clarified 2026-10-05. These definitions apply the [charter](charter.md) and
[active reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md).
They do not promote the successor, amend historical release evidence, promise
response times or establish a contractual support service.

## Terms and claim scope

| Term | Required meaning |
| --- | --- |
| Installed | A verified, identified artifact has been placed at its intended per-user location with an ownership record. Installation alone does not mean that a service is active, custody is available, an account is enrolled or an application is supported. |
| Enrolled | An authorized source yielded an independently verified identity and a grant with known audience, purpose, scope, validity and custody authority. Ambiguous candidates remain quarantined. Source authorization and native login alone do not prove usable Omux authorization or transfer renewal ownership. |
| Usable | For an exact operation, the daemon, native integration, compatible authorization and durable local admission/completion headroom are ready, or an explicit supported enrollment/repair action can establish the required readiness. Healthy custody and provider quota do not establish local metadata admission. A pending or `needs_user` job is not completed readiness; unknown capacity remains unknown. |
| Supported | A named platform, application version/commit, native hook, provider, credential operation and resource scope has passed its applicable installed and live gates, with published limits. The word does not imply arbitrary applications, credentials or account substitution. |
| Complete | All required acceptance gates for an explicitly bounded release scope are satisfied, evidence is committed and generated claims agree with implementation. A component can be implemented while the product outcome remains incomplete. Deferred scopes remain named, not silently included. |

Support is a tuple, not a platform or adapter checkbox. Record OS release and
architecture; artifact revision/digest and execution inputs; application
version/commit and hook version; provider/account type and entitlement; source
kind; credential form, audience, scopes, expiry and renewal owner; operation and
resource units/window; ordinary launch/resume/attachment mode; and known unsafe
state. Calls, bytes, uploads, duration, rates and provider-specific capacity each
need compatible semantics. Shared quota buckets never multiply capacity.

An access-token request proof does not prove refresh adoption, API-key scope,
browser-bound signing, upstream revocation, uploads or every application tool.
Passwords, OTPs, passkeys and security keys are enrollment factors, not grants.

## Evidence and release labels

| Evidence class | What it establishes | What it cannot establish |
| --- | --- | --- |
| Declaration | A schema, catalog or planned capability names a contract. | Implementation or provider/native compatibility. |
| Candidate | Reviewable version-bound source or patch with provenance. | Stock application support or a shipped fork. |
| Fixture / synthetic | Executed local predicates using isolated data or fake peers/providers. | Real vault custody, installed services, real provider acceptance or same-process handoff. |
| Local installation / relocation | A particular artifact installs or executes in recorded local conditions. Record ownership, service and environment limits separately. | A clean-machine install, other desktops/platforms or live continuity. |
| Live continuity | Exact native build and provider evidence satisfies the applicable ordinary-launch, resume, handoff and state-preservation gates below. | Untested versions, credentials, ancillary operations or historical evidence inheritance. |

**Experimental** permits explicit incomplete implementations and bounded local
evaluation, with missing capabilities visible. This is the successor's current
label. **Beta** requires a named, published scope with completed installed and
live outcome gates and remaining limitations disclosed; it is not earned by
test counts. **GA** requires all mandatory gates for that release scope,
reviewed release artifacts and truthful delivery/removal documentation. Neither
beta nor GA is claimed here. These are promotion criteria, not a promise of
availability, timelines or an SLA.

Omux owns each application's authentication integration contract and adapter.
Adapter delivery may use a sufficient extension API, upstream contribution or
maintained modification; waiting for a vendor-supplied Omux hook is not a product
dependency. Exact delivery/version evidence remains mandatory. The present
candidate does not establish support for unmodified Codex or a shipped maintained
distribution. Installed Chromium leads acceptance, followed by verified usable
authority, renewal, ordinary native launch/resume and seamless handoff.

## Current dimensions and limits

The [reset evidence record](../implementation/native-reset-evidence-2026-10-02.md)
and [safety evidence](../implementation/native-safety-evidence-2026-10-03.md),
[saved evening evidence](../implementation/native-evening-evidence-2026-10-03.md)
and [current admission evidence](../implementation/native-admission-evidence-2026-10-04.md),
with [installed native interoperability evidence](../implementation/native-interop-evidence-2026-10-04.md),
own execution receipts. The reset's 37 passing project test targets and 66 build
targets retain their original scope; the later safety graph has its own receipts.
Neither test count establishes platform or live application support. Current
admission foundation passed its seven stated gates at its recorded source epoch,
including 66 local tests and isolated installed Sting custody. The completed
[owner sprint](../plans/omux-native-owner-sprint-2026-10-04.md) retains its own
protocol and ownership receipts. The later installed interoperability checkpoint
has a separate exact runtime pair and bounded result; no live receipt is inherited.

| Dimension | Current evidence and promotion gap |
| --- | --- |
| Linux x86_64 delivery / Qt6 | Actual experimental archive relocated and installed in isolated local conditions; genuine private Secret Service, production daemon restart, CLI lost-reply recovery and actual offscreen Qt socket/state requests passed their recorded predicates. Clean-machine installation, personal-session custody, service activation and interactive X11/Wayland/tray behavior remain unproved. Host fonts/XKB and the service-manager boundary remain explicit dependencies. |
| macOS / SwiftUI | Experimental bundle minimum is macOS 14.0, matching the locked runtime closure. The private macOS Keychain C driver compiled against the declared SDK and passed genuine isolated IO; that receipt does not establish the application archive. Sources and bundle/Mach-O policy fixtures exist. Neo is for teletype/source inspection. PZM is the declared operator-configured REAPI compiler route, currently GF-held; preceding coordinator closure and declared-input analysis receipts establish neither PZM registration nor selected-worker execution. The earlier Neo archive caller was interrupted, with remote workspace disposition unknown; local SSH absence does not prove remote cleanup. No production SwiftUI archive or installed application proof is established. Signing/notarization as applicable, installed production-daemon custody, launchd/SMAppService behavior and menu-bar operation require their own receipts. Linux fixtures do not establish them. |
| Codex | Omux-developed candidate targets official `rust-v0.157.0`, commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`; compilation and focused native fixtures passed. Separate owner-V2 installed checkpoint `4b0fcf36` proved configured app-server registration, initialized zero-turn history preservation and zero-acquire removal on the recorded exact pair. Automatic discovery, ordinary CLI/TUI launch/resume, accepted history, daemon replacement and live provider handoff remain unproved. `native_support: false`; promotion requires completed adapter delivery and live evidence. No maintained Codex distribution is shipped today; the candidate does not establish unmodified Codex support. Opaque account-bound state and outstanding ancillary authorization can prevent attachment/handoff. |
| Claude Code | Reversible configuration foundation exists. Authenticated request proxy and native continuity are not implemented/proved; setup must reject unproved activation. Existing-process attachment requires a native hook. |
| Git HTTPS / GitHub | Native credential-helper boundary is implemented for declared GitHub HTTPS contexts, with scoped materialization and rejection fixtures. Real remote permissions and live recovery remain unproved. Helper boundaries do not authorize replay of an accepted request/upload; SSH and arbitrary hosts are outside this claim. |
| Optional Chromium / Firefox | Transport, unsigned packaging and host-registration fixtures exist. Production Codex/Claude/GitHub provider export is disabled pending exact acquisition schema and identity evidence. Live browser installation/import and signing remain separate gates. No browser automation. |
| Credential operations | Encrypted custody, discovery, durable request/mutation fencing and SQLite-only rollback predicates have local evidence. Isolated real Linux and private macOS vault driver IO passed; production Darwin runtime custody and live provider verification remain separate gates. Refresh adoption/renewal ownership transfer and upstream revocation remain incomplete. Browser-bound authority must remain browser-bound. |
| Deferred | OpenCode has no supported adapter claim. Cross-host federation, Windows, Safari, arbitrary providers and speculative mid-stream recovery remain deferred. npm distribution remains retired. |

## Acceptable user lifecycle and promotion gates

The IDs below name reviewable acceptance obligations, not existing passing tests.
Each receipt must identify the exact tuple above, command/declared action,
environment, date, observed result and limits, while excluding secrets and PII.
All project execution uses Bazel/Bazelisk through locked Nix inputs, locally by
default. Zig is pinned to the reset's verified official 0.17.0 release. No
automatic CI, wrapper, browser automation or remote proof is required by these
definitions.

| ID | Required observable behavior |
| --- | --- |
| SC-01 Install and preflight | Verify artifact contents, revision, digest and platform compatibility before writes. Report vault availability, daemon/socket readiness, native hook/version and optional browser status independently. Reject unowned/modified targets, preserve native stores and explain unavailable capabilities. No plaintext custody fallback or replacement key over an existing database. |
| SC-02 Resident service | Install and explicitly activate the per-user userspace daemon through the platform boundary. Verify private sockets/peer checks, login-session lifecycle and persistence. Closing CLI/Qt/SwiftUI controls leaves it running. Optional browser closure has the documented effect for exportable versus browser-bound grants. |
| SC-03 Enrollment | Authorize the source once; verify identity and adoption authority before activation. Automatically enroll verified identities within authorized scope, quarantine ambiguity and enforce tombstones. Keep native stores in place; do not collect factors in control clients or expose secrets in diagnostics. |
| SC-04 Ordinary launch and resume | After reversible native setup, ordinary application commands and native resume use the integration without an Omux launch wrapper, alternate home or relaunch. Show unsupported stock versions honestly. Record native session/history identity before and after. |
| SC-05 Existing-process attachment | Attach an already-running native process only through a verified hook and safe context. Prove late registration and bounded failure for unsupported, active, opaque or outstanding-auth contexts; attachment is independently claimed from future-launch setup. |
| SC-06 Live handoff | Observe a real provider-originated pre-acceptance auth/quota/entitlement rejection and compatible alternate admission before routine native error/prompt. Preserve application process identity, native session/transcript, tools and approvals. Record concurrency isolation and credential-generation/transport reset. No restart, accepted-stream replay, repeated tool execution or synthetic exhaustion substitutes for this gate. |
| SC-07 Status and capacity | Expose redacted handles, capability/version, independent lifecycle/grant/entitlement/readiness states, active routes and observation provenance/age. Distinguish durable local admission/completion headroom from provider quota and healthy custody; positive request/mutation partition space alone cannot prove whole-snapshot admission. Display stale, missing and clock-mismatched data honestly. Aggregate only compatible units/scopes/windows and deduplicate buckets. Status does not acquire authorization or fabricate provider usage. |
| SC-08 Repair and custody | Distinguish locked vault, expired grant, missing hook, verification pending, local metadata admission refusal and provider-required user action. Reconcile authorized sources without silently transferring refresh ownership, retrying ambiguous rotation or replaying uncertain mutations. Account repair cannot compact/reset durable replay authority or clear tombstones to free space. Verify encrypted persistence/journals, restart recovery, single renewal writer and bounded failures against actual platform/provider operations. |
| SC-09 Upgrade | Validate the replacement artifact and existing ownership before writes; preserve database/vault/native state and restore prior owned contents on failed installation. Prove transactional migration and compatible API/native-hook negotiation. Do not infer uninterrupted live upgrade continuity from rollback fixtures. |
| SC-10 Disconnect and remove | Safe native detach/restoration is distinct from service stop and owned-file uninstall. Preserve independently valid grants/history on source detachment; distinguish pause, drain, forget/tombstone and explicit upstream revoke. A successful forget commits secret deletion, every applicable source tombstone and its durable completion atomically; admission refusal leaves retained secrets and previous tombstones intact. Preserve user-modified files and native sessions; retain database/vault unless explicit secret removal is requested. Verify service shutdown and restored native settings on the actual platform. |
| SC-11 Release reconciliation | Bind committed receipts to clean stamped artifacts, declared tool/platform inputs and published capability limits; complete applicable signing/install/distribution gates. Generated API/CLI/capability/release facts must match source and evidence. The separate documentation SPA cannot create support authority. |
| SC-12 Shared declarative setup | Native UI and CLI use shared setup operations with independent installation, service, vault, source, identity, usable-grant and adapter-capability results. Home Manager owns fleet packages, service definitions and exact-ID native-host registration. Recognize managed files, guide declarative changes and prove interruption recovery without overwriting declarative ownership. |
| SC-13 Installed browser context | Load actual Chromium extension and native messaging artifacts; authorize the selected context, explain subsequent verified-identity enrollment, show persistent status and prove browser restart/reconnect. Explicit Disconnect affects that context's acquisition authority and retained secrets; independent grants/history survive. Host absence, incompatible versions, revoked permissions and lost replies have bounded visible outcomes. |
| SC-14 Isolated development loop | Prove serialized Bazel build/stage of actual daemon, native host, CLI, UI and extension with provenance. Use stable separate development extension/host/service identities, paths, sockets, database and vault namespace. Manual Chromium reload and explicit daemon restart are documented and observed. Development and release coexist without shared custody or renewal writers. |
| SC-15 Update and permanent key loss | Guide explicit core updates through declarative deployment, check compatibility before activation and prove ownership-safe refusal/recovery. Generation rollback preserves monotonic credential generations, tombstones and replay authority. Permanent vault-key loss preserves failed installation and offers explicit fresh enrollment into separate custody; never replace the key over its existing database. |

Platform delivery promotion requires SC-01, SC-02, SC-07 through SC-12 and SC-15 for
that platform. Adapter continuity promotion additionally requires SC-03, SC-04
and SC-06; SC-05 is mandatory before claiming existing-process attachment.
Credential operations and browser imports require their own SC-03/SC-08 receipts
and the applicable adapter live gate; browser delivery additionally requires SC-13.
Development-lane readiness requires SC-14, independently from release
promotion. Any excluded operation must stay visibly
unsupported. Product completeness requires these gates across the expressly
selected release scope; passing one tuple cannot promote the rest.

Under local metadata pressure, already-admitted terminal outcomes must remain
completable using their reserved durable space. Releasing unused completion
space cannot replenish a request's original attempt budget, replay accepted
work or authorize removal of prior replay records or tombstones. These are
acceptance predicates and require source-bound actor, custody and restart
receipts; they do not establish installed-client or live-provider behavior.

Current acceptable reporting is therefore **experimental implementation and
candidate evidence, live continuity unavailable**. Unrun platform/provider gates
remain unrun until their own receipts exist. Historical v0.1.15 claims stay bound
to their original release and reviewed evidence.
