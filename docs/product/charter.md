# Omux product charter

Status: **existing user-directed outcome; experimental, unshipped successor**.
Recorded 2026-10-02; clarified by the user on 2026-10-05. This charter records
the ratified adapter ownership and delivery direction without promoting capabilities.

## Immutable user outcome

Install Omux, authorize account sources once, and keep using ordinary terminal
applications. For a supported application/version and compatible authorization,
changes in account, quota, entitlement or credential state must not require an
application restart, routine handoff prompt or change to native session/history.
An application does not have to launch through Omux. Closing an Omux control
client leaves the per-user daemon running.

This outcome is the acceptance bar throughout the reset. It may be revised only
by an explicit user decision; a convenient implementation, passing fixture or
unsupported native hook cannot silently weaken it. Initial authorization,
explicit repair and provider-required authentication may still need user action.
Failure to meet the bar must remain visible as a limitation.

## People, identities and authority

The same outcome applies to contractors, scientists and people using work,
startup, research or home accounts. These describe users and contexts, not
separate continuity products or credentials that are automatically interchangeable.
One person can hold multiple independently verified identities and account types.
Presentation labels never establish identity or authorization.

An authorized source permits discovery within its declared scope. Verified
identities enroll automatically within that scope; ambiguous candidates are
quarantined. Browser read permission does not authorize API use. Imported
credentials do not transfer renewal ownership.

Technically compatible accounts are eligible by default, and users can narrow
policy. Compatibility includes verified grant audience, purpose, scopes,
resource demand and the native application's safe substitution boundary.
Persona labels cannot waive those checks or authorize access to another
organization's resources. No additional employer, client, project or household
isolation policy is ratified here; any proposed policy needs an explicit decision
and an enforceable contract before it becomes a claim.

## Existing decisions and boundaries

The [repository instructions](../../AGENTS.md) and
[native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md)
are the authority for these existing decisions:

- One resident per-user Zig 0.17 daemon owns lifecycle, encrypted grant custody,
  policy and routing; adapters own native protocol boundaries. CLI, SwiftUI/macOS
  and Qt/Linux clients are thin controls.
- Codex is the first native integration proof; Claude and Git HTTPS/GitHub follow.
  Omux owns each application's authentication integration contract and adapter.
  A vendor-supplied Omux hook is not an architectural dependency. Delivery uses
  an adequate extension API, upstream integration or maintained modification,
  selected per application. Existing-process attachment requires a verified
  adapter boundary. No maintained Codex distribution is shipped today, and an
  experimental candidate does not confer support on unmodified Codex.
- Native setup is reversible and preserves native stores in place. Restart,
  relaunch, alternate homes, route warming and synthetic admission do not satisfy
  same-process continuity.
- Optional Chromium/Firefox conduits use narrow provider permissions and native
  messaging. Browser-bound authorization remains browser-bound. Product browser
  automation and generic scraping are outside the architecture.
- Resources include calls, bytes, uploads, duration, rates and provider capacity.
  Only compatible units, scopes and windows aggregate; shared quota buckets count
  once. Freshness and unknown capacity are explicit.
- Pause, drain, detachment, forget and upstream revoke are distinct operations.
  Detachment retains history and independently valid grants. Forget removes
  retained secrets and leaves a tombstone; automatic discovery cannot clear it.
- Local federation is the initial scope. Cross-host federation, Windows, Safari,
  arbitrary-provider support and speculative mid-stream recovery are deferred.
  The separate project SPA publishes repository-derived facts. npm distribution
  remains retired.
- Builds, tests, generators, packages and executable checks use Bazel/Bazelisk
  through the locked Nix flake, with local proof as the default. Historical
  releases and reviewed evidence retain their original claim boundaries.

## Installed lifecycle and delivery order

Chromium leads installed proof: install and activate → connect authorized browser
contexts → verify identities and usable authority → maintain renewal → integrate
ordinary application launch/resume → prove same-process handoff. Other authorized
enrollment methods remain valid; Firefox and Darwin retain independent gates.
The installation carrier is TIN-2063; browser acquisition is TIN-2720; repository-
derived SPA facts are TIN-734; Codex adapter work is TIN-5338/TIN-5421; complete
continuity acceptance is TIN-2057. The [user journeys](user-stories.md) and
[support gates](support-and-completeness.md) provide stable acceptance IDs for
those carriers; tracker completion alone does not close a gate.

Native UI onboarding and CLI share setup operations and independent readiness
results. Home Manager owns fleet package/service/host-registration deployment,
including exact extension IDs. Omux recognizes declarative ownership, reports
the necessary declarative change and owns only live state and authorized
enrollment. Development has distinct extension ID, native host, service, paths,
sockets, database and vault namespace; it never shares a renewal writer or
custody database with release. The rebuild/stage loop is serialized and explicit;
developers manually reload Chromium and explicitly restart the development
daemon. Core updates are guided through declarative deployment and compatibility
checks. Generation rollback cannot roll back credential generations, tombstones
or replay authority. Permanent vault-key loss preserves the failed installation
and permits explicitly authorized fresh enrollment into separate custody.

## Success and failure invariants

A successful handoff changes compatible authorization at a verified safe boundary
while the same application process retains native transcript, session, tools and
approval authority. Active routes stay sticky where compatible. Omux never
replays an accepted stream or repeats accepted tool execution to simulate success.

Admission respects distinct identity, account, source, grant, resource,
observation, binding and lease state. Unknown readiness is not reported as ready;
unknown capacity is not invented and alone does not establish unavailability.
Missing hooks, incompatible grants, accepted-stream failures and unsafe
account-bound state produce honest bounded failures or repair conditions.

Custody encrypts secrets before SQLite insertion, including journal/backup paths,
with the wrapping key in the OS vault. An unavailable key never creates a
replacement over an existing database, and plaintext fallback is forbidden.
Each adopted refresh lineage has one renewal writer; uncertain rotation is
quarantined. Control clients receive redacted metadata and opaque handles.
Trusted adapter materialization is narrowly scoped. Credentials and PII never
enter logs, source, fixtures, diagnostic output or evidence.

## Implementation, proof and remaining acceptance

The [implementation evidence record](../implementation/native-reset-evidence-2026-10-02.md)
owns receipts and detailed limits. At this charter's checkpoint:

The [subsequent safety sprint](../implementation/native-safety-evidence-2026-10-03.md)
adds durable request/mutation authority, independent SQLite rollback fencing,
strict runtime custody and bounded local observation. Genuine isolated Linux
vault and installed daemon/Qt predicates have passed their recorded scopes.
The table below preserves the October 2 checkpoint; current evidence determines
which later predicates passed and which platform/live gates remain unavailable.

| Classification | Concrete status |
| --- | --- |
| Source implemented | Fresh daemon/domain/control/custody/transport implementations; thin client sources; browser transport/packaging; native Git helper; generated reference and Linux development packaging. This is experimental source, not installed or live support. |
| Native candidate | Version-bound Codex hook candidate against official `rust-v0.157.0`, commit `00c972ed5d6ff6499317fd41b7f23605b8e6850d`. Stock support and `native_support` remain unavailable/false. |
| Experimentally proved | 37 project Bazel test targets and 66 build targets; eight candidate production builds, 64 focused Rust cases and 318 protocol cases with one intentional ignore; seven development SPA gates; local Linux archive relocation. Each proves only its recorded predicates. |
| Unproved | Live provider continuity, ordinary launch/resume/attachment against real accounts, real OS-vault IO, macOS compilation/execution, installed services and desktop sessions, clean-machine delivery, signed/stamped publication and website deployment. |
| Blocked pending evidence | Production Codex/Claude/GitHub browser exports are disabled pending exact provider schema and identity proof. Refresh adoption/ownership transfer and upstream revocation need completed implementation and version-bound evaluation. |
| Deferred | Cross-host federation, Windows, Safari, arbitrary providers and speculative mid-stream recovery. |

Promotion requires exact application/version/commit evidence of ordinary native
launch and resume, compatible account substitution after the relevant failure,
unchanged process, preserved native history/session/tool/approval state and no
routine prompt. Attachment and ancillary authorization limits require their own
evaluation. Neither this charter nor historical release proof supplies that
evidence. Remaining gates must be reported as unrun until executed.
