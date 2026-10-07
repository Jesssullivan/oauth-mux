# Repository roles and claim custody

Status: recorded repository-boundary decision for this experimental reset under
the active, unshipped [native reset](../plans/omux-native-account-lifecycle-reset-2026-10-02.md).
The user's requested ratification authorizes these duties within the current
repository scopes. This reviewed boundary implementation of user-directed
repository authority is not a new organizational agreement. It assigns review
duties to roles without appointing people, GitHub teams or on-call staff. It does
not transfer repository ownership, authorize publication, or change release claims.
Stable v0.1.15 retains its historical evidence boundaries.

## Authority and decisions

Resolve conflicts in the order established by `AGENTS.md`: user instructions;
the active reset; [authority map](../authority-map.md); changelog, tags and
committed release evidence; implemented source and locked build inputs; README.
This role map is subordinate to that order. A conflicting neighboring README or
historical runbook cannot reinstate remote-first proof, Just, managed launch or
automatic publication for Omux.

This map records the user's authorized ratification of the design/product and
repository-role decisions in this reset push. Subsequent changes remain subject
to user instructions and the applicable repository review process; record their
authorizing instruction or review and exact revision.
Reviewers resolve ordinary implementation choices within existing authorization.
An unresolved architecture conflict is reported with the conflicting sources and
keeps the affected claim or promotion pending. No new named approver or branch
protection requirement is implied.

## Repository boundaries and hand-offs

| Repository or surface | Decision and boundary | Proof and source/generator custody | Owner duties and hand-off |
| --- | --- | --- | --- |
| `oauth-mux` runtime, adapters and clients | Daemon owns lifecycle, encrypted grants, policy and route decisions. Supervised adapters own protocol boundaries; native applications retain session/history/tool/approval authority. | Executable definitions, [capability catalog](../../src/catalog.zig), [reference generator](../../src/reference.zig), `//:reference`, locked Nix/Bazel graph and [implementation evidence](../implementation/native-reset-evidence-2026-10-02.md). | Runtime reviewer checks implemented behavior, custody and honest capability classification. Proof reviewer records exact revision, application version, predicate, result and limitation. Send only public generated metadata and evidence references downstream. |
| Official upstream Codex and `integrations/codex-upstream` candidate | Upstream owns its application and contribution acceptance. Omux owns the integration contract, application-specific hook/adapter development and version-bound delivery proposal; no vendor-provided Omux hook is assumed. | [Candidate README and manifest](../../integrations/codex-upstream/README.md), source hashes, validation receipts and [upstream tool custody](../../tools/codex-upstream-custody.md). | Native integration reviewer distinguishes offline patch checks, compilation, synthetic Rust tests, installed delivery and live proof. Missing capabilities remain explicit development gaps. Handoff identifies exact upstream base, adapter/export digests, delivery lane, protocol and outstanding gates; upstream submission needs applicable authorization. |
| `omux.xoxd.ai` | Separate SvelteKit SPA for documentation, downloads and curated product explanations. Its static public metadata contains no user account state. It owns rendering, not runtime claims. | Exact bytes from runtime `//:reference`, versioned schema, SHA256 digest and producer provenance; site schema/drift/render/archive checks. | Site reviewer verifies import provenance and status/limitations in rendered copy. A digest detects drift, not authenticity or signature. Preserve experimental dirty/unstamped provenance when emitted; do not relabel it a release. Return factual discrepancies to runtime source; curate explanatory prose without promoting support. |
| `homebrew-omux` and any release-derived tap lane | Distribution of approved public release artifacts. Historical stable releases remain the install authority until explicit successor promotion. npm remains retired. | Published runtime release formula/assets and checksums, exact release/tag evidence, version-specific install/rollback evidence. | Distribution reviewer consumes release output rather than workstation-generated substitutes, checks formula version/checksums and reversible rollback. New runtime packaging or a site download link does not authorize a tap update or create a shipped release. |
| Infrastructure repositories and GloriousFlywheel | Infrastructure owns its own deployment, endpoint, credential and worker policy. GF is a possible future RBE/REAPI substrate, not an Omux proof prerequisite. No particular neighboring infrastructure checkout is appointed Omux deployment owner here. | Omux's declared action graph and [closure/worker contract](../../tools/nix-workers.md); infrastructure's own applicable authority and exact installation evidence. | Execution reviewer requires identical digest-addressed tool closures and declared platform inputs. Hand off closure metadata and platform requirements; keep endpoints, credentials and scheduler mapping in operator configuration. A local passing gate remains local proof; closure export alone proves no remote execution. |
| Lab/workstation policy and operator secret custody | Fleet/user setup remains outside runtime claim authority. Neighboring lab remote-first or Just policies do not govern this checkout. | Explicit host/operator authorization and that repository's own configuration/evidence. Omux vault custody remains its native Keychain/Secret Service contract. | Operator handles authorized host setup and private credentials outside Omux source. No tokens, cookies, private keys, raw account IDs, email addresses or PII captures enter source, fixtures, logs or public evidence. Never import private lab data into the reference bundle. |
| External tracker, including Linear | Planning, dependencies and intent; subordinate to repository authority and committed implementation/evidence. Ticket status is neither a support claim nor release proof. | Existing TIN-491/TIN-2057 intent references and repository-linked acceptance evidence. No signed tracker authority is assumed. | Workstream reviewer reconciles tracker proposals with the reset and records repository acceptance links. Tracker updates, comments and status changes require separate authorization; this map authorizes none. |

Neighboring status/README inspection establishes context only. It neither proves
deployment nor ratifies changes in those repositories, whose existing work and
ownership remain intact.

## Review and promotion conditions

Omux owns the integration contract, hook development and adapter delivery for
each adapted OAuth terminal application. No OpenAI-provided Omux hook is
assumed. Existing extension mechanisms may suffice; otherwise the delivery lane
may be an upstream contribution or explicitly maintained application modification.
Upstream retains application ownership and contribution acceptance. Missing
capability is a development/delivery gap, not a dependency on a vendor supplying
the hook. The current Codex candidate remains an evaluation artifact with its
own exact-version gates, not delivered live support.

Home Manager owns declarative fleet artifacts, services and exact-extension-ID
native-host registration. Omux owns live account state, custody and enrollment.
Shared CLI/UI setup observes managed ownership and guides declarative changes
rather than overwriting Nix-owned files. Deployment rollback cannot roll back
credential generations, tombstones or replay authority. Trace this delivery scope
to [TIN-2063](https://linear.app/tinyland/issue/TIN-2063), the locked
[flake](../../flake.nix) and [delivery instructions](../../delivery/README.md).

Role labels may be combined by an authorized contributor; they describe duties,
not a mandatory staffing arrangement. The change reviewer checks scope and
authority, the proof reviewer checks evidence strength, and the release/site/
distribution reviewer checks the concrete artifact being proposed. Applicable
repository permissions and explicit session authorization determine who acts.

Every executable check, generator, package and proof invocation uses Bazel or
Bazelisk with the locked Nix tools. Local sandboxed execution is the default.
The upstream Codex graph uses the separately audited `#codex-upstream` shell.
Receipts distinguish source review, synthetic predicates, native conformance,
platform execution and live-provider evidence; overlapping test cases are not
added into an invented total. Automatic CI gates and legacy release dispatchers
are not restored by assigning a review role.

A support promotion requires an exact application/version/commit and verified
native hook plus ordinary launch/resume, same-process handoff, native state and
approval preservation, compatible alternate admission and no routine prompt.
Accepted streams and tools are never replayed. Attachment claims require their
own existing-process evidence. Restart, warming, synthetic admission and old
release receipts cannot substitute. Current Codex candidate `native_support:
false` and missing live continuity remain visible. Genuine isolated Linux
Secret Service and private macOS Keychain C-driver IO passed their recorded
[safety evidence](../implementation/native-safety-evidence-2026-10-03.md)
predicates; they do not establish personal-session custody, production Darwin
daemon/application execution or installed service/desktop behavior. Those gates
remain unproved until their own exact receipts exist.

Release approval concerns a concrete versioned artifact, checksums/provenance,
platform/install/uninstall evidence and bounded release notes. It does not imply
approval of external publication unless already authorized. Site approval concerns
the exact imported bundle/digest and built site artifact, rendered experimental/
stable distinctions and relevant site checks. Tap approval concerns the exact
published release-derived formula and version-specific distribution evidence.
Publishing, signing, deployment, upstream submission and tracker mutation are
explicit operations; this document does not grant standing autopublish authority.

## Acceptance trace

These IDs identify checks of this role map, not completed product gates. A
ratification record should cite each applicable ID and its review evidence.

| ID | Acceptance condition | Authoritative trace |
| --- | --- | --- |
| RR-01 | Runtime decisions, native session authority and upstream application custody remain separate; no vendor-provided hook or shipped support is inferred. | Reset: Processes, custody and interfaces / Native application integration; candidate README. |
| RR-02 | Runtime claims originate in implemented source/catalog and committed evidence; generated site facts preserve bundle bytes, digest, schema and source provenance. | Reset: Clients and generated documentation; `src/catalog.zig`, `src/reference.zig`, site README import contract. |
| RR-03 | Stable historical release truth, experimental successor state and distribution promotion remain separate. | Reset: Deletion and evidence map / Acceptance and implementation status; authority map; changelog and release tags; tap README. |
| RR-04 | Local Nix+Bazel action/proof custody remains the default; future RBE uses identical inputs without GF/remote proof mandates. | Reset: Toolchain, deletion and delivery; `tools/nix-workers.md`, `tools/codex-upstream-custody.md`. |
| RR-05 | Secrets stay in authorized private/vault custody, outside repository and public site/tracker evidence. | `AGENTS.md` Hard rules; reset: Processes, custody and interfaces / Browser acquisition. |
| RR-06 | Review roles do not invent human assignments, transfer repositories or authorize external mutation; ratification and conflicts identify their actual authority. | `AGENTS.md` authority order; reset: Backlog disposition and explicit artifact-driven publication. |
| RR-07 | Support/release/site/tap approval names exact artifacts and evidence; synthetic or historical proof cannot promote live continuity. | Reset: Acceptance and implementation status; implementation evidence's remaining gates; authority map evidence rules. |
| RR-08 | Omux owns adapter/hook development and delivery; Home Manager owns fleet artifacts/services/host registration, while shared CLI/UI setup preserves declarative ownership and daemon-owned custody. | This map: Review and promotion conditions; `flake.nix`; delivery instructions; TIN-2063. |

Ratification records responsibility for these checks; it does not mark RR-01
through RR-08 as product acceptance or close any unrun implementation gate.
