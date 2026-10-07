# Omux — Agent Instructions

## Product outcome and active authority

Install Omux, authorize account sources once, and keep using ordinary terminal
applications. Supported integrations substitute compatible authorization when
account, quota, entitlement or credential state changes, without restarting the
application, changing its native session/history, or prompting for routine
handoff. Applications do **not** have to launch through Omux.

The active architecture is
[the native account-lifecycle reset](docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md).
It supersedes the managed-launch restriction, optional-daemon architecture,
LLM-only resource assumptions, remote-first validation, and Just/Zig-build
execution paths in earlier documents. The preservation rule is unchanged:
plans cannot broaden historical release claims or erase their evidence.

The seamless, same-process outcome in Section 0 of
`docs/spec/broker-mcp-contract-2026-05-03.md` remains the product bar. Its wrapper
invocation is superseded. Restart, supervised relaunch, prepared fallback,
route warming and synthetic admission tests never prove seamless handoff.

## Authority order

1. User instructions and this file.
2. `docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md` — active,
   unshipped architecture, lifecycle, security and deletion contract.
3. `docs/authority-map.md` and `docs/authority.json` — historical/current
   document classification. `docs/README.md` indexes the current product,
   decisions, lifecycle, native-adapter, security, reliability and repo-role
   contracts. Their acceptance criteria elaborate the reset; they are not proof.
4. `CHANGELOG.md`, release tags and committed evidence — shipped claim truth.
5. Source definitions, generated API/capability documentation, `BUILD.bazel`,
   `MODULE.bazel`, `.bazelrc`, `flake.nix` and `flake.lock` — implemented behavior
   and pinned tool/execution inputs.
6. `README.md` — current public summary; subordinate to implementation/evidence.

Select earlier records remain historical evidence references; obsolete operational
and unshipped design content is deleted under `docs/history/retired-design-inventory.md`.
Do not implement their conflicting managed-launch, GF-only, zero-C
library, or provider-specific constraints as current policy. Reuse a security
invariant only when it agrees with the reset; rewrite it against new types.

## Product boundary

Omux is a per-user account-continuity daemon with thin clients, not a generic
browser scraper or a universal process interceptor. Codex is the first native
integration proof; Claude and Git HTTPS/GitHub follow. Generic resource demand
covers calls, bytes, uploads, duration, rates and provider-specific capacity.
Each application/provider capability needs version-bound evidence.

Omux owns the authentication integration contract and implementation for each
adapted application. There is no OpenAI-provided Omux/Codex hook to wait for.
Use adequate existing extension mechanisms or implement the necessary native
boundary; delivery may be a plugin, configuration, upstream contribution or an
explicitly maintained application modification. Delivery and evidence are
qualified per application. Current Codex candidates remain experimental;
unmodified Codex has no established Omux continuity support.

Product delivery proceeds through install/activation, Chromium source connection,
verified identity and usable authority, renewal maintenance, ordinary application
integration, then same-process handoff proof. Home Manager owns fleet packages,
service definitions and exact-ID browser host registration; Omux owns live
custody and user-authorized enrollment. Never overwrite declaratively owned files.

One-time native integration setup is reversible. Existing processes are
attachable only where a verified native hook supports attachment. Unsupported
applications report the missing capability; interception or restart must not be
presented as transparent continuity. Preserve native session stores in place.
Never replay accepted streams or repeat tool execution.

Cross-host federation, Windows, Safari, arbitrary-provider support and speculative
mid-stream recovery are deferred. `omux.xoxd.ai` is the separate project SPA for
downloads and documentation; it derives API, CLI, capability and release facts
from this repository and never owns runtime claims. The npm distribution lane
remains retired.

## Architecture and custody

- Fresh Zig runtime pinned to the latest verified official release (0.17.0 for
  this reset). Do not restore legacy runtime modules or build entrypoints.
- One resident per-user daemon owns lifecycle, grants, policy and routing;
  supervised adapters own application protocol boundaries. Use bounded
  `std.Io.Threaded` work, a libcurl multi owner and a SQLite writer queue.
- Identity, account, source, grant, resource, observation, binding and lease are
  distinct types. Authentication factors are not OAuth grants. Labels are not
  identity authority; browser read authorization is not API-call authorization.
- SQLite stores metadata and ciphertext grants. Encrypt payloads before insertion,
  including before journal/backup writes. Hold the wrapping key in macOS Keychain
  or Linux Secret Service. An unavailable key never regenerates over an existing
  database. Never provide a plaintext fallback.
- Each adopted refresh grant has one renewal writer. A native/browser import does
  not transfer renewal ownership. Verify identity and adoption authority before
  activation; quarantine ambiguous rotation rather than restore spent tokens.
- Automatically enroll verified identities within authorized sources. Detachment
  retains history and independently valid grants; forget removes retained secrets
  and leaves a re-enrollment tombstone. Pause, drain, forget and upstream revoke
  have separate effects.
- Make technically compatible accounts eligible by default. Keep active routes
  sticky and alternatives ready. Aggregate only compatible units, scopes and
  windows; grants sharing a quota bucket never multiply available capacity.
- Chromium/Firefox acquisition uses narrow provider-specific permissions and
  native messaging. Import only declared cookie/storage fields, preserve context
  metadata and verify provider identity. Browser-bound grants stay browser-bound.
  No browser automation is part of the product architecture.
- Control clients receive redacted metadata and opaque handles. Only trusted
  adapter channels may materialize narrowly scoped credentials when the native
  protocol requires them. Keep local sockets private with peer-user checks,
  bounded frames and revisioned snapshots.

## Execution and validation

**Every build, test, generator, package, executable invocation and check runs
through Bazel/Bazelisk, with tools provided by the locked Nix flake.** Reading
files and ordinary repository inspection are not build/test execution.

```bash
nix develop --command bazelisk build //...
nix develop --command bazelisk test //...
nix develop --command bazelisk test //:docs_check
```

Local sandboxed execution is the proof default. Automatic CI test/build/check
workflows are removed for the reset. Do not invoke Just, local `zig build`,
standalone test scripts or the former GF proof dispatchers. Future RBE/REAPI must
use the same declared action graph and digest-addressed execution inputs;
endpoints and credentials belong in operator configuration, never source.

A passing unit/synthetic suite proves its stated predicates. A live continuity
claim additionally requires exact application/version/commit evidence of ordinary
launch, native resume, same-process handoff and preserved native state. Report
unrun gates and missing native hooks plainly. No future capability becomes
shipped because a schema, stub, fixture or generated page names it.

Reliability targets and error budgets are defined in
`docs/reliability/service-objectives.md`; they require measured baselines and
do not create a contractual SLA or staffed support promise. Repo roles are
defined in `docs/governance/repository-roles.md`, without appointing human owners.
The user-authorized October 2 Linear reconciliation is recorded in
`docs/tracker-updates/native-ratification-2026-10-02.md`. Publication and provider
access still require their own applicable authorization.

## Hard rules

- No secrets, raw tokens, passwords, cookies, OTPs, private keys, raw account IDs,
  email addresses or PII screenshots in source, fixtures, logs or evidence.
- Pin all external libraries and tools in Nix/Bazel inputs. SQLite, libcurl and
  the required transport/native UI dependencies are intentional dependencies.
- Exhaustive tagged-union switches and propagated error unions; no silent failure.
- OS vault integrations must keep secrets out of argv and diagnostic output.
- Follow XDG directories on Linux and `~/Library/` on macOS. Thin client closure
  does not stop the daemon; disconnect, uninstall and restoration are explicit.
- Preserve release history and reviewed evidence. New code does not inherit
  old live proofs; legacy code may survive in tags only, outside the build graph.
