# Omux

Omux is being rebuilt as a per-user account-continuity daemon for ordinary terminal
applications. Authorize account sources once, then keep using normal commands.
The goal is compatible account handoff without application restart, routine login
prompts or changes to native session/history state.

**The replacement is experimental and unshipped.** Native Codex handoff needs a
Omux-developed per-thread/request authorization adapter and live proof; an account store or broker
route decision alone does not provide it. Claude and Git HTTPS/GitHub follow the
Codex proof. No application is advertised as transparently supported before its
native integration is verified.

The latest historical stable release is **v0.1.15**. Its published artifacts and
claims remain documented in [the changelog](CHANGELOG.md) and release tags. The
source reset removes the former runtime and build/install paths; new code does
not inherit old support claims. npm remains retired.

## Architecture

A resident Zig daemon owns account lifecycle, encrypted grants, readiness and
routing. Omux develops the integration contract and authentication adapter for
each adapted OAuth-based terminal application. Delivery may use a sufficient
existing extension API, an upstream contribution or a maintained application
modification; it is not contingent on a vendor supplying an Omux hook. Each
adapter must establish safe application request boundaries with exact-version
evidence. The current Codex candidate does not establish unmodified Codex support.
Thin SwiftUI/macOS, Qt6/Linux and CLI clients inspect and control the daemon.
Chromium/Firefox extensions provide scoped browser acquisition through native
messaging; no browser automation is required by the architecture.

Accounts, identities, sources, grants, resources, observations, application
bindings and leases are separate. Quota is one possible resource: calls, bytes,
uploads, duration and throughput use the same scoped observation model. Totals
include only compatible units/windows and do not multiply shared quota buckets.
Source disappearance detaches an account; explicit forget removes stored secrets
and prevents automatic re-enrollment.

SQLite holds metadata and encrypted grant payloads. The wrapping key belongs in
macOS Keychain or Linux Secret Service. Native/browser imports do not automatically
transfer refresh-token ownership. Browser-bound grants retain their browser
requirements. General control clients receive metadata and opaque handles.

See the [active architecture and acceptance contract](docs/plans/omux-native-account-lifecycle-reset-2026-10-02.md)
and [authority map](docs/authority-map.md) for current direction and historical
spec classification.

The [product charter](docs/product/charter.md),
[user stories](docs/product/user-stories.md) and
[support/completeness gates](docs/product/support-and-completeness.md) define
what install, ordinary use and successful handoff must prove.
[Recorded decisions](docs/decisions/README.md),
[repository roles](docs/governance/repository-roles.md) and
[reliability objectives](docs/reliability/service-objectives.md) make the design
durable. Reliability numbers are measurement targets; no contractual SLA or
staffed response promise applies to this experimental self-hosted software.
Use the [docs index](docs/README.md) for lifecycle, security and repair contracts.

Delivery proceeds through Chromium installation and daemon activation, browser
connection, verified identity and usable authority, renewal, ordinary native
launch/resume and same-process handoff. Native UI onboarding uses shared CLI
setup operations. Home Manager owns fleet packages, service definitions and
exact-extension-ID host registration; Omux owns live state and authorized
enrollment and must guide declarative changes instead of overwriting managed
files. Development has separate extension/host/service identities, sockets,
database and vault custody, with an explicit serialized rebuild, manual browser
reload and daemon restart. Updates are guided through the declarative lane;
rollback must not restore spent credential generations or erase tombstones.
Permanent key loss offers explicit fresh enrollment into separate custody while
preserving the failed installation. These are acceptance requirements, not
claims that the installed lifecycle has passed.

## Develop and validate

All executable work uses Bazel/Bazelisk with tools from the locked Nix flake.
Local sandboxed execution is the default; automated CI test/build/check lanes and
legacy Just/Zig-build paths are removed.

```bash
nix develop --command bazelisk build //...
nix develop --command bazelisk test //...
nix develop --command bazelisk test //:docs_check
```

The toolchain targets Zig **0.17.0**, verified in the
[official release index](https://ziglang.org/download/index.json). Bazel declares compiler, library, test,
generator and packaging actions. Future RBE/REAPI uses the same action graph with
operator-supplied execution configuration.

A passing synthetic suite proves its local predicates. Live continuity requires
exact application-version and commit evidence of native launch/resume, attachment,
quota handoff, unchanged process/session authority and no routine prompt.

## Documentation and distribution

[omux.xoxd.ai](https://omux.xoxd.ai) is the separate project SPA for downloads and
documentation. The development SPA imports API method summaries, CLI, lifecycle,
capability and release facts by digest from the versioned bundle generated by
`//:reference`; curated lifecycle explanations remain prose.
[Reset](docs/implementation/native-reset-evidence-2026-10-02.md),
[saved evening](docs/implementation/native-evening-evidence-2026-10-03.md) and
[current admission evidence](docs/implementation/native-admission-evidence-2026-10-04.md)
record their local runtime, native-hook, delivery and SPA gates. Platform execution
and live continuity require their own evidence before this experimental checkout
becomes an installable release.

The exact pinned owner candidate also passed a [provider-free installed
app-server checkpoint](docs/implementation/native-interop-evidence-2026-10-04.md)
on Sting: genuine native registration and acknowledged zero-acquire removal
preserved its process, thread/session, initialized zero-turn history and native
configuration. Stock Codex support, CLI/TUI resume and live account handoff
remain unproved.

The [weekend push](docs/plans/omux-ratification-weekend-push-2026-10-02.md) and
[.goal ledger](.goal/omux-weekend-2026-10-02.json) record three-, five-, ten-hour
and Sunday acceptance checkpoints. They track actual receipts and blockers;
they do not schedule automatic execution or promote support at a deadline.

The subsequent [native safety sprint](docs/plans/omux-native-safety-sprint-2026-10-03.md)
tracks durable request/mutation authority, backup rollback refusal, XDG socket
custody, local observations and available platform proof. Its
[receipt](docs/implementation/native-safety-evidence-2026-10-03.md) and
[five-hour checkpoint](.goal/omux-native-safety-2026-10-03.json) distinguish
current implementation from installed and live acceptance.
