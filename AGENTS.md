# oauth-mux — Agent Instructions

## Product Anchor (read first)

The product success metric is in `docs/spec/broker-mcp-contract-2026-05-03.md`:

> The user runs `oauth-mux <harness>` (e.g. `oauth-mux codex`). The harness
> behaves like the real one. The active subscription account exhausts its
> quota. Another credited account is **seamlessly substituted in place**.
> The harness process is not restarted. The user is not prompted.

The Codex implementation of that bar is in
`docs/spec/codex-adapter-contract-2026-05-03.md`. Restart, supervised
relaunch, and `prepared_fallback` are NOT the product — they are
diagnostic / Level 1–2 infrastructure. If a spec sentence, ticket goal,
commit message, or PR description frames any of those as "the success" or
"the fallback if seamless mux is hard," it is wrong by construction;
delete and re-anchor on the broker contract.

## Active v0.2 Design Authority (unshipped)

Immediately after the immutable product anchor, the active design authority is
`docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` (GitHub #463;
Linear TIN-2057). Its sequenced removal contract is
`docs/plans/oauth-mux-v0.2-deletion-ledger-2026-07-11.md`; the complete authority
order is `docs/authority-map.md`, and the managed-boundary security contract is
`docs/security/omux-v0.2-threat-model-2026-07-11.md`. The declaration-only
process compatibility contract is `docs/spec/managed-harness-jsonrpc-v2.md`;
its methods remain unimplemented until adapter proof lands.

v0.2 is a full-broker hard contract reset, beginning with a managed Claude
request proxy. It is future/unshipped direction until its golden proof passes;
v0.1.15 remains stable and shipped claims remain bounded by the changelog and
committed evidence.

## Product Guardrail

oauth-mux is a harness continuity layer, not a general auth diagnostics
toolkit. The product is:

> Install omux, enroll the engineer's agent accounts, run `omux <harness>`,
> and keep that harness usable when auth, quota, tier,
> or local runtime state changes, with little to no extra user interaction.

Treat work as core only when it directly improves one of these surfaces:

- `omux claude` as the v0.2 golden managed request-broker flow.
- Codex as the shipped reference adapter and OpenCode as the conformance proof.
- Account enrollment and route-health truth across multiple engineer identities.
- Managed in-session quota/rate/auth/tier handoff.
- Native-feeling UX for install, preflight, login/pass-through, resume, status,
  and repair.
- Redacted diagnostic AX so agents can inspect state and request safe next actions
  without reading tokens or spending provider calls.
- A reusable harness adapter contract for future Claude, OpenCode, and other
  harness integrations.

Broker MCP methods, daemon status, route diagnostics, trace flags, cassette
capture, packaging, and website/docs updates are support infrastructure. They
matter only when they make the managed harness experience more reliable, easier
to repair, safer for agents, or easier to generalize into the next real harness
adapter.

Defer or contain work that primarily chases universal provider support, hidden
daemon dependency, unmanaged harness hot-swap, same-thread cross-provider continuity,
mid-turn streaming recovery, or broad adapter claims without live proof.

Feature-creep test: if a change does not make `omux claude` more reliable,
preserve the Codex reference contract, improve setup/repair/agent inspection, or
prove the OpenCode conformance boundary, it is probably out of scope.

## Source of Truth Hierarchy

1. This file (AGENTS.md)
2. `docs/spec/broker-mcp-contract-2026-05-03.md` — the product anchor
3. `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` — active,
   unshipped v0.2 design authority
4. `docs/plans/oauth-mux-v0.2-deletion-ledger-2026-07-11.md` — v0.2 removal order
5. `docs/security/omux-v0.2-threat-model-2026-07-11.md` — managed broker threats
6. `docs/spec/managed-harness-jsonrpc-v2.md` — declaration-only process adapter
   compatibility contract; explicitly unshipped
7. `docs/spec/codex-adapter-contract-2026-05-03.md` — shipped Codex adapter spec
8. `docs/spec/harness-session-authority-bridge-2026-05-05.md` — auth/config
   overlays must not hide or fork harness session authority
9. `CHANGELOG.md` and committed evidence — shipped claim truth
10. `justfile` — operator entrypoint for all build/test/release tasks
11. `README.md` — public-facing current-state summary; subordinate to specs
12. `flake.nix` — Nix devShell and package definitions
13. `build.zig.zon` plus the Zig release graph — version and release semantics;
    they emit/check the v0.2 manifest contract and currently migrated consumers.
    Remaining packaging and Bazel/GF consumers stay sequenced under TIN-2050,
    TIN-2046, and TIN-2105 until their own proof lands.
14. `src/` — implementation

## Superseded Design Inputs (pending deletion)

These notes are no longer design authority. They are historical inputs to the
v0.2 program and are pending safe deletion under its deletion ledger. Do not
implement against them or cite them as current direction; preserve their shipped
evidence references and v0.1.15 history until replacement proof exists.

- `docs/spec/model-quota-granularity-2026-07-03.md` is superseded by the exact-model
  route-readiness and evidence rules in the v0.2 program (TIN-2400 / GitHub #436).
  Its pure quota algebra and committed evidence remain reusable until migrated.
- `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md` and
  `docs/spec/claude-managed-hotswap-experiment-2026-07-14.md` are superseded.
  The per-session request proxy is the product mechanism; E1 canonical-keychain
  mutation is canceled. Browser/cookie-picker tooling remains evidence-only and
  may never commit cookies, tokens, raw account ids, raw emails, or PII screenshots.

## Build And Validation

Remote-first rule: proof builds, test gates, release checks, and agent validation
must use the GloriousFlywheel remote lanes. The bare proof recipes dispatch
remote by default:

```bash
just build          # build on the GloriousFlywheel runner
just test           # test on the GloriousFlywheel runner
just check          # full check on the GloriousFlywheel runner
just e2e            # e2e on the GloriousFlywheel runner

just remote-build   # build on the GloriousFlywheel runner
just remote-test    # test on the GloriousFlywheel runner
just remote-check   # full check on the GloriousFlywheel runner
just remote-e2e     # e2e on the GloriousFlywheel runner
```

Do not use local `zig build`, `just build-local`, `just test-local`,
`just check-local`, or `just e2e-local` as the completion proof on a developer
laptop. Local build commands remain available only for narrow debugging of a
local toolchain, generated binary, or installer issue. If a local build is used
for debugging, state that it is not validation and follow with the remote lane
before making a completion or merge claim.

The independent FOSS gate is the unprivileged `Public Source` workflow. It runs
`nix develop --command just public-source-check-local` on a GitHub-hosted runner
with Tinyland/GF credentials and endpoints absent. This proves the public
Just/Nix source path; it complements and never replaces required GF proof.

Private GloriousFlywheel action checkout is authenticated by
`.github/actions/checkout-gloriousflywheel`, which mints a short-lived token
from the dedicated `omux-gf-checkout` App, restricted to
`tinyland-inc/GloriousFlywheel` with `contents: read`. Do not restore the static
`GF_ACTIONS_TOKEN` path for GloriousFlywheel checkout, substitute a broad PAT,
or weaken the fail-closed proof behavior when App custody is unavailable.
Separate legacy checkout uses in registry-keeper workflows are not GF proof
authority and must migrate under their own repository-scoped credential names.

## Architecture

Pure Zig, zero external dependencies. All capabilities from `std`:
- `std.http.Client` — HTTP/HTTPS
- `std.crypto.tls` — TLS 1.3
- `std.json` — JSON parsing/serialization
- `std.crypto` — age decryption (X25519 + ChaCha20-Poly1305)

### Monadic Pipeline

The core is a linear pipeline where each stage transforms `PipelineContext` or
short-circuits via Zig error unions (`PipelineError!void`). `try` is the bind operator:

```
Config → Resolve Provider → Select Account → Read Secret →
Validate Token → Refresh if Needed → Inject Env → Exec
```

### Provider Adapters

`src/providers/` contains shipped and legacy provider implementations. The v0.2
product surface is managed Claude plus the Codex reference adapter and OpenCode
conformance. Other built-ins are pending deletion under the v0.2 ledger and may
not be presented as managed-continuity support.

### Secret Backends

`src/secret/` — keychain (macOS/Linux), SOPS/age, env vars, files, commands, stdin.
Keychain access shells out to `/usr/bin/security` (macOS) or `secret-tool` (Linux)
to avoid framework linking and keep the binary static.

## Hard Rules

- No external Zig dependencies. Everything from `std`.
- No hardcoded secrets or `.env` commits.
- Exhaustive switch on all tagged unions — compiler enforces this.
- All pipeline errors propagate via error unions, never silently swallowed.
- Shell out for platform services (Keychain, secret-tool) rather than FFI.
- JSON for config (Zig `std.json` provides zero-code struct deserialization).
- XDG Base Directory compliant on Linux; ~/Library/ on macOS.

## Testing

```bash
just remote-test    # unit tests on the GloriousFlywheel runner
just remote-check   # full validation on the GloriousFlywheel runner
```

Tests are in-file `test` blocks (Zig convention) plus `test/fixtures/` for
provider token format samples. `just test` is a remote proof lane. Local
`just test-local` and `just test-verbose` are debugging tools only; do not use
them as completion proof.

## Current v0.1.15 Distribution

Current binary name: `oauth-mux`. Distributed as static binaries for 6 targets:
- x86_64-linux-musl, aarch64-linux-musl
- x86_64-macos, aarch64-macos
- x86_64-windows, aarch64-windows

Packaging (real lanes, 2026-07-02): 6 CLI tarballs + curl installer + rpm/deb (nfpm) +
the `Jesssullivan/homebrew-omux` tap (binary-only Formula) + nix source flake, all off
GitHub Releases. **npm is RETIRED** — `npm-deprecate.yml` exists to keep it dead; never
recommend the npm lane. There is no `.app`/`.dmg`/AppImage; systemd/launchd exist only
as user-wrapper templates.

## Repo Boundary Map

This repo is the **broker runtime authority**. Full matrix with proof anchors:
`docs/research/omux-foundation-2026-07-02T0532Z.md` (boundary map section).

- `Jesssullivan/oauth-mux` (here): broker/OAuth runtime logic, locks, refresh, resume,
  provider truth (`src/provider_schema.zig` `proof_status` +
  `docs/spec/provider-truth-matrix-2026-07-02.md`), release lane and versioning
  (`build.zig.zon` is the version SSOT).
- `tinyland-inc/omux.xoxd.ai`: static docs/marketing rendering ONLY. It never owns
  runtime claims; its provider page must derive from the truth matrix here and may
  never show a capability as live from another capability's local proof.
- `Jesssullivan/homebrew-omux`: the brew release surface (binary-only Formula).
- GloriousFlywheel + `tinyland-inc/ci-templates`: build/cache/RBE and CI-shape
  authority. Endpoints are environment authority — never baked into rc files.
- `lab` (sops/age fleet repo): secrets. No secret material ever lands in any omux repo.
