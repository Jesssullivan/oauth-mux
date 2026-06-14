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

## Product Guardrail

oauth-mux is a harness continuity layer, not a general auth diagnostics
toolkit. The product is:

> Install oauth-mux, enroll the engineer's agent accounts, run
> `oauth-mux <harness>`, and keep that harness usable when auth, quota, tier,
> or local runtime state changes, with little to no extra user interaction.

Treat work as core only when it directly improves one of these surfaces:

- `oauth-mux codex` as the reference managed harness flow.
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
daemon dependency, unmanaged harness hot-swap, same-thread provider continuity,
mid-turn streaming recovery, or broad adapter claims without live proof.

Feature-creep test: if a change does not make `oauth-mux codex` more reliable,
easier to install, easier to repair, easier for agents to inspect safely, or
easier to generalize into the next harness adapter, it is probably out of scope.

## Source of Truth Hierarchy

1. This file (AGENTS.md)
2. `docs/spec/broker-mcp-contract-2026-05-03.md` — the product anchor
3. `docs/spec/codex-adapter-contract-2026-05-03.md` — Codex adapter spec
4. `docs/spec/harness-session-authority-bridge-2026-05-05.md` — auth/config
   overlays must not hide or fork harness session authority
5. `justfile` — operator entrypoint for all build/test/release tasks
6. `README.md` — public-facing current-state summary; subordinate to specs
7. `flake.nix` — Nix devShell and package definitions
8. `build.zig` / `build.zig.zon` — Zig build system
9. `src/` — implementation

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

Each AI harness (Claude, Codex, Gemini, Vercel, GitHub, MCP) has an adapter in
`src/providers/` that knows how to parse its token format, build refresh requests,
and inject the correct environment variables.

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

## Distribution

Binary name: `oauth-mux`. Distributed as static binaries for 6 targets:
- x86_64-linux-musl, aarch64-linux-musl
- x86_64-macos, aarch64-macos
- x86_64-windows, aarch64-windows

Packaging: npm (esbuild pattern), Homebrew, deb/rpm (nfpm), curl|sh, GitHub Releases.
