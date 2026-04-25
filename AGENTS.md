# oauth-mux — Agent Instructions

## Source of Truth Hierarchy

1. This file (AGENTS.md)
2. `justfile` — operator entrypoint for all build/test/release tasks
3. `flake.nix` — Nix devShell and package definitions
4. `build.zig` / `build.zig.zon` — Zig build system
5. `src/` — implementation

## Build

Zig 0.14+ via Nix flake. Always use `just` as the entrypoint:

```bash
just build          # debug build
just test           # run all tests
just build-release  # ReleaseSafe optimized build
just release        # cross-compile all 6 platform targets
just check          # full validation (test suite)
```

Direct `zig build` is acceptable when iterating, but `just` is the canonical path.

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
just test           # unit tests via zig build test
just test-verbose   # with output
```

Tests are in-file `test` blocks (Zig convention) plus `test/fixtures/` for
provider token format samples.

## Distribution

Binary name: `oauth-mux`. Distributed as static binaries for 6 targets:
- x86_64-linux-musl, aarch64-linux-musl
- x86_64-macos, aarch64-macos
- x86_64-windows, aarch64-windows

Packaging: npm (esbuild pattern), Homebrew, deb/rpm (nfpm), curl|sh, GitHub Releases.
