# oauth-mux

`oauth-mux` is a compiled OAuth fallback mux for AI harness subscriptions and
connector auth. It selects among configured provider accounts, records typed
credential liveness, and falls through without poisoning an entire account when
only one route or capability is unavailable.

The implementation is pure Zig with no external Zig dependencies.

## Current Shape

- Typed liveness model: `live`, `degraded`, `dead`.
- Route-scoped health keys: `provider:account#capability`.
- Provider definitions for credential parsing, env/config injection, failure
  rules, and HTTP or command probes.
- Built-in examples for Codex, Claude, GitHub, Linear, Vercel, Figma, FlakeHub,
  and MCP HTTP resource-server probes.
- Release graph for six targets:
  - `x86_64-linux-musl`
  - `aarch64-linux-musl`
  - `x86_64-macos`
  - `aarch64-macos`
  - `x86_64-windows`
  - `aarch64-windows`

## Development

Use `just` as the operator entrypoint:

```bash
just build
just test
just check
just release
```

`just check` enters the Nix dev shell and then runs `just check-local`, which
runs Zig tests, builds the binary, validates every example config, and runs the
synthetic local E2E harness.

## Quick Checks

Discover the redacted, agent-safe inventory:

```bash
oauth-mux discover --json
```

Validate an example:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json ./zig-out/bin/oauth-mux config validate
```

Probe a configured account:

```bash
./zig-out/bin/oauth-mux probe --provider codex --account max-1 --capability codex-mini --json
```

Run the deterministic no-secret E2E harness:

```bash
just e2e
```

That harness creates a temporary provider config and proves env injection,
command probes, route-scoped quota fallback, health persistence, and `exec`
target injection without contacting live OAuth providers.

## Release Staging

Build local release artifacts from one version:

```bash
just release-local 0.1.0
```

Outputs are written under `dist/out/v0.1.0/`:

- `artifacts/` for binary tarballs and `SHA256SUMS`
- `artifacts/install.sh` for checksum-verified `curl | sh` installs
- `homebrew/oauth-mux.rb`
- `npm/` package workspace
- `npm-tarballs/`
- `nfpm/` configs plus deb/rpm artifacts

Build and smoke-test the same release tree:

```bash
just release-proof 0.1.0
```

Generate the non-publishing operator handoff for the staged tree:

```bash
just release-handoff 0.1.0
```

The handoff is written under `dist/out/v0.1.0/handoff/` and lists GitHub
Release attachments, npm publish order, Homebrew tap input, deb/rpm files, and
full checksums.

See `docs/release-runbook.md` for release and CI details.
See `docs/onboarding.md` for human and agent onboarding.
See `docs/live-provider-qa.md` for manual secret-scoped provider probes.
See `docs/registry-dry-runs-and-rollback.md` for publication dry-runs and
rollback.
See `docs/daemon-boundary.md` for the current daemon decision.
See `docs/spec/development-timeline-2026-04-27.md` for the current
production-readiness timeline.
