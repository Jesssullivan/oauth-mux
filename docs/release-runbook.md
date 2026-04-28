# oauth-mux Release Runbook

Updated: 2026-04-28

## Local Quality Gates

Run the canonical repo check:

```bash
just check
```

This enters the Nix dev shell and runs:

- Zig unit tests
- binary build
- every `examples/*.config.json` through `config validate`
- synthetic local E2E via `scripts/e2e-local.sh`

The E2E harness is intentionally no-secret and no-network. It creates a
temporary provider definition, command probe, config, and state directory, then
proves:

- shell env injection for a selected account
- command-transport capability probes
- route-scoped quota fallback from `toy:a1#expensive` to `toy:a2#expensive`
- unrelated route survival for `toy:a1#cheap`
- persisted typed health evidence
- `exec` target process env injection

Run only that harness with:

```bash
just e2e
```

## Local Release Proof

Run the full local release staging path:

```bash
just release-local 0.1.0
```

This runs the single Zig release graph and stages artifacts under
`dist/out/v0.1.0/`.

Expected output:

- `artifacts/oauth-mux-x86_64-linux.tar.gz`
- `artifacts/oauth-mux-aarch64-linux.tar.gz`
- `artifacts/oauth-mux-x86_64-macos.tar.gz`
- `artifacts/oauth-mux-aarch64-macos.tar.gz`
- `artifacts/oauth-mux-x86_64-windows.tar.gz`
- `artifacts/oauth-mux-aarch64-windows.tar.gz`
- `artifacts/SHA256SUMS`
- `artifacts/install.sh`
- `homebrew/oauth-mux.rb`
- `npm/` package workspace
- `npm-tarballs/*.tgz`
- `nfpm/oauth-mux-{amd64,arm64}.yaml`
- deb/rpm artifacts

The Nix dev shell supplies Zig, Just, Node/npm, and nfpm, so `just release-local`
is the reproducible proof path. Running `scripts/release-local.sh` directly will
still skip npm or deb/rpm output if those host tools are absent.

Run the full build-plus-smoke proof:

```bash
just release-proof 0.1.0
```

This runs `release-local` and then checks:

- required binary tarballs, debs, rpms, npm tarballs, and Homebrew formula
- `SHA256SUMS` against the artifact directory
- tarball payload names for Unix and Windows targets
- rendered Homebrew formula placeholders and Ruby syntax when Ruby is present
- local npm install of the matching platform package plus root shim
- local installer execution against the staged artifact directory
- non-publishing release handoff generation

Generate only the handoff for an already staged tree:

```bash
just release-handoff 0.1.0
```

This validates the staged publication inputs and writes:

- `dist/out/v0.1.0/handoff/release-handoff.md`
- `dist/out/v0.1.0/handoff/publish-files.txt`
- `dist/out/v0.1.0/handoff/SHA256SUMS.full`

The handoff lists GitHub Release attachments, npm publish order, Homebrew tap
input, deb/rpm files, and full checksums. It does not use registry credentials
or publish anything.

npm publication is intentionally separate and CI-only. Use
`.github/workflows/npm-publish.yml`; it reuses the release derivation, resolves
auth at runtime, and publishes only the generated tarballs with npm provenance.
Do not publish npm packages from a workstation.

## Release Workflow

Tags matching `v*` run `.github/workflows/release.yml`.

The workflow calls the same build-plus-smoke proof used locally:

```bash
nix develop --command just release-proof-local "${GITHUB_REF_NAME#v}"
```

The release job only uploads the staged `dist/out/` tree after the smoke proof
and handoff generation pass. It then attaches these files to the GitHub release:

- `v*/artifacts/*`
- `v*/npm-tarballs/*.tgz`
- `v*/homebrew/oauth-mux.rb`
- `v*/handoff/*`

This tag workflow does not publish npm packages. npm publication is handled by
the manual `NPM Publish` workflow after the release artifacts and registry
dry-run are reviewed.

The staged `install.sh` verifies the selected tarball against `SHA256SUMS`
before installing. For local proof, `OMUX_RELEASE_BASE_URL=file://...` points it
at the staged artifact directory instead of GitHub Releases.

## GloriousFlywheel Release Proof

`.github/workflows/release-proof.yml` is a manual cache-first proof surface for
the release path. It runs on `tinyland-nix`, checks out the private
GloriousFlywheel action when `GF_ACTIONS_TOKEN` is available, and executes:

```bash
nix develop --command just release-proof-local <version>
```

That workflow does not publish release artifacts. It proves that the staged
release graph can attach to the same Nix/Attic substrate as normal CI.
Because this workflow is introduced by the initial implementation PR, GitHub
can dispatch it only after the workflow file exists on `main`.

## GloriousFlywheel Boundary

The normal CI workflow has a GloriousFlywheel cache-first lane on
`tinyland-nix`. Because `GloriousFlywheel` is private, that lane needs
`GF_ACTIONS_TOKEN` to check out the private composite action.

If `GF_ACTIONS_TOKEN` is absent, CI records a token-gated skip instead of
claiming a cache-first proof.

During known lab or runner outages, do not block release staging on a queued
`tinyland-nix` job alone. Use these signals together:

- local `just check`
- local `nix flake check`
- local `just release-proof <version>`
- hosted CI `test`, `nix`, and six cross-compile jobs

Only claim GloriousFlywheel cache-first CI proof when the GF job actually runs
the private action and completes.

Current release evidence:

- PR-head CI run `25031620446` completed `test`, `nix`, all six
  cross-compiles, and real GloriousFlywheel cache-first validation.
- Manual release-proof run `25032112196` completed the real private-action
  cache-first lane from `main` and ran
  `nix develop --command just release-proof-local 0.1.0` on `tinyland-nix`.
- Registry dry-run run `25032112178` completed
  `plan,github,npm,homebrew,system` from `main` without publishing.
- NPM publish workflow run `25032112186` completed from `main` with
  `dry_run=true`; no npm package was published.

## Before Marking A PR Ready

- `just check` passes.
- `just release-proof <version>` produces and smoke-checks the release tree.
- Hosted PR CI passes.
- GF lane either passes or is explicitly deferred because of runner/token state.
- Release notes mention any skipped GF proof.
