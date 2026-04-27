# oauth-mux Release Runbook

Updated: 2026-04-26

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

## Release Workflow

Tags matching `v*` run `.github/workflows/release.yml`.

The workflow calls:

```bash
nix develop --command ./scripts/release-local.sh "${GITHUB_REF_NAME#v}"
```

It uploads the staged `dist/out/` tree, then attaches these files to the GitHub
release:

- `v*/artifacts/*`
- `v*/npm-tarballs/*.tgz`
- `v*/homebrew/oauth-mux.rb`

## GloriousFlywheel Release Proof

`.github/workflows/release-proof.yml` is a manual cache-first proof surface for
the release path. It runs on `tinyland-nix`, checks out the private
GloriousFlywheel action when `GF_ACTIONS_TOKEN` is available, and executes:

```bash
nix develop --command just release-proof-local <version>
```

That workflow does not publish release artifacts. It proves that the staged
release graph can attach to the same Nix/Attic substrate as normal CI.

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
- local `just release-local <version>`
- hosted CI `test`, `nix`, and six cross-compile jobs

Only claim GloriousFlywheel cache-first CI proof when the GF job actually runs
the private action and completes.

## Before Marking A PR Ready

- `just check` passes.
- `just release-proof <version>` produces and smoke-checks the release tree.
- Hosted PR CI passes.
- GF lane either passes or is explicitly deferred because of runner/token state.
- Release notes mention any skipped GF proof.
