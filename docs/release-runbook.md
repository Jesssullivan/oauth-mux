# oauth-mux Release Runbook

Updated: 2026-05-09

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

Run the flake package smoke separately when changing packaging or release
surfaces:

```bash
XDG_CACHE_HOME=/tmp/oauth-mux-nix-cache nix flake check
```

That check proves the Nix package runs, reports the source version, and validates
no-secret examples. It is intentionally smaller than `just check`.

The lane-level source of truth for installer, package, and local dogfood
provenance is `docs/release-install-lanes.md`.

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
version="$(scripts/project-version.sh)"
just release-local "$version"
```

This runs the single Zig release graph and stages artifacts under
`dist/out/v<version>/`.

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

`release-local` performs a host-resource preflight before deleting or staging
`dist/out/v<version>`. By default it requires at least 12 GiB free on the repo
filesystem. On hosts with less than 12 GiB RAM, it constrains Zig release
compilation with `-j2` unless `OMUX_RELEASE_ZIG_JOBS` is already set. This is
intentional: the six-target ReleaseSafe graph can look like a shell hang on
low-disk, memory-compressed dogfood machines.

Useful overrides:

- `OMUX_RELEASE_PREFLIGHT_ONLY=1 scripts/release-local.sh <version>` checks the
  host without mutating release output.
- `OMUX_RELEASE_ALLOW_LOW_DISK=1` continues despite the disk warning.
- `OMUX_RELEASE_MIN_FREE_KIB=<kib>` changes the free-space threshold.
- `OMUX_RELEASE_ZIG_JOBS=<n>` sets Zig release concurrency explicitly.
- `OMUX_RELEASE_SKIP_PREFLIGHT=1` disables the host-resource guard.

Run the full build-plus-smoke proof:

```bash
version="$(scripts/project-version.sh)"
just release-proof "$version"
```

This runs `release-local` and then checks:

- required binary tarballs, debs, rpms, npm tarballs, and Homebrew formula
- `SHA256SUMS` against the artifact directory
- tarball payload names for Unix and Windows targets
- rendered Homebrew formula placeholders and Ruby syntax when Ruby is present
- rendered Homebrew formula explicit version metadata
- local npm install of the matching platform package plus root shim
- local installer execution against the staged artifact directory
- non-publishing release handoff generation

The release scripts set an isolated npm cache for packing, dry-run, publish, and
deprecation operations. A broken workstation `~/.npm` cache must not change
release proof results.

Generate only the handoff for an already staged tree:

```bash
version="$(scripts/project-version.sh)"
just release-handoff "$version"
```

This validates the staged publication inputs and writes:

- `dist/out/v<version>/handoff/release-handoff.md`
- `dist/out/v<version>/handoff/publish-files.txt`
- `dist/out/v<version>/handoff/SHA256SUMS.full`

The handoff lists GitHub Release attachments, npm publish order, Homebrew tap
input, deb/rpm files, and full checksums. It does not use registry credentials
or publish anything.

npm publication is intentionally separate and CI-only. Use
`.github/workflows/npm-publish.yml`; it reuses the release derivation, resolves
auth at runtime, and publishes only the generated tarballs. Keep npm provenance
enabled when the source repository is public; npm rejects GitHub Actions
provenance from private repositories. Do not publish npm packages from a
workstation.

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

## System Package Install QA

After the GitHub Release exists, run the hosted system-package install proof:

```bash
gh workflow run system-package-install-qa.yml -f version=<version>
```

This workflow downloads the published `.deb` and `.rpm` release assets, verifies
them against the published `SHA256SUMS`, installs them in clean Debian and Rocky
Linux containers on `ubuntu-latest`, and runs `/usr/bin/oauth-mux version`.

For local reproduction on a healthy Docker-compatible host:

```bash
just system-package-qa <version>
```

This is stricter than the registry `system` dry-run lane. The dry-run lane
checks package metadata and release staging; this install QA proves that the
published packages can be installed and execute from the system path.

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
- Main CI run `25032478278` completed `test`, `nix`, all six cross-compiles,
  and real GloriousFlywheel cache-first validation after the evidence docs
  merged.
- Release workflow run `25195318899` published v0.1.6 GitHub Release assets:
  tarballs, npm package bundles, deb/rpm packages, formula, installer, and
  checksums.
- Registry dry-run run `25195456326` completed
  `plan,github,npm,homebrew,system` for v0.1.6 without mutating registries.
- System Package Install QA run `25195456319` completed for v0.1.6 and proved
  published `.deb` and `.rpm` assets install in hosted Debian/Rocky containers
  and execute `/usr/bin/oauth-mux version`.
- Homebrew tap PR `tinyland-inc/homebrew-tools#4` updated `tinyland/tools` to
  v0.1.6; `just homebrew-qa 0.1.6` passed against the production tap.
- Public Homebrew tap `Jesssullivan/homebrew-omux` now serves
  `jesssullivan/omux/oauth-mux` v0.1.6; strict local QA removed the prior
  install/tap and `just homebrew-qa 0.1.6` passed against the public tap.
- Registry dry-run run `25199131583` completed the Homebrew lane against the
  public `Jesssullivan/homebrew-omux` tap checkout.
- NPM publish workflow run `25195456341` completed from `main` with
  `dry_run=true` for v0.1.6.
- NPM publish workflow run `25195609579` published v0.1.6 through the CI-only
  SOPS-backed path; `npm view oauth-mux version` reports `0.1.6`.
- Main CI run `25954361661` completed successfully on 2026-05-16 for the latest
  checked `main` state before the `0.1.7` release-parity tranche.
- Hosted GloriousFlywheel release proof run `25979637380` passed for `0.1.7`.
- Hosted registry dry-run run `25979761165` passed for `0.1.7` lanes
  `plan,github,system`.
- Release workflow run `25980203233` published the latest `v0.1.7` GitHub
  Release assets from commit `6838db5`.
- System Package Install QA run `25980333371` passed for published `0.1.7`
  `.deb` and `.rpm` assets.
- NPM publish dry-run `25980347239` passed for all seven `0.1.7` packages, then
  NPM publish run `25980468974` published all seven packages with provenance
  disabled for the private-source release path.
- Public npm verification confirms `oauth-mux@0.1.7` and all six platform
  packages resolve; temp-prefix npm install and `npx -y oauth-mux@0.1.7`
  both return `oauth-mux 0.1.7`.
- Public Homebrew tap PR `Jesssullivan/homebrew-omux#1` updated the formula
  from the `v0.1.7` GitHub Release asset and merged at `43c32ce`; clean
  public tap QA passed with installed binary `oauth-mux 0.1.7` and parsed
  stable version `0.1.7`.

## Before Marking A PR Ready

- `just check` passes.
- `just release-proof <version>` produces and smoke-checks the release tree.
- `nix flake check` passes, preferably with an isolated cache such as
  `XDG_CACHE_HOME=/tmp/oauth-mux-nix-cache` on sandboxed agent hosts.
- Hosted `System Package Install QA` passes after release assets exist when the
  release changes deb/rpm packaging.
- Homebrew QA proves both binary output and parsed formula stable version.
- Hosted PR CI passes.
- GF lane either passes or is explicitly deferred because of runner/token state.
- Release notes mention any skipped GF proof.
