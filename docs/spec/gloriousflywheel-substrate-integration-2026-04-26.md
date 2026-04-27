# GloriousFlywheel Substrate Integration

Updated: 2026-04-26

This records how `oauth-mux` attaches to the house remote runner and cache
substrate without importing unrelated build-system weight.

## Source Contract

The read-only source for this pass was sibling repo `../GloriousFlywheel`.
Its current contract is:

- use capability-shaped runner labels such as `tinyland-nix`, not
  project-specific runner labels;
- attach local and CI work to the same Nix/devshell substrate where possible;
- treat Attic and Bazel remote cache as acceleration layers, not publication
  authority;
- be explicit when a path proves cache-backed execution rather than full remote
  execution or universal remote builder offload;
- for Bazel repos, verify the strict cache contract before invoking Bazel.

`oauth-mux` is Zig-only today. It has no Bazel target graph, so the first
integration point is the Nix/Attic runner path, not a Bazel wrapper.

## Applied Shape

`just check` remains the operator entrypoint. It now enters the Nix devshell
and delegates the validation body to `just check-local`.

`just check-local` is the devshell-local validation body:

1. `zig build test`
2. `zig build`
3. validate every `examples/*.config.json`

This split gives local operators and remote CI the same test body while letting
GloriousFlywheel jobs enter the devshell once and run the local check directly.

The CI workflow now has a cache-first lane:

- runner: `tinyland-nix`
- action source: private checkout of
  `tinyland-inc/GloriousFlywheel/.github/actions/nix-job`
- required runtime evidence: `ATTIC_SERVER`, `ATTIC_CACHE`, and `NIX_CONFIG`
- command: `nix develop --command just check-local`

Because `GloriousFlywheel` is private, `oauth-mux` does not reference the
cross-repo composite action directly. The workflow checks out the substrate repo
into `.gloriousflywheel` with `GF_ACTIONS_TOKEN` and then uses the local
composite action path. If `GF_ACTIONS_TOKEN` is not configured, the job records
that the cache-first proof was skipped rather than failing before any useful
diagnostics can run.

The existing GitHub-hosted lane remains as a portability check. It still builds
and tests with Zig directly, and now validates all example configs too.

## What This Proves

When `GF_ACTIONS_TOKEN` and the Attic settings are present, this proves that
`oauth-mux` can build and test on the shared GloriousFlywheel Nix runner
substrate with Attic cache attachment.

It does not yet prove:

- cache-first CI execution when the private action checkout token is absent;
- full remote execution for every local developer action;
- Bazel remote-cache behavior, because this repo has no Bazel targets;
- package publication to npm, Homebrew, deb, rpm, or GitHub Releases;
- live OAuth provider route health, except when explicit operator probe jobs
  are run with real credentials.

## Release Tie-In

CI and release target matrices now match the repo contract:

- `x86_64-linux-musl`
- `aarch64-linux-musl`
- `x86_64-macos`
- `aarch64-macos`
- `x86_64-windows`
- `aarch64-windows`

`just release-local <version>` now stages release artifacts from one version
input:

- binary tarballs and `SHA256SUMS`
- checksum-verifying `install.sh` for `curl | sh`
- rendered Homebrew formula
- npm package workspace and npm tarballs
- nfpm configs and deb/rpm artifacts

`just release-proof <version>` runs the same staging command and then validates
the artifact tree, checksums, archive payloads, Homebrew rendering, local npm
install path, and local installer path. `.github/workflows/release-proof.yml`
exposes this as a manual GloriousFlywheel proof on `tinyland-nix` through the
private `nix-job` action. It is intentionally manual while runner capacity is
expected to be noisy.

`just release` runs the single Zig release graph (`zig build release`) rather
than entering the Nix devshell once per target. Per-target Just recipes remain
available for focused iteration.

## Next Integration Gates

1. Promote the manual GloriousFlywheel release proof into a required pre-tag
   publication gate once `tinyland-nix` capacity is stable enough to block
   releases on it.
2. Keep Bazel out until there is a real target graph or downstream adoption
   reason; if added later, copy the GloriousFlywheel shape:
   `cache-contract-strict` before any cache-backed Bazel command.
3. Add a scheduled or manual live-provider QA workflow only after secret
   scoping is explicit; route probes spend real subscription calls.
