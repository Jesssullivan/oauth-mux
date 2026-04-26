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
- action: `tinyland-inc/GloriousFlywheel/.github/actions/nix-job@main`
- required runtime evidence: `ATTIC_SERVER`, `ATTIC_CACHE`, and `NIX_CONFIG`
- command: `nix develop --command just check-local`

The existing GitHub-hosted lane remains as a portability check. It still builds
and tests with Zig directly, and now validates all example configs too.

## What This Proves

This proves that `oauth-mux` can build and test on the shared
GloriousFlywheel Nix runner substrate with Attic cache attachment.

It does not yet prove:

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

This is still artifact-build plumbing. The next release arc is to generate
tarballs, checksums, npm platform packages, Homebrew formula updates, and
nfpm deb/rpm packages from one version input.

`just release` runs the single Zig release graph (`zig build release`) rather
than entering the Nix devshell once per target. Per-target Just recipes remain
available for focused iteration.

## Next Integration Gates

1. Add a `release-local` recipe that emits all release archives and checksums
   from one version input.
2. Add a GloriousFlywheel-backed release proof job that runs on `tinyland-nix`
   before tag publication.
3. Keep Bazel out until there is a real target graph or downstream adoption
   reason; if added later, copy the GloriousFlywheel shape:
   `cache-contract-strict` before any cache-backed Bazel command.
4. Add a scheduled or manual live-provider QA workflow only after secret
   scoping is explicit; route probes spend real subscription calls.
