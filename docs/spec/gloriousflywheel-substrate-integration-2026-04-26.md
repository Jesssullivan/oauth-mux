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
4. `scripts/e2e-local.sh`

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

## Remote-First Operator Dispatch

Update, 2026-06-03: low-power developer machines should not have to prove the
full repo locally. The repo now exposes an explicit remote validation lane:

- `.github/workflows/remote-validate.yml`
- `scripts/remote-validate.sh`
- `just remote-check`
- `just remote-test`
- `just remote-build`
- `just remote-e2e`
- `just remote-release-proof`

These commands dispatch a `workflow_dispatch` run on `tinyland-nix` and, by
default, watch the resulting GitHub Actions run. The workflow uses the same
private GloriousFlywheel `nix-job` composite action as the cache-first CI lane,
requires `GF_ACTIONS_TOKEN`, requires the Nix/Attic environment variables, and
then runs the existing Just/Zig validation bodies inside `nix develop`.
Because GitHub exposes manual dispatch workflows from the default branch, the
remote validation workflow must land on `main` before branch/SHA validation can
be requested through `just remote-*`.

Update, 2026-06-13: the bare proof entrypoints now dispatch the same remote
lane:

- `just build` -> `just remote-build`
- `just build-release` -> `just remote-build-release`
- `just build-small` -> `just remote-build-small`
- `just test` -> `just remote-test`
- `just check` -> `just remote-check`
- `just e2e` -> `just remote-e2e`
- `just first-run-e2e` -> `just remote-first-run-e2e`
- `just release-proof <version> [ref]` -> remote release proof

Local execution is intentionally explicit through `build-local`, `test-local`,
`check-local`, `e2e-local`, `first-run-e2e-local`, and
`release-proof-local`. Just recipes that need `./zig-out/bin/oauth-mux` still
depend on `build-local`; that is a local debug/build-artifact dependency, not a
proof claim.

This is intentionally remote-first. `just check-local`, `just e2e-local`, and
direct Zig recipes remain available only for narrow local debugging and runner
failure triage. They are not proof gates for PR readiness, release readiness, or
dogfood readiness on developer laptops. Use `just remote-check`,
`just remote-test`, `just remote-build`, `just remote-e2e`, and
`just remote-release-proof` for completion claims.

The remote workflow fails rather than silently falling back when the
GloriousFlywheel action token is absent. A skipped or fallback local run is not
remote validation.

## What This Proves

When `GF_ACTIONS_TOKEN` and the Attic settings are present, this proves that
`oauth-mux` can build and test on the shared GloriousFlywheel Nix runner
substrate with Attic cache attachment.

Current evidence: PR run `25009779392`, job `73266579091`, checked out
`tinyland-inc/GloriousFlywheel`, ran the private `nix-job` action on
`tinyland-nix`, executed `nix develop --command just check-local`, and passed
the deterministic no-secret E2E gate. Cache push was intentionally skipped
because PR events set `push-cache` to `false`.

It does not yet prove:

- cache-first CI execution when the private action checkout token is absent;
- full remote execution for every local developer action;
- Bazel remote-cache behavior, because this repo has no Bazel targets;
- Bazel remote execution, because `oauth-mux` still has no Bazel target graph;
- package publication to npm, Homebrew, deb, rpm, or GitHub Releases;
- live OAuth provider route health, except when explicit operator probe jobs
  are run with real credentials.

It does prove the deterministic no-secret mux E2E path: env injection, command
probe classification, route-scoped fallback, persisted health evidence, and
`exec` target env injection.

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

`just remote-release-proof <ref> <version>` runs the same staging command on the
remote runner and then validates the artifact tree, checksums, archive payloads,
Homebrew rendering, npm install path, installer path, and non-publishing release
handoff generation. The handoff captures GitHub Release attachments, npm publish order,
Homebrew tap input, deb/rpm files, and full checksums under
`dist/out/v<version>/handoff/`.

`.github/workflows/release-proof.yml` exposes this as a manual GloriousFlywheel
proof on `tinyland-nix` through the private `nix-job` action. It is
intentionally manual while runner capacity is expected to be noisy. GitHub can
dispatch it only after the workflow file exists on `main`; run it after this PR
lands and before publishing tags.

The tag release workflow also runs `just release-proof-local` before uploading
the staged artifact tree, so GitHub Release publication is gated by the same
artifact smoke and handoff checks even when the manual self-hosted proof is
deferred.

`just release` runs the single Zig release graph (`zig build release`) rather
than entering the Nix devshell once per target. Per-target Just recipes remain
available for focused iteration.

## Next Integration Gates

1. Turn the generated release handoff into authenticated dry-run lanes for npm,
   Homebrew tap updates, and deb/rpm repository publication.
2. Promote the manual GloriousFlywheel release proof into a required
   pre-publication self-hosted gate once `tinyland-nix` capacity is stable
   enough to block releases on it.
3. Keep Bazel out until there is a real target graph or downstream adoption
   reason. Remote-first validation should ride the existing Just/Nix contract
   first. If Bazel is added later, copy the GloriousFlywheel shape:
   `cache-contract-strict` before any cache-backed Bazel command, and require
   explicit executor-backed evidence before claiming remote execution.
4. Add a scheduled or manual live-provider QA workflow only after secret
   scoping is explicit; route probes spend real subscription calls.
