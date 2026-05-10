# Registry Dry-Runs and Rollback

Registry publication is intentionally separate from release artifact proof.
`just release-proof <version>` proves the release tree and handoff without
publication credentials. Authenticated registry dry-runs are CI/operator gates
and non-publishing.
For the DRY lane map across worktree, Nix, GitHub Release, npm, Homebrew,
curl, deb, and rpm installers, see `docs/release-install-lanes.md`.

npm publication is CI-only. Do not run `npm publish` from a workstation. The
publish workflow stages the same release derivation, then publishes the
generated tarballs. npm provenance is enabled by default and requires a public
source repository.

## Dry-Run

Stage and prove artifacts:

```bash
version="$(scripts/project-version.sh)"
just release-proof "$version"
```

Run a plan-only dry-run report:

```bash
version="$(scripts/project-version.sh)"
OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run \
OMUX_REGISTRY_LANES=plan \
just registry-dry-run "$version"
```

Run authenticated lanes:

```bash
version="$(scripts/project-version.sh)"
OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run \
OMUX_REGISTRY_LANES=github,npm,homebrew,system \
NPM_TOKEN_FILE=/path/to/npm-token \
OMUX_HOMEBREW_TAP_DIR=/path/to/homebrew-tap \
just registry-dry-run "$version"
```

The npm dry-run lane resolves auth in this order: `NPM_TOKEN`,
`NODE_AUTH_TOKEN`, `NPM_TOKEN_FILE`, `NODE_AUTH_TOKEN_FILE`, then
`OMUX_NPM_TOKEN_SOPS_FILE` with `OMUX_NPM_TOKEN_SOPS_KEY`. The default SOPS key
candidate is `.api.npm_token`.

Before publication, the npm lane expects `npm publish --dry-run` to succeed for
each staged tarball. After publication, npm rejects dry-runs for an existing
`package@version`; the lane treats that as OK only when `npm view` confirms the
exact published version.

The script writes `dist/out/v<version>/handoff/registry-dry-run.md`.

## GitHub Workflow

`.github/workflows/registry-dry-run.yml` is manual-only. It requires
`confirm=registry-dry-run`. It stages the release through
`just release-proof-local <version>` and then runs selected dry-run lanes.

Required secret and variable surfaces:

- `NPM_TOKEN` for the npm lane, or SOPS inputs:
  `OMUX_GLOBAL_SOPS_B64` plus `SOPS_AGE_KEY`, or
  `OMUX_GLOBAL_SOPS_REPOSITORY` plus `OMUX_GLOBAL_SOPS_FILE` and `SOPS_AGE_KEY`.
- `OMUX_NPM_TOKEN_SOPS_KEY` repository variable when the npm token is not at
  `.api.npm_token`.
- `OMUX_HOMEBREW_TAP_DIR` repository variable for the Homebrew lane when a tap
  checkout is available in the runner environment.
- `OMUX_HOMEBREW_TAP_REPOSITORY` plus optional `OMUX_HOMEBREW_TAP_REF` when
  the workflow should check out the tap before the Homebrew lane.
- `OMUX_HOMEBREW_TAP_NAME` when Homebrew requires auditing by tap/formula name
  instead of by formula path. Public release dry-runs should use
  `jesssullivan/omux`; `tinyland/tools` is the private staged tap.
- `OMUX_BREW_BIN` when the Homebrew executable is not available as `brew`.
  The GitHub workflow installs Homebrew on Ubuntu and sets this automatically.
- `OMUX_HOMEBREW_AUDIT_ONLINE=1` only after the homepage and release URLs are
  publicly reachable. Pre-release dry-runs use strict offline audit because the
  release artifacts are intentionally not published yet.
- The default workflow `GITHUB_TOKEN` for the GitHub lane.

## npm Publish

`.github/workflows/npm-publish.yml` is the only supported npm mutation path. It
requires `confirm=publish-npm`, stages `just release-proof-local <version>`, and
then publishes the generated tarballs in this order:

1. `oauth-mux-linux-x64`
2. `oauth-mux-linux-arm64`
3. `oauth-mux-darwin-x64`
4. `oauth-mux-darwin-arm64`
5. `oauth-mux-windows-x64`
6. `oauth-mux-windows-arm64`
7. `oauth-mux`

The workflow requests `id-token: write` so
`npm publish --provenance --access public` can attach GitHub Actions
provenance. npm only accepts GitHub Actions provenance from public source
repositories. If the repository is still private at publication time, either
make the source repository public before publishing or set `provenance=false`
after explicitly accepting a no-provenance npm release. Keep `dry_run=true` for
the first authenticated execution. Set `dry_run=false` only for the actual
release publication.

The publish script is idempotent by default: if `package@version` already exists
on npm, it records a skip instead of overwriting or republishing.

## npm Deprecation

`.github/workflows/npm-deprecate.yml` is the only supported npm deprecation
mutation path. It requires `confirm=deprecate-npm` and defaults to
`plan_only=true`.

The default target is the orphaned partial `0.1.1` platform package set from the
failed first publication attempt:

1. `oauth-mux-linux-x64@0.1.1`
2. `oauth-mux-linux-arm64@0.1.1`
3. `oauth-mux-darwin-x64@0.1.1`
4. `oauth-mux-darwin-arm64@0.1.1`

Run the plan locally or in CI before mutating npm:

```bash
just npm-deprecate-plan 0.1.1
```

The workflow resolves npm auth through the same SOPS/token surfaces as the
publish workflow. Set `plan_only=false` only after the uploaded
`npm-ci-deprecate.md` plan names exactly the versions to deprecate.

Evidence for the `0.1.1` cleanup:

- Plan-only workflow run `25074614756` targeted only the four orphaned
  `0.1.1` platform packages listed above.
- Mutation workflow run `25074691124` deprecated those four package versions
  with the message:
  `oauth-mux 0.1.1 platform package was orphaned by a failed release. Use oauth-mux@0.1.2 or newer.`
- Public npm metadata checks confirmed the deprecation message on all four
  package versions and confirmed `oauth-mux@0.1.1` remains unpublished.

## Rollback

GitHub Release:

1. Delete or mark the bad release as draft.
2. Delete the tag only after consumers are notified.
3. Re-run `just release-proof <version>` before publishing a replacement.

npm:

1. Prefer deprecating bad packages over unpublish after the npm unpublish
   window or when downstream consumers may already depend on them.
2. Deprecate platform packages and the root shim with the same message.
3. Publish a fixed patch version.

Homebrew:

1. Revert the tap formula commit.
2. Run `brew audit` against the reverted formula.
3. Publish a fixed formula commit with new checksums.

deb/rpm:

1. Remove the bad package from repository metadata or mark it superseded.
2. Rebuild repository metadata.
3. Publish a fixed package with a higher version or release number.

curl installer:

1. Do not mutate a published artifact in place.
2. Publish a corrected version and checksum set.
3. Keep old checksums in release notes for forensic comparison.

Rollback must be documented in the release notes for any public publication
mistake.
