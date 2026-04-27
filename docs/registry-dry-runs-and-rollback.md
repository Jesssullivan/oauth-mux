# Registry Dry-Runs and Rollback

Registry publication is intentionally separate from release artifact proof.
`just release-proof <version>` proves the release tree and handoff without
publication credentials. Authenticated registry dry-runs are CI/operator gates
and non-publishing.

npm publication is CI-only. Do not run `npm publish` from a workstation. The
publish workflow stages the same release derivation, then publishes the
generated tarballs with npm provenance.

## Dry-Run

Stage and prove artifacts:

```bash
just release-proof 0.1.0
```

Run a plan-only dry-run report:

```bash
OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run \
OMUX_REGISTRY_LANES=plan \
just registry-dry-run 0.1.0
```

Run authenticated lanes:

```bash
OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run \
OMUX_REGISTRY_LANES=github,npm,homebrew,system \
NPM_TOKEN_FILE=/path/to/npm-token \
OMUX_HOMEBREW_TAP_DIR=/path/to/homebrew-tap \
just registry-dry-run 0.1.0
```

The npm dry-run lane resolves auth in this order: `NPM_TOKEN`,
`NODE_AUTH_TOKEN`, `NPM_TOKEN_FILE`, `NODE_AUTH_TOKEN_FILE`, then
`OMUX_NPM_TOKEN_SOPS_FILE` with `OMUX_NPM_TOKEN_SOPS_KEY`. The default SOPS key
candidate is `.api.npm_token`.

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
- The default workflow `GITHUB_TOKEN` for the GitHub lane.

## npm Publish

`.github/workflows/npm-publish.yml` is the only supported npm mutation path. It
requires `confirm=publish-npm`, stages `just release-proof-local <version>`, and
then publishes the generated tarballs in this order:

1. `@oauth-mux/linux-x64`
2. `@oauth-mux/linux-arm64`
3. `@oauth-mux/darwin-x64`
4. `@oauth-mux/darwin-arm64`
5. `@oauth-mux/win32-x64`
6. `@oauth-mux/win32-arm64`
7. `oauth-mux`

The workflow requests `id-token: write` so `npm publish --provenance` can attach
GitHub Actions provenance. Keep `dry_run=true` for the first authenticated
execution. Set `dry_run=false` only for the actual release publication.

The publish script is idempotent by default: if `package@version` already exists
on npm, it records a skip instead of overwriting or republishing.

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
