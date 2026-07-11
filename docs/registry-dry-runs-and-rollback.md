# Registry Dry-Runs and Rollback

Registry publication is intentionally separate from release artifact proof.
`just remote-release-proof <ref> <version>` proves the release tree and handoff
without publication credentials on the remote runner. Authenticated registry
dry-runs are CI/operator gates and non-publishing.
For the DRY lane map across worktree, Nix, GitHub Release, Homebrew,
curl, deb, and rpm installers, see `docs/release-install-lanes.md`.

npm publication is retired (operator decision 2026-06-12, TIN-2042). Release
staging and registry dry-runs exclude npm. `.github/workflows/npm-deprecate.yml`
remains as a manual deprecation-only keeper for already-published versions.

## Dry-Run

Stage and prove artifacts:

```bash
version="$(scripts/project-version.sh)"
ref="$(git rev-parse --abbrev-ref HEAD)"
just remote-release-proof "$ref" "$version"
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
OMUX_REGISTRY_LANES=github,homebrew,system \
OMUX_HOMEBREW_TAP_DIR=/path/to/homebrew-tap \
just registry-dry-run "$version"
```

The script writes `dist/out/v<version>/handoff/registry-dry-run.md`.

## GitHub Workflow

`.github/workflows/registry-dry-run.yml` is manual-only. It requires
`confirm=registry-dry-run`. It stages the release through
`just release-proof-local <version>` and then runs selected dry-run lanes.

Required secret and variable surfaces:

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

The workflow resolves npm auth through its SOPS/token inputs. Set
`plan_only=false` only after the uploaded `npm-ci-deprecate.md` plan names
exactly the versions to deprecate.

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
3. Re-run `just remote-release-proof <ref> <version>` before publishing a
   replacement.

npm (RETIRED lane; kept for historical/orientation value only — do not
publish):

1. Prefer deprecating bad packages over unpublish after the npm unpublish
   window or when downstream consumers may already depend on them.
2. Deprecate platform packages and the root shim with the same message using
   `.github/workflows/npm-deprecate.yml`, the one surviving live npm action.
3. Do not publish a fixed patch version to npm; the lane is retired
   (TIN-2042). Ship the fix through the non-npm lanes instead.

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
