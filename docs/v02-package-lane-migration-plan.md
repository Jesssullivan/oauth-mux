# v0.2 Package-Lane Migration Plan (TIN-2799 / TIN-2050)

Updated: 2026-08-28

Status: planning/scoping only. No release pipeline code changes are made by
this document. It exists so the remaining TIN-2799/TIN-2050 acceptance items
have an exact, reviewable implementation plan instead of an open-ended gap.

## What already lands the v0.2 naming contract

* The Zig build already emits `zig-out/<target>/omux` as primary, with
  `oauth-mux` a byte-identical compatibility entrypoint
  (`scripts/test-executable-compat.sh`).
* `scripts/install-local-dogfood.sh` / `scripts/uninstall-local-dogfood.sh`
  already install and remove both names transactionally, including a PATH
  shadow warning and dangling-entry cleanup
  (`scripts/test-executable-compat.sh` proves install then uninstall leaves
  neither `omux` nor `oauth-mux` behind).
* `release-manifest.json` already declares the target shape:
  `product.compatibility_links`, and every `release_assets[].declared_v0_2_members`
  entry already lists `["omux", "oauth-mux"]` (or the `.exe` pair) per asset.
* `test/release_manifest_readiness_root.zig` already proves the *schema* for
  `compatibility_links` rejects drift and duplicates.

## What is genuinely still pending (the real TIN-2799/TIN-2050 gap)

Every packaged consumer lane still reads the **v0.1.15 projection**
(`current_v0_1_15_members`), not the **v0.2 projection**
(`declared_v0_2_members`), of `release-manifest.json`. Concretely:

1. `scripts/release-manifest-current.sh` — `release_manifest_archive_rows`
   and `release_manifest_package_rows` project `current_v0_1_15_members`
   only. There is no `release_manifest_v02_archive_rows` /
   `release_manifest_v02_package_rows` sibling that projects
   `declared_v0_2_members`.
2. `scripts/release-local.sh` — `package_archive()` and
   `write_nfpm_config()` special-case exactly two member names
   (`oauth-mux`/`oauth-mux.exe` and `codex`); neither has an `omux` case, so
   pointing them at `declared_v0_2_members` today would fail closed with
   "unsupported current archive member: omux" rather than silently
   mis-package.
3. `dist/homebrew/oauth-mux.rb` — `install` only does `bin.install
   "oauth-mux"`; it has no `omux` primary + `oauth-mux` compatibility-link
   install step, and `scripts/homebrew-install-qa.sh` only asserts the
   single `oauth-mux` binary and explicitly asserts `codex` is *absent*
   (correct for `codex`, silent on `omux`).
4. `dist/install.sh` — downloads `oauth-mux`/`codex` by fixed name from the
   v0.1.15 archive layout; it has no `omux` primary install step or
   compatibility-link creation, unlike the local dogfood installer it was
   forked from.
5. `scripts/release-local.sh` opens with
   `release_manifest_require_current_v0_1_15 "$version"` — a fail-closed
   guard that intentionally keeps this whole script pinned to the old
   projection today. **Do not remove or weaken this guard as a side effect
   of wiring v0.2 consumers.** The correct shape is additive: a new,
   separately-gated v0.2 packaging path (own script or an explicit
   `--projection=v0.2` mode), proven by its own smoke test, that this guard
   continues to block from `release-local.sh`'s existing v0.1.15 path until
   an operator explicitly flips it. Collapsing the two projections into one
   ungated code path is the failure mode this plan is written to avoid.

## Proposed implementation shape (for the next focused session)

1. Add `release_manifest_v02_archive_rows` / `release_manifest_v02_package_rows`
   to `scripts/release-manifest-current.sh`, projecting
   `declared_v0_2_members` with the same TSV shape the v0.1.15 rows already
   use, so callers stay diffable against the existing functions.
2. Add `omux`/`omux.exe` cases to `package_archive()` and
   `write_nfpm_config()` (or their v0.2-path equivalents) that stage the
   built `omux` binary as the primary member and materialize `oauth-mux` as
   the declared compatibility link (`same_bytes`, matching
   `product.compatibility_links[0].materialization`) rather than a second
   independent copy — mirroring how `install-local-dogfood.sh` already
   treats the pair.
3. Extend `dist/homebrew/oauth-mux.rb`'s `install` to
   `bin.install "omux"` then create the `oauth-mux` compatibility symlink,
   and extend `scripts/homebrew-install-qa.sh` to assert both entrypoints
   report matching identity (same pattern as
   `scripts/test-executable-compat.sh`) while still asserting no `codex`
   shim is linked.
4. Extend `dist/install.sh` to install `omux` plus the `oauth-mux`
   compatibility link (symlink, not a second download), matching the
   archive's `declared_v0_2_members` shape once step 2 lands.
5. Add upgrade/uninstall dangling-binary QA for the *package* lanes
   (Homebrew reinstall-at-new-version, deb/rpm upgrade via `dpkg -i`/`rpm
   -U`) parallel to the source-lane proof `test-executable-compat.sh`
   already provides, so TIN-2799's "leaves no dangling duplicate binary"
   acceptance item is proven for every consumer, not only the dogfood lane.
6. Only after 1-5 pass their own smokes, decide (as an explicit operator
   step, not implied by this plan) whether/when
   `release_manifest_require_current_v0_1_15` in `release-local.sh` is
   replaced or given a v0.2 sibling gate.

## Why this session did not implement 1-5 directly

Steps 1-4 touch the actual release/package pipeline
(`scripts/release-local.sh`, the Homebrew formula, and the curl installer)
that ships real binaries to real users, and their correctness can only be
proven by running `zig build release`, `nfpm package`, and a live `brew
install` — none of which a source-only review pass can execute or verify.
Given the explicit `release_manifest_require_current_v0_1_15` staging guard
already in place, blind edits here risk silently contradicting a deliberate
migration sequence rather than advancing it. This plan exists so that work
is a bounded, reviewable diff instead of a redo of this investigation.
