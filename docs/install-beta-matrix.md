# Install Beta Matrix

Updated: 2026-07-04

This matrix tracks clean-install proof for the public adoption surfaces. It is
operator evidence, not a credential runbook: do not paste OAuth stores, `.env`
files, SOPS plaintext, or token-shaped values here.

The lane contract and current operator rules live in
`docs/release-install-lanes.md`.

npm lane retired 2026-06-12 (TIN-2042); registry intentionally stale at 0.1.9
with a deprecation workflow keeping it dead. There is no npm row in this
matrix and no npm evidence below.

"Pending re-verification at 0.1.14" means the evidence command exists and
targets the current release, but has not been re-run since the v0.1.14 cut.
Do not read that label as a failure; do not read it as a Pass either — run the
matching evidence command and flip it to Pass only after it actually runs
clean.

## Current Status

| Surface | Version | Host | Source | Result | Caveat |
| --- | --- | --- | --- | --- | --- |
| GitHub release tarball | 0.1.14 | macOS arm64 | public `Jesssullivan/oauth-mux` release asset | Pending re-verification at 0.1.14 | Last confirmed Pass was v0.1.7 (release workflow `25980203233`, all tarballs/packages/checksums/formula/installer/handoff published). Re-run the tarball evidence command below against v0.1.14 before calling this row Pass again. |
| `curl \| sh` installer | 0.1.14 | macOS arm64 | public `Jesssullivan/oauth-mux` `install.sh` asset | Pending re-verification at 0.1.14 | Last confirmed Pass was v0.1.7 (installed SHA-256 `42197206aab61c615eb1544acc74630529ba261a792229bf794381044b504cad`). Re-run the installer evidence command below against v0.1.14. |
| Homebrew formula | 0.1.14 | macOS arm64 | public `jesssullivan/omux` tap | Pending re-verification at 0.1.14 | Last confirmed Pass was v0.1.7 (tap PR `Jesssullivan/homebrew-omux#1` merged at `43c32ce`). Re-run `just homebrew-qa 0.1.14` and reconfirm `brew info --json=v2` parses `0.1.14` before calling this row Pass. |
| deb package (nfpm) | 0.1.14 | hosted Linux amd64 container | public GitHub Release `.deb` asset | Pending re-verification at 0.1.14 | Last confirmed Pass was v0.1.7 via System Package Install QA run `25980333371`. Re-run `system-package-install-qa.yml` for v0.1.14 before calling this row Pass. |
| rpm package (nfpm) | 0.1.14 | hosted Linux x86_64 container | public GitHub Release `.rpm` asset | Pending re-verification at 0.1.14 | Last confirmed Pass was v0.1.7 via System Package Install QA run `25980333371`. Re-run `system-package-install-qa.yml` for v0.1.14 before calling this row Pass. |
| nix flake package | 0.1.14 | macOS arm64 | source flake | Pending re-verification at 0.1.14 | Last confirmed Pass was v0.1.7 (`nix eval .#packages.aarch64-darwin.default.version` reported `0.1.7`; `nix flake check` package smoke gate passed). Re-run against v0.1.14 before calling this row Pass. |
| user-local dogfood install | source checkout | macOS arm64 | current worktree staged into `~/.local/bin` | Pass | Installer refuses by default when active managed `oauth-mux codex` sessions are visible, force requires `OMUX_DOGFOOD_ALLOW_ACTIVE_SESSIONS=1`, and default install does not create or replace a `codex` shim. `./zig-out/bin/oauth-mux` and `~/.local/bin/oauth-mux` hashes match. This row is procedure proof, not release-version proof, so it stays current across releases. |
| Codex route dogfood | 0.1.7 | macOS arm64 | installed binary | Historical | (historical snapshot, binary predates v0.1.14) 2026-05-17 diagnostic truth: `codex-max` selected `max-1`, had `max-3` and `max-4` as selectable fallbacks, and blocked `max-2` as `token_revoked`. Current paid-cohort route truth lives in `docs/qa-handoff-matrix.md`; refresh live operator state with `oauth-mux route explain` rather than trusting this row. |
| first-run source e2e | main | macOS arm64 | source checkout | Pass | `just first-run-e2e` runs with temporary HOME/XDG roots and proves no-config `init --codex-max`, JSON diagnostics, runtime diagnostics, redacted report, diagnostic route explanation/select refusal, and non-mutating Codex help. This row is procedure proof, not release-version proof. |

## Evidence Commands

Raw release tarball:

```bash
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/oauth-mux-aarch64-macos.tar.gz" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.14/oauth-mux-aarch64-macos.tar.gz
curl -fsSL -o "$tmp/SHA256SUMS" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.14/SHA256SUMS
(cd "$tmp" && shasum -a 256 -c --ignore-missing SHA256SUMS)
tar -xzf "$tmp/oauth-mux-aarch64-macos.tar.gz" -C "$tmp"
"$tmp/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux-aarch64-macos.tar.gz: OK
oauth-mux 0.1.14
```

Public installer for v0.1.14:

```bash
tmp="$(mktemp -d)"
VERSION=0.1.14 \
INSTALL_DIR="$tmp/bin" \
  sh -c 'curl -fsSL https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.14/install.sh | sh'
"$tmp/bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.14
```

Homebrew tap install:

```bash
just homebrew-qa 0.1.14
```

Expected output includes:

```text
Homebrew install QA passed for oauth-mux 0.1.14 via jesssullivan/omux/oauth-mux
```

Homebrew metadata check:

```bash
brew info jesssullivan/omux/oauth-mux --json=v2
```

For the current public tap, both the installed keg and
`formulae[0].versions.stable` should report `0.1.14` once the tap update is
verified. Treat a mismatch as a release metadata defect even if the binary
itself runs.

First-run source e2e:

```bash
just first-run-e2e
```

Expected output includes:

```text
first-run e2e: route explain reports no recorded health without mutation
first-run e2e: route select refuses unrecorded health evidence
first-run e2e: runtime doctor classifies unbootstrapped stores without mutation
first-run e2e passed
```

To keep the formula installed after dogfood QA:

```bash
OMUX_HOMEBREW_KEEP_INSTALLED=1 OMUX_HOMEBREW_KEEP_TAP=1 just homebrew-qa 0.1.14
```

To include the starter Codex canary from the installed Homebrew binary:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
OMUX_STATE_DIR=/tmp/oauth-mux-brew-codex-live \
OMUX_HOMEBREW_KEEP_INSTALLED=1 \
OMUX_HOMEBREW_KEEP_TAP=1 \
OMUX_HOMEBREW_CODEX_CANARY=1 \
OMUX_HOMEBREW_CODEX_LIVE=1 \
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
  just homebrew-qa 0.1.14
```

Latest local Homebrew dogfood proof (historical snapshot, binary predates
v0.1.14 — not yet re-run at 0.1.14):

```text
brew uninstall oauth-mux: pass
brew untap jesssullivan/omux: pass
brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git: pass
brew install jesssullivan/omux/oauth-mux: pass
brew audit --formula --strict jesssullivan/omux/oauth-mux: pass
brew test jesssullivan/omux/oauth-mux: pass
/opt/homebrew/bin/oauth-mux version: oauth-mux 0.1.7
/opt/homebrew/bin/oauth-mux doctor --json: ok
Public tap repository: `Jesssullivan/homebrew-omux`, default branch `main`.
Public tap PR `Jesssullivan/homebrew-omux#1`: merged at `43c32ce`.
Clean local QA installed from `https://github.com/Jesssullivan/homebrew-omux.git`
and passed audit, parsed stable-version check, install, test, `version`, and
`doctor --json`.
```

Latest private/staged Homebrew proof (historical snapshot, binary predates
v0.1.14 — not yet re-run at 0.1.14):

```text
brew tap tinyland/tools https://github.com/tinyland-inc/homebrew-tools.git: pass
brew install tinyland/tools/oauth-mux: pass
brew audit --formula --strict tinyland/tools/oauth-mux: pass
brew test tinyland/tools/oauth-mux: pass
/opt/homebrew/bin/oauth-mux version: oauth-mux 0.1.6
/opt/homebrew/bin/oauth-mux doctor --json: ok
Production tap PR `tinyland-inc/homebrew-tools#4` merged at `f3016e3`.
```

Current paid-cohort route truth is tracked in `docs/qa-handoff-matrix.md`.
Refresh live operator state with `oauth-mux route explain` rather than copying
time-sensitive account availability into this install matrix.

System package install QA after GitHub Release publication:

```bash
gh workflow run system-package-install-qa.yml -f version=0.1.14
```

Latest hosted proof (historical snapshot, binary predates v0.1.14 — not yet
re-run at 0.1.14):

```text
System Package Install QA run 25980333371: pass
job 76367854350: deb/rpm install from published release assets
```

Local reproduction on a host with healthy Docker:

```bash
just system-package-qa 0.1.14
```

## Next Proof

1. Keep the hosted system-package install QA workflow in the release checklist.
2. For each release that changes deb/rpm packaging, run the workflow after the
   GitHub Release assets exist.
3. Treat registry metadata checks as insufficient without this install proof.
4. Keep Homebrew release updates derived from public GitHub Release
   `oauth-mux.rb` and `SHA256SUMS`, then rerun `just homebrew-qa <version>`
   against the public `jesssullivan/omux` tap.
5. Require the Homebrew parsed stable version to match the release version
   before calling a tap update complete.
6. Re-run every "Pending re-verification at 0.1.14" evidence command above and
   flip its row to Pass only after that exact command has actually run clean
   against v0.1.14.
