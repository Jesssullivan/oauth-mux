# Install Beta Matrix

Updated: 2026-05-17

This matrix tracks clean-install proof for the public adoption surfaces. It is
operator evidence, not a credential runbook: do not paste OAuth stores, `.env`
files, SOPS plaintext, or token-shaped values here.

The lane contract and current operator rules live in
`docs/release-install-lanes.md`.

## Current Status

| Surface | Version | Host | Source | Result | Caveat |
| --- | --- | --- | --- | --- | --- |
| npm global install | 0.1.7 | macOS arm64 | public npm registry | Pass | Public registry reports `oauth-mux@0.1.7` plus all six platform packages; temp-prefix global install returns `oauth-mux 0.1.7`. |
| npm one-shot | 0.1.7 | macOS arm64 | public npm registry | Pass | `npx -y oauth-mux@0.1.7 version` returns `oauth-mux 0.1.7`; `doctor --json` reports `ok:true`. |
| user-local dogfood install | source checkout | macOS arm64 | current worktree copied to `~/.local/bin` | Pass | Remove the old installed file before copying; `./zig-out/bin/oauth-mux` and `~/.local/bin/oauth-mux` hashes match. Use this lane only for unreleased installed-command dogfood. |
| Nix package | 0.1.7 | macOS arm64 | source flake | Pass | `nix eval .#packages.aarch64-darwin.default.version` reports `0.1.7`; `nix flake check` includes a package smoke gate. |
| GitHub release tarball | 0.1.7 | macOS arm64 | public `Jesssullivan/oauth-mux` release asset | Pass | Release workflow `25980203233` published all tarballs, packages, checksums, formula, installer, and handoff files. |
| `curl | sh` installer | 0.1.7 | macOS arm64 | public `Jesssullivan/oauth-mux` `install.sh` asset | Pass | Public installer installed `oauth-mux 0.1.7`; installed binary SHA-256 was `42197206aab61c615eb1544acc74630529ba261a792229bf794381044b504cad`. |
| Homebrew formula | 0.1.7 | macOS arm64 | public `jesssullivan/omux` tap | Pass | Public tap PR `Jesssullivan/homebrew-omux#1` updated the formula from the GitHub Release asset; clean QA installed `oauth-mux 0.1.7` and `brew info --json=v2` reports stable `0.1.7`. |
| deb package | 0.1.7 | hosted Linux amd64 container | public GitHub Release `.deb` asset | Pass | System Package Install QA run `25980333371` installed package and ran `/usr/bin/oauth-mux version`. |
| rpm package | 0.1.7 | hosted Linux x86_64 container | public GitHub Release `.rpm` asset | Pass | System Package Install QA run `25980333371` installed package and ran `/usr/bin/oauth-mux version`. |
| Codex route dogfood | 0.1.7 | macOS arm64 | installed binary | Pass with four selectable routes | Current 2026-05-16 no-spend truth: `codex-max` has four selectable broker-ready routes, `session_start_ready:true`, `fallback_ready:true`, and `single_route_at_risk:false`. |
| lab dogfood | 0.1.7 | macOS arm64 | public npm one-shot | Pass | Public `npx` run reports `oauth-mux 0.1.7` and `doctor --json` reports `ok:true` against local config/state. |
| first-run source e2e | main | macOS arm64 | source checkout | Pass | `just first-run-e2e` runs with temporary HOME/XDG roots and proves no-config `init --codex-max`, JSON diagnostics, runtime diagnostics, redacted report, no-spend route explanation/select refusal, and non-mutating Codex help. |

## Evidence Commands

npm clean install:

```bash
tmp="$(mktemp -d)"
npm_config_cache="$tmp/cache" \
  npm install --prefix "$tmp/app" --install-strategy=shallow oauth-mux@0.1.7 \
  --ignore-scripts=false --no-audit --no-fund
"$tmp/app/node_modules/.bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.7
```

Raw release tarball:

```bash
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/oauth-mux-aarch64-macos.tar.gz" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.7/oauth-mux-aarch64-macos.tar.gz
curl -fsSL -o "$tmp/SHA256SUMS" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.7/SHA256SUMS
(cd "$tmp" && shasum -a 256 -c --ignore-missing SHA256SUMS)
tar -xzf "$tmp/oauth-mux-aarch64-macos.tar.gz" -C "$tmp"
"$tmp/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux-aarch64-macos.tar.gz: OK
oauth-mux 0.1.7
```

Public installer for v0.1.7:

```bash
tmp="$(mktemp -d)"
VERSION=0.1.7 \
INSTALL_DIR="$tmp/bin" \
  sh -c 'curl -fsSL https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.7/install.sh | sh'
"$tmp/bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.7
```

Homebrew tap install:

```bash
just homebrew-qa 0.1.7
```

Expected output includes:

```text
Homebrew install QA passed for oauth-mux 0.1.7 via jesssullivan/omux/oauth-mux
```

Homebrew metadata check:

```bash
brew info jesssullivan/omux/oauth-mux --json=v2
```

For the current public tap, both the installed keg and
`formulae[0].versions.stable` report `0.1.7`. Treat a future mismatch as a
release metadata defect even if the binary itself runs.

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
OMUX_HOMEBREW_KEEP_INSTALLED=1 OMUX_HOMEBREW_KEEP_TAP=1 just homebrew-qa 0.1.7
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
  just homebrew-qa 0.1.7
```

Latest local Homebrew dogfood proof:

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

Latest private/staged Homebrew proof:

```text
brew tap tinyland/tools https://github.com/tinyland-inc/homebrew-tools.git: pass
brew install tinyland/tools/oauth-mux: pass
brew audit --formula --strict tinyland/tools/oauth-mux: pass
brew test tinyland/tools/oauth-mux: pass
/opt/homebrew/bin/oauth-mux version: oauth-mux 0.1.6
/opt/homebrew/bin/oauth-mux doctor --json: ok
Production tap PR `tinyland-inc/homebrew-tools#4` merged at `f3016e3`.
```

Latest public npm dogfood proof, 2026-05-17 snapshot:

```text
npm publish workflow run 25980468974: pass
npm view oauth-mux@0.1.7 version: 0.1.7
npm view oauth-mux-<platform>@0.1.7 version: 0.1.7 for all six platform packages
temp-prefix npm install oauth-mux@0.1.7: oauth-mux 0.1.7
npx -y oauth-mux@0.1.7 version: oauth-mux 0.1.7
npx -y oauth-mux@0.1.7 doctor --json: ok
```

Current paid-cohort route truth is tracked in `docs/qa-handoff-matrix.md`.
Refresh live operator state with `oauth-mux route explain` rather than copying
time-sensitive account availability into this install matrix.

System package install QA after GitHub Release publication:

```bash
gh workflow run system-package-install-qa.yml -f version=0.1.7
```

Latest hosted proof:

```text
System Package Install QA run 25980333371: pass
job 76367854350: deb/rpm install from published release assets
```

Local reproduction on a host with healthy Docker:

```bash
just system-package-qa 0.1.7
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
