# Install Beta Matrix

Updated: 2026-04-30

This matrix tracks clean-install proof for the public adoption surfaces. It is
operator evidence, not a credential runbook: do not paste OAuth stores, `.env`
files, SOPS plaintext, or token-shaped values here.

## Current Status

| Surface | Version | Host | Source | Result | Caveat |
| --- | --- | --- | --- | --- | --- |
| npm global install | 0.1.5 | macOS arm64 | public npm registry | Pass | Public registry reports `oauth-mux@0.1.5` plus all six platform packages. |
| npm one-shot | 0.1.5 | macOS arm64 | public npm registry | Pass | `npx -y oauth-mux@0.1.5 version` returns `oauth-mux 0.1.5`. |
| GitHub release tarball | 0.1.5 | macOS arm64 | public `Jesssullivan/oauth-mux` release asset | Pass | Release workflow `25171997189` published all tarballs, packages, checksums, formula, and installer. |
| `curl | sh` installer | 0.1.5 | macOS arm64 and `../lab` | public `Jesssullivan/oauth-mux` `install.sh` asset | Pass | Default installer repo is canonical; no `REPO=...` override needed. |
| Homebrew formula | 0.1.5 | macOS arm64 | `tinyland/tools` tap | Pass | `just homebrew-qa 0.1.5` installs from the private `tinyland-inc/homebrew-tools` tap, runs `brew audit`, `brew test`, `oauth-mux version`, and `oauth-mux doctor --json`. |
| deb package | 0.1.5 | hosted Linux amd64 container | public GitHub Release `.deb` asset | Pass | System Package Install QA run `25172711458` installed package and ran `/usr/bin/oauth-mux version`. |
| rpm package | 0.1.5 | hosted Linux x86_64 container | public GitHub Release `.rpm` asset | Pass | System Package Install QA run `25172711458` installed package and ran `/usr/bin/oauth-mux version`. |
| Codex live dogfood | 0.1.5 | macOS arm64 | public npm one-shot | Pass with degraded route | Published npm binary reported `max-1#codex-max` quota exhausted while `max-2` and `max-3` covered `codex-max`; `codex-mini` remained covered. |
| lab dogfood | 0.1.5 | macOS arm64 | public npm one-shot | Pass | Installed `oauth-mux doctor --json` reports `ok: true` against local config/state. |
| first-run source e2e | main | macOS arm64 | source checkout | Pass | `just first-run-e2e` runs with temporary HOME/XDG roots and proves no-config `init --codex-max`, JSON diagnostics, runtime diagnostics, redacted report, no-spend route explanation/select refusal, and non-mutating Codex help. |

## Evidence Commands

npm clean install:

```bash
tmp="$(mktemp -d)"
npm_config_cache="$tmp/cache" \
  npm install --prefix "$tmp/app" --install-strategy=shallow oauth-mux@0.1.5 \
  --ignore-scripts=false --no-audit --no-fund
"$tmp/app/node_modules/.bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.5
```

Raw release tarball:

```bash
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/oauth-mux-aarch64-macos.tar.gz" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.5/oauth-mux-aarch64-macos.tar.gz
curl -fsSL -o "$tmp/SHA256SUMS" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.5/SHA256SUMS
(cd "$tmp" && shasum -a 256 -c --ignore-missing SHA256SUMS)
tar -xzf "$tmp/oauth-mux-aarch64-macos.tar.gz" -C "$tmp"
"$tmp/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux-aarch64-macos.tar.gz: OK
oauth-mux 0.1.5
```

Public installer for v0.1.5:

```bash
tmp="$(mktemp -d)"
VERSION=0.1.5 \
INSTALL_DIR="$tmp/bin" \
  sh -c 'curl -fsSL https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.5/install.sh | sh'
"$tmp/bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.5
```

Homebrew tap install:

```bash
just homebrew-qa 0.1.5
```

Expected output includes:

```text
Homebrew install QA passed for oauth-mux 0.1.5 via tinyland/tools/oauth-mux
```

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
OMUX_HOMEBREW_KEEP_INSTALLED=1 OMUX_HOMEBREW_KEEP_TAP=1 just homebrew-qa 0.1.5
```

To include the three-account Codex canary from the installed Homebrew binary:

```bash
OMUX_CONFIG=$PWD/examples/codex-max.config.json \
OMUX_STATE_DIR=/tmp/oauth-mux-brew-codex-live \
OMUX_HOMEBREW_KEEP_INSTALLED=1 \
OMUX_HOMEBREW_KEEP_TAP=1 \
OMUX_HOMEBREW_CODEX_CANARY=1 \
OMUX_HOMEBREW_CODEX_LIVE=1 \
OMUX_LIVE_QA_CONFIRM=spend-real-calls \
  just homebrew-qa 0.1.5
```

Latest local Homebrew dogfood proof:

```text
brew tap tinyland/tools https://github.com/tinyland-inc/homebrew-tools.git: pass
brew install tinyland/tools/oauth-mux: pass
brew audit --formula --strict tinyland/tools/oauth-mux: pass
brew test tinyland/tools/oauth-mux: pass
/opt/homebrew/bin/oauth-mux version: oauth-mux 0.1.5
/opt/homebrew/bin/oauth-mux doctor --json: ok
Homebrew-installed oauth-mux codex live-qa --confirm-spend with examples/codex-max.config.json:
  max-1, max-2, max-3 available for codex-mini and codex-max
```

Latest public npm dogfood proof:

```text
npx -y oauth-mux@0.1.5 version: oauth-mux 0.1.5
npx -y oauth-mux@0.1.5 doctor --json: ok
npx -y oauth-mux@0.1.5 codex live-qa --json: confirmation_required without --confirm-spend
confirmed live QA:
  routes_total: 6
  routes_available: 5
  routes_unavailable: 1
  probe_errors: 0
  capabilities_covered: 2
  capabilities_uncovered: 0
  max-1#codex-mini: available
  max-1#codex-max: quota_exhausted reset@1777987200
  max-2#codex-mini: available
  max-2#codex-max: available
  max-3#codex-mini: available
  max-3#codex-max: available
```

System package install QA after GitHub Release publication:

```bash
gh workflow run system-package-install-qa.yml -f version=0.1.5
```

Latest hosted proof:

```text
System Package Install QA run 25172711458: pass
job 73796295655: deb/rpm install from published release assets
```

Local reproduction on a host with healthy Docker:

```bash
just system-package-qa 0.1.5
```

## Next Proof

1. Keep the hosted system-package install QA workflow in the release checklist.
2. For each release that changes deb/rpm packaging, run the workflow after the
   GitHub Release assets exist.
3. Treat registry metadata checks as insufficient without this install proof.
