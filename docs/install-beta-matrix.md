# Install Beta Matrix

Updated: 2026-05-03

This matrix tracks clean-install proof for the public adoption surfaces. It is
operator evidence, not a credential runbook: do not paste OAuth stores, `.env`
files, SOPS plaintext, or token-shaped values here.

## Current Status

| Surface | Version | Host | Source | Result | Caveat |
| --- | --- | --- | --- | --- | --- |
| npm global install | 0.1.6 | macOS arm64 | public npm registry | Pass | Public registry reports `oauth-mux@0.1.6` plus all six platform packages. |
| npm one-shot | 0.1.6 | macOS arm64 | public npm registry | Pass | `npx -y oauth-mux@0.1.6 version` returns `oauth-mux 0.1.6`. |
| GitHub release tarball | 0.1.6 | macOS arm64 | public `Jesssullivan/oauth-mux` release asset | Pass | Release workflow `25195318899` published all tarballs, packages, checksums, formula, and installer. |
| `curl | sh` installer | 0.1.6 | macOS arm64 and `../lab` | public `Jesssullivan/oauth-mux` `install.sh` asset | Pass | Default installer repo is canonical; no `REPO=...` override needed. |
| Homebrew formula | 0.1.6 | macOS arm64 + hosted Ubuntu dry-run | public `jesssullivan/omux` tap | Pass | Clean local uninstall/untap followed by `just homebrew-qa 0.1.6` installed from `Jesssullivan/homebrew-omux`; hosted registry dry-run `25199131583` checked out the public tap and passed the Homebrew lane. |
| deb package | 0.1.6 | hosted Linux amd64 container | public GitHub Release `.deb` asset | Pass | System Package Install QA run `25195456319` installed package and ran `/usr/bin/oauth-mux version`. |
| rpm package | 0.1.6 | hosted Linux x86_64 container | public GitHub Release `.rpm` asset | Pass | System Package Install QA run `25195456319` installed package and ran `/usr/bin/oauth-mux version`. |
| Codex route dogfood | 0.1.6 | macOS arm64 | public npm one-shot | Pass with degraded route | Historical 2026-05-01 snapshot: published npm binary selected `max-2#codex-max` while recorded liveness kept `max-1#codex-max` quota exhausted. Current paid-cohort truth is `max-1` selected, `max-4` spare fallback, and `max-2`/`max-3` quota-exhausted for `codex-max`. |
| lab dogfood | 0.1.6 | macOS arm64 | public npm one-shot | Pass | Installed `oauth-mux doctor --json` reports `ok: true` against local config/state. |
| first-run source e2e | main | macOS arm64 | source checkout | Pass | `just first-run-e2e` runs with temporary HOME/XDG roots and proves no-config `init --codex-max`, JSON diagnostics, runtime diagnostics, redacted report, no-spend route explanation/select refusal, and non-mutating Codex help. |

## Evidence Commands

npm clean install:

```bash
tmp="$(mktemp -d)"
npm_config_cache="$tmp/cache" \
  npm install --prefix "$tmp/app" --install-strategy=shallow oauth-mux@0.1.6 \
  --ignore-scripts=false --no-audit --no-fund
"$tmp/app/node_modules/.bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.6
```

Raw release tarball:

```bash
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/oauth-mux-aarch64-macos.tar.gz" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.6/oauth-mux-aarch64-macos.tar.gz
curl -fsSL -o "$tmp/SHA256SUMS" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.6/SHA256SUMS
(cd "$tmp" && shasum -a 256 -c --ignore-missing SHA256SUMS)
tar -xzf "$tmp/oauth-mux-aarch64-macos.tar.gz" -C "$tmp"
"$tmp/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux-aarch64-macos.tar.gz: OK
oauth-mux 0.1.6
```

Public installer for v0.1.6:

```bash
tmp="$(mktemp -d)"
VERSION=0.1.6 \
INSTALL_DIR="$tmp/bin" \
  sh -c 'curl -fsSL https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.6/install.sh | sh'
"$tmp/bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.6
```

Homebrew tap install:

```bash
just homebrew-qa 0.1.6
```

Expected output includes:

```text
Homebrew install QA passed for oauth-mux 0.1.6 via jesssullivan/omux/oauth-mux
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
OMUX_HOMEBREW_KEEP_INSTALLED=1 OMUX_HOMEBREW_KEEP_TAP=1 just homebrew-qa 0.1.6
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
  just homebrew-qa 0.1.6
```

Latest local Homebrew dogfood proof:

```text
brew uninstall oauth-mux: pass
brew untap jesssullivan/omux: pass
brew tap jesssullivan/omux https://github.com/Jesssullivan/homebrew-omux.git: pass
brew install jesssullivan/omux/oauth-mux: pass
brew audit --formula --strict jesssullivan/omux/oauth-mux: pass
brew test jesssullivan/omux/oauth-mux: pass
/opt/homebrew/bin/oauth-mux version: oauth-mux 0.1.6
/opt/homebrew/bin/oauth-mux doctor --json: ok
Public tap repository: `Jesssullivan/homebrew-omux`, default branch `main`.
Hosted registry dry-run `25199131583`: pass, checked out public tap and passed
the Homebrew lane.
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

Latest public npm dogfood proof, historical 2026-05-01 snapshot:

```text
npm publish workflow run 25195609579: pass
npm view oauth-mux version: 0.1.6
npx -y oauth-mux@0.1.6 version: oauth-mux 0.1.6
npx -y oauth-mux@0.1.6 doctor --json: ok
npx -y oauth-mux@0.1.6 route select --profile codex-max --capability codex-max --json:
  selected: codex:max-2#codex-max
  max-1#codex-max: quota_exhausted reset@1777987200
```

Current paid-cohort truth is tracked in
`docs/spec/paid-multi-account-proof-cohort-2026-05-01.md`: `max-1#codex-max`
is selected after revalidation, `max-4#codex-max` is the spare fallback, and
`max-2#codex-max` plus `max-3#codex-max` remain provider quota-exhausted for
`codex-max`.

System package install QA after GitHub Release publication:

```bash
gh workflow run system-package-install-qa.yml -f version=0.1.6
```

Latest hosted proof:

```text
System Package Install QA run 25195456319: pass
job 73874903526: deb/rpm install from published release assets
```

Local reproduction on a host with healthy Docker:

```bash
just system-package-qa 0.1.6
```

## Next Proof

1. Keep the hosted system-package install QA workflow in the release checklist.
2. For each release that changes deb/rpm packaging, run the workflow after the
   GitHub Release assets exist.
3. Treat registry metadata checks as insufficient without this install proof.
4. Keep Homebrew release updates derived from public GitHub Release
   `oauth-mux.rb` and `SHA256SUMS`, then rerun `just homebrew-qa <version>`
   against the public `jesssullivan/omux` tap.
