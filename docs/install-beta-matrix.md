# Install Beta Matrix

Updated: 2026-04-29

This matrix tracks clean-install proof for the public adoption surfaces. It is
operator evidence, not a credential runbook: do not paste OAuth stores, `.env`
files, SOPS plaintext, or token-shaped values here.

## Current Status

| Surface | Version | Host | Source | Result | Caveat |
| --- | --- | --- | --- | --- | --- |
| npm global install | 0.1.3 | macOS arm64 | public npm registry | Pass | Clean temp-prefix global install returns `oauth-mux 0.1.3`. |
| npm one-shot | 0.1.3 | `../lab` on macOS arm64 | public npm registry | Pass | `npx -y oauth-mux@0.1.3 version` returns `oauth-mux 0.1.3`. |
| GitHub release tarball | 0.1.3 | macOS arm64 | public `Jesssullivan/oauth-mux` release asset | Pass | Repo visibility must remain public for unauthenticated downloads. |
| `curl | sh` installer | 0.1.3 | macOS arm64 and `../lab` | public `Jesssullivan/oauth-mux` `install.sh` asset | Pass | Default installer repo is now canonical; no `REPO=...` override needed. |
| Homebrew formula | 0.1.3 | macOS arm64 | `tinyland/tools` tap | Pass | Tap install and rollback passed after `tinyland-inc/homebrew-tools#2`; tap repo is still private. |
| deb package | 0.1.3 | hosted Linux amd64 container | public GitHub Release `.deb` asset | Pass | System Package Install QA run `25137031548` installed package and ran `/usr/bin/oauth-mux version`. |
| rpm package | 0.1.3 | hosted Linux x86_64 container | public GitHub Release `.rpm` asset | Pass | System Package Install QA run `25137031548` installed package and ran `/usr/bin/oauth-mux version`. |
| lab dogfood | 0.1.3 | `../lab` on macOS arm64 | installed `oauth-mux` CLI | Pass | Installed `oauth-mux doctor --json` reports `ok: true` against local config/state. |

## Evidence Commands

npm clean install:

```bash
tmp="$(mktemp -d)"
npm_config_cache="$tmp/cache" \
  npm install --prefix "$tmp/app" --install-strategy=shallow oauth-mux@0.1.3 \
  --ignore-scripts=false --no-audit --no-fund
"$tmp/app/node_modules/.bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.3
```

Raw release tarball:

```bash
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/oauth-mux-aarch64-macos.tar.gz" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.3/oauth-mux-aarch64-macos.tar.gz
curl -fsSL -o "$tmp/SHA256SUMS" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.3/SHA256SUMS
(cd "$tmp" && shasum -a 256 -c --ignore-missing SHA256SUMS)
tar -xzf "$tmp/oauth-mux-aarch64-macos.tar.gz" -C "$tmp"
"$tmp/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux-aarch64-macos.tar.gz: OK
oauth-mux 0.1.3
```

Public installer for v0.1.3:

```bash
tmp="$(mktemp -d)"
VERSION=0.1.3 \
INSTALL_DIR="$tmp/bin" \
  sh -c 'curl -fsSL https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.3/install.sh | sh'
"$tmp/bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.3
```

Homebrew tap install:

```bash
HOMEBREW_NO_AUTO_UPDATE=1 \
  brew tap tinyland/tools https://github.com/tinyland-inc/homebrew-tools.git
brew install tinyland/tools/oauth-mux
oauth-mux version
brew uninstall oauth-mux
brew untap tinyland/tools
```

Expected output includes:

```text
oauth-mux 0.1.3
```

System package install QA after GitHub Release publication:

```bash
gh workflow run system-package-install-qa.yml -f version=0.1.3
```

Latest hosted proof:

```text
System Package Install QA run 25137031548: pass
job 73677864724: deb/rpm install from published release assets
```

Local reproduction on a host with healthy Docker:

```bash
just system-package-qa 0.1.3
```

## Next Proof

1. Keep the hosted system-package install QA workflow in the release checklist.
2. For each release that changes deb/rpm packaging, run the workflow after the
   GitHub Release assets exist.
3. Treat registry metadata checks as insufficient without this install proof.
