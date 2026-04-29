# Install Beta Matrix

Updated: 2026-04-29

This matrix tracks clean-install proof for the public adoption surfaces. It is
operator evidence, not a credential runbook: do not paste OAuth stores, `.env`
files, SOPS plaintext, or token-shaped values here.

## Current Status

| Surface | Version | Host | Source | Result | Caveat |
| --- | --- | --- | --- | --- | --- |
| npm global install | 0.1.2 | macOS arm64 | public npm registry | Pass | Published metadata still points at `tinyland-inc/oauth-mux`; v0.1.3 templates now point at `Jesssullivan/oauth-mux` and `https://omux.xoxd.ai`. |
| GitHub release tarball | 0.1.2 | macOS arm64 | public `Jesssullivan/oauth-mux` release asset | Pass | Repo visibility must remain public for unauthenticated downloads. |
| `curl | sh` installer | 0.1.2 | macOS arm64 | public `Jesssullivan/oauth-mux` `install.sh` asset | Pass with `REPO=Jesssullivan/oauth-mux` | The v0.1.2 installer asset was generated before the canonical repo transfer. v0.1.3 uses the corrected default. |
| Homebrew formula | 0.1.3 staged | macOS arm64 | generated formula in temporary tap | Pass audit | Needs real tap install proof after release assets exist. |
| deb package | 0.1.3 staged | Linux target | generated `nfpm` artifact | Pass artifact smoke | Needs Debian/Ubuntu host or container install proof. |
| rpm package | 0.1.3 staged | Linux target | generated `nfpm` artifact | Pass artifact smoke | Needs Fedora/Rocky host or container install proof. |
| lab dogfood | v0.1.3 branch | lab machines | installed `oauth-mux` CLI | Pending | Use installed commands, not repo-local `just` wrappers, once v0.1.3 is published. |

## Evidence Commands

npm clean install:

```bash
tmp="$(mktemp -d)"
npm_config_cache="$tmp/cache" \
  npm install --prefix "$tmp/app" --install-strategy=shallow oauth-mux@0.1.2 \
  --ignore-scripts=false --no-audit --no-fund
"$tmp/app/node_modules/.bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.2
```

Raw release tarball:

```bash
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/oauth-mux-aarch64-macos.tar.gz" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.2/oauth-mux-aarch64-macos.tar.gz
curl -fsSL -o "$tmp/SHA256SUMS" \
  https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.2/SHA256SUMS
(cd "$tmp" && shasum -a 256 -c --ignore-missing SHA256SUMS)
tar -xzf "$tmp/oauth-mux-aarch64-macos.tar.gz" -C "$tmp"
"$tmp/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux-aarch64-macos.tar.gz: OK
oauth-mux 0.1.2
```

Public installer for v0.1.2:

```bash
tmp="$(mktemp -d)"
REPO=Jesssullivan/oauth-mux \
VERSION=0.1.2 \
INSTALL_DIR="$tmp/bin" \
  sh -c 'curl -fsSL https://github.com/Jesssullivan/oauth-mux/releases/download/v0.1.2/install.sh | sh'
"$tmp/bin/oauth-mux" version
rm -rf "$tmp"
```

Expected output includes:

```text
oauth-mux 0.1.2
```

The `REPO` override above is intentional for v0.1.2 only. v0.1.3 release
artifacts should install from the canonical public repository by default.

Staged v0.1.3 Homebrew audit:

```bash
tmp="$(mktemp -d)"
git -C "$tmp" init -q
OMUX_REGISTRY_DRY_RUN_CONFIRM=registry-dry-run \
OMUX_REGISTRY_LANES=homebrew \
OMUX_HOMEBREW_TAP_DIR="$tmp" \
HOMEBREW_NO_AUTO_UPDATE=1 \
  ./scripts/registry-dry-run.sh 0.1.3
rm -rf "$tmp"
```

Expected report entry:

```text
brew audit --strict OK
```

## Next Proof

1. Publish v0.1.3 artifacts from the corrected templates.
2. Re-run the public installer command without `REPO=...`.
3. Install the generated Homebrew formula from the selected tap.
4. Install generated deb and rpm packages on Linux hosts or containers.
5. Update this matrix with host, version, result, and caveat for each lane.
