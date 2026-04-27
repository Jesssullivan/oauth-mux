#!/bin/sh
# oauth-mux installer - detects OS/arch, verifies checksums, installs the binary
set -eu

REPO="${REPO:-tinyland-inc/oauth-mux}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"
OMUX_RELEASE_BASE_URL="${OMUX_RELEASE_BASE_URL:-}"

main() {
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) die "unsupported architecture: $arch" ;;
    esac

    case "$os" in
        linux)  target="${arch}-linux" ;;
        darwin) target="${arch}-macos" ;;
        *)      die "unsupported OS: $os" ;;
    esac

    if [ "$VERSION" = "latest" ]; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"v//' | sed 's/".*//')
    else
        VERSION=$(printf '%s' "$VERSION" | sed 's/^v//')
    fi

    archive="oauth-mux-${target}.tar.gz"
    if [ -n "$OMUX_RELEASE_BASE_URL" ]; then
        base_url="${OMUX_RELEASE_BASE_URL%/}"
    else
        base_url="https://github.com/${REPO}/releases/download/v${VERSION}"
    fi
    url="${base_url}/${archive}"
    sums_url="${base_url}/SHA256SUMS"

    echo "downloading oauth-mux v${VERSION} for ${target}..."

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fsSL "$url" -o "$tmpdir/oauth-mux.tar.gz"
    curl -fsSL "$sums_url" -o "$tmpdir/SHA256SUMS"
    verify_checksum "$tmpdir/oauth-mux.tar.gz" "$tmpdir/SHA256SUMS" "$archive"

    tar xzf "$tmpdir/oauth-mux.tar.gz" -C "$tmpdir"

    mkdir -p "$INSTALL_DIR"
    mv "$tmpdir/oauth-mux" "$INSTALL_DIR/oauth-mux"
    chmod +x "$INSTALL_DIR/oauth-mux"

    echo "installed oauth-mux to ${INSTALL_DIR}/oauth-mux"

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        echo ""
        echo "add to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
}

verify_checksum() {
    file="$1"
    sums="$2"
    archive="$3"

    expected=$(awk -v archive="$archive" '$2 == archive { print $1; found = 1 } END { exit found ? 0 : 1 }' "$sums") || {
        die "missing checksum for ${archive}"
    }

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{ print $1 }')
    else
        die "sha256sum or shasum is required to verify ${archive}"
    fi

    if [ "$actual" != "$expected" ]; then
        die "checksum mismatch for ${archive}"
    fi
}

die() {
    echo "error: $1" >&2
    exit 1
}

main "$@"
