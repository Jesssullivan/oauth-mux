#!/bin/sh
# oauth-mux installer — detects OS/arch and downloads the right binary
set -eu

REPO="tinyland-inc/oauth-mux"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-latest}"

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
    fi

    url="https://github.com/${REPO}/releases/download/v${VERSION}/oauth-mux-${target}.tar.gz"
    echo "downloading oauth-mux v${VERSION} for ${target}..."

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    curl -fsSL "$url" -o "$tmpdir/oauth-mux.tar.gz"
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

die() {
    echo "error: $1" >&2
    exit 1
}

main "$@"
