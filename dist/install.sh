#!/bin/sh
# oauth-mux installer - detects OS/arch, verifies checksums, installs the binary
set -eu

REPO="${REPO:-Jesssullivan/oauth-mux}"
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
    write_codex_shim "$INSTALL_DIR"

    echo "installed oauth-mux to ${INSTALL_DIR}/oauth-mux"
    echo "installed managed codex shim to ${INSTALL_DIR}/codex"

    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        echo ""
        echo "add to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
}

write_codex_shim() {
    install_dir="$1"
    cat >"${install_dir}/codex" <<EOF
#!/bin/sh
# OMUX_CODEX_SHIM
set -eu

oauth_mux_bin="${install_dir}/oauth-mux"

real_path() {
    if command -v realpath >/dev/null 2>&1; then
        realpath "\$1"
    else
        dir=\$(dirname "\$1")
        base=\$(basename "\$1")
        printf '%s/%s\n' "\$(cd "\$dir" 2>/dev/null && pwd -P)" "\$base"
    fi
}

is_omux_codex_shim() {
    grep -q 'OMUX_CODEX_SHIM' "\$1" 2>/dev/null
}

find_native_codex() {
    self=\$(real_path "\$0")
    old_ifs=\$IFS
    IFS=:
    for dir in \$PATH; do
        [ -n "\$dir" ] || continue
        candidate="\$dir/codex"
        [ -x "\$candidate" ] || continue
        candidate_real=\$(real_path "\$candidate")
        [ "\$candidate_real" != "\$self" ] || continue
        if is_omux_codex_shim "\$candidate"; then
            continue
        fi
        IFS=\$old_ifs
        printf '%s\n' "\$candidate"
        return 0
    done
    IFS=\$old_ifs
    return 1
}

native_codex="\${OMUX_CODEX_BIN:-}"
if [ -z "\$native_codex" ]; then
    native_codex=\$(find_native_codex || true)
fi
if [ -z "\$native_codex" ]; then
    echo "codex: native Codex CLI not found; set OMUX_CODEX_BIN to the upstream Codex executable" >&2
    exit 127
fi

OMUX_CODEX_BIN="\$native_codex" OMUX_CODEX_SHIM=1 OMUX_COMMAND_SPELLING=codex exec "\$oauth_mux_bin" codex "\$@"
EOF
    chmod +x "${install_dir}/codex"
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
