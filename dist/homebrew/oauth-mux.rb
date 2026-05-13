class OauthMux < Formula
  desc "OAuth fallback muxing for AI harness subscriptions"
  homepage "https://omux.xoxd.ai"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/Jesssullivan/oauth-mux/releases/download/v${VERSION}/oauth-mux-aarch64-macos.tar.gz"
      sha256 "${SHA_MACOS_ARM64}"
    else
      url "https://github.com/Jesssullivan/oauth-mux/releases/download/v${VERSION}/oauth-mux-x86_64-macos.tar.gz"
      sha256 "${SHA_MACOS_X64}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/Jesssullivan/oauth-mux/releases/download/v${VERSION}/oauth-mux-aarch64-linux.tar.gz"
      sha256 "${SHA_LINUX_ARM64}"
    else
      url "https://github.com/Jesssullivan/oauth-mux/releases/download/v${VERSION}/oauth-mux-x86_64-linux.tar.gz"
      sha256 "${SHA_LINUX_X64}"
    end
  end

  def install
    bin.install "oauth-mux"
    (bin/"codex").write <<~EOS
      #!/bin/sh
      # OMUX_CODEX_SHIM
      set -eu

      oauth_mux_bin="#{bin}/oauth-mux"

      real_path() {
          if command -v realpath >/dev/null 2>&1; then
              realpath "$1"
          else
              dir=$(dirname "$1")
              base=$(basename "$1")
              printf '%s/%s\\n' "$(cd "$dir" 2>/dev/null && pwd -P)" "$base"
          fi
      }

      is_omux_codex_shim() {
          grep -q 'OMUX_CODEX_SHIM' "$1" 2>/dev/null
      }

      find_native_codex() {
          self=$(real_path "$0")
          old_ifs=$IFS
          IFS=:
          for dir in $PATH; do
              [ -n "$dir" ] || continue
              candidate="$dir/codex"
              [ -x "$candidate" ] || continue
              candidate_real=$(real_path "$candidate")
              [ "$candidate_real" != "$self" ] || continue
              if is_omux_codex_shim "$candidate"; then
                  continue
              fi
              IFS=$old_ifs
              printf '%s\\n' "$candidate"
              return 0
          done
          IFS=$old_ifs
          return 1
      }

      native_codex="${OMUX_CODEX_BIN:-}"
      if [ -z "$native_codex" ]; then
          native_codex=$(find_native_codex || true)
      fi
      if [ -z "$native_codex" ]; then
          echo "codex: native Codex CLI not found; set OMUX_CODEX_BIN to the upstream Codex executable" >&2
          exit 127
      fi

      OMUX_CODEX_BIN="$native_codex" OMUX_CODEX_SHIM=1 OMUX_COMMAND_SPELLING=codex exec "$oauth_mux_bin" codex "$@"
    EOS
    chmod 0755, bin/"codex"
  end

  test do
    assert_match "oauth-mux", shell_output("#{bin}/oauth-mux version")
    assert_match "OMUX_CODEX_SHIM", shell_output("grep OMUX_CODEX_SHIM #{bin}/codex")
  end
end
