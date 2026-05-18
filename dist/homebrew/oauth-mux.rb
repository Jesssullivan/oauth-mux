class OauthMux < Formula
  desc "OAuth fallback muxing for AI harness subscriptions"
  homepage "https://omux.xoxd.ai"
  license "MIT"
  version "${VERSION}"

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
    bin.install "codex"
  end

  test do
    assert_match "oauth-mux", shell_output("#{bin}/oauth-mux version")
    assert_match "OMUX_CODEX_SHIM", shell_output("grep OMUX_CODEX_SHIM #{bin}/codex")
    native = testpath/"native-codex"
    native.write <<~EOS
      #!/bin/sh
      case "$1" in
        --version) echo "native-codex-stub 0.0.0" ;;
        *) echo "native-codex-stub" ;;
      esac
    EOS
    chmod 0755, native
    assert_match "native-codex-stub 0.0.0", shell_output("OMUX_CODEX_BIN=#{native} #{bin}/codex --version")
  end
end
