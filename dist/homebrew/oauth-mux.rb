class OauthMux < Formula
  desc "OAuth fallback muxing for AI harness subscriptions"
  homepage "https://github.com/tinyland-inc/oauth-mux"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/tinyland-inc/oauth-mux/releases/download/v${VERSION}/oauth-mux-aarch64-macos.tar.gz"
      sha256 "${SHA_MACOS_ARM64}"
    else
      url "https://github.com/tinyland-inc/oauth-mux/releases/download/v${VERSION}/oauth-mux-x86_64-macos.tar.gz"
      sha256 "${SHA_MACOS_X64}"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/tinyland-inc/oauth-mux/releases/download/v${VERSION}/oauth-mux-aarch64-linux.tar.gz"
      sha256 "${SHA_LINUX_ARM64}"
    else
      url "https://github.com/tinyland-inc/oauth-mux/releases/download/v${VERSION}/oauth-mux-x86_64-linux.tar.gz"
      sha256 "${SHA_LINUX_X64}"
    end
  end

  def install
    bin.install "oauth-mux"
  end

  test do
    assert_match "oauth-mux", shell_output("#{bin}/oauth-mux version")
  end
end
