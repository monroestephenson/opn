class Opn < Formula
  desc "Modern, human-friendly replacement for lsof"
  homepage "https://github.com/monroestephenson/opn"
  url "https://github.com/monroestephenson/opn/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "" # update after release: curl -sL <url> | shasum -a 256
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "build", "--release"
    bin.install "target/release/opn"
  end

  test do
    assert_match "Usage", shell_output("#{bin}/opn --help")
  end
end
