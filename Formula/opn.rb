class Opn < Formula
  desc "Modern, human-friendly replacement for lsof"
  homepage "https://github.com/monroestephenson/opn"
  url "https://github.com/monroestephenson/opn/archive/refs/tags/v#{version}.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
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
