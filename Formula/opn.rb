class Opn < Formula
  desc "Modern, human-friendly replacement for lsof"
  homepage "https://github.com/monroestephenson/opn"
  url "https://github.com/monroestephenson/opn/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "78ea9c4b37264d69dd7e9eede842756d5b67f4a2fe6bb797b20870b29b62e544"
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
