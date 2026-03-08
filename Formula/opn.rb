class Opn < Formula
  desc "Modern, human-friendly replacement for lsof"
  homepage "https://github.com/monroestephenson/opn"
  url "https://github.com/monroestephenson/opn/archive/refs/tags/v#{version}.tar.gz"
  version "0.1.0"
  sha256 "0451095a6d9e31ca2bbbb612503475349a08a9192fe3fedb96a6555ef4d2aee4"
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
