# Release Process

## 1. Bump version

Edit `Cargo.toml`:

```toml
version = "X.Y.Z"
```

## 2. Commit, tag, push

```bash
git add -A && git commit -m "Release vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

Pushing the tag triggers the release pipeline (`.github/workflows/release.yml`), which:
- Builds binaries for macOS (arm64, x86_64) and Linux (x86_64, aarch64)
- Creates tarballs with SHA256 checksums
- Publishes a GitHub release at https://github.com/monroestephenson/opn/releases

Wait for the pipeline to finish before proceeding:

```bash
gh run list --limit 1
gh run watch <run-id> --exit-status
```

## 3. Update Homebrew formula

Get the source tarball SHA256:

```bash
curl -sL https://github.com/monroestephenson/opn/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256
```

Clone the tap repo, update the formula, and push:

```bash
cd /tmp && rm -rf homebrew-tap && gh repo clone monroestephenson/homebrew-tap
```

Edit `/tmp/homebrew-tap/Formula/opn.rb` — update `version` and `sha256`:

```ruby
  version "X.Y.Z"
  sha256 "<new hash from above>"
```

Then commit and push:

```bash
cd /tmp/homebrew-tap
git add -A && git commit -m "Update opn to vX.Y.Z"
git push origin main
```

## 4. Users upgrade with

```bash
brew update && brew upgrade opn
```

## First-time install

```bash
brew tap monroestephenson/tap
brew install opn
```
