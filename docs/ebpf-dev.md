# eBPF Development

`opn` now has three Linux-side eBPF pieces:

- `ebpf-common/`: shared ABI between kernel-space and user-space
- `ebpf/`: the eBPF program crate
- `src/platform/linux_ebpf.rs`: the host-side loader and Linux backend integration

## Current scope

The current kernel program crate emits lightweight live socket lifecycle probe events for:

- `tcp_connect`
- `inet_csk_accept`
- `tcp_close`
- `tcp_retransmit_skb`

The host loader auto-discovers a built object at:

- `target/bpfel-unknown-none/release/opn-ebpf`
- `target/bpfel-unknown-none/debug/opn-ebpf`
- `ebpf/target/bpfel-unknown-none/release/opn-ebpf`
- `ebpf/target/bpfel-unknown-none/debug/opn-ebpf`
- `.o` variants of the same paths

Override it explicitly with:

```bash
export OPN_EBPF_OBJECT=/absolute/path/to/opn-ebpf
```

Production lookup order is:

1. `OPN_EBPF_OBJECT`
2. bundled object produced at build time
3. installed paths:
   - `/usr/lib/opn/opn-ebpf`
   - `/usr/libexec/opn/opn-ebpf`
   - `/opt/opn/lib/opn-ebpf`
4. repo-local development paths under `ebpf/target/...`

Enable the backend with:

```bash
export OPN_LINUX_SOCKET_BACKEND=ebpf
```

Fail hard instead of falling back to `/proc` with:

```bash
export OPN_EBPF_STRICT=1
```

## Lima VM loop

Inside the Linux VM:

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev libpcap-dev pkg-config
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"
rustup default stable
```

Use a writable repo copy:

```bash
mkdir -p ~/src
rsync -a /Users/monroestephenson/opn/ ~/src/opn/
cd ~/src/opn
cargo test --features ebpf
```

## Building the eBPF object

From the repo root:

```bash
cargo +nightly build -Z build-std=core -Z unstable-options --manifest-path ebpf/Cargo.toml --target bpfel-unknown-none --release
```

To bundle that object into the Linux host binary at build time:

```bash
OPN_EBPF_BUNDLE_SOURCE=$PWD/target/bpfel-unknown-none/release/opn-ebpf \
  cargo build --features ebpf --release
```

For workspace builds, this is usually the right path:

```bash
OPN_EBPF_BUNDLE_SOURCE=$PWD/target/bpfel-unknown-none/release/opn-ebpf \
  cargo build --features ebpf --release
```

That gives you a production-style `opn` binary that can load eBPF without `OPN_EBPF_OBJECT`.

Then run the host CLI against the built object:

```bash
sudo -E OPN_LINUX_SOCKET_BACKEND=ebpf cargo run --features ebpf -- sockets
```

Or explicitly point at the object:

```bash
sudo -E \
  OPN_LINUX_SOCKET_BACKEND=ebpf \
  OPN_EBPF_OBJECT=$PWD/target/bpfel-unknown-none/release/opn-ebpf \
  cargo run --features ebpf -- sockets
```

For production, the intended UX is simply:

```bash
sudo opn backend
sudo opn sockets
sudo opn watch
sudo opn history record
```

`opn backend` is the first command to run on a Linux host. It tells you:

- which backend was selected
- whether eBPF is actually loaded
- whether strict live mode is enabled
- which object path was used
- how many tracked flows are currently in the in-memory table

If the binary was built with a bundled object or installed alongside `/usr/lib/opn/opn-ebpf`,
Linux will auto-select the eBPF backend when running as root unless `OPN_LINUX_SOCKET_BACKEND=procfs`
is set explicitly.

## Next implementation steps

Current limitations:

- strict eBPF `opn sockets` is live-flow oriented, so it may be empty on a cold start until new socket activity occurs after attach
- the current probe set is strongest for `watch` and `history`
- process names in live eBPF events are still lightweight and may not match full procfs enrichment in all cases

Future depth work:

1. Add broader listener/state coverage so cold-start `sockets` is less sparse in strict mode.
2. Improve process-name enrichment for eBPF-native events.
3. Extend the live flow model beyond the current lightweight probe set.
4. Add a dedicated backend diagnostic command path to LLM/JSON workflows if needed.
