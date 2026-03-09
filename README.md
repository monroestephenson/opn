# opn — A Modern lsof Replacement

A cross-platform CLI tool that replaces common `lsof` workflows. Reads process/file/socket info directly from OS APIs — no shelling out.

## Installation

```bash
cargo install --path .
```

## Development Hooks

Use `pre-commit` to run formatting/lint/tests before each commit:

```bash
pipx install pre-commit   # or: brew install pre-commit
pre-commit install

# Fuzz `/proc/net` parser
cargo install cargo-fuzz
cargo fuzz run proc_net
```

## Testing

Run the full local test suite:

```bash
cargo test --all-targets --all-features
```

Generate coverage locally:

```bash
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --all-features --summary-only
```

Privileged firewall integration tests are opt-in only:

```bash
sudo OPN_RUN_PRIVILEGED_TESTS=1 cargo test --test firewall_privileged_e2e -- --ignored
```

## Usage

### Find processes on a port

```bash
$ opn port 8080
PROTO  LOCAL ADDRESS      REMOTE ADDRESS  STATE        PID   PROCESS
TCP    127.0.0.1:8080     -               LISTEN       1234  node

$ opn port 8080 --json
[
  {
    "protocol": "Tcp",
    "local_addr": "127.0.0.1:8080",
    "remote_addr": "0.0.0.0:0",
    "state": "Listen",
    "process": {
      "pid": 1234,
      "name": "node",
      "user": "monroestephenson",
      "uid": 501,
      "command": "/usr/local/bin/node"
    }
  }
]
```

### Find processes with a file open

```bash
$ opn file /var/log/system.log
PID   PROCESS  USER  FD  TYPE  PATH
312   syslogd  root  4   REG   /var/log/system.log
```

### Filter flags

```bash
opn port 80 --tcp          # TCP only
opn port 53 --udp          # UDP only
opn port 443 --ipv4        # IPv4 only
opn port 443 --ipv6        # IPv6 only
opn sockets --state LISTEN # Socket state filter
opn port 8080 --pid 1234   # Filter by PID (`--filter-pid` alias still works)
```

### Other commands

```bash
opn pid 1234               # Show open files for a PID
opn deleted                # Find deleted-but-open files
opn sockets                # List all open sockets
opn watch                  # Interactive terminal mode
opn watch --target port --port 8080
opn watch --target file --file /tmp/demo.log
opn watch --target sockets --theme kanagawa
```

## How This Differs from lsof

| Feature | lsof | opn |
|---------|------|-----|
| Output format | Dense, hard to parse | Clean aligned columns or JSON |
| JSON output | No | `--json` flag |
| Implementation | Shells out / kernel module | Direct OS API calls |
| Speed | Slow (enumerates everything) | Fast (targeted queries) |
| Cross-platform | Mostly Linux | Linux (`/proc`) + macOS (`libproc`/`netstat2`) |

## Quick Benchmark

Replicated locally on macOS with `hyperfine -N --warmup 20 --runs 200`:

| Scenario | Relative result (`opn` vs `lsof`) |
|---------|------------------------------------|
| `opn port 8080 --json` vs `lsof -i :8080 -P -n` | `3.63x` faster |
| `opn port 8080` vs `lsof -i :8080 -P -n` | `3.58x` faster |
| `opn sockets` vs `lsof -i -P -n` | `1.72x` faster |
| `opn sockets --json` vs `lsof -i -P -n` | `1.83x` faster |
| `opn pid <small pid>` vs `lsof -p <pid>` | `1.08x` faster (near parity) |
| `opn pid <FD-heavy pid>` vs `lsof -p <pid>` | `3.46x` faster |
| `opn deleted` vs `lsof +L1` | `5.99x` faster |

PIDs used in this run:

- `small pid`: `11588`
- `FD-heavy pid`: `46254`

FD-heavy PID selection and benchmark setup:

```bash
PID=$(
  lsof -nP 2>/dev/null \
    | awk 'NR>1 {count[$2]++} END {for (pid in count) print count[pid], pid}' \
    | sort -nr \
    | head -1 \
    | awk '{print $2}'
)

echo "Benchmarking PID: $PID"

hyperfine -N --warmup 20 --runs 200 \
  "./target/release/opn pid $PID" \
  "lsof -p $PID"
```

Results vary by OS, permissions, workload size, and background system activity. Some scenarios showed statistical outliers during this run.

## Platform Support

- **macOS**: Uses `libproc` for process enumeration and `netstat2` for socket info
- **Linux**: Reads directly from `/proc` filesystem

## Exit Codes

- `0`: Command executed and returned one or more results
- `1`: Command executed successfully but returned no results
- `2`: Command failed (invalid args/runtime/platform error)

## Known Limitations

- Requires appropriate permissions to inspect other users' processes (run with `sudo` for full visibility)
- `watch` controls: `j/k` or arrow keys move selection, `g/G` jump top/bottom, `x` opens a terminate confirmation dialog (`y`/`Enter` confirm, `n`/`Esc` cancel), `space` pause, `s` sort, `q` quit
- `watch` themes: `catppuccin-latte`, `catppuccin`, `ethereal`, `everforest`, `flexoki-light`, `gruvbox`, `hackerman`, `kanagawa`, `matte-black`, `miasma`, `nord`, `osaka-jade`, `ristretto`, `rose-pine`, `tokyo-night`, `vantablack`, `white`
- Some e2e tests rely on local socket bind permissions and may skip in restricted environments
- Race conditions with short-lived processes are handled by skipping vanished PIDs
