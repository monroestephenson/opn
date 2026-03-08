# opn — A Modern lsof Replacement

A cross-platform CLI tool that replaces common `lsof` workflows. Reads process/file/socket info directly from OS APIs — no shelling out.

## Installation

```bash
cargo install --path .
```

## Usage

### Find processes on a port

```bash
$ opn port 8080
PROTO  LOCAL ADDRESS      REMOTE ADDRESS  STATE        PID   PROCESS
TCP    127.0.0.1:8080     0.0.0.0:0       LISTEN       1234  node

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
```

### Stub commands (not yet implemented)

```bash
opn pid 1234               # Show open files for PID
opn deleted                 # Find deleted files still open
opn sockets                 # List all open sockets
```

## How This Differs from lsof

| Feature | lsof | opn |
|---------|------|-----|
| Output format | Dense, hard to parse | Clean aligned columns or JSON |
| JSON output | No | `--json` flag |
| Implementation | Shells out / kernel module | Direct OS API calls |
| Speed | Slow (enumerates everything) | Fast (targeted queries) |
| Cross-platform | Mostly Linux | Linux (`/proc`) + macOS (`libproc`/`netstat2`) |

## Platform Support

- **macOS**: Uses `libproc` for process enumeration and `netstat2` for socket info
- **Linux**: Reads directly from `/proc` filesystem

## Known Limitations

- Requires appropriate permissions to inspect other users' processes (run with `sudo` for full visibility)
- macOS `file` subcommand is limited to matching process executables (no per-FD file path resolution in `libproc` 0.14)
- `pid`, `deleted`, `sockets`, and `watch` subcommands are stubs
- Race conditions with short-lived processes are handled by skipping vanished PIDs
