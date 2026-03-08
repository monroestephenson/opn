# opn — TODO

## Legend
- [ ] Not started
- [~] In progress
- [x] Done

---

## Phase 1: Core Infrastructure
- [x] Project scaffolding (Cargo.toml, directory structure)
- [x] Data models (`ProcessInfo`, `OpenFile`, `SocketEntry`, `FdType`, `Protocol`, `QueryFilter`)
- [x] CLI definitions (clap derive, subcommands, global `--json` flag)
- [x] Platform trait definition
- [x] Render modules (table + JSON)
- [x] Wire `main.rs` dispatch

## Phase 2: Port Lookup (`opn port <port>`)
- [x] macOS: `find_by_port()` via `netstat2::iterate_sockets_info()`
- [x] Linux: `/proc/net/tcp` parser in `net.rs`
- [x] Linux: inode-to-socket map + fd scan
- [x] Protocol filter flags (`--tcp`, `--udp`, `--ipv4`, `--ipv6`)
- [x] Unit tests for `/proc/net/tcp` hex parsing

## Phase 3: File Lookup (`opn file <path>`)
- [x] macOS: `find_by_file()` via pidpath scanning
- [x] Linux: `list_open_files()` (fd symlink reading + classification)
- [x] Linux: `find_by_file()` (canonicalized path matching)
- [x] Permission error handling (skip with stderr warning)
- [ ] macOS: Per-FD file path resolution (needs `libproc` upgrade or FFI bindings for `proc_pidfdvnodeinfo`)

## Phase 4: PID Inspection (`opn pid <pid>`)
- [ ] Implement `commands/pid.rs` — list all open files/sockets for a given PID
- [ ] Table output showing FD number, type, path/socket info
- [ ] JSON output for `opn pid <pid> --json`
- [ ] Handle non-existent PID gracefully
- [ ] Handle permission-denied for other users' PIDs

## Phase 5: Deleted Files (`opn deleted`)
- [ ] Linux: Scan `/proc/*/fd/` for symlinks ending in `(deleted)`
- [ ] macOS: Investigate feasibility (no direct equivalent)
- [ ] Table output: PID, process, user, path, size (if available)
- [ ] Filter by user/process name

## Phase 6: Socket Listing (`opn sockets`)
- [ ] Linux: Parse all of `/proc/net/{tcp,tcp6,udp,udp6}`, resolve inodes to PIDs
- [ ] macOS: Use `netstat2::iterate_sockets_info()` (no port filter)
- [ ] Filter flags: `--tcp`, `--udp`, `--ipv4`, `--ipv6`, `--state LISTEN`
- [ ] Sort output by protocol, then port
- [ ] JSON output

## Phase 7: Watch Mode (`opn watch`)
- [ ] Feature-gated behind `watch` Cargo feature
- [ ] Add `ratatui` + `crossterm` dependencies
- [ ] TUI layout: table with live-updating rows
- [ ] Configurable refresh interval (`--interval 2s`)
- [ ] Support watching ports, files, or all sockets
- [ ] Keyboard controls: quit (q), pause (space), sort columns

## Improvements & Polish

### CLI & UX
- [ ] Add `--no-header` flag to suppress table headers (for scripting)
- [ ] Add `--count` flag to just print the number of matches
- [ ] Add `--wide` flag to show full command line instead of truncated process name
- [ ] Colorized output (red for CLOSE_WAIT, green for LISTEN, etc.)
- [ ] Add shell completions generation (`opn completions bash/zsh/fish`)
- [ ] `opn port` without argument lists all listening ports
- [ ] Support port ranges (`opn port 8000-9000`)
- [ ] Support multiple ports (`opn port 80,443,8080`)

### Platform
- [ ] macOS: Upgrade `libproc` or add raw FFI for `proc_pidfdvnodeinfo` to get per-FD file paths
- [ ] macOS: Get actual UID for `find_by_file` results (currently using pidpath approach)
- [ ] Linux: Use `rayon` for parallel PID scanning in `find_by_port()`
- [ ] Linux: Handle `/proc` permission errors more gracefully with `--all` flag
- [ ] FreeBSD platform support
- [ ] Windows platform support (via `windows-sys` crate)

### Performance
- [ ] Cache `process_info()` lookups when scanning all PIDs (avoid repeated reads)
- [ ] Lazy process info resolution (only fetch user/command when needed for display)
- [ ] Benchmark against `lsof` and `ss` on large PID counts
- [ ] Pre-filter PIDs by UID before scanning FDs (when `--user` is set)

### Output & Rendering
- [ ] TSV output mode (`--tsv`)
- [ ] CSV output mode (`--csv`)
- [ ] Custom column selection (`--columns pid,port,state`)
- [ ] Sort by column (`--sort port`)
- [ ] Reverse sort (`--sort port --desc`)
- [ ] Truncate long paths with ellipsis in table mode

### Error Handling
- [ ] Distinguish between "no results" and "permission denied" in exit codes
- [ ] Exit code 1 for "no results found", 2 for errors
- [ ] Structured error output in JSON mode (`{"error": "..."}`)
- [ ] `--verbose` flag for debug-level logging to stderr

### Testing
- [x] Unit tests for `/proc/net/tcp` hex parsing
- [x] Unit tests for `FilterArgs` → `QueryFilter` conversion
- [~] Integration tests with mock `Platform` impl
- [ ] Integration tests with real platform (port listener + lookup)
- [ ] CLI argument parsing tests (valid and invalid inputs)
- [ ] JSON output schema validation tests
- [ ] Table output formatting tests
- [ ] Cross-platform CI (Linux + macOS)
- [ ] Benchmark tests

### Documentation
- [x] README with usage examples
- [ ] `--help` text review and polish for all subcommands
- [ ] Man page generation
- [ ] CHANGELOG.md
- [ ] Contributing guide
- [ ] Architecture doc explaining platform abstraction

### Packaging & Distribution
- [ ] GitHub Actions CI workflow (test on Linux + macOS)
- [ ] Release workflow with prebuilt binaries
- [ ] Homebrew formula
- [ ] AUR package
- [ ] Publish to crates.io
- [ ] Nix flake

### Security
- [ ] Audit: ensure no information leaks when running as root
- [ ] Audit: ensure no TOCTOU races in `/proc` reads
- [ ] Fuzz test the `/proc/net/tcp` parser
- [ ] Validate all user-supplied paths (no path traversal in output)

---

## Known Issues
1. `opn file` on macOS only matches process executables, not all open file descriptors
2. `--filter-pid` flag name is awkward (workaround for clap conflict with `pid` subcommand positional arg)
3. Dead code warnings for Linux-only `net.rs` functions when building on macOS
4. `list_open_files` on macOS shows `fd:N` placeholder paths instead of real file paths
5. No exit code distinction between "no results" and "error"
