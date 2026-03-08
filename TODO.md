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
- [x] macOS: Per-FD file path resolution (`proc_pidfdinfo` FFI + vnode path info)

## Phase 4: PID Inspection (`opn pid <pid>`)
- [x] Implement `commands/pid.rs` — list all open files/sockets for a given PID
- [x] Table output showing FD number, type, path/socket info
- [x] JSON output for `opn pid <pid> --json`
- [x] Handle non-existent PID gracefully
- [x] Handle permission-denied for other users' PIDs

## Phase 5: Deleted Files (`opn deleted`)
- [x] Linux: Scan `/proc/*/fd/` for symlinks ending in `(deleted)`
- [x] macOS: Implement via vnode FD info (`st_nlink == 0`)
- [~] Table output: PID, process, user, path, size (if available; size pending)
- [x] Filter by user/process name

## Phase 6: Socket Listing (`opn sockets`)
- [x] Linux: Parse all of `/proc/net/{tcp,tcp6,udp,udp6}`, resolve inodes to PIDs
- [x] macOS: Use `netstat2::iterate_sockets_info()` (no port filter)
- [x] Filter flags: `--tcp`, `--udp`, `--ipv4`, `--ipv6`, `--state LISTEN`
- [ ] Sort output by protocol, then port
- [x] JSON output

## Phase 7: Watch Mode (`opn watch`)
- [x] Feature-gated behind `watch` Cargo feature
- [x] Add `ratatui` + `crossterm` dependencies
- [x] TUI layout: table with live-updating rows
- [ ] Configurable refresh interval (`--interval 2s`)
- [~] Support watching ports, files, or all sockets (currently sockets only)
- [x] Keyboard controls: quit (q), pause (space), sort columns

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
- [x] macOS: Raw FFI for vnode path resolution (`proc_pidfdinfo` flavor 2)
- [ ] macOS: Get actual UID for `find_by_file` results (currently using pidpath approach)
- [ ] Linux: Use `rayon` for parallel PID scanning in `find_by_port()`
- [ ] Linux: Handle `/proc` permission errors more gracefully with `--all` flag
- [ ] FreeBSD platform support
- [ ] Windows platform support (via `windows-sys` crate)

### Performance
- [~] Cache `process_info()`/prefilter when scanning all PIDs (additional tuning pending)
- [ ] Lazy process info resolution (only fetch user/command when needed for display)
- [ ] Benchmark against `lsof` and `ss` on large PID counts
- [x] Pre-filter PIDs by UID/name before scanning FDs on Linux (`--user`, `--process`)

### Output & Rendering
- [ ] TSV output mode (`--tsv`)
- [ ] CSV output mode (`--csv`)
- [ ] Custom column selection (`--columns pid,port,state`)
- [ ] Sort by column (`--sort port`)
- [ ] Reverse sort (`--sort port --desc`)
- [ ] Truncate long paths with ellipsis in table mode

### Error Handling
- [ ] Distinguish between "no results" and "permission denied" in exit codes
- [x] Exit code 1 for "no results found", 2 for errors
- [x] Structured error output in JSON mode (`{"error":{"code","category","message"}}`)
- [ ] `--verbose` flag for debug-level logging to stderr

### Testing
- [x] Unit tests for `/proc/net/tcp` hex parsing (47 tests)
- [x] Unit tests for `FilterArgs` → `QueryFilter` conversion (10 tests)
- [x] Unit tests for model serialization, Display, Clone (27 tests)
- [x] Integration tests with mock `Platform` impl (13 tests)
- [x] Integration tests with real TCP/UDP listeners (e2e port lookup, protocol filters, closed port)
- [x] CLI argument parsing tests (valid and invalid inputs, 33 tests)
- [x] JSON output schema validation tests (port + pid schemas)
- [x] Table output formatting tests
- [x] PID command tests (own process, nonexistent PID, filters)
- [x] Deleted command tests (mock platform)
- [x] macOS-specific tests for vnode path and deleted detection (including restricted PID behavior)
- [x] Env-sensitive socket e2e tests skip cleanly when bind is not permitted
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
- [x] GitHub Actions CI workflow (test on Linux + macOS)
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
1. `watch` supports sockets only; watch-by-port/file and interval configuration are not implemented
2. `--filter-pid` is retained as an alias for compatibility; canonical flag is `--pid`
3. vnode path lookup may still fail for some FDs and returns `<path unavailable>`
4. JSON errors have categories/codes but no stable versioned schema contract yet
5. Socket list output is not yet sorted by a user-selectable CLI sort flag
