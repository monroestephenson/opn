//! Integration tests for the `opn` CLI binary.
//! These tests invoke the compiled binary and verify output behavior.

use std::fs;
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::process::{Command, Output};

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
}

fn bind_tcp_local() -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => Some(l),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(e) => panic!("failed to bind TCP listener: {}", e),
    }
}

fn bind_udp_local() -> Option<UdpSocket> {
    match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(e) => panic!("failed to bind UDP socket: {}", e),
    }
}

fn assert_non_error_exit(output: &Output) {
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "Expected non-error exit code (0/1), got {}. stderr={}",
        code,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
fn tmp_path_aliases(path: &str) -> Vec<String> {
    let mut aliases = vec![path.to_string()];
    if let Some(rest) = path.strip_prefix("/tmp/") {
        aliases.push(format!("/private/tmp/{}", rest));
    } else if let Some(rest) = path.strip_prefix("/private/tmp/") {
        aliases.push(format!("/tmp/{}", rest));
    }
    aliases
}

// ============================================================
// Help & Version
// ============================================================

#[test]
fn test_help_flag() {
    let output = opn_cmd().arg("--help").output().expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("A modern, human-friendly replacement for lsof"));
    assert!(stdout.contains("port"));
    assert!(stdout.contains("file"));
    assert!(stdout.contains("pid"));
    assert!(stdout.contains("deleted"));
    assert!(stdout.contains("sockets"));
    assert!(stdout.contains("watch"));
    assert!(stdout.contains("--json"));
}

#[test]
fn test_version_flag() {
    let output = opn_cmd()
        .arg("--version")
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("opn"));
}

#[test]
fn test_no_subcommand_shows_error() {
    let output = opn_cmd().output().expect("failed to run opn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage") || stderr.contains("subcommand"),
        "Expected usage info, got: {}",
        stderr
    );
}

// ============================================================
// Subcommand help
// ============================================================

#[test]
fn test_port_help() {
    let output = opn_cmd()
        .args(["port", "--help"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("port"));
    assert!(stdout.contains("--tcp"));
    assert!(stdout.contains("--udp"));
    assert!(stdout.contains("--ipv4"));
    assert!(stdout.contains("--ipv6"));
}

#[test]
fn test_file_help() {
    let output = opn_cmd()
        .args(["file", "--help"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PATH") || stdout.contains("Path"));
}

#[test]
fn test_pid_help() {
    let output = opn_cmd()
        .args(["pid", "--help"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pid"));
}

// ============================================================
// Argument validation
// ============================================================

#[test]
fn test_port_requires_number() {
    let output = opn_cmd()
        .args(["port", "notanumber"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
}

#[test]
fn test_port_rejects_negative() {
    let output = opn_cmd()
        .args(["port", "-1"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
}

#[test]
fn test_port_rejects_too_large() {
    let output = opn_cmd()
        .args(["port", "99999"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
}

#[test]
fn test_pid_requires_number() {
    let output = opn_cmd()
        .args(["pid", "abc"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
}

#[test]
fn test_file_requires_path() {
    let output = opn_cmd()
        .args(["file"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
}

#[test]
fn test_unknown_subcommand() {
    let output = opn_cmd()
        .args(["foobar"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
}

// ============================================================
// PID + remaining stub commands
// ============================================================

#[test]
fn test_pid_succeeds_for_current_process() {
    let pid = std::process::id().to_string();
    let output = opn_cmd()
        .args(["pid", &pid])
        .output()
        .expect("failed to run opn");
    assert!(output.status.success());
}

#[test]
fn test_pid_nonexistent_returns_error() {
    let output = opn_cmd()
        .args(["pid", "4294967295"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found"),
        "Expected not-found message, got: {}",
        stderr
    );
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn test_json_error_payload_for_failures() {
    let output = opn_cmd()
        .args(["pid", "4294967295", "--json"])
        .output()
        .expect("failed to run opn");
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let err = parsed.get("error").expect("missing error object");
    assert!(err.get("code").and_then(|v| v.as_str()).is_some());
    assert!(err.get("category").and_then(|v| v.as_str()).is_some());
    assert!(err.get("message").and_then(|v| v.as_str()).is_some());
}

#[test]
fn test_deleted_command_runs_or_returns_not_implemented() {
    let output = opn_cmd()
        .args(["deleted", "--json"])
        .output()
        .expect("failed to run opn");
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        assert!(parsed.is_array());
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not yet implemented"),
            "Expected stub message on unsupported platform, got: {}",
            stderr
        );
    }
}

#[test]
fn test_sockets_command_runs_or_returns_not_implemented() {
    let output = opn_cmd()
        .args(["sockets", "--json"])
        .output()
        .expect("failed to run opn");
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        assert!(parsed.is_array());
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not yet implemented"),
            "Expected stub message on unsupported platform, got: {}",
            stderr
        );
    }
}

#[test]
fn test_watch_without_feature_returns_error() {
    let output = opn_cmd()
        .args(["watch"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        (stderr.contains("watch") && stderr.contains("feature"))
            || stderr.contains("failed to enable raw mode"),
        "Expected feature-gate or terminal-environment error, got: {}",
        stderr
    );
}

// ============================================================
// Port lookup (functional, uses real system)
// ============================================================

#[test]
fn test_port_no_listener_empty_output() {
    // Port 19 (chargen) is almost certainly unused
    let output = opn_cmd()
        .args(["port", "19"])
        .output()
        .expect("failed to run opn");
    // Should succeed (exit 0) but print "No results found" to stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("No results") || stdout.is_empty() || stdout.trim().is_empty(),
        "Expected empty/no-results output for unused port, stdout={}, stderr={}",
        stdout,
        stderr
    );
}

#[test]
fn test_port_no_listener_json_empty_array() {
    let output = opn_cmd()
        .args(["port", "19", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 0);
    assert_eq!(output.status.code(), Some(1));
}

#[test]
fn test_port_json_output_is_valid_json() {
    // Even with results, output should be valid JSON
    let output = opn_cmd()
        .args(["port", "80", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(parsed.is_ok(), "JSON output was not valid: {}", stdout);
    }
}

#[test]
fn test_port_with_tcp_filter() {
    let output = opn_cmd()
        .args(["port", "19", "--tcp"])
        .output()
        .expect("failed to run opn");
    // Should succeed regardless of results
    assert!(
        output.status.success() || {
            let stderr = String::from_utf8_lossy(&output.stderr);
            stderr.contains("No results")
        }
    );
}

#[test]
fn test_port_with_udp_filter() {
    let output = opn_cmd()
        .args(["port", "19", "--udp"])
        .output()
        .expect("failed to run opn");
    assert!(
        output.status.success() || {
            let stderr = String::from_utf8_lossy(&output.stderr);
            stderr.contains("No results")
        }
    );
}

#[test]
fn test_port_with_ipv4_filter() {
    let output = opn_cmd()
        .args(["port", "19", "--ipv4", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

#[test]
fn test_port_with_ipv6_filter() {
    let output = opn_cmd()
        .args(["port", "19", "--ipv6", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

#[test]
fn test_port_combined_filters() {
    let output = opn_cmd()
        .args(["port", "19", "--tcp", "--ipv4", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

// ============================================================
// File lookup (functional, uses real system)
// ============================================================

#[test]
fn test_file_nonexistent_path() {
    let output = opn_cmd()
        .args(["file", "/nonexistent/path/that/does/not/exist"])
        .output()
        .expect("failed to run opn");
    // Should succeed but find nothing
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No results") || stderr.contains("macOS") || output.status.success(),
        "Unexpected output for nonexistent path: {}",
        stderr
    );
}

#[test]
fn test_file_json_output_is_valid() {
    let output = opn_cmd()
        .args(["file", "/etc/hosts", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(parsed.is_ok(), "JSON output was not valid: {}", stdout);
    }
}

// ============================================================
// Global --json flag position
// ============================================================

#[test]
fn test_json_flag_before_subcommand() {
    let output = opn_cmd()
        .args(["--json", "port", "19"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should produce valid JSON (even if empty array)
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

#[test]
fn test_json_flag_after_subcommand() {
    let output = opn_cmd()
        .args(["port", "19", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

// ============================================================
// Filter flags on subcommands
// ============================================================

#[test]
fn test_filter_pid_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--pid", "1"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);
}

#[test]
fn test_filter_user_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--user", "root"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);
}

#[test]
fn test_filter_process_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--process", "sshd"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);
}

#[test]
fn test_filter_all_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--all"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);
}

#[test]
fn test_short_flags() {
    let output = opn_cmd()
        .args(["port", "19", "-a", "-u", "root", "-p", "sshd"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);
}

// ============================================================
// Edge cases
// ============================================================

#[test]
fn test_port_zero() {
    let output = opn_cmd()
        .args(["port", "0", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

#[test]
fn test_port_max_valid() {
    let output = opn_cmd()
        .args(["port", "65535", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}

#[test]
fn test_file_with_spaces_in_path() {
    // Should not crash even if the path doesn't exist
    let output = opn_cmd()
        .args(["file", "/tmp/path with spaces/file.txt"])
        .output()
        .expect("failed to run opn");
    // May fail gracefully but should not panic
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panic"));
}

#[test]
fn test_file_symlink() {
    // /etc is often a symlink on macOS to /private/etc
    let output = opn_cmd()
        .args(["file", "/etc/hosts", "--json"])
        .output()
        .expect("failed to run opn");
    // Should handle symlink resolution gracefully
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panic"));
}

// ============================================================
// End-to-end: real TCP listener + opn port lookup
// ============================================================

#[test]
fn test_e2e_tcp_listener_found_by_port() {
    // Bind to port 0 to get a random available port
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["port", &port.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("invalid JSON output");

    assert!(parsed.is_array(), "Expected JSON array");
    let arr = parsed.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "Expected at least one result for TCP port {}, got empty array",
        port
    );

    // Verify our PID is in the results
    let found_our_pid = arr.iter().any(|entry| {
        entry["process"]["pid"]
            .as_u64()
            .map(|pid| pid == my_pid as u64)
            .unwrap_or(false)
    });
    assert!(
        found_our_pid,
        "Expected to find our PID {} in results for port {}. Results: {}",
        my_pid, port, stdout
    );

    // Verify the entry has the right port in local_addr
    let found_port = arr.iter().any(|entry| {
        entry["local_addr"]
            .as_str()
            .map(|addr| addr.ends_with(&format!(":{}", port)))
            .unwrap_or(false)
    });
    assert!(
        found_port,
        "Expected local_addr to contain port {}. Results: {}",
        port, stdout
    );

    // Verify protocol is TCP
    let found_tcp = arr.iter().any(|entry| {
        entry["protocol"]
            .as_str()
            .map(|p| p == "Tcp")
            .unwrap_or(false)
    });
    assert!(found_tcp, "Expected protocol Tcp in results: {}", stdout);

    // Keep listener alive until assertions are done
    drop(listener);
}

#[test]
fn test_e2e_tcp_listener_table_output() {
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();

    let output = opn_cmd()
        .args(["port", &port.to_string()])
        .output()
        .expect("failed to run opn");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Table output should contain headers
    assert!(
        stdout.contains("PROTO") && stdout.contains("LOCAL ADDRESS"),
        "Expected table headers in output: {}",
        stdout
    );
    // Should contain TCP and the port
    assert!(
        stdout.contains("TCP"),
        "Expected TCP in table output: {}",
        stdout
    );
    assert!(
        stdout.contains(&port.to_string()),
        "Expected port {} in table output: {}",
        port,
        stdout
    );

    drop(listener);
}

#[test]
fn test_e2e_tcp_listener_with_tcp_filter() {
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();

    // With --tcp filter, should still find it
    let output = opn_cmd()
        .args(["port", &port.to_string(), "--tcp", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(
        !parsed.as_array().unwrap().is_empty(),
        "TCP filter should still find the TCP listener on port {}",
        port
    );

    // With --udp filter only, should NOT find it
    let output_udp = opn_cmd()
        .args(["port", &port.to_string(), "--udp", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout_udp = String::from_utf8_lossy(&output_udp.stdout);
    let parsed_udp: serde_json::Value =
        serde_json::from_str(stdout_udp.trim()).expect("invalid JSON");
    assert!(
        parsed_udp.as_array().unwrap().is_empty(),
        "UDP filter should NOT find a TCP listener. Got: {}",
        stdout_udp
    );

    drop(listener);
}

#[test]
fn test_e2e_tcp_listener_closed_port_not_found() {
    // Bind, get the port, then drop the listener
    let port = {
        let Some(listener) = bind_tcp_local() else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        drop(listener); // Close the socket
        port
    };

    // Small delay to let OS clean up
    std::thread::sleep(std::time::Duration::from_millis(100));

    let output = opn_cmd()
        .args(["port", &port.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(
        parsed.as_array().unwrap().is_empty(),
        "Closed port {} should have no listeners. Got: {}",
        port,
        stdout
    );
}

// ============================================================
// End-to-end: real UDP socket + opn port lookup
// ============================================================

#[test]
fn test_e2e_udp_socket_found_by_port() {
    let Some(socket) = bind_udp_local() else {
        return;
    };
    let port = socket.local_addr().unwrap().port();
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["port", &port.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("invalid JSON output");

    assert!(parsed.is_array());
    let arr = parsed.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "Expected at least one result for UDP port {}, got empty array",
        port
    );

    // Verify our PID is in the results
    let found_our_pid = arr.iter().any(|entry| {
        entry["process"]["pid"]
            .as_u64()
            .map(|pid| pid == my_pid as u64)
            .unwrap_or(false)
    });
    assert!(
        found_our_pid,
        "Expected to find our PID {} in UDP results for port {}. Results: {}",
        my_pid, port, stdout
    );

    // Verify protocol is UDP
    let found_udp = arr.iter().any(|entry| {
        entry["protocol"]
            .as_str()
            .map(|p| p == "Udp")
            .unwrap_or(false)
    });
    assert!(found_udp, "Expected protocol Udp in results: {}", stdout);

    drop(socket);
}

#[test]
fn test_e2e_udp_socket_with_udp_filter() {
    let Some(socket) = bind_udp_local() else {
        return;
    };
    let port = socket.local_addr().unwrap().port();

    // With --udp filter, should find it
    let output = opn_cmd()
        .args(["port", &port.to_string(), "--udp", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(
        !parsed.as_array().unwrap().is_empty(),
        "UDP filter should find the UDP socket on port {}",
        port
    );

    // With --tcp filter only, should NOT find it
    let output_tcp = opn_cmd()
        .args(["port", &port.to_string(), "--tcp", "--json"])
        .output()
        .expect("failed to run opn");
    let stdout_tcp = String::from_utf8_lossy(&output_tcp.stdout);
    let parsed_tcp: serde_json::Value =
        serde_json::from_str(stdout_tcp.trim()).expect("invalid JSON");
    assert!(
        parsed_tcp.as_array().unwrap().is_empty(),
        "TCP filter should NOT find a UDP socket. Got: {}",
        stdout_tcp
    );

    drop(socket);
}

// ============================================================
// End-to-end: TCP + UDP on same port
// ============================================================

#[test]
fn test_e2e_tcp_and_udp_same_port() {
    let Some(tcp_listener) = bind_tcp_local() else {
        return;
    };
    let port = tcp_listener.local_addr().unwrap().port();

    // Bind UDP to the same port (TCP and UDP namespaces are separate)
    let udp_socket = match UdpSocket::bind(format!("127.0.0.1:{}", port)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
        Err(e) => panic!("failed to bind UDP socket to same port: {}", e),
    };

    let output = opn_cmd()
        .args(["port", &port.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("invalid JSON output");

    let arr = parsed.as_array().unwrap();
    assert!(
        arr.len() >= 2,
        "Expected at least 2 results (TCP + UDP) on port {}, got {}. Output: {}",
        port,
        arr.len(),
        stdout
    );

    let has_tcp = arr.iter().any(|e| e["protocol"].as_str() == Some("Tcp"));
    let has_udp = arr.iter().any(|e| e["protocol"].as_str() == Some("Udp"));
    assert!(has_tcp, "Expected TCP entry for port {}", port);
    assert!(has_udp, "Expected UDP entry for port {}", port);

    drop(tcp_listener);
    drop(udp_socket);
}

// ============================================================
// End-to-end: PID lookup finds own process FDs
// ============================================================

#[test]
fn test_e2e_pid_finds_own_open_files() {
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    assert!(
        output.status.success(),
        "opn pid {} should succeed. stderr: {}",
        my_pid,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("invalid JSON output");

    assert!(parsed.is_array());
    // The test process should have at least stdin/stdout/stderr open
    let arr = parsed.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "Expected at least some open files for our PID {}. Got empty.",
        my_pid
    );
}

// ============================================================
// End-to-end: JSON schema validation for port results
// ============================================================

#[test]
fn test_e2e_port_json_schema() {
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();

    let output = opn_cmd()
        .args(["port", &port.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().unwrap();
    assert!(!arr.is_empty());

    // Validate every entry has the expected fields
    for entry in arr {
        assert!(entry["protocol"].is_string(), "Missing protocol field");
        assert!(entry["local_addr"].is_string(), "Missing local_addr field");
        assert!(
            entry["remote_addr"].is_string(),
            "Missing remote_addr field"
        );
        assert!(entry["state"].is_string(), "Missing state field");
        assert!(entry["process"].is_object(), "Missing process object");

        let process = &entry["process"];
        assert!(process["pid"].is_number(), "Missing process.pid");
        assert!(process["name"].is_string(), "Missing process.name");
        assert!(process["user"].is_string(), "Missing process.user");
        assert!(process["uid"].is_number(), "Missing process.uid");
        assert!(process["command"].is_string(), "Missing process.command");
    }

    drop(listener);
}

// ============================================================
// End-to-end: JSON schema validation for pid results
// ============================================================

#[test]
fn test_e2e_pid_json_schema() {
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    if !output.status.success() {
        return; // skip if permissions prevent reading own fds
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().unwrap();

    for entry in arr {
        assert!(entry["fd"].is_number(), "Missing fd field");
        assert!(entry["fd_type"].is_string(), "Missing fd_type field");
        assert!(entry["path"].is_string(), "Missing path field");
        assert!(entry["deleted"].is_boolean(), "Missing deleted field");
        assert!(entry["process"].is_object(), "Missing process object");

        let process = &entry["process"];
        assert!(process["pid"].is_number(), "Missing process.pid");
        assert!(process["name"].is_string(), "Missing process.name");
    }
}

// ============================================================
// End-to-end: multiple TCP listeners on different ports
// ============================================================

#[test]
fn test_e2e_multiple_tcp_listeners_different_ports() {
    let Some(listener1) = bind_tcp_local() else {
        return;
    };
    let port1 = listener1.local_addr().unwrap().port();

    let Some(listener2) = bind_tcp_local() else {
        return;
    };
    let port2 = listener2.local_addr().unwrap().port();

    // port1 should find listener1 but not listener2
    let output1 = opn_cmd()
        .args(["port", &port1.to_string(), "--json"])
        .output()
        .expect("failed to run opn");
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let parsed1: serde_json::Value = serde_json::from_str(stdout1.trim()).expect("invalid JSON");
    assert!(!parsed1.as_array().unwrap().is_empty());

    // port2 should find listener2
    let output2 = opn_cmd()
        .args(["port", &port2.to_string(), "--json"])
        .output()
        .expect("failed to run opn");
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let parsed2: serde_json::Value = serde_json::from_str(stdout2.trim()).expect("invalid JSON");
    assert!(!parsed2.as_array().unwrap().is_empty());

    // Verify they found different ports
    let addr1 = parsed1.as_array().unwrap()[0]["local_addr"]
        .as_str()
        .unwrap()
        .to_string();
    let addr2 = parsed2.as_array().unwrap()[0]["local_addr"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(
        addr1, addr2,
        "Different ports should produce different local_addr values"
    );

    drop(listener1);
    drop(listener2);
}

// ============================================================
// End-to-end: sockets listing includes active listener
// ============================================================

#[test]
fn test_e2e_sockets_lists_own_tcp_listener() {
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["sockets", "--json"])
        .output()
        .expect("failed to run opn");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not yet implemented"),
            "Expected sockets support or explicit not-implemented. stderr={}",
            stderr
        );
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().expect("expected array");
    let found = arr.iter().any(|entry| {
        entry["process"]["pid"].as_u64() == Some(my_pid as u64)
            && entry["local_addr"]
                .as_str()
                .map(|a| a.ends_with(&format!(":{}", port)))
                .unwrap_or(false)
    });
    assert!(
        found,
        "Expected sockets list to include our listener pid={} port={}. Output={}",
        my_pid, port, stdout
    );

    drop(listener);
}

#[test]
fn test_e2e_sockets_state_filter_listen() {
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["sockets", "--state", "LISTEN", "--json"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().expect("expected array");
    let found = arr.iter().any(|entry| {
        entry["state"]
            .as_str()
            .map(|s| s.eq_ignore_ascii_case("LISTEN"))
            .unwrap_or(false)
            && entry["process"]["pid"].as_u64() == Some(my_pid as u64)
            && entry["local_addr"]
                .as_str()
                .map(|a| a.ends_with(&format!(":{}", port)))
                .unwrap_or(false)
    });
    assert!(
        found,
        "Expected LISTEN sockets entry for our listener. Output={}",
        stdout
    );
}

// ============================================================
// End-to-end: opn pid with a known open file
// ============================================================

#[test]
fn test_e2e_pid_shows_open_tcp_socket() {
    // Open a TCP listener, then use opn pid to verify the socket FD appears
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().unwrap();

    // Should find at least one Socket-type FD (our TCP listener)
    let has_socket = arr.iter().any(|entry| {
        entry["fd_type"]
            .as_str()
            .map(|t| t == "Socket")
            .unwrap_or(false)
    });
    assert!(
        has_socket,
        "Expected to find a Socket FD for PID {} (has a TCP listener). Got: {}",
        my_pid, stdout
    );

    drop(listener);
}

#[test]
fn test_e2e_pid_table_output_has_headers() {
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string()])
        .output()
        .expect("failed to run opn");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Table output should contain the OpenFile headers
    assert!(
        stdout.contains("PID") && stdout.contains("TYPE") && stdout.contains("PATH"),
        "Expected table headers PID/TYPE/PATH in output: {}",
        stdout
    );
}

#[test]
fn test_e2e_pid_with_user_filter() {
    let my_pid = std::process::id();

    // With our own username, should still return results
    let whoami = std::process::Command::new("whoami")
        .output()
        .expect("whoami failed");
    let username = String::from_utf8_lossy(&whoami.stdout).trim().to_string();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string(), "--user", &username, "--json"])
        .output()
        .expect("failed to run opn");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "Filtering by our own username '{}' should return results for PID {}",
        username,
        my_pid
    );

    // With a bogus username, should return empty
    let output_bogus = opn_cmd()
        .args([
            "pid",
            &my_pid.to_string(),
            "--user",
            "nonexistent_user_xyz",
            "--json",
        ])
        .output()
        .expect("failed to run opn");
    let stdout_bogus = String::from_utf8_lossy(&output_bogus.stdout);
    let parsed_bogus: serde_json::Value =
        serde_json::from_str(stdout_bogus.trim()).expect("invalid JSON");
    assert!(
        parsed_bogus.as_array().unwrap().is_empty(),
        "Bogus user filter should return empty for PID {}. Got: {}",
        my_pid,
        stdout_bogus
    );
}

// ============================================================
// End-to-end: opn file finds a running executable
// ============================================================

#[test]
fn test_e2e_file_finds_running_executable() {
    // Start a long-running child process so we can look up its executable
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("failed to spawn sleep");

    // /bin/sleep or /usr/bin/sleep — find the real path
    let sleep_path_output = Command::new("which")
        .arg("sleep")
        .output()
        .expect("failed to run which");
    let sleep_path = String::from_utf8_lossy(&sleep_path_output.stdout)
        .trim()
        .to_string();

    // Canonicalize to resolve symlinks (e.g., /bin -> /usr/bin on macOS)
    let canonical_path =
        fs::canonicalize(&sleep_path).unwrap_or_else(|_| std::path::PathBuf::from(&sleep_path));

    let output = opn_cmd()
        .args(["file", canonical_path.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // On macOS, file lookup matches process executables
    if output.status.success() && !stdout.trim().is_empty() {
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        let arr = parsed.as_array().unwrap();

        // Should find at least the sleep process we spawned
        let child_pid = child.id();
        let found_child = arr.iter().any(|entry| {
            entry["process"]["pid"]
                .as_u64()
                .map(|pid| pid == child_pid as u64)
                .unwrap_or(false)
        });
        assert!(
            found_child,
            "Expected to find child PID {} (sleep) when looking up '{}'. Results: {}",
            child_pid,
            canonical_path.display(),
            stdout
        );
    }
    // If it didn't find anything, that's OK on platforms with limited file lookup
    // but it shouldn't have panicked
    assert!(
        !stderr.contains("panic"),
        "opn file should not panic: {}",
        stderr
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn test_e2e_file_table_output() {
    // Spawn sleep and look it up in table mode
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("failed to spawn sleep");

    let sleep_path_output = Command::new("which")
        .arg("sleep")
        .output()
        .expect("failed to run which");
    let sleep_path = String::from_utf8_lossy(&sleep_path_output.stdout)
        .trim()
        .to_string();
    let canonical_path =
        fs::canonicalize(&sleep_path).unwrap_or_else(|_| std::path::PathBuf::from(&sleep_path));

    let output = opn_cmd()
        .args(["file", canonical_path.to_str().unwrap()])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);

    if !stdout.trim().is_empty() {
        // Table should have headers
        assert!(
            stdout.contains("PID") && stdout.contains("PROCESS"),
            "Expected table headers in file output: {}",
            stdout
        );
        // Should mention sleep
        assert!(
            stdout.contains("sleep"),
            "Expected 'sleep' in file output: {}",
            stdout
        );
    }

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn test_e2e_file_json_schema_validation() {
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("failed to spawn sleep");

    let sleep_path_output = Command::new("which")
        .arg("sleep")
        .output()
        .expect("failed to run which");
    let sleep_path = String::from_utf8_lossy(&sleep_path_output.stdout)
        .trim()
        .to_string();
    let canonical_path =
        fs::canonicalize(&sleep_path).unwrap_or_else(|_| std::path::PathBuf::from(&sleep_path));

    let output = opn_cmd()
        .args(["file", canonical_path.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() && stdout.trim() != "[]" {
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        let arr = parsed.as_array().unwrap();

        for entry in arr {
            // fd is Option<i32>: present as number for real FDs, absent for exe matches
            assert!(
                entry.get("fd").is_none() || entry["fd"].is_number(),
                "fd should be a number or absent"
            );
            assert!(entry["fd_type"].is_string(), "Missing fd_type field");
            assert!(entry["path"].is_string(), "Missing path field");
            assert!(entry["deleted"].is_boolean(), "Missing deleted field");
            assert!(entry["process"].is_object(), "Missing process object");
            assert!(entry["process"]["pid"].is_number(), "Missing process.pid");
            assert!(entry["process"]["name"].is_string(), "Missing process.name");
            assert!(entry["process"]["user"].is_string(), "Missing process.user");
        }
    }

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn test_e2e_file_killed_process_not_found() {
    // Start a process, get its executable path, kill it, then search — should not find it
    let mut child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("failed to spawn sleep");
    let child_pid = child.id();

    let sleep_path_output = Command::new("which")
        .arg("sleep")
        .output()
        .expect("failed to run which");
    let sleep_path = String::from_utf8_lossy(&sleep_path_output.stdout)
        .trim()
        .to_string();
    let canonical_path =
        fs::canonicalize(&sleep_path).unwrap_or_else(|_| std::path::PathBuf::from(&sleep_path));

    // Kill the child first
    child.kill().ok();
    child.wait().ok();
    std::thread::sleep(std::time::Duration::from_millis(100));

    let output = opn_cmd()
        .args(["file", canonical_path.to_str().unwrap(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.trim().is_empty() && stdout.trim() != "[]" {
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        let arr = parsed.as_array().unwrap();
        // The killed child should NOT be in results
        let found_dead_child = arr.iter().any(|entry| {
            entry["process"]["pid"]
                .as_u64()
                .map(|pid| pid == child_pid as u64)
                .unwrap_or(false)
        });
        assert!(
            !found_dead_child,
            "Killed PID {} should not appear in results: {}",
            child_pid, stdout
        );
    }
}

// ============================================================
// End-to-end: opn deleted
// ============================================================

#[test]
fn test_e2e_deleted_with_open_deleted_file() {
    // Create a temp file, open it, delete it, then check opn deleted
    let tmp_path = format!("/tmp/opn_test_deleted_{}", std::process::id());
    {
        let mut f = fs::File::create(&tmp_path).expect("failed to create temp file");
        f.write_all(b"test data for deleted file detection")
            .expect("failed to write");
    }

    // Open the file and keep the handle, then delete the path
    let _held_file = fs::File::open(&tmp_path).expect("failed to open temp file");
    fs::remove_file(&tmp_path).expect("failed to delete temp file");

    let output = opn_cmd()
        .args(["deleted", "--json"])
        .output()
        .expect("failed to run opn");

    let stderr = String::from_utf8_lossy(&output.stderr);

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        assert!(
            parsed.is_array(),
            "Expected JSON array from deleted command"
        );

        // On Linux, this should find the deleted file held open by our process
        // On macOS, find_deleted may not be implemented yet
        let arr = parsed.as_array().unwrap();
        if !arr.is_empty() {
            // Validate schema of any results
            for entry in arr {
                assert!(entry["fd"].is_number(), "Missing fd");
                assert!(
                    entry["deleted"].as_bool() == Some(true),
                    "deleted should be true"
                );
                assert!(entry["process"].is_object(), "Missing process");
            }
        }
    } else {
        // Acceptable: macOS returns "not yet implemented"
        assert!(
            stderr.contains("not yet implemented"),
            "Expected either success or 'not yet implemented', got: {}",
            stderr
        );
    }

    // _held_file drops here, releasing the deleted file
}

#[test]
fn test_e2e_deleted_json_is_valid() {
    let output = opn_cmd()
        .args(["deleted", "--json"])
        .output()
        .expect("failed to run opn");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(stdout.trim());
        assert!(
            parsed.is_ok(),
            "deleted --json should produce valid JSON: {}",
            stdout
        );
        assert!(parsed.unwrap().is_array());
    }
}

#[test]
fn test_e2e_deleted_with_user_filter() {
    let whoami = Command::new("whoami").output().expect("whoami failed");
    let username = String::from_utf8_lossy(&whoami.stdout).trim().to_string();

    let output = opn_cmd()
        .args(["deleted", "--user", &username, "--json"])
        .output()
        .expect("failed to run opn");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        let arr = parsed.as_array().unwrap();
        // All results should belong to our user
        for entry in arr {
            let entry_user = entry["process"]["user"].as_str().unwrap_or("");
            assert_eq!(
                entry_user, username,
                "User filter should only return entries for '{}', got '{}'",
                username, entry_user
            );
        }
    }
}

// ============================================================
// End-to-end: opn pid with open file handle
// ============================================================

#[test]
fn test_e2e_pid_shows_open_file_handle() {
    // Open a known file and check opn pid shows it (or at least shows an FD)
    let tmp_path = format!("/tmp/opn_test_pid_file_{}", std::process::id());
    {
        let mut f = fs::File::create(&tmp_path).expect("failed to create temp file");
        f.write_all(b"test data").expect("failed to write");
    }
    let _held_file = fs::File::open(&tmp_path).expect("failed to open temp file");
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().unwrap();

    // We should have more FDs now than just stdin/stdout/stderr
    // At minimum: 0, 1, 2 + the held file + the TCP listener from other tests
    assert!(
        arr.len() >= 4,
        "Expected at least 4 open FDs for PID {} (stdin/stdout/stderr + held file). Got {}. Output: {}",
        my_pid,
        arr.len(),
        stdout
    );

    // Clean up
    drop(_held_file);
    fs::remove_file(&tmp_path).ok();
}

// ============================================================
// End-to-end: verify port lookup finds correct process name
// ============================================================

#[test]
fn test_e2e_port_shows_correct_process_name() {
    let Some(listener) = bind_tcp_local() else {
        return;
    };
    let port = listener.local_addr().unwrap().port();

    let output = opn_cmd()
        .args(["port", &port.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().unwrap();
    assert!(!arr.is_empty());

    // The process name should be the test runner binary name (contains "opn" or "cli_integration")
    let our_entry = arr.iter().find(|e| {
        e["process"]["pid"]
            .as_u64()
            .map(|pid| pid == std::process::id() as u64)
            .unwrap_or(false)
    });
    assert!(our_entry.is_some(), "Should find our PID in results");

    let process_name = our_entry.unwrap()["process"]["name"].as_str().unwrap_or("");
    assert!(!process_name.is_empty(), "Process name should not be empty");
    // The process name should be a real name, not <unknown>
    assert!(
        process_name != "<unknown>",
        "Process name should be resolved, not <unknown>"
    );

    drop(listener);
}

// ============================================================
// macOS-specific FFI path/deleted behavior
// ============================================================

#[cfg(target_os = "macos")]
#[test]
fn test_macos_vnode_path_resolution_for_pid() {
    let tmp_path = format!("/tmp/opn_macos_vnode_path_{}", std::process::id());
    let mut f = fs::File::create(&tmp_path).expect("failed to create temp file");
    f.write_all(b"macos-vnode-path")
        .expect("failed to write temp file");
    let _held = fs::File::open(&tmp_path).expect("failed to reopen temp file");

    let output = opn_cmd()
        .args(["pid", &std::process::id().to_string(), "--json"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    let arr = parsed.as_array().expect("expected array");
    let aliases = tmp_path_aliases(&tmp_path);
    let found = arr.iter().any(|entry| {
        entry["path"]
            .as_str()
            .map(|p| aliases.iter().any(|a| a == p))
            .unwrap_or(false)
    });
    assert!(
        found,
        "Expected pid output to include vnode path '{}'. Output={}",
        tmp_path, stdout
    );

    drop(_held);
    fs::remove_file(&tmp_path).ok();
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_deleted_detects_unlinked_open_file() {
    let tmp_path = format!("/tmp/opn_macos_deleted_{}", std::process::id());
    let mut created = fs::File::create(&tmp_path).expect("failed to create temp file");
    created
        .write_all(b"macos-deleted-detection")
        .expect("failed to write");
    let held = fs::File::open(&tmp_path).expect("failed to open temp file");
    fs::remove_file(&tmp_path).expect("failed to unlink temp file");

    let mut found = false;
    let aliases = tmp_path_aliases(&tmp_path);
    for _ in 0..10 {
        let output = opn_cmd()
            .args([
                "deleted",
                "--filter-pid",
                &std::process::id().to_string(),
                "--json",
            ])
            .output()
            .expect("failed to run opn");
        assert_non_error_exit(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
        let arr = parsed.as_array().expect("expected array");
        found = arr.iter().any(|entry| {
            entry["path"]
                .as_str()
                .map(|p| aliases.iter().any(|a| a == p))
                .unwrap_or(false)
                && entry["deleted"].as_bool().unwrap_or(false)
        });
        if found {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        found,
        "Expected deleted output to include unlinked open file '{}'",
        tmp_path
    );

    drop(held);
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_deleted_restricted_pid_nonfatal() {
    let output = opn_cmd()
        .args(["deleted", "--filter-pid", "1", "--json"])
        .output()
        .expect("failed to run opn");
    assert_non_error_exit(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("invalid JSON");
    assert!(parsed.is_array());
}
