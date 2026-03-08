/// Integration tests for the `opn` CLI binary.
/// These tests invoke the compiled binary and verify output behavior.

use std::process::Command;

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
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
    let output = opn_cmd().arg("--version").output().expect("failed to run opn");
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
fn test_sockets_stub_returns_error() {
    let output = opn_cmd()
        .args(["sockets"])
        .output()
        .expect("failed to run opn");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not yet implemented"),
        "Expected stub message, got: {}",
        stderr
    );
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
        stderr.contains("watch") && stderr.contains("feature"),
        "Expected feature-gate message, got: {}",
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
    assert!(output.status.success() || {
        let stderr = String::from_utf8_lossy(&output.stderr);
        stderr.contains("No results")
    });
}

#[test]
fn test_port_with_udp_filter() {
    let output = opn_cmd()
        .args(["port", "19", "--udp"])
        .output()
        .expect("failed to run opn");
    assert!(output.status.success() || {
        let stderr = String::from_utf8_lossy(&output.stderr);
        stderr.contains("No results")
    });
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
        .args(["port", "19", "--filter-pid", "1"])
        .output()
        .expect("failed to run opn");
    // Should not crash
    assert!(output.status.success());
}

#[test]
fn test_filter_user_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--user", "root"])
        .output()
        .expect("failed to run opn");
    assert!(output.status.success());
}

#[test]
fn test_filter_process_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--process", "sshd"])
        .output()
        .expect("failed to run opn");
    assert!(output.status.success());
}

#[test]
fn test_filter_all_flag() {
    let output = opn_cmd()
        .args(["port", "19", "--all"])
        .output()
        .expect("failed to run opn");
    assert!(output.status.success());
}

#[test]
fn test_short_flags() {
    let output = opn_cmd()
        .args(["port", "19", "-a", "-u", "root", "-p", "sshd"])
        .output()
        .expect("failed to run opn");
    assert!(output.status.success());
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
