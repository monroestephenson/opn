//! End-to-end coverage for newly added operational commands.
//! These tests execute the compiled `opn` binary and validate behavior/shape.

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
}

fn assert_non_error_exit(output: &Output) {
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "Expected non-error exit code (0/1), got {code}. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn llm_json(args: &[&str]) -> serde_json::Value {
    let output = opn_cmd()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {:?}: {e}", args));
    assert_non_error_exit(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON for {:?}: {e}, stdout={stdout}", args))
}

fn bind_tcp_local() -> Option<TcpListener> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => Some(l),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(e) => panic!("failed to bind local TCP listener: {}", e),
    }
}

#[test]
fn test_help_includes_new_commands() {
    let output = opn_cmd().arg("--help").output().expect("failed to run opn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("resources"));
    assert!(stdout.contains("netconfig"));
    assert!(stdout.contains("logs"));
    assert!(stdout.contains("bandwidth"));
    assert!(stdout.contains("capture"));
}

#[test]
fn test_logs_lines_validation_rejects_out_of_range() {
    let output = opn_cmd()
        .args(["logs", "--lines", "10001"])
        .output()
        .expect("failed to run opn logs");
    assert!(
        !output.status.success(),
        "expected argument parse failure for --lines 10001"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lines must be in range 1..=10000")
            || stderr.contains("invalid value")
            || stderr.contains("error"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn test_resources_llm_e2e_includes_current_pid_when_filtered() {
    let Some(listener) = bind_tcp_local() else {
        eprintln!("skipping: local TCP bind not permitted in this environment");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    let pid = std::process::id().to_string();

    let val = llm_json(&["--llm", "resources", "--pid", &pid]);
    assert_eq!(val["schema"], "opn-agent/1");
    assert!(val["data"].is_array(), "resources data should be array");

    let arr = val["data"]
        .as_array()
        .expect("resources data must be array");
    let mine = arr
        .iter()
        .find(|e| e["pid"].as_u64() == Some(std::process::id() as u64));

    assert!(mine.is_some(), "expected resources row for current pid");
    let mine = mine.unwrap();
    assert!(mine["cpu"].is_number(), "cpu must be numeric");
    assert!(mine["rss_kb"].is_number(), "rss_kb must be numeric");
    assert!(mine["vms_kb"].is_number(), "vms_kb must be numeric");
    assert!(mine["fds"].is_number(), "fds must be numeric");
    assert!(mine["threads"].is_number(), "threads must be numeric");
    assert!(mine["ports"].is_array(), "ports must be array");

    let port_str = format!("127.0.0.1:{port}");
    let has_port = mine["ports"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p.as_str() == Some(port_str.as_str()));
    assert!(
        has_port,
        "expected resources to include listener port {port_str}, row={mine}"
    );

    drop(listener);
}

#[test]
fn test_netconfig_llm_e2e_shape() {
    let val = llm_json(&["--llm", "netconfig"]);
    assert_eq!(val["schema"], "opn-agent/1");
    assert!(val["data"].is_object(), "netconfig data must be object");
    let data = &val["data"];
    assert!(data["routes"].is_array(), "routes must be array");
    assert!(data["dns_servers"].is_array(), "dns_servers must be array");
    assert!(data["dns_search"].is_array(), "dns_search must be array");
    assert!(data["hostname"].is_string(), "hostname must be string");
    assert!(data["interfaces"].is_array(), "interfaces must be array");
}

#[test]
fn test_logs_llm_e2e_shape() {
    let val = llm_json(&["--llm", "logs", "--log-type", "all", "--lines", "50"]);
    assert_eq!(val["schema"], "opn-agent/1");
    let data = &val["data"];
    assert!(data.is_object(), "logs data must be object");
    assert!(data["source"].is_string(), "logs source must be string");
    assert!(
        data["total_lines_read"].is_number(),
        "total_lines_read must be number"
    );
    assert!(
        data["network_relevant"].is_number(),
        "network_relevant must be number"
    );
    assert!(data["entries"].is_array(), "entries must be array");
    assert!(data["summary"].is_object(), "summary must be object");
}

#[test]
fn test_bandwidth_llm_e2e_shape() {
    let val = llm_json(&["--llm", "bandwidth", "--duration", "1"]);
    assert_eq!(val["schema"], "opn-agent/1");
    let data = &val["data"];
    assert!(data.is_object(), "bandwidth data must be object");
    assert!(
        data["duration_secs"].as_u64() == Some(1),
        "duration_secs mismatch: {data}"
    );
    assert!(data["interfaces"].is_array(), "interfaces must be array");
}

#[test]
fn test_capture_llm_e2e_success_or_graceful_failure() {
    let Some(listener) = bind_tcp_local() else {
        eprintln!("skipping: local TCP bind not permitted in this environment");
        return;
    };
    let port = listener.local_addr().unwrap().port();

    // Generate at least one packet on the target port.
    let t = thread::spawn(move || {
        // Slight delay so capture starts first in most runs.
        thread::sleep(Duration::from_millis(200));
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.write_all(b"ping");
        }
    });

    let val = llm_json(&[
        "--llm",
        "capture",
        "--port",
        &port.to_string(),
        "--count",
        "20",
        "--duration",
        "2",
    ]);
    let _ = t.join();

    assert_eq!(val["schema"], "opn-agent/1");
    assert_eq!(val["cmd"], "capture");
    assert!(val["ok"].is_boolean());

    if val["ok"] == serde_json::Value::Bool(true) {
        let data = &val["data"];
        assert!(data.is_object(), "capture ok=true must include object data");
        assert!(
            data["packets_captured"].is_number(),
            "packets_captured missing: {data}"
        );
        assert!(data["connections"].is_array(), "connections must be array");
        assert!(
            data["protocol_dist"].is_object(),
            "protocol_dist must be object"
        );
    } else {
        // In restricted CI environments, capture can fail due to missing tcpdump/perms.
        assert!(
            val["data"]["error"].is_string(),
            "capture failure must contain data.error: {val}"
        );
        assert!(
            val["warnings"].is_array(),
            "capture failure must contain warnings: {val}"
        );
    }

    drop(listener);
}
