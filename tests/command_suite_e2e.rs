use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

use serde_json::Value;

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
}

fn assert_non_error_exit(output: &Output) {
    let code = output.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "expected exit code 0/1, got {} stderr={}",
        code,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_json_stdout(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected JSON parse success: {e}. stdout={stdout}"))
}

fn parse_llm_stdout(output: &Output) -> Value {
    let val = parse_json_stdout(output);
    assert_eq!(val["schema"], "opn-agent/2", "invalid llm envelope: {val}");
    assert!(val["ok"].is_boolean(), "missing ok field: {val}");
    assert!(val["ts"].is_number(), "missing ts field: {val}");
    assert!(val["cmd"].is_string(), "missing cmd field: {val}");
    val
}

#[test]
fn test_read_commands_have_non_error_exit() {
    let command_sets: [&[&str]; 8] = [
        &["interfaces"],
        &["snmp"],
        &["diagnose"],
        &["resources"],
        &["netconfig"],
        &["logs", "--lines", "20"],
        &["bandwidth", "--duration", "1"],
        &["capture", "--count", "1", "--duration", "1"],
    ];

    for args in command_sets {
        let output = opn_cmd()
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to run {:?}: {e}", args));
        assert_non_error_exit(&output);
    }
}

#[test]
fn test_read_commands_llm_have_valid_envelope() {
    let command_sets: [&[&str]; 9] = [
        &["--llm", "sockets"],
        &["--llm", "deleted"],
        &["--llm", "interfaces"],
        &["--llm", "snmp"],
        &["--llm", "diagnose"],
        &["--llm", "resources"],
        &["--llm", "netconfig"],
        &["--llm", "logs", "--lines", "20"],
        &["--llm", "bandwidth", "--duration", "1"],
    ];

    for args in command_sets {
        let output = opn_cmd()
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to run {:?}: {e}", args));
        assert_non_error_exit(&output);
        let val = parse_llm_stdout(&output);
        assert!(val["caps"].is_array(), "missing caps field: {val}");
        assert!(val["actions"].is_object(), "missing actions field: {val}");
    }
}

#[test]
fn test_snapshot_then_diff_round_trip() {
    let path = std::env::temp_dir().join(format!(
        "opn-test-snapshot-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos()
    ));

    let snapshot_output = opn_cmd()
        .args(["snapshot", "--out"])
        .arg(&path)
        .output()
        .expect("failed to run snapshot");
    assert_non_error_exit(&snapshot_output);

    let diff_output = opn_cmd()
        .arg("diff")
        .arg(&path)
        .output()
        .expect("failed to run diff");
    assert_non_error_exit(&diff_output);

    let _ = std::fs::remove_file(path);
}

#[test]
fn test_history_record_status_and_events_round_trip() {
    let dir = std::env::temp_dir().join(format!(
        "opn-test-history-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("failed to create history temp dir");

    let record_output = opn_cmd()
        .args([
            "history",
            "record",
            "--foreground",
            "--iterations",
            "1",
            "--interval",
            "1",
            "--capacity",
            "100",
            "--data-dir",
        ])
        .arg(&dir)
        .output()
        .expect("failed to run history record");
    assert_non_error_exit(&record_output);

    let status_output = opn_cmd()
        .args(["history", "status", "--json", "--data-dir"])
        .arg(&dir)
        .output()
        .expect("failed to run history status");
    assert_non_error_exit(&status_output);
    let status = parse_json_stdout(&status_output);
    assert_eq!(status["schema"], "opn-history/1");
    assert!(status["retained_events"].is_number());
    assert!(status["tracked_sockets"].is_number());

    let events_output = opn_cmd()
        .args(["history", "events", "--json", "--limit", "5", "--data-dir"])
        .arg(&dir)
        .output()
        .expect("failed to run history events");
    assert_non_error_exit(&events_output);
    let events = parse_json_stdout(&events_output);
    assert!(events.is_array());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn test_write_commands_require_allow_write() {
    let outputs = [
        opn_cmd()
            .args(["kill", "1"])
            .output()
            .expect("failed to run kill"),
        opn_cmd()
            .args(["kill-port", "1"])
            .output()
            .expect("failed to run kill-port"),
        opn_cmd()
            .args(["firewall", "list"])
            .output()
            .expect("failed to run firewall list"),
    ];

    for output in outputs {
        assert_eq!(
            output.status.code(),
            Some(2),
            "write command should fail with code 2"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("requires --allow-write"),
            "expected write-guard error message, got: {stderr}"
        );
    }
}

#[test]
fn test_firewall_llm_write_guard_envelope() {
    let output = opn_cmd()
        .args(["--llm", "firewall", "list"])
        .output()
        .expect("failed to run --llm firewall list");
    assert_eq!(output.status.code(), Some(2));
    let val = parse_llm_stdout(&output);
    assert_eq!(val["ok"], false);
    assert_eq!(val["cmd"], "firewall");
    assert!(
        val["data"]["error"].is_object(),
        "expected structured data.error payload: {val}"
    );
}

#[test]
fn test_firewall_invalid_ip_llm_has_error_envelope() {
    let output = opn_cmd()
        .args([
            "--llm",
            "--allow-write",
            "firewall",
            "block-ip",
            "not-an-ip",
        ])
        .output()
        .expect("failed to run --llm --allow-write firewall block-ip");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_eq!(val["ok"], false);
    assert!(
        val["warnings"].is_array(),
        "expected warnings array on firewall error: {val}"
    );
}

#[test]
fn test_kill_port_llm_write_guard_envelope() {
    let output = opn_cmd()
        .args(["--llm", "kill-port", "1"])
        .output()
        .expect("failed to run --llm kill-port 1");
    assert_eq!(output.status.code(), Some(2));
    let val = parse_llm_stdout(&output);
    assert_eq!(val["ok"], false);
    assert!(
        val["data"]["error"].is_object(),
        "expected structured data.error payload: {val}"
    );
}

#[test]
fn test_firewall_invalid_ip_json_error_shape() {
    let output = opn_cmd()
        .args([
            "--json",
            "--allow-write",
            "firewall",
            "block-ip",
            "not-an-ip",
        ])
        .output()
        .expect("failed to run --json --allow-write firewall block-ip");
    assert_eq!(output.status.code(), Some(2));
    let val = parse_json_stdout(&output);
    assert!(
        val["error"].is_object(),
        "expected top-level error object in --json mode: {val}"
    );
    assert!(
        val["error"]["code"].is_string(),
        "expected error.code string in --json mode: {val}"
    );
}

#[test]
fn test_stress_read_commands_repeat() {
    let command_sets: [&[&str]; 4] = [
        &["interfaces"],
        &["resources"],
        &["netconfig"],
        &["bandwidth", "--duration", "1"],
    ];

    for _ in 0..3 {
        for args in command_sets {
            let output = opn_cmd()
                .args(args)
                .output()
                .unwrap_or_else(|e| panic!("failed to run {:?}: {e}", args));
            assert_non_error_exit(&output);
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            assert!(
                !stderr.contains("panic"),
                "unexpected panic-like stderr for {:?}: {}",
                args,
                stderr
            );
        }
    }
}

#[cfg(feature = "watch")]
#[test]
fn test_watch_smoke_can_start_and_be_interrupted() {
    let mut child = opn_cmd()
        .args(["watch", "--interval", "1"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn watch");

    thread::sleep(Duration::from_millis(1200));

    // If still running, terminate cleanly from the test harness.
    if child.try_wait().expect("failed to poll watch").is_none() {
        child.kill().expect("failed to kill watch process");
        let _ = child.wait();
    } else {
        let out = child.wait_with_output().expect("failed to collect output");
        let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
        assert!(
            !stderr.contains("panic"),
            "watch exited early with panic-like stderr: {stderr}"
        );
    }
}
