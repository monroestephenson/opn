use std::process::{Command, Output};

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

fn assert_error_exit(output: &Output) {
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        2,
        "expected exit code 2, got {} stderr={}",
        code,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_llm_stdout(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected valid JSON response, parse error: {e}. stdout={stdout}")
    })
}

fn assert_agent_envelope(val: &Value) {
    assert_eq!(val["schema"], "opn-agent/2");
    assert!(val["ok"].is_boolean(), "missing/invalid ok field: {val}");
    assert!(val["ts"].is_number(), "missing/invalid ts field: {val}");
    assert!(val["cmd"].is_string(), "missing/invalid cmd field: {val}");
    assert!(val["caps"].is_array(), "missing/invalid caps field: {val}");
    assert!(
        val["actions"].is_object(),
        "missing/invalid actions field: {val}"
    );
}

#[test]
fn test_llm_sockets_envelope_and_actions_readonly() {
    let output = opn_cmd()
        .args(["--llm", "sockets"])
        .output()
        .expect("failed to run opn --llm sockets");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    assert!(
        val["data"].is_array(),
        "sockets data should be array: {val}"
    );
    let caps = val["caps"].as_array().expect("caps must be array");
    assert!(
        caps.iter().any(|v| v == "read"),
        "read capability should be present: {caps:?}"
    );
    assert!(
        !caps.iter().any(|v| v == "kill" || v == "firewall"),
        "write capabilities should be absent without --allow-write: {caps:?}"
    );
}

#[test]
fn test_llm_sockets_allow_write_includes_write_caps_and_actions() {
    let output = opn_cmd()
        .args(["--llm", "--allow-write", "sockets"])
        .output()
        .expect("failed to run opn --llm --allow-write sockets");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    let caps = val["caps"].as_array().expect("caps must be array");
    assert!(
        caps.iter().any(|v| v == "kill"),
        "kill cap missing: {caps:?}"
    );
    assert!(
        caps.iter().any(|v| v == "firewall"),
        "firewall cap missing: {caps:?}"
    );
    assert!(
        val["actions"]["kill"].is_string(),
        "kill action should be present in allow-write mode: {}",
        val["actions"]
    );
}

#[test]
fn test_llm_resources_shape() {
    let output = opn_cmd()
        .args(["--llm", "resources"])
        .output()
        .expect("failed to run opn --llm resources");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    assert!(
        val["data"].is_array(),
        "resources should return array payload: {val}"
    );
}

#[test]
fn test_llm_netconfig_shape() {
    let output = opn_cmd()
        .args(["--llm", "netconfig"])
        .output()
        .expect("failed to run opn --llm netconfig");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    assert!(val["data"].is_object(), "netconfig data should be object");
    let data = &val["data"];
    assert!(data["routes"].is_array(), "routes should be array: {data}");
    assert!(
        data["dns_servers"].is_array(),
        "dns_servers should be array: {data}"
    );
    assert!(
        data["interfaces"].is_array(),
        "interfaces should be array: {data}"
    );
}

#[test]
fn test_llm_logs_shape() {
    let output = opn_cmd()
        .args(["--llm", "logs", "--lines", "20"])
        .output()
        .expect("failed to run opn --llm logs");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    let data = &val["data"];
    assert!(data.is_object(), "logs data should be object: {val}");
    assert!(data["source"].is_string(), "logs source missing: {data}");
    assert!(data["entries"].is_array(), "logs entries missing: {data}");
    assert!(data["summary"].is_object(), "logs summary missing: {data}");
}

#[test]
fn test_llm_bandwidth_shape() {
    let output = opn_cmd()
        .args(["--llm", "bandwidth", "--duration", "1"])
        .output()
        .expect("failed to run opn --llm bandwidth");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    let data = &val["data"];
    assert!(data.is_object(), "bandwidth data should be object: {val}");
    assert!(
        data["duration_secs"].is_number(),
        "duration_secs missing: {data}"
    );
    assert!(data["interfaces"].is_array(), "interfaces missing: {data}");
}

#[test]
fn test_llm_capture_success_or_graceful_failure_shape() {
    let output = opn_cmd()
        .args(["--llm", "capture", "--count", "1", "--duration", "1"])
        .output()
        .expect("failed to run opn --llm capture");
    assert_non_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);

    if val["ok"].as_bool() == Some(true) {
        assert!(
            val["data"].is_object(),
            "capture ok=true must have object data"
        );
        assert!(
            val["data"]["packets_captured"].is_number(),
            "capture packets_captured missing: {}",
            val["data"]
        );
    } else {
        assert!(
            val["data"]["error"].is_string(),
            "capture ok=false must include data.error: {val}"
        );
        assert!(
            val["warnings"].is_array(),
            "capture failure should include warnings array: {val}"
        );
    }
}

#[test]
fn test_llm_write_guard_uses_agent_error_envelope() {
    let output = opn_cmd()
        .args(["--llm", "kill", "1"])
        .output()
        .expect("failed to run opn --llm kill 1");
    assert_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    assert_eq!(val["ok"], false);
    assert!(
        val["data"]["error"].is_object(),
        "expected structured error object in data.error: {val}"
    );
    assert!(
        val["warnings"].is_array(),
        "expected warnings array in llm error envelope: {val}"
    );
}

#[test]
fn test_llm_runtime_error_uses_agent_error_envelope() {
    let output = opn_cmd()
        .args(["--llm", "diff", "/definitely/not/a/snapshot.json"])
        .output()
        .expect("failed to run opn --llm diff");
    assert_error_exit(&output);
    let val = parse_llm_stdout(&output);
    assert_agent_envelope(&val);
    assert_eq!(val["ok"], false);
    assert!(
        val["data"]["error"].is_object(),
        "expected structured error object in data.error: {val}"
    );
    assert!(
        val["warnings"].is_array(),
        "expected warnings array in llm error envelope: {val}"
    );
}
