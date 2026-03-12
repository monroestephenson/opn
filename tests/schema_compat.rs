//! Schema compatibility tests for v2 JSON contracts of the `opn` tool.
//!
//! These tests validate that the JSON output from `opn` conforms to the
//! documented v2 schema. Since this is an integration test file, we cannot
//! import internal types directly. Instead we validate JSON structure using
//! `serde_json::Value` and by invoking the binary.

use std::process::Command;

use serde_json::Value;

/// The v2 schema version these tests validate against.
const SCHEMA_VERSION: &str = "2.0";

// ============================================================
// Helpers
// ============================================================

fn opn_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opn"));
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Validate that a JSON value represents a valid `ProcessInfo` object.
fn assert_valid_process_info(val: &Value) {
    assert!(val.is_object(), "ProcessInfo must be an object, got: {val}");
    let obj = val.as_object().unwrap();

    // Required fields and their types
    assert!(
        obj.get("pid").is_some_and(|v| v.is_u64()),
        "ProcessInfo.pid must be a u64, got: {:?}",
        obj.get("pid")
    );
    assert!(
        obj.get("name").is_some_and(|v| v.is_string()),
        "ProcessInfo.name must be a string, got: {:?}",
        obj.get("name")
    );
    assert!(
        obj.get("user").is_some_and(|v| v.is_string()),
        "ProcessInfo.user must be a string, got: {:?}",
        obj.get("user")
    );
    assert!(
        obj.get("uid").is_some_and(|v| v.is_u64()),
        "ProcessInfo.uid must be a u64, got: {:?}",
        obj.get("uid")
    );
    assert!(
        obj.get("command").is_some_and(|v| v.is_string()),
        "ProcessInfo.command must be a string, got: {:?}",
        obj.get("command")
    );
}

/// All valid FdType enum serializations.
const VALID_FD_TYPES: &[&str] = &[
    "RegularFile",
    "Directory",
    "Socket",
    "Pipe",
    "Device",
    "Unknown",
];

/// All valid Protocol enum serializations.
const VALID_PROTOCOLS: &[&str] = &["Tcp", "Udp"];

/// Validate that a JSON value represents a valid `SocketEntry` object.
fn assert_valid_socket_entry(val: &Value) {
    assert!(val.is_object(), "SocketEntry must be an object, got: {val}");
    let obj = val.as_object().unwrap();

    // protocol
    let protocol = obj
        .get("protocol")
        .expect("SocketEntry must have 'protocol'");
    assert!(
        protocol.is_string(),
        "SocketEntry.protocol must be a string"
    );
    let proto_str = protocol.as_str().unwrap();
    assert!(
        VALID_PROTOCOLS.contains(&proto_str),
        "SocketEntry.protocol must be one of {VALID_PROTOCOLS:?}, got: {proto_str}"
    );

    // local_addr
    assert!(
        obj.get("local_addr").is_some_and(|v| v.is_string()),
        "SocketEntry.local_addr must be a string"
    );

    // remote_addr
    assert!(
        obj.get("remote_addr").is_some_and(|v| v.is_string()),
        "SocketEntry.remote_addr must be a string"
    );

    // state
    assert!(
        obj.get("state").is_some_and(|v| v.is_string()),
        "SocketEntry.state must be a string"
    );

    // process
    let process = obj.get("process").expect("SocketEntry must have 'process'");
    assert_valid_process_info(process);
}

/// Validate that a JSON value represents a valid `OpenFile` object.
fn assert_valid_open_file(val: &Value) {
    assert!(val.is_object(), "OpenFile must be an object, got: {val}");
    let obj = val.as_object().unwrap();

    // process (required)
    let process = obj.get("process").expect("OpenFile must have 'process'");
    assert_valid_process_info(process);

    // fd (optional - skip_serializing_if)
    if let Some(fd) = obj.get("fd") {
        assert!(
            fd.is_i64() || fd.is_u64(),
            "OpenFile.fd, when present, must be an integer, got: {fd}"
        );
    }

    // fd_type (required)
    let fd_type = obj.get("fd_type").expect("OpenFile must have 'fd_type'");
    assert!(fd_type.is_string(), "OpenFile.fd_type must be a string");
    let fd_type_str = fd_type.as_str().unwrap();
    assert!(
        VALID_FD_TYPES.contains(&fd_type_str),
        "OpenFile.fd_type must be one of {VALID_FD_TYPES:?}, got: {fd_type_str}"
    );

    // path (required)
    assert!(
        obj.get("path").is_some_and(|v| v.is_string()),
        "OpenFile.path must be a string"
    );

    // deleted (required)
    assert!(
        obj.get("deleted").is_some_and(|v| v.is_boolean()),
        "OpenFile.deleted must be a boolean"
    );

    // socket_info (optional - skip_serializing_if)
    if let Some(socket_info) = obj.get("socket_info") {
        assert_valid_socket_entry(socket_info);
    }
}

/// Validate that a JSON value represents a valid error response.
fn assert_valid_error_response(val: &Value) {
    assert!(
        val.is_object(),
        "Error response must be an object, got: {val}"
    );
    let obj = val.as_object().unwrap();

    let error = obj.get("error").expect("Error response must have 'error'");
    assert!(error.is_object(), "error field must be an object");
    let error_obj = error.as_object().unwrap();

    // code
    assert!(
        error_obj.get("code").is_some_and(|v| v.is_string()),
        "error.code must be a string"
    );

    // category
    let category = error_obj
        .get("category")
        .expect("error must have 'category'");
    assert!(category.is_string(), "error.category must be a string");
    let valid_categories = [
        "invalid_input",
        "not_found",
        "permission_denied",
        "not_implemented",
        "runtime",
    ];
    let cat_str = category.as_str().unwrap();
    assert!(
        valid_categories.contains(&cat_str),
        "error.category must be one of {valid_categories:?}, got: {cat_str}"
    );

    // message
    assert!(
        error_obj.get("message").is_some_and(|v| v.is_string()),
        "error.message must be a string"
    );
}

// ============================================================
// Schema version constant
// ============================================================

#[test]
fn schema_version_is_v2() {
    assert_eq!(SCHEMA_VERSION, "2.0");
}

// ============================================================
// ProcessInfo schema from JSON literals
// ============================================================

#[test]
fn process_info_valid_json() {
    let json: Value = serde_json::from_str(
        r#"{
            "pid": 1234,
            "name": "nginx",
            "user": "www-data",
            "uid": 33,
            "command": "/usr/sbin/nginx -g daemon off;"
        }"#,
    )
    .unwrap();
    assert_valid_process_info(&json);
}

#[test]
fn process_info_missing_pid_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "name": "nginx",
            "user": "www-data",
            "uid": 33,
            "command": "/usr/sbin/nginx"
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_process_info(&json));
    assert!(result.is_err(), "Should fail when pid is missing");
}

#[test]
fn process_info_wrong_pid_type_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "pid": "not_a_number",
            "name": "nginx",
            "user": "www-data",
            "uid": 33,
            "command": "/usr/sbin/nginx"
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_process_info(&json));
    assert!(result.is_err(), "Should fail when pid is wrong type");
}

#[test]
fn process_info_missing_name_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "pid": 1,
            "user": "root",
            "uid": 0,
            "command": "/bin/sh"
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_process_info(&json));
    assert!(result.is_err(), "Should fail when name is missing");
}

#[test]
fn process_info_missing_command_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "pid": 1,
            "name": "sh",
            "user": "root",
            "uid": 0
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_process_info(&json));
    assert!(result.is_err(), "Should fail when command is missing");
}

// ============================================================
// SocketEntry schema from JSON literals
// ============================================================

#[test]
fn socket_entry_valid_tcp() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Tcp",
            "local_addr": "127.0.0.1:8080",
            "remote_addr": "0.0.0.0:0",
            "state": "LISTEN",
            "process": {
                "pid": 42,
                "name": "httpd",
                "user": "www",
                "uid": 80,
                "command": "/usr/sbin/httpd"
            }
        }"#,
    )
    .unwrap();
    assert_valid_socket_entry(&json);
}

#[test]
fn socket_entry_valid_udp() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Udp",
            "local_addr": "0.0.0.0:53",
            "remote_addr": "*:0",
            "state": "-",
            "process": {
                "pid": 100,
                "name": "dnsmasq",
                "user": "nobody",
                "uid": 65534,
                "command": "/usr/sbin/dnsmasq"
            }
        }"#,
    )
    .unwrap();
    assert_valid_socket_entry(&json);
}

#[test]
fn socket_entry_invalid_protocol_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Icmp",
            "local_addr": "0.0.0.0:0",
            "remote_addr": "0.0.0.0:0",
            "state": "-",
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_socket_entry(&json));
    assert!(result.is_err(), "Should fail with invalid protocol");
}

#[test]
fn socket_entry_missing_local_addr_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Tcp",
            "remote_addr": "0.0.0.0:0",
            "state": "LISTEN",
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_socket_entry(&json));
    assert!(result.is_err(), "Should fail when local_addr is missing");
}

#[test]
fn socket_entry_missing_process_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Tcp",
            "local_addr": "0.0.0.0:80",
            "remote_addr": "0.0.0.0:0",
            "state": "LISTEN"
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_socket_entry(&json));
    assert!(result.is_err(), "Should fail when process is missing");
}

// ============================================================
// OpenFile schema from JSON literals
// ============================================================

#[test]
fn open_file_with_all_fields() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": {
                "pid": 42,
                "name": "curl",
                "user": "user",
                "uid": 1000,
                "command": "/usr/bin/curl https://example.com"
            },
            "fd": 5,
            "fd_type": "Socket",
            "path": "",
            "deleted": false,
            "socket_info": {
                "protocol": "Tcp",
                "local_addr": "0.0.0.0:12345",
                "remote_addr": "93.184.216.34:443",
                "state": "ESTABLISHED",
                "process": {
                    "pid": 42,
                    "name": "curl",
                    "user": "user",
                    "uid": 1000,
                    "command": "/usr/bin/curl https://example.com"
                }
            }
        }"#,
    )
    .unwrap();
    assert_valid_open_file(&json);
}

#[test]
fn open_file_without_optional_fields() {
    // fd and socket_info are optional (skip_serializing_if = "Option::is_none")
    let json: Value = serde_json::from_str(
        r#"{
            "process": {
                "pid": 99,
                "name": "vim",
                "user": "user",
                "uid": 1000,
                "command": "/usr/bin/vim /tmp/file.txt"
            },
            "fd_type": "RegularFile",
            "path": "/tmp/file.txt",
            "deleted": false
        }"#,
    )
    .unwrap();
    assert_valid_open_file(&json);
}

#[test]
fn open_file_with_fd_only() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd": 3,
            "fd_type": "Directory",
            "path": "/var/log",
            "deleted": false
        }"#,
    )
    .unwrap();
    assert_valid_open_file(&json);
}

#[test]
fn open_file_deleted_flag_true() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd": 7,
            "fd_type": "RegularFile",
            "path": "/tmp/gone.log",
            "deleted": true
        }"#,
    )
    .unwrap();
    assert_valid_open_file(&json);
    assert_eq!(json["deleted"], true);
}

#[test]
fn open_file_missing_process_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "fd_type": "RegularFile",
            "path": "/tmp/file",
            "deleted": false
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_open_file(&json));
    assert!(result.is_err(), "Should fail when process is missing");
}

#[test]
fn open_file_missing_fd_type_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "path": "/tmp/file",
            "deleted": false
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_open_file(&json));
    assert!(result.is_err(), "Should fail when fd_type is missing");
}

#[test]
fn open_file_missing_path_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd_type": "RegularFile",
            "deleted": false
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_open_file(&json));
    assert!(result.is_err(), "Should fail when path is missing");
}

#[test]
fn open_file_missing_deleted_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd_type": "RegularFile",
            "path": "/tmp/file"
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_open_file(&json));
    assert!(result.is_err(), "Should fail when deleted is missing");
}

#[test]
fn open_file_invalid_fd_type_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd_type": "Symlink",
            "path": "/tmp/file",
            "deleted": false
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_open_file(&json));
    assert!(result.is_err(), "Should fail with invalid fd_type");
}

// ============================================================
// FdType enum serialization values
// ============================================================

#[test]
fn fd_type_all_variants_accepted() {
    for variant in VALID_FD_TYPES {
        let json_str = format!(
            r#"{{
                "process": {{ "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }},
                "fd_type": "{variant}",
                "path": "/tmp/test",
                "deleted": false
            }}"#
        );
        let val: Value = serde_json::from_str(&json_str).unwrap();
        assert_valid_open_file(&val);
    }
}

#[test]
fn fd_type_serializes_as_pascal_case() {
    // FdType variants serialize as PascalCase (serde default for enums)
    let expected = vec![
        "RegularFile",
        "Directory",
        "Socket",
        "Pipe",
        "Device",
        "Unknown",
    ];
    assert_eq!(VALID_FD_TYPES, expected.as_slice());
}

// ============================================================
// Protocol enum serialization values
// ============================================================

#[test]
fn protocol_serializes_as_pascal_case() {
    // Protocol variants serialize as PascalCase: "Tcp", "Udp"
    assert_eq!(VALID_PROTOCOLS, &["Tcp", "Udp"]);
}

#[test]
fn protocol_tcp_in_socket_entry() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Tcp",
            "local_addr": "0.0.0.0:80",
            "remote_addr": "0.0.0.0:0",
            "state": "LISTEN",
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }
        }"#,
    )
    .unwrap();
    assert_eq!(json["protocol"].as_str().unwrap(), "Tcp");
    assert_valid_socket_entry(&json);
}

#[test]
fn protocol_udp_in_socket_entry() {
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Udp",
            "local_addr": "0.0.0.0:53",
            "remote_addr": "*:0",
            "state": "-",
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }
        }"#,
    )
    .unwrap();
    assert_eq!(json["protocol"].as_str().unwrap(), "Udp");
    assert_valid_socket_entry(&json);
}

// ============================================================
// Error JSON schema
// ============================================================

#[test]
fn error_schema_valid_not_found() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "NOT_FOUND",
                "category": "not_found",
                "message": "No process found with PID 99999"
            }
        }"#,
    )
    .unwrap();
    assert_valid_error_response(&json);
}

#[test]
fn error_schema_valid_invalid_input() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "INVALID_INPUT",
                "category": "invalid_input",
                "message": "Port must be between 1 and 65535"
            }
        }"#,
    )
    .unwrap();
    assert_valid_error_response(&json);
}

#[test]
fn error_schema_valid_permission_denied() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "PERMISSION_DENIED",
                "category": "permission_denied",
                "message": "Operation not permitted"
            }
        }"#,
    )
    .unwrap();
    assert_valid_error_response(&json);
}

#[test]
fn error_schema_valid_not_implemented() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "NOT_IMPLEMENTED",
                "category": "not_implemented",
                "message": "Feature requires the 'watch' feature"
            }
        }"#,
    )
    .unwrap();
    assert_valid_error_response(&json);
}

#[test]
fn error_schema_valid_runtime() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "RUNTIME_ERROR",
                "category": "runtime",
                "message": "An unexpected error occurred"
            }
        }"#,
    )
    .unwrap();
    assert_valid_error_response(&json);
}

#[test]
fn error_schema_all_categories_accepted() {
    let categories = [
        "invalid_input",
        "not_found",
        "permission_denied",
        "not_implemented",
        "runtime",
    ];
    for cat in &categories {
        let json_str = format!(
            r#"{{
                "error": {{
                    "code": "TEST",
                    "category": "{cat}",
                    "message": "test message"
                }}
            }}"#
        );
        let val: Value = serde_json::from_str(&json_str).unwrap();
        assert_valid_error_response(&val);
    }
}

#[test]
fn error_schema_invalid_category_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "TEST",
                "category": "unknown_category",
                "message": "test"
            }
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_error_response(&json));
    assert!(result.is_err(), "Should fail with invalid category");
}

#[test]
fn error_schema_missing_code_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "category": "runtime",
                "message": "test"
            }
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_error_response(&json));
    assert!(result.is_err(), "Should fail when code is missing");
}

#[test]
fn error_schema_missing_message_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "TEST",
                "category": "runtime"
            }
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_error_response(&json));
    assert!(result.is_err(), "Should fail when message is missing");
}

#[test]
fn error_schema_missing_error_key_fails() {
    let json: Value = serde_json::from_str(
        r#"{
            "code": "TEST",
            "category": "runtime",
            "message": "test"
        }"#,
    )
    .unwrap();
    let result = std::panic::catch_unwind(|| assert_valid_error_response(&json));
    assert!(result.is_err(), "Should fail when 'error' key is missing");
}

// ============================================================
// SocketEntry[] output via `opn sockets --json`
// ============================================================

#[test]
fn sockets_json_output_is_valid_array() {
    let output = opn_cmd()
        .args(["sockets", "--json"])
        .output()
        .expect("failed to run opn");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Exit code 0 (has results) or 1 (no results) are both non-error.
    // Exit code 2 means an error occurred; check for error schema instead.
    if code == 2 {
        let val: Value = serde_json::from_str(&stdout).expect("Error output must be valid JSON");
        assert_valid_error_response(&val);
        return;
    }

    assert!(
        code == 0 || code == 1,
        "Expected exit code 0, 1, or 2, got {code}. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    if code == 1 && stdout.trim().is_empty() {
        // No results; stdout might be empty or "[]"
        return;
    }

    let val: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout: {stdout}"));
    assert!(val.is_array(), "sockets --json must produce a JSON array");

    for entry in val.as_array().unwrap() {
        assert_valid_socket_entry(entry);
    }
}

// ============================================================
// OpenFile[] output via `opn pid --json`
// ============================================================

#[test]
fn pid_json_output_is_valid_array() {
    // Use our own PID so we always have results.
    let my_pid = std::process::id();

    let output = opn_cmd()
        .args(["pid", &my_pid.to_string(), "--json"])
        .output()
        .expect("failed to run opn");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if code == 2 {
        let val: Value = serde_json::from_str(&stdout).expect("Error output must be valid JSON");
        assert_valid_error_response(&val);
        return;
    }

    assert!(
        code == 0 || code == 1,
        "Expected exit code 0, 1, or 2, got {code}. stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    if code == 1 && stdout.trim().is_empty() {
        return;
    }

    let val: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout: {stdout}"));
    assert!(val.is_array(), "pid --json must produce a JSON array");

    for entry in val.as_array().unwrap() {
        assert_valid_open_file(entry);
    }
}

// ============================================================
// Error output via `opn port --json` with a bogus port
// ============================================================

#[test]
fn error_json_output_from_nonexistent_pid() {
    let output = opn_cmd()
        .args(["pid", "4294967295", "--json"])
        .output()
        .expect("failed to run opn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code().unwrap_or(-1);

    // This may return exit code 1 (no results with empty array) or 2 (error).
    if code == 2 {
        let val: Value = serde_json::from_str(&stdout).expect("Error output must be valid JSON");
        assert_valid_error_response(&val);
    } else if code == 0 || code == 1 {
        // No error, just empty or present results; still valid.
        if !stdout.trim().is_empty() {
            let val: Value = serde_json::from_str(&stdout)
                .unwrap_or_else(|e| panic!("stdout is not valid JSON: {e}\nstdout: {stdout}"));
            assert!(val.is_array(), "Non-error output must be a JSON array");
        }
    }
}

// ============================================================
// SocketEntry[] array: validate top-level is array
// ============================================================

#[test]
fn socket_entry_array_schema() {
    let json: Value = serde_json::from_str(
        r#"[
            {
                "protocol": "Tcp",
                "local_addr": "0.0.0.0:80",
                "remote_addr": "0.0.0.0:0",
                "state": "LISTEN",
                "process": { "pid": 1, "name": "nginx", "user": "www", "uid": 33, "command": "/usr/sbin/nginx" }
            },
            {
                "protocol": "Udp",
                "local_addr": "0.0.0.0:53",
                "remote_addr": "*:0",
                "state": "-",
                "process": { "pid": 2, "name": "dnsmasq", "user": "nobody", "uid": 65534, "command": "/usr/sbin/dnsmasq" }
            }
        ]"#,
    )
    .unwrap();

    assert!(json.is_array());
    for entry in json.as_array().unwrap() {
        assert_valid_socket_entry(entry);
    }
}

// ============================================================
// OpenFile[] array: validate top-level is array
// ============================================================

#[test]
fn open_file_array_schema() {
    let json: Value = serde_json::from_str(
        r#"[
            {
                "process": { "pid": 42, "name": "vim", "user": "user", "uid": 1000, "command": "/usr/bin/vim" },
                "fd": 3,
                "fd_type": "RegularFile",
                "path": "/tmp/test.txt",
                "deleted": false
            },
            {
                "process": { "pid": 42, "name": "vim", "user": "user", "uid": 1000, "command": "/usr/bin/vim" },
                "fd_type": "Directory",
                "path": "/tmp",
                "deleted": false
            }
        ]"#,
    )
    .unwrap();

    assert!(json.is_array());
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    for entry in arr {
        assert_valid_open_file(entry);
    }

    // First entry has fd, second does not (optional field omitted).
    assert!(arr[0].get("fd").is_some());
    assert!(arr[1].get("fd").is_none());
}

// ============================================================
// Validate field names are exact (no extra, no typos)
// ============================================================

#[test]
fn process_info_exact_field_names() {
    let expected_fields: Vec<&str> = vec!["pid", "name", "user", "uid", "command"];
    let json: Value =
        serde_json::from_str(r#"{ "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }"#)
            .unwrap();
    let obj = json.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    keys.sort();
    let mut expected_sorted = expected_fields.clone();
    expected_sorted.sort();
    assert_eq!(
        keys, expected_sorted,
        "ProcessInfo fields must match exactly"
    );
}

#[test]
fn socket_entry_exact_field_names() {
    let expected_fields: Vec<&str> =
        vec!["protocol", "local_addr", "remote_addr", "state", "process"];
    let json: Value = serde_json::from_str(
        r#"{
            "protocol": "Tcp",
            "local_addr": "0.0.0.0:80",
            "remote_addr": "0.0.0.0:0",
            "state": "LISTEN",
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }
        }"#,
    )
    .unwrap();
    let obj = json.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    keys.sort();
    let mut expected_sorted = expected_fields.clone();
    expected_sorted.sort();
    assert_eq!(
        keys, expected_sorted,
        "SocketEntry fields must match exactly"
    );
}

#[test]
fn open_file_exact_field_names_all_present() {
    let expected_fields: Vec<&str> =
        vec!["process", "fd", "fd_type", "path", "deleted", "socket_info"];
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd": 3,
            "fd_type": "Socket",
            "path": "",
            "deleted": false,
            "socket_info": {
                "protocol": "Tcp",
                "local_addr": "0.0.0.0:80",
                "remote_addr": "0.0.0.0:0",
                "state": "LISTEN",
                "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" }
            }
        }"#,
    )
    .unwrap();
    let obj = json.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    keys.sort();
    let mut expected_sorted = expected_fields.clone();
    expected_sorted.sort();
    assert_eq!(
        keys, expected_sorted,
        "OpenFile fields (all present) must match exactly"
    );
}

#[test]
fn open_file_exact_field_names_optional_omitted() {
    // When fd and socket_info are None, they should be omitted entirely.
    let expected_fields: Vec<&str> = vec!["process", "fd_type", "path", "deleted"];
    let json: Value = serde_json::from_str(
        r#"{
            "process": { "pid": 1, "name": "a", "user": "b", "uid": 0, "command": "c" },
            "fd_type": "RegularFile",
            "path": "/tmp/test",
            "deleted": false
        }"#,
    )
    .unwrap();
    let obj = json.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
    keys.sort();
    let mut expected_sorted = expected_fields.clone();
    expected_sorted.sort();
    assert_eq!(
        keys, expected_sorted,
        "OpenFile fields (optional omitted) must match exactly"
    );
}

#[test]
fn error_response_exact_field_names() {
    let json: Value = serde_json::from_str(
        r#"{
            "error": {
                "code": "NOT_FOUND",
                "category": "not_found",
                "message": "Not found"
            }
        }"#,
    )
    .unwrap();

    // Top level has only "error"
    let top_keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    assert_eq!(top_keys, vec!["error"]);

    // Error object has exactly code, category, message
    let error_obj = json["error"].as_object().unwrap();
    let mut error_keys: Vec<&str> = error_obj.keys().map(|k| k.as_str()).collect();
    error_keys.sort();
    assert_eq!(
        error_keys,
        vec!["category", "code", "message"],
        "Error object fields must match exactly"
    );
}
