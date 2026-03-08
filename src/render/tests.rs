/// Tests for render modules: table formatting, JSON output, and Tabular impls.

#[cfg(test)]
mod tests {
    use crate::model::*;
    use crate::render::table::{format_table, Tabular};

    fn make_process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            user: "testuser".to_string(),
            uid: 1000,
            command: format!("/usr/bin/{}", name),
        }
    }

    // ============================================================
    // SocketEntry Tabular impl
    // ============================================================

    #[test]
    fn test_socket_entry_headers() {
        let headers = SocketEntry::headers();
        assert_eq!(headers, vec!["PROTO", "LOCAL ADDRESS", "REMOTE ADDRESS", "STATE", "PID", "PROCESS"]);
    }

    #[test]
    fn test_socket_entry_row() {
        let entry = SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1:80".to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: make_process(1234, "nginx"),
        };
        let row = entry.row();
        assert_eq!(row[0], "TCP");
        assert_eq!(row[1], "127.0.0.1:80");
        assert_eq!(row[2], "0.0.0.0:0");
        assert_eq!(row[3], "LISTEN");
        assert_eq!(row[4], "1234");
        assert_eq!(row[5], "nginx");
    }

    #[test]
    fn test_socket_entry_row_udp() {
        let entry = SocketEntry {
            protocol: Protocol::Udp,
            local_addr: "0.0.0.0:53".to_string(),
            remote_addr: "*:0".to_string(),
            state: "-".to_string(),
            process: make_process(99, "dnsmasq"),
        };
        let row = entry.row();
        assert_eq!(row[0], "UDP");
        assert_eq!(row[1], "0.0.0.0:53");
    }

    // ============================================================
    // OpenFile Tabular impl
    // ============================================================

    #[test]
    fn test_open_file_headers() {
        let headers = OpenFile::headers();
        assert_eq!(headers, vec!["PID", "PROCESS", "USER", "FD", "TYPE", "PATH"]);
    }

    #[test]
    fn test_open_file_row() {
        let file = OpenFile {
            process: make_process(42, "vim"),
            fd: 3,
            fd_type: FdType::RegularFile,
            path: "/tmp/test.txt".to_string(),
            deleted: false,
            socket_info: None,
        };
        let row = file.row();
        assert_eq!(row[0], "42");
        assert_eq!(row[1], "vim");
        assert_eq!(row[2], "testuser");
        assert_eq!(row[3], "3");
        assert_eq!(row[4], "REG");
        assert_eq!(row[5], "/tmp/test.txt");
    }

    #[test]
    fn test_open_file_row_deleted() {
        let file = OpenFile {
            process: make_process(42, "app"),
            fd: 7,
            fd_type: FdType::RegularFile,
            path: "/tmp/old.log".to_string(),
            deleted: true,
            socket_info: None,
        };
        let row = file.row();
        assert_eq!(row[5], "/tmp/old.log (deleted)");
    }

    #[test]
    fn test_open_file_row_socket_type() {
        let file = OpenFile {
            process: make_process(42, "curl"),
            fd: 5,
            fd_type: FdType::Socket,
            path: String::new(),
            deleted: false,
            socket_info: None,
        };
        let row = file.row();
        assert_eq!(row[4], "SOCK");
    }

    #[test]
    fn test_open_file_row_pipe_type() {
        let file = OpenFile {
            process: make_process(42, "bash"),
            fd: 1,
            fd_type: FdType::Pipe,
            path: "pipe:[12345]".to_string(),
            deleted: false,
            socket_info: None,
        };
        let row = file.row();
        assert_eq!(row[4], "PIPE");
    }

    // ============================================================
    // Table formatting
    // ============================================================

    #[test]
    fn test_format_table_empty() {
        let items: Vec<SocketEntry> = vec![];
        let output = format_table(&items);
        assert_eq!(output, "");
    }

    #[test]
    fn test_format_table_single_row() {
        let items = vec![SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: "0.0.0.0:80".to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: make_process(1, "nginx"),
        }];
        let output = format_table(&items);
        // Should contain headers
        assert!(output.contains("PROTO"));
        assert!(output.contains("LOCAL ADDRESS"));
        assert!(output.contains("STATE"));
        // Should contain separator
        assert!(output.contains("---"));
        // Should contain data
        assert!(output.contains("TCP"));
        assert!(output.contains("0.0.0.0:80"));
        assert!(output.contains("LISTEN"));
        assert!(output.contains("nginx"));
    }

    #[test]
    fn test_format_table_multiple_rows() {
        let items = vec![
            SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "0.0.0.0:80".to_string(),
                remote_addr: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
                process: make_process(1, "nginx"),
            },
            SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "0.0.0.0:443".to_string(),
                remote_addr: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
                process: make_process(1, "nginx"),
            },
        ];
        let output = format_table(&items);
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 4); // header + separator + 2 data rows
    }

    #[test]
    fn test_format_table_column_alignment() {
        let items = vec![
            SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1:8080".to_string(),
                remote_addr: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
                process: make_process(12345, "a-very-long-process-name"),
            },
            SocketEntry {
                protocol: Protocol::Udp,
                local_addr: "0.0.0.0:53".to_string(),
                remote_addr: "*:0".to_string(),
                state: "-".to_string(),
                process: make_process(1, "dns"),
            },
        ];
        let output = format_table(&items);
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines.len() >= 4, "Should have header + separator + 2 data rows");
        // Verify separator is all dashes and spaces
        assert!(lines[1].chars().all(|c| c == '-' || c == ' '));
        // Verify header contains expected columns
        assert!(lines[0].contains("PROTO"));
        assert!(lines[0].contains("PROCESS"));
    }

    // ============================================================
    // JSON output
    // ============================================================

    #[test]
    fn test_json_serialize_socket_entries() {
        let items = vec![SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1:80".to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: make_process(1, "nginx"),
        }];
        let json = serde_json::to_string_pretty(&items).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["protocol"], "Tcp");
        assert_eq!(parsed[0]["local_addr"], "127.0.0.1:80");
        assert_eq!(parsed[0]["process"]["pid"], 1);
        assert_eq!(parsed[0]["process"]["name"], "nginx");
    }

    #[test]
    fn test_json_serialize_empty_array() {
        let items: Vec<SocketEntry> = vec![];
        let json = serde_json::to_string_pretty(&items).unwrap();
        assert_eq!(json.trim(), "[]");
    }

    #[test]
    fn test_json_serialize_open_files() {
        let items = vec![OpenFile {
            process: make_process(42, "vim"),
            fd: 3,
            fd_type: FdType::RegularFile,
            path: "/tmp/test.txt".to_string(),
            deleted: false,
            socket_info: None,
        }];
        let json = serde_json::to_string_pretty(&items).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["fd"], 3);
        assert_eq!(parsed[0]["fd_type"], "RegularFile");
        assert_eq!(parsed[0]["path"], "/tmp/test.txt");
        assert_eq!(parsed[0]["deleted"], false);
        // socket_info should be absent
        assert!(parsed[0].get("socket_info").is_none());
    }

    #[test]
    fn test_json_roundtrip_multiple_socket_entries() {
        let items = vec![
            SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "0.0.0.0:80".to_string(),
                remote_addr: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
                process: make_process(1, "nginx"),
            },
            SocketEntry {
                protocol: Protocol::Udp,
                local_addr: "0.0.0.0:53".to_string(),
                remote_addr: "*:0".to_string(),
                state: "-".to_string(),
                process: make_process(2, "dnsmasq"),
            },
        ];
        let json = serde_json::to_string(&items).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["protocol"], "Tcp");
        assert_eq!(parsed[1]["protocol"], "Udp");
    }
}
