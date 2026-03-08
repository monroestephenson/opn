use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub uid: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenFile {
    pub process: Arc<ProcessInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    pub fd_type: FdType,
    pub path: String,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_info: Option<SocketEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum FdType {
    RegularFile,
    Directory,
    Socket,
    Pipe,
    Device,
    Unknown,
}

impl std::fmt::Display for FdType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FdType::RegularFile => write!(f, "REG"),
            FdType::Directory => write!(f, "DIR"),
            FdType::Socket => write!(f, "SOCK"),
            FdType::Pipe => write!(f, "PIPE"),
            FdType::Device => write!(f, "DEV"),
            FdType::Unknown => write!(f, "???"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketEntry {
    pub protocol: Protocol,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub process: Arc<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    pub pid: Option<u32>,
    pub user: Option<String>,
    pub process_name: Option<String>,
    pub state: Option<String>,
    pub tcp: bool,
    pub udp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub all: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // FdType Display
    // ============================================================

    #[test]
    fn test_fdtype_display_regular() {
        assert_eq!(FdType::RegularFile.to_string(), "REG");
    }

    #[test]
    fn test_fdtype_display_directory() {
        assert_eq!(FdType::Directory.to_string(), "DIR");
    }

    #[test]
    fn test_fdtype_display_socket() {
        assert_eq!(FdType::Socket.to_string(), "SOCK");
    }

    #[test]
    fn test_fdtype_display_pipe() {
        assert_eq!(FdType::Pipe.to_string(), "PIPE");
    }

    #[test]
    fn test_fdtype_display_device() {
        assert_eq!(FdType::Device.to_string(), "DEV");
    }

    #[test]
    fn test_fdtype_display_unknown() {
        assert_eq!(FdType::Unknown.to_string(), "???");
    }

    // ============================================================
    // Protocol Display
    // ============================================================

    #[test]
    fn test_protocol_display_tcp() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
    }

    #[test]
    fn test_protocol_display_udp() {
        assert_eq!(Protocol::Udp.to_string(), "UDP");
    }

    // ============================================================
    // FdType PartialEq
    // ============================================================

    #[test]
    fn test_fdtype_equality() {
        assert_eq!(FdType::Socket, FdType::Socket);
        assert_ne!(FdType::Socket, FdType::Pipe);
    }

    // ============================================================
    // Protocol PartialEq
    // ============================================================

    #[test]
    fn test_protocol_equality() {
        assert_eq!(Protocol::Tcp, Protocol::Tcp);
        assert_ne!(Protocol::Tcp, Protocol::Udp);
    }

    // ============================================================
    // QueryFilter default
    // ============================================================

    #[test]
    fn test_query_filter_default() {
        let f = QueryFilter::default();
        assert_eq!(f.pid, None);
        assert_eq!(f.user, None);
        assert_eq!(f.process_name, None);
        assert!(!f.tcp);
        assert!(!f.udp);
        assert!(!f.ipv4);
        assert!(!f.ipv6);
        assert!(!f.all);
    }

    // ============================================================
    // Serialization
    // ============================================================

    #[test]
    fn test_process_info_serialize() {
        let p = ProcessInfo {
            pid: 1234,
            name: "test".to_string(),
            user: "root".to_string(),
            uid: 0,
            command: "/usr/bin/test".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"user\":\"root\""));
        assert!(json.contains("\"uid\":0"));
        assert!(json.contains("\"command\":\"/usr/bin/test\""));
    }

    #[test]
    fn test_socket_entry_serialize() {
        let s = SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1:80".to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: Arc::new(ProcessInfo {
                pid: 1,
                name: "nginx".to_string(),
                user: "www".to_string(),
                uid: 33,
                command: "/usr/sbin/nginx".to_string(),
            }),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"protocol\":\"Tcp\""));
        assert!(json.contains("\"local_addr\":\"127.0.0.1:80\""));
        assert!(json.contains("\"state\":\"LISTEN\""));
    }

    #[test]
    fn test_open_file_serialize_without_socket_info() {
        let f = OpenFile {
            process: Arc::new(ProcessInfo {
                pid: 42,
                name: "vim".to_string(),
                user: "user".to_string(),
                uid: 1000,
                command: "/usr/bin/vim".to_string(),
            }),
            fd: Some(3),
            fd_type: FdType::RegularFile,
            path: "/tmp/test.txt".to_string(),
            deleted: false,
            socket_info: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"fd\":3"));
        assert!(json.contains("\"path\":\"/tmp/test.txt\""));
        assert!(json.contains("\"deleted\":false"));
        // socket_info should be absent (skip_serializing_if)
        assert!(!json.contains("socket_info"));

        // fd: None should be omitted
        let f2 = OpenFile { fd: None, ..f };
        let json2 = serde_json::to_string(&f2).unwrap();
        assert!(!json2.contains("\"fd\""));
    }

    #[test]
    fn test_open_file_serialize_with_socket_info() {
        let proc_info = Arc::new(ProcessInfo {
            pid: 42,
            name: "curl".to_string(),
            user: "user".to_string(),
            uid: 1000,
            command: "/usr/bin/curl".to_string(),
        });
        let f = OpenFile {
            process: proc_info.clone(),
            fd: Some(5),
            fd_type: FdType::Socket,
            path: String::new(),
            deleted: false,
            socket_info: Some(SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "0.0.0.0:12345".to_string(),
                remote_addr: "93.184.216.34:443".to_string(),
                state: "ESTABLISHED".to_string(),
                process: proc_info,
            }),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"socket_info\""));
        assert!(json.contains("ESTABLISHED"));
    }

    #[test]
    fn test_open_file_deleted_serialize() {
        let f = OpenFile {
            process: Arc::new(ProcessInfo {
                pid: 99,
                name: "app".to_string(),
                user: "root".to_string(),
                uid: 0,
                command: "/opt/app".to_string(),
            }),
            fd: Some(7),
            fd_type: FdType::RegularFile,
            path: "/tmp/deleted_file.log".to_string(),
            deleted: true,
            socket_info: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"deleted\":true"));
    }

    #[test]
    fn test_fdtype_serialize() {
        let json = serde_json::to_string(&FdType::RegularFile).unwrap();
        assert_eq!(json, "\"RegularFile\"");
        let json = serde_json::to_string(&FdType::Socket).unwrap();
        assert_eq!(json, "\"Socket\"");
    }

    #[test]
    fn test_protocol_serialize() {
        let json = serde_json::to_string(&Protocol::Tcp).unwrap();
        assert_eq!(json, "\"Tcp\"");
        let json = serde_json::to_string(&Protocol::Udp).unwrap();
        assert_eq!(json, "\"Udp\"");
    }

    // ============================================================
    // Clone
    // ============================================================

    #[test]
    fn test_process_info_clone() {
        let p = ProcessInfo {
            pid: 1,
            name: "test".to_string(),
            user: "root".to_string(),
            uid: 0,
            command: "/bin/test".to_string(),
        };
        let p2 = p.clone();
        assert_eq!(p2.pid, 1);
        assert_eq!(p2.name, "test");
    }

    #[test]
    fn test_socket_entry_clone() {
        let s = SocketEntry {
            protocol: Protocol::Udp,
            local_addr: "0.0.0.0:53".to_string(),
            remote_addr: "*:0".to_string(),
            state: "-".to_string(),
            process: Arc::new(ProcessInfo {
                pid: 100,
                name: "dnsmasq".to_string(),
                user: "nobody".to_string(),
                uid: 65534,
                command: "/usr/sbin/dnsmasq".to_string(),
            }),
        };
        let s2 = s.clone();
        assert_eq!(s2.protocol, Protocol::Udp);
        assert_eq!(s2.process.name, "dnsmasq");
    }

    // ============================================================
    // Special characters in fields
    // ============================================================

    #[test]
    fn test_process_info_with_special_chars() {
        let p = ProcessInfo {
            pid: 1,
            name: "my app (v2)".to_string(),
            user: "user-name".to_string(),
            uid: 1000,
            command: "/opt/my app/bin --flag=\"value\"".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "my app (v2)");
        assert_eq!(parsed["command"], "/opt/my app/bin --flag=\"value\"");
    }

    #[test]
    fn test_process_info_with_unicode() {
        let p = ProcessInfo {
            pid: 1,
            name: "日本語".to_string(),
            user: "ユーザー".to_string(),
            uid: 1000,
            command: "/usr/bin/日本語".to_string(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "日本語");
    }

    #[test]
    fn test_process_info_with_empty_fields() {
        let p = ProcessInfo {
            pid: 0,
            name: String::new(),
            user: String::new(),
            uid: 0,
            command: String::new(),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("\"name\":\"\""));
    }
}
