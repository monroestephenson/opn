use crate::model::SocketEntry;

fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    addr.rsplit_once(':')
}

fn format_addr(addr: &str) -> String {
    let Some((host, port)) = split_host_port(addr) else {
        return addr.to_string();
    };
    if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
        format!("[{host}]:{port}")
    } else {
        addr.to_string()
    }
}

pub fn display_local_addr(entry: &SocketEntry) -> String {
    format_addr(&entry.local_addr)
}

pub fn display_remote_addr(entry: &SocketEntry) -> String {
    if entry.state.eq_ignore_ascii_case("LISTEN") {
        "-".to_string()
    } else {
        format_addr(&entry.remote_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::{display_local_addr, display_remote_addr};
    use crate::model::{ProcessInfo, Protocol, SocketEntry};
    use std::sync::Arc;

    fn socket(local: &str, remote: &str, state: &str) -> SocketEntry {
        SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: local.to_string(),
            remote_addr: remote.to_string(),
            state: state.to_string(),
            process: Arc::new(ProcessInfo {
                pid: 1,
                name: "p".to_string(),
                user: "u".to_string(),
                uid: 1,
                command: "c".to_string(),
            }),
        }
    }

    #[test]
    fn test_display_local_addr_wraps_ipv6() {
        let e = socket(":::8080", ":::0", "LISTEN");
        assert_eq!(display_local_addr(&e), "[::]:8080");
    }

    #[test]
    fn test_display_remote_addr_hides_listen_peer() {
        let e = socket("0.0.0.0:80", "0.0.0.0:0", "LISTEN");
        assert_eq!(display_remote_addr(&e), "-");
    }

    #[test]
    fn test_display_remote_addr_keeps_non_listen_peer() {
        let e = socket("10.0.0.2:51762", "93.184.216.34:443", "ESTABLISHED");
        assert_eq!(display_remote_addr(&e), "93.184.216.34:443");
    }
}
