pub mod backend;
pub mod bandwidth;
pub mod capture;
pub mod deleted;
pub mod diagnose;
pub mod file;
pub mod firewall;
pub mod history;
pub mod interfaces;
pub mod kill;
pub mod logs;
pub mod netconfig;
pub mod pid;
pub mod port;
pub mod resources;
pub mod snapshot;
pub mod snmp;
pub mod sockets;

use crate::model::{Protocol, SocketEntry};

fn protocol_rank(protocol: &Protocol) -> u8 {
    match protocol {
        Protocol::Tcp => 0,
        Protocol::Udp => 1,
    }
}

fn local_port(addr: &str) -> u16 {
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .unwrap_or(u16::MAX)
}

pub(crate) fn sort_sockets(entries: &mut [SocketEntry]) {
    entries.sort_by(|a, b| {
        (
            protocol_rank(&a.protocol),
            local_port(&a.local_addr),
            &a.local_addr,
            a.process.pid,
        )
            .cmp(&(
                protocol_rank(&b.protocol),
                local_port(&b.local_addr),
                &b.local_addr,
                b.process.pid,
            ))
    });
}

#[cfg(test)]
mod tests {
    use super::sort_sockets;
    use crate::model::{ProcessInfo, Protocol, SocketEntry};
    use std::sync::Arc;

    fn socket(proto: Protocol, local_addr: &str, pid: u32) -> SocketEntry {
        SocketEntry {
            protocol: proto,
            local_addr: local_addr.to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: Arc::new(ProcessInfo {
                pid,
                name: format!("p{pid}"),
                user: "u".to_string(),
                uid: 1,
                command: "cmd".to_string(),
            }),
        }
    }

    #[test]
    fn test_sort_sockets_protocol_then_port() {
        let mut entries = vec![
            socket(Protocol::Udp, "127.0.0.1:53", 3),
            socket(Protocol::Tcp, "127.0.0.1:8080", 2),
            socket(Protocol::Tcp, "127.0.0.1:22", 1),
            socket(Protocol::Udp, "127.0.0.1:5353", 4),
        ];
        sort_sockets(&mut entries);
        let got: Vec<String> = entries
            .iter()
            .map(|e| format!("{} {}", e.protocol, e.local_addr))
            .collect();
        assert_eq!(
            got,
            vec![
                "TCP 127.0.0.1:22",
                "TCP 127.0.0.1:8080",
                "UDP 127.0.0.1:53",
                "UDP 127.0.0.1:5353"
            ]
        );
    }
}
