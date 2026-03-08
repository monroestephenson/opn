/// Shared helpers for network-related parsing (primarily used by the Linux platform).

use std::net::{Ipv4Addr, Ipv6Addr};

/// /proc/net/tcp stores IPv4 as a single little-endian 32-bit hex.
/// e.g., "0100007F" => 127.0.0.1
pub fn parse_proc_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(hex, 16).ok()?;
    // /proc stores in host byte order (little-endian on x86)
    // The bytes are: val as LE => [b0, b1, b2, b3] => IP is b0.b1.b2.b3
    let bytes = val.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// Parse a hex-encoded IPv6 address from /proc/net/tcp6.
/// Format: 4 groups of 8 hex chars, each group is a little-endian u32.
pub fn parse_proc_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        let le = val.to_le_bytes();
        bytes[i * 4] = le[0];
        bytes[i * 4 + 1] = le[1];
        bytes[i * 4 + 2] = le[2];
        bytes[i * 4 + 3] = le[3];
    }
    Some(Ipv6Addr::from(bytes))
}

/// Parse hex port string.
pub fn parse_hex_port(hex: &str) -> Option<u16> {
    u16::from_str_radix(hex, 16).ok()
}

/// Parse an address:port pair like "0100007F:0050".
pub fn parse_addr_port_v4(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let addr = parse_proc_ipv4(addr_hex)?;
    let port = parse_hex_port(port_hex)?;
    Some((addr, port))
}

/// Parse an IPv6 address:port pair like "00000000000000000000000001000000:0050".
pub fn parse_addr_port_v6(s: &str) -> Option<(Ipv6Addr, u16)> {
    let (addr_hex, port_hex) = s.split_once(':')?;
    let addr = parse_proc_ipv6(addr_hex)?;
    let port = parse_hex_port(port_hex)?;
    Some((addr, port))
}

/// Map TCP state code from /proc/net/tcp to human-readable string.
pub fn tcp_state_name(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parse the TCP state hex string (e.g. "0A") into a state name.
pub fn parse_tcp_state(hex: &str) -> &'static str {
    let code = u8::from_str_radix(hex, 16).unwrap_or(0);
    tcp_state_name(code)
}

/// Represents a parsed line from /proc/net/tcp or /proc/net/tcp6.
#[derive(Debug, Clone)]
pub struct ProcNetEntry {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: u64,
}

/// Parse a single line from /proc/net/tcp.
pub fn parse_proc_net_tcp_line(line: &str) -> Option<ProcNetEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    // fields[0] = "sl", fields[1] = local_address, fields[2] = rem_address,
    // fields[3] = st, fields[9] = inode
    let (local_addr, local_port) = parse_addr_port_v4(fields[1])?;
    let (remote_addr, remote_port) = parse_addr_port_v4(fields[2])?;
    let state = parse_tcp_state(fields[3]).to_string();
    let inode: u64 = fields[9].parse().ok()?;

    Some(ProcNetEntry {
        local_addr: local_addr.to_string(),
        local_port,
        remote_addr: remote_addr.to_string(),
        remote_port,
        state,
        inode,
    })
}

/// Parse a single line from /proc/net/tcp6.
pub fn parse_proc_net_tcp6_line(line: &str) -> Option<ProcNetEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let (local_addr, local_port) = parse_addr_port_v6(fields[1])?;
    let (remote_addr, remote_port) = parse_addr_port_v6(fields[2])?;
    let state = parse_tcp_state(fields[3]).to_string();
    let inode: u64 = fields[9].parse().ok()?;

    Some(ProcNetEntry {
        local_addr: local_addr.to_string(),
        local_port,
        remote_addr: remote_addr.to_string(),
        remote_port,
        state,
        inode,
    })
}

/// Parse a single line from /proc/net/udp.
pub fn parse_proc_net_udp_line(line: &str) -> Option<ProcNetEntry> {
    // Same format as tcp, but state is less meaningful
    parse_proc_net_tcp_line(line).map(|mut e| {
        // UDP states are different — 07 = established, others mostly unused
        // We just show the raw state or simplify
        e.state = if e.state == "CLOSE" { "UNCONN".to_string() } else { e.state };
        e
    })
}

/// Parse a single line from /proc/net/udp6.
pub fn parse_proc_net_udp6_line(line: &str) -> Option<ProcNetEntry> {
    parse_proc_net_tcp6_line(line).map(|mut e| {
        e.state = if e.state == "CLOSE" { "UNCONN".to_string() } else { e.state };
        e
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_ipv4_loopback() {
        let addr = parse_proc_ipv4("0100007F").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_parse_proc_ipv4_any() {
        let addr = parse_proc_ipv4("00000000").unwrap();
        assert_eq!(addr, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_proc_ipv4_example() {
        // 192.168.1.100 in network byte order = 0xC0A80164
        // On LE machine, stored in memory as [0x64, 0x01, 0xA8, 0xC0]
        // /proc prints as hex u32: "6401A8C0"
        let addr = parse_proc_ipv4("6401A8C0").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_parse_hex_port() {
        assert_eq!(parse_hex_port("0050"), Some(80));
        assert_eq!(parse_hex_port("0016"), Some(22));
        assert_eq!(parse_hex_port("1F90"), Some(8080));
    }

    #[test]
    fn test_tcp_state_name() {
        assert_eq!(tcp_state_name(0x0A), "LISTEN");
        assert_eq!(tcp_state_name(0x01), "ESTABLISHED");
        assert_eq!(tcp_state_name(0x06), "TIME_WAIT");
        assert_eq!(tcp_state_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn test_parse_proc_net_tcp_line() {
        // Example line from /proc/net/tcp:
        //   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 12345 1
        let line = "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 12345 1";
        let entry = parse_proc_net_tcp_line(line).unwrap();
        assert_eq!(entry.local_addr, "127.0.0.1");
        assert_eq!(entry.local_port, 80);
        assert_eq!(entry.remote_addr, "0.0.0.0");
        assert_eq!(entry.remote_port, 0);
        assert_eq!(entry.state, "LISTEN");
        assert_eq!(entry.inode, 12345);
    }

    #[test]
    fn test_parse_addr_port_v4() {
        let (addr, port) = parse_addr_port_v4("0100007F:0016").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 22);
    }

    #[test]
    fn test_parse_proc_ipv6_loopback() {
        // ::1 in /proc format: 00000000000000000000000001000000
        let addr = parse_proc_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }
}
