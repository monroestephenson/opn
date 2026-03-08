/// Shared helpers for network-related parsing (primarily used by the Linux platform).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::model::Protocol;

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
    pub protocol: Protocol,
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
        protocol: Protocol::Tcp,
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
        protocol: Protocol::Tcp,
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
        e.protocol = Protocol::Udp;
        // UDP states are different — 07 = established, others mostly unused
        // We just show the raw state or simplify
        e.state = if e.state == "CLOSE" { "UNCONN".to_string() } else { e.state };
        e
    })
}

/// Parse a single line from /proc/net/udp6.
pub fn parse_proc_net_udp6_line(line: &str) -> Option<ProcNetEntry> {
    parse_proc_net_tcp6_line(line).map(|mut e| {
        e.protocol = Protocol::Udp;
        e.state = if e.state == "CLOSE" { "UNCONN".to_string() } else { e.state };
        e
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // IPv4 parsing
    // ============================================================

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
    fn test_parse_proc_ipv4_broadcast() {
        // 255.255.255.255 => LE hex "FFFFFFFF"
        let addr = parse_proc_ipv4("FFFFFFFF").unwrap();
        assert_eq!(addr, Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn test_parse_proc_ipv4_example() {
        let addr = parse_proc_ipv4("6401A8C0").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_parse_proc_ipv4_10_0_0_1() {
        // 10.0.0.1 => LE bytes [0x0A, 0x00, 0x00, 0x01] => hex "0100000A"
        let addr = parse_proc_ipv4("0100000A").unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_parse_proc_ipv4_too_short() {
        assert!(parse_proc_ipv4("0100").is_none());
    }

    #[test]
    fn test_parse_proc_ipv4_too_long() {
        assert!(parse_proc_ipv4("0100007F00").is_none());
    }

    #[test]
    fn test_parse_proc_ipv4_empty() {
        assert!(parse_proc_ipv4("").is_none());
    }

    #[test]
    fn test_parse_proc_ipv4_invalid_hex() {
        assert!(parse_proc_ipv4("ZZZZZZZZ").is_none());
    }

    #[test]
    fn test_parse_proc_ipv4_lowercase() {
        let addr = parse_proc_ipv4("0100007f").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_parse_proc_ipv4_mixed_case() {
        let addr = parse_proc_ipv4("0100007F").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
    }

    // ============================================================
    // IPv6 parsing
    // ============================================================

    #[test]
    fn test_parse_proc_ipv6_loopback() {
        let addr = parse_proc_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_parse_proc_ipv6_any() {
        let addr = parse_proc_ipv6("00000000000000000000000000000000").unwrap();
        assert_eq!(addr, Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn test_parse_proc_ipv6_too_short() {
        assert!(parse_proc_ipv6("0000000000000000").is_none());
    }

    #[test]
    fn test_parse_proc_ipv6_too_long() {
        assert!(parse_proc_ipv6("0000000000000000000000000000000000").is_none());
    }

    #[test]
    fn test_parse_proc_ipv6_empty() {
        assert!(parse_proc_ipv6("").is_none());
    }

    #[test]
    fn test_parse_proc_ipv6_invalid_hex() {
        assert!(parse_proc_ipv6("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ").is_none());
    }

    // ============================================================
    // Hex port parsing
    // ============================================================

    #[test]
    fn test_parse_hex_port() {
        assert_eq!(parse_hex_port("0050"), Some(80));
        assert_eq!(parse_hex_port("0016"), Some(22));
        assert_eq!(parse_hex_port("1F90"), Some(8080));
    }

    #[test]
    fn test_parse_hex_port_zero() {
        assert_eq!(parse_hex_port("0000"), Some(0));
    }

    #[test]
    fn test_parse_hex_port_max() {
        assert_eq!(parse_hex_port("FFFF"), Some(65535));
    }

    #[test]
    fn test_parse_hex_port_common_ports() {
        assert_eq!(parse_hex_port("01BB"), Some(443)); // HTTPS
        assert_eq!(parse_hex_port("0015"), Some(21));  // FTP
        assert_eq!(parse_hex_port("0019"), Some(25));  // SMTP
        assert_eq!(parse_hex_port("006F"), Some(111)); // RPC
        assert_eq!(parse_hex_port("0035"), Some(53));  // DNS
    }

    #[test]
    fn test_parse_hex_port_lowercase() {
        assert_eq!(parse_hex_port("1f90"), Some(8080));
    }

    #[test]
    fn test_parse_hex_port_empty() {
        assert!(parse_hex_port("").is_none());
    }

    #[test]
    fn test_parse_hex_port_invalid() {
        assert!(parse_hex_port("ZZZZ").is_none());
    }

    #[test]
    fn test_parse_hex_port_overflow() {
        // More than u16 max
        assert!(parse_hex_port("10000").is_none());
    }

    // ============================================================
    // Address:port pairs
    // ============================================================

    #[test]
    fn test_parse_addr_port_v4() {
        let (addr, port) = parse_addr_port_v4("0100007F:0016").unwrap();
        assert_eq!(addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(port, 22);
    }

    #[test]
    fn test_parse_addr_port_v4_any_http() {
        let (addr, port) = parse_addr_port_v4("00000000:0050").unwrap();
        assert_eq!(addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_addr_port_v4_no_colon() {
        assert!(parse_addr_port_v4("0100007F0016").is_none());
    }

    #[test]
    fn test_parse_addr_port_v4_empty() {
        assert!(parse_addr_port_v4("").is_none());
    }

    #[test]
    fn test_parse_addr_port_v4_bad_addr() {
        assert!(parse_addr_port_v4("ZZZZZZZZ:0050").is_none());
    }

    #[test]
    fn test_parse_addr_port_v4_bad_port() {
        assert!(parse_addr_port_v4("0100007F:ZZZZ").is_none());
    }

    #[test]
    fn test_parse_addr_port_v6_loopback() {
        let (addr, port) = parse_addr_port_v6("00000000000000000000000001000000:0050").unwrap();
        assert_eq!(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_addr_port_v6_any() {
        let (addr, port) = parse_addr_port_v6("00000000000000000000000000000000:01BB").unwrap();
        assert_eq!(addr, Ipv6Addr::UNSPECIFIED);
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_addr_port_v6_no_colon() {
        assert!(parse_addr_port_v6("000000000000000000000000000000000050").is_none());
    }

    // ============================================================
    // TCP state codes
    // ============================================================

    #[test]
    fn test_tcp_state_name() {
        assert_eq!(tcp_state_name(0x0A), "LISTEN");
        assert_eq!(tcp_state_name(0x01), "ESTABLISHED");
        assert_eq!(tcp_state_name(0x06), "TIME_WAIT");
        assert_eq!(tcp_state_name(0xFF), "UNKNOWN");
    }

    #[test]
    fn test_tcp_state_name_all_defined() {
        assert_eq!(tcp_state_name(0x01), "ESTABLISHED");
        assert_eq!(tcp_state_name(0x02), "SYN_SENT");
        assert_eq!(tcp_state_name(0x03), "SYN_RECV");
        assert_eq!(tcp_state_name(0x04), "FIN_WAIT1");
        assert_eq!(tcp_state_name(0x05), "FIN_WAIT2");
        assert_eq!(tcp_state_name(0x06), "TIME_WAIT");
        assert_eq!(tcp_state_name(0x07), "CLOSE");
        assert_eq!(tcp_state_name(0x08), "CLOSE_WAIT");
        assert_eq!(tcp_state_name(0x09), "LAST_ACK");
        assert_eq!(tcp_state_name(0x0A), "LISTEN");
        assert_eq!(tcp_state_name(0x0B), "CLOSING");
    }

    #[test]
    fn test_tcp_state_name_zero() {
        assert_eq!(tcp_state_name(0x00), "UNKNOWN");
    }

    #[test]
    fn test_tcp_state_name_boundary() {
        assert_eq!(tcp_state_name(0x0C), "UNKNOWN");
    }

    #[test]
    fn test_parse_tcp_state_hex() {
        assert_eq!(parse_tcp_state("0A"), "LISTEN");
        assert_eq!(parse_tcp_state("01"), "ESTABLISHED");
        assert_eq!(parse_tcp_state("06"), "TIME_WAIT");
    }

    #[test]
    fn test_parse_tcp_state_lowercase() {
        assert_eq!(parse_tcp_state("0a"), "LISTEN");
    }

    #[test]
    fn test_parse_tcp_state_invalid() {
        assert_eq!(parse_tcp_state("ZZ"), "UNKNOWN");
    }

    #[test]
    fn test_parse_tcp_state_empty() {
        assert_eq!(parse_tcp_state(""), "UNKNOWN");
    }

    // ============================================================
    // Full /proc/net/tcp line parsing
    // ============================================================

    #[test]
    fn test_parse_proc_net_tcp_line() {
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
    fn test_parse_proc_net_tcp_line_established() {
        let line = "   1: 6401A8C0:1F90 0101A8C0:C350 01 00000000:00000000 00:00000000 00000000  1000 0 67890 1";
        let entry = parse_proc_net_tcp_line(line).unwrap();
        assert_eq!(entry.local_addr, "192.168.1.100");
        assert_eq!(entry.local_port, 8080);
        assert_eq!(entry.remote_addr, "192.168.1.1");
        assert_eq!(entry.remote_port, 50000);
        assert_eq!(entry.state, "ESTABLISHED");
        assert_eq!(entry.inode, 67890);
    }

    #[test]
    fn test_parse_proc_net_tcp_line_time_wait() {
        let line = "   2: 0100007F:1F90 0100007F:C001 06 00000000:00000000 00:00000000 00000000  0 0 0 1";
        let entry = parse_proc_net_tcp_line(line).unwrap();
        assert_eq!(entry.state, "TIME_WAIT");
        assert_eq!(entry.inode, 0);
    }

    #[test]
    fn test_parse_proc_net_tcp_line_too_short() {
        let line = "   0: 0100007F:0050";
        assert!(parse_proc_net_tcp_line(line).is_none());
    }

    #[test]
    fn test_parse_proc_net_tcp_line_header() {
        // The header line should return None
        let line = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        assert!(parse_proc_net_tcp_line(line).is_none());
    }

    #[test]
    fn test_parse_proc_net_tcp_line_empty() {
        assert!(parse_proc_net_tcp_line("").is_none());
    }

    #[test]
    fn test_parse_proc_net_tcp_line_whitespace() {
        assert!(parse_proc_net_tcp_line("   ").is_none());
    }

    // ============================================================
    // /proc/net/tcp6 line parsing
    // ============================================================

    #[test]
    fn test_parse_proc_net_tcp6_line_listen() {
        let line = "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 11111 1";
        let entry = parse_proc_net_tcp6_line(line).unwrap();
        assert_eq!(entry.local_port, 80);
        assert_eq!(entry.remote_port, 0);
        assert_eq!(entry.state, "LISTEN");
        assert_eq!(entry.inode, 11111);
    }

    #[test]
    fn test_parse_proc_net_tcp6_line_loopback() {
        let line = "   1: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0 0 22222 1";
        let entry = parse_proc_net_tcp6_line(line).unwrap();
        assert_eq!(entry.local_addr, "::1");
        assert_eq!(entry.local_port, 443);
        assert_eq!(entry.state, "LISTEN");
        assert_eq!(entry.inode, 22222);
    }

    #[test]
    fn test_parse_proc_net_tcp6_line_too_short() {
        assert!(parse_proc_net_tcp6_line("   0: 0000:0050").is_none());
    }

    // ============================================================
    // /proc/net/udp line parsing
    // ============================================================

    #[test]
    fn test_parse_proc_net_udp_line() {
        let line = "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  0 0 55555 1";
        let entry = parse_proc_net_udp_line(line).unwrap();
        assert_eq!(entry.local_addr, "0.0.0.0");
        assert_eq!(entry.local_port, 53); // DNS
        // State 07 = CLOSE in TCP, but UDP rewrites CLOSE → UNCONN
        assert_eq!(entry.state, "UNCONN");
        assert_eq!(entry.inode, 55555);
    }

    #[test]
    fn test_parse_proc_net_udp_line_unconn() {
        // State 07 maps to "CLOSE" in TCP, but UDP rewrite maps it to itself (not "CLOSE")
        // Actually state 07 = CLOSE in tcp_state_name. UDP rewrites "CLOSE" to "UNCONN"
        let line = "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  0 0 55555 1";
        let entry = parse_proc_net_udp_line(line).unwrap();
        assert_eq!(entry.state, "UNCONN");
    }

    #[test]
    fn test_parse_proc_net_udp_line_non_close_state_preserved() {
        // If state isn't CLOSE, it should be preserved as-is
        let line = "   0: 00000000:0035 00000000:0000 01 00000000:00000000 00:00000000 00000000  0 0 55555 1";
        let entry = parse_proc_net_udp_line(line).unwrap();
        assert_eq!(entry.state, "ESTABLISHED");
    }

    // ============================================================
    // /proc/net/udp6 line parsing
    // ============================================================

    #[test]
    fn test_parse_proc_net_udp6_line() {
        let line = "   0: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000  0 0 66666 1";
        let entry = parse_proc_net_udp6_line(line).unwrap();
        assert_eq!(entry.local_port, 53);
        assert_eq!(entry.state, "UNCONN");
        assert_eq!(entry.inode, 66666);
    }

    // ============================================================
    // Multiple lines (simulated /proc/net/tcp file)
    // ============================================================

    #[test]
    fn test_parse_multiple_tcp_lines() {
        let content = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 100 0 0 10 0
   2: 6401A8C0:C000 0101A8C0:01BB 01 00000000:00000000 02:000000FF 00000000  1000        0 3333 2 0000000000000000 20 4 30 10 -1";

        let entries: Vec<ProcNetEntry> = content
            .lines()
            .skip(1) // skip header
            .filter_map(parse_proc_net_tcp_line)
            .collect();

        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].local_addr, "0.0.0.0");
        assert_eq!(entries[0].local_port, 80);
        assert_eq!(entries[0].state, "LISTEN");
        assert_eq!(entries[0].inode, 1111);

        assert_eq!(entries[1].local_addr, "127.0.0.1");
        assert_eq!(entries[1].local_port, 631); // CUPS
        assert_eq!(entries[1].state, "LISTEN");
        assert_eq!(entries[1].inode, 2222);

        assert_eq!(entries[2].local_addr, "192.168.1.100");
        assert_eq!(entries[2].local_port, 49152);
        assert_eq!(entries[2].remote_addr, "192.168.1.1");
        assert_eq!(entries[2].remote_port, 443);
        assert_eq!(entries[2].state, "ESTABLISHED");
        assert_eq!(entries[2].inode, 3333);
    }
}
