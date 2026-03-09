use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use pcap::{Capture, Device};

use crate::agent::{self, reverse_dns, AgentResponse};
use crate::render::RenderOutcome;

// ── packet parsing ──────────────────────────────────────────────────────────

struct ParsedPacket {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    proto: String,
    length: u32,
}

/// Map link-layer header → (ip_offset, ip_version) for a given DLT type.
fn link_offsets(data: &[u8], dlt: i32) -> Option<(usize, u8)> {
    match dlt {
        1 => {
            // DLT_EN10MB – Ethernet
            if data.len() < 14 {
                return None;
            }
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            let mut offset = 14usize;
            // 802.1Q VLAN tag
            if ethertype == 0x8100 && data.len() >= 18 {
                ethertype = u16::from_be_bytes([data[16], data[17]]);
                offset = 18;
            }
            match ethertype {
                0x0800 => Some((offset, 4)),
                0x86DD => Some((offset, 6)),
                _ => None,
            }
        }
        0 => {
            // DLT_NULL – BSD loopback (4-byte AF in host byte order)
            if data.len() < 4 {
                return None;
            }
            let af = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            match af {
                2 => Some((4, 4)),  // AF_INET
                30 => Some((4, 6)), // AF_INET6 on macOS
                _ => None,
            }
        }
        113 => {
            // DLT_LINUX_SLL – Linux cooked capture
            if data.len() < 16 {
                return None;
            }
            let ethertype = u16::from_be_bytes([data[14], data[15]]);
            match ethertype {
                0x0800 => Some((16, 4)),
                0x86DD => Some((16, 6)),
                _ => None,
            }
        }
        12 | 228 => Some((0, 4)), // DLT_RAW / DLT_IPV4
        229 => Some((0, 6)),      // DLT_IPV6
        _ => None,
    }
}

fn parse_ipv4(d: &[u8]) -> Option<(String, String, u8, usize, u32)> {
    if d.len() < 20 {
        return None;
    }
    let ihl = (d[0] & 0x0F) as usize * 4;
    if ihl < 20 || d.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([d[2], d[3]]) as u32;
    let proto = d[9];
    let src = std::net::Ipv4Addr::new(d[12], d[13], d[14], d[15]).to_string();
    let dst = std::net::Ipv4Addr::new(d[16], d[17], d[18], d[19]).to_string();
    Some((src, dst, proto, ihl, total_len))
}

fn parse_ipv6(d: &[u8]) -> Option<(String, String, u8, usize, u32)> {
    if d.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([d[4], d[5]]) as u32;
    let next_hdr = d[6];
    let src: [u8; 16] = d[8..24].try_into().ok()?;
    let dst: [u8; 16] = d[24..40].try_into().ok()?;
    let src_ip = std::net::Ipv6Addr::from(src).to_string();
    let dst_ip = std::net::Ipv6Addr::from(dst).to_string();
    Some((src_ip, dst_ip, next_hdr, 40, 40 + payload_len))
}

fn parse_transport(d: &[u8], proto: u8) -> (u16, u16, &'static str) {
    match proto {
        6 if d.len() >= 4 => (
            u16::from_be_bytes([d[0], d[1]]),
            u16::from_be_bytes([d[2], d[3]]),
            "TCP",
        ),
        17 if d.len() >= 4 => (
            u16::from_be_bytes([d[0], d[1]]),
            u16::from_be_bytes([d[2], d[3]]),
            "UDP",
        ),
        1 => (0, 0, "ICMP"),
        58 => (0, 0, "ICMPv6"),
        _ => (0, 0, "OTHER"),
    }
}

fn parse_packet(data: &[u8], dlt: i32) -> Option<ParsedPacket> {
    let (ip_offset, ip_ver) = link_offsets(data, dlt)?;
    let ip_data = data.get(ip_offset..)?;

    let (src_ip, dst_ip, proto_num, ip_hdr_len, total_len) = if ip_ver == 4 {
        parse_ipv4(ip_data)?
    } else {
        parse_ipv6(ip_data)?
    };

    let transport = ip_data.get(ip_hdr_len..).unwrap_or(&[]);
    let (src_port, dst_port, proto) = parse_transport(transport, proto_num);

    Some(ParsedPacket {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        proto: proto.to_string(),
        length: total_len,
    })
}

// ── main command ─────────────────────────────────────────────────────────────

pub fn run(
    interface: Option<&str>,
    port: Option<u16>,
    host: Option<&str>,
    count: u32,
    duration_secs: u64,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    // Build BPF filter
    let mut filter_parts: Vec<String> = Vec::new();
    if let Some(p) = port {
        filter_parts.push(format!("port {p}"));
    }
    if let Some(h) = host {
        filter_parts.push(format!("host {h}"));
    }
    let filter_expr = filter_parts.join(" and ");
    let used_iface: String;

    // Find device
    let device = if let Some(iface) = interface {
        used_iface = iface.to_string();
        Device::list()
            .ok()
            .and_then(|devs| devs.into_iter().find(|d| d.name == iface))
            .unwrap_or_else(|| Device {
                name: iface.to_string(),
                desc: None,
                addresses: vec![],
                flags: pcap::DeviceFlags::empty(),
            })
    } else {
        match Device::lookup() {
            Ok(Some(d)) => {
                used_iface = d.name.clone();
                d
            }
            _ => {
                return render_unavailable("No network device found", llm, allow_write);
            }
        }
    };

    // Open capture (500ms read timeout so we can check the deadline)
    let mut cap = match Capture::from_device(device)
        .map_err(|e| e.to_string())
        .and_then(|b| {
            b.promisc(false)
                .snaplen(65535)
                .timeout(500)
                .open()
                .map_err(|e| e.to_string())
        }) {
        Ok(c) => c,
        Err(e) => {
            let msg = if e.to_ascii_lowercase().contains("permission")
                || e.contains("Operation not permitted")
            {
                String::from(
                    "Insufficient permissions to capture packets. \
                     Try: sudo opn --allow-write capture",
                )
            } else {
                format!("Failed to open capture on {used_iface}: {e}")
            };
            return render_unavailable(&msg, llm, allow_write);
        }
    };

    if !filter_expr.is_empty() {
        if let Err(e) = cap.filter(&filter_expr, true) {
            return render_unavailable(
                &format!("Invalid filter '{filter_expr}': {e}"),
                llm,
                allow_write,
            );
        }
    }

    let dlt = cap.get_datalink().0;
    let deadline = if duration_secs > 0 {
        Some(Instant::now() + Duration::from_secs(duration_secs))
    } else {
        None
    };

    // Capture loop
    let mut packets: Vec<ParsedPacket> = Vec::new();
    loop {
        if packets.len() >= count as usize {
            break;
        }
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }

        match cap.next_packet() {
            Ok(pkt) => {
                if let Some(p) = parse_packet(pkt.data, dlt) {
                    packets.push(p);
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Check deadline; otherwise keep waiting
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    let packets_captured = packets.len();

    // Aggregate connections: (src, dst, proto) → (count, bytes, dst_ip)
    let mut conn_map: HashMap<(String, String, String), (u32, u64, String)> = HashMap::new();
    let mut proto_dist: HashMap<String, u32> = HashMap::new();
    let mut talker_map: HashMap<String, u32> = HashMap::new();

    for p in &packets {
        let src = format!("{}:{}", p.src_ip, p.src_port);
        let dst = format!("{}:{}", p.dst_ip, p.dst_port);
        let key = (src.clone(), dst.clone(), p.proto.clone());
        let entry = conn_map.entry(key).or_insert((0, 0, p.dst_ip.clone()));
        entry.0 += 1;
        entry.1 += p.length as u64;
        *proto_dist.entry(p.proto.clone()).or_insert(0) += 1;
        *talker_map.entry(p.src_ip.clone()).or_insert(0) += 1;
        *talker_map.entry(p.dst_ip.clone()).or_insert(0) += 1;
    }

    let mut connections: Vec<serde_json::Value> = conn_map
        .iter()
        .map(|((src, dst, proto), (pkt_count, bytes, dst_ip))| {
            let rdns_dst = if llm { reverse_dns(dst_ip) } else { None };
            let mut v = serde_json::json!({
                "src": src,
                "dst": dst,
                "proto": proto,
                "packets": pkt_count,
                "bytes": bytes
            });
            if let Some(rdns) = rdns_dst {
                v["rdns_dst"] = serde_json::Value::String(rdns);
            }
            v
        })
        .collect();
    connections.sort_by(|a, b| {
        b["packets"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["packets"].as_u64().unwrap_or(0))
    });

    let mut talkers: Vec<(&String, &u32)> = talker_map.iter().collect();
    talkers.sort_by(|a, b| b.1.cmp(a.1));
    let top_talkers: Vec<String> = talkers
        .iter()
        .take(10)
        .map(|(ip, cnt)| format!("{ip} ({cnt} pkts)"))
        .collect();

    if llm {
        let data = serde_json::json!({
            "interface": used_iface,
            "filter": filter_expr,
            "packets_captured": packets_captured,
            "duration_secs": duration_secs,
            "connections": connections,
            "protocol_dist": proto_dist,
            "top_talkers": top_talkers
        });
        let resp = AgentResponse {
            schema: String::from("opn-agent/1"),
            ok: true,
            ts: agent::current_ts(),
            cmd: String::from("capture"),
            caps: agent::caps(allow_write),
            data: Some(data),
            hints: vec![],
            warnings: if !allow_write {
                vec![String::from("Run with --allow-write for full capabilities")]
            } else {
                vec![]
            },
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!("Captured {packets_captured} packets on {used_iface} (filter: '{filter_expr}')");
        println!(
            "\n{:<40} {:<40} {:<8} {:<8} {:<10}",
            "SRC", "DST", "PROTO", "PKTS", "BYTES"
        );
        println!("{}", "-".repeat(106));
        for conn in &connections {
            println!(
                "{:<40} {:<40} {:<8} {:<8} {:<10}",
                conn["src"].as_str().unwrap_or(""),
                conn["dst"].as_str().unwrap_or(""),
                conn["proto"].as_str().unwrap_or(""),
                conn["packets"].as_u64().unwrap_or(0),
                conn["bytes"].as_u64().unwrap_or(0)
            );
        }
        let mut proto_list: Vec<(&String, &u32)> = proto_dist.iter().collect();
        proto_list.sort_by(|a, b| b.1.cmp(a.1));
        let proto_str: Vec<String> = proto_list
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        println!("\nProtocol distribution: {}", proto_str.join(", "));
        println!("Top talkers: {}", top_talkers.join(", "));
    }

    if packets_captured == 0 {
        Ok(RenderOutcome::NoResults)
    } else {
        Ok(RenderOutcome::HasResults)
    }
}

fn render_unavailable(msg: &str, llm: bool, allow_write: bool) -> Result<RenderOutcome> {
    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/1"),
            ok: false,
            ts: agent::current_ts(),
            cmd: String::from("capture"),
            caps: agent::caps(allow_write),
            data: Some(serde_json::json!({"error": msg})),
            hints: vec![],
            warnings: vec![msg.to_string()],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        eprintln!("{msg}");
    }
    Ok(RenderOutcome::NoResults)
}
