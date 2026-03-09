use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::agent::{self, reverse_dns, AgentResponse};
use crate::render::RenderOutcome;
use anyhow::Result;

pub fn run(
    interface: Option<&str>,
    port: Option<u16>,
    host: Option<&str>,
    count: u32,
    duration_secs: u64,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    // Build tcpdump command
    let mut args: Vec<String> = vec![
        String::from("-nn"),
        String::from("-q"),
        String::from("-c"),
        count.to_string(),
    ];

    if let Some(iface) = interface {
        args.push(String::from("-i"));
        args.push(iface.to_string());
    }

    // Build filter expression
    let mut filter_parts: Vec<String> = Vec::new();
    if let Some(p) = port {
        filter_parts.push(format!("port {p}"));
    }
    if let Some(h) = host {
        filter_parts.push(format!("host {h}"));
    }
    if !filter_parts.is_empty() {
        args.push(filter_parts.join(" and "));
    }

    let filter_expr = filter_parts.join(" and ");
    let used_iface = interface.unwrap_or("(auto)").to_string();

    // Run tcpdump
    let output = match std::process::Command::new("tcpdump")
        .args(&args)
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if duration_secs > 0 {
                let deadline = Instant::now() + Duration::from_secs(duration_secs + 2);
                loop {
                    match child.try_wait() {
                        Ok(Some(_status)) => break,
                        Ok(None) => {
                            if Instant::now() >= deadline {
                                let _ = child.kill();
                                let _ = child.wait();
                                return render_unavailable("tcpdump timed out", llm, allow_write);
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(e) => {
                            return render_unavailable(
                                &format!("tcpdump wait error: {e}"),
                                llm,
                                allow_write,
                            );
                        }
                    }
                }
            }
            match child.wait_with_output() {
                Ok(o) => o,
                Err(e) => {
                    return render_unavailable(&format!("tcpdump error: {e}"), llm, allow_write);
                }
            }
        }
        Err(e) => {
            let msg = if e.kind() == std::io::ErrorKind::NotFound {
                String::from(
                    "tcpdump not available or insufficient permissions. \
                     Try: sudo opn --allow-write capture",
                )
            } else {
                format!("Failed to run tcpdump: {e}")
            };
            return render_unavailable(&msg, llm, allow_write);
        }
    };

    // Check for permission error
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    if stderr_text.contains("permission denied")
        || stderr_text.contains("Operation not permitted")
        || stderr_text.contains("You don't have permission")
    {
        return render_unavailable(
            "tcpdump not available or insufficient permissions. \
             Try: sudo opn --llm --allow-write capture",
            llm,
            allow_write,
        );
    }

    // Combine stdout (packet lines) and relevant stderr lines
    let stdout_text = String::from_utf8_lossy(&output.stdout);
    // tcpdump writes packets to stdout with -q
    let all_text = format!("{}{}", stdout_text, stderr_text);

    // Parse packets
    // tcpdump -q -nn lines look like:
    // HH:MM:SS.usec IP src.port > dst.port: proto, length N
    // or just: HH:MM:SS.usec IP src > dst: flags ...
    let mut packets: Vec<(String, String, u16, String, u16, String, u32)> = Vec::new();
    // (ts, src_ip, src_port, dst_ip, dst_port, proto, length)

    for line in all_text.lines() {
        let line = line.trim();
        if !line.contains(" IP ") && !line.contains(" IP6 ") {
            continue;
        }
        if let Some(p) = parse_tcpdump_line(line) {
            packets.push(p);
        }
    }

    let packets_captured = packets.len();

    // Aggregate connections: (src_ip:port, dst_ip:port, proto) -> (count, bytes, dst_ip)
    // dst_ip stored separately so IPv6 addresses are extracted correctly without re-parsing.
    let mut conn_map: HashMap<(String, String, String), (u32, u64, String)> = HashMap::new();
    let mut proto_dist: HashMap<String, u32> = HashMap::new();
    let mut talker_map: HashMap<String, u32> = HashMap::new();

    for (_, src_ip, src_port, dst_ip, dst_port, proto, length) in &packets {
        let src = format!("{src_ip}:{src_port}");
        let dst = format!("{dst_ip}:{dst_port}");
        let key = (src.clone(), dst.clone(), proto.clone());
        let entry = conn_map.entry(key).or_insert((0, 0, dst_ip.clone()));
        entry.0 += 1;
        entry.1 += *length as u64;
        *proto_dist.entry(proto.clone()).or_insert(0) += 1;
        *talker_map.entry(src_ip.clone()).or_insert(0) += 1;
        *talker_map.entry(dst_ip.clone()).or_insert(0) += 1;
    }

    // Build connection list
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

    // Top talkers (sorted by packet count)
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

/// Parse a tcpdump -q -nn line. Returns (ts, src_ip, src_port, dst_ip, dst_port, proto, length).
fn parse_tcpdump_line(line: &str) -> Option<(String, String, u16, String, u16, String, u32)> {
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let ts = parts[0].to_string();
    let rest = parts[1];

    // Skip "IP " or "IP6 "
    let rest = if let Some(r) = rest.strip_prefix("IP6 ") {
        r
    } else if let Some(r) = rest.strip_prefix("IP ") {
        r
    } else {
        return None;
    };

    // rest: "src.port > dst.port: proto, length N"
    // or "src > dst: flags ..."
    let arrow_idx = rest.find(" > ")?;
    let src_part = &rest[..arrow_idx];
    let after_arrow = &rest[arrow_idx + 3..];

    let (dst_part, proto_len) = if let Some(colon_idx) = after_arrow.find(':') {
        (&after_arrow[..colon_idx], &after_arrow[colon_idx + 1..])
    } else {
        (after_arrow, "")
    };

    // Extract proto from "proto, length N"
    let proto = proto_len
        .split_whitespace()
        .next()
        .unwrap_or("TCP")
        .trim_end_matches(',')
        .to_uppercase();
    let proto = if proto.is_empty() {
        String::from("TCP")
    } else {
        proto
    };

    // Extract length
    let length: u32 = proto_len
        .split_whitespace()
        .enumerate()
        .find(|(_, w)| w.eq_ignore_ascii_case("length"))
        .and_then(|(i, _)| proto_len.split_whitespace().nth(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let (src_ip, src_port) = parse_addr(src_part);
    let (dst_ip, dst_port) = parse_addr(dst_part);

    Some((ts, src_ip, src_port, dst_ip, dst_port, proto, length))
}

/// Parse "addr.port" or "addr" into (ip, port).
fn parse_addr(s: &str) -> (String, u16) {
    // IPv6 addresses won't have dots for port, handle simple split on last dot
    if let Some(pos) = s.rfind('.') {
        let potential_port = &s[pos + 1..];
        if let Ok(port) = potential_port.parse::<u16>() {
            return (s[..pos].to_string(), port);
        }
    }
    // No port found
    (s.to_string(), 0)
}
