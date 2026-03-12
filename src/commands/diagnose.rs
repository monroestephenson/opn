use std::collections::HashSet;

use anyhow::Result;

use crate::agent::{self, AgentResponse};
use crate::model::QueryFilter;
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run(
    platform: &dyn Platform,
    filter: &QueryFilter,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    // 1. Collect sockets with ancestry
    let sockets = platform.list_sockets(filter)?;
    let agent_sockets: Vec<_> = sockets
        .iter()
        .map(|s| {
            let ancestry = platform.process_ancestry(s.process.pid).unwrap_or_default();
            agent::socket_to_agent(s, ancestry, llm)
        })
        .collect();

    // 2. Collect deleted files
    let deleted_files = platform.find_deleted(filter).unwrap_or_default();
    let agent_files: Vec<_> = deleted_files.iter().map(agent::file_to_agent).collect();

    // 3. Interface stats
    let interfaces = platform.interface_stats().unwrap_or_default();

    // 4. TCP metrics
    let tcp_metrics = platform.tcp_metrics().unwrap_or(None);

    // 5. Build summary
    let tcp_listen = agent_sockets
        .iter()
        .filter(|s| s.protocol == "TCP" && s.state == "LISTEN")
        .count();
    let tcp_est = agent_sockets
        .iter()
        .filter(|s| s.protocol == "TCP" && s.state != "LISTEN")
        .count();
    let udp_count = agent_sockets.iter().filter(|s| s.protocol == "UDP").count();
    let unique_pids: HashSet<u32> = agent_sockets.iter().map(|s| s.pid).collect();

    // 6. Detect anomalies
    let hints = agent::detect_anomalies(&agent_sockets, &agent_files);

    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/2"),
            ok: true,
            ts: agent::current_ts(),
            cmd: String::from("diagnose"),
            caps: agent::caps(allow_write),
            data: Some(serde_json::json!({
                "summary": {
                    "tcp_listen": tcp_listen,
                    "tcp_est": tcp_est,
                    "udp": udp_count,
                    "procs": unique_pids.len()
                },
                "sockets": agent_sockets,
                "deleted_files": agent_files,
                "interfaces": interfaces,
                "tcp_metrics": tcp_metrics
            })),
            hints,
            warnings: vec![],
            next_steps: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!("=== SOCKETS ===");
        println!(
            "  TCP listen: {}  TCP established: {}  UDP: {}  Processes: {}",
            tcp_listen,
            tcp_est,
            udp_count,
            unique_pids.len()
        );
        if !agent_sockets.is_empty() {
            println!();
            println!(
                "  {:<6} {:<26} {:<26} {:<14} {:<7} PROCESS",
                "PROTO", "LOCAL", "REMOTE", "STATE", "PID"
            );
            println!("  {}", "-".repeat(90));
            for s in &agent_sockets {
                println!(
                    "  {:<6} {:<26} {:<26} {:<14} {:<7} {}",
                    s.protocol, s.local, s.remote, s.state, s.pid, s.process
                );
            }
        }

        println!("\n=== INTERFACES ===");
        if interfaces.is_empty() {
            println!("  (no interfaces)");
        } else {
            println!(
                "  {:<16} {:>14} {:>14}",
                "INTERFACE", "RX-BYTES", "TX-BYTES"
            );
            println!("  {}", "-".repeat(46));
            for iface in &interfaces {
                println!(
                    "  {:<16} {:>14} {:>14}",
                    iface.name, iface.rx_bytes, iface.tx_bytes
                );
            }
        }

        println!("\n=== TCP METRICS ===");
        if let Some(m) = &tcp_metrics {
            println!(
                "  retrans: {}  curr_estab: {}  active_opens: {}",
                m.retrans, m.curr_estab, m.active_opens
            );
        } else {
            println!("  (not available on this platform)");
        }

        println!("\n=== ANOMALIES ===");
        if hints.is_empty() {
            println!("  None detected.");
        } else {
            for h in &hints {
                println!("  ! {h}");
            }
        }

        println!("\nTip: run 'opn watch' for a live view, or 'opn resources' to see CPU/memory per process.");
    }

    if agent_sockets.is_empty() && agent_files.is_empty() {
        Ok(RenderOutcome::NoResults)
    } else {
        Ok(RenderOutcome::HasResults)
    }
}
