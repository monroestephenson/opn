use std::collections::HashMap;

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
    let sockets = platform.list_sockets(filter)?;

    if sockets.is_empty() {
        if llm {
            let resp = AgentResponse {
                schema: String::from("opn-agent/1"),
                ok: true,
                ts: agent::current_ts(),
                cmd: String::from("resources"),
                caps: agent::caps(allow_write),
                data: Some(serde_json::json!([])),
                hints: vec![String::from("No sockets found")],
                warnings: vec![],
                actions: agent::build_actions(allow_write),
            };
            agent::print_agent_response(&resp);
        } else {
            println!("No sockets found.");
        }
        return Ok(RenderOutcome::NoResults);
    }

    // Collect unique PIDs and which ports they use
    let mut pid_ports: HashMap<u32, Vec<String>> = HashMap::new();
    let mut pid_proc: HashMap<u32, String> = HashMap::new();
    for s in &sockets {
        let pid = s.process.pid;
        pid_ports.entry(pid).or_default().push(s.local_addr.clone());
        pid_proc
            .entry(pid)
            .or_insert_with(|| s.process.name.clone());
    }

    // Gather resource stats (best-effort)
    let mut resource_rows = Vec::new();
    for (pid, proc_name) in &pid_proc {
        let res = platform
            .process_resources(*pid)
            .unwrap_or(crate::model::ProcessResources {
                pid: *pid,
                cpu_pct: 0.0,
                mem_rss_kb: 0,
                mem_vms_kb: 0,
                open_fds: 0,
                threads: 0,
            });
        let ports = pid_ports.get(pid).cloned().unwrap_or_default();
        resource_rows.push((proc_name.clone(), res, ports));
    }

    // Sort by PID
    resource_rows.sort_by_key(|(_, r, _)| r.pid);

    if llm {
        let data: Vec<serde_json::Value> = resource_rows
            .iter()
            .map(|(proc_name, res, ports)| {
                serde_json::json!({
                    "pid": res.pid,
                    "proc": proc_name,
                    "cpu": res.cpu_pct,
                    "rss_kb": res.mem_rss_kb,
                    "vms_kb": res.mem_vms_kb,
                    "fds": res.open_fds,
                    "threads": res.threads,
                    "ports": ports
                })
            })
            .collect();

        let resp = AgentResponse {
            schema: String::from("opn-agent/1"),
            ok: true,
            ts: agent::current_ts(),
            cmd: String::from("resources"),
            caps: agent::caps(allow_write),
            data: Some(serde_json::json!(data)),
            hints: vec![],
            warnings: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!(
            "{:<8} {:<20} {:>8} {:>12} {:>12} {:>8} {:>8}  PORTS",
            "PID", "PROCESS", "CPU%", "MEM-RSS", "MEM-VMS", "FDS", "THREADS"
        );
        println!("{}", "-".repeat(100));
        for (proc_name, res, ports) in &resource_rows {
            let ports_str = ports.join(", ");
            println!(
                "{:<8} {:<20} {:>8.1} {:>11}K {:>11}K {:>8} {:>8}  {}",
                res.pid,
                proc_name,
                res.cpu_pct,
                res.mem_rss_kb,
                res.mem_vms_kb,
                res.open_fds,
                res.threads,
                ports_str
            );
        }
    }

    Ok(RenderOutcome::HasResults)
}
