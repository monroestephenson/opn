use anyhow::Result;

use crate::agent::{self, AgentResponse};
use crate::model::{KillSignal, QueryFilter};
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run_kill(
    platform: &dyn Platform,
    pid: u32,
    signal: KillSignal,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    let proc_info = platform.process_info(pid)?;
    platform.kill_process(pid, signal)?;

    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/2"),
            ok: true,
            ts: agent::current_ts(),
            cmd: format!("kill {} --signal {}", pid, signal),
            caps: agent::caps(allow_write),
            data: Some(serde_json::json!({
                "pid": pid,
                "signal": signal.to_string(),
                "proc_name": proc_info.name
            })),
            hints: vec![],
            warnings: vec![],
            next_steps: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!("Sent SIG{} to {} ({})", signal, pid, proc_info.name);
    }

    Ok(RenderOutcome::HasResults)
}

pub fn run_kill_port(
    platform: &dyn Platform,
    port: u16,
    signal: KillSignal,
    filter: &QueryFilter,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    let sockets = platform.find_by_port(port, filter)?;

    if sockets.is_empty() {
        if llm {
            let resp = AgentResponse {
                schema: String::from("opn-agent/2"),
                ok: true,
                ts: agent::current_ts(),
                cmd: format!("kill-port {}", port),
                caps: agent::caps(allow_write),
                data: Some(
                    serde_json::json!({ "port": port, "killed": serde_json::Value::Array(vec![]) }),
                ),
                hints: vec![format!("No processes found on port {}", port)],
                warnings: vec![],
                next_steps: vec![],
            actions: agent::build_actions(allow_write),
            };
            agent::print_agent_response(&resp);
        } else {
            println!("No processes found on port {}", port);
        }
        return Ok(RenderOutcome::NoResults);
    }

    // Deduplicate by pid
    let mut seen_pids = std::collections::HashSet::new();
    let mut killed = Vec::new();

    for socket in &sockets {
        let pid = socket.process.pid;
        if seen_pids.insert(pid) {
            platform.kill_process(pid, signal)?;
            killed.push(serde_json::json!({
                "pid": pid,
                "proc": socket.process.name
            }));
        }
    }

    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/2"),
            ok: true,
            ts: agent::current_ts(),
            cmd: format!("kill-port {}", port),
            caps: agent::caps(allow_write),
            data: Some(serde_json::json!({ "port": port, "killed": killed })),
            hints: vec![],
            warnings: vec![],
            next_steps: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!("Sent SIG{} to processes on port {}:", signal, port);
        for socket in &sockets {
            if seen_pids.contains(&socket.process.pid) {
                println!("  pid {} ({})", socket.process.pid, socket.process.name);
            }
        }
    }

    Ok(RenderOutcome::HasResults)
}
