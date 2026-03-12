use anyhow::Result;

use crate::agent::{self, AgentResponse};
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run(platform: &dyn Platform, llm: bool, allow_write: bool) -> Result<RenderOutcome> {
    let stats = platform.interface_stats()?;

    if stats.is_empty() {
        if llm {
            let resp = AgentResponse {
                schema: String::from("opn-agent/2"),
                ok: true,
                ts: agent::current_ts(),
                cmd: String::from("interfaces"),
                caps: agent::caps(allow_write),
                data: Some(serde_json::json!([])),
                hints: vec![String::from("No network interfaces found")],
                warnings: vec![],
                next_steps: vec![],
                actions: agent::build_actions(allow_write),
            };
            agent::print_agent_response(&resp);
        } else {
            println!("No network interfaces found.");
        }
        return Ok(RenderOutcome::NoResults);
    }

    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/2"),
            ok: true,
            ts: agent::current_ts(),
            cmd: String::from("interfaces"),
            caps: agent::caps(allow_write),
            data: Some(serde_json::to_value(&stats)?),
            hints: vec![],
            warnings: vec![],
            next_steps: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        // Print as table
        println!(
            "{:<16} {:>12} {:>12} {:>10} {:>10} {:>8} {:>8} {:>8}",
            "INTERFACE", "RX-BYTES", "TX-BYTES", "RX-PKT", "TX-PKT", "RX-ERR", "TX-ERR", "RX-DROP"
        );
        println!("{}", "-".repeat(94));
        for s in &stats {
            println!(
                "{:<16} {:>12} {:>12} {:>10} {:>10} {:>8} {:>8} {:>8}",
                s.name,
                s.rx_bytes,
                s.tx_bytes,
                s.rx_packets,
                s.tx_packets,
                s.rx_errors,
                s.tx_errors,
                s.rx_drop
            );
        }
    }

    Ok(RenderOutcome::HasResults)
}
