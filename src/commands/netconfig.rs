use anyhow::Result;

use crate::agent::{self, AgentResponse};
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run(platform: &dyn Platform, llm: bool, allow_write: bool) -> Result<RenderOutcome> {
    let config = platform.net_config()?;

    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/2"),
            ok: true,
            ts: agent::current_ts(),
            cmd: String::from("netconfig"),
            caps: agent::caps(allow_write),
            data: Some(serde_json::to_value(&config)?),
            hints: vec![],
            warnings: vec![],
            next_steps: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!("=== ROUTES ===");
        if config.routes.is_empty() {
            println!("  (none)");
        } else {
            println!(
                "{:<20} {:<20} {:<12} {:<10} FLAGS",
                "DESTINATION", "GATEWAY", "INTERFACE", "METRIC"
            );
            println!("{}", "-".repeat(70));
            for r in &config.routes {
                println!(
                    "{:<20} {:<20} {:<12} {:<10} {}",
                    r.destination, r.gateway, r.interface, r.metric, r.flags
                );
            }
        }

        println!("\n=== DNS ===");
        println!("  Servers: {}", config.dns_servers.join(", "));
        println!("  Search:  {}", config.dns_search.join(", "));

        println!("\n=== HOSTNAME ===");
        println!("  {}", config.hostname);

        println!("\n=== INTERFACE ADDRESSES ===");
        for iface in &config.interfaces {
            if iface.addrs.is_empty() {
                println!("  {}: (no addresses)", iface.name);
            } else {
                println!("  {}: {}", iface.name, iface.addrs.join(", "));
            }
        }
    }

    Ok(RenderOutcome::HasResults)
}
