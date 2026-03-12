use anyhow::Result;

use crate::agent::{self, AgentResponse};
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run(platform: &dyn Platform, llm: bool, allow_write: bool) -> Result<RenderOutcome> {
    let metrics = platform.tcp_metrics()?;

    if let Some(m) = metrics {
        if llm {
            let resp = AgentResponse {
                schema: String::from("opn-agent/2"),
                ok: true,
                ts: agent::current_ts(),
                cmd: String::from("snmp"),
                caps: agent::caps(allow_write),
                data: Some(serde_json::to_value(&m)?),
                hints: vec![],
                warnings: vec![],
                next_steps: vec![],
            actions: agent::build_actions(allow_write),
            };
            agent::print_agent_response(&resp);
        } else {
            println!("TCP Metrics:");
            println!("  retrans:          {}", m.retrans);
            println!("  syn_cookies_sent: {}", m.syn_cookies_sent);
            println!("  active_opens:     {}", m.active_opens);
            println!("  passive_opens:    {}", m.passive_opens);
            println!("  attempt_fails:    {}", m.attempt_fails);
            println!("  estab_resets:     {}", m.estab_resets);
            println!("  curr_estab:       {}", m.curr_estab);
        }
        Ok(RenderOutcome::HasResults)
    } else {
        let msg = "TCP metrics not available on this platform";
        if llm {
            let resp = AgentResponse {
                schema: String::from("opn-agent/2"),
                ok: true,
                ts: agent::current_ts(),
                cmd: String::from("snmp"),
                caps: agent::caps(allow_write),
                data: None,
                hints: vec![msg.to_string()],
                warnings: vec![],
                next_steps: vec![],
            actions: agent::build_actions(allow_write),
            };
            agent::print_agent_response(&resp);
        } else {
            println!("{}", msg);
        }
        Ok(RenderOutcome::NoResults)
    }
}
