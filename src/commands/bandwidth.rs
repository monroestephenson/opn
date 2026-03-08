use anyhow::Result;

use crate::agent::{self, AgentResponse};
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn human_rate(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.1} GB/s", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.1} MB/s", bps as f64 / 1_000_000.0)
    } else if bps >= 1_000 {
        format!("{:.1} KB/s", bps as f64 / 1_000.0)
    } else {
        format!("{bps} B/s")
    }
}

pub fn run(
    platform: &dyn Platform,
    duration_secs: u64,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    let t1 = platform.interface_stats()?;
    std::thread::sleep(std::time::Duration::from_secs(duration_secs));
    let t2 = platform.interface_stats()?;

    // Build lookup by name for t1
    let t1_map: std::collections::HashMap<_, _> = t1.iter().map(|s| (s.name.clone(), s)).collect();

    #[derive(serde::Serialize)]
    struct IfaceRate {
        iface: String,
        rx_bps: u64,
        tx_bps: u64,
        rx_human: String,
        tx_human: String,
    }

    let mut rates: Vec<IfaceRate> = t2
        .iter()
        .filter_map(|s2| {
            let s1 = t1_map.get(&s2.name)?;
            let rx_delta = s2.rx_bytes.saturating_sub(s1.rx_bytes);
            let tx_delta = s2.tx_bytes.saturating_sub(s1.tx_bytes);
            let rx_bps = rx_delta / duration_secs;
            let tx_bps = tx_delta / duration_secs;
            Some(IfaceRate {
                iface: s2.name.clone(),
                rx_bps,
                tx_bps,
                rx_human: human_rate(rx_bps),
                tx_human: human_rate(tx_bps),
            })
        })
        .collect();

    // Sort by total rate descending
    rates.sort_by(|a, b| (b.rx_bps + b.tx_bps).cmp(&(a.rx_bps + a.tx_bps)));

    if rates.is_empty() {
        if llm {
            let resp = AgentResponse {
                schema: String::from("opn-agent/1"),
                ok: true,
                ts: agent::current_ts(),
                cmd: String::from("bandwidth"),
                caps: agent::caps(allow_write),
                data: Some(serde_json::json!({"duration_secs": duration_secs, "interfaces": []})),
                hints: vec![String::from("No interfaces found")],
                warnings: vec![],
                actions: agent::build_actions(allow_write),
            };
            agent::print_agent_response(&resp);
        } else {
            println!("No interfaces found.");
        }
        return Ok(RenderOutcome::NoResults);
    }

    if llm {
        let data = serde_json::json!({
            "duration_secs": duration_secs,
            "interfaces": rates
        });
        let resp = AgentResponse {
            schema: String::from("opn-agent/1"),
            ok: true,
            ts: agent::current_ts(),
            cmd: format!("bandwidth --duration {duration_secs}"),
            caps: agent::caps(allow_write),
            data: Some(data),
            hints: vec![],
            warnings: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        // Also collect total bytes from t2 for display
        let t2_map: std::collections::HashMap<_, _> =
            t2.iter().map(|s| (s.name.clone(), s)).collect();

        println!(
            "{:<16} {:>14} {:>14} {:>14} {:>14}",
            "INTERFACE", "RX RATE", "TX RATE", "RX TOTAL", "TX TOTAL"
        );
        println!("{}", "-".repeat(74));
        for r in &rates {
            let (rx_total, tx_total) = t2_map
                .get(&r.iface)
                .map(|s| (s.rx_bytes, s.tx_bytes))
                .unwrap_or((0, 0));
            println!(
                "{:<16} {:>14} {:>14} {:>14} {:>14}",
                r.iface,
                r.rx_human,
                r.tx_human,
                human_rate(rx_total),
                human_rate(tx_total)
            );
        }
    }

    Ok(RenderOutcome::HasResults)
}
