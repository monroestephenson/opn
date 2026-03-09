use std::path::Path;

use anyhow::Result;

use crate::agent::{self, AgentResponse, Snapshot};
use crate::model::QueryFilter;
use crate::platform::Platform;
use crate::render::RenderOutcome;

pub fn run_snapshot(
    platform: &dyn Platform,
    filter: &QueryFilter,
    out: Option<&Path>,
) -> Result<RenderOutcome> {
    let sockets = platform.list_sockets(filter)?;

    let agent_sockets: Vec<_> = sockets
        .iter()
        .map(|s| {
            let ancestry = platform.process_ancestry(s.process.pid).unwrap_or_default();
            agent::socket_to_agent(s, ancestry, false)
        })
        .collect();

    let interfaces = platform.interface_stats().unwrap_or_default();
    let tcp_metrics = platform.tcp_metrics().unwrap_or(None);

    let snapshot = Snapshot {
        schema: String::from("opn-snapshot/1"),
        ts: agent::current_ts(),
        sockets: agent_sockets,
        interfaces,
        tcp_metrics,
    };

    let json = serde_json::to_string_pretty(&snapshot)?;

    if let Some(path) = out {
        std::fs::write(path, &json)?;
        eprintln!("Snapshot written to {}", path.display());
    } else {
        println!("{}", json);
    }

    Ok(RenderOutcome::HasResults)
}

pub fn run_diff(
    snapshot_path: &Path,
    platform: &dyn Platform,
    filter: &QueryFilter,
    llm: bool,
) -> Result<RenderOutcome> {
    let content = std::fs::read_to_string(snapshot_path)?;
    let old_snapshot: Snapshot = serde_json::from_str(&content)?;

    let sockets = platform.list_sockets(filter)?;
    let agent_sockets: Vec<_> = sockets
        .iter()
        .map(|s| {
            let ancestry = platform.process_ancestry(s.process.pid).unwrap_or_default();
            agent::socket_to_agent(s, ancestry, false)
        })
        .collect();

    let interfaces = platform.interface_stats().unwrap_or_default();
    let tcp_metrics = platform.tcp_metrics().unwrap_or(None);

    let new_snapshot = Snapshot {
        schema: String::from("opn-snapshot/1"),
        ts: agent::current_ts(),
        sockets: agent_sockets,
        interfaces,
        tcp_metrics,
    };

    let diff = agent::diff_snapshots(&old_snapshot, &new_snapshot);

    if llm {
        let resp = AgentResponse {
            schema: String::from("opn-agent/1"),
            ok: true,
            ts: agent::current_ts(),
            cmd: format!("diff {}", snapshot_path.display()),
            caps: agent::caps(false),
            data: Some(diff),
            hints: vec![],
            warnings: vec![],
            actions: agent::build_actions(false),
        };
        agent::print_agent_response(&resp);
    } else {
        let fmt_socket = |s: &serde_json::Value| -> String {
            format!(
                "  {} {} → {} [{}] pid={} proc={}",
                s["p"].as_str().unwrap_or("?"),
                s["l"].as_str().unwrap_or("?"),
                s["r"].as_str().unwrap_or("?"),
                s["st"].as_str().unwrap_or("?"),
                s["pid"].as_u64().unwrap_or(0),
                s["proc"].as_str().unwrap_or("?"),
            )
        };

        let empty = vec![];
        let added = diff["added_listeners"].as_array().unwrap_or(&empty);
        let removed = diff["removed_listeners"].as_array().unwrap_or(&empty);
        let new_conns = diff["new_connections"].as_array().unwrap_or(&empty);
        let dropped = diff["dropped_connections"].as_array().unwrap_or(&empty);
        let anomalies = diff["anomalies"].as_array().unwrap_or(&empty);

        if added.is_empty() && removed.is_empty() && new_conns.is_empty() && dropped.is_empty() {
            println!("No changes since snapshot.");
        } else {
            if !added.is_empty() {
                println!("+ NEW LISTENERS ({}):", added.len());
                for s in added {
                    println!("{}", fmt_socket(s));
                }
            }
            if !removed.is_empty() {
                println!("- REMOVED LISTENERS ({}):", removed.len());
                for s in removed {
                    println!("{}", fmt_socket(s));
                }
            }
            if !new_conns.is_empty() {
                println!("+ NEW CONNECTIONS ({}):", new_conns.len());
                for s in new_conns {
                    println!("{}", fmt_socket(s));
                }
            }
            if !dropped.is_empty() {
                println!("- DROPPED CONNECTIONS ({}):", dropped.len());
                for s in dropped {
                    println!("{}", fmt_socket(s));
                }
            }
        }
        if !anomalies.is_empty() {
            println!("\nANOMALIES:");
            for a in anomalies {
                println!("  ! {}", a.as_str().unwrap_or(""));
            }
        }
    }

    Ok(RenderOutcome::HasResults)
}
