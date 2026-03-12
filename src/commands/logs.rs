use anyhow::Result;
use std::collections::HashSet;

use crate::agent::{self, AgentResponse};
use crate::render::RenderOutcome;

const NETWORK_KEYWORDS: &[&str] = &[
    "connection",
    "refused",
    "failed",
    "denied",
    "timeout",
    "invalid",
    "unauthorized",
    "attack",
    "blocked",
    "DROP",
    "REJECT",
    "sshd",
    "port",
];

fn is_network_relevant(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    NETWORK_KEYWORDS
        .iter()
        .any(|kw| lower.contains(&kw.to_ascii_lowercase()))
}

/// Try to read last `lines` lines from a file. Returns (source_path, lines_vec) or None.
fn try_read_file(path: &str, max_lines: usize) -> Option<(String, Vec<String>)> {
    let content = std::fs::read_to_string(path).ok()?;
    let all_lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let start = all_lines.len().saturating_sub(max_lines);
    Some((path.to_string(), all_lines[start..].to_vec()))
}

#[cfg(target_os = "linux")]
fn get_log_lines(log_type: &str, lines: usize) -> (String, Vec<String>) {
    match log_type {
        "auth" => {
            if let Some(r) = try_read_file("/var/log/auth.log", lines) {
                return r;
            }
            if let Some(r) = try_read_file("/var/log/secure", lines) {
                return r;
            }
        }
        "kernel" => {
            if let Some(r) = try_read_file("/var/log/kern.log", lines) {
                return r;
            }
        }
        "firewall" => {
            if let Some(r) = try_read_file("/var/log/ufw.log", lines) {
                return r;
            }
            if let Some(r) = try_read_file("/var/log/firewall", lines) {
                return r;
            }
        }
        "web" => {
            for path in &[
                "/var/log/nginx/access.log",
                "/var/log/apache2/access.log",
                "/var/log/httpd/access_log",
            ] {
                if let Some(r) = try_read_file(path, lines) {
                    return r;
                }
            }
        }
        _ => {} // system | all: fall through
    }

    // System / all / fallback — file-based only
    for path in &["/var/log/syslog", "/var/log/messages"] {
        if let Some(r) = try_read_file(path, lines) {
            return r;
        }
    }

    (String::from("(none — no readable log files found)"), vec![])
}

#[cfg(target_os = "macos")]
fn get_log_lines(log_type: &str, lines: usize) -> (String, Vec<String>) {
    match log_type {
        "auth" => {
            if let Some(r) = try_read_file("/var/log/system.log", lines) {
                return r;
            }
        }
        "web" => {
            for path in &[
                "/var/log/nginx/access.log",
                "/usr/local/var/log/nginx/access.log",
                "/opt/homebrew/var/log/nginx/access.log",
            ] {
                if let Some(r) = try_read_file(path, lines) {
                    return r;
                }
            }
        }
        _ => {} // system | all: fall through
    }

    // system / all — file-based only
    if let Some(r) = try_read_file("/var/log/system.log", lines) {
        return r;
    }

    (
        String::from("(none — /var/log/system.log not readable; try sudo)"),
        vec![],
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn get_log_lines(_log_type: &str, _lines: usize) -> (String, Vec<String>) {
    (String::from("(not supported on this platform)"), vec![])
}

pub fn run(
    log_type: &str,
    lines: usize,
    filter: Option<&str>,
    llm: bool,
    allow_write: bool,
) -> Result<RenderOutcome> {
    let (source, raw_lines) = get_log_lines(log_type, lines);

    let total_read = raw_lines.len();

    // Filter for network relevance, then optionally apply user filter substring
    let filtered: Vec<&str> = raw_lines
        .iter()
        .filter(|l| is_network_relevant(l))
        .filter(|l| {
            filter
                .map(|f| l.to_ascii_lowercase().contains(&f.to_ascii_lowercase()))
                .unwrap_or(true)
        })
        .map(|l| l.as_str())
        .collect();

    let network_relevant = filtered.len();

    // Build summary
    let mut failed_auth: usize = 0;
    let mut connections: usize = 0;
    let mut unique_ips: HashSet<String> = HashSet::new();

    for line in &filtered {
        let lower = line.to_ascii_lowercase();
        if lower.contains("failed") || lower.contains("denied") || lower.contains("unauthorized") {
            failed_auth += 1;
        }
        if lower.contains("connection") || lower.contains("connect") {
            connections += 1;
        }
        // Very simple IP extraction
        for word in line.split_whitespace() {
            let w = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':');
            let parts: Vec<&str> = w.split('.').collect();
            if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                unique_ips.insert(w.to_string());
            }
        }
    }

    if llm {
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            msg: &'a str,
        }

        let entries: Vec<Entry> = filtered.iter().map(|l| Entry { msg: l }).collect();
        let mut unique_ip_list: Vec<String> = unique_ips.into_iter().collect();
        unique_ip_list.sort();

        let data = serde_json::json!({
            "source": source,
            "total_lines_read": total_read,
            "network_relevant": network_relevant,
            "entries": entries,
            "summary": {
                "failed_auth": failed_auth,
                "connections": connections,
                "unique_ips": unique_ip_list
            }
        });

        let resp = AgentResponse {
            schema: String::from("opn-agent/2"),
            ok: true,
            ts: agent::current_ts(),
            cmd: format!("logs --log-type {log_type}"),
            caps: agent::caps(allow_write),
            data: Some(data),
            hints: vec![],
            warnings: vec![],
            next_steps: vec![],
            actions: agent::build_actions(allow_write),
        };
        agent::print_agent_response(&resp);
    } else {
        println!(
            "Source: {source}  (read {total_read} lines, {network_relevant} network-relevant)"
        );
        println!("{}", "-".repeat(80));
        for line in &filtered {
            println!("{}", line);
        }
        println!("{}", "-".repeat(80));
        println!(
            "Summary: failed_auth={failed_auth}  connections={connections}  unique_ips={}",
            unique_ips.len()
        );
    }

    if raw_lines.is_empty() {
        Ok(RenderOutcome::NoResults)
    } else {
        Ok(RenderOutcome::HasResults)
    }
}
