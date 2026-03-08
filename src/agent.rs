use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::{InterfaceStats, OpenFile, ProcessAncestor, SocketEntry, TcpMetrics};

// ── Compact socket for LLM output ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone)]
pub struct AgentSocket {
    #[serde(rename = "p")]
    pub protocol: String,
    #[serde(rename = "l")]
    pub local: String,
    #[serde(rename = "r")]
    pub remote: String,
    #[serde(rename = "st")]
    pub state: String,
    pub pid: u32,
    #[serde(rename = "proc")]
    pub process: String,
    pub user: String,
    pub cmd: String,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "tree")]
    pub ancestry: Vec<AgentAncestor>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AgentAncestor {
    pub pid: u32,
    #[serde(rename = "proc")]
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AgentFile {
    pub pid: u32,
    #[serde(rename = "proc")]
    pub process: String,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd: Option<i32>,
    #[serde(rename = "type")]
    pub fd_type: String,
    pub path: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}

#[derive(Serialize, Deserialize)]
pub struct AgentResponse {
    pub schema: String,
    pub ok: bool,
    pub ts: u64,
    pub cmd: String,
    pub caps: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    pub actions: serde_json::Value,
}

// ── Snapshot types ─────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    pub ts: u64,
    pub sockets: Vec<AgentSocket>,
    pub interfaces: Vec<InterfaceStats>,
    pub tcp_metrics: Option<TcpMetrics>,
}

// ── Helper functions ────────────────────────────────────────────────────────

pub fn current_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn caps(allow_write: bool) -> Vec<String> {
    if allow_write {
        vec![
            String::from("read"),
            String::from("kill"),
            String::from("firewall"),
        ]
    } else {
        vec![String::from("read")]
    }
}

pub fn build_actions(allow_write: bool) -> serde_json::Value {
    let mut actions = json!({
        "sockets":    "opn --llm sockets",
        "port":       "opn --llm port <PORT>",
        "pid":        "opn --llm pid <PID>",
        "file":       "opn --llm file <PATH>",
        "deleted":    "opn --llm deleted",
        "interfaces": "opn --llm interfaces",
        "snmp":       "opn --llm snmp",
        "diagnose":   "opn --llm diagnose",
        "snapshot":   "opn --llm snapshot [--out <FILE>]",
        "diff":       "opn --llm diff <SNAPSHOT_FILE>"
    });

    if allow_write {
        let write_actions = json!({
            "kill":       "opn --llm --allow-write kill <PID> [--signal TERM|KILL|HUP|INT]",
            "kill-port":  "opn --llm --allow-write kill-port <PORT>",
            "firewall": {
                "block-ip":   "opn --llm --allow-write firewall block-ip <IP> [--comment TEXT] [--ttl SECS]",
                "block-port": "opn --llm --allow-write firewall block-port <PORT> [--dir in|out]",
                "list":       "opn --llm --allow-write firewall list",
                "undo":       "opn --llm --allow-write firewall undo",
                "flush":      "opn --llm --allow-write firewall flush",
                "unblock":    "opn --llm --allow-write firewall unblock <TARGET>"
            }
        });
        if let (serde_json::Value::Object(ref mut m), serde_json::Value::Object(w)) =
            (&mut actions, write_actions)
        {
            m.extend(w);
        }
    }

    actions
}

pub fn print_agent_response(resp: &AgentResponse) {
    println!("{}", serde_json::to_string(resp).unwrap_or_default());
}

pub fn socket_to_agent(s: &SocketEntry, ancestry: Vec<ProcessAncestor>) -> AgentSocket {
    AgentSocket {
        protocol: s.protocol.to_string(),
        local: s.local_addr.clone(),
        remote: s.remote_addr.clone(),
        state: s.state.clone(),
        pid: s.process.pid,
        process: s.process.name.clone(),
        user: s.process.user.clone(),
        cmd: s.process.command.clone(),
        ancestry: ancestry
            .into_iter()
            .map(|a| AgentAncestor {
                pid: a.pid,
                name: a.name,
            })
            .collect(),
    }
}

pub fn file_to_agent(f: &OpenFile) -> AgentFile {
    AgentFile {
        pid: f.process.pid,
        process: f.process.name.clone(),
        user: f.process.user.clone(),
        fd: f.fd,
        fd_type: f.fd_type.to_string(),
        path: f.path.clone(),
        deleted: f.deleted,
    }
}

pub fn detect_anomalies(sockets: &[AgentSocket], files: &[AgentFile]) -> Vec<String> {
    let mut hints = Vec::new();

    // 1. Shell/dangerous processes listening on a port
    let shell_procs = ["bash", "sh", "zsh", "fish", "nc", "ncat", "netcat", "socat"];
    for s in sockets {
        if s.state == "LISTEN" {
            let proc_lower = s.process.to_ascii_lowercase();
            if shell_procs
                .iter()
                .any(|sp| proc_lower == *sp || proc_lower.starts_with(&format!("{sp} ")))
            {
                hints.push(format!(
                    "ALERT: shell/netcat process '{}' (pid {}) is listening on {}",
                    s.process, s.pid, s.local
                ));
            }
        }
    }

    // 2. More than 20 connections from a single remote IP
    let mut ip_count: HashMap<String, usize> = HashMap::new();
    for s in sockets {
        if s.state != "LISTEN" {
            // Extract IP from "ip:port"
            let ip = s
                .remote
                .rsplit_once(':')
                .map(|(ip, _)| ip.to_string())
                .unwrap_or_else(|| s.remote.clone());
            if !ip.is_empty() && ip != "*" && ip != "0.0.0.0" && ip != "::" {
                *ip_count.entry(ip).or_insert(0) += 1;
            }
        }
    }
    for (ip, count) in &ip_count {
        if *count > 20 {
            hints.push(format!(
                "WARN: {} connections from remote IP {} (possible DoS/scan)",
                count, ip
            ));
        }
    }

    // 3. Deleted files still held open
    let deleted_count = files.iter().filter(|f| f.deleted).count();
    if deleted_count > 0 {
        hints.push(format!(
            "INFO: {} deleted file(s) still held open by processes (disk space not released)",
            deleted_count
        ));
    }

    hints
}

pub fn diff_snapshots(old: &Snapshot, new: &Snapshot) -> serde_json::Value {
    let key = |s: &AgentSocket| format!("{}|{}|{}|{}", s.protocol, s.local, s.remote, s.process);

    let old_listeners: HashMap<String, &AgentSocket> = old
        .sockets
        .iter()
        .filter(|s| s.state == "LISTEN")
        .map(|s| (key(s), s))
        .collect();
    let new_listeners: HashMap<String, &AgentSocket> = new
        .sockets
        .iter()
        .filter(|s| s.state == "LISTEN")
        .map(|s| (key(s), s))
        .collect();

    let old_conns: HashMap<String, &AgentSocket> = old
        .sockets
        .iter()
        .filter(|s| s.state != "LISTEN")
        .map(|s| (key(s), s))
        .collect();
    let new_conns: HashMap<String, &AgentSocket> = new
        .sockets
        .iter()
        .filter(|s| s.state != "LISTEN")
        .map(|s| (key(s), s))
        .collect();

    let added_listeners: Vec<&AgentSocket> = new_listeners
        .iter()
        .filter(|(k, _)| !old_listeners.contains_key(*k))
        .map(|(_, s)| *s)
        .collect();

    let removed_listeners: Vec<&AgentSocket> = old_listeners
        .iter()
        .filter(|(k, _)| !new_listeners.contains_key(*k))
        .map(|(_, s)| *s)
        .collect();

    let new_connections: Vec<&AgentSocket> = new_conns
        .iter()
        .filter(|(k, _)| !old_conns.contains_key(*k))
        .map(|(_, s)| *s)
        .collect();

    let dropped_connections: Vec<&AgentSocket> = old_conns
        .iter()
        .filter(|(k, _)| !new_conns.contains_key(*k))
        .map(|(_, s)| *s)
        .collect();

    let all_new_sockets: Vec<AgentSocket> = new.sockets.clone();
    let all_new_files: Vec<AgentFile> = Vec::new();
    let anomalies = detect_anomalies(&all_new_sockets, &all_new_files);

    json!({
        "schema": "opn-diff/1",
        "old_ts": old.ts,
        "new_ts": new.ts,
        "added_listeners": added_listeners,
        "removed_listeners": removed_listeners,
        "new_connections": new_connections,
        "dropped_connections": dropped_connections,
        "anomalies": anomalies
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_caps_read_only() {
        let c = caps(false);
        assert_eq!(c, vec!["read"]);
    }

    #[test]
    fn test_caps_write() {
        let c = caps(true);
        assert!(c.contains(&String::from("read")));
        assert!(c.contains(&String::from("kill")));
        assert!(c.contains(&String::from("firewall")));
    }

    #[test]
    fn test_detect_anomalies_shell_listener() {
        let sockets = vec![AgentSocket {
            protocol: "TCP".to_string(),
            local: "0.0.0.0:4444".to_string(),
            remote: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            pid: 1234,
            process: "nc".to_string(),
            user: "root".to_string(),
            cmd: "nc -l 4444".to_string(),
            ancestry: vec![],
        }];
        let hints = detect_anomalies(&sockets, &[]);
        assert!(!hints.is_empty());
        assert!(hints[0].contains("ALERT"));
    }

    #[test]
    fn test_detect_anomalies_deleted_files() {
        let files = vec![AgentFile {
            pid: 100,
            process: "app".to_string(),
            user: "root".to_string(),
            fd: Some(3),
            fd_type: "REG".to_string(),
            path: "/tmp/deleted.log".to_string(),
            deleted: true,
        }];
        let hints = detect_anomalies(&[], &files);
        assert!(!hints.is_empty());
        assert!(hints[0].contains("deleted"));
    }

    #[test]
    fn test_current_ts_reasonable() {
        let ts = current_ts();
        // Should be after 2024-01-01 (Unix timestamp > 1700000000)
        assert!(ts > 1_700_000_000);
    }
}
