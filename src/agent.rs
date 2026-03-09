use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::{InterfaceStats, OpenFile, ProcessAncestor, SocketEntry, TcpMetrics};

// ── DNS reverse lookup ──────────────────────────────────────────────────────

/// Cache of resolved IPs to avoid redundant lookups and unbounded thread spawning.
static DNS_CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
static DNS_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
const DNS_MAX_IN_FLIGHT: usize = 32;

fn dns_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Perform a reverse DNS lookup for `ip` with a 500ms timeout.
/// Results are cached so each IP is resolved at most once per process.
/// Returns None for loopback/unspecified addresses or on any failure.
pub fn reverse_dns(ip: &str) -> Option<String> {
    // Skip loopback / unspecified
    if ip.starts_with("127.")
        || ip == "0.0.0.0"
        || ip == "::"
        || ip == "::1"
        || ip.is_empty()
        || ip == "*"
    {
        return None;
    }

    // Check cache first (read lock)
    if let Ok(cache) = dns_cache().lock() {
        if let Some(cached) = cache.get(ip) {
            return cached.clone();
        }
    }

    // Prevent unbounded thread growth if many unresolved IPs are seen at once.
    if DNS_IN_FLIGHT.fetch_add(1, Ordering::AcqRel) >= DNS_MAX_IN_FLIGHT {
        DNS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
        return None;
    }

    let ip_owned = ip.to_string();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = getnameinfo_lookup(&ip_owned);
        let _ = tx.send(result);
    });

    let result = rx.recv_timeout(Duration::from_millis(500)).ok().flatten();

    // Store in cache
    if let Ok(mut cache) = dns_cache().lock() {
        cache.insert(ip.to_string(), result.clone());
    }
    DNS_IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);

    result
}

/// Perform a reverse lookup using libc::getnameinfo.
fn getnameinfo_lookup(ip: &str) -> Option<String> {
    use std::net::IpAddr;
    let addr: IpAddr = ip.parse().ok()?;

    let mut host_buf = [0i8; 1025]; // NI_MAXHOST
    let ret = unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_be_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                    #[cfg(target_os = "macos")]
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host_buf.as_mut_ptr(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                    #[cfg(target_os = "macos")]
                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host_buf.as_mut_ptr(),
                    host_buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if ret != 0 {
        return None;
    }

    let cstr = unsafe { std::ffi::CStr::from_ptr(host_buf.as_ptr()) };
    let s = cstr.to_string_lossy().trim_end_matches('.').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdns: Option<String>,
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
        "diff":       "opn --llm diff <SNAPSHOT_FILE>",
        "resources":  "opn --llm resources",
        "netconfig":  "opn --llm netconfig",
        "logs":       "opn --llm logs [--log-type auth|system|kernel|web|firewall|all] [--lines N] [--filter TEXT]",
        "bandwidth":  "opn --llm bandwidth [--duration SECS]",
        "capture":    "opn --llm capture [--interface IFACE] [--port PORT] [--host IP] [--count N] [--duration SECS]"
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

pub fn socket_to_agent(
    s: &SocketEntry,
    ancestry: Vec<ProcessAncestor>,
    resolve: bool,
) -> AgentSocket {
    let rdns = if resolve {
        // Extract IP from "ip:port" (handle IPv6 "[::1]:port" form too)
        let remote_ip = if s.remote_addr.starts_with('[') {
            // IPv6 bracket notation: [::1]:port
            s.remote_addr
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or("")
        } else {
            s.remote_addr
                .rsplit_once(':')
                .map(|(ip, _)| ip)
                .unwrap_or(&s.remote_addr)
        };
        reverse_dns(remote_ip)
    } else {
        None
    };

    AgentSocket {
        protocol: s.protocol.to_string(),
        local: s.local_addr.clone(),
        remote: s.remote_addr.clone(),
        state: s.state.to_ascii_uppercase(),
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
        rdns,
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
            rdns: None,
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
