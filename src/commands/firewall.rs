use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::{self, AgentResponse};
use crate::cli::FirewallAction;
use crate::render::RenderOutcome;

#[derive(Serialize, Deserialize)]
struct UndoEntry {
    ts: u64,
    action: String,
    target: String,
    undo_cmd: Vec<String>,
}

fn undo_log_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("opn")
        .join("undo.jsonl")
}

fn ensure_undo_dir() -> Result<()> {
    let path = undo_log_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create opn data dir")?;
    }
    Ok(())
}

fn append_undo_entry(entry: &UndoEntry) -> Result<()> {
    ensure_undo_dir()?;
    let path = undo_log_path();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("Failed to open undo log at {}", path.display()))?;
    let line = serde_json::to_string(entry)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

fn run_cmd(args: &[&str]) -> Result<String> {
    if args.is_empty() {
        anyhow::bail!("Empty command");
    }
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("Failed to run {:?}", args[0]))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        let combined = format!("{}{}", stdout, stderr).trim().to_string();
        anyhow::bail!("{}", combined);
    }
    Ok(format!("{}{}", stdout, stderr))
}

#[cfg(target_os = "linux")]
mod linux_fw {
    use super::*;

    fn ensure_opn_chain() -> Result<()> {
        // Create OPN chain if it doesn't exist
        let _ = Command::new("iptables").args(["-N", "OPN"]).output();
        // Ensure INPUT jumps to OPN
        let check = Command::new("iptables")
            .args(["-C", "INPUT", "-j", "OPN"])
            .output();
        if let Ok(out) = check {
            if !out.status.success() {
                run_cmd(&["iptables", "-I", "INPUT", "-j", "OPN"])?;
            }
        }
        Ok(())
    }

    pub fn list() -> Result<String> {
        let output = Command::new("iptables")
            .args(["-L", "OPN", "-n", "--line-numbers"])
            .output();
        match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_string()
                    + &String::from_utf8_lossy(&out.stderr);
                Ok(text)
            }
            Err(e) => Err(anyhow::anyhow!("Failed to run iptables: {}", e)),
        }
    }

    pub fn block_ip(ip: &str, comment: Option<&str>, _ttl: Option<u64>) -> Result<String> {
        ip.parse::<std::net::IpAddr>()
            .with_context(|| format!("Invalid IP address: {}", ip))?;
        ensure_opn_chain()?;
        let label = comment.unwrap_or(ip);
        run_cmd(&[
            "iptables",
            "-I",
            "OPN",
            "-s",
            ip,
            "-j",
            "DROP",
            "-m",
            "comment",
            "--comment",
            &format!("opn:{}", label),
        ])?;
        let undo = UndoEntry {
            ts: agent::current_ts(),
            action: String::from("block-ip"),
            target: ip.to_string(),
            undo_cmd: vec![
                String::from("iptables"),
                String::from("-D"),
                String::from("OPN"),
                String::from("-s"),
                ip.to_string(),
                String::from("-j"),
                String::from("DROP"),
            ],
        };
        append_undo_entry(&undo)?;
        Ok(format!("Blocked IP {}", ip))
    }

    pub fn block_port(port: u16, dir: &str) -> Result<String> {
        ensure_opn_chain()?;
        let chain = if dir == "out" { "OUTPUT" } else { "INPUT" };
        run_cmd(&[
            "iptables",
            "-I",
            chain,
            "-p",
            "tcp",
            "--dport",
            &port.to_string(),
            "-j",
            "DROP",
        ])?;
        let undo = UndoEntry {
            ts: agent::current_ts(),
            action: String::from("block-port"),
            target: port.to_string(),
            undo_cmd: vec![
                String::from("iptables"),
                String::from("-D"),
                chain.to_string(),
                String::from("-p"),
                String::from("tcp"),
                String::from("--dport"),
                port.to_string(),
                String::from("-j"),
                String::from("DROP"),
            ],
        };
        append_undo_entry(&undo)?;
        Ok(format!("Blocked port {} ({})", port, chain))
    }

    pub fn unblock(target: &str) -> Result<String> {
        // Remove rules matching the target comment or IP
        let output = run_cmd(&["iptables", "-L", "OPN", "-n", "--line-numbers"])?;
        let mut lines_to_delete: Vec<u32> = Vec::new();
        for line in output.lines() {
            if line.contains(target) {
                if let Some(num_str) = line.split_whitespace().next() {
                    if let Ok(num) = num_str.parse::<u32>() {
                        lines_to_delete.push(num);
                    }
                }
            }
        }
        // Delete in reverse order so line numbers stay valid
        lines_to_delete.sort_unstable();
        lines_to_delete.reverse();
        for num in lines_to_delete {
            let _ = run_cmd(&["iptables", "-D", "OPN", &num.to_string()]);
        }
        Ok(format!("Unblocked {}", target))
    }

    pub fn flush() -> Result<String> {
        run_cmd(&["iptables", "-F", "OPN"])?;
        Ok(String::from("Flushed all OPN rules"))
    }

    pub fn undo() -> Result<String> {
        let path = super::undo_log_path();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read undo log at {}", path.display()))?;
        let last_line = content
            .lines()
            .last()
            .ok_or_else(|| anyhow::anyhow!("Undo log is empty"))?;
        let entry: UndoEntry = serde_json::from_str(last_line)?;
        if entry.undo_cmd.is_empty() {
            anyhow::bail!("Undo command is empty");
        }
        let args: Vec<&str> = entry.undo_cmd.iter().map(|s| s.as_str()).collect();
        run_cmd(&args)?;
        // Remove last line from undo log
        let lines: Vec<&str> = content.lines().collect();
        let new_content: String = lines[..lines.len().saturating_sub(1)].join("\n");
        std::fs::write(&path, new_content)?;
        Ok(format!("Undid: {} {}", entry.action, entry.target))
    }
}

#[cfg(target_os = "macos")]
mod macos_fw {
    use super::*;

    fn pf_rules_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("opn")
            .join("pf-rules.conf")
    }

    fn ensure_rules_dir() -> Result<()> {
        let path = pf_rules_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Check that the 'opn' anchor is declared in /etc/pf.conf.
    /// Returns a helpful error if not, since pfctl will refuse to load rules otherwise.
    fn check_anchor_setup() -> Result<()> {
        let pf_conf = std::fs::read_to_string("/etc/pf.conf").unwrap_or_default();
        let has_anchor = pf_conf
            .lines()
            .any(|l| !l.trim_start().starts_with('#') && l.contains("anchor") && l.contains("opn"));
        if !has_anchor {
            anyhow::bail!(
                "The 'opn' pf anchor is not set up.\n\
                 \n\
                 Add this line to /etc/pf.conf (before the com.apple anchor lines):\n\
                 \n\
                 \tanchor \"opn\"\n\
                 \n\
                 Then reload pf:\n\
                 \n\
                 \tsudo pfctl -f /etc/pf.conf\n\
                 \n\
                 After that, firewall commands will work."
            );
        }
        Ok(())
    }

    pub fn list() -> Result<String> {
        let output = Command::new("pfctl")
            .args(["-a", "opn", "-s", "rules"])
            .output();
        match output {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                // Anchor doesn't exist yet — no rules have been added
                if stderr.contains("DIOCGETRULES") || stderr.contains("Invalid argument") {
                    return Ok(String::from("No rules. Use 'opn --allow-write firewall block-ip <IP>' or 'block-port <PORT>' to add one."));
                }
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                // Filter out harmless ALTQ noise from stderr
                let relevant_stderr: String = stderr
                    .lines()
                    .filter(|l| !l.contains("ALTQ") && !l.contains("DIOCGETRULES"))
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(if relevant_stderr.is_empty() {
                    stdout
                } else {
                    format!("{}{}", stdout, relevant_stderr)
                })
            }
            Err(e) => Err(anyhow::anyhow!("Failed to run pfctl: {}", e)),
        }
    }

    fn reload_rules() -> Result<()> {
        check_anchor_setup()?;
        let rules_path = pf_rules_path();
        run_cmd(&[
            "pfctl",
            "-a",
            "opn",
            "-f",
            rules_path.to_str().unwrap_or("/tmp/opn-pf-rules.conf"),
        ])?;
        Ok(())
    }

    fn append_rule(rule: &str) -> Result<()> {
        ensure_rules_dir()?;
        let path = pf_rules_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(file, "{}", rule)?;
        reload_rules()
    }

    pub fn block_ip(ip: &str, comment: Option<&str>, _ttl: Option<u64>) -> Result<String> {
        ip.parse::<std::net::IpAddr>()
            .with_context(|| format!("Invalid IP address: {}", ip))?;
        let label = comment.unwrap_or(ip);
        append_rule(&format!("block from {} to any # opn:{}", ip, label))?;
        let undo = UndoEntry {
            ts: agent::current_ts(),
            action: String::from("block-ip"),
            target: ip.to_string(),
            undo_cmd: vec![String::from("opn-pf-undo")],
        };
        append_undo_entry(&undo)?;
        Ok(format!("Blocked IP {} via pf", ip))
    }

    pub fn block_port(port: u16, dir: &str) -> Result<String> {
        let direction = if dir == "out" { "out" } else { "in" };
        append_rule(&format!(
            "block {} proto tcp from any to any port {}",
            direction, port
        ))?;
        let undo = UndoEntry {
            ts: agent::current_ts(),
            action: String::from("block-port"),
            target: port.to_string(),
            undo_cmd: vec![String::from("opn-pf-undo")],
        };
        append_undo_entry(&undo)?;
        Ok(format!("Blocked port {} ({}) via pf", port, direction))
    }

    pub fn unblock(target: &str) -> Result<String> {
        let path = pf_rules_path();
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        let new_content: String = content
            .lines()
            .filter(|l| !l.contains(target))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, &new_content)?;
        reload_rules()?;
        Ok(format!("Unblocked {}", target))
    }

    pub fn flush() -> Result<String> {
        run_cmd(&["pfctl", "-a", "opn", "-F", "rules"])?;
        // Clear the rules file too
        let path = pf_rules_path();
        if path.exists() {
            std::fs::write(&path, "")?;
        }
        Ok(String::from("Flushed all opn pf rules"))
    }

    pub fn undo() -> Result<String> {
        let path = super::undo_log_path();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read undo log at {}", path.display()))?;
        let last_line = content
            .lines()
            .last()
            .ok_or_else(|| anyhow::anyhow!("Undo log is empty"))?;
        let entry: UndoEntry = serde_json::from_str(last_line)?;
        // For pf, undo means removing the last rule from the rules file and reloading
        let rules_path = pf_rules_path();
        let rules_content = std::fs::read_to_string(&rules_path).unwrap_or_default();
        let rules_lines: Vec<&str> = rules_content.lines().collect();
        let new_rules = rules_lines[..rules_lines.len().saturating_sub(1)].join("\n");
        std::fs::write(&rules_path, &new_rules)?;
        reload_rules()?;
        // Remove last line from undo log
        let lines: Vec<&str> = content.lines().collect();
        let new_content = lines[..lines.len().saturating_sub(1)].join("\n");
        std::fs::write(&path, new_content)?;
        Ok(format!("Undid: {} {}", entry.action, entry.target))
    }
}

pub fn run(action: &FirewallAction, llm: bool, allow_write: bool) -> Result<RenderOutcome> {
    let result = dispatch_action(action);

    match result {
        Ok(msg) => {
            if llm {
                let resp = AgentResponse {
                    schema: String::from("opn-agent/1"),
                    ok: true,
                    ts: agent::current_ts(),
                    cmd: String::from("firewall"),
                    caps: agent::caps(allow_write),
                    data: Some(serde_json::json!({ "message": msg })),
                    hints: vec![],
                    warnings: vec![],
                    actions: agent::build_actions(allow_write),
                };
                agent::print_agent_response(&resp);
            } else {
                println!("{}", msg);
            }
            Ok(RenderOutcome::HasResults)
        }
        Err(e) => {
            if llm {
                let resp = AgentResponse {
                    schema: String::from("opn-agent/1"),
                    ok: false,
                    ts: agent::current_ts(),
                    cmd: String::from("firewall"),
                    caps: agent::caps(allow_write),
                    data: None,
                    hints: vec![],
                    warnings: vec![e.to_string()],
                    actions: agent::build_actions(allow_write),
                };
                agent::print_agent_response(&resp);
                Ok(RenderOutcome::NoResults)
            } else {
                Err(e)
            }
        }
    }
}

fn dispatch_action(action: &FirewallAction) -> Result<String> {
    match action {
        FirewallAction::List => fw_list(),
        FirewallAction::BlockIp { ip, comment, ttl } => fw_block_ip(ip, comment.as_deref(), *ttl),
        FirewallAction::BlockPort { port, dir } => fw_block_port(*port, dir),
        FirewallAction::Unblock { target } => fw_unblock(target),
        FirewallAction::Flush => fw_flush(),
        FirewallAction::Undo => fw_undo(),
    }
}

#[cfg(target_os = "linux")]
fn fw_list() -> Result<String> {
    linux_fw::list()
}

#[cfg(target_os = "linux")]
fn fw_block_ip(ip: &str, comment: Option<&str>, ttl: Option<u64>) -> Result<String> {
    linux_fw::block_ip(ip, comment, ttl)
}

#[cfg(target_os = "linux")]
fn fw_block_port(port: u16, dir: &str) -> Result<String> {
    linux_fw::block_port(port, dir)
}

#[cfg(target_os = "linux")]
fn fw_unblock(target: &str) -> Result<String> {
    linux_fw::unblock(target)
}

#[cfg(target_os = "linux")]
fn fw_flush() -> Result<String> {
    linux_fw::flush()
}

#[cfg(target_os = "linux")]
fn fw_undo() -> Result<String> {
    linux_fw::undo()
}

#[cfg(target_os = "macos")]
fn fw_list() -> Result<String> {
    macos_fw::list()
}

#[cfg(target_os = "macos")]
fn fw_block_ip(ip: &str, comment: Option<&str>, ttl: Option<u64>) -> Result<String> {
    macos_fw::block_ip(ip, comment, ttl)
}

#[cfg(target_os = "macos")]
fn fw_block_port(port: u16, dir: &str) -> Result<String> {
    macos_fw::block_port(port, dir)
}

#[cfg(target_os = "macos")]
fn fw_unblock(target: &str) -> Result<String> {
    macos_fw::unblock(target)
}

#[cfg(target_os = "macos")]
fn fw_flush() -> Result<String> {
    macos_fw::flush()
}

#[cfg(target_os = "macos")]
fn fw_undo() -> Result<String> {
    macos_fw::undo()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fw_list() -> Result<String> {
    anyhow::bail!("Firewall management not supported on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fw_block_ip(_ip: &str, _comment: Option<&str>, _ttl: Option<u64>) -> Result<String> {
    anyhow::bail!("Firewall management not supported on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fw_block_port(_port: u16, _dir: &str) -> Result<String> {
    anyhow::bail!("Firewall management not supported on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fw_unblock(_target: &str) -> Result<String> {
    anyhow::bail!("Firewall management not supported on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fw_flush() -> Result<String> {
    anyhow::bail!("Firewall management not supported on this platform")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn fw_undo() -> Result<String> {
    anyhow::bail!("Firewall management not supported on this platform")
}
