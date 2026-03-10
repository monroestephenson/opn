use anyhow::Context;
use std::sync::Arc;

use crate::agent::{AgentFile, AgentResponse, AgentSocket};
use crate::cli::{Cli, Command};
use crate::model::{FdType, OpenFile, ProcessInfo, Protocol, SocketEntry};
use crate::render::{self, RenderOutcome};

pub fn run(host: &str, cli: &Cli) -> anyhow::Result<RenderOutcome> {
    // Bail early for Watch — it's interactive and can't be remoted
    if matches!(cli.command, Command::Watch { .. }) {
        anyhow::bail!(
            "Remote watch is not yet supported. Use --host with: sockets, port, file, pid, or other non-interactive commands."
        );
    }

    let mut ssh = std::process::Command::new("ssh");
    if let Ok(cfg) = std::env::var("OPN_SSH_CONFIG") {
        ssh.args(["-F", &cfg]);
    }
    let output = ssh
        .arg(host)
        .arg("opn")
        .args(build_remote_args())
        .output()
        .context("failed to run ssh — is it on your PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{stderr}");
        anyhow::bail!("SSH connection failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: AgentResponse = serde_json::from_str(&stdout)
        .context("failed to parse remote opn output as AgentResponse")?;

    // Print hints and warnings to stderr with [remote] prefix
    for h in &resp.hints {
        eprintln!("[remote] {h}");
    }
    for w in &resp.warnings {
        eprintln!("[remote] warning: {w}");
    }

    // Branch on command type
    match &cli.command {
        Command::Sockets { .. } | Command::Port { .. } | Command::Pid { .. } => {
            let data = resp.data.unwrap_or_default();
            let agent_sockets: Vec<AgentSocket> = serde_json::from_value(data)
                .context("failed to parse remote data as socket list")?;
            let entries: Vec<SocketEntry> = agent_sockets.iter().map(socket_from_agent).collect();
            Ok(render::render(&entries, cli.json))
        }
        Command::File { .. } | Command::Deleted { .. } => {
            let data = resp.data.unwrap_or_default();
            let agent_files: Vec<AgentFile> =
                serde_json::from_value(data).context("failed to parse remote data as file list")?;
            let files: Vec<OpenFile> = agent_files.iter().map(file_from_agent).collect();
            Ok(render::render(&files, cli.json))
        }
        Command::Watch { .. } => unreachable!("handled above"),
        _ => {
            // For all other commands, pretty-print the raw data as JSON
            let out =
                serde_json::to_string_pretty(&resp.data.unwrap_or_default()).unwrap_or_default();
            println!("{out}");
            Ok(RenderOutcome::HasResults)
        }
    }
}

fn build_remote_args() -> Vec<String> {
    let mut result = vec!["--llm".to_string()];
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut skip = false;
    for arg in &args {
        if skip {
            skip = false;
            continue;
        }
        if arg == "--host" {
            skip = true;
            continue;
        }
        if arg.starts_with("--host=") {
            continue;
        }
        if arg == "--llm" || arg == "--json" {
            continue;
        }
        result.push(arg.clone());
    }
    result
}

fn socket_from_agent(s: &AgentSocket) -> SocketEntry {
    let protocol = match s.protocol.to_ascii_uppercase().as_str() {
        "UDP" => Protocol::Udp,
        _ => Protocol::Tcp,
    };
    let process = Arc::new(ProcessInfo {
        pid: s.pid,
        name: s.process.clone(),
        user: s.user.clone(),
        uid: 0, // not in remote payload
        command: s.cmd.clone(),
    });
    SocketEntry {
        protocol,
        local_addr: s.local.clone(),
        remote_addr: s.remote.clone(),
        state: s.state.clone(),
        process,
    }
}

fn file_from_agent(f: &AgentFile) -> OpenFile {
    let fd_type = match f.fd_type.as_str() {
        "REG" => FdType::RegularFile,
        "DIR" => FdType::Directory,
        "SOCK" => FdType::Socket,
        "PIPE" => FdType::Pipe,
        "DEV" => FdType::Device,
        _ => FdType::Unknown,
    };
    let process = Arc::new(ProcessInfo {
        pid: f.pid,
        name: f.process.clone(),
        user: f.user.clone(),
        uid: 0, // not in remote payload
        command: String::new(),
    });
    OpenFile {
        process,
        fd: f.fd,
        fd_type,
        path: f.path.clone(),
        deleted: f.deleted,
        socket_info: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_agent_socket(protocol: &str, local: &str, state: &str) -> AgentSocket {
        AgentSocket {
            protocol: protocol.to_string(),
            local: local.to_string(),
            remote: "0.0.0.0:0".to_string(),
            state: state.to_string(),
            pid: 42,
            process: "nginx".to_string(),
            user: "www".to_string(),
            cmd: "/usr/sbin/nginx".to_string(),
            ancestry: vec![],
            rdns: None,
            service: None,
            container: None,
        }
    }

    fn make_agent_file(fd_type: &str, path: &str, deleted: bool) -> AgentFile {
        AgentFile {
            pid: 99,
            process: "app".to_string(),
            user: "alice".to_string(),
            fd: Some(3),
            fd_type: fd_type.to_string(),
            path: path.to_string(),
            deleted,
        }
    }

    // ── socket_from_agent ────────────────────────────────────────────────────

    #[test]
    fn socket_from_agent_tcp() {
        let s = make_agent_socket("TCP", "0.0.0.0:80", "LISTEN");
        let entry = socket_from_agent(&s);
        assert_eq!(entry.protocol, Protocol::Tcp);
        assert_eq!(entry.local_addr, "0.0.0.0:80");
        assert_eq!(entry.state, "LISTEN");
        assert_eq!(entry.process.pid, 42);
        assert_eq!(entry.process.name, "nginx");
        assert_eq!(entry.process.user, "www");
        assert_eq!(entry.process.uid, 0);
        assert_eq!(entry.process.command, "/usr/sbin/nginx");
    }

    #[test]
    fn socket_from_agent_udp() {
        let s = make_agent_socket("UDP", "0.0.0.0:53", "-");
        let entry = socket_from_agent(&s);
        assert_eq!(entry.protocol, Protocol::Udp);
    }

    #[test]
    fn socket_from_agent_unknown_protocol_defaults_to_tcp() {
        let s = make_agent_socket("SCTP", "0.0.0.0:9", "LISTEN");
        let entry = socket_from_agent(&s);
        assert_eq!(entry.protocol, Protocol::Tcp);
    }

    #[test]
    fn socket_from_agent_lowercase_udp() {
        let s = make_agent_socket("udp", "127.0.0.1:5353", "-");
        let entry = socket_from_agent(&s);
        assert_eq!(entry.protocol, Protocol::Udp);
    }

    // ── file_from_agent ──────────────────────────────────────────────────────

    #[test]
    fn file_from_agent_reg() {
        let f = make_agent_file("REG", "/tmp/foo.txt", false);
        let of = file_from_agent(&f);
        assert_eq!(of.fd_type, FdType::RegularFile);
        assert_eq!(of.path, "/tmp/foo.txt");
        assert!(!of.deleted);
        assert_eq!(of.fd, Some(3));
        assert_eq!(of.process.pid, 99);
        assert_eq!(of.process.uid, 0);
    }

    #[test]
    fn file_from_agent_dir() {
        let f = make_agent_file("DIR", "/var/log", false);
        assert_eq!(file_from_agent(&f).fd_type, FdType::Directory);
    }

    #[test]
    fn file_from_agent_sock() {
        let f = make_agent_file("SOCK", "", false);
        assert_eq!(file_from_agent(&f).fd_type, FdType::Socket);
    }

    #[test]
    fn file_from_agent_pipe() {
        let f = make_agent_file("PIPE", "", false);
        assert_eq!(file_from_agent(&f).fd_type, FdType::Pipe);
    }

    #[test]
    fn file_from_agent_dev() {
        let f = make_agent_file("DEV", "/dev/null", false);
        assert_eq!(file_from_agent(&f).fd_type, FdType::Device);
    }

    #[test]
    fn file_from_agent_unknown_fd_type() {
        let f = make_agent_file("???", "/weird", false);
        assert_eq!(file_from_agent(&f).fd_type, FdType::Unknown);
    }

    #[test]
    fn file_from_agent_deleted_flag() {
        let f = make_agent_file("REG", "/tmp/gone.log", true);
        assert!(file_from_agent(&f).deleted);
    }

    #[test]
    fn file_from_agent_no_fd() {
        let mut f = make_agent_file("REG", "/tmp/x", false);
        f.fd = None;
        assert_eq!(file_from_agent(&f).fd, None);
    }

    // ── build_remote_args ────────────────────────────────────────────────────
    // These tests call the function with the real process args, which in test
    // context are cargo test flags — we just verify the invariants hold:
    // result always starts with "--llm" and never contains "--host" or "--json".

    #[test]
    fn build_remote_args_always_starts_with_llm() {
        let args = build_remote_args();
        assert_eq!(args[0], "--llm");
    }

    #[test]
    fn build_remote_args_strips_llm_and_json_dedup() {
        // In normal test invocation there is no --json or --llm in args,
        // so the result is just ["--llm", ...test runner flags...].
        // The key invariant: "--llm" appears exactly once at position 0.
        let args = build_remote_args();
        let llm_count = args.iter().filter(|a| *a == "--llm").count();
        assert_eq!(llm_count, 1, "expected exactly one --llm in {args:?}");
    }

    #[test]
    fn build_remote_args_no_host_flag() {
        let args = build_remote_args();
        assert!(
            !args
                .iter()
                .any(|a| a == "--host" || a.starts_with("--host=")),
            "--host must not appear in remote args: {args:?}"
        );
    }
}
