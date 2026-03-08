mod agent;
mod cli;
mod commands;
mod model;
#[cfg(any(test, target_os = "linux"))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod net;
mod path_safety;
mod platform;
mod render;
mod socket_display;
mod watch;

use clap::Parser;
use serde::Serialize;
use std::process::ExitCode;

use agent::{
    build_actions, caps, current_ts, detect_anomalies, file_to_agent, print_agent_response,
    socket_to_agent, AgentResponse,
};
use cli::{Cli, Command};
use model::{KillSignal, OpenFile, QueryFilter, SocketEntry};
use platform::{create_platform, Platform};
use render::RenderOutcome;

// ── LLM rendering helpers ────────────────────────────────────────────────────

fn render_sockets_llm(
    platform: &dyn Platform,
    mut sockets: Vec<SocketEntry>,
    cmd: &str,
    allow_write: bool,
) -> anyhow::Result<RenderOutcome> {
    commands::sort_sockets(&mut sockets);
    let agent_sockets: Vec<_> = sockets
        .iter()
        .map(|s| {
            let ancestry = platform.process_ancestry(s.process.pid).unwrap_or_default();
            // resolve=true since this helper is only called in --llm mode
            socket_to_agent(s, ancestry, true)
        })
        .collect();
    let hints = detect_anomalies(&agent_sockets, &[]);
    let resp = AgentResponse {
        schema: "opn-agent/1".to_string(),
        ok: true,
        ts: current_ts(),
        cmd: cmd.to_string(),
        caps: caps(allow_write),
        data: Some(serde_json::to_value(&agent_sockets).unwrap_or_default()),
        hints,
        warnings: vec![],
        actions: build_actions(allow_write),
    };
    print_agent_response(&resp);
    Ok(if sockets.is_empty() {
        RenderOutcome::NoResults
    } else {
        RenderOutcome::HasResults
    })
}

fn render_files_llm(
    files: Vec<OpenFile>,
    cmd: &str,
    allow_write: bool,
) -> anyhow::Result<RenderOutcome> {
    let agent_files: Vec<_> = files.iter().map(file_to_agent).collect();
    let hints = detect_anomalies(&[], &agent_files);
    let resp = AgentResponse {
        schema: "opn-agent/1".to_string(),
        ok: true,
        ts: current_ts(),
        cmd: cmd.to_string(),
        caps: caps(allow_write),
        data: Some(serde_json::to_value(&agent_files).unwrap_or_default()),
        hints,
        warnings: vec![],
        actions: build_actions(allow_write),
    };
    print_agent_response(&resp);
    Ok(if files.is_empty() {
        RenderOutcome::NoResults
    } else {
        RenderOutcome::HasResults
    })
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCategory {
    InvalidInput,
    NotFound,
    PermissionDenied,
    NotImplemented,
    Runtime,
}

#[derive(Debug, Serialize)]
struct JsonError {
    code: String,
    category: ErrorCategory,
    message: String,
}

fn classify_error(message: &str) -> JsonError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found") {
        JsonError {
            code: String::from("NOT_FOUND"),
            category: ErrorCategory::NotFound,
            message: message.to_string(),
        }
    } else if lower.contains("permission denied") || lower.contains("operation not permitted") {
        JsonError {
            code: String::from("PERMISSION_DENIED"),
            category: ErrorCategory::PermissionDenied,
            message: message.to_string(),
        }
    } else if lower.contains("not implemented") || lower.contains("requires the 'watch' feature") {
        JsonError {
            code: String::from("NOT_IMPLEMENTED"),
            category: ErrorCategory::NotImplemented,
            message: message.to_string(),
        }
    } else if lower.contains("invalid") || lower.contains("usage:") {
        JsonError {
            code: String::from("INVALID_INPUT"),
            category: ErrorCategory::InvalidInput,
            message: message.to_string(),
        }
    } else {
        JsonError {
            code: String::from("RUNTIME_ERROR"),
            category: ErrorCategory::Runtime,
            message: message.to_string(),
        }
    }
}

fn write_guard_error(llm: bool) -> ExitCode {
    let msg = "This command requires --allow-write. Re-run with: opn --allow-write <command>";
    if llm {
        println!(
            "{}",
            serde_json::json!({"schema":"opn-agent/1","ok":false,"error":msg})
        );
    } else {
        eprintln!("error: {msg}");
    }
    ExitCode::from(2)
}

fn has_all_flag(cli: &Cli) -> bool {
    match &cli.command {
        Command::Port { filter, .. }
        | Command::File { filter, .. }
        | Command::Pid { filter, .. }
        | Command::Deleted { filter }
        | Command::Sockets { filter } => filter.all,
        Command::Watch { filter, .. } => filter.all,
        Command::KillPort { filter, .. } => filter.all,
        Command::Snapshot { filter, .. } => filter.all,
        Command::Diff { filter, .. } => filter.all,
        Command::Diagnose { filter } => filter.all,
        Command::Resources { filter } => filter.all,
        // These commands don't have filter args
        Command::Kill { .. }
        | Command::Interfaces
        | Command::Snmp
        | Command::Firewall { .. }
        | Command::Netconfig
        | Command::Logs { .. }
        | Command::Bandwidth { .. }
        | Command::Capture { .. } => false,
    }
}

fn warn_partial_visibility(cli: &Cli) {
    if !has_all_flag(cli) {
        return;
    }
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        eprintln!(
            "Warning: --all requires root/sudo for full visibility. \
             Results may be incomplete for other users' processes."
        );
    }
}

/// Exit codes:
///   0 — results found and printed
///   1 — no results (query succeeded but matched nothing)
///   2 — error (invalid input, permission denied, runtime failure)
fn main() -> ExitCode {
    let cli = Cli::parse();
    let platform = create_platform();

    // Warn about partial visibility when --all is used without root/sudo.
    warn_partial_visibility(&cli);

    let result = match &cli.command {
        Command::Port { port, filter } => {
            let qf = QueryFilter::from(filter);
            if cli.llm {
                (|| -> anyhow::Result<RenderOutcome> {
                    let sockets = platform.find_by_port(*port, &qf)?;
                    render_sockets_llm(&platform, sockets, &format!("port {port}"), cli.allow_write)
                })()
            } else {
                commands::port::run(&platform, *port, &qf, cli.json)
            }
        }
        Command::File { path, filter } => {
            let qf = QueryFilter::from(filter);
            if cli.llm {
                (|| -> anyhow::Result<RenderOutcome> {
                    crate::path_safety::validate_user_path(path)?;
                    let files = platform.find_by_file(path, &qf)?;
                    render_files_llm(files, &format!("file {path}"), cli.allow_write)
                })()
            } else {
                commands::file::run(&platform, path, &qf, cli.json)
            }
        }
        Command::Pid { pid, filter } => {
            let qf = QueryFilter::from(filter);
            if cli.llm {
                (|| -> anyhow::Result<RenderOutcome> {
                    let known = platform.list_pids(&QueryFilter::default())?;
                    if !known.contains(pid) {
                        anyhow::bail!("PID {} not found", pid);
                    }
                    let files = platform.list_open_files(*pid)?;
                    render_files_llm(files, &format!("pid {pid}"), cli.allow_write)
                })()
            } else {
                commands::pid::run(&platform, *pid, &qf, cli.json)
            }
        }
        Command::Deleted { filter } => {
            let qf = QueryFilter::from(filter);
            if cli.llm {
                (|| -> anyhow::Result<RenderOutcome> {
                    let files = platform.find_deleted(&qf)?;
                    render_files_llm(files, "deleted", cli.allow_write)
                })()
            } else {
                commands::deleted::run(&platform, &qf, cli.json)
            }
        }
        Command::Sockets { filter } => {
            let qf = QueryFilter::from(filter);
            if cli.llm {
                (|| -> anyhow::Result<RenderOutcome> {
                    let sockets = platform.list_sockets(&qf)?;
                    render_sockets_llm(&platform, sockets, "sockets", cli.allow_write)
                })()
            } else {
                commands::sockets::run(&platform, &qf, cli.json)
            }
        }
        Command::Watch {
            target,
            theme,
            port,
            file,
            interval,
            filter,
        } => {
            #[cfg(feature = "watch")]
            {
                let qf = QueryFilter::from(filter);
                match watch::run(
                    &platform,
                    watch::WatchRunOptions {
                        target: *target,
                        theme: *theme,
                        port: *port,
                        file: file.as_deref(),
                        interval_secs: *interval,
                        filter: &qf,
                        as_json: cli.json,
                    },
                ) {
                    Ok(_) => Ok(RenderOutcome::HasResults),
                    Err(e) => Err(e),
                }
            }
            #[cfg(not(feature = "watch"))]
            {
                let _ = (target, theme, port, file, interval, filter);
                Err(anyhow::anyhow!(
                    "opn watch is unavailable in this build (missing 'watch' feature). Rebuild with: cargo build --features watch"
                ))
            }
        }
        Command::Kill { pid, signal } => {
            if !cli.allow_write {
                return write_guard_error(cli.llm);
            }
            match signal.parse::<KillSignal>() {
                Ok(sig) => commands::kill::run_kill(&platform, *pid, sig, cli.llm, cli.allow_write),
                Err(e) => Err(e),
            }
        }
        Command::KillPort {
            port,
            signal,
            filter,
        } => {
            if !cli.allow_write {
                return write_guard_error(cli.llm);
            }
            match signal.parse::<KillSignal>() {
                Ok(sig) => {
                    let qf = QueryFilter::from(filter);
                    commands::kill::run_kill_port(
                        &platform,
                        *port,
                        sig,
                        &qf,
                        cli.llm,
                        cli.allow_write,
                    )
                }
                Err(e) => Err(e),
            }
        }
        Command::Snapshot { out, filter } => {
            let qf = QueryFilter::from(filter);
            commands::snapshot::run_snapshot(&platform, &qf, out.as_deref())
        }
        Command::Diff { snapshot, filter } => {
            let qf = QueryFilter::from(filter);
            commands::snapshot::run_diff(snapshot, &platform, &qf, cli.llm)
        }
        Command::Interfaces => commands::interfaces::run(&platform, cli.llm, cli.allow_write),
        Command::Snmp => commands::snmp::run(&platform, cli.llm, cli.allow_write),
        Command::Diagnose { filter } => {
            let qf = QueryFilter::from(filter);
            commands::diagnose::run(&platform, &qf, cli.llm, cli.allow_write)
        }
        Command::Firewall { action } => {
            if !cli.allow_write {
                return write_guard_error(cli.llm);
            }
            commands::firewall::run(action, cli.llm, cli.allow_write)
        }
        Command::Resources { filter } => {
            let qf = QueryFilter::from(filter);
            commands::resources::run(&platform, &qf, cli.llm, cli.allow_write)
        }
        Command::Netconfig => commands::netconfig::run(&platform, cli.llm, cli.allow_write),
        Command::Logs {
            log_type,
            lines,
            filter,
        } => commands::logs::run(
            log_type,
            *lines,
            filter.as_deref(),
            cli.llm,
            cli.allow_write,
        ),
        Command::Bandwidth { duration } => {
            commands::bandwidth::run(&platform, *duration, cli.llm, cli.allow_write)
        }
        Command::Capture {
            interface,
            port,
            host,
            count,
            duration,
        } => commands::capture::run(
            interface.as_deref(),
            *port,
            host.as_deref(),
            *count,
            *duration,
            cli.llm,
            cli.allow_write,
        ),
    };

    match result {
        Ok(RenderOutcome::HasResults) => ExitCode::from(0),
        Ok(RenderOutcome::NoResults) => ExitCode::from(1),
        Err(err) => {
            if cli.json || cli.llm {
                let payload = serde_json::json!({ "error": classify_error(&err.to_string()) });
                println!("{payload}");
            } else {
                eprintln!("{err}");
            }
            ExitCode::from(2)
        }
    }
}
