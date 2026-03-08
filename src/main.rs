mod cli;
mod commands;
mod model;
#[cfg(any(test, target_os = "linux"))]
mod net;
mod platform;
mod render;
mod watch;

use clap::Parser;
use serde::Serialize;
use std::process::ExitCode;

use cli::{Cli, Command};
use model::QueryFilter;
use platform::create_platform;
use render::RenderOutcome;

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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let platform = create_platform();

    let result = match &cli.command {
        Command::Port { port, filter } => {
            let qf = QueryFilter::from(filter);
            commands::port::run(&platform, *port, &qf, cli.json)
        }
        Command::File { path, filter } => {
            let qf = QueryFilter::from(filter);
            commands::file::run(&platform, path, &qf, cli.json)
        }
        Command::Pid { pid, filter } => {
            let qf = QueryFilter::from(filter);
            commands::pid::run(&platform, *pid, &qf, cli.json)
        }
        Command::Deleted { filter } => {
            let qf = QueryFilter::from(filter);
            commands::deleted::run(&platform, &qf, cli.json)
        }
        Command::Sockets { filter } => {
            let qf = QueryFilter::from(filter);
            commands::sockets::run(&platform, &qf, cli.json)
        }
        Command::Watch {
            target,
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
                    *target,
                    *port,
                    file.as_deref(),
                    *interval,
                    &qf,
                    cli.json,
                ) {
                    Ok(_) => Ok(RenderOutcome::HasResults),
                    Err(e) => Err(e),
                }
            }
            #[cfg(not(feature = "watch"))]
            {
                let _ = (target, port, file, interval, filter);
                Err(anyhow::anyhow!(
                    "opn watch is unavailable in this build (missing 'watch' feature). Rebuild with: cargo build --features watch"
                ))
            }
        }
    };

    match result {
        Ok(RenderOutcome::HasResults) => ExitCode::from(0),
        Ok(RenderOutcome::NoResults) => ExitCode::from(1),
        Err(err) => {
            if cli.json {
                let payload = serde_json::json!({ "error": classify_error(&err.to_string()) });
                println!("{payload}");
            } else {
                eprintln!("{err}");
            }
            ExitCode::from(2)
        }
    }
}
