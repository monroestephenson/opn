mod cli;
mod commands;
mod model;
mod net;
mod platform;
mod render;
mod watch;

use clap::Parser;
use std::process::ExitCode;

use cli::{Cli, Command};
use model::QueryFilter;
use platform::create_platform;
use render::RenderOutcome;

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
        Command::Watch { .. } => {
            #[cfg(feature = "watch")]
            {
                match watch::run() {
                    Ok(_) => Ok(RenderOutcome::HasResults),
                    Err(e) => Err(e),
                }
            }
            #[cfg(not(feature = "watch"))]
            {
                Err(anyhow::anyhow!(
                    "opn watch requires the 'watch' feature. Rebuild with: cargo build --features watch"
                ))
            }
        }
    };

    match result {
        Ok(RenderOutcome::HasResults) => ExitCode::from(0),
        Ok(RenderOutcome::NoResults) => ExitCode::from(1),
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}
