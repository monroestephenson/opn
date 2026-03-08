mod cli;
mod commands;
mod model;
mod net;
mod platform;
mod render;
mod watch;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};
use model::QueryFilter;
use platform::create_platform;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let platform = create_platform();

    match &cli.command {
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
                watch::run()
            }
            #[cfg(not(feature = "watch"))]
            {
                anyhow::bail!("opn watch requires the 'watch' feature. Rebuild with: cargo build --features watch")
            }
        }
    }
}
