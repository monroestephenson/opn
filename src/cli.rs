use clap::{Parser, Subcommand};

use crate::model::QueryFilter;

#[derive(Parser, Debug)]
#[command(name = "opn", version, about = "A modern, human-friendly replacement for lsof")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output results as JSON
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Find processes listening on a port
    Port {
        /// Port number to look up
        port: u16,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Find processes that have a file open
    File {
        /// Path to the file
        path: String,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Show open files for a given PID
    Pid {
        /// Process ID
        pid: u32,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Find processes with deleted files still open
    Deleted {
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// List all open sockets
    Sockets {
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Watch open files/sockets in real time (requires --features watch)
    Watch {
        #[command(flatten)]
        filter: FilterArgs,
    },
}

#[derive(Parser, Debug, Clone)]
pub struct FilterArgs {
    /// Include all users' processes (may require root)
    #[arg(long, short = 'a')]
    pub all: bool,

    /// Filter by username
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Filter by process name
    #[arg(long, short = 'p')]
    pub process: Option<String>,

    /// Filter by PID
    #[arg(long = "filter-pid")]
    pub filter_pid: Option<u32>,

    /// Show only TCP sockets
    #[arg(long)]
    pub tcp: bool,

    /// Show only UDP sockets
    #[arg(long)]
    pub udp: bool,

    /// Show only IPv4 sockets
    #[arg(long)]
    pub ipv4: bool,

    /// Show only IPv6 sockets
    #[arg(long)]
    pub ipv6: bool,
}

impl From<&FilterArgs> for QueryFilter {
    fn from(args: &FilterArgs) -> Self {
        QueryFilter {
            pid: args.filter_pid,
            user: args.user.clone(),
            process_name: args.process.clone(),
            tcp: args.tcp,
            udp: args.udp,
            ipv4: args.ipv4,
            ipv6: args.ipv6,
            all: args.all,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_args_to_query_filter() {
        let args = FilterArgs {
            all: true,
            user: Some("root".to_string()),
            process: Some("sshd".to_string()),
            filter_pid: Some(1234),
            tcp: true,
            udp: false,
            ipv4: true,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert_eq!(filter.pid, Some(1234));
        assert_eq!(filter.user.as_deref(), Some("root"));
        assert_eq!(filter.process_name.as_deref(), Some("sshd"));
        assert!(filter.tcp);
        assert!(!filter.udp);
        assert!(filter.ipv4);
        assert!(!filter.ipv6);
        assert!(filter.all);
    }
}
