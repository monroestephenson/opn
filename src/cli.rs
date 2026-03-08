use clap::{Parser, Subcommand};

use crate::model::QueryFilter;

#[derive(Parser, Debug)]
#[command(
    name = "opn",
    version,
    about = "A modern, human-friendly replacement for lsof"
)]
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

    /// Filter by socket state (e.g. LISTEN, ESTABLISHED)
    #[arg(long)]
    pub state: Option<String>,

    /// Filter by PID
    #[arg(long = "pid", visible_alias = "filter-pid")]
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
            state: args.state.clone(),
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

    // ============================================================
    // FilterArgs → QueryFilter conversion
    // ============================================================

    #[test]
    fn test_filter_args_to_query_filter_full() {
        let args = FilterArgs {
            all: true,
            user: Some("root".to_string()),
            process: Some("sshd".to_string()),
            state: Some("LISTEN".to_string()),
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
        assert_eq!(filter.state.as_deref(), Some("LISTEN"));
        assert!(filter.tcp);
        assert!(!filter.udp);
        assert!(filter.ipv4);
        assert!(!filter.ipv6);
        assert!(filter.all);
    }

    #[test]
    fn test_filter_args_to_query_filter_defaults() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: None,
            state: None,
            filter_pid: None,
            tcp: false,
            udp: false,
            ipv4: false,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert_eq!(filter.pid, None);
        assert_eq!(filter.user, None);
        assert_eq!(filter.process_name, None);
        assert!(!filter.tcp);
        assert!(!filter.udp);
        assert!(!filter.ipv4);
        assert!(!filter.ipv6);
        assert!(!filter.all);
    }

    #[test]
    fn test_filter_args_to_query_filter_tcp_only() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: None,
            state: None,
            filter_pid: None,
            tcp: true,
            udp: false,
            ipv4: false,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert!(filter.tcp);
        assert!(!filter.udp);
    }

    #[test]
    fn test_filter_args_to_query_filter_udp_only() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: None,
            state: None,
            filter_pid: None,
            tcp: false,
            udp: true,
            ipv4: false,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert!(!filter.tcp);
        assert!(filter.udp);
    }

    #[test]
    fn test_filter_args_to_query_filter_both_protocols() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: None,
            state: None,
            filter_pid: None,
            tcp: true,
            udp: true,
            ipv4: false,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert!(filter.tcp);
        assert!(filter.udp);
    }

    #[test]
    fn test_filter_args_to_query_filter_ipv4_only() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: None,
            state: None,
            filter_pid: None,
            tcp: false,
            udp: false,
            ipv4: true,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert!(filter.ipv4);
        assert!(!filter.ipv6);
    }

    #[test]
    fn test_filter_args_to_query_filter_ipv6_only() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: None,
            state: None,
            filter_pid: None,
            tcp: false,
            udp: false,
            ipv4: false,
            ipv6: true,
        };
        let filter = QueryFilter::from(&args);
        assert!(!filter.ipv4);
        assert!(filter.ipv6);
    }

    #[test]
    fn test_filter_args_to_query_filter_user_cloned() {
        let args = FilterArgs {
            all: false,
            user: Some("testuser".to_string()),
            process: None,
            state: None,
            filter_pid: None,
            tcp: false,
            udp: false,
            ipv4: false,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert_eq!(filter.user, Some("testuser".to_string()));
        // Ensure it's a clone, not a reference
        drop(args);
        assert_eq!(filter.user.unwrap(), "testuser");
    }

    #[test]
    fn test_filter_args_to_query_filter_process_name() {
        let args = FilterArgs {
            all: false,
            user: None,
            process: Some("nginx".to_string()),
            state: None,
            filter_pid: None,
            tcp: false,
            udp: false,
            ipv4: false,
            ipv6: false,
        };
        let filter = QueryFilter::from(&args);
        assert_eq!(filter.process_name.as_deref(), Some("nginx"));
    }

    // ============================================================
    // CLI parsing (via clap try_parse_from)
    // ============================================================

    #[test]
    fn test_cli_parse_port() {
        let cli = Cli::try_parse_from(["opn", "port", "8080"]).unwrap();
        match cli.command {
            Command::Port { port, .. } => assert_eq!(port, 8080),
            _ => panic!("Expected Port command"),
        }
        assert!(!cli.json);
    }

    #[test]
    fn test_cli_parse_port_with_json() {
        let cli = Cli::try_parse_from(["opn", "--json", "port", "80"]).unwrap();
        assert!(cli.json);
        match cli.command {
            Command::Port { port, .. } => assert_eq!(port, 80),
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_port_json_after() {
        let cli = Cli::try_parse_from(["opn", "port", "80", "--json"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn test_cli_parse_port_with_tcp() {
        let cli = Cli::try_parse_from(["opn", "port", "80", "--tcp"]).unwrap();
        match cli.command {
            Command::Port { filter, .. } => assert!(filter.tcp),
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_port_with_all_filters() {
        let cli = Cli::try_parse_from([
            "opn", "port", "80", "--tcp", "--ipv4", "-a", "-u", "root", "-p", "nginx",
        ])
        .unwrap();
        match cli.command {
            Command::Port { filter, .. } => {
                assert!(filter.tcp);
                assert!(filter.ipv4);
                assert!(filter.all);
                assert_eq!(filter.user.as_deref(), Some("root"));
                assert_eq!(filter.process.as_deref(), Some("nginx"));
            }
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_file() {
        let cli = Cli::try_parse_from(["opn", "file", "/etc/hosts"]).unwrap();
        match cli.command {
            Command::File { path, .. } => assert_eq!(path, "/etc/hosts"),
            _ => panic!("Expected File command"),
        }
    }

    #[test]
    fn test_cli_parse_file_with_spaces() {
        let cli = Cli::try_parse_from(["opn", "file", "/path/with spaces/file.txt"]).unwrap();
        match cli.command {
            Command::File { path, .. } => assert_eq!(path, "/path/with spaces/file.txt"),
            _ => panic!("Expected File command"),
        }
    }

    #[test]
    fn test_cli_parse_pid() {
        let cli = Cli::try_parse_from(["opn", "pid", "1234"]).unwrap();
        match cli.command {
            Command::Pid { pid, .. } => assert_eq!(pid, 1234),
            _ => panic!("Expected Pid command"),
        }
    }

    #[test]
    fn test_cli_parse_pid_zero() {
        let cli = Cli::try_parse_from(["opn", "pid", "0"]).unwrap();
        match cli.command {
            Command::Pid { pid, .. } => assert_eq!(pid, 0),
            _ => panic!("Expected Pid command"),
        }
    }

    #[test]
    fn test_cli_parse_deleted() {
        let cli = Cli::try_parse_from(["opn", "deleted"]).unwrap();
        assert!(matches!(cli.command, Command::Deleted { .. }));
    }

    #[test]
    fn test_cli_parse_sockets() {
        let cli = Cli::try_parse_from(["opn", "sockets"]).unwrap();
        assert!(matches!(cli.command, Command::Sockets { .. }));
    }

    #[test]
    fn test_cli_parse_watch() {
        let cli = Cli::try_parse_from(["opn", "watch"]).unwrap();
        assert!(matches!(cli.command, Command::Watch { .. }));
    }

    #[test]
    fn test_cli_parse_invalid_port_not_number() {
        assert!(Cli::try_parse_from(["opn", "port", "abc"]).is_err());
    }

    #[test]
    fn test_cli_parse_invalid_port_too_large() {
        assert!(Cli::try_parse_from(["opn", "port", "99999"]).is_err());
    }

    #[test]
    fn test_cli_parse_invalid_pid_not_number() {
        assert!(Cli::try_parse_from(["opn", "pid", "abc"]).is_err());
    }

    #[test]
    fn test_cli_parse_no_subcommand() {
        assert!(Cli::try_parse_from(["opn"]).is_err());
    }

    #[test]
    fn test_cli_parse_unknown_subcommand() {
        assert!(Cli::try_parse_from(["opn", "foobar"]).is_err());
    }

    #[test]
    fn test_cli_parse_port_missing_arg() {
        assert!(Cli::try_parse_from(["opn", "port"]).is_err());
    }

    #[test]
    fn test_cli_parse_file_missing_arg() {
        assert!(Cli::try_parse_from(["opn", "file"]).is_err());
    }

    #[test]
    fn test_cli_parse_pid_missing_arg() {
        assert!(Cli::try_parse_from(["opn", "pid"]).is_err());
    }

    #[test]
    fn test_cli_parse_port_min() {
        let cli = Cli::try_parse_from(["opn", "port", "0"]).unwrap();
        match cli.command {
            Command::Port { port, .. } => assert_eq!(port, 0),
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_port_max() {
        let cli = Cli::try_parse_from(["opn", "port", "65535"]).unwrap();
        match cli.command {
            Command::Port { port, .. } => assert_eq!(port, 65535),
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_filter_pid_flag() {
        let cli = Cli::try_parse_from(["opn", "port", "80", "--filter-pid", "42"]).unwrap();
        match cli.command {
            Command::Port { filter, .. } => assert_eq!(filter.filter_pid, Some(42)),
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_pid_flag() {
        let cli = Cli::try_parse_from(["opn", "port", "80", "--pid", "42"]).unwrap();
        match cli.command {
            Command::Port { filter, .. } => assert_eq!(filter.filter_pid, Some(42)),
            _ => panic!("Expected Port command"),
        }
    }

    #[test]
    fn test_cli_parse_deleted_with_filters() {
        let cli = Cli::try_parse_from(["opn", "deleted", "-a", "-u", "root"]).unwrap();
        match cli.command {
            Command::Deleted { filter } => {
                assert!(filter.all);
                assert_eq!(filter.user.as_deref(), Some("root"));
            }
            _ => panic!("Expected Deleted command"),
        }
    }

    #[test]
    fn test_cli_parse_sockets_with_filters() {
        let cli = Cli::try_parse_from(["opn", "sockets", "--tcp", "--ipv6"]).unwrap();
        match cli.command {
            Command::Sockets { filter } => {
                assert!(filter.tcp);
                assert!(filter.ipv6);
            }
            _ => panic!("Expected Sockets command"),
        }
    }
}
