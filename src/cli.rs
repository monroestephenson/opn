use clap::{Parser, Subcommand, ValueEnum};

use crate::model::QueryFilter;

#[derive(Parser, Debug)]
#[command(
    name = "opn",
    version,
    about = "Find which processes have files, ports, and sockets open"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Output results as JSON instead of a table.
    #[arg(long, global = true)]
    pub json: bool,

    /// Output in LLM-optimized compact JSON with self-describing actions.
    #[arg(long = "llm", global = true)]
    pub llm: bool,

    /// Enable write operations: kill, firewall. Handle with care.
    #[arg(long, global = true)]
    pub allow_write: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show processes with sockets bound to a local port.
    Port {
        /// Local port number to inspect.
        port: u16,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Show processes that currently have a file open.
    File {
        /// File path to match.
        path: String,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// List open file descriptors for a process ID.
    Pid {
        /// Process ID to inspect.
        pid: u32,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Show processes still holding deleted files open.
    Deleted {
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// List open sockets.
    Sockets {
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Refresh and display live results continuously.
    Watch {
        /// What to watch: sockets, one port, or one file.
        #[arg(long, value_enum, default_value_t = WatchTarget::Sockets)]
        target: WatchTarget,

        /// Color theme for watch mode.
        #[arg(long, value_enum, default_value_t = WatchTheme::Everforest)]
        theme: WatchTheme,

        /// Port to watch (required with `--target port`).
        #[arg(long)]
        port: Option<u16>,

        /// File path to watch (required with `--target file`).
        #[arg(long)]
        file: Option<String>,

        /// Refresh interval in seconds (1-60).
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=60))]
        interval: u64,

        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Kill a process by PID.
    Kill {
        /// PID to terminate.
        pid: u32,
        /// Signal to send (TERM, KILL, HUP, INT).
        #[arg(long, default_value = "TERM")]
        signal: String,
    },

    /// Kill all processes listening on a port.
    KillPort {
        /// Port number.
        port: u16,
        /// Signal to send.
        #[arg(long, default_value = "TERM")]
        signal: String,
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Take a point-in-time snapshot of network state.
    Snapshot {
        /// Write snapshot JSON to this file (default: stdout).
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Show what changed since a previous snapshot.
    Diff {
        /// Path to snapshot file created with `opn snapshot`.
        snapshot: std::path::PathBuf,
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Show network interface statistics.
    Interfaces,

    /// Show TCP/IP stack health metrics (Linux only).
    Snmp,

    /// Full network diagnostic: sockets + interfaces + metrics + anomalies in one call.
    Diagnose {
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Manage firewall rules (requires --allow-write).
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// Show CPU/memory/fd stats for processes with open sockets.
    Resources {
        #[command(flatten)]
        filter: FilterArgs,
    },

    /// Show network configuration: routes, DNS, interface addresses.
    Netconfig,

    /// Analyze network-related log entries.
    Logs {
        /// Log type: auth, system, kernel, web, firewall, all.
        #[arg(long, default_value = "all")]
        log_type: String,
        /// Number of lines to read from log (1–10000).
        #[arg(long, default_value_t = 200, value_parser = parse_lines)]
        lines: usize,
        /// Filter string (grep-style substring match).
        #[arg(long)]
        filter: Option<String>,
    },

    /// Measure network bandwidth by polling interface stats.
    Bandwidth {
        /// Measurement duration in seconds (1-30).
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=30))]
        duration: u64,
    },

    /// Capture and summarize network packets (wraps tcpdump).
    Capture {
        /// Network interface (default: auto).
        #[arg(long)]
        interface: Option<String>,
        /// Filter by port.
        #[arg(long)]
        port: Option<u16>,
        /// Filter by host IP.
        #[arg(long)]
        host: Option<String>,
        /// Max packets to capture.
        #[arg(long, default_value_t = 100)]
        count: u32,
        /// Stop after this many seconds.
        #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=60))]
        duration: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum FirewallAction {
    /// List current opn firewall rules.
    List,
    /// Block an IP address.
    BlockIp {
        ip: String,
        #[arg(long)]
        comment: Option<String>,
        /// Rule TTL in seconds (informational only, not auto-expired).
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Block a port.
    BlockPort {
        port: u16,
        /// Direction: in or out.
        #[arg(long, default_value = "in")]
        dir: String,
    },
    /// Remove a rule by IP or comment.
    Unblock { target: String },
    /// Flush all opn firewall rules.
    Flush,
    /// Undo the last firewall action.
    Undo,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum WatchTarget {
    Sockets,
    Port,
    File,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum WatchTheme {
    CatppuccinLatte,
    Catppuccin,
    Ethereal,
    Everforest,
    FlexokiLight,
    Gruvbox,
    Hackerman,
    Kanagawa,
    MatteBlack,
    Miasma,
    Nord,
    OsakaJade,
    Ristretto,
    RosePine,
    TokyoNight,
    Vantablack,
    White,
}

fn parse_lines(raw: &str) -> Result<usize, String> {
    let value: usize = raw
        .parse()
        .map_err(|_| String::from("lines must be a positive integer"))?;
    if (1..=10_000).contains(&value) {
        Ok(value)
    } else {
        Err(String::from("lines must be in range 1..=10000"))
    }
}

#[derive(Parser, Debug, Clone)]
pub struct FilterArgs {
    /// Include all users' processes (requires root for full visibility).
    #[arg(long, short = 'a')]
    pub all: bool,

    /// Match an exact username.
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Match an exact process name.
    #[arg(long, short = 'p')]
    pub process: Option<String>,

    /// Match socket state (example: LISTEN, ESTABLISHED).
    #[arg(long)]
    pub state: Option<String>,

    /// Match an exact process ID.
    #[arg(long = "pid", visible_alias = "filter-pid")]
    pub filter_pid: Option<u32>,

    /// Include TCP sockets.
    #[arg(long)]
    pub tcp: bool,

    /// Include UDP sockets.
    #[arg(long)]
    pub udp: bool,

    /// Include IPv4 sockets.
    #[arg(long)]
    pub ipv4: bool,

    /// Include IPv6 sockets.
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
