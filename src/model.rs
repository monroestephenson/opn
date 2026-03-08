use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub uid: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenFile {
    pub process: ProcessInfo,
    pub fd: i32,
    pub fd_type: FdType,
    pub path: String,
    pub deleted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket_info: Option<SocketEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum FdType {
    RegularFile,
    Directory,
    Socket,
    Pipe,
    Device,
    Unknown,
}

impl std::fmt::Display for FdType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FdType::RegularFile => write!(f, "REG"),
            FdType::Directory => write!(f, "DIR"),
            FdType::Socket => write!(f, "SOCK"),
            FdType::Pipe => write!(f, "PIPE"),
            FdType::Device => write!(f, "DEV"),
            FdType::Unknown => write!(f, "???"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketEntry {
    pub protocol: Protocol,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub process: ProcessInfo,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct QueryFilter {
    pub pid: Option<u32>,
    pub user: Option<String>,
    pub process_name: Option<String>,
    pub tcp: bool,
    pub udp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub all: bool,
}
