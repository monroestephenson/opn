use anyhow::Result;

use crate::model::{
    InterfaceStats, KillSignal, NetConfig, OpenFile, ProcessAncestor, ProcessInfo,
    ProcessResources, ProcessTableRow, QueryFilter, SocketEntry, TcpMetrics,
};

pub trait Platform: Send + Sync {
    fn list_pids(&self, filter: &QueryFilter) -> Result<Vec<u32>>;
    fn process_info(&self, pid: u32) -> Result<ProcessInfo>;
    fn list_open_files(&self, pid: u32) -> Result<Vec<OpenFile>>;
    fn find_by_file(&self, path: &str, filter: &QueryFilter) -> Result<Vec<OpenFile>>;
    fn find_by_port(&self, port: u16, filter: &QueryFilter) -> Result<Vec<SocketEntry>>;
    fn list_sockets(&self, filter: &QueryFilter) -> Result<Vec<SocketEntry>>;
    fn find_deleted(&self, filter: &QueryFilter) -> Result<Vec<OpenFile>>;
    fn process_ancestry(&self, pid: u32) -> Result<Vec<ProcessAncestor>>;
    fn process_table(&self) -> Result<Vec<ProcessTableRow>>;
    fn interface_stats(&self) -> Result<Vec<InterfaceStats>>;
    fn tcp_metrics(&self) -> Result<Option<TcpMetrics>>;
    fn kill_process(&self, pid: u32, signal: KillSignal) -> Result<()>;
    fn process_resources(&self, pid: u32) -> Result<ProcessResources>;
    fn net_config(&self) -> Result<NetConfig>;
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOsPlatform as NativePlatform;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxPlatform as NativePlatform;

pub fn create_platform() -> NativePlatform {
    NativePlatform::new()
}

#[cfg(test)]
pub mod mock;

#[cfg(test)]
mod tests {
    use super::mock::MockPlatform;
    use super::Platform;
    use crate::model::*;
    use std::sync::Arc;

    fn make_socket(pid: u32, name: &str, addr: &str) -> SocketEntry {
        SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: addr.to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: Arc::new(ProcessInfo {
                pid,
                name: name.to_string(),
                user: "www".to_string(),
                uid: 33,
                command: format!("/usr/sbin/{name}"),
            }),
        }
    }

    fn make_file(pid: u32, name: &str, path: &str, deleted: bool) -> OpenFile {
        OpenFile {
            process: Arc::new(ProcessInfo {
                pid,
                name: name.to_string(),
                user: "alice".to_string(),
                uid: 1000,
                command: format!("/usr/bin/{name}"),
            }),
            fd: Some(3),
            fd_type: FdType::RegularFile,
            path: path.to_string(),
            deleted,
            socket_info: None,
        }
    }

    #[test]
    fn test_mock_platform_find_by_port_found() {
        let mock = MockPlatform::with_sockets(vec![make_socket(1, "nginx", "0.0.0.0:80")]);
        let results = mock.find_by_port(80, &QueryFilter::default()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].process.name, "nginx");
    }

    #[test]
    fn test_mock_platform_find_by_port_not_found() {
        let mock = MockPlatform::with_sockets(vec![make_socket(1, "nginx", "0.0.0.0:80")]);
        let results = mock.find_by_port(443, &QueryFilter::default()).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_mock_platform_find_by_port_multiple() {
        let mock = MockPlatform::with_sockets(vec![
            make_socket(1, "nginx", "0.0.0.0:80"),
            make_socket(2, "apache", "127.0.0.1:80"),
        ]);
        let results = mock.find_by_port(80, &QueryFilter::default()).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_mock_platform_find_by_file_found() {
        let mock = MockPlatform::with_files(vec![make_file(42, "vim", "/etc/hosts", false)]);
        let results = mock
            .find_by_file("/etc/hosts", &QueryFilter::default())
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].process.name, "vim");
    }

    #[test]
    fn test_mock_platform_find_by_file_not_found() {
        let mock = MockPlatform::with_files(vec![make_file(42, "vim", "/etc/hosts", false)]);
        let results = mock
            .find_by_file("/etc/passwd", &QueryFilter::default())
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_mock_platform_list_pids() {
        let mock = MockPlatform::with_pids(vec![1, 42, 1000, 9999]);
        let pids = mock.list_pids(&QueryFilter::default()).unwrap();
        assert_eq!(pids, vec![1, 42, 1000, 9999]);
    }

    #[test]
    fn test_mock_platform_list_pids_empty() {
        let mock = MockPlatform::empty();
        let pids = mock.list_pids(&QueryFilter::default()).unwrap();
        assert!(pids.is_empty());
    }

    #[test]
    fn test_mock_platform_process_info() {
        let mock = MockPlatform::with_pids(vec![42]);
        let info = mock.process_info(42).unwrap();
        assert_eq!(info.pid, 42);
    }

    #[test]
    fn test_mock_platform_process_info_not_found() {
        let mock = MockPlatform::with_pids(vec![1]);
        assert!(mock.process_info(99999).is_err());
    }

    #[test]
    fn test_mock_platform_list_sockets_empty() {
        let mock = MockPlatform::empty();
        let sockets = mock.list_sockets(&QueryFilter::default()).unwrap();
        assert!(sockets.is_empty());
    }

    #[test]
    fn test_mock_platform_find_deleted() {
        let mock = MockPlatform::with_files(vec![
            make_file(10, "worker", "/tmp/a.log", true),
            make_file(11, "worker", "/tmp/b.log", false),
        ]);

        let all = mock.find_deleted(&QueryFilter::default()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].path, "/tmp/a.log");

        let by_pid = mock
            .find_deleted(&QueryFilter {
                pid: Some(10),
                ..QueryFilter::default()
            })
            .unwrap();
        assert_eq!(by_pid.len(), 1);

        let by_user_miss = mock
            .find_deleted(&QueryFilter {
                user: Some("bob".to_string()),
                ..QueryFilter::default()
            })
            .unwrap();
        assert!(by_user_miss.is_empty());
    }

    #[test]
    fn test_mock_platform_list_open_files() {
        let proc_info = Arc::new(ProcessInfo {
            pid: 42,
            name: "test".to_string(),
            user: "user".to_string(),
            uid: 1000,
            command: "test".to_string(),
        });
        let mock = MockPlatform::with_files(vec![
            OpenFile {
                process: proc_info.clone(),
                fd: Some(0),
                fd_type: FdType::RegularFile,
                path: "/dev/null".to_string(),
                deleted: false,
                socket_info: None,
            },
            OpenFile {
                process: proc_info,
                fd: Some(1),
                fd_type: FdType::Pipe,
                path: "pipe:[123]".to_string(),
                deleted: false,
                socket_info: None,
            },
        ]);
        let files = mock.list_open_files(42).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].fd_type, FdType::RegularFile);
        assert_eq!(files[1].fd_type, FdType::Pipe);
    }
}
