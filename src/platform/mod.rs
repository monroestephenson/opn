use anyhow::Result;

use crate::model::{OpenFile, ProcessInfo, QueryFilter, SocketEntry};

pub trait Platform: Send + Sync {
    fn list_pids(&self, filter: &QueryFilter) -> Result<Vec<u32>>;
    fn process_info(&self, pid: u32) -> Result<ProcessInfo>;
    fn list_open_files(&self, pid: u32) -> Result<Vec<OpenFile>>;
    fn find_by_file(&self, path: &str, filter: &QueryFilter) -> Result<Vec<OpenFile>>;
    fn find_by_port(&self, port: u16, filter: &QueryFilter) -> Result<Vec<SocketEntry>>;
    fn list_sockets(&self, filter: &QueryFilter) -> Result<Vec<SocketEntry>>;
    fn find_deleted(&self, filter: &QueryFilter) -> Result<Vec<OpenFile>>;
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

    #[test]
    fn test_mock_platform_find_by_port_found() {
        let mock = MockPlatform::with_sockets(vec![SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: "0.0.0.0:80".to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: ProcessInfo {
                pid: 1,
                name: "nginx".to_string(),
                user: "www".to_string(),
                uid: 33,
                command: "/usr/sbin/nginx".to_string(),
            },
        }]);
        let filter = QueryFilter::default();
        let results = mock.find_by_port(80, &filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].process.name, "nginx");
    }

    #[test]
    fn test_mock_platform_find_by_port_not_found() {
        let mock = MockPlatform::with_sockets(vec![SocketEntry {
            protocol: Protocol::Tcp,
            local_addr: "0.0.0.0:80".to_string(),
            remote_addr: "0.0.0.0:0".to_string(),
            state: "LISTEN".to_string(),
            process: ProcessInfo {
                pid: 1,
                name: "nginx".to_string(),
                user: "www".to_string(),
                uid: 33,
                command: "/usr/sbin/nginx".to_string(),
            },
        }]);
        let filter = QueryFilter::default();
        let results = mock.find_by_port(443, &filter).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_mock_platform_find_by_port_multiple() {
        let mock = MockPlatform::with_sockets(vec![
            SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "0.0.0.0:80".to_string(),
                remote_addr: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
                process: ProcessInfo {
                    pid: 1,
                    name: "nginx".to_string(),
                    user: "www".to_string(),
                    uid: 33,
                    command: "/usr/sbin/nginx".to_string(),
                },
            },
            SocketEntry {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1:80".to_string(),
                remote_addr: "0.0.0.0:0".to_string(),
                state: "LISTEN".to_string(),
                process: ProcessInfo {
                    pid: 2,
                    name: "apache".to_string(),
                    user: "www".to_string(),
                    uid: 33,
                    command: "/usr/sbin/apache".to_string(),
                },
            },
        ]);
        let filter = QueryFilter::default();
        let results = mock.find_by_port(80, &filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_mock_platform_find_by_file_found() {
        let mock = MockPlatform::with_files(vec![OpenFile {
            process: ProcessInfo {
                pid: 42,
                name: "vim".to_string(),
                user: "user".to_string(),
                uid: 1000,
                command: "/usr/bin/vim".to_string(),
            },
            fd: 3,
            fd_type: FdType::RegularFile,
            path: "/etc/hosts".to_string(),
            deleted: false,
            socket_info: None,
        }]);
        let filter = QueryFilter::default();
        let results = mock.find_by_file("/etc/hosts", &filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].process.name, "vim");
    }

    #[test]
    fn test_mock_platform_find_by_file_not_found() {
        let mock = MockPlatform::with_files(vec![OpenFile {
            process: ProcessInfo {
                pid: 42,
                name: "vim".to_string(),
                user: "user".to_string(),
                uid: 1000,
                command: "/usr/bin/vim".to_string(),
            },
            fd: 3,
            fd_type: FdType::RegularFile,
            path: "/etc/hosts".to_string(),
            deleted: false,
            socket_info: None,
        }]);
        let filter = QueryFilter::default();
        let results = mock.find_by_file("/etc/passwd", &filter).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_mock_platform_list_pids() {
        let mock = MockPlatform::with_pids(vec![1, 42, 1000, 9999]);
        let filter = QueryFilter::default();
        let pids = mock.list_pids(&filter).unwrap();
        assert_eq!(pids, vec![1, 42, 1000, 9999]);
    }

    #[test]
    fn test_mock_platform_list_pids_empty() {
        let mock = MockPlatform::empty();
        let filter = QueryFilter::default();
        let pids = mock.list_pids(&filter).unwrap();
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
        let result = mock.process_info(99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_platform_stubs_return_errors() {
        let mock = MockPlatform::empty();
        let filter = QueryFilter::default();
        assert!(mock.list_sockets(&filter).is_err());
    }

    #[test]
    fn test_mock_platform_find_deleted() {
        let mock = MockPlatform::with_files(vec![
            OpenFile {
                process: ProcessInfo {
                    pid: 10,
                    name: "worker".to_string(),
                    user: "alice".to_string(),
                    uid: 1000,
                    command: "/usr/bin/worker".to_string(),
                },
                fd: 4,
                fd_type: FdType::RegularFile,
                path: "/tmp/a.log".to_string(),
                deleted: true,
                socket_info: None,
            },
            OpenFile {
                process: ProcessInfo {
                    pid: 11,
                    name: "worker".to_string(),
                    user: "alice".to_string(),
                    uid: 1000,
                    command: "/usr/bin/worker".to_string(),
                },
                fd: 5,
                fd_type: FdType::RegularFile,
                path: "/tmp/b.log".to_string(),
                deleted: false,
                socket_info: None,
            },
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
        let mock = MockPlatform::with_files(vec![
            OpenFile {
                process: ProcessInfo {
                    pid: 42,
                    name: "test".to_string(),
                    user: "user".to_string(),
                    uid: 1000,
                    command: "test".to_string(),
                },
                fd: 0,
                fd_type: FdType::RegularFile,
                path: "/dev/null".to_string(),
                deleted: false,
                socket_info: None,
            },
            OpenFile {
                process: ProcessInfo {
                    pid: 42,
                    name: "test".to_string(),
                    user: "user".to_string(),
                    uid: 1000,
                    command: "test".to_string(),
                },
                fd: 1,
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
