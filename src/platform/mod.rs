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
