//! Mock Platform for testing command logic without OS dependencies.

use anyhow::{bail, Result};

use super::Platform;
use crate::model::*;

pub struct MockPlatform {
    pids: Vec<u32>,
    sockets: Vec<SocketEntry>,
    files: Vec<OpenFile>,
}

impl MockPlatform {
    pub fn empty() -> Self {
        MockPlatform {
            pids: vec![],
            sockets: vec![],
            files: vec![],
        }
    }

    pub fn with_pids(pids: Vec<u32>) -> Self {
        MockPlatform {
            pids,
            sockets: vec![],
            files: vec![],
        }
    }

    pub fn with_sockets(sockets: Vec<SocketEntry>) -> Self {
        let pids = sockets.iter().map(|s| s.process.pid).collect();
        MockPlatform {
            pids,
            sockets,
            files: vec![],
        }
    }

    pub fn with_files(files: Vec<OpenFile>) -> Self {
        let pids = files.iter().map(|f| f.process.pid).collect();
        MockPlatform {
            pids,
            sockets: vec![],
            files,
        }
    }
}

impl Platform for MockPlatform {
    fn list_pids(&self, _filter: &QueryFilter) -> Result<Vec<u32>> {
        Ok(self.pids.clone())
    }

    fn process_info(&self, pid: u32) -> Result<ProcessInfo> {
        if self.pids.contains(&pid) {
            // Check if we have a socket or file with this PID for more details
            if let Some(s) = self.sockets.iter().find(|s| s.process.pid == pid) {
                return Ok((*s.process).clone());
            }
            if let Some(f) = self.files.iter().find(|f| f.process.pid == pid) {
                return Ok((*f.process).clone());
            }
            Ok(ProcessInfo {
                pid,
                name: format!("mock-{pid}"),
                user: "mockuser".to_string(),
                uid: 1000,
                command: format!("/usr/bin/mock-{pid}"),
            })
        } else {
            bail!("Process {} not found", pid)
        }
    }

    fn list_open_files(&self, pid: u32) -> Result<Vec<OpenFile>> {
        Ok(self
            .files
            .iter()
            .filter(|f| f.process.pid == pid)
            .cloned()
            .collect())
    }

    fn find_by_file(&self, path: &str, _filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        Ok(self
            .files
            .iter()
            .filter(|f| f.path == path)
            .cloned()
            .collect())
    }

    fn find_by_port(&self, port: u16, _filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        Ok(self
            .sockets
            .iter()
            .filter(|s| {
                // Extract port from local_addr "addr:port"
                s.local_addr
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
                    == Some(port)
            })
            .cloned()
            .collect())
    }

    fn list_sockets(&self, _filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        Ok(self.sockets.clone())
    }

    fn find_deleted(&self, filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        Ok(self
            .files
            .iter()
            .filter(|f| f.deleted)
            .filter(|f| filter.pid.map(|pid| f.process.pid == pid).unwrap_or(true))
            .filter(|f| {
                filter
                    .user
                    .as_ref()
                    .map(|user| f.process.user == *user)
                    .unwrap_or(true)
            })
            .filter(|f| {
                filter
                    .process_name
                    .as_ref()
                    .map(|name| f.process.name == *name)
                    .unwrap_or(true)
            })
            .cloned()
            .collect())
    }
}
