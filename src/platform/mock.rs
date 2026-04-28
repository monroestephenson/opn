//! Mock Platform for testing command logic without OS dependencies.

use anyhow::{bail, Result};

use super::Platform;
use crate::model::*;

impl Default for MockPlatform {
    fn default() -> Self {
        Self::empty()
    }
}

pub struct MockPlatform {
    pids: Vec<u32>,
    sockets: Vec<SocketEntry>,
    files: Vec<OpenFile>,
    process_table: Vec<ProcessTableRow>,
}

impl MockPlatform {
    pub fn empty() -> Self {
        MockPlatform {
            pids: vec![],
            sockets: vec![],
            files: vec![],
            process_table: vec![],
        }
    }

    pub fn with_pids(pids: Vec<u32>) -> Self {
        MockPlatform {
            pids,
            sockets: vec![],
            files: vec![],
            process_table: vec![],
        }
    }

    pub fn with_sockets(sockets: Vec<SocketEntry>) -> Self {
        let pids = sockets.iter().map(|s| s.process.pid).collect();
        MockPlatform {
            pids,
            sockets,
            files: vec![],
            process_table: vec![],
        }
    }

    pub fn with_files(files: Vec<OpenFile>) -> Self {
        let pids = files.iter().map(|f| f.process.pid).collect();
        MockPlatform {
            pids,
            sockets: vec![],
            files,
            process_table: vec![],
        }
    }

    pub fn with_process_table(rows: Vec<ProcessTableRow>) -> Self {
        let pids: Vec<u32> = rows.iter().map(|r| r.pid).collect();
        MockPlatform {
            pids,
            sockets: vec![],
            files: vec![],
            process_table: rows,
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

    fn process_ancestry(&self, _pid: u32) -> Result<Vec<ProcessAncestor>> {
        Ok(vec![])
    }

    fn process_table(&self) -> Result<Vec<ProcessTableRow>> {
        Ok(self.process_table.clone())
    }

    fn interface_stats(&self) -> Result<Vec<InterfaceStats>> {
        Ok(vec![])
    }

    fn tcp_metrics(&self) -> Result<Option<TcpMetrics>> {
        Ok(None)
    }

    fn kill_process(&self, _pid: u32, _signal: KillSignal) -> Result<()> {
        Ok(())
    }

    fn process_resources(&self, pid: u32) -> Result<ProcessResources> {
        Ok(ProcessResources {
            pid,
            cpu_pct: 0.0,
            mem_rss_kb: 0,
            mem_vms_kb: 0,
            open_fds: 0,
            threads: 0,
        })
    }

    fn net_config(&self) -> Result<NetConfig> {
        Ok(NetConfig {
            routes: vec![],
            dns_servers: vec![],
            dns_search: vec![],
            hostname: String::new(),
            interfaces: vec![],
        })
    }
}
