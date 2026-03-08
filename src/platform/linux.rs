use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::model::*;
use crate::net;
use super::Platform;

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        LinuxPlatform
    }

    fn uid_to_username(uid: u32) -> String {
        unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                return uid.to_string();
            }
            let name = std::ffi::CStr::from_ptr((*pw).pw_name);
            name.to_string_lossy().into_owned()
        }
    }

    fn read_proc_uid(pid: u32) -> Option<u32> {
        let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
        for line in status.lines() {
            if line.starts_with("Uid:") {
                let uid_str = line.split_whitespace().nth(1)?;
                return uid_str.parse().ok();
            }
        }
        None
    }

    fn classify_fd_target(target: &str) -> FdType {
        if target.starts_with("socket:[") {
            FdType::Socket
        } else if target.starts_with("pipe:[") {
            FdType::Pipe
        } else if target.starts_with("/dev/") {
            FdType::Device
        } else if Path::new(target).is_dir() {
            FdType::Directory
        } else {
            FdType::RegularFile
        }
    }

    /// Build a mapping of inode -> (local_addr, local_port, remote_addr, remote_port, state, protocol)
    fn build_inode_socket_map(port_filter: Option<u16>, filter: &QueryFilter) -> HashMap<u64, net::ProcNetEntry> {
        let mut map = HashMap::new();

        let should_tcp = !filter.udp || filter.tcp || (!filter.tcp && !filter.udp);
        let should_udp = !filter.tcp || filter.udp || (!filter.tcp && !filter.udp);

        if should_tcp {
            if !filter.ipv6 || (!filter.ipv4 && !filter.ipv6) {
                if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
                    for line in content.lines().skip(1) {
                        if let Some(entry) = net::parse_proc_net_tcp_line(line) {
                            if port_filter.is_none() || port_filter == Some(entry.local_port) {
                                map.insert(entry.inode, entry);
                            }
                        }
                    }
                }
            }
            if !filter.ipv4 || (!filter.ipv4 && !filter.ipv6) {
                if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
                    for line in content.lines().skip(1) {
                        if let Some(entry) = net::parse_proc_net_tcp6_line(line) {
                            if port_filter.is_none() || port_filter == Some(entry.local_port) {
                                map.insert(entry.inode, entry);
                            }
                        }
                    }
                }
            }
        }

        if should_udp {
            if !filter.ipv6 || (!filter.ipv4 && !filter.ipv6) {
                if let Ok(content) = fs::read_to_string("/proc/net/udp") {
                    for line in content.lines().skip(1) {
                        if let Some(entry) = net::parse_proc_net_udp_line(line) {
                            if port_filter.is_none() || port_filter == Some(entry.local_port) {
                                map.insert(entry.inode, entry);
                            }
                        }
                    }
                }
            }
            if !filter.ipv4 || (!filter.ipv4 && !filter.ipv6) {
                if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
                    for line in content.lines().skip(1) {
                        if let Some(entry) = net::parse_proc_net_udp6_line(line) {
                            if port_filter.is_none() || port_filter == Some(entry.local_port) {
                                map.insert(entry.inode, entry);
                            }
                        }
                    }
                }
            }
        }

        map
    }

    fn extract_socket_inode(target: &str) -> Option<u64> {
        // target looks like "socket:[12345]"
        if target.starts_with("socket:[") && target.ends_with(']') {
            target[8..target.len() - 1].parse().ok()
        } else {
            None
        }
    }
}

impl Platform for LinuxPlatform {
    fn list_pids(&self, _filter: &QueryFilter) -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        for entry in fs::read_dir("/proc").context("Failed to read /proc")? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
        Ok(pids)
    }

    fn process_info(&self, pid: u32) -> Result<ProcessInfo> {
        let name = fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_else(|_| String::from("<unknown>"))
            .trim()
            .to_string();

        let command = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let uid = Self::read_proc_uid(pid).unwrap_or(0);
        let user = Self::uid_to_username(uid);

        Ok(ProcessInfo {
            pid,
            name,
            user,
            uid,
            command: if command.is_empty() { name.clone() } else { command },
        })
    }

    fn list_open_files(&self, pid: u32) -> Result<Vec<OpenFile>> {
        let fd_dir = format!("/proc/{}/fd", pid);
        let process = self.process_info(pid)?;
        let mut results = Vec::new();

        let entries = fs::read_dir(&fd_dir)
            .with_context(|| format!("Failed to read {}", fd_dir))?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let fd: i32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
                Some(fd) => fd,
                None => continue,
            };

            let target = match fs::read_link(entry.path()) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            let deleted = target.ends_with(" (deleted)");
            let clean_path = if deleted {
                target.trim_end_matches(" (deleted)").to_string()
            } else {
                target.clone()
            };

            let fd_type = Self::classify_fd_target(&target);

            results.push(OpenFile {
                process: process.clone(),
                fd,
                fd_type,
                path: clean_path,
                deleted,
                socket_info: None,
            });
        }

        Ok(results)
    }

    fn find_by_file(&self, path: &str, filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        let canonical = fs::canonicalize(path)
            .unwrap_or_else(|_| PathBuf::from(path));
        let canonical_str = canonical.to_string_lossy().to_string();

        let pids = self.list_pids(filter)?;

        let results: Vec<OpenFile> = pids.par_iter()
            .filter_map(|&pid| {
                self.list_open_files(pid).ok()
            })
            .flatten()
            .filter(|f| {
                if let Ok(p) = fs::canonicalize(&f.path) {
                    p.to_string_lossy() == canonical_str
                } else {
                    f.path == canonical_str
                }
            })
            .collect();

        Ok(results)
    }

    fn find_by_port(&self, port: u16, filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        let inode_map = Self::build_inode_socket_map(Some(port), filter);
        if inode_map.is_empty() {
            return Ok(Vec::new());
        }

        let pids = self.list_pids(filter)?;
        let mut results = Vec::new();

        for &pid in &pids {
            let fd_dir = format!("/proc/{}/fd", pid);
            let entries = match fs::read_dir(&fd_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let target = match fs::read_link(entry.path()) {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => continue,
                };

                if let Some(inode) = Self::extract_socket_inode(&target) {
                    if let Some(net_entry) = inode_map.get(&inode) {
                        let process = match self.process_info(pid) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        // Determine protocol from the file source
                        let protocol = if net_entry.state == "UNCONN" {
                            Protocol::Udp
                        } else {
                            Protocol::Tcp
                        };

                        results.push(SocketEntry {
                            protocol,
                            local_addr: format!("{}:{}", net_entry.local_addr, net_entry.local_port),
                            remote_addr: format!("{}:{}", net_entry.remote_addr, net_entry.remote_port),
                            state: net_entry.state.clone(),
                            process,
                        });
                    }
                }
            }
        }

        Ok(results)
    }

    fn list_sockets(&self, _filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        anyhow::bail!("opn sockets: not yet implemented")
    }

    fn find_deleted(&self, _filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        anyhow::bail!("opn deleted: not yet implemented")
    }
}
