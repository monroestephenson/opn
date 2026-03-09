use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::Platform;
use crate::model::*;
use crate::net;

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        LinuxPlatform
    }

    fn uid_to_username(uid: u32) -> String {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let sys_buf_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
        let buf_len = if sys_buf_len <= 0 {
            16 * 1024
        } else {
            sys_buf_len as usize
        };
        let mut buf = vec![0_u8; buf_len];
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return uid.to_string();
        }
        unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned()
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

    fn read_proc_name(pid: u32) -> Option<String> {
        let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
        Some(comm.trim().to_string())
    }

    fn parse_proc_start_time(stat_line: &str) -> Option<u64> {
        let after_comm_idx = stat_line.rfind(") ")? + 2;
        let after_comm = &stat_line[after_comm_idx..];
        after_comm.split_whitespace().nth(19)?.parse().ok()
    }

    fn read_proc_start_time(pid: u32) -> Option<u64> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
        Self::parse_proc_start_time(&stat)
    }

    fn process_is_stable(pid: u32, expected_start_time: u64) -> bool {
        Self::read_proc_start_time(pid) == Some(expected_start_time)
    }

    fn current_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn warn_if_parse_issues(path: &str, result: &net::ProcNetParseResult) {
        if !result.header_valid {
            eprintln!(
                "warning: {} has an unexpected header format — \
                 socket data may be incomplete or incorrect",
                path
            );
        }
        if result.failed_lines > 0 {
            eprintln!(
                "warning: {} line(s) in {} could not be parsed and were skipped",
                result.failed_lines, path
            );
        }
    }

    fn classify_fd_target(target: &str) -> FdType {
        if target.starts_with("socket:[") {
            FdType::Socket
        } else if target.starts_with("pipe:[") {
            FdType::Pipe
        } else if target.starts_with("anon_inode:") {
            FdType::Unknown
        } else if target.starts_with("/dev/") {
            FdType::Device
        } else if Path::new(target).is_dir() {
            FdType::Directory
        } else {
            FdType::RegularFile
        }
    }

    /// Build a mapping of inode -> (local_addr, local_port, remote_addr, remote_port, state, protocol)
    fn build_inode_socket_map(
        port_filter: Option<u16>,
        filter: &QueryFilter,
    ) -> HashMap<u64, net::ProcNetEntry> {
        let mut map = HashMap::new();

        let should_tcp = !filter.udp || filter.tcp;
        let should_udp = !filter.tcp || filter.udp;
        let want_v4 = !filter.ipv6;
        let want_v6 = !filter.ipv4;

        if should_tcp {
            if want_v4 {
                if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
                    let result = net::parse_proc_net_tcp(&content);
                    Self::warn_if_parse_issues("/proc/net/tcp", &result);
                    for entry in result.entries {
                        if port_filter.is_none() || port_filter == Some(entry.local_port) {
                            map.insert(entry.inode, entry);
                        }
                    }
                }
            }
            if want_v6 {
                if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
                    let result = net::parse_proc_net_tcp6(&content);
                    Self::warn_if_parse_issues("/proc/net/tcp6", &result);
                    for entry in result.entries {
                        if port_filter.is_none() || port_filter == Some(entry.local_port) {
                            map.insert(entry.inode, entry);
                        }
                    }
                }
            }
        }

        if should_udp {
            if want_v4 {
                if let Ok(content) = fs::read_to_string("/proc/net/udp") {
                    let result = net::parse_proc_net_udp(&content);
                    Self::warn_if_parse_issues("/proc/net/udp", &result);
                    for entry in result.entries {
                        if port_filter.is_none() || port_filter == Some(entry.local_port) {
                            map.insert(entry.inode, entry);
                        }
                    }
                }
            }
            if want_v6 {
                if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
                    let result = net::parse_proc_net_udp6(&content);
                    Self::warn_if_parse_issues("/proc/net/udp6", &result);
                    for entry in result.entries {
                        if port_filter.is_none() || port_filter == Some(entry.local_port) {
                            map.insert(entry.inode, entry);
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

    fn matches_process_filter(process: &ProcessInfo, filter: &QueryFilter) -> bool {
        if let Some(filter_pid) = filter.pid {
            if process.pid != filter_pid {
                return false;
            }
        }
        if let Some(user) = &filter.user {
            if process.user != *user {
                return false;
            }
        }
        if let Some(process_name) = &filter.process_name {
            if process.name != *process_name {
                return false;
            }
        }
        true
    }

    fn collect_sockets(
        &self,
        port_filter: Option<u16>,
        filter: &QueryFilter,
    ) -> Result<Vec<SocketEntry>> {
        let inode_map = Self::build_inode_socket_map(port_filter, filter);
        if inode_map.is_empty() {
            return Ok(Vec::new());
        }

        let pids = self.list_pids(filter)?;
        let mut results = Vec::new();

        for pid in pids {
            let Some(start_time) = Self::read_proc_start_time(pid) else {
                continue;
            };
            let process = match self.process_info(pid) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !Self::process_is_stable(pid, start_time) {
                continue;
            }
            if !Self::matches_process_filter(&process, filter) {
                continue;
            }

            let process = Arc::new(process);
            let fd_dir = format!("/proc/{}/fd", pid);
            let entries = match fs::read_dir(&fd_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let mut pid_seen = HashSet::<u64>::new();
            let mut pid_results = Vec::new();

            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let target = match fs::read_link(entry.path()) {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => continue,
                };

                let Some(inode) = Self::extract_socket_inode(&target) else {
                    continue;
                };
                let Some(net_entry) = inode_map.get(&inode) else {
                    continue;
                };
                if !pid_seen.insert(inode) {
                    continue;
                }
                if let Some(state) = &filter.state {
                    if !net_entry.state.eq_ignore_ascii_case(state) {
                        continue;
                    }
                }

                pid_results.push(SocketEntry {
                    protocol: net_entry.protocol.clone(),
                    local_addr: format!("{}:{}", net_entry.local_addr, net_entry.local_port),
                    remote_addr: format!("{}:{}", net_entry.remote_addr, net_entry.remote_port),
                    state: net_entry.state.clone(),
                    process: process.clone(),
                });
            }

            if Self::process_is_stable(pid, start_time) {
                results.extend(pid_results);
            }
        }

        Ok(results)
    }
}

impl Platform for LinuxPlatform {
    fn list_pids(&self, filter: &QueryFilter) -> Result<Vec<u32>> {
        let mut pids = Vec::new();
        for entry in fs::read_dir("/proc").context("Failed to read /proc")? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    if let Some(filter_pid) = filter.pid {
                        if pid != filter_pid {
                            continue;
                        }
                    }
                    if !filter.all && filter.user.is_none() {
                        let uid = match Self::read_proc_uid(pid) {
                            Some(v) => v,
                            None => continue,
                        };
                        if uid != Self::current_uid() {
                            continue;
                        }
                    }
                    if let Some(filter_user) = &filter.user {
                        let uid = match Self::read_proc_uid(pid) {
                            Some(v) => v,
                            None => continue,
                        };
                        let user = Self::uid_to_username(uid);
                        if &user != filter_user {
                            continue;
                        }
                    }
                    if let Some(filter_process) = &filter.process_name {
                        let proc_name = match Self::read_proc_name(pid) {
                            Some(v) => v,
                            None => continue,
                        };
                        if &proc_name != filter_process {
                            continue;
                        }
                    }
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
        let display_command = if command.is_empty() {
            name.clone()
        } else {
            command
        };

        Ok(ProcessInfo {
            pid,
            name,
            user,
            uid,
            command: display_command,
        })
    }

    fn list_open_files(&self, pid: u32) -> Result<Vec<OpenFile>> {
        let start_time =
            Self::read_proc_start_time(pid).with_context(|| format!("PID {} not found", pid))?;
        let fd_dir = format!("/proc/{}/fd", pid);
        let process = Arc::new(self.process_info(pid)?);
        if !Self::process_is_stable(pid, start_time) {
            bail!("PID {} changed during inspection", pid);
        }
        let mut results = Vec::new();

        let entries =
            fs::read_dir(&fd_dir).with_context(|| format!("Failed to read {}", fd_dir))?;

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
                fd: Some(fd),
                fd_type,
                path: clean_path,
                deleted,
                socket_info: None,
            });
        }

        if !Self::process_is_stable(pid, start_time) {
            bail!("PID {} changed during inspection", pid);
        }

        Ok(results)
    }

    fn find_by_file(&self, path: &str, filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        let canonical = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
        let canonical_str = canonical.to_string_lossy().to_string();

        let pids = self.list_pids(filter)?;

        let results: Vec<OpenFile> = pids
            .par_iter()
            .filter_map(|&pid| self.list_open_files(pid).ok())
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
        self.collect_sockets(Some(port), filter)
    }

    fn list_sockets(&self, filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        self.collect_sockets(None, filter)
    }

    fn find_deleted(&self, filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        let pids = self.list_pids(filter)?;
        let mut results = Vec::new();

        for pid in pids {
            if let Some(filter_pid) = filter.pid {
                if pid != filter_pid {
                    continue;
                }
            }

            let files = match self.list_open_files(pid) {
                Ok(f) => f,
                Err(_) => continue,
            };

            for file in files {
                if !file.deleted {
                    continue;
                }
                if let Some(user) = &filter.user {
                    if file.process.user != *user {
                        continue;
                    }
                }
                if let Some(process_name) = &filter.process_name {
                    if file.process.name != *process_name {
                        continue;
                    }
                }
                results.push(file);
            }
        }

        Ok(results)
    }

    fn kill_process(&self, pid: u32, signal: KillSignal) -> Result<()> {
        let ret = unsafe { libc::kill(pid as i32, signal.as_libc()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("Failed to send SIG{} to pid {}: {}", signal, pid, err);
        }
        Ok(())
    }

    fn process_ancestry(&self, pid: u32) -> Result<Vec<ProcessAncestor>> {
        let mut ancestors = Vec::new();
        let mut current_pid = pid;
        for _ in 0..16 {
            let status_path = format!("/proc/{}/status", current_pid);
            let status = match fs::read_to_string(&status_path) {
                Ok(s) => s,
                Err(_) => break,
            };
            let ppid: u32 = status
                .lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            if ppid == 0 || ppid == current_pid {
                break;
            }
            let name = Self::read_proc_name(ppid).unwrap_or_else(|| String::from("<unknown>"));
            ancestors.push(ProcessAncestor { pid: ppid, name });
            current_pid = ppid;
        }
        ancestors.reverse();
        Ok(ancestors)
    }

    fn interface_stats(&self) -> Result<Vec<InterfaceStats>> {
        let content =
            fs::read_to_string("/proc/net/dev").context("Failed to read /proc/net/dev")?;
        let mut results = Vec::new();
        for line in content.lines().skip(2) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (iface, rest) = match line.split_once(':') {
                Some(v) => v,
                None => continue,
            };
            let iface = iface.trim().to_string();
            let cols: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            // /proc/net/dev columns after iface:
            // rx: bytes packets errs drop fifo frame compressed multicast
            // tx: bytes packets errs drop fifo colls carrier compressed
            if cols.len() < 16 {
                continue;
            }
            results.push(InterfaceStats {
                name: iface,
                rx_bytes: cols[0],
                rx_packets: cols[1],
                rx_errors: cols[2],
                rx_drop: cols[3],
                tx_bytes: cols[8],
                tx_packets: cols[9],
                tx_errors: cols[10],
                tx_drop: cols[11],
            });
        }
        Ok(results)
    }

    fn tcp_metrics(&self) -> Result<Option<TcpMetrics>> {
        let content =
            fs::read_to_string("/proc/net/snmp").context("Failed to read /proc/net/snmp")?;
        // Find the two "Tcp:" lines (header then values)
        let mut tcp_header: Option<Vec<String>> = None;
        let mut tcp_values: Option<Vec<u64>> = None;
        for line in content.lines() {
            if line.starts_with("Tcp:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() < 2 {
                    continue;
                }
                let fields: Vec<String> =
                    parts[1].split_whitespace().map(|s| s.to_string()).collect();
                if tcp_header.is_none() {
                    tcp_header = Some(fields);
                } else {
                    tcp_values = Some(
                        fields
                            .iter()
                            .filter_map(|s| s.parse::<u64>().ok())
                            .collect(),
                    );
                    break;
                }
            }
        }
        let (Some(header), Some(values)) = (tcp_header, tcp_values) else {
            return Ok(None);
        };

        fn get_val(header: &[String], values: &[u64], key: &str) -> u64 {
            header
                .iter()
                .position(|h| h == key)
                .and_then(|i| values.get(i))
                .copied()
                .unwrap_or(0)
        }

        // Also check IcmpMsg / Ip section for SyncookiesSent — it's actually in
        // /proc/net/netstat, not /proc/net/snmp. We try netstat for SyncookiesSent.
        let syn_cookies_sent = {
            let netstat_content = fs::read_to_string("/proc/net/netstat").unwrap_or_default();
            let mut hdr: Option<Vec<String>> = None;
            let mut val: Option<Vec<u64>> = None;
            for line in netstat_content.lines() {
                if line.starts_with("TcpExt:") {
                    let parts: Vec<&str> = line.splitn(2, ':').collect();
                    if parts.len() < 2 {
                        continue;
                    }
                    let fields: Vec<String> =
                        parts[1].split_whitespace().map(|s| s.to_string()).collect();
                    if hdr.is_none() {
                        hdr = Some(fields);
                    } else {
                        val = Some(
                            fields
                                .iter()
                                .filter_map(|s| s.parse::<u64>().ok())
                                .collect(),
                        );
                        break;
                    }
                }
            }
            if let (Some(h), Some(v)) = (hdr, val) {
                h.iter()
                    .position(|x| x == "SyncookiesSent")
                    .and_then(|i| v.get(i))
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            }
        };

        Ok(Some(TcpMetrics {
            retrans: get_val(&header, &values, "RetransSegs"),
            syn_cookies_sent,
            active_opens: get_val(&header, &values, "ActiveOpens"),
            passive_opens: get_val(&header, &values, "PassiveOpens"),
            attempt_fails: get_val(&header, &values, "AttemptFails"),
            estab_resets: get_val(&header, &values, "EstabResets"),
            curr_estab: get_val(&header, &values, "CurrEstab"),
        }))
    }

    fn process_resources(&self, pid: u32) -> Result<ProcessResources> {
        // Parse /proc/[pid]/status for memory and threads
        let status =
            fs::read_to_string(format!("/proc/{}/status", pid)).context("process not found")?;

        let mut mem_rss_kb: u64 = 0;
        let mut mem_vms_kb: u64 = 0;
        let mut threads: u32 = 0;

        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                mem_rss_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                mem_vms_kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                threads = rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }

        // Count open FDs
        let open_fds = fs::read_dir(format!("/proc/{}/fd", pid))
            .map(|rd| rd.filter(|e| e.is_ok()).count() as u32)
            .unwrap_or(0);

        // Measure CPU usage: read utime+stime at T1, sleep 100ms, read at T2
        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let clk_tck = if clk_tck <= 0 { 100 } else { clk_tck as u64 };

        fn read_cpu_ticks(pid: u32) -> Option<u64> {
            let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
            // Fields are after the comm (process name in parens)
            let after_comm = stat.rfind(") ")? + 2;
            let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
            // utime is field index 11 (after_comm field 11), stime is 12
            // (0-indexed from after_comm: field[11]=utime, field[12]=stime, where first field after ')' is state=0)
            let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
            let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
            Some(utime + stime)
        }

        let t1_ticks = read_cpu_ticks(pid).unwrap_or(0);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let t2_ticks = read_cpu_ticks(pid).unwrap_or(0);

        let delta = t2_ticks.saturating_sub(t1_ticks);
        let cpu_pct = (delta as f64 / (0.1 * clk_tck as f64)) * 100.0;

        Ok(ProcessResources {
            pid,
            cpu_pct,
            mem_rss_kb,
            mem_vms_kb,
            open_fds,
            threads,
        })
    }

    fn net_config(&self) -> Result<NetConfig> {
        // Routes: parse /proc/net/route (hex, little-endian IPv4)
        let routes = {
            let content = fs::read_to_string("/proc/net/route").unwrap_or_default();
            let mut routes = Vec::new();
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 8 {
                    continue;
                }
                let iface = cols[0].to_string();
                // Destination and Gateway are hex little-endian u32
                let dst_hex = u32::from_str_radix(cols[1], 16).unwrap_or(0);
                let gw_hex = u32::from_str_radix(cols[2], 16).unwrap_or(0);
                let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
                let mask_hex = u32::from_str_radix(cols[7], 16).unwrap_or(0);
                let metric: u32 = cols[6].parse().unwrap_or(0);

                // RTF_UP = 0x1, RTF_GATEWAY = 0x2
                if (flags & 0x1) == 0 {
                    continue; // skip non-UP routes
                }

                let dst_ip = std::net::Ipv4Addr::from(dst_hex.swap_bytes());
                let gw_ip = std::net::Ipv4Addr::from(gw_hex.swap_bytes());
                let prefix = mask_hex.swap_bytes().count_ones();

                let destination = if dst_hex == 0 {
                    String::from("default")
                } else {
                    format!("{}/{}", dst_ip, prefix)
                };
                let gateway = if gw_hex == 0 {
                    String::from("*")
                } else {
                    gw_ip.to_string()
                };
                let mut flag_str = String::from("U");
                if (flags & 0x2) != 0 {
                    flag_str.push('G');
                }

                routes.push(crate::model::RouteEntry {
                    destination,
                    gateway,
                    interface: iface,
                    flags: flag_str,
                    metric,
                });
            }
            routes
        };

        // DNS: parse /etc/resolv.conf
        let (dns_servers, dns_search) = {
            let content = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            let mut servers = Vec::new();
            let mut search = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("nameserver") {
                    if let Some(s) = rest.split_whitespace().next() {
                        servers.push(s.to_string());
                    }
                } else if let Some(rest) = line.strip_prefix("search") {
                    for s in rest.split_whitespace() {
                        search.push(s.to_string());
                    }
                }
            }
            (servers, search)
        };

        // Hostname: /etc/hostname fallback to gethostname(2)
        let hostname = {
            let from_file = fs::read_to_string("/etc/hostname")
                .unwrap_or_default()
                .trim()
                .to_string();
            if !from_file.is_empty() {
                from_file
            } else {
                let mut buf = vec![0u8; 256];
                let ret =
                    unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
                if ret == 0 {
                    let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
                    String::from_utf8_lossy(&buf[..nul]).into_owned()
                } else {
                    String::new()
                }
            }
        };

        // Interface addresses via getifaddrs(3)
        let interfaces = {
            use std::collections::BTreeMap;
            let mut iface_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

            unsafe {
                let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
                if libc::getifaddrs(&mut ifap) == 0 {
                    let mut ifa = ifap;
                    while !ifa.is_null() {
                        let ifa_ref = &*ifa;
                        ifa = ifa_ref.ifa_next;

                        if ifa_ref.ifa_name.is_null() || ifa_ref.ifa_addr.is_null() {
                            continue;
                        }
                        let name = std::ffi::CStr::from_ptr(ifa_ref.ifa_name)
                            .to_string_lossy()
                            .into_owned();
                        iface_map.entry(name.clone()).or_default();

                        let sa_family = (*ifa_ref.ifa_addr).sa_family as libc::c_int;
                        if sa_family == libc::AF_INET {
                            let sin = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in);
                            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            let prefix = if !ifa_ref.ifa_netmask.is_null() {
                                let mask = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in);
                                u32::from_be(mask.sin_addr.s_addr).count_ones()
                            } else {
                                32
                            };
                            iface_map
                                .entry(name)
                                .or_default()
                                .push(format!("{}/{}", ip, prefix));
                        } else if sa_family == libc::AF_INET6 {
                            let sin6 = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in6);
                            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                            let prefix = if !ifa_ref.ifa_netmask.is_null() {
                                let mask = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in6);
                                mask.sin6_addr
                                    .s6_addr
                                    .iter()
                                    .map(|b| b.count_ones())
                                    .sum::<u32>()
                            } else {
                                128
                            };
                            iface_map
                                .entry(name)
                                .or_default()
                                .push(format!("{}/{}", ip, prefix));
                        }
                    }
                    libc::freeifaddrs(ifap);
                }
            }

            iface_map
                .into_iter()
                .map(|(name, addrs)| crate::model::InterfaceAddr { name, addrs })
                .collect()
        };

        Ok(crate::model::NetConfig {
            routes,
            dns_servers,
            dns_search,
            hostname,
            interfaces,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::LinuxPlatform;

    #[test]
    fn test_parse_proc_start_time_parses_expected_field() {
        let stat =
            "12345 (nginx worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 21 22";
        assert_eq!(LinuxPlatform::parse_proc_start_time(stat), Some(987654));
    }

    #[test]
    fn test_parse_proc_start_time_rejects_invalid_line() {
        assert_eq!(LinuxPlatform::parse_proc_start_time("1234 invalid"), None);
    }
}
