use anyhow::{Context, Result};
use rayon::prelude::*;
use std::path::Path;

use crate::model::*;
use super::Platform;

pub struct MacOsPlatform;

impl MacOsPlatform {
    pub fn new() -> Self {
        MacOsPlatform
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
}

impl Platform for MacOsPlatform {
    fn list_pids(&self, _filter: &QueryFilter) -> Result<Vec<u32>> {
        use libproc::processes::{pids_by_type, ProcFilter};
        let pids = pids_by_type(ProcFilter::All)
            .context("Failed to enumerate processes")?;
        Ok(pids)
    }

    fn process_info(&self, pid: u32) -> Result<ProcessInfo> {
        use libproc::proc_pid;

        let name = proc_pid::name(pid as i32)
            .unwrap_or_else(|_| String::from("<unknown>"));

        let command = proc_pid::pidpath(pid as i32)
            .unwrap_or_else(|_| name.clone());

        // Get UID from BSDInfo
        let (uid, user) = match proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid as i32, 0) {
            Ok(info) => {
                let uid = info.pbi_uid;
                let user = Self::uid_to_username(uid);
                (uid, user)
            }
            Err(_) => (0, String::from("<unknown>")),
        };

        Ok(ProcessInfo {
            pid,
            name,
            user,
            uid,
            command,
        })
    }

    fn list_open_files(&self, pid: u32) -> Result<Vec<OpenFile>> {
        use libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
        use libproc::net_info::SocketFDInfo;
        use libproc::proc_pid;

        let process = self.process_info(pid)?;
        let fd_list = proc_pid::listpidinfo::<ListFDs>(pid as i32, 256)
            .unwrap_or_default();

        let mut results = Vec::new();
        for fd_info in &fd_list {
            let fd = fd_info.proc_fd as i32;
            let fd_type_val = fd_info.proc_fdtype;

            let fd_type = if fd_type_val == ProcFDType::VNode as u32 {
                FdType::RegularFile
            } else if fd_type_val == ProcFDType::Socket as u32 {
                FdType::Socket
            } else if fd_type_val == ProcFDType::Pipe as u32 {
                FdType::Pipe
            } else {
                FdType::Unknown
            };

            let mut path = String::new();
            let socket_info = None;

            // For sockets, try to get socket info
            if fd_type == FdType::Socket {
                if let Ok(_sock_info) = pidfdinfo::<SocketFDInfo>(pid as i32, fd_info.proc_fd as i32) {
                    // Socket info obtained but path not applicable
                }
            }

            // For vnodes, we can't easily get the path from libproc 0.14
            // without VnodeFDInfo. The pidpath gives the executable path only.
            if fd_type == FdType::RegularFile {
                path = format!("fd:{}", fd);
            }

            results.push(OpenFile {
                process: process.clone(),
                fd,
                fd_type,
                path,
                deleted: false,
                socket_info,
            });
        }

        Ok(results)
    }

    fn find_by_file(&self, path: &str, _filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        // On macOS without VnodeFDInfo, we use lsof-style approach via
        // checking /dev/fd or using a different strategy.
        // For now, we scan all processes' pidpath to find matches.
        let canonical = std::fs::canonicalize(path)
            .unwrap_or_else(|_| Path::new(path).to_path_buf());
        let canonical_str = canonical.to_string_lossy().to_string();

        let pids = self.list_pids(&QueryFilter::default())?;

        // Check pidpath for each process — this only finds executables, not all open files
        let results: Vec<OpenFile> = pids.par_iter()
            .filter_map(|&pid| {
                use libproc::proc_pid;
                let proc_path = proc_pid::pidpath(pid as i32).ok()?;
                if let Ok(proc_canonical) = std::fs::canonicalize(&proc_path) {
                    if proc_canonical.to_string_lossy() == canonical_str {
                        let process = self.process_info(pid).ok()?;
                        return Some(OpenFile {
                            process,
                            fd: -1,
                            fd_type: FdType::RegularFile,
                            path: proc_path,
                            deleted: false,
                            socket_info: None,
                        });
                    }
                }
                None
            })
            .collect();

        if results.is_empty() {
            eprintln!("Note: On macOS, file lookup is limited to process executables.");
            eprintln!("For full open file tracking, consider using `lsof` as a fallback.");
        }

        Ok(results)
    }

    fn find_by_port(&self, port: u16, filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        use netstat2::{
            iterate_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo,
        };

        let mut af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        if filter.ipv4 && !filter.ipv6 {
            af_flags = AddressFamilyFlags::IPV4;
        } else if filter.ipv6 && !filter.ipv4 {
            af_flags = AddressFamilyFlags::IPV6;
        }

        let mut proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        if filter.tcp && !filter.udp {
            proto_flags = ProtocolFlags::TCP;
        } else if filter.udp && !filter.tcp {
            proto_flags = ProtocolFlags::UDP;
        }

        let sockets = iterate_sockets_info(af_flags, proto_flags)
            .context("Failed to iterate sockets")?;

        let mut results = Vec::new();
        for socket_result in sockets {
            let socket = match socket_result {
                Ok(s) => s,
                Err(_) => continue,
            };

            let (protocol, local_addr, local_port, remote_addr, remote_port, state) = match &socket.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    (Protocol::Tcp,
                     tcp.local_addr.to_string(),
                     tcp.local_port,
                     tcp.remote_addr.to_string(),
                     tcp.remote_port,
                     format!("{:?}", tcp.state))
                }
                ProtocolSocketInfo::Udp(udp) => {
                    (Protocol::Udp,
                     udp.local_addr.to_string(),
                     udp.local_port,
                     String::from("*"),
                     0u16,
                     String::from("-"))
                }
            };

            if local_port != port {
                continue;
            }

            for pid_info in &socket.associated_pids {
                let process = self.process_info(*pid_info)
                    .unwrap_or(ProcessInfo {
                        pid: *pid_info,
                        name: String::from("<unknown>"),
                        user: String::from("<unknown>"),
                        uid: 0,
                        command: String::new(),
                    });

                results.push(SocketEntry {
                    protocol: protocol.clone(),
                    local_addr: format!("{}:{}", local_addr, local_port),
                    remote_addr: format!("{}:{}", remote_addr, remote_port),
                    state: state.clone(),
                    process,
                });
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
