use anyhow::{Context, Result};
use rayon::prelude::*;
use std::path::Path;
use std::sync::Arc;

use super::Platform;
use crate::model::*;

// ── Raw FFI for proc_pidfdvnodeinfo (bypasses libproc 0.14 limitation) ──

const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2; // PIDFDInfoFlavor::VNodePathInfo

#[repr(C)]
#[derive(Copy, Clone)]
struct vinfo_stat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct fsid_t {
    val: [i32; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct vnode_info {
    vi_stat: vinfo_stat,
    vi_type: libc::c_int,
    vi_pad: libc::c_int,
    vi_fsid: fsid_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct vnode_info_path {
    vip_vi: vnode_info,
    vip_path: [libc::c_char; 1024],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct proc_fileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct vnode_fdinfowithpath {
    pfi: proc_fileinfo,
    pvip: vnode_info_path,
}

extern "C" {
    fn proc_pidfdinfo(
        pid: libc::c_int,
        fd: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

#[derive(Debug, Clone)]
struct VnodeFdInfo {
    path: String,
    nlink: u16,
    mode: u16,
}

fn parse_c_char_buf(buf: &[libc::c_char]) -> Option<String> {
    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len()) };
    let nul_idx = bytes.iter().position(|b| *b == 0)?;
    if nul_idx == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..nul_idx]).into_owned())
}

/// Get vnode path metadata for an FD using raw FFI to proc_pidfdinfo.
fn get_vnode_fd_info(pid: i32, fd: i32) -> Option<VnodeFdInfo> {
    unsafe {
        let mut info: vnode_fdinfowithpath = std::mem::zeroed();
        let size = std::mem::size_of::<vnode_fdinfowithpath>() as libc::c_int;
        let ret = proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            &mut info as *mut _ as *mut libc::c_void,
            size,
        );
        if ret <= 0 {
            return None;
        }
        let path = parse_c_char_buf(&info.pvip.vip_path)?;
        Some(VnodeFdInfo {
            path,
            nlink: info.pvip.vip_vi.vi_stat.vst_nlink,
            mode: info.pvip.vip_vi.vi_stat.vst_mode,
        })
    }
}

// ── MacOsPlatform ──

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

    fn matches_process_filter(process: &ProcessInfo, filter: &QueryFilter) -> bool {
        if let Some(filter_pid) = filter.pid {
            if process.pid != filter_pid {
                return false;
            }
        }
        if let Some(ref user) = filter.user {
            if &process.user != user {
                return false;
            }
        }
        if let Some(ref name) = filter.process_name {
            if &process.name != name {
                return false;
            }
        }
        true
    }

    fn current_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn classify_vnode_mode(mode: u16) -> FdType {
        let file_type = (mode as libc::mode_t) & libc::S_IFMT;
        if file_type == libc::S_IFDIR {
            FdType::Directory
        } else if file_type == libc::S_IFCHR || file_type == libc::S_IFBLK {
            FdType::Device
        } else {
            FdType::RegularFile
        }
    }

    fn collect_sockets(
        &self,
        filter: &QueryFilter,
        port_filter: Option<u16>,
    ) -> Result<Vec<SocketEntry>> {
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

        let sockets =
            iterate_sockets_info(af_flags, proto_flags).context("Failed to iterate sockets")?;

        let mut results = Vec::new();
        for socket_result in sockets {
            let socket = match socket_result {
                Ok(s) => s,
                Err(_) => continue,
            };

            let (protocol, local_addr, local_port, remote_addr, remote_port, state) =
                match &socket.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(tcp) => (
                        Protocol::Tcp,
                        tcp.local_addr.to_string(),
                        tcp.local_port,
                        tcp.remote_addr.to_string(),
                        tcp.remote_port,
                        format!("{:?}", tcp.state),
                    ),
                    ProtocolSocketInfo::Udp(udp) => (
                        Protocol::Udp,
                        udp.local_addr.to_string(),
                        udp.local_port,
                        String::from("*"),
                        0u16,
                        String::from("-"),
                    ),
                };

            if let Some(port) = port_filter {
                if local_port != port {
                    continue;
                }
            }
            if let Some(state_filter) = &filter.state {
                if !state.eq_ignore_ascii_case(state_filter) {
                    continue;
                }
            }

            for pid_info in &socket.associated_pids {
                let process = self.process_info(*pid_info).unwrap_or(ProcessInfo {
                    pid: *pid_info,
                    name: String::from("<unknown>"),
                    user: String::from("<unknown>"),
                    uid: 0,
                    command: String::new(),
                });
                if !Self::matches_process_filter(&process, filter) {
                    continue;
                }

                results.push(SocketEntry {
                    protocol: protocol.clone(),
                    local_addr: format!("{}:{}", local_addr, local_port),
                    remote_addr: format!("{}:{}", remote_addr, remote_port),
                    state: state.clone(),
                    process: Arc::new(process),
                });
            }
        }

        Ok(results)
    }
}

impl Platform for MacOsPlatform {
    fn list_pids(&self, filter: &QueryFilter) -> Result<Vec<u32>> {
        use libproc::proc_pid;
        use libproc::processes::{pids_by_type, ProcFilter};
        let mut pids = pids_by_type(ProcFilter::All).context("Failed to enumerate processes")?;
        if let Some(pid) = filter.pid {
            pids.retain(|p| *p == pid);
        }
        if !filter.all && filter.user.is_none() {
            let uid = Self::current_uid();
            pids.retain(|p| {
                proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(*p as i32, 0)
                    .map(|info| info.pbi_uid == uid)
                    .unwrap_or(false)
            });
        }
        Ok(pids)
    }

    fn process_info(&self, pid: u32) -> Result<ProcessInfo> {
        use libproc::proc_pid;

        let name = proc_pid::name(pid as i32).unwrap_or_else(|_| String::from("<unknown>"));

        let command = proc_pid::pidpath(pid as i32).unwrap_or_else(|_| name.clone());

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
        use libproc::file_info::{ListFDs, ProcFDType};
        use libproc::proc_pid;

        let process = Arc::new(self.process_info(pid)?);
        let fd_list = proc_pid::listpidinfo::<ListFDs>(pid as i32, 256).unwrap_or_default();

        let mut results = Vec::new();
        for fd_info in &fd_list {
            let fd = fd_info.proc_fd;
            let fd_type_val = fd_info.proc_fdtype;

            let mut fd_type = if fd_type_val == ProcFDType::VNode as u32 {
                FdType::RegularFile
            } else if fd_type_val == ProcFDType::Socket as u32 {
                FdType::Socket
            } else if fd_type_val == ProcFDType::Pipe as u32 {
                FdType::Pipe
            } else {
                FdType::Unknown
            };

            let mut path = String::new();
            let mut deleted = false;

            if fd_type == FdType::RegularFile {
                if let Some(vnode_info) = get_vnode_fd_info(pid as i32, fd) {
                    deleted = vnode_info.nlink == 0;
                    fd_type = Self::classify_vnode_mode(vnode_info.mode);
                    path = vnode_info.path;
                } else {
                    path = String::from("<path unavailable>");
                }
            }

            results.push(OpenFile {
                process: process.clone(),
                fd: Some(fd),
                fd_type,
                path,
                deleted,
                socket_info: None,
            });
        }

        Ok(results)
    }

    fn find_by_file(&self, path: &str, filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        use libproc::file_info::{ListFDs, ProcFDType};
        use libproc::proc_pid;

        let canonical =
            std::fs::canonicalize(path).unwrap_or_else(|_| Path::new(path).to_path_buf());
        let canonical_str = canonical.to_string_lossy().to_string();

        // Pass `all` through so we scan other users' PIDs when requested.
        let pids_filter = QueryFilter {
            all: filter.all,
            ..QueryFilter::default()
        };
        let pids = self.list_pids(&pids_filter)?;

        let results: Vec<OpenFile> = pids
            .par_iter()
            .flat_map(|&pid| {
                let process = match self.process_info(pid) {
                    Ok(p) => p,
                    Err(_) => return vec![],
                };
                if !Self::matches_process_filter(&process, filter) {
                    return vec![];
                }

                let process = Arc::new(process);
                let fd_list = proc_pid::listpidinfo::<ListFDs>(pid as i32, 256).unwrap_or_default();

                // Scan all vnode FDs for the target path.
                let mut matches: Vec<OpenFile> = fd_list
                    .iter()
                    .filter(|fi| fi.proc_fdtype == ProcFDType::VNode as u32)
                    .filter_map(|fi| {
                        let vnode_info = get_vnode_fd_info(pid as i32, fi.proc_fd)?;
                        let path_matches = if let Ok(vc) = std::fs::canonicalize(&vnode_info.path) {
                            vc.to_string_lossy() == canonical_str
                        } else {
                            vnode_info.path == canonical_str
                        };
                        if !path_matches {
                            return None;
                        }
                        Some(OpenFile {
                            process: process.clone(),
                            fd: Some(fi.proc_fd),
                            fd_type: FdType::RegularFile,
                            path: vnode_info.path,
                            deleted: vnode_info.nlink == 0,
                            socket_info: None,
                        })
                    })
                    .collect();

                // If no FD matched, fall back to executable-path matching
                // (the binary's text segment is mmap'd, not an open FD).
                if matches.is_empty() {
                    if let Ok(proc_path) = proc_pid::pidpath(pid as i32) {
                        let exec_matches = if let Ok(ec) = std::fs::canonicalize(&proc_path) {
                            ec.to_string_lossy() == canonical_str
                        } else {
                            proc_path == canonical_str
                        };
                        if exec_matches {
                            matches.push(OpenFile {
                                process: process.clone(),
                                fd: None,
                                fd_type: FdType::RegularFile,
                                path: proc_path,
                                deleted: false,
                                socket_info: None,
                            });
                        }
                    }
                }

                matches
            })
            .collect();

        Ok(results)
    }

    fn find_by_port(&self, port: u16, filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        self.collect_sockets(filter, Some(port))
    }

    fn list_sockets(&self, filter: &QueryFilter) -> Result<Vec<SocketEntry>> {
        self.collect_sockets(filter, None)
    }

    fn find_deleted(&self, filter: &QueryFilter) -> Result<Vec<OpenFile>> {
        use libproc::file_info::{ListFDs, ProcFDType};
        use libproc::proc_pid;

        let pids_filter = QueryFilter {
            all: filter.all,
            ..QueryFilter::default()
        };
        let pids = self.list_pids(&pids_filter)?;

        let results: Vec<OpenFile> = pids
            .par_iter()
            .flat_map(|&pid| {
                let process = match self.process_info(pid) {
                    Ok(p) => p,
                    Err(_) => return vec![],
                };
                if !Self::matches_process_filter(&process, filter) {
                    return vec![];
                }

                let process = Arc::new(process);
                let fd_list = proc_pid::listpidinfo::<ListFDs>(pid as i32, 256).unwrap_or_default();

                fd_list
                    .iter()
                    .filter(|fi| fi.proc_fdtype == ProcFDType::VNode as u32)
                    .filter_map(|fi| {
                        let vnode_info = get_vnode_fd_info(pid as i32, fi.proc_fd)?;
                        if vnode_info.nlink == 0 {
                            Some(OpenFile {
                                process: process.clone(),
                                fd: Some(fi.proc_fd),
                                fd_type: FdType::RegularFile,
                                path: vnode_info.path,
                                deleted: true,
                                socket_info: None,
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .collect();

        Ok(results)
    }
}
