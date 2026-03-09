use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashSet;
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

// ── getifaddrs-based interface address listing ──

fn macos_net_config_interfaces() -> Vec<crate::model::InterfaceAddr> {
    use std::collections::BTreeMap;
    let mut iface_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return vec![];
        }

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
                // Compute prefix from netmask
                let prefix = if !ifa_ref.ifa_netmask.is_null() {
                    let mask_sin = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in);
                    u32::from_be(mask_sin.sin_addr.s_addr).count_ones()
                } else {
                    32
                };
                iface_map
                    .entry(name)
                    .or_default()
                    .push(format!("{}/{}", ip, prefix));
            } else if sa_family == libc::AF_INET6 {
                let sin6 = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in6);
                let bytes = sin6.sin6_addr.s6_addr;
                let ip = std::net::Ipv6Addr::from(bytes);
                let prefix = if !ifa_ref.ifa_netmask.is_null() {
                    let mask_sin6 = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in6);
                    mask_sin6
                        .sin6_addr
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

    iface_map
        .into_iter()
        .map(|(name, addrs)| crate::model::InterfaceAddr { name, addrs })
        .collect()
}

// ── sysctl(NET_RT_DUMP)-based routing table ──

fn macos_net_config_routes() -> Vec<crate::model::RouteEntry> {
    // Round address length up to 4-byte boundary (BSD ROUNDUP macro)
    fn roundup(len: usize) -> usize {
        if len == 0 {
            4
        } else {
            (len + 3) & !3
        }
    }

    // Format a sockaddr as an IP string (AF_INET only for now)
    fn sa_to_str(ptr: *const u8) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        unsafe {
            let sa_len = *ptr as usize;
            let sa_family = *ptr.add(1) as libc::c_int;
            if sa_family == libc::AF_INET && sa_len >= 8 {
                let sa = &*(ptr as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                Some(ip.to_string())
            } else {
                None
            }
        }
    }

    let mut routes = Vec::new();

    unsafe {
        let mib: [libc::c_int; 6] = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET as libc::c_int,
            libc::NET_RT_DUMP,
            0,
        ];
        let mut needed: libc::size_t = 0;
        if libc::sysctl(
            mib.as_ptr() as *mut _,
            6,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        ) != 0
            || needed == 0
        {
            return routes;
        }

        let mut buf = vec![0u8; needed];
        if libc::sysctl(
            mib.as_ptr() as *mut _,
            6,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut needed,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return routes;
        }

        let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
        let mut offset = 0usize;

        while offset + hdr_size <= needed {
            let hdr = &*(buf.as_ptr().add(offset) as *const libc::rt_msghdr);
            let msg_len = hdr.rtm_msglen as usize;
            if msg_len < hdr_size || offset + msg_len > needed {
                break;
            }

            // Only care about RTM_GET routes that are UP
            let rtm_up = libc::RTF_UP;
            if (hdr.rtm_flags & rtm_up) != 0 {
                let addrs_bits = hdr.rtm_addrs;
                let flags = hdr.rtm_flags;

                // Walk sockaddrs after the header
                let mut sa_ptr = buf.as_ptr().add(offset + hdr_size);
                let end_ptr = buf.as_ptr().add(offset + msg_len);

                // Resolve interface name from rtm_index (simpler than parsing RTA_IFP)
                let interface = {
                    let mut name_buf = [0u8; libc::IF_NAMESIZE];
                    let ret = libc::if_indextoname(
                        hdr.rtm_index as libc::c_uint,
                        name_buf.as_mut_ptr() as *mut libc::c_char,
                    );
                    if ret.is_null() {
                        String::new()
                    } else {
                        let nul = name_buf.iter().position(|b| *b == 0).unwrap_or(name_buf.len());
                        String::from_utf8_lossy(&name_buf[..nul]).into_owned()
                    }
                };

                let mut dst_str: Option<String> = None;
                let mut gw_str: Option<String> = None;
                let mut mask_bits: u32 = 32;

                for bit in 0..8 {
                    if sa_ptr >= end_ptr {
                        break;
                    }
                    if (addrs_bits & (1 << bit)) == 0 {
                        continue;
                    }
                    let sa_len = (*sa_ptr) as usize;
                    let advance = roundup(if sa_len == 0 { 4 } else { sa_len });

                    match bit {
                        0 => dst_str = sa_to_str(sa_ptr), // RTA_DST
                        1 => gw_str = sa_to_str(sa_ptr),  // RTA_GATEWAY
                        2 => {
                            // RTA_NETMASK — compute prefix length
                            if sa_len >= 8 {
                                let sa = &*(sa_ptr as *const libc::sockaddr_in);
                                mask_bits = u32::from_be(sa.sin_addr.s_addr).count_ones();
                            } else if sa_len == 0 {
                                mask_bits = 0; // default route
                            }
                        }
                        _ => {}
                    }

                    sa_ptr = sa_ptr.add(advance);
                }

                if let Some(dst) = dst_str {
                    let destination = if (flags & libc::RTF_HOST) != 0 {
                        format!("{}/32", dst)
                    } else if dst == "0.0.0.0" {
                        String::from("default")
                    } else {
                        format!("{}/{}", dst, mask_bits)
                    };
                    let gateway = gw_str.unwrap_or_else(|| String::from("*"));
                    let mut flag_str = String::new();
                    if (flags & libc::RTF_UP) != 0 {
                        flag_str.push('U');
                    }
                    if (flags & libc::RTF_GATEWAY) != 0 {
                        flag_str.push('G');
                    }
                    if (flags & libc::RTF_HOST) != 0 {
                        flag_str.push('H');
                    }
                    routes.push(crate::model::RouteEntry {
                        destination,
                        gateway,
                        flags: flag_str,
                        interface,
                        metric: 0,
                    });
                }
            }

            offset += msg_len;
        }
    }

    routes
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

    fn kill_process(&self, pid: u32, signal: KillSignal) -> Result<()> {
        let ret = unsafe { libc::kill(pid as i32, signal.as_libc()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("Failed to send SIG{} to pid {}: {}", signal, pid, err);
        }
        Ok(())
    }

    fn process_ancestry(&self, pid: u32) -> Result<Vec<ProcessAncestor>> {
        use libproc::bsd_info::BSDInfo;
        use libproc::proc_pid;

        let mut ancestors = Vec::new();
        let mut current_pid = pid;
        for _ in 0..16 {
            let info = match proc_pid::pidinfo::<BSDInfo>(current_pid as i32, 0) {
                Ok(i) => i,
                Err(_) => break,
            };
            let ppid = info.pbi_ppid;
            if ppid == 0 || ppid == current_pid {
                break;
            }
            let name = proc_pid::name(ppid as i32).unwrap_or_else(|_| String::from("<unknown>"));
            ancestors.push(ProcessAncestor { pid: ppid, name });
            current_pid = ppid;
        }
        ancestors.reverse();
        Ok(ancestors)
    }

    fn interface_stats(&self) -> Result<Vec<InterfaceStats>> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return Err(anyhow::anyhow!(
                    "getifaddrs failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let mut ifa = ifap;
            while !ifa.is_null() {
                let ifa_ref = &*ifa;
                ifa = ifa_ref.ifa_next;

                let name = if ifa_ref.ifa_name.is_null() {
                    continue;
                } else {
                    std::ffi::CStr::from_ptr(ifa_ref.ifa_name)
                        .to_string_lossy()
                        .into_owned()
                };

                // Only process AF_LINK entries (link-level stats) once per interface
                if ifa_ref.ifa_addr.is_null() {
                    continue;
                }
                let sa_family = (*ifa_ref.ifa_addr).sa_family as libc::c_int;
                if sa_family != libc::AF_LINK {
                    continue;
                }
                if seen.contains(&name) {
                    continue;
                }
                seen.insert(name.clone());

                // ifa_data points to struct if_data for AF_LINK entries
                if ifa_ref.ifa_data.is_null() {
                    results.push(InterfaceStats {
                        name,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                        rx_errors: 0,
                        tx_errors: 0,
                        rx_drop: 0,
                        tx_drop: 0,
                    });
                    continue;
                }

                let d = &*(ifa_ref.ifa_data as *const libc::if_data);
                results.push(InterfaceStats {
                    name,
                    rx_bytes: d.ifi_ibytes as u64,
                    tx_bytes: d.ifi_obytes as u64,
                    rx_packets: d.ifi_ipackets as u64,
                    tx_packets: d.ifi_opackets as u64,
                    rx_errors: d.ifi_ierrors as u64,
                    tx_errors: d.ifi_oerrors as u64,
                    rx_drop: d.ifi_iqdrops as u64,
                    tx_drop: 0,
                });
            }

            libc::freeifaddrs(ifap);
        }

        Ok(results)
    }

    fn tcp_metrics(&self) -> Result<Option<TcpMetrics>> {
        Ok(None)
    }

    fn process_resources(&self, pid: u32) -> Result<ProcessResources> {
        use libproc::file_info::ListFDs;
        use libproc::proc_pid;
        use libproc::task_info::TaskAllInfo;

        let t1 = proc_pid::pidinfo::<TaskAllInfo>(pid as i32, 0)
            .map_err(|e| anyhow::anyhow!("pidinfo failed for pid {}: {}", pid, e))?;
        let t1_ns = t1.ptinfo.pti_total_user + t1.ptinfo.pti_total_system;

        std::thread::sleep(std::time::Duration::from_millis(100));

        let t2 = proc_pid::pidinfo::<TaskAllInfo>(pid as i32, 0).unwrap_or(t1);
        let t2_ns = t2.ptinfo.pti_total_user + t2.ptinfo.pti_total_system;

        // delta_ns over 100ms window → percent
        let cpu_pct = t2_ns.saturating_sub(t1_ns) as f64 / 1_000_000.0;
        let mem_rss_kb = t2.ptinfo.pti_resident_size / 1024;
        let mem_vms_kb = t2.ptinfo.pti_virtual_size / 1024;
        let threads = t2.ptinfo.pti_threadnum.max(0) as u32;

        let open_fds = proc_pid::listpidinfo::<ListFDs>(pid as i32, 1024)
            .map(|v| v.len() as u32)
            .unwrap_or(0);

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
        // Hostname via gethostname(2)
        let hostname = {
            let mut buf = vec![0u8; 256];
            let ret =
                unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
            if ret == 0 {
                let nul = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
                String::from_utf8_lossy(&buf[..nul]).into_owned()
            } else {
                String::new()
            }
        };

        // DNS: /etc/resolv.conf
        let (dns_servers, dns_search) = {
            let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
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

        // Interface addresses via getifaddrs(3)
        let interfaces = macos_net_config_interfaces();

        // Routes via sysctl(NET_RT_DUMP)
        let routes = macos_net_config_routes();

        Ok(crate::model::NetConfig {
            routes,
            dns_servers,
            dns_search,
            hostname,
            interfaces,
        })
    }
}
