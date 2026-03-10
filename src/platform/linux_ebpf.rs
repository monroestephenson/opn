#![allow(dead_code)]

use std::collections::{hash_map::Entry, HashMap};
use std::convert::TryInto;
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use aya::maps::{perf::PerfEventArrayBuffer, MapData, PerfEventArray};
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{Ebpf, EbpfLoader, VerifierLogLevel};
use bytes::BytesMut;
use opn_ebpf_common::{EventKind, SocketEvent, TASK_COMM_LEN};
use serde::{Deserialize, Serialize};

use crate::model::{Protocol, SocketEntry};

include!(concat!(env!("OUT_DIR"), "/ebpf_bundle.rs"));

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfSocketEventKind {
    Listen,
    Accept,
    Connect,
    Close,
    StateChange,
    Retransmit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfSocketListingSource {
    None,
    Live,
    ProcfsFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EbpfSocketKey {
    pub pid: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EbpfSocketStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub retransmits: u64,
    pub rtt_us: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfSocketEvent {
    pub ts_ns: u64,
    pub kind: EbpfSocketEventKind,
    pub key: EbpfSocketKey,
    pub comm: String,
    pub stats: EbpfSocketStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfSocketSnapshot {
    pub key: EbpfSocketKey,
    pub comm: String,
    pub state: String,
    pub stats: EbpfSocketStats,
    pub last_seen_ts: u64,
}

#[derive(Debug, Clone)]
pub struct EbpfConfig {
    pub object_path: Option<PathBuf>,
    pub interface: Option<String>,
    pub strict: bool,
}

impl EbpfConfig {
    pub fn from_env() -> Self {
        Self {
            object_path: std::env::var_os("OPN_EBPF_OBJECT")
                .map(PathBuf::from)
                .or_else(Self::installed_object_path)
                .or_else(Self::discover_object_path),
            interface: std::env::var("OPN_EBPF_IFACE").ok(),
            strict: matches!(
                std::env::var("OPN_EBPF_STRICT").ok().as_deref(),
                Some("1" | "true" | "TRUE" | "yes" | "YES")
            ),
        }
    }

    pub fn is_available() -> bool {
        std::env::var_os("OPN_EBPF_OBJECT").is_some()
            || BUNDLED_EBPF_OBJECT.is_some()
            || Self::installed_object_path().is_some()
            || Self::discover_object_path().is_some()
    }

    fn installed_object_path() -> Option<PathBuf> {
        [
            PathBuf::from("/usr/lib/opn/opn-ebpf"),
            PathBuf::from("/usr/libexec/opn/opn-ebpf"),
            PathBuf::from("/opt/opn/lib/opn-ebpf"),
        ]
        .into_iter()
        .find(|path| path.exists())
    }

    fn discover_object_path() -> Option<PathBuf> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        [
            repo_root.join("target/bpfel-unknown-none/release/opn-ebpf"),
            repo_root.join("target/bpfel-unknown-none/debug/opn-ebpf"),
            repo_root.join("target/bpfel-unknown-none/release/opn-ebpf.o"),
            repo_root.join("target/bpfel-unknown-none/debug/opn-ebpf.o"),
            repo_root.join("ebpf/target/bpfel-unknown-none/release/opn-ebpf"),
            repo_root.join("ebpf/target/bpfel-unknown-none/debug/opn-ebpf"),
            repo_root.join("ebpf/target/bpfel-unknown-none/release/opn-ebpf.o"),
            repo_root.join("ebpf/target/bpfel-unknown-none/debug/opn-ebpf.o"),
        ]
        .into_iter()
        .find(|path| path.exists())
    }
}

pub struct EbpfCollector {
    config: EbpfConfig,
    bpf: Option<Ebpf>,
    perf_buffers: Vec<PerfEventArrayBuffer<MapData>>,
    pending_events: Vec<EbpfSocketEvent>,
    flows: HashMap<EbpfSocketKey, EbpfSocketSnapshot>,
    last_listing_source: EbpfSocketListingSource,
}

impl EbpfCollector {
    pub fn from_env() -> Result<Self> {
        Self::new(EbpfConfig::from_env())
    }

    pub fn new(config: EbpfConfig) -> Result<Self> {
        let bpf = Self::load_bpf(&config)?;

        let mut collector = Self {
            config,
            bpf,
            perf_buffers: Vec::new(),
            pending_events: Vec::new(),
            flows: HashMap::new(),
            last_listing_source: EbpfSocketListingSource::None,
        };
        collector.open_perf_buffers()?;
        Ok(collector)
    }

    pub fn is_ready(&self) -> bool {
        self.bpf.is_some()
    }

    pub fn strict(&self) -> bool {
        self.config.strict
    }

    pub fn object_path(&self) -> Option<&PathBuf> {
        self.config.object_path.as_ref()
    }

    pub fn interface(&self) -> Option<&str> {
        self.config.interface.as_deref()
    }

    pub fn collect_snapshot<F>(&mut self, fallback: F) -> Result<Vec<EbpfSocketSnapshot>>
    where
        F: FnOnce() -> Result<Vec<EbpfSocketSnapshot>>,
    {
        self.wait_for_events(Duration::from_millis(0))?;
        if self.flows.is_empty() {
            if self.strict() {
                Ok(Vec::new())
            } else {
                fallback()
            }
        } else {
            Ok(self.flows.values().cloned().collect())
        }
    }

    pub fn wait_for_events(&mut self, timeout: Duration) -> Result<usize> {
        if self.bpf.is_none() {
            if self.strict() {
                anyhow::bail!(
                    "eBPF backend selected but no object is loaded; set OPN_EBPF_OBJECT to a compiled eBPF object"
                );
            }
            return Ok(0);
        }

        self.open_perf_buffers()?;
        let deadline = Instant::now() + timeout;
        let mut total = 0usize;

        while Instant::now() < deadline {
            let mut readable = false;
            let mut decoded_events = Vec::new();
            for buffer in &mut self.perf_buffers {
                if !buffer.readable() {
                    continue;
                }
                readable = true;
                let mut out_bufs = vec![BytesMut::with_capacity(size_of::<SocketEvent>()); 32];
                let events = buffer.read_events(&mut out_bufs)?;
                for buf in out_bufs.into_iter().take(events.read) {
                    if let Some(event) = decode_socket_event(&buf) {
                        decoded_events.push(event);
                    }
                }
            }

            for event in decoded_events {
                self.apply_event(&event);
                self.pending_events.push(event);
                total += 1;
            }

            if total > 0 {
                return Ok(total);
            }
            if !readable {
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        Ok(0)
    }

    pub fn drain_events(&mut self) -> Vec<EbpfSocketEvent> {
        std::mem::take(&mut self.pending_events)
    }

    pub fn flow_snapshots(&self) -> Vec<EbpfSocketSnapshot> {
        self.flows.values().cloned().collect()
    }

    pub fn last_listing_source(&self) -> EbpfSocketListingSource {
        self.last_listing_source
    }

    pub fn set_last_listing_source(&mut self, source: EbpfSocketListingSource) {
        self.last_listing_source = source;
    }

    pub fn seed_from_sockets(&mut self, entries: &[SocketEntry]) {
        let ts_ns = system_time_ns();
        for entry in entries {
            let key = EbpfSocketKey {
                pid: entry.process.pid,
                protocol: protocol_label(&entry.protocol).to_string(),
                local_addr: entry.local_addr.clone(),
                remote_addr: entry.remote_addr.clone(),
            };
            match self.flows.entry(key.clone()) {
                Entry::Occupied(_) => {}
                Entry::Vacant(slot) => {
                    slot.insert(EbpfSocketSnapshot {
                        key,
                        comm: entry.process.name.clone(),
                        state: entry.state.clone(),
                        stats: EbpfSocketStats::default(),
                        last_seen_ts: ts_ns,
                    });
                }
            }
        }
    }

    fn attach_kprobes(bpf: &mut Ebpf) -> Result<()> {
        Self::attach_kprobe(bpf, "opn_tcp_connect", "tcp_connect")?;
        Self::attach_kprobe(bpf, "opn_inet_csk_listen_start", "inet_csk_listen_start")?;
        Self::attach_kprobe(bpf, "opn_inet_listen", "inet_listen")?;
        Self::attach_kprobe(bpf, "opn_inet_csk_accept", "inet_csk_accept")?;
        Self::attach_kprobe(bpf, "opn_tcp_close", "tcp_close")?;
        Self::attach_kprobe(bpf, "opn_tcp_retransmit_skb", "tcp_retransmit_skb")?;
        Self::attach_kprobe(bpf, "opn_tcp_set_state", "tcp_set_state")?;
        Ok(())
    }

    fn attach_kprobe(bpf: &mut Ebpf, program_name: &str, kernel_symbol: &str) -> Result<()> {
        let program: &mut KProbe = bpf
            .program_mut(program_name)
            .with_context(|| format!("missing eBPF program '{program_name}'"))?
            .try_into()
            .with_context(|| format!("program '{program_name}' is not a kprobe"))?;
        if let Err(error) = program.load() {
            return Err(anyhow!(
                "failed to load eBPF program '{program_name}': {error:#}"
            ));
        }
        program.attach(kernel_symbol, 0).map_err(|error| {
            anyhow!("failed to attach '{program_name}' to {kernel_symbol}: {error:#}")
        })?;
        Ok(())
    }

    fn open_perf_buffers(&mut self) -> Result<()> {
        if self.bpf.is_none() || !self.perf_buffers.is_empty() {
            return Ok(());
        }
        let bpf = self.bpf.as_mut().expect("checked above");
        let events_map = bpf
            .take_map("EVENTS")
            .context("missing eBPF perf map 'EVENTS'")?;
        let mut perf_array =
            PerfEventArray::try_from(events_map).context("failed to open EVENTS perf map")?;

        for cpu_id in online_cpus().map_err(|(_, error)| error)? {
            self.perf_buffers.push(
                perf_array
                    .open(cpu_id, None)
                    .with_context(|| format!("failed to open perf buffer for cpu {cpu_id}"))?,
            );
        }
        Ok(())
    }

    fn apply_event(&mut self, event: &EbpfSocketEvent) {
        match event.kind {
            EbpfSocketEventKind::Close => {
                self.flows.remove(&event.key);
            }
            EbpfSocketEventKind::Listen
            | EbpfSocketEventKind::Accept
            | EbpfSocketEventKind::Connect
            | EbpfSocketEventKind::StateChange
            | EbpfSocketEventKind::Retransmit => {
                let previous = self.flows.get(&event.key);
                let state = derive_state(event, previous);
                let stats = merge_stats(event, previous);

                self.flows.insert(
                    event.key.clone(),
                    EbpfSocketSnapshot {
                        key: event.key.clone(),
                        comm: event.comm.clone(),
                        state,
                        stats,
                        last_seen_ts: event.ts_ns,
                    },
                );
            }
        }
    }
}

impl EbpfCollector {
    fn load_bpf(config: &EbpfConfig) -> Result<Option<Ebpf>> {
        if let Some(path) = &config.object_path {
            let bytes = std::fs::read(path).with_context(|| {
                format!("failed to read eBPF object file at {}", path.display())
            })?;
            let mut bpf = EbpfLoader::new()
                .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
                .load(&bytes)
                .context("failed to load eBPF object")?;
            Self::attach_kprobes(&mut bpf)?;
            return Ok(Some(bpf));
        }

        if let Some(bytes) = BUNDLED_EBPF_OBJECT {
            let mut bpf = EbpfLoader::new()
                .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
                .load(bytes)
                .context("failed to load bundled eBPF object")?;
            Self::attach_kprobes(&mut bpf)?;
            return Ok(Some(bpf));
        }

        Ok(None)
    }
}

fn derive_state(event: &EbpfSocketEvent, previous: Option<&EbpfSocketSnapshot>) -> String {
    match event.kind {
        EbpfSocketEventKind::Listen => String::from("LISTEN"),
        EbpfSocketEventKind::Accept | EbpfSocketEventKind::Connect => String::from("ESTABLISHED"),
        EbpfSocketEventKind::Retransmit => previous
            .map(|snapshot| snapshot.state.clone())
            .unwrap_or_else(|| String::from("ESTABLISHED")),
        EbpfSocketEventKind::StateChange => previous
            .map(|snapshot| snapshot.state.clone())
            .unwrap_or_else(|| infer_state_from_key(&event.key)),
        EbpfSocketEventKind::Close => String::from("CLOSED"),
    }
}

fn merge_stats(event: &EbpfSocketEvent, previous: Option<&EbpfSocketSnapshot>) -> EbpfSocketStats {
    let mut stats = previous
        .map(|snapshot| snapshot.stats.clone())
        .unwrap_or_default();
    stats.rx_bytes = stats.rx_bytes.max(event.stats.rx_bytes);
    stats.tx_bytes = stats.tx_bytes.max(event.stats.tx_bytes);
    stats.retransmits = stats.retransmits.max(event.stats.retransmits);
    stats.rtt_us = event.stats.rtt_us.or(stats.rtt_us);
    stats
}

fn infer_state_from_key(key: &EbpfSocketKey) -> String {
    if key.remote_addr == "*:0" || key.remote_addr == "-:0" || key.remote_addr == "0.0.0.0:0" {
        String::from("LISTEN")
    } else {
        String::from("ESTABLISHED")
    }
}

fn decode_socket_event(bytes: &[u8]) -> Option<EbpfSocketEvent> {
    if bytes.len() < size_of::<SocketEvent>() {
        return None;
    }

    let raw = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const SocketEvent) };
    Some(EbpfSocketEvent {
        ts_ns: raw.ts_ns,
        kind: match raw.kind {
            x if x == EventKind::Listen as u8 => EbpfSocketEventKind::Listen,
            x if x == EventKind::Accept as u8 => EbpfSocketEventKind::Accept,
            x if x == EventKind::Connect as u8 => EbpfSocketEventKind::Connect,
            x if x == EventKind::Close as u8 => EbpfSocketEventKind::Close,
            x if x == EventKind::StateChange as u8 => EbpfSocketEventKind::StateChange,
            x if x == EventKind::Retransmit as u8 => EbpfSocketEventKind::Retransmit,
            _ => EbpfSocketEventKind::StateChange,
        },
        key: EbpfSocketKey {
            pid: raw.pid,
            protocol: protocol_name(raw.protocol).to_string(),
            local_addr: format_addr(
                raw.family,
                [
                    raw.local_addr_0,
                    raw.local_addr_1,
                    raw.local_addr_2,
                    raw.local_addr_3,
                ],
                raw.local_port,
            ),
            remote_addr: format_addr(
                raw.family,
                [
                    raw.remote_addr_0,
                    raw.remote_addr_1,
                    raw.remote_addr_2,
                    raw.remote_addr_3,
                ],
                raw.remote_port,
            ),
        },
        comm: decode_comm([raw.comm_0, raw.comm_1, raw.comm_2, raw.comm_3]),
        stats: EbpfSocketStats {
            rx_bytes: raw.rx_bytes,
            tx_bytes: raw.tx_bytes,
            retransmits: raw.retransmits as u64,
            rtt_us: if raw.rtt_us == 0 {
                None
            } else {
                Some(raw.rtt_us)
            },
        },
    })
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        17 => "UDP",
        _ => "TCP",
    }
}

fn protocol_label(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
    }
}

fn decode_comm(comm_words: [u32; 4]) -> String {
    let mut comm = [0u8; TASK_COMM_LEN];
    for (index, word) in comm_words.into_iter().enumerate() {
        let bytes = word.to_ne_bytes();
        let start = index * 4;
        comm[start..start + 4].copy_from_slice(&bytes);
    }
    let len = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).to_string()
}

fn format_addr(family: u8, raw: [u32; 4], port: u16) -> String {
    match family as i32 {
        libc::AF_INET => {
            let bytes = raw[0].to_be_bytes();
            let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            format!("{ip}:{port}")
        }
        libc::AF_INET6 => {
            let mut bytes = [0u8; 16];
            bytes[0..4].copy_from_slice(&raw[0].to_be_bytes());
            bytes[4..8].copy_from_slice(&raw[1].to_be_bytes());
            bytes[8..12].copy_from_slice(&raw[2].to_be_bytes());
            bytes[12..16].copy_from_slice(&raw[3].to_be_bytes());
            let ip = std::net::Ipv6Addr::from(bytes);
            format!("[{ip}]:{port}")
        }
        _ => format!("*:{}", port),
    }
}

fn system_time_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}
