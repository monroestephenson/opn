use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::SocketEntry;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct EbpfConfig {
    pub object_path: Option<PathBuf>,
    pub interface: Option<String>,
    pub strict: bool,
}

impl EbpfConfig {
    pub fn from_env() -> Self {
        Self {
            object_path: std::env::var_os("OPN_EBPF_OBJECT").map(PathBuf::from),
            interface: std::env::var("OPN_EBPF_IFACE").ok(),
            strict: matches!(
                std::env::var("OPN_EBPF_STRICT").ok().as_deref(),
                Some("1" | "true" | "TRUE" | "yes" | "YES")
            ),
        }
    }
}

pub struct EbpfCollector {
    config: EbpfConfig,
    #[allow(dead_code)]
    bpf: Option<aya::Ebpf>,
}

impl EbpfCollector {
    pub fn from_env() -> Result<Self> {
        Self::new(EbpfConfig::from_env())
    }

    pub fn new(config: EbpfConfig) -> Result<Self> {
        let bpf = if let Some(path) = &config.object_path {
            let bytes = std::fs::read(path).with_context(|| {
                format!("failed to read eBPF object file at {}", path.display())
            })?;
            Some(aya::Ebpf::load(&bytes).context("failed to load eBPF object")?)
        } else {
            None
        };

        Ok(Self { config, bpf })
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

    pub fn collect_snapshot<F>(&self, fallback: F) -> Result<Vec<SocketEntry>>
    where
        F: FnOnce() -> Result<Vec<SocketEntry>>,
    {
        // The first aya-backed slice will replace this fallback with
        // ringbuf/perf-event collection and map-backed socket state.
        fallback()
    }
}
