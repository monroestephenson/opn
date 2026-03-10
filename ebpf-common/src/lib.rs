#![cfg_attr(not(feature = "std"), no_std)]

pub const TASK_COMM_LEN: usize = 16;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Listen = 1,
    Accept = 2,
    Connect = 3,
    Close = 4,
    StateChange = 5,
    Retransmit = 6,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SocketEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub kind: u8,
    pub protocol: u8,
    pub family: u8,
    pub _reserved: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_addr_0: u32,
    pub local_addr_1: u32,
    pub local_addr_2: u32,
    pub local_addr_3: u32,
    pub remote_addr_0: u32,
    pub remote_addr_1: u32,
    pub remote_addr_2: u32,
    pub remote_addr_3: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub retransmits: u32,
    pub rtt_us: u32,
    pub comm_0: u32,
    pub comm_1: u32,
    pub comm_2: u32,
    pub comm_3: u32,
}

impl SocketEvent {
    pub const fn zeroed() -> Self {
        Self {
            ts_ns: 0,
            pid: 0,
            kind: 0,
            protocol: 0,
            family: 0,
            _reserved: 0,
            local_port: 0,
            remote_port: 0,
            local_addr_0: 0,
            local_addr_1: 0,
            local_addr_2: 0,
            local_addr_3: 0,
            remote_addr_0: 0,
            remote_addr_1: 0,
            remote_addr_2: 0,
            remote_addr_3: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            retransmits: 0,
            rtt_us: 0,
            comm_0: 0,
            comm_1: 0,
            comm_2: 0,
            comm_3: 0,
        }
    }
}
