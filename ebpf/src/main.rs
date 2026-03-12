#![no_std]
#![no_main]

use core::{mem::MaybeUninit, ptr};

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::PerfEventArray,
    programs::ProbeContext,
};
use aya_ebpf_bindings::bindings::bpf_sock;
use opn_ebpf_common::{EventKind, SocketEvent};

#[map]
static EVENTS: PerfEventArray<SocketEvent> = PerfEventArray::new(0);

#[kprobe]
pub fn opn_tcp_connect(ctx: ProbeContext) -> u32 {
    emit_event(&ctx, EventKind::Connect, socket_arg(&ctx))
}

#[kprobe]
pub fn opn_inet_csk_listen_start(ctx: ProbeContext) -> u32 {
    emit_event(&ctx, EventKind::Listen, socket_arg(&ctx))
}

#[kprobe]
pub fn opn_inet_listen(ctx: ProbeContext) -> u32 {
    emit_event(&ctx, EventKind::Listen, socket_arg(&ctx))
}

#[kprobe]
pub fn opn_inet_csk_accept(ctx: ProbeContext) -> u32 {
    emit_event(&ctx, EventKind::Accept, socket_arg(&ctx))
}

#[kprobe]
pub fn opn_tcp_close(ctx: ProbeContext) -> u32 {
    emit_event(&ctx, EventKind::Close, socket_arg(&ctx))
}

#[kprobe]
pub fn opn_tcp_retransmit_skb(ctx: ProbeContext) -> u32 {
    emit_event(&ctx, EventKind::Retransmit, socket_arg(&ctx))
}

#[kprobe]
pub fn opn_tcp_set_state(ctx: ProbeContext) -> u32 {
    let Some(state) = int_arg(&ctx) else {
        return 0;
    };
    let kind = match state {
        10 => EventKind::Listen,
        1 => EventKind::StateChange,
        _ => return 0,
    };
    emit_event(&ctx, kind, socket_arg(&ctx))
}

#[inline(always)]
fn socket_arg(ctx: &ProbeContext) -> Option<*const bpf_sock> {
    ctx.arg(0)
}

#[inline(always)]
fn int_arg(ctx: &ProbeContext) -> Option<i32> {
    ctx.arg(1)
}

#[inline(always)]
fn emit_event(ctx: &ProbeContext, kind: EventKind, sock_ptr: Option<*const bpf_sock>) -> u32 {
    let mut event = MaybeUninit::<SocketEvent>::uninit();

    unsafe {
        let event_ptr = event.as_mut_ptr();
        ptr::addr_of_mut!((*event_ptr).ts_ns).write(bpf_ktime_get_ns());
        ptr::addr_of_mut!((*event_ptr).pid).write((bpf_get_current_pid_tgid() >> 32) as u32);
        ptr::addr_of_mut!((*event_ptr).kind).write(kind as u8);
        ptr::addr_of_mut!((*event_ptr)._reserved).write(0);
        let comm_bytes = bpf_get_current_comm().unwrap_or([0u8; 16]);
        ptr::addr_of_mut!((*event_ptr).comm_0).write(u32::from_ne_bytes([
            comm_bytes[0],
            comm_bytes[1],
            comm_bytes[2],
            comm_bytes[3],
        ]));
        ptr::addr_of_mut!((*event_ptr).comm_1).write(u32::from_ne_bytes([
            comm_bytes[4],
            comm_bytes[5],
            comm_bytes[6],
            comm_bytes[7],
        ]));
        ptr::addr_of_mut!((*event_ptr).comm_2).write(u32::from_ne_bytes([
            comm_bytes[8],
            comm_bytes[9],
            comm_bytes[10],
            comm_bytes[11],
        ]));
        ptr::addr_of_mut!((*event_ptr).comm_3).write(u32::from_ne_bytes([
            comm_bytes[12],
            comm_bytes[13],
            comm_bytes[14],
            comm_bytes[15],
        ]));
    }

    let mut event = unsafe { event.assume_init() };

    if let Some(sock_ptr) = sock_ptr {
        if fill_socket_fields(sock_ptr, &mut event).is_err() {
            return 0;
        }
    } else {
        return 0;
    }
    let _ = EVENTS.output(ctx, &event, 0);
    0
}

#[inline(always)]
fn fill_socket_fields(sock_ptr: *const bpf_sock, event: &mut SocketEvent) -> Result<(), i64> {
    if sock_ptr.is_null() {
        return Err(-1);
    }

    let family = unsafe { read_u32(ptr::addr_of!((*sock_ptr).family)) };
    let protocol = unsafe { read_u32(ptr::addr_of!((*sock_ptr).protocol)) };
    let src_port = unsafe { read_u32(ptr::addr_of!((*sock_ptr).src_port)) };
    let dst_port = unsafe { read_u16(ptr::addr_of!((*sock_ptr).dst_port)) };

    event.family = family as u8;
    event.protocol = protocol as u8;
    event.local_port = src_port as u16;
    event.remote_port = u16::from_be(dst_port);

    match family as i32 {
        2 => {
            let src_ip4 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).src_ip4)) };
            let dst_ip4 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).dst_ip4)) };
            event.local_addr_0 = src_ip4;
            event.remote_addr_0 = dst_ip4;
            event.local_addr_1 = 0;
            event.local_addr_2 = 0;
            event.local_addr_3 = 0;
            event.remote_addr_1 = 0;
            event.remote_addr_2 = 0;
            event.remote_addr_3 = 0;
        }
        10 => {
            let src0 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).src_ip6[0])) };
            let src1 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).src_ip6[1])) };
            let src2 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).src_ip6[2])) };
            let src3 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).src_ip6[3])) };
            let dst0 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).dst_ip6[0])) };
            let dst1 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).dst_ip6[1])) };
            let dst2 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).dst_ip6[2])) };
            let dst3 = unsafe { read_u32(ptr::addr_of!((*sock_ptr).dst_ip6[3])) };
            event.local_addr_0 = src0;
            event.local_addr_1 = src1;
            event.local_addr_2 = src2;
            event.local_addr_3 = src3;
            event.remote_addr_0 = dst0;
            event.remote_addr_1 = dst1;
            event.remote_addr_2 = dst2;
            event.remote_addr_3 = dst3;
        }
        _ => return Err(-1),
    }

    Ok(())
}

#[inline(always)]
unsafe fn read_u16(field: *const u16) -> u16 {
    bpf_probe_read_kernel(field).unwrap_or(0)
}

#[inline(always)]
unsafe fn read_u32(field: *const u32) -> u32 {
    bpf_probe_read_kernel(field).unwrap_or(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
