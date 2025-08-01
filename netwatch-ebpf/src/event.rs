
use aya_ebpf::{helpers::{bpf_probe_read_kernel, r#gen::bpf_get_current_pid_tgid}, programs::ProbeContext};
use netwatch_common::Event;

#[repr(C)]
pub struct SockCommon {
    pub skc_daddr: u32,
    pub skc_rcv_saddr: u32,
    pub skc_dport: u16,
    pub skc_num: u16
}

#[repr(C)]
pub struct Sock {
    pub __sk_common: SockCommon
}

pub fn event_from_socket(ctx:  &ProbeContext) -> Result<Event, i64> {

    let sk: *const Sock = ctx.arg(0).ok_or(-1)?;

    let src_addr = unsafe {bpf_probe_read_kernel(&(*sk).__sk_common.skc_rcv_saddr)}?;
    let dest_addr = unsafe {bpf_probe_read_kernel(&(*sk).__sk_common.skc_daddr)}?;
    let src_port = unsafe {bpf_probe_read_kernel(&(*sk).__sk_common.skc_num)}?;
    let dest_port = unsafe {bpf_probe_read_kernel(&(*sk).__sk_common.skc_dport)}?;
    let pid = (unsafe { bpf_get_current_pid_tgid()} >> 32) as u32;

    Ok(Event{
        event_type: 0,
        src_addr: src_addr,
        dest_addr: dest_addr,
        src_port: src_port,
        dest_port: u16::from_be(dest_port),
        pid: pid
    })
}