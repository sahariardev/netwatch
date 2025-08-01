#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext, maps::PerfEventArray};
use netwatch_common::Event;
pub mod event;
use event::event_from_sock;

#[map]
pub static EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx, 0) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn tcp_send_message(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx, 1) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn tcp_receive_message(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx, 2) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn tcp_close(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(ctx, 3) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_tcp_connect(ctx: ProbeContext, event_type: u8) -> Result<u32, i64> {
    let event = event_from_sock(&ctx, event_type)?;
    EVENTS.output(&ctx, &event, 0);
    
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

