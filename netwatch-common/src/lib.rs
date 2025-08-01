#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub event_type: u8,
    pub pid: u32,
    pub src_addr: u32,
    pub dest_addr: u32,
    pub src_port: u16,
    pub dest_port: u16
}