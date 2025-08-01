use chrono::{DateTime, Utc};
use netwatch_common::Event;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct DetailEvent {
    pub pid: u32,
    pub src_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
    pub src_port: u16,
    pub dest_port: u16,
    pub event_type: EventType,
    pub happed_at: DateTime<Utc>
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Connect,
    Send,
    Receive,
    Close
}

impl EventType {
    fn from_type(event_type: u8) -> Result<Self, String> {
        match event_type {
            0 => Ok(EventType::Connect),
            1 => Ok(EventType::Send),
            2 => Ok(EventType::Receive),
            3 => Ok(EventType::Close),
            other => Err(format!("Invalid event type: {} is not valid value..", other))
        }
    }
}

impl From<Event> for DetailEvent {
    fn from(event: Event) -> Self {
        let event_type = EventType::from_type(event.event_type).unwrap_or_else(|err| {
            panic!(" error {} ", err);
        });

        DetailEvent {
            pid: event.pid,
            src_addr: Ipv4Addr::from(event.src_addr),
            dest_addr: Ipv4Addr::from(event.dest_addr),
            src_port: event.src_port,
            dest_port: event.dest_port,
            event_type: event_type,
            happed_at: Utc::now()
        }
    }   
}

