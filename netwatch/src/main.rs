use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{KProbe, SchedClassifier, TcAttachType},
    util::online_cpus,
    Bpf,
};
use netwatch_common::Event;
use log::{debug, warn};
use tokio::signal;
use clap::Parser;
use bytes::BytesMut;
use std::{mem, ptr};

use anyhow::anyhow;

mod  detail_event;
use detail_event::DetailEvent;

#[derive(Parser, Debug)]
struct Opts {
    #[arg[long]]
    port: u16
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/netwatch"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
         warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut KProbe = ebpf.program_mut("tcp_connect").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    let program: &mut KProbe = ebpf.program_mut("tcp_send_message").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_sendmsg", 0)?;

    let program: &mut KProbe = ebpf.program_mut("tcp_receive_message").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_recvmsg", 0)?;

    let program: &mut KProbe = ebpf.program_mut("tcp_close").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_close", 0)?;

    let opts = Opts::parse();

    let cpus = online_cpus().map_err(|(msg, err)| anyhow!("{}: {}", msg, err))?;
    let num_cpus = cpus.len();
    let perf_array = ebpf.take_map("EVENTS")
    .ok_or_else(|| anyhow!("Failed to take the EVENTS map"))?;
    let mut events = AsyncPerfEventArray::try_from(perf_array)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let event = unsafe { ptr::read_unaligned(buf.as_ptr() as *const Event) };

                    let detail_event : DetailEvent = event.into();
                    println!("Detail event : {:?}", detail_event);

                }
            }
        });
    }


    let ctrl_c = signal::ctrl_c();
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}