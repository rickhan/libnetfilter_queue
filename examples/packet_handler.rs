extern crate netfilter_queue as nfq;

use nfq::error::Error;
use nfq::handle::{Handle, ProtocolFamily};
use nfq::message::Message;
use nfq::queue::{CopyMode, PacketHandler, QueueHandle, Verdict};
use std::ptr::null;

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    handle.bind(ProtocolFamily::INET).ok().unwrap();

    let mut queue = handle.queue(0, Decider).ok().unwrap();
    let _ = queue.set_mode(CopyMode::Metadata).unwrap();

    println!("Listening for packets...");
    handle.start(4096);

    println!("...finished.");
}

struct Decider;

impl PacketHandler for Decider {
    #[allow(non_snake_case)]
    fn handle(&mut self, hq: QueueHandle, message: Result<&Message, &Error>) -> i32 {
        match message {
            Ok(m) => {
                let _ = Verdict::set_verdict(hq, m.header.id(), Verdict::Accept, 0, null());
            }
            Err(_) => (),
        }
        0
    }
}
