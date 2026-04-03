extern crate netfilter_queue as nfq;

use nfq::handle::{Handle, ProtocolFamily};
use nfq::message::Message;
use nfq::queue::{CopyMode, Verdict};

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    let _ = handle.bind(ProtocolFamily::INET).ok().unwrap();

    let mut queue = handle
        .queue(0, move |message: &Message| {
            println!("Handling packet (ID: {})", message.header.id());
            Verdict::Accept
        })
        .ok()
        .unwrap();
    queue.set_mode(CopyMode::Metadata).ok().unwrap();

    println!("Listening for packets...");
    handle.start(4096);

    println!("...finished.");
}
