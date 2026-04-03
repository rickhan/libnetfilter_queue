//! Bindings for [netfilter_queue](http://netfilter.org/projects/libnetfilter_queue/doxygen/index.html)
//!
//! These bindings allow you to have access to the `QUEUE` and `NFQUEUE`, set in `iptables`,
//! and write your own userspace programs to process these queues.
#![deny(missing_docs)]

extern crate errno;
extern crate libc;
extern crate num;
#[macro_use]
extern crate lazy_static;

mod ffi;

mod lock;
mod util;

pub mod error;
pub mod handle;
pub mod message;
pub mod queue;

//#[cfg(test)]
//mod test;
