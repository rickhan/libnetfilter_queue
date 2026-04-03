//! Message parsing
//!
//! Analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Parsing.html>

use error::*;
pub use ffi::nfqnl_msg_packet_hdr as Header;
use ffi::*;
use libc::*;
use num::traits::PrimInt;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr::null;
use util::*;

/// Structs impl'ing `Payload` must be sized correctly for the payload data that mill be transmuted to it
pub trait Payload {}

#[allow(dead_code)]
#[allow(missing_docs)]
/// A `Payload` to fetch and parse an IP packet header
pub struct IPHeader {
    pub version_and_header_raw: u8,
    pub dscp_raw: u8,
    pub total_length_raw: u16,
    pub id_raw: u16,
    pub flags_and_offset_raw: u16,
    pub ttl_raw: u8,
    pub protocol_raw: u8,
    pub checksum_raw: u16,
    pub saddr_raw: u32,
    pub daddr_raw: u32,
}

impl IPHeader {
    /// Parse the source address
    pub fn saddr(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.saddr_raw)
    }

    /// Parse the destination address
    pub fn daddr(&self) -> Ipv4Addr {
        addr_to_ipv4(&self.daddr_raw)
    }
}

#[inline]
fn addr_to_ipv4(src: &u32) -> Ipv4Addr {
    let octets: [u8; 4] = unsafe { mem::transmute(*src) };
    Ipv4Addr::new(
        u8::from_be(octets[0]),
        u8::from_be(octets[1]),
        u8::from_be(octets[2]),
        u8::from_be(octets[3]),
    )
}

impl Payload for IPHeader {}

/// The packet message
pub struct Message<'a> {
    /// A raw pointer to the queue data
    pub raw: *mut nfgenmsg,
    /// A raw pointer to the packet data
    pub ptr: *mut nfq_data,
    /// The `Message` header
    ///
    /// A verdict cannot be set without the packet's id
    /// parsed from the header.
    /// For convenience, the header is always parsed into the message.
    pub header: &'a Header,
}

impl<'a> Drop for Message<'a> {
    fn drop(&mut self) {}
}

impl<'a> Message<'a> {
    #[doc(hidden)]
    pub fn new(raw: *mut nfgenmsg, ptr: *mut nfq_data) -> Result<Message<'a>, Error> {
        let header = unsafe {
            let ptr = nfq_get_msg_packet_hdr(ptr);
            match as_ref(&ptr) {
                Some(h) => h,
                None => return Err(error(Reason::GetHeader, "Failed to get header", None)),
            }
        };
        Ok(Message {
            raw: raw,
            ptr: ptr,
            header: header,
        })
    }

    /// Parse the `IPHeader` from the message
    ///
    /// When parsing `IPHeader` from a message, the `Queue`'s `CopyMode` and the `Handle` should be sized to the `IPHeader`.
    /// The best way to do this is with the `queue_builder.set_copy_mode_sized_to_payload`
    /// and `handle.start_sized_to_payload` methods.
    /// See `examples/get_addrs.rs`.
    pub unsafe fn ip_header(&self) -> Result<&IPHeader, Error> {
        self.payload::<IPHeader>()
    }

    /// Parse a sized `Payload` from the message
    ///
    /// The size of the `Payload` must be equal to the value that `handle.start` was called with.
    /// The best way to do this is with the `queue_builder.set_copy_mode_sized_to_payload`
    /// and `handle.start_sized_to_payload` methods.
    /// See `examples/get_addrs.rs`.
    pub unsafe fn payload<A: Payload>(&self) -> Result<&A, Error> {
        let data: *const A = null();
        let ptr: *mut *mut A = &mut (data as *mut A);
        let len = nfq_get_payload(self.ptr, ptr as *mut *mut c_uchar);
        if len < 0 {
            return Err(error(Reason::GetPayload, "Failed to get payload", Some(-1)));
        }
        let len = len as usize;
        // 确保长度足够读取 A
        if len < mem::size_of::<A>() {
            return Err(error(
                Reason::GetPayload,
                "Payload too small",
                Some(len as i32),
            ));
        }
        // 构造安全的引用
        let slice = std::slice::from_raw_parts(ptr, len); // &[u8]
        let a_ref = &*(slice.as_ptr() as *const A);
        Ok(a_ref)
        // match as_ref(&data) {
        //     Some(payload) => Ok(payload),
        //     None => Err(error(Reason::GetPayload, "Failed to get payload", None))
        // }
    }
}
