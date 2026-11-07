#![forbid(unsafe_code)]
//! UDP-Lite (RFC 3828) datagrams as Ginux sends and checks them.
//!
//! A UDP-Lite header is UDP's, with the length field holding the
//! checksum's coverage: how many bytes, from the header's first, the
//! checksum covers (0 for all). The checksum is mandatory and covers the
//! IP pseudo-header, whose length is the whole datagram's, then the
//! covered bytes. A sender may cover less than all of a datagram
//! (UDPLITE_SEND_CSCOV); a receiver may refuse partly covered datagrams
//! below a coverage it names (UDPLITE_RECV_CSCOV).
//!
//! The rules follow Linux's net/ipv4/udplite.c and udp.c; this is pure
//! byte work, tested on the host. The kernel adds and strips the IP
//! header and finds the socket a datagram is for.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// IPPROTO_UDPLITE.
pub const PROTOCOL: u8 = 136;
/// The header's length.
pub const HEADER: usize = 8;

/// An IP address the pseudo-header holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// What a received datagram's header says, once it checks out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    /// The bytes the checksum covers, header included.
    pub coverage: usize,
    /// Whether that is less than the whole datagram.
    pub partial: bool,
}

/// The value a UDPLITE_SEND_CSCOV or UDPLITE_RECV_CSCOV option keeps for
/// `value`, as Linux stores it: 1 to 7 are the header's 8, values past
/// 65535 are 65535, and negative ones are 0.
pub fn coverage_option(value: i32) -> u16 {
    match value {
        1..=7 => HEADER as u16,
        value => value.clamp(0, i32::from(u16::MAX)) as u16,
    }
}

/// The datagram from `source_port` to `destination_port` carrying
/// `payload` between `source` and `destination`, with its checksum. With
/// UDPLITE_SEND_CSCOV set (`coverage`) below the datagram's length the
/// checksum covers that much and the field says so (0: all of it);
/// otherwise the field holds the length, as Linux writes it. None when the
/// datagram is longer than the field can say, or the addresses' families
/// differ.
pub fn encode(
    source: Ip,
    destination: Ip,
    source_port: u16,
    destination_port: u16,
    coverage: Option<u16>,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let length = HEADER + payload.len();
    let whole = u16::try_from(length).ok()?;
    let (field, covered) = match coverage {
        Some(wanted) if usize::from(wanted) < length => (
            wanted,
            if wanted == 0 {
                length
            } else {
                usize::from(wanted)
            },
        ),
        _ => (whole, length),
    };
    let mut datagram = Vec::new();
    datagram.try_reserve_exact(length).ok()?;
    datagram.extend_from_slice(&source_port.to_be_bytes());
    datagram.extend_from_slice(&destination_port.to_be_bytes());
    datagram.extend_from_slice(&field.to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    // A sum of 0 goes out as 0xffff: 0 would mean "no checksum", which
    // UDP-Lite does not have.
    let sum = match checksum(source, destination, &datagram, covered)? {
        0 => 0xffff,
        sum => sum,
    };
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    Some(datagram)
}

/// The header of `datagram`, received from `source` for `destination`, or
/// None for one to drop as Linux drops it: shorter than the header, a
/// coverage below the header or past the datagram's end, a zero checksum,
/// or a checksum that does not add up.
pub fn parse(source: Ip, destination: Ip, datagram: &[u8]) -> Option<Header> {
    if datagram.len() < HEADER {
        return None;
    }
    let field = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    let (coverage, partial) = match field {
        0 => (datagram.len(), false),
        field if field < HEADER || field > datagram.len() => return None,
        field => (field, field < datagram.len()),
    };
    if datagram[6..8] == [0, 0] || checksum(source, destination, datagram, coverage)? != 0 {
        return None;
    }
    Some(Header {
        source_port: u16::from_be_bytes([datagram[0], datagram[1]]),
        destination_port: u16::from_be_bytes([datagram[2], datagram[3]]),
        coverage,
        partial,
    })
}

/// Whether a socket whose UDPLITE_RECV_CSCOV is `wanted` takes a datagram
/// with `header`: a partly covered one needs at least that coverage, and
/// none is taken once the socket asked for 0 (full coverage only), as
/// Linux's udp_queue_rcv_one_skb checks. A fully covered one always is.
pub fn coverage_suffices(header: &Header, wanted: Option<u16>) -> bool {
    match wanted {
        Some(wanted) if header.partial => wanted != 0 && header.coverage >= usize::from(wanted),
        _ => true,
    }
}

/// The Internet checksum over the pseudo-header (`source`, `destination`,
/// the protocol and the datagram's whole length) and the first `coverage`
/// bytes of `datagram`; None for addresses of two families.
pub fn checksum(source: Ip, destination: Ip, datagram: &[u8], coverage: usize) -> Option<u16> {
    let length = u32::try_from(datagram.len()).ok()?;
    let mut sum = Sum::default();
    match (source, destination) {
        (Ip::V4(source), Ip::V4(destination)) => {
            sum.add(&source);
            sum.add(&destination);
            sum.add(&[0, PROTOCOL]);
            sum.add(&u16::try_from(length).ok()?.to_be_bytes());
        }
        (Ip::V6(source), Ip::V6(destination)) => {
            sum.add(&source);
            sum.add(&destination);
            sum.add(&length.to_be_bytes());
            sum.add(&[0, 0, 0, PROTOCOL]);
        }
        _ => return None,
    }
    sum.add(&datagram[..coverage.min(datagram.len())]);
    Some(sum.finish())
}

/// A ones'-complement sum (RFC 1071) of 16-bit words. Every run but the
/// last added must be of even length, as the pseudo-header's are.
#[derive(Default)]
struct Sum(u32);

impl Sum {
    fn add(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<2>();
        for word in words {
            self.0 += u32::from(u16::from_be_bytes(*word));
        }
        if let [last] = rest {
            self.0 += u32::from(*last) << 8;
        }
        while self.0 >> 16 != 0 {
            self.0 = (self.0 & 0xffff) + (self.0 >> 16);
        }
    }

    fn finish(self) -> u16 {
        !(self.0 as u16)
    }
}

#[cfg(test)]
mod tests;
