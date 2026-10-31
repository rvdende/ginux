//! What bring-up needs from a network controller, and a DHCP probe that
//! shows a controller can send and receive on a real network.
//!
//! The probe broadcasts one DHCPDISCOVER and waits for an offer. It never
//! requests or uses the address, so running it leaves no lease behind.

use super::wait_until_ms;

/// The largest Ethernet frame the drivers send or receive, without the FCS.
pub(crate) const FRAME_LIMIT: usize = 1514;
const DHCP_TIMEOUT_MS: u64 = 4000;
const ETHERTYPE_IPV4: u16 = 0x0800;
const PROTOCOL_UDP: u8 = 17;
const PORT_DHCP_CLIENT: u16 = 68;
const PORT_DHCP_SERVER: u16 = 67;
const DHCP_MAGIC: [u8; 4] = [99, 130, 83, 99];
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const OPTION_SUBNET: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNS: u8 = 6;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER: u8 = 54;
const OPTION_PARAMETERS: u8 = 55;
const OPTION_END: u8 = 255;
/// Offsets of the BOOTP message inside a frame: Ethernet, IPv4 without
/// options, then UDP headers.
const BOOTP: usize = 14 + 20 + 8;

/// An Ethernet controller that can move whole frames by polling.
pub(crate) trait Nic {
    fn mac(&self) -> [u8; 6];

    /// Queues `frame`, which includes the Ethernet header but not the FCS.
    fn send(&mut self, frame: &[u8]) -> bool;

    /// Copies the next received frame into `buffer`, without its FCS, and
    /// returns its length.
    fn receive(&mut self, buffer: &mut [u8; FRAME_LIMIT]) -> Option<usize>;
}

/// What a DHCP server offered.
pub(crate) struct Offer {
    pub(crate) address: [u8; 4],
    pub(crate) server: [u8; 4],
    pub(crate) subnet: Option<[u8; 4]>,
    pub(crate) router: Option<[u8; 4]>,
    pub(crate) dns: Option<[u8; 4]>,
}

/// An IPv4 address in dotted-quad form.
pub(crate) struct Ipv4(pub(crate) [u8; 4]);

impl core::fmt::Display for Ipv4 {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d] = self.0;
        write!(output, "{a}.{b}.{c}.{d}")
    }
}

/// A MAC address in colon-separated form.
pub(crate) struct Mac(pub(crate) [u8; 6]);

impl core::fmt::Display for Mac {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(output, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
    }
}

/// Broadcasts a DHCPDISCOVER and returns the first matching offer.
pub(crate) fn dhcp_discover(nic: &mut impl Nic, transaction: u32) -> Option<Offer> {
    let mac = nic.mac();
    let mut frame = [0_u8; FRAME_LIMIT];
    let length = discover_frame(&mut frame, mac, transaction);
    if !nic.send(&frame[..length]) {
        return None;
    }
    let mut offer = None;
    wait_until_ms(DHCP_TIMEOUT_MS, || {
        while let Some(length) = nic.receive(&mut frame) {
            offer = parse_offer(&frame[..length], mac, transaction);
            if offer.is_some() {
                return true;
            }
        }
        false
    });
    offer
}

fn discover_frame(frame: &mut [u8; FRAME_LIMIT], mac: [u8; 6], transaction: u32) -> usize {
    const OPTIONS: [u8; 13] = [
        DHCP_MAGIC[0],
        DHCP_MAGIC[1],
        DHCP_MAGIC[2],
        DHCP_MAGIC[3],
        OPTION_MESSAGE_TYPE,
        1,
        DHCP_DISCOVER,
        OPTION_PARAMETERS,
        3,
        OPTION_SUBNET,
        OPTION_ROUTER,
        OPTION_DNS,
        OPTION_END,
    ];
    let bootp_length = 236 + OPTIONS.len();
    let udp_length = 8 + bootp_length;
    let ip_length = 20 + udp_length;

    frame[..6].fill(0xff);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(ip_length as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = PROTOCOL_UDP;
    ip[16..20].fill(0xff);
    let checksum = internet_checksum(ip);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());

    let udp = &mut frame[34..42];
    udp[0..2].copy_from_slice(&PORT_DHCP_CLIENT.to_be_bytes());
    udp[2..4].copy_from_slice(&PORT_DHCP_SERVER.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());

    let bootp = &mut frame[BOOTP..BOOTP + bootp_length];
    bootp[0] = 1;
    bootp[1] = 1;
    bootp[2] = 6;
    bootp[4..8].copy_from_slice(&transaction.to_be_bytes());
    // Ask for a broadcast reply: there is no address to unicast to yet.
    bootp[10] = 0x80;
    bootp[28..34].copy_from_slice(&mac);
    bootp[236..].copy_from_slice(&OPTIONS);
    // Pad to the 60-byte Ethernet minimum.
    (BOOTP + bootp_length).max(60)
}

fn parse_offer(frame: &[u8], mac: [u8; 6], transaction: u32) -> Option<Offer> {
    if frame.len() < BOOTP + 240
        || frame[12..14] != ETHERTYPE_IPV4.to_be_bytes()
        || frame[14] != 0x45
        || frame[23] != PROTOCOL_UDP
        || frame[36..38] != PORT_DHCP_CLIENT.to_be_bytes()
    {
        return None;
    }
    let bootp = &frame[BOOTP..];
    if bootp[0] != 2
        || bootp[4..8] != transaction.to_be_bytes()
        || bootp[28..34] != mac
        || bootp[236..240] != DHCP_MAGIC
    {
        return None;
    }
    let mut offer = Offer {
        address: bootp[16..20].try_into().ok()?,
        server: bootp[20..24].try_into().ok()?,
        subnet: None,
        router: None,
        dns: None,
    };
    let mut message_type = None;
    let mut options = &bootp[240..];
    while let [code, rest @ ..] = options {
        match *code {
            OPTION_END => break,
            0 => {
                options = rest;
                continue;
            }
            _ => {}
        }
        let [length, rest @ ..] = rest else {
            break;
        };
        let length = usize::from(*length);
        let value = rest.get(..length)?;
        let address = value.get(..4).and_then(|bytes| bytes.try_into().ok());
        match *code {
            OPTION_MESSAGE_TYPE => message_type = value.first().copied(),
            OPTION_SERVER => offer.server = address.unwrap_or(offer.server),
            OPTION_SUBNET => offer.subnet = address,
            OPTION_ROUTER => offer.router = address,
            OPTION_DNS => offer.dns = address,
            _ => {}
        }
        options = &rest[length..];
    }
    (message_type == Some(DHCP_OFFER)).then_some(offer)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
