#![forbid(unsafe_code)]
//! rtnetlink (NETLINK_ROUTE) as Ginux answers it: the requests iproute2
//! and busybox `ip` send, and the messages Linux sends back.
//!
//! The kernel describes a network namespace as a [`View`] (its links,
//! addresses and routes) and hands each datagram a process sends to
//! [`answer`], which returns the datagrams to queue for the process:
//!
//! - RTM_GETLINK, RTM_GETADDR and RTM_GETROUTE dumps (NLM_F_DUMP):
//!   NLM_F_MULTI messages packed into datagrams, then NLMSG_DONE;
//! - RTM_GETLINK of one link (by index or IFLA_IFNAME) and RTM_GETROUTE of
//!   one destination (`ip route get`);
//! - RTM_NEWLINK/RTM_SETLINK changes of a link's flags and MTU, which the
//!   kernel applies or refuses through [`Network`];
//! - RTM_NEWADDR, RTM_DELADDR, RTM_NEWROUTE and RTM_DELROUTE, answered as
//!   Linux answers what the namespace has (EEXIST, EADDRNOTAVAIL, ESRCH)
//!   and EOPNOTSUPP for changes the kernel does not make;
//! - NLM_F_ACK acknowledgements and NLMSG_ERROR for failures, carrying the
//!   request's sequence number and the socket's port id.
//!
//! This is pure message work, so it is tested on the host.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// struct nlmsghdr's size.
pub const HEADER: usize = 16;

/// Netlink control message types.
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;

/// Netlink message flags.
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_MULTI: u16 = 0x2;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;

/// rtnetlink message types.
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

/// Address families.
pub const AF_UNSPEC: u8 = 0;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// Link attributes (IFLA_*).
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_BROADCAST: u16 = 2;
pub const IFLA_IFNAME: u16 = 3;
pub const IFLA_MTU: u16 = 4;
pub const IFLA_QDISC: u16 = 6;
pub const IFLA_TXQLEN: u16 = 13;
pub const IFLA_OPERSTATE: u16 = 16;
pub const IFLA_LINKMODE: u16 = 17;
pub const IFLA_LINKINFO: u16 = 18;
pub const IFLA_GROUP: u16 = 27;
pub const IFLA_PROMISCUITY: u16 = 30;
pub const IFLA_NUM_TX_QUEUES: u16 = 31;
pub const IFLA_NUM_RX_QUEUES: u16 = 32;
pub const IFLA_CARRIER: u16 = 33;
pub const IFLA_MIN_MTU: u16 = 50;
pub const IFLA_MAX_MTU: u16 = 51;

/// Address attributes (IFA_*).
pub const IFA_ADDRESS: u16 = 1;
pub const IFA_LOCAL: u16 = 2;
pub const IFA_LABEL: u16 = 3;
pub const IFA_BROADCAST: u16 = 4;
pub const IFA_CACHEINFO: u16 = 6;
pub const IFA_FLAGS: u16 = 8;
/// IFA_F_PERMANENT: an address the kernel or the administrator set, with
/// no lifetime.
pub const IFA_F_PERMANENT: u32 = 0x80;

/// Route attributes (RTA_*).
pub const RTA_DST: u16 = 1;
pub const RTA_OIF: u16 = 4;
pub const RTA_GATEWAY: u16 = 5;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_PREFSRC: u16 = 7;
pub const RTA_TABLE: u16 = 15;
pub const RTA_PREF: u16 = 20;

/// Routing tables.
pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;

/// Route types (RTN_*).
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BROADCAST: u8 = 3;

/// Route origins (RTPROT_*).
pub const RTPROT_KERNEL: u8 = 2;
pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_DHCP: u8 = 16;

/// Scopes (RT_SCOPE_*).
pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_LINK: u8 = 253;
pub const RT_SCOPE_HOST: u8 = 254;

/// rtm_flags: RTM_F_CLONED, the route a lookup answers with.
pub const RTM_F_CLONED: u32 = 0x200;

/// Interface flags (IFF_*).
pub const IFF_UP: u32 = 0x1;
pub const IFF_LOOPBACK: u32 = 0x8;
pub const IFF_RUNNING: u32 = 0x40;
pub const IFF_LOWER_UP: u32 = 0x1_0000;

/// Operational states (IF_OPER_*).
pub const IF_OPER_UNKNOWN: u8 = 0;
pub const IF_OPER_DOWN: u8 = 2;
pub const IF_OPER_UP: u8 = 6;

/// The errno values the answers carry (negated in NLMSG_ERROR).
pub const EPERM: i32 = 1;
pub const ESRCH: i32 = 3;
pub const EEXIST: i32 = 17;
pub const ENODEV: i32 = 19;
pub const EINVAL: i32 = 22;
pub const ENOBUFS: i32 = 105;
pub const EOPNOTSUPP: i32 = 95;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETUNREACH: i32 = 101;

/// The most bytes one datagram of a dump holds; a dump's messages fill
/// datagrams up to it, as Linux fills socket buffers.
pub const DATAGRAM_LIMIT: usize = 4096;

/// A network interface.
#[derive(Clone, Copy, Debug)]
pub struct Link<'a> {
    pub index: i32,
    pub name: &'a [u8],
    /// ARPHRD_* type.
    pub kind: u16,
    /// IFF_* flags as SIOCGIFFLAGS shows them (IFF_LOWER_UP is added for
    /// a running link).
    pub flags: u32,
    pub mtu: u32,
    pub min_mtu: u32,
    pub max_mtu: u32,
    pub address: [u8; 6],
    pub broadcast: [u8; 6],
    pub txqlen: u32,
    /// The queueing discipline's name.
    pub qdisc: &'a [u8],
}

impl Link<'_> {
    fn operstate(&self) -> u8 {
        if self.flags & IFF_UP == 0 {
            IF_OPER_DOWN
        } else if self.flags & IFF_LOOPBACK != 0 {
            // Linux's loopback has no carrier state to report.
            IF_OPER_UNKNOWN
        } else {
            IF_OPER_UP
        }
    }

    fn reported_flags(&self) -> u32 {
        if self.flags & IFF_UP != 0 && self.flags & IFF_RUNNING != 0 {
            self.flags | IFF_LOWER_UP
        } else {
            self.flags
        }
    }
}

/// An IP address: IPv4 in the first four bytes, or IPv6.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ip {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl Ip {
    fn family(self) -> u8 {
        match self {
            Self::V4(_) => AF_INET,
            Self::V6(_) => AF_INET6,
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Self::V4(bytes) => bytes,
            Self::V6(bytes) => bytes,
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::V4(_) => 32,
            Self::V6(_) => 128,
        }
    }

    fn parse(family: u8, bytes: &[u8]) -> Option<Self> {
        match family {
            AF_INET => Some(Self::V4(bytes.try_into().ok()?)),
            AF_INET6 => Some(Self::V6(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    /// Whether the first `length` bits of `self` and `other` agree.
    fn matches(self, other: Self, length: u8) -> bool {
        if self.family() != other.family() {
            return false;
        }
        let (left, right) = (self.bytes(), other.bytes());
        let whole = usize::from(length / 8);
        let rest = length % 8;
        left[..whole] == right[..whole]
            && (rest == 0 || {
                let mask = 0xff_u8 << (8 - rest);
                left[whole] & mask == right[whole] & mask
            })
    }
}

/// An address on a link.
#[derive(Clone, Copy, Debug)]
pub struct Address {
    pub index: i32,
    pub address: Ip,
    pub prefix: u8,
    pub scope: u8,
    /// An IPv4 address's broadcast address.
    pub broadcast: Option<[u8; 4]>,
}

/// A route.
#[derive(Clone, Copy, Debug)]
pub struct Route {
    pub table: u8,
    /// RTN_* type.
    pub kind: u8,
    /// RTPROT_* origin.
    pub protocol: u8,
    pub scope: u8,
    pub destination: Ip,
    pub destination_length: u8,
    pub gateway: Option<Ip>,
    pub output: i32,
    pub source: Option<Ip>,
    pub priority: Option<u32>,
}

/// What a network namespace has.
#[derive(Clone, Copy, Debug)]
pub struct View<'a> {
    pub links: &'a [Link<'a>],
    pub addresses: &'a [Address],
    pub routes: &'a [Route],
}

/// A change to a link that RTM_NEWLINK or RTM_SETLINK asks for: its new
/// IFF_* flags and MTU, each when it changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkChange {
    pub index: i32,
    pub flags: Option<u32>,
    pub mtu: Option<u32>,
}

/// The kernel's side of the changes requests ask for.
pub trait Network {
    /// Whether the sender has CAP_NET_ADMIN over the namespace, which every
    /// request but a GET needs (EPERM otherwise).
    fn administrator(&self) -> bool;

    /// Applies `change`, or says why not (an errno).
    fn change_link(&mut self, change: LinkChange) -> Result<(), i32>;
}

/// The datagrams that answer `input`, one or more netlink messages a
/// process sent from port id `port`, about the namespace `view`
/// describes. Messages that are not requests are ignored, as Linux
/// ignores them; a malformed one ends the datagram with EINVAL.
pub fn answer(view: &View, network: &mut dyn Network, input: &[u8], port: u32) -> Vec<Vec<u8>> {
    let mut output = Output::default();
    let mut offset = 0;
    while input.len() - offset >= HEADER {
        let header = Header::parse(&input[offset..]);
        let length = header.length as usize;
        if length < HEADER || length > input.len() - offset {
            break;
        }
        let message = &input[offset..offset + length];
        if header.flags & NLM_F_REQUEST != 0 && header.kind >= RTM_NEWLINK {
            let reply = Reply {
                port,
                sequence: header.sequence,
            };
            let result = request(
                view,
                network,
                &header,
                &message[HEADER..],
                reply,
                &mut output,
            );
            match result {
                Ok(()) if header.flags & NLM_F_ACK != 0 => {
                    output.single(error_message(reply, 0, &message[..HEADER]));
                }
                Ok(()) => {}
                // A failed request's answer carries all of it.
                Err(errno) => output.single(error_message(reply, -errno, message)),
            }
        }
        // Messages are 4-byte aligned (NLMSG_ALIGN).
        offset += align(length);
        if offset >= input.len() {
            break;
        }
    }
    output.datagrams
}

/// One request: a dump, a single answer, or a change.
fn request(
    view: &View,
    network: &mut dyn Network,
    header: &Header,
    body: &[u8],
    reply: Reply,
    output: &mut Output,
) -> Result<(), i32> {
    let get = header.kind & 3 == 2;
    if !get && !network.administrator() {
        return Err(EPERM);
    }
    let dump = get && header.flags & NLM_F_DUMP == NLM_F_DUMP;
    // The first byte of every rtnetlink body is its family (rtgenmsg).
    let family = body.first().copied().unwrap_or(AF_UNSPEC);
    match header.kind {
        RTM_GETLINK if dump => {
            for link in view.links {
                output.part(&link_message(link, reply, NLM_F_MULTI));
            }
            output.done(reply);
            Ok(())
        }
        RTM_GETLINK => {
            let link = find_link(view, body)?;
            output.single(link_message(link, reply, 0));
            Ok(())
        }
        RTM_NEWLINK | RTM_SETLINK => change_link(view, network, header, body),
        RTM_DELLINK => {
            find_link(view, body)?;
            Err(EOPNOTSUPP)
        }
        RTM_GETADDR if dump => {
            for address in view
                .addresses
                .iter()
                .filter(|address| family == AF_UNSPEC || address.address.family() == family)
            {
                let label = view
                    .links
                    .iter()
                    .find(|link| link.index == address.index)
                    .map(|link| link.name);
                output.part(&address_message(address, label, reply));
            }
            output.done(reply);
            Ok(())
        }
        // IPv4 has no single-address GETADDR; Linux answers EOPNOTSUPP.
        RTM_GETADDR => Err(EOPNOTSUPP),
        RTM_NEWADDR | RTM_DELADDR => change_address(view, header, body),
        RTM_GETROUTE if dump => {
            for route in view
                .routes
                .iter()
                .filter(|route| family == AF_UNSPEC || route.destination.family() == family)
            {
                output.part(&route_message(route, reply, NLM_F_MULTI, 0));
            }
            output.done(reply);
            Ok(())
        }
        RTM_GETROUTE => {
            let message = route_lookup(view, body, reply)?;
            output.single(message);
            Ok(())
        }
        RTM_NEWROUTE | RTM_DELROUTE => change_route(view, header, body),
        _ => Err(EOPNOTSUPP),
    }
}

/// The link an ifinfomsg names: by index, else by IFLA_IFNAME (ENODEV
/// when none matches, EINVAL when it names none).
fn find_link<'v>(view: &'v View, body: &[u8]) -> Result<&'v Link<'v>, i32> {
    const IFINFOMSG: usize = 16;
    let index = body.get(4..8).map_or(0, |bytes| {
        i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    });
    if index > 0 {
        return view
            .links
            .iter()
            .find(|link| link.index == index)
            .ok_or(ENODEV);
    }
    let name = attributes(body.get(IFINFOMSG..).unwrap_or(&[]))
        .find(|(kind, _)| *kind == IFLA_IFNAME)
        .map(|(_, value)| trim_nul(value))
        .ok_or(EINVAL)?;
    view.links
        .iter()
        .find(|link| link.name == name)
        .ok_or(ENODEV)
}

/// RTM_NEWLINK or RTM_SETLINK of an existing link: new flags (ifi_flags
/// under the ifi_change mask, all of them for a mask of 0, as Linux reads
/// it) and IFLA_MTU. Making links (NLM_F_CREATE with IFLA_LINKINFO) is
/// EOPNOTSUPP.
fn change_link(
    view: &View,
    network: &mut dyn Network,
    header: &Header,
    body: &[u8],
) -> Result<(), i32> {
    const IFINFOMSG: usize = 16;
    if body.len() < IFINFOMSG {
        return Err(EINVAL);
    }
    let attributes_bytes = &body[IFINFOMSG..];
    if header.flags & NLM_F_CREATE != 0
        && attributes(attributes_bytes).any(|(kind, _)| kind == IFLA_LINKINFO)
    {
        return Err(EOPNOTSUPP);
    }
    let link = find_link(view, body)?;
    let word = |at: usize| u32::from_ne_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]);
    let (flags, mask) = (word(8), word(12));
    let flags = if flags == 0 && mask == 0 {
        None
    } else if mask == 0 {
        Some(flags)
    } else {
        Some(flags & mask | link.flags & !mask)
    };
    let mtu = attributes(attributes_bytes)
        .find(|(kind, _)| *kind == IFLA_MTU)
        .map(|(_, value)| value.try_into().map(u32::from_ne_bytes).map_err(|_| EINVAL))
        .transpose()?;
    if let Some(mtu) = mtu {
        if mtu < link.min_mtu || mtu > link.max_mtu {
            return Err(EINVAL);
        }
    }
    let change = LinkChange {
        index: link.index,
        // Only IFF_UP changes here; the kernel keeps the other flags.
        flags: flags.filter(|flags| (flags ^ link.flags) & IFF_UP != 0),
        mtu: mtu.filter(|mtu| *mtu != link.mtu),
    };
    if change.flags.is_none() && change.mtu.is_none() {
        return Ok(());
    }
    network.change_link(change)
}

/// RTM_NEWADDR and RTM_DELADDR: an address the link already has is
/// EEXIST to add (unless NLM_F_REPLACE), one it lacks EADDRNOTAVAIL to
/// delete; the kernel adds and removes none (EOPNOTSUPP).
fn change_address(view: &View, header: &Header, body: &[u8]) -> Result<(), i32> {
    const IFADDRMSG: usize = 8;
    if body.len() < IFADDRMSG {
        return Err(EINVAL);
    }
    let (family, prefix) = (body[0], body[1]);
    let index = i32::from_ne_bytes([body[4], body[5], body[6], body[7]]);
    if !view.links.iter().any(|link| link.index == index) {
        return Err(ENODEV);
    }
    let address = attributes(&body[IFADDRMSG..])
        .filter(|(kind, _)| *kind == IFA_LOCAL || *kind == IFA_ADDRESS)
        .find_map(|(_, value)| Ip::parse(family, value))
        .ok_or(EINVAL)?;
    if prefix > address.bits() {
        return Err(EINVAL);
    }
    let existing = view
        .addresses
        .iter()
        .any(|known| known.index == index && known.address == address && known.prefix == prefix);
    match (header.kind, existing) {
        (RTM_NEWADDR, true) if header.flags & NLM_F_REPLACE == 0 => Err(EEXIST),
        (RTM_NEWADDR, true) => Ok(()),
        (RTM_DELADDR, false) => Err(EADDRNOTAVAIL),
        _ => Err(EOPNOTSUPP),
    }
}

/// RTM_NEWROUTE and RTM_DELROUTE: a route the table already has is
/// EEXIST to add with NLM_F_EXCL, one it lacks ESRCH to delete; the kernel
/// adds and removes none (EOPNOTSUPP).
fn change_route(view: &View, header: &Header, body: &[u8]) -> Result<(), i32> {
    let route = RouteRequest::parse(body)?;
    let existing = view.routes.iter().any(|known| {
        known.table == route.table
            && known.destination_length == route.destination_length
            && known.destination.family() == route.family
            && route.destination.is_none_or(|destination| {
                known
                    .destination
                    .matches(destination, route.destination_length)
            })
    });
    match (header.kind, existing) {
        (RTM_NEWROUTE, true) if header.flags & NLM_F_EXCL != 0 => Err(EEXIST),
        (RTM_DELROUTE, false) => Err(ESRCH),
        _ => Err(EOPNOTSUPP),
    }
}

/// The parts of an rtmsg request: family, destination and table.
struct RouteRequest {
    family: u8,
    destination: Option<Ip>,
    destination_length: u8,
    table: u8,
}

impl RouteRequest {
    fn parse(body: &[u8]) -> Result<Self, i32> {
        const RTMSG: usize = 12;
        if body.len() < RTMSG {
            return Err(EINVAL);
        }
        let family = body[0];
        if family != AF_INET && family != AF_INET6 {
            return Err(EOPNOTSUPP);
        }
        let mut request = Self {
            family,
            destination: None,
            destination_length: body[1],
            table: body[4],
        };
        for (kind, value) in attributes(&body[RTMSG..]) {
            match kind {
                RTA_DST => request.destination = Some(Ip::parse(family, value).ok_or(EINVAL)?),
                RTA_TABLE => {
                    let table: [u8; 4] = value.try_into().map_err(|_| EINVAL)?;
                    request.table = u32::from_ne_bytes(table).min(255) as u8;
                }
                _ => {}
            }
        }
        if request.table == 0 {
            request.table = RT_TABLE_MAIN;
        }
        if request.destination_length > if family == AF_INET { 32 } else { 128 } {
            return Err(EINVAL);
        }
        Ok(request)
    }
}

/// `ip route get`: the route RTA_DST takes, from the local table first,
/// then the longest prefix in the main table (ENETUNREACH with none), as
/// one RTM_NEWROUTE for that address alone.
fn route_lookup(view: &View, body: &[u8], reply: Reply) -> Result<Vec<u8>, i32> {
    let request = RouteRequest::parse(body)?;
    let unspecified = match request.family {
        AF_INET => Ip::V4([0; 4]),
        _ => Ip::V6([0; 16]),
    };
    let destination = request.destination.unwrap_or(unspecified);
    let best = |table: u8| {
        view.routes
            .iter()
            .filter(|route| {
                route.table == table
                    && route.kind != RTN_BROADCAST
                    && route
                        .destination
                        .matches(destination, route.destination_length)
            })
            .max_by_key(|route| route.destination_length)
    };
    let route = best(RT_TABLE_LOCAL)
        .or_else(|| best(RT_TABLE_MAIN))
        .ok_or(ENETUNREACH)?;
    // The source: the route's preferred one, the destination itself for a
    // local one, else the output link's first address of the family.
    let source = route.source.or(if route.kind == RTN_LOCAL {
        Some(destination)
    } else {
        view.addresses
            .iter()
            .find(|address| {
                address.index == route.output && address.address.family() == request.family
            })
            .map(|address| address.address)
    });
    let found = Route {
        destination,
        destination_length: destination.bits(),
        source,
        ..*route
    };
    Ok(route_message(&found, reply, 0, RTM_F_CLONED))
}

/// Where answers go: the requesting socket's port id and the request's
/// sequence number.
#[derive(Clone, Copy)]
struct Reply {
    port: u32,
    sequence: u32,
}

struct Header {
    length: u32,
    kind: u16,
    flags: u16,
    sequence: u32,
}

impl Header {
    fn parse(bytes: &[u8]) -> Self {
        let word = |at: usize| {
            u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Self {
            length: word(0),
            kind: u16::from_ne_bytes([bytes[4], bytes[5]]),
            flags: u16::from_ne_bytes([bytes[6], bytes[7]]),
            sequence: word(8),
        }
    }
}

/// The datagrams being built: a dump's parts share them up to
/// DATAGRAM_LIMIT bytes each.
#[derive(Default)]
struct Output {
    datagrams: Vec<Vec<u8>>,
    /// Whether the last datagram is a dump's, open to more parts.
    open: bool,
}

impl Output {
    fn part(&mut self, message: &[u8]) {
        match self.datagrams.last_mut() {
            Some(last) if self.open && last.len() + message.len() <= DATAGRAM_LIMIT => {
                last.extend_from_slice(message);
            }
            _ => {
                self.datagrams.push(message.to_vec());
                self.open = true;
            }
        }
    }

    fn done(&mut self, reply: Reply) {
        // NLMSG_DONE carries an int, the dump's result.
        let mut message = Message::new(NLMSG_DONE, NLM_F_MULTI, reply);
        message.bytes.extend_from_slice(&0_i32.to_ne_bytes());
        self.part(&message.finish());
        self.open = false;
    }

    fn single(&mut self, message: Vec<u8>) {
        self.datagrams.push(message);
        self.open = false;
    }
}

/// A message being built: header, fixed part and attributes.
struct Message {
    bytes: Vec<u8>,
}

impl Message {
    fn new(kind: u16, flags: u16, reply: Reply) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&reply.sequence.to_ne_bytes());
        bytes.extend_from_slice(&reply.port.to_ne_bytes());
        Self { bytes }
    }

    fn attribute(&mut self, kind: u16, value: &[u8]) {
        let length = 4 + value.len();
        self.bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        self.bytes.extend_from_slice(&kind.to_ne_bytes());
        self.bytes.extend_from_slice(value);
        self.bytes.resize(align(self.bytes.len()), 0);
    }

    fn u32(&mut self, kind: u16, value: u32) {
        self.attribute(kind, &value.to_ne_bytes());
    }

    fn u8(&mut self, kind: u16, value: u8) {
        self.attribute(kind, &[value]);
    }

    /// A NUL-terminated string attribute.
    fn string(&mut self, kind: u16, value: &[u8]) {
        let mut text = Vec::with_capacity(value.len() + 1);
        text.extend_from_slice(value);
        text.push(0);
        self.attribute(kind, &text);
    }

    fn finish(mut self) -> Vec<u8> {
        let length = self.bytes.len() as u32;
        self.bytes[..4].copy_from_slice(&length.to_ne_bytes());
        self.bytes
    }
}

/// RTM_NEWLINK for `link`.
fn link_message(link: &Link, reply: Reply, flags: u16) -> Vec<u8> {
    let mut message = Message::new(RTM_NEWLINK, flags, reply);
    // struct ifinfomsg: family, pad, type, index, flags, change.
    message.bytes.extend_from_slice(&[AF_UNSPEC, 0]);
    message.bytes.extend_from_slice(&link.kind.to_ne_bytes());
    message.bytes.extend_from_slice(&link.index.to_ne_bytes());
    message
        .bytes
        .extend_from_slice(&link.reported_flags().to_ne_bytes());
    message.bytes.extend_from_slice(&0_u32.to_ne_bytes());
    message.string(IFLA_IFNAME, link.name);
    message.u32(IFLA_TXQLEN, link.txqlen);
    message.u8(IFLA_OPERSTATE, link.operstate());
    message.u8(IFLA_LINKMODE, 0);
    message.u32(IFLA_MTU, link.mtu);
    message.u32(IFLA_MIN_MTU, link.min_mtu);
    message.u32(IFLA_MAX_MTU, link.max_mtu);
    message.u32(IFLA_GROUP, 0);
    message.u32(IFLA_PROMISCUITY, 0);
    message.u32(IFLA_NUM_TX_QUEUES, 1);
    message.u32(IFLA_NUM_RX_QUEUES, 1);
    message.u8(IFLA_CARRIER, u8::from(link.flags & IFF_RUNNING != 0));
    message.string(IFLA_QDISC, link.qdisc);
    message.attribute(IFLA_ADDRESS, &link.address);
    message.attribute(IFLA_BROADCAST, &link.broadcast);
    message.finish()
}

/// RTM_NEWADDR for `address`, labelled (IPv4) with its link's name.
fn address_message(address: &Address, label: Option<&[u8]>, reply: Reply) -> Vec<u8> {
    let mut message = Message::new(RTM_NEWADDR, NLM_F_MULTI, reply);
    // struct ifaddrmsg: family, prefixlen, flags, scope, index.
    message.bytes.extend_from_slice(&[
        address.address.family(),
        address.prefix,
        IFA_F_PERMANENT as u8,
        address.scope,
    ]);
    message
        .bytes
        .extend_from_slice(&address.index.to_ne_bytes());
    message.attribute(IFA_ADDRESS, address.address.bytes());
    if let Ip::V4(bytes) = address.address {
        message.attribute(IFA_LOCAL, &bytes);
        if let Some(broadcast) = address.broadcast {
            message.attribute(IFA_BROADCAST, &broadcast);
        }
        if let Some(label) = label {
            message.string(IFA_LABEL, label);
        }
    }
    message.u32(IFA_FLAGS, IFA_F_PERMANENT);
    // struct ifa_cacheinfo: preferred and valid lifetimes (forever), then
    // the creation and update stamps.
    let mut cache = [0_u8; 16];
    cache[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    cache[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
    message.attribute(IFA_CACHEINFO, &cache);
    message.finish()
}

/// RTM_NEWROUTE for `route`, with `route_flags` in rtm_flags.
fn route_message(route: &Route, reply: Reply, flags: u16, route_flags: u32) -> Vec<u8> {
    let mut message = Message::new(RTM_NEWROUTE, flags, reply);
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    message.bytes.extend_from_slice(&[
        route.destination.family(),
        route.destination_length,
        0,
        0,
        route.table,
        route.protocol,
        route.scope,
        route.kind,
    ]);
    message.bytes.extend_from_slice(&route_flags.to_ne_bytes());
    message.u32(RTA_TABLE, u32::from(route.table));
    if route.destination_length != 0 {
        message.attribute(RTA_DST, route.destination.bytes());
    }
    if let Some(priority) = route.priority {
        message.u32(RTA_PRIORITY, priority);
    }
    if let Some(source) = route.source {
        message.attribute(RTA_PREFSRC, source.bytes());
    }
    if let Some(gateway) = route.gateway {
        message.attribute(RTA_GATEWAY, gateway.bytes());
    }
    message.u32(RTA_OIF, route.output as u32);
    if matches!(route.destination, Ip::V6(_)) {
        // RTA_PREF: ICMPV6_ROUTER_PREF_MEDIUM.
        message.u8(RTA_PREF, 0);
    }
    message.finish()
}

/// NLMSG_ERROR with `error` (0 for an acknowledgement, else a negated
/// errno) and the request (its header alone for an acknowledgement).
fn error_message(reply: Reply, error: i32, request: &[u8]) -> Vec<u8> {
    let mut message = Message::new(NLMSG_ERROR, 0, reply);
    message.bytes.extend_from_slice(&error.to_ne_bytes());
    message.bytes.extend_from_slice(request);
    message.bytes.resize(align(message.bytes.len()), 0);
    message.finish()
}

/// The (type, value) pairs of a run of rtattrs; a malformed one ends it.
fn attributes(bytes: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut offset = 0;
    core::iter::from_fn(move || {
        let header = bytes.get(offset..offset + 4)?;
        let length = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]) & 0x3fff;
        let value = bytes
            .get(offset + 4..offset.checked_add(length)?)
            .filter(|_| length >= 4)?;
        offset += align(length);
        Some((kind, value))
    })
}

fn trim_nul(bytes: &[u8]) -> &[u8] {
    bytes.split(|byte| *byte == 0).next().unwrap_or(bytes)
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}

#[cfg(test)]
mod tests;
