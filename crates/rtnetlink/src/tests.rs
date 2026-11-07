use alloc::vec;
use alloc::vec::Vec;

use super::*;

const ETHERNET_MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];

fn links() -> [Link<'static>; 2] {
    [
        Link {
            index: 1,
            name: b"lo",
            kind: 772,
            flags: IFF_UP | IFF_LOOPBACK | IFF_RUNNING,
            mtu: 65_536,
            min_mtu: 0,
            max_mtu: 0,
            address: Some([0; 6]),
            broadcast: Some([0; 6]),
            txqlen: 1000,
            qdisc: b"noqueue",
        },
        Link {
            index: 2,
            name: b"eth0",
            kind: 1,
            flags: IFF_UP | 0x2 | IFF_RUNNING | 0x1000,
            mtu: 1500,
            min_mtu: 68,
            max_mtu: 65_535,
            address: Some(ETHERNET_MAC),
            broadcast: Some([0xff; 6]),
            txqlen: 1000,
            qdisc: b"pfifo_fast",
        },
    ]
}

fn addresses() -> [Address; 3] {
    [
        Address {
            index: 1,
            address: Ip::V4([127, 0, 0, 1]),
            prefix: 8,
            scope: RT_SCOPE_HOST,
            broadcast: None,
        },
        Address {
            index: 2,
            address: Ip::V4([10, 0, 2, 15]),
            prefix: 24,
            scope: RT_SCOPE_UNIVERSE,
            broadcast: Some([10, 0, 2, 255]),
        },
        Address {
            index: 1,
            address: Ip::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            prefix: 128,
            scope: RT_SCOPE_HOST,
            broadcast: None,
        },
    ]
}

fn routes() -> [Route; 3] {
    [
        Route {
            table: RT_TABLE_MAIN,
            kind: RTN_UNICAST,
            protocol: RTPROT_DHCP,
            scope: RT_SCOPE_UNIVERSE,
            destination: Ip::V4([0; 4]),
            destination_length: 0,
            gateway: Some(Ip::V4([10, 0, 2, 2])),
            output: 2,
            source: None,
            priority: None,
        },
        Route {
            table: RT_TABLE_MAIN,
            kind: RTN_UNICAST,
            protocol: RTPROT_KERNEL,
            scope: RT_SCOPE_LINK,
            destination: Ip::V4([10, 0, 2, 0]),
            destination_length: 24,
            gateway: None,
            output: 2,
            source: Some(Ip::V4([10, 0, 2, 15])),
            priority: None,
        },
        Route {
            table: RT_TABLE_LOCAL,
            kind: RTN_LOCAL,
            protocol: RTPROT_KERNEL,
            scope: RT_SCOPE_HOST,
            destination: Ip::V4([127, 0, 0, 0]),
            destination_length: 8,
            gateway: None,
            output: 1,
            source: Some(Ip::V4([127, 0, 0, 1])),
            priority: None,
        },
    ]
}

struct Kernel {
    administrator: bool,
    changes: Vec<LinkChange>,
    result: Result<(), i32>,
    /// The addresses added (true) and removed (false).
    addresses: Vec<(bool, i32, Ip, u8)>,
    address_result: Result<(), i32>,
}

impl Kernel {
    fn new() -> Self {
        Self {
            administrator: true,
            changes: Vec::new(),
            result: Ok(()),
            addresses: Vec::new(),
            address_result: Err(EOPNOTSUPP),
        }
    }
}

impl Network for Kernel {
    fn administrator(&self) -> bool {
        self.administrator
    }

    fn change_link(&mut self, change: LinkChange) -> Result<(), i32> {
        self.changes.push(change);
        self.result
    }

    fn add_address(&mut self, index: i32, address: Ip, prefix: u8) -> Result<(), i32> {
        self.addresses.push((true, index, address, prefix));
        self.address_result
    }

    fn remove_address(&mut self, index: i32, address: Ip, prefix: u8) -> Result<(), i32> {
        self.addresses.push((false, index, address, prefix));
        self.address_result
    }
}

/// A request: header, body, attributes.
fn request(
    kind: u16,
    flags: u16,
    sequence: u32,
    body: &[u8],
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut bytes = vec![0; HEADER];
    bytes.extend_from_slice(body);
    bytes.resize(align(bytes.len()), 0);
    for (attribute, value) in attributes {
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&attribute.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align(bytes.len()), 0);
    }
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&length.to_ne_bytes());
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes
}

/// The messages of a run of datagrams: (type, flags, sequence, port, body).
fn messages(datagrams: &[Vec<u8>]) -> Vec<(u16, u16, u32, u32, Vec<u8>)> {
    let mut found = Vec::new();
    for datagram in datagrams {
        let mut offset = 0;
        while offset + HEADER <= datagram.len() {
            let header = &datagram[offset..];
            let length = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
            assert!(length >= HEADER && offset + length <= datagram.len());
            found.push((
                u16::from_ne_bytes([header[4], header[5]]),
                u16::from_ne_bytes([header[6], header[7]]),
                u32::from_ne_bytes(header[8..12].try_into().unwrap()),
                u32::from_ne_bytes(header[12..16].try_into().unwrap()),
                header[HEADER..length].to_vec(),
            ));
            offset += align(length);
        }
    }
    found
}

fn attribute(body: &[u8], fixed: usize, kind: u16) -> Option<Vec<u8>> {
    attributes(&body[fixed..])
        .find(|(found, _)| *found == kind)
        .map(|(_, value)| value.to_vec())
}

fn error_of(message: &(u16, u16, u32, u32, Vec<u8>)) -> i32 {
    assert_eq!(message.0, NLMSG_ERROR);
    i32::from_ne_bytes(message.4[..4].try_into().unwrap())
}

fn run(kernel: &mut Kernel, input: &[u8]) -> Vec<(u16, u16, u32, u32, Vec<u8>)> {
    let (links, addresses, routes) = (links(), addresses(), routes());
    let view = View {
        links: &links,
        addresses: &addresses,
        routes: &routes,
    };
    messages(&answer(&view, kernel, input, 77))
}

#[test]
fn link_dump_lists_each_link_then_done() {
    // busybox's request: nlmsghdr and an rtgenmsg alone.
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_GETLINK,
            NLM_F_REQUEST | NLM_F_DUMP,
            9,
            &[AF_UNSPEC],
            &[],
        ),
    );
    assert_eq!(found.len(), 3);
    for message in &found[..2] {
        assert_eq!(
            (message.0, message.1, message.2, message.3),
            (RTM_NEWLINK, NLM_F_MULTI, 9, 77)
        );
    }
    let (lo, eth0) = (&found[0].4, &found[1].4);
    assert_eq!(i32::from_ne_bytes(lo[4..8].try_into().unwrap()), 1);
    assert_eq!(attribute(lo, 16, IFLA_IFNAME).unwrap(), b"lo\0");
    assert_eq!(
        attribute(lo, 16, IFLA_OPERSTATE).unwrap(),
        [IF_OPER_UNKNOWN]
    );
    assert_eq!(attribute(eth0, 16, IFLA_ADDRESS).unwrap(), ETHERNET_MAC);
    assert_eq!(attribute(eth0, 16, IFLA_OPERSTATE).unwrap(), [IF_OPER_UP]);
    assert_eq!(
        attribute(eth0, 16, IFLA_MTU).unwrap(),
        1500_u32.to_ne_bytes()
    );
    let flags = u32::from_ne_bytes(eth0[8..12].try_into().unwrap());
    assert_ne!(flags & IFF_LOWER_UP, 0);
    assert_eq!((found[2].0, found[2].1), (NLMSG_DONE, NLM_F_MULTI));
    assert_eq!(found[2].4, 0_i32.to_ne_bytes());
}

#[test]
fn address_dump_filters_by_family_and_labels_ipv4() {
    let ifaddrmsg = [AF_INET, 0, 0, 0, 0, 0, 0, 0];
    let found = run(
        &mut Kernel::new(),
        &request(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 3, &ifaddrmsg, &[]),
    );
    assert_eq!(found.len(), 3);
    let eth0 = &found[1].4;
    assert_eq!(&eth0[..2], &[AF_INET, 24]);
    assert_eq!(attribute(eth0, 8, IFA_LOCAL).unwrap(), [10, 0, 2, 15]);
    assert_eq!(attribute(eth0, 8, IFA_BROADCAST).unwrap(), [10, 0, 2, 255]);
    assert_eq!(attribute(eth0, 8, IFA_LABEL).unwrap(), b"eth0\0");
    assert_eq!(found[2].0, NLMSG_DONE);

    let all = run(
        &mut Kernel::new(),
        &request(
            RTM_GETADDR,
            NLM_F_REQUEST | NLM_F_DUMP,
            3,
            &[AF_UNSPEC],
            &[],
        ),
    );
    assert_eq!(all.len(), 4);
    let ipv6 = &all[2].4;
    assert_eq!(
        &ipv6[..4],
        &[AF_INET6, 128, IFA_F_PERMANENT as u8, RT_SCOPE_HOST]
    );
    assert_eq!(attribute(ipv6, 8, IFA_LABEL), None);
}

#[test]
fn route_dump_and_lookup() {
    let rtmsg = [AF_INET, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let found = run(
        &mut Kernel::new(),
        &request(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 5, &rtmsg, &[]),
    );
    assert_eq!(found.len(), 4);
    let default = &found[0].4;
    assert_eq!(default[1], 0);
    assert_eq!(attribute(default, 12, RTA_GATEWAY).unwrap(), [10, 0, 2, 2]);
    assert_eq!(attribute(default, 12, RTA_DST), None);
    assert_eq!(attribute(&found[1].4, 12, RTA_DST).unwrap(), [10, 0, 2, 0]);

    // ip route get 8.8.8.8: the default route, from eth0's address.
    let get = run(
        &mut Kernel::new(),
        &request(
            RTM_GETROUTE,
            NLM_F_REQUEST,
            6,
            &[AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[(RTA_DST, &[8, 8, 8, 8])],
        ),
    );
    assert_eq!(get.len(), 1);
    let route = &get[0].4;
    assert_eq!((get[0].0, get[0].1), (RTM_NEWROUTE, 0));
    assert_eq!(attribute(route, 12, RTA_DST).unwrap(), [8, 8, 8, 8]);
    assert_eq!(attribute(route, 12, RTA_GATEWAY).unwrap(), [10, 0, 2, 2]);
    assert_eq!(attribute(route, 12, RTA_PREFSRC).unwrap(), [10, 0, 2, 15]);
    assert_eq!(
        u32::from_ne_bytes(route[8..12].try_into().unwrap()),
        RTM_F_CLONED
    );

    // ip route get 127.0.0.5: local, from the local table.
    let local = run(
        &mut Kernel::new(),
        &request(
            RTM_GETROUTE,
            NLM_F_REQUEST,
            7,
            &[AF_INET, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[(RTA_DST, &[127, 0, 0, 5])],
        ),
    );
    assert_eq!(local[0].4[4], RT_TABLE_LOCAL);
    assert_eq!(local[0].4[7], RTN_LOCAL);
    assert_eq!(
        attribute(&local[0].4, 12, RTA_PREFSRC).unwrap(),
        [127, 0, 0, 1]
    );

    // No IPv6 route reaches 2001:db8::1.
    let mut v6 = [0_u8; 16];
    v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    let none = run(
        &mut Kernel::new(),
        &request(
            RTM_GETROUTE,
            NLM_F_REQUEST,
            8,
            &[AF_INET6, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[(RTA_DST, &v6)],
        ),
    );
    assert_eq!(error_of(&none[0]), -ENETUNREACH);
}

#[test]
fn single_link_by_name_or_index() {
    let ifinfomsg = [0_u8; 16];
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_GETLINK,
            NLM_F_REQUEST,
            1,
            &ifinfomsg,
            &[(IFLA_IFNAME, b"eth0\0")],
        ),
    );
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].0, found[0].1), (RTM_NEWLINK, 0));
    assert_eq!(attribute(&found[0].4, 16, IFLA_IFNAME).unwrap(), b"eth0\0");

    let mut by_index = [0_u8; 16];
    by_index[4..8].copy_from_slice(&9_i32.to_ne_bytes());
    let missing = run(
        &mut Kernel::new(),
        &request(RTM_GETLINK, NLM_F_REQUEST, 2, &by_index, &[]),
    );
    assert_eq!(error_of(&missing[0]), -ENODEV);
    // A failed request's answer carries the whole request after the error.
    assert_eq!(missing[0].4.len(), 4 + HEADER + 16);
}

#[test]
fn link_changes_reach_the_kernel_and_ack() {
    // ip link set lo down: ifi_change IFF_UP, ifi_flags 0.
    let mut ifinfomsg = [0_u8; 16];
    ifinfomsg[4..8].copy_from_slice(&1_i32.to_ne_bytes());
    ifinfomsg[12..16].copy_from_slice(&IFF_UP.to_ne_bytes());
    let mut kernel = Kernel::new();
    let found = run(
        &mut kernel,
        &request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 4, &ifinfomsg, &[]),
    );
    assert_eq!(
        kernel.changes,
        [LinkChange {
            index: 1,
            flags: Some(IFF_LOOPBACK | IFF_RUNNING),
            mtu: None,
        }]
    );
    assert_eq!(found.len(), 1);
    assert_eq!(error_of(&found[0]), 0);
    // An acknowledgement carries the request's header alone.
    assert_eq!(found[0].4.len(), 4 + HEADER);
    assert_eq!(found[0].2, 4);

    // ip link set lo up while up: nothing to change, still acknowledged.
    ifinfomsg[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
    let mut kernel = Kernel::new();
    let found = run(
        &mut kernel,
        &request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, 5, &ifinfomsg, &[]),
    );
    assert!(kernel.changes.is_empty());
    assert_eq!(error_of(&found[0]), 0);

    // An MTU the link cannot take is EINVAL; the kernel's refusal comes back.
    let mut eth0 = [0_u8; 16];
    eth0[4..8].copy_from_slice(&2_i32.to_ne_bytes());
    let mut kernel = Kernel::new();
    let found = run(
        &mut kernel,
        &request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            6,
            &eth0,
            &[(IFLA_MTU, &20_u32.to_ne_bytes())],
        ),
    );
    assert_eq!(error_of(&found[0]), -EINVAL);
    let mut kernel = Kernel::new();
    kernel.result = Err(EOPNOTSUPP);
    let found = run(
        &mut kernel,
        &request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK,
            7,
            &eth0,
            &[(IFLA_MTU, &9000_u32.to_ne_bytes())],
        ),
    );
    assert_eq!(kernel.changes[0].mtu, Some(9000));
    assert_eq!(error_of(&found[0]), -EOPNOTSUPP);

    // Making a link (ip link add) is not done here.
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
            8,
            &[0; 16],
            &[(IFLA_IFNAME, b"veth0\0"), (IFLA_LINKINFO, &[])],
        ),
    );
    assert_eq!(error_of(&found[0]), -EOPNOTSUPP);
}

#[test]
fn changes_need_an_administrator() {
    let mut kernel = Kernel::new();
    kernel.administrator = false;
    let found = run(
        &mut kernel,
        &request(
            RTM_NEWADDR,
            NLM_F_REQUEST,
            1,
            &[AF_INET, 8, 0, 0, 1, 0, 0, 0],
            &[],
        ),
    );
    assert_eq!(error_of(&found[0]), -EPERM);
    // Reading needs nothing.
    let found = run(
        &mut kernel,
        &request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 2, &[0], &[]),
    );
    assert_eq!(found.last().unwrap().0, NLMSG_DONE);
}

#[test]
fn address_and_route_changes_answer_as_linux() {
    let lo = [AF_INET, 8, 0, 0, 1, 0, 0, 0];
    let add = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    let found = run(
        &mut Kernel::new(),
        &request(RTM_NEWADDR, add, 1, &lo, &[(IFA_LOCAL, &[127, 0, 0, 1])]),
    );
    assert_eq!(error_of(&found[0]), -EEXIST);
    let found = run(
        &mut Kernel::new(),
        &request(RTM_NEWADDR, add, 2, &lo, &[(IFA_LOCAL, &[127, 0, 0, 2])]),
    );
    assert_eq!(error_of(&found[0]), -EOPNOTSUPP);
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_DELADDR,
            NLM_F_REQUEST | NLM_F_ACK,
            3,
            &lo,
            &[(IFA_LOCAL, &[127, 0, 0, 2])],
        ),
    );
    assert_eq!(error_of(&found[0]), -EADDRNOTAVAIL);
    let missing = [AF_INET, 8, 0, 0, 7, 0, 0, 0];
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_NEWADDR,
            add,
            4,
            &missing,
            &[(IFA_LOCAL, &[127, 0, 0, 2])],
        ),
    );
    assert_eq!(error_of(&found[0]), -ENODEV);

    let rtmsg = [
        AF_INET,
        24,
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_BOOT,
        0,
        RTN_UNICAST,
        0,
        0,
        0,
        0,
    ];
    let found = run(
        &mut Kernel::new(),
        &request(RTM_NEWROUTE, add, 5, &rtmsg, &[(RTA_DST, &[10, 0, 2, 0])]),
    );
    assert_eq!(error_of(&found[0]), -EEXIST);
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            6,
            &rtmsg,
            &[(RTA_DST, &[192, 168, 0, 0])],
        ),
    );
    assert_eq!(error_of(&found[0]), -ESRCH);
    let found = run(
        &mut Kernel::new(),
        &request(
            RTM_NEWROUTE,
            add,
            7,
            &rtmsg,
            &[(RTA_DST, &[192, 168, 0, 0])],
        ),
    );
    assert_eq!(error_of(&found[0]), -EOPNOTSUPP);
}

#[test]
fn other_messages_are_ignored_or_unsupported() {
    // Not a request: no answer.
    assert!(run(
        &mut Kernel::new(),
        &request(RTM_GETLINK, NLM_F_DUMP, 1, &[0], &[])
    )
    .is_empty());
    // NLMSG_NOOP and other control types: no answer.
    assert!(run(&mut Kernel::new(), &request(1, NLM_F_REQUEST, 1, &[], &[])).is_empty());
    // An rtnetlink type nothing handles (RTM_GETNEIGH).
    let found = run(
        &mut Kernel::new(),
        &request(30, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0], &[]),
    );
    assert_eq!(error_of(&found[0]), -EOPNOTSUPP);
    // A truncated message is dropped.
    let mut short = request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0], &[]);
    short[..4].copy_from_slice(&200_u32.to_ne_bytes());
    assert!(run(&mut Kernel::new(), &short).is_empty());
}

#[test]
fn several_requests_in_one_datagram() {
    let mut input = request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0], &[]);
    input.extend(request(
        RTM_GETADDR,
        NLM_F_REQUEST | NLM_F_DUMP,
        2,
        &[0],
        &[],
    ));
    let found = run(&mut Kernel::new(), &input);
    let sequences: Vec<(u16, u32)> = found.iter().map(|message| (message.0, message.2)).collect();
    assert_eq!(
        sequences,
        [
            (RTM_NEWLINK, 1),
            (RTM_NEWLINK, 1),
            (NLMSG_DONE, 1),
            (RTM_NEWADDR, 2),
            (RTM_NEWADDR, 2),
            (RTM_NEWADDR, 2),
            (NLMSG_DONE, 2),
        ]
    );
}

#[test]
fn large_dumps_span_datagrams() {
    let names: Vec<[u8; 8]> = (0..100_u8)
        .map(|index| {
            let mut name = *b"dummy\0\0\0";
            name[5] = b'0' + index / 10;
            name[6] = b'0' + index % 10;
            name
        })
        .collect();
    let links: Vec<Link> = names
        .iter()
        .enumerate()
        .map(|(index, name)| Link {
            index: index as i32 + 1,
            name: &name[..7],
            ..links()[1]
        })
        .collect();
    let view = View {
        links: &links,
        addresses: &[],
        routes: &[],
    };
    let datagrams = answer(
        &view,
        &mut Kernel::new(),
        &request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0], &[]),
        5,
    );
    assert!(datagrams.len() > 1);
    assert!(datagrams
        .iter()
        .all(|datagram| datagram.len() <= DATAGRAM_LIMIT));
    let found = messages(&datagrams);
    assert_eq!(found.len(), 101);
    assert_eq!(found[100].0, NLMSG_DONE);
}

#[test]
fn prefixes_match_by_bits() {
    assert!(Ip::V4([10, 0, 2, 200]).matches(Ip::V4([10, 0, 2, 0]), 24));
    assert!(!Ip::V4([10, 0, 3, 1]).matches(Ip::V4([10, 0, 2, 0]), 24));
    assert!(Ip::V4([10, 0, 3, 1]).matches(Ip::V4([10, 0, 2, 0]), 23));
    assert!(Ip::V4([1, 2, 3, 4]).matches(Ip::V4([0; 4]), 0));
    assert!(!Ip::V4([1, 2, 3, 4]).matches(Ip::V6([0; 16]), 0));
}

#[test]
fn the_kernel_adds_and_removes_addresses() {
    let lo = [AF_INET, 8, 0, 0, 1, 0, 0, 0];
    let add = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    let mut kernel = Kernel::new();
    kernel.address_result = Ok(());
    let found = run(
        &mut kernel,
        &request(RTM_NEWADDR, add, 1, &lo, &[(IFA_LOCAL, &[127, 0, 0, 2])]),
    );
    assert_eq!(error_of(&found[0]), 0);
    let found = run(
        &mut kernel,
        &request(
            RTM_DELADDR,
            NLM_F_REQUEST | NLM_F_ACK,
            2,
            &lo,
            &[(IFA_LOCAL, &[127, 0, 0, 1])],
        ),
    );
    assert_eq!(error_of(&found[0]), 0);
    assert_eq!(
        kernel.addresses,
        [
            (true, 1, Ip::V4([127, 0, 0, 2]), 8),
            (false, 1, Ip::V4([127, 0, 0, 1]), 8),
        ]
    );
    // Linux's own answers come first: the kernel is not asked.
    let mut kernel = Kernel::new();
    run(
        &mut kernel,
        &request(RTM_NEWADDR, add, 3, &lo, &[(IFA_LOCAL, &[127, 0, 0, 1])]),
    );
    run(
        &mut kernel,
        &request(
            RTM_DELADDR,
            NLM_F_REQUEST,
            4,
            &lo,
            &[(IFA_LOCAL, &[127, 0, 0, 9])],
        ),
    );
    assert!(kernel.addresses.is_empty());
}

#[test]
fn links_without_an_address_have_none() {
    let tun = Link {
        index: 3,
        name: b"tun0",
        kind: 65_534,
        address: None,
        broadcast: None,
        ..links()[1]
    };
    let view = View {
        links: &[tun],
        addresses: &[],
        routes: &[],
    };
    let found = messages(&answer(
        &view,
        &mut Kernel::new(),
        &request(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, &[0], &[]),
        5,
    ));
    assert_eq!(attribute(&found[0].4, 16, IFLA_ADDRESS), None);
    assert_eq!(attribute(&found[0].4, 16, IFLA_IFNAME).unwrap(), b"tun0\0");
}
