//! NETLINK_ROUTE sockets: what `ip addr`, `ip link` and `ip route` ask.
//!
//! A request sent on a NETLINK_ROUTE socket is answered at once from the
//! sender's network namespace, by `ginux_rtnetlink`, and the answers wait
//! on the socket for its reader. The namespace the domain starts in has the
//! domain's loopback and eth0, with eth0's IPv4 address, its subnet and
//! default route, and IPv6 loopback; a network namespace made inside it has
//! its own loopback, which carries 127.0.0.0/8 and ::1 while it is up. Links
//! change as SIOCSIFFLAGS and SIOCSIFMTU change them: a namespace's
//! loopback goes up and down and takes another MTU; the domain's own
//! interfaces stay as the kernel set them up (EOPNOTSUPP). TUN and TAP
//! devices (`linux_socket::tun_*`) are links like any other: they go up
//! and down, take another MTU, and are given and lose IPv4 addresses,
//! whose subnet routes follow while they are up. Other addresses and
//! routes are not added or removed. Linux also tells RTNLGRP_* listeners
//! about changes; nothing is sent to them here.

use super::*;

use ginux_rtnetlink as rtnetlink;

/// NETLINK_ROUTE's protocol number.
pub(super) const LINUX_NETLINK_ROUTE: u8 = 0;

/// The links of the caller's network namespace.
struct Links {
    interfaces: Vec<crate::linux_socket::InterfaceInfo>,
}

impl Links {
    fn current() -> Self {
        Self {
            interfaces: linux_network_interfaces(),
        }
    }

    fn links(&self) -> Vec<rtnetlink::Link<'_>> {
        const ARPHRD_ETHER: u16 = 1;
        const ARPHRD_NONE: u16 = 65_534;
        self.interfaces
            .iter()
            .map(|interface| {
                let ethernet = interface.hardware.0 == ARPHRD_ETHER;
                let hardware = interface.hardware.0 != ARPHRD_NONE;
                rtnetlink::Link {
                    index: interface.index,
                    name: interface.name.as_bytes(),
                    kind: interface.hardware.0,
                    flags: u32::from(interface.flags),
                    mtu: interface.mtu as u32,
                    min_mtu: 68,
                    max_mtu: if ethernet { 65_535 } else { 65_536 },
                    address: hardware.then_some(interface.hardware.1),
                    broadcast: hardware.then_some(if ethernet { [0xff; 6] } else { [0; 6] }),
                    txqlen: if interface.tun { 500 } else { 1000 },
                    qdisc: if interface.tun {
                        b"fq_codel"
                    } else if ethernet {
                        b"pfifo_fast"
                    } else {
                        b"noqueue"
                    },
                }
            })
            .collect()
    }

    /// Each interface's IPv4 addresses with prefix lengths.
    fn ipv4(
        interface: &crate::linux_socket::InterfaceInfo,
    ) -> impl Iterator<Item = (u32, u8)> + '_ {
        core::iter::once((interface.ipv4, interface.prefix))
            .filter(|(address, _)| *address != 0)
            .chain(interface.more_ipv4.iter().copied())
    }

    /// The addresses: each link's IPv4 one (127.0.0.1/8 on a loopback that
    /// is up), and ::1 on an up loopback.
    fn addresses(&self) -> Vec<rtnetlink::Address> {
        let mut addresses = Vec::new();
        for interface in &self.interfaces {
            let loopback = interface.flags & LINUX_IFF_LOOPBACK != 0;
            for (address, prefix) in Self::ipv4(interface) {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                addresses.push(rtnetlink::Address {
                    index: interface.index,
                    address: rtnetlink::Ip::V4(address.to_be_bytes()),
                    prefix,
                    scope: if loopback {
                        rtnetlink::RT_SCOPE_HOST
                    } else {
                        rtnetlink::RT_SCOPE_UNIVERSE
                    },
                    broadcast: (!loopback && prefix < 31).then(|| (address | !mask).to_be_bytes()),
                });
            }
        }
        if let Some(loopback) = self.up_loopback() {
            addresses.push(rtnetlink::Address {
                index: loopback.index,
                address: rtnetlink::Ip::V6(IPV6_LOOPBACK),
                prefix: 128,
                scope: rtnetlink::RT_SCOPE_HOST,
                broadcast: None,
            });
        }
        addresses
    }

    fn up_loopback(&self) -> Option<&crate::linux_socket::InterfaceInfo> {
        self.interfaces.iter().find(|interface| {
            interface.flags & LINUX_IFF_LOOPBACK != 0 && interface.flags & LINUX_IFF_UP != 0
        })
    }

    /// The routes Linux would hold for these addresses: the main table's
    /// subnet and default routes (eth0) and IPv6 loopback, and the local
    /// table's local and broadcast routes.
    fn routes(&self) -> Vec<rtnetlink::Route> {
        let mut routes = Vec::new();
        let route = |table, kind, protocol, scope, destination, length, output| rtnetlink::Route {
            table,
            kind,
            protocol,
            scope,
            destination,
            destination_length: length,
            gateway: None,
            output,
            source: None,
            priority: None,
        };
        let v4 = |address: u32| rtnetlink::Ip::V4(address.to_be_bytes());
        // A link's routes are there while it is up (the domain's always
        // are; a TUN or TAP device's follow it).
        for (interface, (address, prefix)) in self
            .interfaces
            .iter()
            .filter(|interface| interface.flags & LINUX_IFF_UP != 0)
            .flat_map(|interface| Self::ipv4(interface).map(move |pair| (interface, pair)))
        {
            let index = interface.index;
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            let loopback = interface.flags & LINUX_IFF_LOOPBACK != 0;
            let source = Some(v4(address));
            if !loopback {
                let gateway = crate::network::ipv4_gateway() as u32;
                if gateway != 0 && !interface.tun {
                    routes.push(rtnetlink::Route {
                        gateway: Some(v4(gateway)),
                        ..route(
                            rtnetlink::RT_TABLE_MAIN,
                            rtnetlink::RTN_UNICAST,
                            rtnetlink::RTPROT_BOOT,
                            rtnetlink::RT_SCOPE_UNIVERSE,
                            v4(0),
                            0,
                            index,
                        )
                    });
                }
                routes.push(rtnetlink::Route {
                    source,
                    ..route(
                        rtnetlink::RT_TABLE_MAIN,
                        rtnetlink::RTN_UNICAST,
                        rtnetlink::RTPROT_KERNEL,
                        rtnetlink::RT_SCOPE_LINK,
                        v4(address & mask),
                        prefix,
                        index,
                    )
                });
            } else {
                // The loopback's whole prefix is local.
                routes.push(rtnetlink::Route {
                    source,
                    ..route(
                        rtnetlink::RT_TABLE_LOCAL,
                        rtnetlink::RTN_LOCAL,
                        rtnetlink::RTPROT_KERNEL,
                        rtnetlink::RT_SCOPE_HOST,
                        v4(address & mask),
                        prefix,
                        index,
                    )
                });
            }
            routes.push(rtnetlink::Route {
                source,
                ..route(
                    rtnetlink::RT_TABLE_LOCAL,
                    rtnetlink::RTN_LOCAL,
                    rtnetlink::RTPROT_KERNEL,
                    rtnetlink::RT_SCOPE_HOST,
                    v4(address),
                    32,
                    index,
                )
            });
            if prefix < 31 {
                routes.push(rtnetlink::Route {
                    source,
                    ..route(
                        rtnetlink::RT_TABLE_LOCAL,
                        rtnetlink::RTN_BROADCAST,
                        rtnetlink::RTPROT_KERNEL,
                        rtnetlink::RT_SCOPE_LINK,
                        v4(address | !mask),
                        32,
                        index,
                    )
                });
            }
        }
        if let Some(loopback) = self.up_loopback() {
            let ipv6 = rtnetlink::Ip::V6(IPV6_LOOPBACK);
            routes.push(rtnetlink::Route {
                priority: Some(256),
                ..route(
                    rtnetlink::RT_TABLE_MAIN,
                    rtnetlink::RTN_UNICAST,
                    rtnetlink::RTPROT_KERNEL,
                    rtnetlink::RT_SCOPE_UNIVERSE,
                    ipv6,
                    128,
                    loopback.index,
                )
            });
            routes.push(rtnetlink::Route {
                priority: Some(0),
                ..route(
                    rtnetlink::RT_TABLE_LOCAL,
                    rtnetlink::RTN_LOCAL,
                    rtnetlink::RTPROT_KERNEL,
                    rtnetlink::RT_SCOPE_HOST,
                    ipv6,
                    128,
                    loopback.index,
                )
            });
        }
        routes
    }
}

/// ::1.
const IPV6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// IFF_LOOPBACK.
const LINUX_IFF_LOOPBACK: u16 = 0x8;

/// The kernel's side of a request: the sender's rights, and the changes a
/// namespace's loopback and TUN and TAP devices take.
struct Namespace<'a> {
    interfaces: &'a [crate::linux_socket::InterfaceInfo],
}

impl Namespace<'_> {
    /// Whether link `index` is a TUN or TAP device.
    fn tun(&self, index: i32) -> bool {
        self.interfaces
            .iter()
            .any(|interface| interface.index == index && interface.tun)
    }
}

impl rtnetlink::Network for Namespace<'_> {
    fn administrator(&self) -> bool {
        current_linux_credentials()
            .is_some_and(|credentials| credentials.has(ginux_credentials::capability::NET_ADMIN))
    }

    fn change_link(&mut self, change: rtnetlink::LinkChange) -> Result<(), i32> {
        if self.tun(change.index) {
            return crate::linux_socket::tun_set_link(
                change.index,
                change.flags.map(|flags| flags & rtnetlink::IFF_UP != 0),
                change.mtu,
            );
        }
        let network = current_linux_namespaces().net;
        // Only a network namespace's own loopback (index 1) changes.
        if network == 0 || change.index != 1 {
            return Err(rtnetlink::EOPNOTSUPP);
        }
        let changed =
            linux_namespace::set_loopback(linux_execution_instance(), network, |loopback| {
                if let Some(flags) = change.flags {
                    loopback.up = flags & rtnetlink::IFF_UP != 0;
                }
                if let Some(mtu) = change.mtu {
                    loopback.mtu = mtu as i32;
                }
            });
        if changed {
            Ok(())
        } else {
            Err(rtnetlink::ENODEV)
        }
    }

    /// Only a TUN or TAP device takes IPv4 addresses.
    fn add_address(&mut self, index: i32, address: rtnetlink::Ip, prefix: u8) -> Result<(), i32> {
        match address {
            rtnetlink::Ip::V4(address) if self.tun(index) => {
                crate::linux_socket::tun_change_address(index, address, prefix, true)
            }
            _ => Err(rtnetlink::EOPNOTSUPP),
        }
    }

    fn remove_address(
        &mut self,
        index: i32,
        address: rtnetlink::Ip,
        prefix: u8,
    ) -> Result<(), i32> {
        match address {
            rtnetlink::Ip::V4(address) if self.tun(index) => {
                crate::linux_socket::tun_change_address(index, address, prefix, false)
            }
            _ => Err(rtnetlink::EOPNOTSUPP),
        }
    }
}

/// Whether socket `slot` is a NETLINK_ROUTE one.
pub(super) fn linux_rtnetlink_socket(slot: crate::linux_socket::SlotId) -> bool {
    crate::linux_socket::netlink_address(slot)
        .is_some_and(|(protocol, _)| protocol == LINUX_NETLINK_ROUTE)
}

/// Sends `payload` on NETLINK_ROUTE socket `slot`: its requests' answers
/// are queued for the socket's reader. An unbound socket is bound to a
/// port id first, as Linux binds one on its first send.
pub(super) fn linux_rtnetlink_send(
    slot: crate::linux_socket::SlotId,
    payload: &[u8],
) -> Result<usize, crate::linux_socket::Error> {
    let port = match crate::linux_socket::netlink_address(slot) {
        Some((_, 0)) => crate::linux_socket::bind_netlink(slot, 0, current_linux_process_pid())?,
        Some((_, port)) => port,
        None => return Err(crate::linux_socket::Error::Invalid),
    };
    let current = Links::current();
    let (links, addresses, routes) = (current.links(), current.addresses(), current.routes());
    let view = rtnetlink::View {
        links: &links,
        addresses: &addresses,
        routes: &routes,
    };
    let mut namespace = Namespace {
        interfaces: &current.interfaces,
    };
    for datagram in rtnetlink::answer(&view, &mut namespace, payload, port) {
        // A reader that does not keep up loses answers, as Linux drops
        // them (its reader sees ENOBUFS).
        if !crate::linux_socket::deliver_netlink(slot, &datagram) {
            break;
        }
    }
    Ok(payload.len())
}
