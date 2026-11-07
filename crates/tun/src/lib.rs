#![forbid(unsafe_code)]
//! TUN and TAP devices (/dev/net/tun), as Linux's drivers/net/tun.c
//! gives them, for a network stack that has one Ethernet interface.
//!
//! A TUN device is an IP interface whose far end is a process: what the
//! stack sends to it the process reads, one packet per read (after a
//! 4-byte packet information header unless IFF_NO_PI), and what the
//! process writes the stack receives. A TAP device is the same at the
//! Ethernet layer: whole frames.
//!
//! Ginux's stack (smoltcp) runs one Ethernet interface, so a device here is
//! a part of its traffic: the addresses given to a device join the
//! interface's, and [`Tun::egress`] takes the frames the stack sends that
//! belong to an up device, an IPv4 destination in one of its subnets or an
//! ARP exchange for one, and queues them for the device's readers. A TUN
//! device has no link layer, so the stack's ARP requests for its peers are
//! answered here, with the device's own made-up neighbour address. A TAP
//! device's frames carry the device's MAC address, in place of the
//! interface's, each way. [`Tun::write`] makes the frame the stack
//! receives from what a process writes.
//!
//! The rules of TUNSETIFF (making or attaching to a device, names with
//! `%d`, IFF_MULTI_QUEUE, the owner and group a device admits besides
//! CAP_NET_ADMIN), TUNSETPERSIST, TUNSETOWNER, TUNSETGROUP, TUNSETQUEUE and
//! TUNGETIFF follow Linux's. This is pure policy and byte work, tested on
//! the host; the kernel keeps the table and wires it to the stack.

#![no_std]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// TUNSETIFF flags (struct ifreq's ifr_flags).
pub const IFF_TUN: u16 = 0x0001;
pub const IFF_TAP: u16 = 0x0002;
pub const IFF_MULTI_QUEUE: u16 = 0x0100;
pub const IFF_ATTACH_QUEUE: u16 = 0x0200;
pub const IFF_DETACH_QUEUE: u16 = 0x0400;
pub const IFF_PERSIST: u16 = 0x0800;
pub const IFF_NO_PI: u16 = 0x1000;
/// TUNGETIFF's "no socket filter attached", the same bit as IFF_NO_PI.
pub const IFF_NOFILTER: u16 = 0x1000;
pub const IFF_ONE_QUEUE: u16 = 0x2000;
pub const IFF_TUN_EXCL: u16 = 0x8000;
/// The flags a device keeps from TUNSETIFF (Linux's TUN_FEATURES, less
/// IFF_VNET_HDR and the NAPI ones, which are not offered here).
const KEPT: u16 = IFF_NO_PI | IFF_ONE_QUEUE | IFF_MULTI_QUEUE;
/// TUNGETFEATURES: the flags TUNSETIFF takes.
pub const FEATURES: u32 = (IFF_TUN | IFF_TAP | KEPT) as u32;

/// The packet information header's flag for a packet cut short by a small
/// read (TUN_PKT_STRIP).
pub const TUN_PKT_STRIP: u16 = 0x0001;

/// Interface flags (IFF_* of if.h) a device shows.
pub const NETDEVICE_UP: u32 = 0x1;
pub const NETDEVICE_BROADCAST: u32 = 0x2;
pub const NETDEVICE_POINTOPOINT: u32 = 0x10;
pub const NETDEVICE_RUNNING: u32 = 0x40;
pub const NETDEVICE_NOARP: u32 = 0x80;
pub const NETDEVICE_MULTICAST: u32 = 0x1000;

/// The errno values the calls answer with.
pub const EPERM: i32 = 1;
pub const EIO: i32 = 5;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EINVAL: i32 = 22;
pub const EBADFD: i32 = 77;
pub const EADDRNOTAVAIL: i32 = 99;

/// The most packets a queue keeps for its reader (a device's default
/// transmit queue length); past it the stack's packets are dropped.
pub const QUEUE_LIMIT: usize = 1000;
/// The largest packet a write takes.
pub const PACKET_LIMIT: usize = 65_535;
/// The most bytes of a name, without its terminating NUL (IFNAMSIZ - 1).
pub const NAME_LIMIT: usize = 15;

const ETHERNET_HEADER: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// An interface name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name {
    bytes: [u8; 16],
    length: u8,
}

impl Name {
    /// `name` if it is a valid interface name (Linux's dev_valid_name):
    /// not empty, at most 15 bytes, not "." or "..", without '/', ':' or
    /// whitespace.
    pub fn new(name: &[u8]) -> Option<Self> {
        let valid = !name.is_empty()
            && name.len() <= NAME_LIMIT
            && name != b"."
            && name != b".."
            && !name
                .iter()
                .any(|byte| matches!(byte, b'/' | b':' | 0) || byte.is_ascii_whitespace());
        valid.then(|| {
            let mut bytes = [0; 16];
            bytes[..name.len()].copy_from_slice(name);
            Self {
                bytes,
                length: name.len() as u8,
            }
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// What a caller is, for the device permission checks.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    pub user: u32,
    pub group: u32,
    pub groups: &'a [u32],
    /// CAP_NET_ADMIN over the network namespace.
    pub administrator: bool,
}

impl Caller<'_> {
    fn in_group(&self, group: u32) -> bool {
        self.group == group || self.groups.contains(&group)
    }
}

/// An IPv4 address and prefix length a device has.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    pub address: [u8; 4],
    pub prefix: u8,
}

impl Address {
    fn mask(&self) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0)
    }

    /// Whether `address` is in this address's subnet.
    pub fn covers(&self, address: [u8; 4]) -> bool {
        u32::from_be_bytes(address) & self.mask() == u32::from_be_bytes(self.address) & self.mask()
    }
}

/// What a device TUNSETIFF makes gets: its interface index and MAC
/// address.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub index: i32,
    pub mac: [u8; 6],
}

/// A device.
#[derive(Clone, Debug)]
pub struct Device {
    pub name: Name,
    pub index: i32,
    pub tap: bool,
    flags: u16,
    persist: bool,
    owner: Option<u32>,
    group: Option<u32>,
    pub up: bool,
    pub mtu: u32,
    /// A TAP device's MAC address; a TUN device's made-up neighbour address
    /// (the stack's ARP requests for its peers get it).
    pub mac: [u8; 6],
    pub addresses: Vec<Address>,
    /// The files attached to it (its queues), in order.
    queues: Vec<u64>,
}

impl Device {
    /// The interface flags it shows: TUN devices are point-to-point without
    /// ARP, TAP ones broadcast; running while a queue is attached.
    pub fn interface_flags(&self) -> u32 {
        let kind = if self.tap {
            NETDEVICE_BROADCAST | NETDEVICE_MULTICAST
        } else {
            NETDEVICE_POINTOPOINT | NETDEVICE_NOARP | NETDEVICE_MULTICAST
        };
        let up = if self.up { NETDEVICE_UP } else { 0 };
        let running = if self.queues.is_empty() {
            0
        } else {
            NETDEVICE_RUNNING
        };
        kind | up | running
    }

    /// The flags TUNGETIFF reports.
    fn reported_flags(&self) -> u16 {
        let kind = if self.tap { IFF_TAP } else { IFF_TUN };
        kind | self.flags | if self.persist { IFF_PERSIST } else { 0 }
    }

    fn is_own(&self, address: [u8; 4]) -> bool {
        self.addresses.iter().any(|own| own.address == address)
    }

    fn subnet_covers(&self, address: [u8; 4]) -> bool {
        self.addresses.iter().any(|own| own.covers(address))
    }
}

/// An open /dev/net/tun.
#[derive(Debug)]
struct File {
    id: u64,
    /// The device it is attached to (by interface index), even while a
    /// TUNSETQUEUE detach keeps it out of the device's queues.
    device: Option<i32>,
    detached: bool,
    packets: VecDeque<Vec<u8>>,
}

/// What the stack's frame turned out to be (`Tun::egress`).
#[derive(Debug, Eq, PartialEq)]
pub enum Egress {
    /// Not a device's: send it on.
    Pass,
    /// To one of a device's own addresses: the stack receives it itself.
    Local,
    /// Taken (queued for a device's reader, or dropped for a device that
    /// is down or whose queues are full).
    Taken,
    /// An ARP request for a TUN device's peer: the stack receives this
    /// answer in its place.
    Answer(Vec<u8>),
}

/// What [`Tun::close`] did to the file's device.
#[derive(Debug, Eq, PartialEq)]
pub enum Closed {
    /// Nothing more: the device has other queues, or persists, or the file
    /// had none.
    Kept,
    /// The device went with its last queue: these were its addresses.
    Removed { index: i32, addresses: Vec<Address> },
}

/// The devices and open files of a network stack.
#[derive(Debug, Default)]
pub struct Tun {
    devices: Vec<Device>,
    files: Vec<File>,
    next_file: u64,
}

impl Tun {
    pub fn new() -> Self {
        Self::default()
    }

    /// A new open file's id.
    pub fn open(&mut self) -> Result<u64, i32> {
        self.files.try_reserve(1).map_err(|_| ENOMEM)?;
        self.next_file += 1;
        self.files.push(File {
            id: self.next_file,
            device: None,
            detached: false,
            packets: VecDeque::new(),
        });
        Ok(self.next_file)
    }

    /// Closes file `id`: its device loses the queue, and goes with its last
    /// one unless it persists.
    pub fn close(&mut self, id: u64) -> Closed {
        let Some(position) = self.files.iter().position(|file| file.id == id) else {
            return Closed::Kept;
        };
        let file = self.files.swap_remove(position);
        let Some(index) = file.device else {
            return Closed::Kept;
        };
        self.detach(index, id);
        self.remove_if_unused(index)
    }

    fn detach(&mut self, index: i32, id: u64) {
        if let Some(device) = self.device_mut(index) {
            device.queues.retain(|queue| *queue != id);
        }
    }

    /// Removes device `index` once nothing keeps it: no file attached
    /// (detached queues count) and not persistent.
    fn remove_if_unused(&mut self, index: i32) -> Closed {
        let used = self.files.iter().any(|file| file.device == Some(index));
        let Some(position) = self.devices.iter().position(|device| device.index == index) else {
            return Closed::Kept;
        };
        if used || self.devices[position].persist {
            return Closed::Kept;
        }
        let device = self.devices.remove(position);
        Closed::Removed {
            index,
            addresses: device.addresses,
        }
    }

    /// TUNSETIFF on file `id`: attaches it to the device `name` names, or
    /// makes one (named from `tun%d` or `tap%d` when `name` is empty; a
    /// `%d` takes the lowest free number). `taken` says whether another
    /// interface of the namespace has a name; `identity` is what a new
    /// device gets. Returns the
    /// device's name and flags, as TUNSETIFF writes them back.
    pub fn set_iff(
        &mut self,
        id: u64,
        name: &[u8],
        flags: u16,
        caller: &Caller,
        taken: &dyn Fn(&[u8]) -> bool,
        identity: Identity,
    ) -> Result<(Name, u16), i32> {
        let file = self.file(id)?;
        if file.device.is_some() {
            return Err(if file.detached { EINVAL } else { EEXIST });
        }
        let existing = (!name.is_empty())
            .then(|| {
                self.devices
                    .iter()
                    .position(|device| device.name.as_bytes() == name)
            })
            .flatten();
        if let Some(position) = existing {
            let device = &self.devices[position];
            if flags & IFF_TUN_EXCL != 0 {
                return Err(EBUSY);
            }
            let wanted_tap = match flags & (IFF_TUN | IFF_TAP) {
                IFF_TUN => false,
                IFF_TAP => true,
                _ => return Err(EINVAL),
            };
            if wanted_tap != device.tap
                || (flags & IFF_MULTI_QUEUE != 0) != (device.flags & IFF_MULTI_QUEUE != 0)
            {
                return Err(EINVAL);
            }
            let refused = (device.owner.is_some_and(|owner| owner != caller.user)
                || device.group.is_some_and(|group| !caller.in_group(group)))
                && !caller.administrator;
            if refused {
                return Err(EPERM);
            }
            if device.flags & IFF_MULTI_QUEUE == 0 && !device.queues.is_empty() {
                return Err(EBUSY);
            }
            let device = &mut self.devices[position];
            // The first queue sets the device's flags; more of a
            // multi-queue device take them as they are.
            if device.queues.is_empty() {
                device.flags = flags & KEPT;
            }
            device.queues.try_reserve(1).map_err(|_| ENOMEM)?;
            device.queues.push(id);
            let (name, reported, index) = (device.name, device.reported_flags(), device.index);
            self.attach_file(id, index);
            return Ok((name, reported));
        }
        if !caller.administrator {
            return Err(EPERM);
        }
        let tap = match (flags & IFF_TUN != 0, flags & IFF_TAP != 0) {
            (true, _) => false,
            (false, true) => true,
            (false, false) => return Err(EINVAL),
        };
        let pattern: &[u8] = if !name.is_empty() {
            name
        } else if tap {
            b"tap%d"
        } else {
            b"tun%d"
        };
        let name = self.allocate_name(pattern, taken)?;
        if taken(name.as_bytes()) || self.devices.iter().any(|device| device.name == name) {
            return Err(EEXIST);
        }
        self.devices.try_reserve(1).map_err(|_| ENOMEM)?;
        let mut queues = Vec::new();
        queues.try_reserve(1).map_err(|_| ENOMEM)?;
        queues.push(id);
        let Identity { index, mac } = identity;
        let device = Device {
            name,
            index,
            tap,
            flags: flags & KEPT,
            persist: false,
            owner: None,
            group: None,
            up: false,
            mtu: 1500,
            mac,
            addresses: Vec::new(),
            queues,
        };
        let reported = device.reported_flags();
        self.devices.push(device);
        self.attach_file(id, index);
        Ok((name, reported))
    }

    fn attach_file(&mut self, id: u64, index: i32) {
        if let Some(file) = self.files.iter_mut().find(|file| file.id == id) {
            file.device = Some(index);
            file.detached = false;
        }
    }

    /// `pattern` as a name: itself, or with its one `%d` replaced by the
    /// lowest number no interface has (EINVAL for an invalid name, or
    /// more than one `%`).
    fn allocate_name(&self, pattern: &[u8], taken: &dyn Fn(&[u8]) -> bool) -> Result<Name, i32> {
        let percent = pattern.iter().filter(|byte| **byte == b'%').count();
        if percent == 0 {
            return Name::new(pattern).ok_or(EINVAL);
        }
        let at = pattern.windows(2).position(|pair| pair == b"%d");
        let (Some(at), 1) = (at, percent) else {
            return Err(EINVAL);
        };
        for number in 0..32_768_u32 {
            let mut buffer = [0_u8; 24];
            let mut length = 0;
            for byte in &pattern[..at] {
                buffer[length] = *byte;
                length += 1;
                if length > NAME_LIMIT {
                    return Err(EINVAL);
                }
            }
            let mut digits = [0_u8; 5];
            let mut count = 0;
            let mut value = number;
            loop {
                digits[count] = b'0' + (value % 10) as u8;
                count += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            for digit in digits[..count].iter().rev().chain(&pattern[at + 2..]) {
                if length >= buffer.len() {
                    return Err(EINVAL);
                }
                buffer[length] = *digit;
                length += 1;
            }
            let name = Name::new(&buffer[..length]).ok_or(EINVAL)?;
            if !taken(name.as_bytes()) && !self.devices.iter().any(|device| device.name == name) {
                return Ok(name);
            }
        }
        Err(EINVAL)
    }

    /// TUNGETIFF: the attached device's name and flags (IFF_DETACH_QUEUE
    /// for a detached queue; IFF_NOFILTER, as no filter is ever set).
    pub fn get_iff(&self, id: u64) -> Result<(Name, u16), i32> {
        let file = self.file(id)?;
        let device = file
            .device
            .and_then(|index| self.device(index))
            .ok_or(EBADFD)?;
        let detached = if file.detached { IFF_DETACH_QUEUE } else { 0 };
        Ok((
            device.name,
            device.reported_flags() | detached | IFF_NOFILTER,
        ))
    }

    /// TUNSETPERSIST: whether the device outlasts its last queue.
    pub fn set_persist(&mut self, id: u64, persist: bool) -> Result<(), i32> {
        self.attached_mut(id)?.persist = persist;
        Ok(())
    }

    /// TUNSETOWNER: the user (besides CAP_NET_ADMIN) that may attach (-1:
    /// none set). EINVAL for a user id that is no valid one.
    pub fn set_owner(&mut self, id: u64, owner: u32) -> Result<(), i32> {
        if owner == u32::MAX {
            return Err(EINVAL);
        }
        self.attached_mut(id)?.owner = Some(owner);
        Ok(())
    }

    /// TUNSETGROUP: the group (besides CAP_NET_ADMIN) whose members may
    /// attach.
    pub fn set_group(&mut self, id: u64, group: u32) -> Result<(), i32> {
        if group == u32::MAX {
            return Err(EINVAL);
        }
        self.attached_mut(id)?.group = Some(group);
        Ok(())
    }

    /// TUNSETQUEUE: IFF_DETACH_QUEUE takes a multi-queue device's file out
    /// of its queues (it keeps the device), IFF_ATTACH_QUEUE puts it back
    /// (with the attach permission check); EINVAL otherwise.
    pub fn set_queue(&mut self, id: u64, flags: u16, caller: &Caller) -> Result<(), i32> {
        let file = self.file(id)?;
        let index = file.device.ok_or(EINVAL)?;
        let detached = file.detached;
        let device = self.device(index).ok_or(EINVAL)?;
        if device.flags & IFF_MULTI_QUEUE == 0 {
            return Err(EINVAL);
        }
        let refused = (device.owner.is_some_and(|owner| owner != caller.user)
            || device.group.is_some_and(|group| !caller.in_group(group)))
            && !caller.administrator;
        match flags & (IFF_ATTACH_QUEUE | IFF_DETACH_QUEUE) {
            IFF_ATTACH_QUEUE if detached => {
                if refused {
                    return Err(EPERM);
                }
                let device = self.device_mut(index).ok_or(EINVAL)?;
                device.queues.try_reserve(1).map_err(|_| ENOMEM)?;
                device.queues.push(id);
                self.file_mut(id)?.detached = false;
                Ok(())
            }
            IFF_DETACH_QUEUE if !detached => {
                self.detach(index, id);
                self.file_mut(id)?.detached = true;
                Ok(())
            }
            _ => Err(EINVAL),
        }
    }

    /// Reads the next packet of file `id` into `output`: with packet
    /// information unless IFF_NO_PI (EINVAL when even that does not fit),
    /// cut to `output` (flagged TUN_PKT_STRIP in the information). EBADFD
    /// for a file with no device, EAGAIN with nothing to read.
    pub fn read(&mut self, id: u64, output: &mut [u8]) -> Result<usize, i32> {
        let file = self.file(id)?;
        let index = file.device.ok_or(EBADFD)?;
        let device = self.device(index).ok_or(EBADFD)?;
        let information = device.flags & IFF_NO_PI == 0;
        let tap = device.tap;
        if information && output.len() < 4 {
            return Err(EINVAL);
        }
        let file = self.file_mut(id)?;
        let packet = file.packets.pop_front().ok_or(EAGAIN)?;
        let mut written = 0;
        if information {
            let protocol = if tap {
                0
            } else {
                match packet.first().map(|byte| byte >> 4) {
                    Some(6) => ETHERTYPE_IPV6,
                    _ => ETHERTYPE_IPV4,
                }
            };
            let strip = if packet.len() > output.len() - 4 {
                TUN_PKT_STRIP
            } else {
                0
            };
            output[..2].copy_from_slice(&strip.to_ne_bytes());
            output[2..4].copy_from_slice(&protocol.to_be_bytes());
            written = 4;
        }
        let copied = packet.len().min(output.len() - written);
        output[written..written + copied].copy_from_slice(&packet[..copied]);
        Ok(written + copied)
    }

    /// Whether file `id` has a packet to read (None for no such file).
    pub fn readable(&self, id: u64) -> Option<bool> {
        self.files
            .iter()
            .find(|file| file.id == id)
            .map(|file| !file.packets.is_empty())
    }

    /// The frame the stack receives for what file `id` writes: a TUN
    /// packet (after its packet information, unless IFF_NO_PI) in an
    /// Ethernet header from the device's neighbour address to `interface`,
    /// or a TAP frame with the device's MAC address, as its destination,
    /// changed to `interface`'s. EBADFD with no device, EIO while it is
    /// down, EINVAL for a packet too short or too long.
    pub fn write(&self, id: u64, input: &[u8], interface: [u8; 6]) -> Result<Vec<u8>, i32> {
        let file = self.file(id)?;
        let device = file
            .device
            .and_then(|index| self.device(index))
            .ok_or(EBADFD)?;
        if !device.up {
            return Err(EIO);
        }
        let information = device.flags & IFF_NO_PI == 0;
        let (protocol, packet) = if information {
            if input.len() < 4 {
                return Err(EINVAL);
            }
            (Some(u16::from_be_bytes([input[2], input[3]])), &input[4..])
        } else {
            (None, input)
        };
        if packet.len() > PACKET_LIMIT {
            return Err(EINVAL);
        }
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(ETHERNET_HEADER + packet.len())
            .map_err(|_| ENOMEM)?;
        if device.tap {
            if packet.len() < ETHERNET_HEADER {
                return Err(EINVAL);
            }
            frame.extend_from_slice(packet);
            if frame[..6] == device.mac {
                frame[..6].copy_from_slice(&interface);
            }
            return Ok(frame);
        }
        let ethertype = match protocol {
            Some(protocol) => protocol,
            None => match packet.first().map(|byte| byte >> 4) {
                Some(4) => ETHERTYPE_IPV4,
                Some(6) => ETHERTYPE_IPV6,
                _ => return Err(EINVAL),
            },
        };
        if packet.is_empty() {
            return Err(EINVAL);
        }
        frame.extend_from_slice(&interface);
        frame.extend_from_slice(&device.mac);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(packet);
        Ok(frame)
    }

    /// Sorts a frame the stack sends (from `interface`, the stack's MAC
    /// address): to a device's own address it stays local; to a peer in an
    /// up device's subnet it is queued for the device's reader (an IPv4
    /// packet for TUN, the frame for TAP), or dropped while the device is
    /// down; an ARP request for a TUN peer is answered with the device's
    /// neighbour address, one for a TAP peer goes to its reader.
    pub fn egress(&mut self, frame: &[u8], interface: [u8; 6]) -> Egress {
        let Some(ethertype) = frame
            .get(12..14)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        else {
            return Egress::Pass;
        };
        match ethertype {
            ETHERTYPE_IPV4 => {
                let Some(destination) = frame
                    .get(30..34)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                else {
                    return Egress::Pass;
                };
                if self.devices.iter().any(|device| device.is_own(destination)) {
                    return Egress::Local;
                }
                let Some(position) = self
                    .devices
                    .iter()
                    .position(|device| device.subnet_covers(destination))
                else {
                    return Egress::Pass;
                };
                let device = &self.devices[position];
                if !device.up {
                    return Egress::Taken;
                }
                if device.tap {
                    let mut copy = frame.to_vec();
                    copy[6..12].copy_from_slice(&device.mac);
                    self.queue(position, copy, frame);
                } else {
                    self.queue(position, frame[ETHERNET_HEADER..].to_vec(), frame);
                }
                Egress::Taken
            }
            ETHERTYPE_ARP => self.arp(frame, interface),
            _ => Egress::Pass,
        }
    }

    /// An ARP frame the stack sends: about a device's own address it stays
    /// local; a request for a TUN peer is answered; a request or answer to
    /// a TAP peer goes to its reader, with the device's MAC address.
    fn arp(&mut self, frame: &[u8], interface: [u8; 6]) -> Egress {
        // Ethernet/IPv4 ARP: operation at 20, sender at 22 (hardware) and
        // 28 (protocol), target at 32 and 38.
        let (Some(operation), Some(target)) = (
            frame
                .get(20..22)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]])),
            frame
                .get(38..42)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok()),
        ) else {
            return Egress::Pass;
        };
        if self.devices.iter().any(|device| device.is_own(target)) {
            return Egress::Local;
        }
        let Some(position) = self
            .devices
            .iter()
            .position(|device| device.subnet_covers(target))
        else {
            return Egress::Pass;
        };
        let device = &self.devices[position];
        if !device.up {
            return Egress::Taken;
        }
        if device.tap {
            let mut copy = frame.to_vec();
            copy[6..12].copy_from_slice(&device.mac);
            if copy[22..28] == interface {
                copy[22..28].copy_from_slice(&device.mac);
            }
            self.queue(position, copy, frame);
            return Egress::Taken;
        }
        // A TUN device has no neighbours to ask: its peers are at its
        // neighbour address, as far as the stack can tell.
        if operation != 1 || frame.len() < 42 {
            return Egress::Taken;
        }
        let mut answer = Vec::with_capacity(42);
        answer.extend_from_slice(&frame[6..12]);
        answer.extend_from_slice(&device.mac);
        answer.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        answer.extend_from_slice(&frame[14..20]);
        answer.extend_from_slice(&2_u16.to_be_bytes());
        answer.extend_from_slice(&device.mac);
        answer.extend_from_slice(&target);
        answer.extend_from_slice(&frame[22..28]);
        answer.extend_from_slice(&frame[28..32]);
        Egress::Answer(answer)
    }

    /// Queues `packet` on one of device `position`'s queues: the only one,
    /// or for a multi-queue device the one a hash of the frame's addresses
    /// picks, so a flow stays on one queue.
    fn queue(&mut self, position: usize, packet: Vec<u8>, frame: &[u8]) {
        let device = &self.devices[position];
        if device.queues.is_empty() {
            return;
        }
        let hash = frame
            .get(26..34)
            .unwrap_or(&[])
            .iter()
            .fold(0_u32, |hash, byte| hash.rotate_left(5) ^ u32::from(*byte));
        let queue = device.queues[hash as usize % device.queues.len()];
        if let Some(file) = self.files.iter_mut().find(|file| file.id == queue) {
            if file.packets.len() < QUEUE_LIMIT && file.packets.try_reserve(1).is_ok() {
                file.packets.push_back(packet);
            }
        }
    }

    /// The devices, by interface index.
    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    /// Brings device `index` up or down and sets its MTU (68 to 65535),
    /// each when given.
    pub fn set_link(&mut self, index: i32, up: Option<bool>, mtu: Option<u32>) -> Result<(), i32> {
        if mtu.is_some_and(|mtu| !(68..=65_535).contains(&mtu)) {
            return Err(EINVAL);
        }
        let device = self.device_mut(index).ok_or(EINVAL)?;
        if let Some(up) = up {
            device.up = up;
            if !up {
                for file in self
                    .files
                    .iter_mut()
                    .filter(|file| file.device == Some(index))
                {
                    file.packets.clear();
                }
            }
        }
        if let Some(mtu) = mtu {
            if let Some(device) = self.device_mut(index) {
                device.mtu = mtu;
            }
        }
        Ok(())
    }

    /// Gives device `index` an IPv4 address (EEXIST if it has it).
    pub fn add_address(&mut self, index: i32, address: Address) -> Result<(), i32> {
        if address.prefix > 32 {
            return Err(EINVAL);
        }
        let device = self.device_mut(index).ok_or(EINVAL)?;
        if device
            .addresses
            .iter()
            .any(|own| own.address == address.address)
        {
            return Err(EEXIST);
        }
        device.addresses.try_reserve(1).map_err(|_| ENOMEM)?;
        device.addresses.push(address);
        Ok(())
    }

    /// Takes IPv4 address `address` from device `index` (EADDRNOTAVAIL if
    /// it has not got it).
    pub fn remove_address(&mut self, index: i32, address: Address) -> Result<(), i32> {
        let device = self.device_mut(index).ok_or(EINVAL)?;
        let before = device.addresses.len();
        device
            .addresses
            .retain(|own| !(own.address == address.address && own.prefix == address.prefix));
        if device.addresses.len() == before {
            return Err(EADDRNOTAVAIL);
        }
        Ok(())
    }

    fn file(&self, id: u64) -> Result<&File, i32> {
        self.files.iter().find(|file| file.id == id).ok_or(EBADFD)
    }

    fn file_mut(&mut self, id: u64) -> Result<&mut File, i32> {
        self.files
            .iter_mut()
            .find(|file| file.id == id)
            .ok_or(EBADFD)
    }

    fn device(&self, index: i32) -> Option<&Device> {
        self.devices.iter().find(|device| device.index == index)
    }

    fn device_mut(&mut self, index: i32) -> Option<&mut Device> {
        self.devices.iter_mut().find(|device| device.index == index)
    }

    fn attached_mut(&mut self, id: u64) -> Result<&mut Device, i32> {
        let index = self.file(id)?.device.ok_or(EBADFD)?;
        self.device_mut(index).ok_or(EBADFD)
    }
}

#[cfg(test)]
mod tests;
