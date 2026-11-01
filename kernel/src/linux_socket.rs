//! Sockets and pipes of Linux processes: TCP and UDP through smoltcp over
//! the domain's virtio network device, and local streams (pipes,
//! socketpairs, Unix sockets and TCP connections between the interface's
//! own addresses) whose bytes stay in the kernel.
//!
//! Every socket lives in one table that grows as sockets open, as Linux's
//! file table does; a socket's id is its index there, which descriptors
//! store, and a closed socket's entry is reused. The table, smoltcp's state
//! and the device sit behind one lock, ranked below the kernel heap so that
//! the table, queues and socket buffers can grow while it is held. Calls
//! that wait take the lock once per attempt, so others run in between.
//!
//! Files that are not sockets travel through SCM_RIGHTS as file rights,
//! queued with ids from `FILE_RIGHT_BASE` up, so that a queue of rights
//! holds sockets and files alike.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod virtio_net;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::{Duration, Instant},
    wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};

use crate::{
    arch::x86_64::{
        iommu::DeviceTranslationProfile,
        paging::MmioMapping,
        pci::{VirtioNetworkDevice, VirtioNetworkInitialization},
    },
    network,
    sync::{LockRank, SpinLock},
};
use virtio_net::{VirtioNet, LOOPBACK_FRAME_COUNT};

/// A socket's id: its index in the table. Descriptors store it plus one,
/// with 0 for no socket.
pub(crate) type SlotId = u16;

/// Ids from here up name file rights; sockets take the ids below.
const FILE_RIGHT_BASE: usize = 0xf000;
/// File rights in flight at once: their ids, plus one, still fit a `SlotId`.
const FILE_RIGHT_LIMIT: usize = SlotId::MAX as usize - FILE_RIGHT_BASE;
const UNIX_PATH_CAPACITY: usize = 108;
/// Rights one SCM_RIGHTS message carries.
pub(crate) const PASSED_RIGHT_LIMIT: usize = 64;
/// Credentials (SCM_CREDENTIALS) a Unix socket holds for its reader.
const CREDENTIAL_QUEUE_LIMIT: usize = 64;
/// The longest accept queue: Linux's default `somaxconn`.
const BACKLOG_LIMIT: usize = 4096;
const TCP_BUFFER_SIZE: usize = 64 * 1024;
const UDP_BUFFER_SIZE: usize = 16 * 1024;
const UDP_PACKET_COUNT: usize = 16;
const BLOCKING_POLL_LIMIT: usize = 20_000;
/// Bytes a local stream (a pipe or a socketpair) queues for a writer that
/// must not block: Linux's default pipe capacity. A blocking writer is not
/// held to it yet, because it cannot wait for its reader to run.
const LOCAL_QUEUE_CAPACITY: usize = 64 * 1024;
/// Writes up to this size go into a local queue whole or not at all.
const LOCAL_ATOMIC_WRITE: usize = 4096;
/// Local queues hold their bytes in chunks of this size.
const LOCAL_CHUNK: usize = 4096;
const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy)]
struct Platform {
    device: VirtioNetworkDevice,
    initialization: VirtioNetworkInitialization,
    common: MmioMapping,
    notification: MmioMapping,
    iommu: DeviceTranslationProfile,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Kind {
    Tcp,
    Udp,
    Unix,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Error {
    Unavailable,
    Exhausted,
    AddressInUse,
    AddressNotAvailable,
    Invalid,
    InProgress,
    WouldBlock,
    NotConnected,
    BrokenPipe,
    Reset,
}

#[derive(Clone, Copy)]
pub(crate) enum BooleanOption {
    ReuseAddress,
    KeepAlive,
    ReceiveErrors,
    NoDelay,
    PassCredentials,
    Timestamp,
}

#[derive(Clone, Copy)]
pub(crate) enum TimeoutOption {
    Receive,
    Send,
}

/// Socket options, which an accepted socket takes from its listener.
#[derive(Clone, Copy, Default)]
struct Options {
    reuse_address: bool,
    keep_alive: bool,
    receive_errors: bool,
    no_delay: bool,
    pass_credentials: bool,
    timestamp: bool,
    receive_timeout_us: u64,
    send_timeout_us: u64,
}

/// The bytes a local stream holds for its reader, in chunks taken from the
/// heap as they fill and returned as they drain.
#[derive(Default)]
struct LocalQueue {
    chunks: VecDeque<Vec<u8>>,
    /// Where reading resumes in the first chunk.
    head: usize,
    length: usize,
}

impl LocalQueue {
    fn len(&self) -> usize {
        self.length
    }

    fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Appends as much of `input` as memory allows and says how much.
    fn push(&mut self, input: &[u8]) -> usize {
        let mut rest = input;
        if let Some(tail) = self.chunks.back_mut() {
            let fits = rest.len().min(LOCAL_CHUNK.saturating_sub(tail.len()));
            tail.extend_from_slice(&rest[..fits]);
            rest = &rest[fits..];
        }
        while !rest.is_empty() {
            let mut chunk = Vec::new();
            if chunk.try_reserve_exact(LOCAL_CHUNK).is_err() || self.chunks.try_reserve(1).is_err()
            {
                break;
            }
            let fits = rest.len().min(LOCAL_CHUNK);
            chunk.extend_from_slice(&rest[..fits]);
            self.chunks.push_back(chunk);
            rest = &rest[fits..];
        }
        let queued = input.len() - rest.len();
        self.length += queued;
        queued
    }

    /// Copies the first bytes into `output` without removing them.
    fn peek(&self, output: &mut [u8]) -> usize {
        let mut copied = 0;
        let mut head = self.head;
        for chunk in &self.chunks {
            if copied == output.len() {
                break;
            }
            let bytes = &chunk[head..];
            let amount = bytes.len().min(output.len() - copied);
            output[copied..copied + amount].copy_from_slice(&bytes[..amount]);
            copied += amount;
            head = 0;
        }
        copied
    }

    /// Moves the first bytes into `output`.
    fn pop(&mut self, output: &mut [u8]) -> usize {
        let copied = self.peek(output);
        let mut rest = copied;
        while rest != 0 {
            let Some(front) = self.chunks.front() else {
                break;
            };
            let available = front.len() - self.head;
            if rest < available {
                self.head += rest;
                break;
            }
            rest -= available;
            self.chunks.pop_front();
            self.head = 0;
        }
        self.length -= copied;
        copied
    }
}

struct Slot {
    /// The domain (container slot) that opened the socket.
    owner: u8,
    references: u16,
    kind: Kind,
    /// The smoltcp socket of a TCP or UDP socket.
    handle: Option<SocketHandle>,
    remote: Option<IpEndpoint>,
    local_port: u16,
    listening: bool,
    backlog: usize,
    /// Connections waiting for accept on a listening socket.
    pending: VecDeque<SlotId>,
    /// The other end of a local stream: itself for a loopback socket, the
    /// listener for a local TCP connection not yet accepted.
    peer: Option<SlotId>,
    read_shutdown: bool,
    write_shutdown: bool,
    options: Options,
    /// SCM_RIGHTS queued for this socket's reader: ids and descriptor flags.
    rights: Vec<(SlotId, u32)>,
    /// SCM_CREDENTIALS queued for this socket's reader.
    credentials: VecDeque<(u32, u32, u32)>,
    peer_credentials: Option<(u32, u32, u32)>,
    /// Bytes queued for this socket's reader.
    local: LocalQueue,
    /// Bytes the local queue holds for a writer that must not block (a
    /// pipe's F_SETPIPE_SZ), or 0 for LOCAL_QUEUE_CAPACITY.
    local_capacity: u32,
    /// A Unix socket's type: 1 stream, 2 datagram, 5 sequenced packets.
    unix_type: u8,
    /// The path a Unix socket is bound to; empty when it has none.
    unix_path: Vec<u8>,
}

impl Slot {
    fn new(kind: Kind, owner: u8) -> Self {
        Self {
            owner,
            references: 1,
            kind,
            handle: None,
            remote: None,
            local_port: 0,
            listening: false,
            backlog: 0,
            pending: VecDeque::new(),
            peer: None,
            read_shutdown: false,
            write_shutdown: false,
            options: Options::default(),
            rights: Vec::new(),
            credentials: VecDeque::new(),
            peer_credentials: None,
            local: LocalQueue::default(),
            local_capacity: 0,
            unix_type: 0,
            unix_path: Vec::new(),
        }
    }

    /// Whether the socket's bytes go through local queues: a Unix socket,
    /// or a TCP socket connected to one of the interface's own addresses.
    fn is_local(&self) -> bool {
        self.kind == Kind::Unix || self.peer.is_some() && !self.listening
    }
}

/// A file description travelling as SCM_RIGHTS: the descriptor state a
/// receiver needs to open its own descriptor for the same file. Rights are
/// queued as socket ids, so file rights use the ids from FILE_RIGHT_BASE
/// up, and duplicate and close count references to them like sockets.
#[derive(Clone, Copy)]
pub(crate) struct FileRight {
    pub(crate) device: u16,
    pub(crate) rootfs: u16,
    pub(crate) generation: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
}

impl FileRight {
    const EMPTY: Self = Self {
        device: 0,
        rootfs: 0,
        generation: 0,
        flags: 0,
        offset: 0,
    };
}

struct Runtime {
    interface: Interface,
    device: VirtioNet,
    sockets: SocketSet<'static>,
    tick: i64,
    next_port: u16,
    local_address: u32,
}

struct Sockets {
    platform: Option<Platform>,
    runtime: Option<Runtime>,
    slots: Vec<Option<Slot>>,
    /// File rights by id less FILE_RIGHT_BASE, with their reference counts;
    /// a count of 0 marks a free entry.
    file_rights: Vec<(u32, FileRight)>,
    /// Rights queued on Unix sockets and not yet received.
    unix_inflight_rights: usize,
}

static SOCKETS: SpinLock<Sockets> = SpinLock::new(
    LockRank::SOCKETS,
    Sockets {
        platform: None,
        runtime: None,
        slots: Vec::new(),
        file_rights: Vec::new(),
        unix_inflight_rights: 0,
    },
);

fn current_owner() -> u8 {
    crate::arch::x86_64::cpu::current_container_slot().unwrap_or(crate::control_abi::DOMAIN_LIMIT)
        as u8
}

/// A zero-filled buffer, or `Exhausted` when the heap has no room for it.
fn filled<T: Clone>(length: usize, value: T) -> Result<Vec<T>, Error> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| Error::Exhausted)?;
    buffer.resize(length, value);
    Ok(buffer)
}

fn add_tcp_socket(runtime: &mut Runtime) -> Result<SocketHandle, Error> {
    let rx = tcp::SocketBuffer::new(filled(TCP_BUFFER_SIZE, 0_u8)?);
    let tx = tcp::SocketBuffer::new(filled(TCP_BUFFER_SIZE, 0_u8)?);
    Ok(runtime.sockets.add(tcp::Socket::new(rx, tx)))
}

fn add_udp_socket(runtime: &mut Runtime) -> Result<SocketHandle, Error> {
    let rx = udp::PacketBuffer::new(
        filled(UDP_PACKET_COUNT, udp::PacketMetadata::EMPTY)?,
        filled(UDP_BUFFER_SIZE, 0_u8)?,
    );
    let tx = udp::PacketBuffer::new(
        filled(UDP_PACKET_COUNT, udp::PacketMetadata::EMPTY)?,
        filled(UDP_BUFFER_SIZE, 0_u8)?,
    );
    Ok(runtime.sockets.add(udp::Socket::new(rx, tx)))
}

/// Queues `input` on a local stream's receive queue. With `capacity`,
/// queues only what fits (EAGAIN when nothing does, or when a small write
/// does not fit whole).
fn append_local_data(
    state: &mut Slot,
    input: &[u8],
    capacity: Option<usize>,
) -> Result<usize, Error> {
    let capacity = capacity.map(|capacity| {
        if state.local_capacity == 0 {
            capacity
        } else {
            state.local_capacity as usize
        }
    });
    let room = capacity.map_or(input.len(), |capacity| {
        capacity.saturating_sub(state.local.len())
    });
    if room == 0 || input.len() <= LOCAL_ATOMIC_WRITE && input.len() > room {
        return Err(Error::WouldBlock);
    }
    match state.local.push(&input[..input.len().min(room)]) {
        0 => Err(Error::Exhausted),
        queued => Ok(queued),
    }
}

/// Whether `address` (host order) is one of the interface's own.
fn is_local_address(runtime: &Runtime, address: u32) -> bool {
    address >> 24 == 127 || address == runtime.local_address
}

fn port_in_use(slots: &[Option<Slot>], kind: Kind, port: u16, except: usize) -> bool {
    port != 0
        && slots.iter().enumerate().any(|(index, slot)| {
            index != except
                && slot
                    .as_ref()
                    .is_some_and(|slot| slot.kind == kind && slot.local_port == port)
        })
}

fn allocate_ephemeral_port(
    next_port: &mut u16,
    slots: &[Option<Slot>],
    kind: Kind,
    except: usize,
) -> Option<u16> {
    for _ in 0..(u16::MAX - 49_152) {
        let port = (*next_port).max(49_152);
        *next_port = port.wrapping_add(1).max(49_152);
        if !port_in_use(slots, kind, port, except) {
            return Some(port);
        }
    }
    None
}

/// The index of a free table entry, growing the table when none is.
fn vacant(slots: &mut Vec<Option<Slot>>) -> Result<usize, Error> {
    if let Some(index) = slots.iter().position(Option::is_none) {
        return Ok(index);
    }
    if slots.len() >= FILE_RIGHT_BASE {
        return Err(Error::Exhausted);
    }
    slots.try_reserve(1).map_err(|_| Error::Exhausted)?;
    slots.push(None);
    Ok(slots.len() - 1)
}

fn slot_in(slots: &[Option<Slot>], id: SlotId) -> Option<&Slot> {
    slots.get(usize::from(id))?.as_ref()
}

fn slot_in_mut(slots: &mut [Option<Slot>], id: SlotId) -> Option<&mut Slot> {
    slots.get_mut(usize::from(id))?.as_mut()
}

fn unix_in_mut(slots: &mut [Option<Slot>], id: SlotId) -> Option<&mut Slot> {
    slot_in_mut(slots, id).filter(|state| state.kind == Kind::Unix)
}

pub(crate) fn endpoint(address: u32, port: u16) -> IpEndpoint {
    IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::from_octets(address.to_be_bytes())),
        port,
    )
}

impl Sockets {
    fn slot(&self, id: SlotId) -> Option<&Slot> {
        slot_in(&self.slots, id)
    }

    fn slot_mut(&mut self, id: SlotId) -> Option<&mut Slot> {
        slot_in_mut(&mut self.slots, id)
    }

    fn unix(&self, id: SlotId) -> Option<&Slot> {
        self.slot(id).filter(|state| state.kind == Kind::Unix)
    }

    /// Puts a new socket in the table and returns its id.
    fn insert(&mut self, slot: Slot) -> Result<SlotId, Error> {
        let index = vacant(&mut self.slots)?;
        self.slots[index] = Some(slot);
        Ok(index as SlotId)
    }

    fn configure(&mut self, platform: Platform) -> bool {
        if self.platform.is_some() {
            return false;
        }
        self.platform = Some(platform);
        true
    }

    /// Starts smoltcp on the domain's network device the first time a
    /// socket needs it.
    fn start_runtime(&mut self) -> Result<(), Error> {
        if self.runtime.is_some() {
            return Ok(());
        }
        let platform = self.platform.ok_or(Error::Unavailable)?;
        let configuration = network::ipv4_configuration();
        let ipv4 = configuration as u32;
        let prefix = (configuration >> 32) as u8;
        let gateway = network::ipv4_gateway() as u32;
        if ipv4 == 0 || prefix > 32 || gateway == 0 {
            return Err(Error::Unavailable);
        }
        let mut device = VirtioNet::start(&platform, ipv4).ok_or(Error::Unavailable)?;
        let mut config = InterfaceConfig::new(EthernetAddress(platform.initialization.mac).into());
        config.random_seed = u64::from(ipv4) << 32 | u64::from(gateway);
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::from_octets(ipv4.to_be_bytes())),
                prefix,
            ));
            let _ = addresses.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)),
                8,
            ));
        });
        if interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::from_octets(gateway.to_be_bytes()))
            .is_err()
        {
            let _ = device.stop(&platform);
            return Err(Error::Unavailable);
        }
        self.runtime = Some(Runtime {
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            tick: 0,
            next_port: 49_152,
            local_address: ipv4,
        });
        Ok(())
    }

    fn runtime(&mut self) -> Result<&mut Runtime, Error> {
        self.start_runtime()?;
        self.runtime.as_mut().ok_or(Error::Unavailable)
    }

    fn poll(&mut self) {
        if !network::link_is_up() {
            return;
        }
        let Some(runtime) = self.runtime.as_mut() else {
            return;
        };
        // Frames sent to the interface's own addresses are received on the
        // next pass, so a loopback exchange completes within one poll.
        for _ in 0..LOOPBACK_FRAME_COUNT {
            runtime.tick = runtime.tick.wrapping_add(1);
            let _ = runtime.interface.poll(
                Instant::from_millis(runtime.tick),
                &mut runtime.device,
                &mut runtime.sockets,
            );
            if !runtime.device.loopback_pending() {
                break;
            }
        }
        // A TCP socket shut down for reading discards what arrives.
        for state in self.slots.iter().flatten().filter(|state| {
            state.kind == Kind::Tcp
                && !state.listening
                && state.peer.is_none()
                && state.read_shutdown
        }) {
            let Some(handle) = state.handle else {
                continue;
            };
            let socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
            while socket.can_recv() {
                if socket.recv(|bytes| (bytes.len(), ())).is_err() {
                    break;
                }
            }
        }
    }

    fn teardown(&mut self) -> bool {
        let Some(platform) = self.platform else {
            return false;
        };
        let Some(runtime) = self.runtime.take() else {
            return false;
        };
        runtime.device.stop(&platform)
    }

    fn open(&mut self, kind: Kind) -> Result<SlotId, Error> {
        let handle = match kind {
            Kind::Unix => return self.open_unix(1),
            Kind::Tcp => add_tcp_socket(self.runtime()?)?,
            Kind::Udp => add_udp_socket(self.runtime()?)?,
        };
        let mut slot = Slot::new(kind, current_owner());
        slot.handle = Some(handle);
        let id = self.insert(slot);
        if id.is_err() {
            if let Some(runtime) = self.runtime.as_mut() {
                runtime.sockets.remove(handle);
            }
        }
        id
    }

    fn open_unix(&mut self, socket_type: u8) -> Result<SlotId, Error> {
        if !matches!(socket_type, 1 | 2 | 5) {
            return Err(Error::Invalid);
        }
        let mut slot = Slot::new(Kind::Unix, current_owner());
        slot.unix_type = socket_type;
        self.insert(slot)
    }

    fn socket_type(&self, id: SlotId) -> Option<u8> {
        let state = self.slot(id)?;
        match state.kind {
            Kind::Tcp => Some(1),
            Kind::Udp => Some(2),
            Kind::Unix => Some(state.unix_type),
        }
    }

    fn bind_unix(&mut self, id: SlotId, path: &[u8]) -> Result<(), Error> {
        if path.is_empty() || path.len() > UNIX_PATH_CAPACITY {
            return Err(Error::Invalid);
        }
        let state = self.unix(id).ok_or(Error::Invalid)?;
        if state.peer.is_some() || !state.unix_path.is_empty() {
            return Err(Error::Invalid);
        }
        let owner = state.owner;
        let in_use = self.slots.iter().enumerate().any(|(candidate, slot)| {
            candidate != usize::from(id)
                && slot
                    .as_ref()
                    .is_some_and(|slot| slot.owner == owner && slot.unix_path == path)
        });
        if in_use {
            return Err(Error::AddressInUse);
        }
        let mut name = Vec::new();
        name.try_reserve_exact(path.len())
            .map_err(|_| Error::Exhausted)?;
        name.extend_from_slice(path);
        unix_in_mut(&mut self.slots, id)
            .ok_or(Error::Invalid)?
            .unix_path = name;
        Ok(())
    }

    fn connect_unix(&mut self, id: SlotId, path: &[u8]) -> Result<(), Error> {
        let state = self.unix(id).ok_or(Error::Invalid)?;
        if state.peer.is_some() {
            return Err(Error::Invalid);
        }
        let (owner, unix_type) = (state.owner, state.unix_type);
        let peer = self
            .slots
            .iter()
            .enumerate()
            .find(|(candidate, slot)| {
                *candidate != usize::from(id)
                    && slot.as_ref().is_some_and(|slot| {
                        slot.owner == owner
                            && slot.kind == Kind::Unix
                            && slot.unix_type == unix_type
                            && slot.unix_path == path
                    })
            })
            .map(|(candidate, _)| candidate as SlotId)
            .ok_or(Error::NotConnected)?;
        if unix_type == 2 {
            unix_in_mut(&mut self.slots, id).ok_or(Error::Invalid)?.peer = Some(peer);
            return Ok(());
        }
        let listener = self.slot(peer).ok_or(Error::Invalid)?;
        if !listener.listening || listener.pending.len() >= listener.backlog {
            return Err(Error::WouldBlock);
        }
        // The listener's end of the connection, which accept hands out.
        let mut accepted = Slot::new(Kind::Unix, listener.owner);
        accepted.peer = Some(id);
        accepted.options = listener.options;
        accepted.unix_type = listener.unix_type;
        slot_in_mut(&mut self.slots, peer)
            .ok_or(Error::Invalid)?
            .pending
            .try_reserve(1)
            .map_err(|_| Error::Exhausted)?;
        let accepted = self.insert(accepted)?;
        unix_in_mut(&mut self.slots, id).ok_or(Error::Invalid)?.peer = Some(accepted);
        slot_in_mut(&mut self.slots, peer)
            .ok_or(Error::Invalid)?
            .pending
            .push_back(accepted);
        Ok(())
    }

    fn unix_name(&self, id: SlotId) -> Option<Vec<u8>> {
        let path = &self.unix(id)?.unix_path;
        let mut name = Vec::new();
        name.try_reserve_exact(path.len()).ok()?;
        name.extend_from_slice(path);
        Some(name)
    }

    fn open_pair(&mut self, socket_type: u8) -> Result<(SlotId, SlotId), Error> {
        if !matches!(socket_type, 1 | 2 | 5) {
            return Err(Error::Invalid);
        }
        let owner = current_owner();
        let mut first = Slot::new(Kind::Unix, owner);
        first.unix_type = socket_type;
        let mut second = Slot::new(Kind::Unix, owner);
        second.unix_type = socket_type;
        let first = self.insert(first)?;
        second.peer = Some(first);
        let second = match self.insert(second) {
            Ok(second) => second,
            Err(error) => {
                self.slots[usize::from(first)] = None;
                return Err(error);
            }
        };
        self.slot_mut(first).ok_or(Error::Invalid)?.peer = Some(second);
        Ok((first, second))
    }

    fn open_loopback(&mut self, socket_type: u8) -> Result<SlotId, Error> {
        let (id, peer) = self.open_pair(socket_type)?;
        if !self.close(peer) {
            let _ = self.close(id);
            return Err(Error::Invalid);
        }
        self.slot_mut(id).ok_or(Error::Invalid)?.peer = Some(id);
        Ok(id)
    }

    fn close(&mut self, id: SlotId) -> bool {
        if let Some(references) = self.file_right_references(id) {
            *references -= 1;
            return true;
        }
        let index = usize::from(id);
        let Some(state) = slot_in_mut(&mut self.slots, id) else {
            return false;
        };
        if state.references > 1 {
            state.references -= 1;
            return true;
        }
        if state.kind == Kind::Unix || state.handle.is_none() && !state.listening {
            if state.rights.len() > self.unix_inflight_rights {
                return false;
            }
            let Some(state) = self.slots[index].take() else {
                return false;
            };
            for other in self.slots.iter_mut().flatten() {
                if other.peer == Some(id) {
                    other.peer = None;
                }
                other.pending.retain(|pending| *pending != id);
            }
            self.unix_inflight_rights -= state.rights.len();
            for (right, _) in state.rights {
                let _ = self.close(right);
            }
            for connection in state.pending {
                let _ = self.close(connection);
            }
            return true;
        }
        let Some(runtime) = self.runtime.as_mut() else {
            return false;
        };
        let Some(handle) = state.handle else {
            return false;
        };
        runtime.sockets.remove(handle);
        self.slots[index] = None;
        true
    }

    fn shutdown_socket(&mut self, id: SlotId, how: u8) -> Result<(), Error> {
        if how > 2 {
            return Err(Error::Invalid);
        }
        let state = self
            .slot(id)
            .filter(|state| !state.listening)
            .ok_or(Error::NotConnected)?;
        let peer_connected = state.peer.is_some_and(|peer| self.slot(peer).is_some());
        if state.remote.is_none() && !peer_connected {
            return Err(Error::NotConnected);
        }
        let state = slot_in_mut(&mut self.slots, id).ok_or(Error::NotConnected)?;
        if matches!(how, 0 | 2) {
            state.local = LocalQueue::default();
            state.read_shutdown = true;
        }
        if matches!(how, 1 | 2) {
            state.write_shutdown = true;
            if state.kind == Kind::Tcp && state.peer.is_none() {
                let runtime = self.runtime.as_mut().ok_or(Error::Unavailable)?;
                let handle = state.handle.ok_or(Error::Invalid)?;
                runtime.sockets.get_mut::<tcp::Socket>(handle).close();
            }
        }
        Ok(())
    }

    /// Closes every socket of the current domain as it is torn down, and
    /// stops the device once no domain has sockets left.
    fn shutdown(&mut self) -> bool {
        // A domain teardown owns every remaining socket reference, including
        // duplicated descriptors and SCM_RIGHTS references that no live
        // process can release after its process tree has been retired.
        let owner = current_owner();
        for index in 0..self.slots.len() {
            let Some(state) = self.slots[index]
                .as_mut()
                .filter(|state| state.owner == owner)
            else {
                continue;
            };
            state.references = 1;
            if !self.close(index as SlotId) {
                return false;
            }
        }
        if self.slots.iter().any(Option::is_some) {
            return true;
        }
        self.slots = Vec::new();
        self.unix_inflight_rights = 0;
        self.file_rights = Vec::new();
        if self.runtime.is_none() {
            return true;
        }
        self.teardown()
    }

    fn duplicate(&mut self, id: SlotId) -> bool {
        if let Some(references) = self.file_right_references(id) {
            return references
                .checked_add(1)
                .map(|count| *references = count)
                .is_some();
        }
        self.slot_mut(id)
            .and_then(|state| {
                state.references = state.references.checked_add(1)?;
                Some(())
            })
            .is_some()
    }

    fn set_boolean_option(
        &mut self,
        id: SlotId,
        option: BooleanOption,
        enabled: bool,
    ) -> Result<(), Error> {
        let state = slot_in_mut(&mut self.slots, id).ok_or(Error::Invalid)?;
        let options = &mut state.options;
        match option {
            BooleanOption::ReuseAddress => options.reuse_address = enabled,
            BooleanOption::KeepAlive => options.keep_alive = enabled,
            BooleanOption::ReceiveErrors => options.receive_errors = enabled,
            BooleanOption::NoDelay => options.no_delay = enabled,
            BooleanOption::PassCredentials => options.pass_credentials = enabled,
            BooleanOption::Timestamp => options.timestamp = enabled,
        }
        if state.kind == Kind::Tcp {
            if let Some(handle) = state.handle {
                let runtime = self.runtime.as_mut().ok_or(Error::Unavailable)?;
                let socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
                match option {
                    BooleanOption::KeepAlive => {
                        socket.set_keep_alive(enabled.then_some(Duration::from_secs(75)))
                    }
                    BooleanOption::NoDelay => socket.set_nagle_enabled(!enabled),
                    BooleanOption::ReuseAddress
                    | BooleanOption::ReceiveErrors
                    | BooleanOption::PassCredentials
                    | BooleanOption::Timestamp => {}
                }
            }
        }
        Ok(())
    }

    fn boolean_option(&self, id: SlotId, option: BooleanOption) -> Result<bool, Error> {
        let options = self.slot(id).ok_or(Error::Invalid)?.options;
        Ok(match option {
            BooleanOption::ReuseAddress => options.reuse_address,
            BooleanOption::KeepAlive => options.keep_alive,
            BooleanOption::ReceiveErrors => options.receive_errors,
            BooleanOption::NoDelay => options.no_delay,
            BooleanOption::PassCredentials => options.pass_credentials,
            BooleanOption::Timestamp => options.timestamp,
        })
    }

    fn set_timeout_option(
        &mut self,
        id: SlotId,
        option: TimeoutOption,
        microseconds: u64,
    ) -> Result<(), Error> {
        let options = &mut self.slot_mut(id).ok_or(Error::Invalid)?.options;
        match option {
            TimeoutOption::Receive => options.receive_timeout_us = microseconds,
            TimeoutOption::Send => options.send_timeout_us = microseconds,
        }
        Ok(())
    }

    fn timeout_option(&self, id: SlotId, option: TimeoutOption) -> Result<u64, Error> {
        let options = self.slot(id).ok_or(Error::Invalid)?.options;
        Ok(match option {
            TimeoutOption::Receive => options.receive_timeout_us,
            TimeoutOption::Send => options.send_timeout_us,
        })
    }

    fn bind(&mut self, id: SlotId, address: u32, requested_port: u16) -> Result<u16, Error> {
        self.poll();
        self.start_runtime()?;
        let index = usize::from(id);
        let Self { runtime, slots, .. } = self;
        let runtime = runtime.as_mut().ok_or(Error::Unavailable)?;
        let state = slot_in(slots, id).ok_or(Error::Invalid)?;
        if state.kind == Kind::Unix || state.local_port != 0 || state.remote.is_some() {
            return Err(Error::Invalid);
        }
        let (kind, handle) = (state.kind, state.handle);
        if address != 0 && !is_local_address(runtime, address) {
            return Err(Error::AddressNotAvailable);
        }
        let port = if requested_port == 0 {
            allocate_ephemeral_port(&mut runtime.next_port, slots, kind, index)
                .ok_or(Error::Exhausted)?
        } else {
            requested_port
        };
        if port_in_use(slots, kind, port, index) {
            return Err(Error::AddressInUse);
        }
        if kind == Kind::Udp {
            runtime
                .sockets
                .get_mut::<udp::Socket>(handle.ok_or(Error::Invalid)?)
                .bind(port)
                .map_err(|_| Error::AddressInUse)?;
        }
        slot_in_mut(slots, id).ok_or(Error::Invalid)?.local_port = port;
        Ok(port)
    }

    fn listen(&mut self, id: SlotId, requested_backlog: usize) -> Result<(), Error> {
        self.poll();
        let index = usize::from(id);
        let state = self.slot(id).ok_or(Error::Invalid)?;
        if state.remote.is_some() {
            return Err(Error::Invalid);
        }
        let backlog = requested_backlog.clamp(1, BACKLOG_LIMIT);
        if state.kind == Kind::Unix {
            if state.unix_path.is_empty() {
                return Err(Error::Invalid);
            }
            let state = self.slot_mut(id).ok_or(Error::Invalid)?;
            state.listening = true;
            state.backlog = backlog;
            return Ok(());
        }
        if state.kind != Kind::Tcp {
            return Err(Error::Invalid);
        }
        let (current_port, handle) = (state.local_port, state.handle);
        self.start_runtime()?;
        let Self { runtime, slots, .. } = self;
        let runtime = runtime.as_mut().ok_or(Error::Unavailable)?;
        let local_port = if current_port == 0 {
            allocate_ephemeral_port(&mut runtime.next_port, slots, Kind::Tcp, index)
                .ok_or(Error::Exhausted)?
        } else {
            current_port
        };
        runtime
            .sockets
            .get_mut::<tcp::Socket>(handle.ok_or(Error::Invalid)?)
            .listen(local_port)
            .map_err(|_| Error::Invalid)?;
        let state = slot_in_mut(slots, id).ok_or(Error::Invalid)?;
        state.local_port = local_port;
        state.listening = true;
        state.backlog = backlog;
        Ok(())
    }

    fn accept(&mut self, id: SlotId) -> Result<(SlotId, IpEndpoint), Error> {
        self.poll();
        let kind = self
            .slot(id)
            .filter(|state| matches!(state.kind, Kind::Tcp | Kind::Unix) && state.listening)
            .ok_or(Error::Invalid)?
            .kind;
        if kind == Kind::Tcp {
            self.start_runtime()?;
        }
        let local_address = self
            .runtime
            .as_ref()
            .map_or(0, |runtime| runtime.local_address);
        // Connections whose client has gone are dropped from the queue.
        while let Some(client) = self
            .slot(id)
            .and_then(|state| state.pending.front().copied())
        {
            if self
                .slot(client)
                .is_some_and(|state| state.kind == kind && !state.listening)
            {
                break;
            }
            if let Some(listener) = self.slot_mut(id) {
                listener.pending.pop_front();
            }
        }
        if let Some(client) = self
            .slot(id)
            .and_then(|state| state.pending.front().copied())
        {
            if kind == Kind::Unix {
                // connect_unix made the listener's end already.
                if let Some(listener) = self.slot_mut(id) {
                    listener.pending.pop_front();
                }
                return Ok((client, endpoint(local_address, 0)));
            }
            // A TCP connection from one of the interface's own addresses:
            // the two ends exchange bytes through local queues.
            let client_port = self.slot(client).ok_or(Error::Invalid)?.local_port;
            let listener = self.slot(id).ok_or(Error::Invalid)?;
            let remote = endpoint(local_address, client_port);
            let mut accepted = Slot::new(Kind::Tcp, listener.owner);
            accepted.remote = Some(remote);
            accepted.local_port = listener.local_port;
            accepted.peer = Some(client);
            accepted.options = listener.options;
            let accepted = self.insert(accepted)?;
            self.slot_mut(client).ok_or(Error::Invalid)?.peer = Some(accepted);
            if let Some(listener) = self.slot_mut(id) {
                listener.pending.pop_front();
            }
            return Ok((accepted, remote));
        }
        if kind == Kind::Unix {
            return Err(Error::WouldBlock);
        }
        // smoltcp's listening socket is the connection now: it becomes the
        // accepted socket, and a new one listens in its place.
        let Self { runtime, slots, .. } = self;
        let runtime = runtime.as_mut().ok_or(Error::Unavailable)?;
        let listener = slot_in(slots, id).ok_or(Error::Invalid)?;
        let handle = listener.handle.ok_or(Error::Invalid)?;
        let socket = runtime.sockets.get::<tcp::Socket>(handle);
        if !matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        ) {
            return Err(Error::WouldBlock);
        }
        let remote = socket.remote_endpoint().ok_or(Error::Invalid)?;
        let (owner, local_port, options) = (listener.owner, listener.local_port, listener.options);
        let accepted_index = vacant(slots)?;
        let replacement = add_tcp_socket(runtime)?;
        if runtime
            .sockets
            .get_mut::<tcp::Socket>(replacement)
            .listen(local_port)
            .is_err()
        {
            runtime.sockets.remove(replacement);
            return Err(Error::Invalid);
        }
        let accepted_socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
        accepted_socket.set_nagle_enabled(!options.no_delay);
        accepted_socket.set_keep_alive(options.keep_alive.then_some(Duration::from_secs(75)));
        let mut accepted = Slot::new(Kind::Tcp, owner);
        accepted.handle = Some(handle);
        accepted.remote = Some(remote);
        accepted.local_port = local_port;
        accepted.options = options;
        slots[accepted_index] = Some(accepted);
        let listener = slot_in_mut(slots, id).ok_or(Error::Invalid)?;
        listener.handle = Some(replacement);
        listener.remote = None;
        listener.listening = true;
        Ok((accepted_index as SlotId, remote))
    }

    fn connect(&mut self, id: SlotId, remote: IpEndpoint) -> Result<(), Error> {
        self.poll();
        self.start_runtime()?;
        let index = usize::from(id);
        let Self { runtime, slots, .. } = self;
        let runtime = runtime.as_mut().ok_or(Error::Unavailable)?;
        let state = slot_in(slots, id).ok_or(Error::Invalid)?;
        let handle = state.handle.ok_or(Error::Invalid)?;
        if state.listening {
            return Err(Error::Invalid);
        }
        let (kind, current_port) = (state.kind, state.local_port);
        let local_port = if current_port == 0 {
            allocate_ephemeral_port(&mut runtime.next_port, slots, kind, index)
                .ok_or(Error::Exhausted)?
        } else {
            current_port
        };
        if kind == Kind::Tcp
            && matches!(remote.addr, IpAddress::Ipv4(address)
                if is_local_address(runtime, u32::from_be_bytes(address.octets())))
        {
            let listener = slots.iter().position(|candidate| {
                candidate.as_ref().is_some_and(|candidate| {
                    candidate.kind == Kind::Tcp
                        && candidate.listening
                        && candidate.local_port == remote.port
                        && candidate.pending.len() < candidate.backlog
                })
            });
            if let Some(listener) = listener {
                let listener = listener as SlotId;
                let queue = &mut slot_in_mut(slots, listener).ok_or(Error::Invalid)?.pending;
                queue.try_reserve(1).map_err(|_| Error::Exhausted)?;
                queue.push_back(id);
                let state = slot_in_mut(slots, id).ok_or(Error::Invalid)?;
                state.local_port = local_port;
                state.remote = Some(remote);
                state.peer = Some(listener);
                return Ok(());
            }
        }
        match kind {
            Kind::Tcp => {
                let socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
                if socket.is_active() {
                    return if socket.may_send() {
                        Ok(())
                    } else {
                        Err(Error::InProgress)
                    };
                }
                socket
                    .connect(runtime.interface.context(), remote, local_port)
                    .map_err(|_| Error::Invalid)?;
                let state = slot_in_mut(slots, id).ok_or(Error::Invalid)?;
                state.local_port = local_port;
                state.remote = Some(remote);
                Err(Error::InProgress)
            }
            Kind::Udp => {
                let socket = runtime.sockets.get_mut::<udp::Socket>(handle);
                if !socket.is_open() {
                    socket.bind(local_port).map_err(|_| Error::Invalid)?;
                }
                let state = slot_in_mut(slots, id).ok_or(Error::Invalid)?;
                state.local_port = local_port;
                state.remote = Some(remote);
                Ok(())
            }
            Kind::Unix => Err(Error::Invalid),
        }
    }

    fn send_queued(
        &mut self,
        id: SlotId,
        input: &[u8],
        remote: Option<IpEndpoint>,
        local_capacity: Option<usize>,
    ) -> Result<usize, Error> {
        self.poll();
        let state = self.slot(id).ok_or(Error::Invalid)?;
        if state.peer == Some(id) {
            // A loopback socket reads what it writes.
            if remote.is_some() {
                return Err(Error::Invalid);
            }
            if state.write_shutdown {
                return Err(Error::BrokenPipe);
            }
            if input.is_empty() {
                return Ok(0);
            }
            let state = self.slot_mut(id).ok_or(Error::Invalid)?;
            return append_local_data(state, input, local_capacity);
        }
        if state.write_shutdown {
            return Err(Error::BrokenPipe);
        }
        if state.is_local() {
            if remote.is_some() {
                return Err(Error::Invalid);
            }
            let kind = state.kind;
            let peer = state.peer.ok_or(Error::NotConnected)?;
            let Some(peer_state) = self
                .slot_mut(peer)
                .filter(|slot| slot.kind == kind && !slot.listening)
            else {
                crate::serial_write("ginux: local socket peer unavailable slot/peer ");
                crate::serial_write_u64(u64::from(id));
                crate::serial_write(" ");
                crate::serial_write_u64(u64::from(peer));
                crate::serial_write("\r\n");
                return Err(Error::NotConnected);
            };
            if input.is_empty() {
                return Ok(0);
            }
            return append_local_data(peer_state, input, local_capacity);
        }
        let (kind, handle, connected) = (state.kind, state.handle, state.remote);
        let runtime = self.runtime()?;
        let handle = handle.ok_or(Error::Invalid)?;
        match kind {
            Kind::Tcp => {
                let socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_send() {
                    socket.send_slice(input).map_err(|_| Error::Reset)
                } else if socket.may_send() {
                    Err(Error::WouldBlock)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Kind::Udp => {
                let endpoint = remote.or(connected).ok_or(Error::NotConnected)?;
                runtime
                    .sockets
                    .get_mut::<udp::Socket>(handle)
                    .send_slice(input, endpoint)
                    .map(|_| input.len())
                    .map_err(|_| Error::WouldBlock)
            }
            Kind::Unix => Err(Error::Invalid),
        }
    }

    /// What a local stream with nothing queued returns: EAGAIN while its
    /// peer may still write, else end of file.
    fn local_empty_result(&self, state: &Slot) -> Result<usize, Error> {
        let peer = state.peer.and_then(|peer| self.slot(peer));
        if state.unix_type == 2 || peer.is_some_and(|peer| !peer.write_shutdown) {
            Err(Error::WouldBlock)
        } else {
            Ok(0)
        }
    }

    fn recv(
        &mut self,
        id: SlotId,
        output: &mut [u8],
    ) -> Result<(usize, Option<IpEndpoint>), Error> {
        if self.slot(id).is_some_and(|state| state.kind == Kind::Udp) {
            return self
                .recv_message(id, output, false)
                .map(|(copied, _message_length, endpoint)| (copied, endpoint));
        }
        self.poll();
        let state = slot_in_mut(&mut self.slots, id).ok_or(Error::Invalid)?;
        if state.read_shutdown {
            return Ok((0, None));
        }
        if state.is_local() {
            let received = state.local.pop(output);
            if received != 0 {
                return Ok((received, None));
            }
            let state = self.slot(id).ok_or(Error::Invalid)?;
            return self.local_empty_result(state).map(|size| (size, None));
        }
        let (kind, handle) = (state.kind, state.handle);
        let runtime = self.runtime()?;
        let handle = handle.ok_or(Error::Invalid)?;
        match kind {
            Kind::Tcp => {
                let socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    socket
                        .recv_slice(output)
                        .map(|size| (size, None))
                        .map_err(|_| Error::Reset)
                } else if socket.may_recv() {
                    Err(Error::WouldBlock)
                } else {
                    Ok((0, None))
                }
            }
            Kind::Udp => runtime
                .sockets
                .get_mut::<udp::Socket>(handle)
                .recv_slice(output)
                .map(|(size, metadata)| (size, Some(metadata.endpoint)))
                .map_err(|_| Error::WouldBlock),
            Kind::Unix => Err(Error::Invalid),
        }
    }

    fn peek_local(&self, id: SlotId, output: &mut [u8]) -> Result<usize, Error> {
        let state = self
            .slot(id)
            .filter(|state| state.is_local())
            .ok_or(Error::Invalid)?;
        match state.local.peek(output) {
            0 => self.local_empty_result(state),
            returned => Ok(returned),
        }
    }

    /// A pipe's capacity (F_GETPIPE_SZ).
    fn local_capacity(&self, id: SlotId) -> Result<usize, Error> {
        self.unix(id)
            .map(|state| {
                if state.local_capacity == 0 {
                    LOCAL_QUEUE_CAPACITY
                } else {
                    state.local_capacity as usize
                }
            })
            .ok_or(Error::Invalid)
    }

    /// Sets a pipe's capacity (F_SETPIPE_SZ) on both its ends: `requested`
    /// rounded up to a power of two of at least a page. `Exhausted` when
    /// more is queued than the new capacity holds.
    fn set_local_capacity(&mut self, id: SlotId, requested: usize) -> Result<usize, Error> {
        let capacity = requested
            .max(PAGE_SIZE)
            .checked_next_power_of_two()
            .filter(|capacity| *capacity <= u32::MAX as usize)
            .ok_or(Error::Invalid)?;
        let state = self.unix(id).ok_or(Error::Invalid)?;
        let ends = [Some(id), state.peer];
        if ends.iter().flatten().any(|end| {
            self.slot(*end)
                .is_some_and(|end| end.local.len() > capacity)
        }) {
            return Err(Error::Exhausted);
        }
        for end in ends.into_iter().flatten() {
            if let Some(end) = self.slot_mut(end) {
                end.local_capacity = capacity as u32;
            }
        }
        Ok(capacity)
    }

    /// The bytes in a pipe, read from either end (its data waits in the
    /// read end's queue).
    fn pipe_queued_bytes(&self, id: SlotId) -> Result<usize, Error> {
        let state = self.unix(id).ok_or(Error::Invalid)?;
        let peer = state
            .peer
            .and_then(|peer| self.slot(peer))
            .map_or(0, |peer| peer.local.len());
        Ok(state.local.len() + peer)
    }

    fn peek(
        &mut self,
        id: SlotId,
        output: &mut [u8],
    ) -> Result<(usize, Option<IpEndpoint>), Error> {
        if self.slot(id).is_some_and(|state| state.kind == Kind::Udp) {
            return self
                .recv_message(id, output, true)
                .map(|(copied, _message_length, endpoint)| (copied, endpoint));
        }
        self.poll();
        let state = self.slot(id).ok_or(Error::Invalid)?;
        if state.read_shutdown {
            return Ok((0, None));
        }
        if state.is_local() {
            return self.peek_local(id, output).map(|received| (received, None));
        }
        let (kind, handle) = (state.kind, state.handle);
        let runtime = self.runtime()?;
        let handle = handle.ok_or(Error::Invalid)?;
        match kind {
            Kind::Tcp => {
                let socket = runtime.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    socket
                        .peek_slice(output)
                        .map(|size| (size, None))
                        .map_err(|_| Error::Reset)
                } else if socket.may_recv() {
                    Err(Error::WouldBlock)
                } else {
                    Ok((0, None))
                }
            }
            Kind::Udp => runtime
                .sockets
                .get_mut::<udp::Socket>(handle)
                .peek_slice(output)
                .map(|(size, metadata)| (size, Some(metadata.endpoint)))
                .map_err(|_| Error::WouldBlock),
            Kind::Unix => Err(Error::Invalid),
        }
    }

    fn recv_message(
        &mut self,
        id: SlotId,
        output: &mut [u8],
        peek_only: bool,
    ) -> Result<(usize, usize, Option<IpEndpoint>), Error> {
        if !self.slot(id).is_some_and(|state| state.kind == Kind::Udp) {
            let (copied, endpoint) = if peek_only {
                self.peek(id, output)?
            } else {
                self.recv(id, output)?
            };
            return Ok((copied, copied, endpoint));
        }
        self.poll();
        let state = self.slot(id).ok_or(Error::Invalid)?;
        if state.read_shutdown {
            return Ok((0, 0, None));
        }
        let handle = state.handle.ok_or(Error::Invalid)?;
        let runtime = self.runtime()?;
        let socket = runtime.sockets.get_mut::<udp::Socket>(handle);
        let (payload, endpoint) = if peek_only {
            let (payload, metadata) = socket.peek().map_err(|_| Error::WouldBlock)?;
            (payload, metadata.endpoint)
        } else {
            let (payload, metadata) = socket.recv().map_err(|_| Error::WouldBlock)?;
            (payload, metadata.endpoint)
        };
        let copied = output.len().min(payload.len());
        output[..copied].copy_from_slice(&payload[..copied]);
        Ok((copied, payload.len(), Some(endpoint)))
    }

    fn readiness(&mut self, id: SlotId) -> Option<(bool, bool, bool)> {
        self.poll();
        let state = self.slot(id)?;
        if state.listening && !state.pending.is_empty() {
            return Some((true, false, false));
        }
        if state.kind == Kind::Unix || state.peer.is_some() {
            let named = state.kind == Kind::Unix && !state.unix_path.is_empty();
            let peer = state.peer.and_then(|peer| self.slot(peer));
            let peer_open = peer.is_some();
            let writable = !state.write_shutdown && peer_open;
            let peer_eof = state.unix_type != 2
                && (!named && !peer_open || peer.is_some_and(|peer| peer.write_shutdown));
            let readable = state.read_shutdown || !state.local.is_empty() || peer_eof;
            return Some((readable, writable, false));
        }
        let runtime = self.runtime.as_ref()?;
        let handle = state.handle?;
        Some(match state.kind {
            Kind::Tcp => {
                let socket = runtime.sockets.get::<tcp::Socket>(handle);
                if state.listening {
                    (
                        matches!(
                            socket.state(),
                            tcp::State::Established | tcp::State::CloseWait
                        ),
                        false,
                        false,
                    )
                } else {
                    (
                        state.read_shutdown || socket.can_recv() || !socket.may_recv(),
                        !state.write_shutdown && socket.can_send(),
                        !socket.is_open() && state.remote.is_some(),
                    )
                }
            }
            Kind::Udp => {
                let socket = runtime.sockets.get::<udp::Socket>(handle);
                (socket.can_recv(), socket.can_send(), false)
            }
            Kind::Unix => return None,
        })
    }

    fn local_peer_write_closed(&self, id: SlotId) -> Option<bool> {
        let state = self.unix(id)?;
        if !state.unix_path.is_empty() || state.unix_type == 2 {
            return Some(false);
        }
        let peer = state.peer.and_then(|peer| self.slot(peer));
        Some(!peer.is_some_and(|peer| !peer.write_shutdown))
    }

    fn names(&self, id: SlotId) -> Option<(IpEndpoint, Option<IpEndpoint>)> {
        let state = self.slot(id).filter(|state| state.kind != Kind::Unix)?;
        let runtime = self.runtime.as_ref()?;
        Some((
            endpoint(runtime.local_address, state.local_port),
            state.remote,
        ))
    }

    fn set_unix_pair_credentials(
        &mut self,
        first: SlotId,
        second: SlotId,
        credentials: (u32, u32, u32),
    ) -> bool {
        let paired = |end: SlotId, other: SlotId| {
            self.unix(end)
                .is_some_and(|state| state.peer == Some(other))
        };
        if !paired(first, second) || !paired(second, first) {
            return false;
        }
        for end in [first, second] {
            if let Some(state) = self.slot_mut(end) {
                state.peer_credentials = Some(credentials);
            }
        }
        true
    }

    fn queue_file_right(&mut self, right: FileRight) -> Option<SlotId> {
        let index = match self
            .file_rights
            .iter()
            .position(|(references, _)| *references == 0)
        {
            Some(index) => index,
            None if self.file_rights.len() < FILE_RIGHT_LIMIT => {
                self.file_rights.try_reserve(1).ok()?;
                self.file_rights.push((0, FileRight::EMPTY));
                self.file_rights.len() - 1
            }
            None => return None,
        };
        self.file_rights[index] = (1, right);
        SlotId::try_from(FILE_RIGHT_BASE + index).ok()
    }

    fn file_right(&self, id: SlotId) -> Option<FileRight> {
        let index = usize::from(id).checked_sub(FILE_RIGHT_BASE)?;
        self.file_rights
            .get(index)
            .filter(|(references, _)| *references != 0)
            .map(|(_, right)| *right)
    }

    fn file_right_references(&mut self, id: SlotId) -> Option<&mut u32> {
        let index = usize::from(id).checked_sub(FILE_RIGHT_BASE)?;
        self.file_rights
            .get_mut(index)
            .map(|(references, _)| references)
            .filter(|references| **references != 0)
    }

    /// The connected peer of a Unix socket `sender`.
    fn unix_peer(&self, sender: SlotId) -> Result<SlotId, Error> {
        self.unix(sender)
            .ok_or(Error::Invalid)?
            .peer
            .ok_or(Error::NotConnected)
    }

    fn queue_unix_rights(&mut self, sender: SlotId, rights: &[(SlotId, u32)]) -> Result<(), Error> {
        if rights.is_empty() || rights.len() > PASSED_RIGHT_LIMIT {
            return Err(Error::Invalid);
        }
        let peer = self.unix_peer(sender)?;
        if rights.iter().any(|(right, _)| *right == peer) {
            return Err(Error::Invalid);
        }
        let peer_state = unix_in_mut(&mut self.slots, peer).ok_or(Error::NotConnected)?;
        if !peer_state.rights.is_empty() {
            return Err(Error::WouldBlock);
        }
        let next_inflight = self
            .unix_inflight_rights
            .checked_add(rights.len())
            .ok_or(Error::Exhausted)?;
        peer_state
            .rights
            .try_reserve_exact(rights.len())
            .map_err(|_| Error::Exhausted)?;
        peer_state.rights.extend_from_slice(rights);
        self.unix_inflight_rights = next_inflight;
        Ok(())
    }

    fn unix_right_queue_available(&self, sender: SlotId, rights: &[SlotId]) -> Result<(), Error> {
        if rights.is_empty() || rights.len() > PASSED_RIGHT_LIMIT {
            return Err(Error::Invalid);
        }
        let peer = self.unix_peer(sender)?;
        if rights.contains(&peer) {
            return Err(Error::Invalid);
        }
        let peer_state = self.unix(peer).ok_or(Error::NotConnected)?;
        if !peer_state.rights.is_empty() || !peer_state.local.is_empty() {
            return Err(Error::WouldBlock);
        }
        Ok(())
    }

    fn unix_credentials_queue_available(&self, sender: SlotId) -> Result<(), Error> {
        let peer = self.unix_peer(sender)?;
        let peer_state = self.unix(peer).ok_or(Error::NotConnected)?;
        if peer_state.credentials.len() == CREDENTIAL_QUEUE_LIMIT {
            return Err(Error::WouldBlock);
        }
        Ok(())
    }

    fn receive_unix_rights(
        &mut self,
        receiver: SlotId,
        output: &mut [(SlotId, u32)],
        peek_only: bool,
    ) -> Result<usize, Error> {
        let state = self.unix(receiver).ok_or(Error::Invalid)?;
        let count = state.rights.len();
        let output = output.get_mut(..count).ok_or(Error::Invalid)?;
        output.copy_from_slice(&state.rights);
        if peek_only {
            // The receiver gets references of its own; the queued ones stay.
            for (duplicated, (right, _)) in output.iter().enumerate() {
                if !self.duplicate(*right) {
                    for (rollback, _) in &output[..duplicated] {
                        let _ = self.close(*rollback);
                    }
                    return Err(Error::Exhausted);
                }
            }
        } else {
            if count > self.unix_inflight_rights {
                return Err(Error::Invalid);
            }
            unix_in_mut(&mut self.slots, receiver)
                .ok_or(Error::Invalid)?
                .rights
                .clear();
            self.unix_inflight_rights -= count;
        }
        Ok(count)
    }

    fn queue_unix_credentials(
        &mut self,
        sender: SlotId,
        credentials: (u32, u32, u32),
    ) -> Result<(), Error> {
        let peer = self.unix_peer(sender)?;
        let queue = &mut unix_in_mut(&mut self.slots, peer)
            .ok_or(Error::NotConnected)?
            .credentials;
        if queue.len() == CREDENTIAL_QUEUE_LIMIT {
            return Err(Error::WouldBlock);
        }
        queue.try_reserve(1).map_err(|_| Error::Exhausted)?;
        queue.push_back(credentials);
        Ok(())
    }

    fn receive_unix_credentials(
        &mut self,
        receiver: SlotId,
        peek_only: bool,
    ) -> Result<Option<(u32, u32, u32)>, Error> {
        let queue = &mut unix_in_mut(&mut self.slots, receiver)
            .ok_or(Error::Invalid)?
            .credentials;
        Ok(if peek_only {
            queue.front().copied()
        } else {
            queue.pop_front()
        })
    }

    /// Drops the rights (closing them) and, with `credentials`, the
    /// credentials queued for `receiver`; says whether rights were closed.
    fn discard_unix_ancillary(
        &mut self,
        receiver: SlotId,
        credentials: bool,
    ) -> Result<bool, Error> {
        let state = unix_in_mut(&mut self.slots, receiver).ok_or(Error::Invalid)?;
        if credentials {
            state.credentials.clear();
        }
        let count = state.rights.len();
        if count > self.unix_inflight_rights {
            return Err(Error::Invalid);
        }
        let rights = core::mem::take(&mut state.rights);
        self.unix_inflight_rights -= count;
        let mut closed = count != 0;
        for (right, _) in rights {
            closed &= self.close(right);
        }
        Ok(closed)
    }
}

pub(crate) fn configure(
    device: VirtioNetworkDevice,
    initialization: VirtioNetworkInitialization,
    common: MmioMapping,
    notification: MmioMapping,
    iommu: DeviceTranslationProfile,
) -> bool {
    SOCKETS.lock().configure(Platform {
        device,
        initialization,
        common,
        notification,
        iommu,
    })
}

pub(crate) fn open(kind: Kind) -> Result<SlotId, Error> {
    SOCKETS.lock().open(kind)
}

pub(crate) fn open_unix(socket_type: u8) -> Result<SlotId, Error> {
    SOCKETS.lock().open_unix(socket_type)
}

pub(crate) fn socket_type(id: SlotId) -> Option<u8> {
    SOCKETS.lock().socket_type(id)
}

pub(crate) fn bind_unix(id: SlotId, path: &[u8]) -> Result<(), Error> {
    SOCKETS.lock().bind_unix(id, path)
}

pub(crate) fn connect_unix(id: SlotId, path: &[u8]) -> Result<(), Error> {
    SOCKETS.lock().connect_unix(id, path)
}

/// The path a Unix socket is bound to, empty when it has none.
pub(crate) fn unix_name(id: SlotId) -> Option<Vec<u8>> {
    SOCKETS.lock().unix_name(id)
}

pub(crate) fn unix_peer_name(id: SlotId) -> Option<Vec<u8>> {
    let sockets = SOCKETS.lock();
    sockets.unix_name(sockets.unix(id)?.peer?)
}

pub(crate) fn open_pair(socket_type: u8) -> Result<(SlotId, SlotId), Error> {
    SOCKETS.lock().open_pair(socket_type)
}

pub(crate) fn open_loopback(socket_type: u8) -> Result<SlotId, Error> {
    SOCKETS.lock().open_loopback(socket_type)
}

pub(crate) fn close(id: SlotId) -> bool {
    SOCKETS.lock().close(id)
}

pub(crate) fn shutdown_socket(id: SlotId, how: u8) -> Result<(), Error> {
    SOCKETS.lock().shutdown_socket(id, how)
}

pub(crate) fn shutdown() -> bool {
    SOCKETS.lock().shutdown()
}

pub(crate) fn duplicate(id: SlotId) -> bool {
    SOCKETS.lock().duplicate(id)
}

pub(crate) fn kind(id: SlotId) -> Option<Kind> {
    SOCKETS.lock().slot(id).map(|state| state.kind)
}

pub(crate) fn is_listening(id: SlotId) -> bool {
    SOCKETS.lock().slot(id).is_some_and(|state| state.listening)
}

pub(crate) fn set_boolean_option(
    id: SlotId,
    option: BooleanOption,
    enabled: bool,
) -> Result<(), Error> {
    SOCKETS.lock().set_boolean_option(id, option, enabled)
}

pub(crate) fn boolean_option(id: SlotId, option: BooleanOption) -> Result<bool, Error> {
    SOCKETS.lock().boolean_option(id, option)
}

pub(crate) fn set_timeout_option(
    id: SlotId,
    option: TimeoutOption,
    microseconds: u64,
) -> Result<(), Error> {
    SOCKETS.lock().set_timeout_option(id, option, microseconds)
}

pub(crate) fn timeout_option(id: SlotId, option: TimeoutOption) -> Result<u64, Error> {
    SOCKETS.lock().timeout_option(id, option)
}

/// Whether a timeout (SO_RCVTIMEO or SO_SNDTIMEO) bounds blocking calls on
/// the socket `id`.
pub(crate) fn has_timeout(id: SlotId, option: TimeoutOption) -> bool {
    timeout_poll_limit(id, option).is_some()
}

fn timeout_poll_limit(id: SlotId, option: TimeoutOption) -> Option<usize> {
    timeout_option(id, option)
        .ok()
        .filter(|microseconds| *microseconds != 0)
        .map(|microseconds| {
            usize::try_from(microseconds.div_ceil(1_000))
                .unwrap_or(usize::MAX)
                .max(1)
        })
}

pub(crate) fn bind(id: SlotId, address: u32, requested_port: u16) -> Result<u16, Error> {
    SOCKETS.lock().bind(id, address, requested_port)
}

pub(crate) fn listen(id: SlotId, requested_backlog: usize) -> Result<(), Error> {
    SOCKETS.lock().listen(id, requested_backlog)
}

pub(crate) fn accept(id: SlotId) -> Result<(SlotId, IpEndpoint), Error> {
    SOCKETS.lock().accept(id)
}

pub(crate) fn accept_blocking(id: SlotId) -> Result<(SlotId, IpEndpoint), Error> {
    if let Some(limit) = timeout_poll_limit(id, TimeoutOption::Receive) {
        for _ in 0..limit {
            match accept(id) {
                Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
                result => return result,
            }
        }
        return Err(Error::WouldBlock);
    }
    loop {
        match accept(id) {
            Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
            result => return result,
        }
    }
}

pub(crate) fn connect(id: SlotId, remote: IpEndpoint) -> Result<(), Error> {
    SOCKETS.lock().connect(id, remote)
}

/// Sends without blocking: a full local queue is `WouldBlock`.
pub(crate) fn send(id: SlotId, input: &[u8], remote: Option<IpEndpoint>) -> Result<usize, Error> {
    SOCKETS
        .lock()
        .send_queued(id, input, remote, Some(LOCAL_QUEUE_CAPACITY))
}

pub(crate) fn send_blocking(
    id: SlotId,
    input: &[u8],
    remote: Option<IpEndpoint>,
) -> Result<usize, Error> {
    let limit = timeout_poll_limit(id, TimeoutOption::Send).unwrap_or(BLOCKING_POLL_LIMIT);
    for _ in 0..limit {
        match SOCKETS.lock().send_queued(id, input, remote, None) {
            Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
            result => return result,
        }
    }
    Err(Error::WouldBlock)
}

pub(crate) fn recv(id: SlotId, output: &mut [u8]) -> Result<(usize, Option<IpEndpoint>), Error> {
    SOCKETS.lock().recv(id, output)
}

pub(crate) fn peek_local(id: SlotId, output: &mut [u8]) -> Result<usize, Error> {
    SOCKETS.lock().peek_local(id, output)
}

/// A pipe's capacity (F_GETPIPE_SZ).
pub(crate) fn local_capacity(id: SlotId) -> Result<usize, Error> {
    SOCKETS.lock().local_capacity(id)
}

/// Sets a pipe's capacity (F_SETPIPE_SZ); see `Sockets::set_local_capacity`.
pub(crate) fn set_local_capacity(id: SlotId, requested: usize) -> Result<usize, Error> {
    SOCKETS.lock().set_local_capacity(id, requested)
}

/// The bytes in a pipe, read from either end.
pub(crate) fn pipe_queued_bytes(id: SlotId) -> Result<usize, Error> {
    SOCKETS.lock().pipe_queued_bytes(id)
}

pub(crate) fn local_queued_bytes(id: SlotId) -> Result<usize, Error> {
    SOCKETS
        .lock()
        .unix(id)
        .map(|state| state.local.len())
        .ok_or(Error::Invalid)
}

pub(crate) fn recv_message(
    id: SlotId,
    output: &mut [u8],
    peek_only: bool,
) -> Result<(usize, usize, Option<IpEndpoint>), Error> {
    SOCKETS.lock().recv_message(id, output, peek_only)
}

pub(crate) fn recv_message_blocking(
    id: SlotId,
    output: &mut [u8],
    peek_only: bool,
    wait_all: bool,
) -> Result<(usize, usize, Option<IpEndpoint>), Error> {
    if output.is_empty() {
        return Ok((0, 0, None));
    }
    let limit = timeout_poll_limit(id, TimeoutOption::Receive).unwrap_or(BLOCKING_POLL_LIMIT);
    if !wait_all || kind(id) == Some(Kind::Udp) {
        for _ in 0..limit {
            match recv_message(id, output, peek_only) {
                Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
                result => return result,
            }
        }
        report_timeout(if peek_only { "peek" } else { "receive" });
        return Err(Error::WouldBlock);
    }
    if peek_only {
        let mut observed = 0;
        for _ in 0..limit {
            match recv_message(id, output, true) {
                Ok((copied, _, endpoint)) if copied == output.len() || copied == 0 => {
                    return Ok((copied, copied, endpoint));
                }
                Ok((copied, _, _)) => observed = copied,
                Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
                Err(error) => {
                    return if observed == 0 {
                        Err(error)
                    } else {
                        Ok((observed, observed, None))
                    }
                }
            }
        }
        return if observed == 0 {
            report_timeout("peek");
            Err(Error::WouldBlock)
        } else {
            Ok((observed, observed, None))
        };
    }
    let mut received = 0;
    for _ in 0..limit {
        match recv_message(id, &mut output[received..], false) {
            Ok((0, _, endpoint)) => return Ok((received, received, endpoint)),
            Ok((copied, _, endpoint)) => {
                received += copied;
                if received == output.len() {
                    return Ok((received, received, endpoint));
                }
            }
            Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
            Err(error) => {
                return if received == 0 {
                    Err(error)
                } else {
                    Ok((received, received, None))
                };
            }
        }
    }
    if received == 0 {
        report_timeout("receive");
        Err(Error::WouldBlock)
    } else {
        Ok((received, received, None))
    }
}

pub(crate) fn recv_blocking(
    id: SlotId,
    output: &mut [u8],
) -> Result<(usize, Option<IpEndpoint>), Error> {
    let limit = timeout_poll_limit(id, TimeoutOption::Receive).unwrap_or(BLOCKING_POLL_LIMIT);
    for _ in 0..limit {
        match recv(id, output) {
            Err(Error::WouldBlock | Error::InProgress) => core::hint::spin_loop(),
            result => return result,
        }
    }
    report_timeout("receive");
    Err(Error::WouldBlock)
}

pub(crate) fn complete_connect(id: SlotId) -> Result<(), Error> {
    let limit = timeout_poll_limit(id, TimeoutOption::Send).unwrap_or(BLOCKING_POLL_LIMIT);
    for _ in 0..limit {
        let Some((_, writable, error)) = readiness(id) else {
            return Err(Error::Invalid);
        };
        if writable {
            return Ok(());
        }
        if error {
            return Err(Error::Reset);
        }
        core::hint::spin_loop();
    }
    report_timeout("connect");
    Err(Error::WouldBlock)
}

fn report_timeout(operation: &str) {
    let sockets = SOCKETS.lock();
    let Some(runtime) = sockets.runtime.as_ref() else {
        return;
    };
    let [rx_avail, rx_used, tx_avail, tx_used] = runtime.device.queue_positions();
    crate::serial_write("ginux: socket ");
    crate::serial_write(operation);
    crate::serial_write(" timeout rx/tx available/used: ");
    crate::serial_write_u64(u64::from(rx_avail));
    crate::serial_write("/");
    crate::serial_write_u64(u64::from(rx_used));
    crate::serial_write(" ");
    crate::serial_write_u64(u64::from(tx_avail));
    crate::serial_write("/");
    crate::serial_write_u64(u64::from(tx_used));
    crate::serial_write("\r\n");
}

pub(crate) fn readiness(id: SlotId) -> Option<(bool, bool, bool)> {
    SOCKETS.lock().readiness(id)
}

pub(crate) fn local_peer_write_closed(id: SlotId) -> Option<bool> {
    SOCKETS.lock().local_peer_write_closed(id)
}

pub(crate) fn local_peer_slot(id: SlotId) -> Option<SlotId> {
    SOCKETS.lock().unix(id)?.peer
}

pub(crate) fn names(id: SlotId) -> Option<(IpEndpoint, Option<IpEndpoint>)> {
    SOCKETS.lock().names(id)
}

pub(crate) fn set_unix_pair_credentials(
    first: SlotId,
    second: SlotId,
    credentials: (u32, u32, u32),
) -> bool {
    SOCKETS
        .lock()
        .set_unix_pair_credentials(first, second, credentials)
}

pub(crate) fn unix_peer_credentials(id: SlotId) -> Option<(u32, u32, u32)> {
    SOCKETS.lock().unix(id)?.peer_credentials
}

pub(crate) fn queue_file_right(right: FileRight) -> Option<SlotId> {
    SOCKETS.lock().queue_file_right(right)
}

pub(crate) fn file_right(id: SlotId) -> Option<FileRight> {
    SOCKETS.lock().file_right(id)
}

pub(crate) fn queue_unix_rights(sender: SlotId, rights: &[(SlotId, u32)]) -> Result<(), Error> {
    SOCKETS.lock().queue_unix_rights(sender, rights)
}

pub(crate) fn unix_inflight_rights() -> usize {
    SOCKETS.lock().unix_inflight_rights
}

pub(crate) fn unix_right_queue_available(sender: SlotId, rights: &[SlotId]) -> Result<(), Error> {
    SOCKETS.lock().unix_right_queue_available(sender, rights)
}

pub(crate) fn unix_credentials_queue_available(sender: SlotId) -> Result<(), Error> {
    SOCKETS.lock().unix_credentials_queue_available(sender)
}

pub(crate) fn receive_unix_rights(
    receiver: SlotId,
    output: &mut [(SlotId, u32)],
    peek_only: bool,
) -> Result<usize, Error> {
    SOCKETS
        .lock()
        .receive_unix_rights(receiver, output, peek_only)
}

pub(crate) fn unix_right_count(receiver: SlotId) -> usize {
    SOCKETS
        .lock()
        .unix(receiver)
        .map_or(0, |state| state.rights.len())
}

pub(crate) fn unix_peer_passes_credentials(sender: SlotId) -> Result<bool, Error> {
    let sockets = SOCKETS.lock();
    let peer = sockets.unix_peer(sender)?;
    sockets
        .unix(peer)
        .map(|state| state.options.pass_credentials)
        .ok_or(Error::NotConnected)
}

pub(crate) fn queue_unix_credentials(
    sender: SlotId,
    credentials: (u32, u32, u32),
) -> Result<(), Error> {
    SOCKETS.lock().queue_unix_credentials(sender, credentials)
}

pub(crate) fn receive_unix_credentials(
    receiver: SlotId,
    peek_only: bool,
) -> Result<Option<(u32, u32, u32)>, Error> {
    SOCKETS.lock().receive_unix_credentials(receiver, peek_only)
}

pub(crate) fn unix_credentials_pending(receiver: SlotId) -> bool {
    SOCKETS
        .lock()
        .unix(receiver)
        .is_some_and(|state| !state.credentials.is_empty())
}

pub(crate) fn discard_unix_ancillary(receiver: SlotId) -> Result<bool, Error> {
    SOCKETS.lock().discard_unix_ancillary(receiver, true)
}

pub(crate) fn discard_unix_peer_ancillary(sender: SlotId) -> Result<bool, Error> {
    let mut sockets = SOCKETS.lock();
    let peer = sockets.unix_peer(sender)?;
    sockets.discard_unix_ancillary(peer, true)
}

pub(crate) fn discard_unix_rights(receiver: SlotId) -> Result<bool, Error> {
    SOCKETS.lock().discard_unix_ancillary(receiver, false)
}
