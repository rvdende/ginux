//! virtio-gpu as the display, for the kernel console and /dev/fb0.
//!
//! A virtio-gpu has no framebuffer of its own: the guest draws into a 2D
//! resource's backing, which is ordinary guest memory, and tells the host
//! which rectangles to copy into the resource (`TRANSFER_TO_HOST_2D`) and
//! show (`RESOURCE_FLUSH`). The driver makes one resource the size of the
//! mode the host prefers (`GET_DISPLAY_INFO`), backs it with physically
//! contiguous kernel frames, and points a scanout at it. The console and
//! /dev/fb0 then use that backing exactly as they use the firmware
//! framebuffer: the console draws into it, and a domain maps it.
//!
//! Bring-up follows the xHCI input driver. [`discover`] finds the device
//! before the kernel builds its page tables, so its registers join the
//! device window. [`prepare`] opens it while DMA translation is still off,
//! creates and backs the resource, and returns the DMA regions to admit;
//! the I/O MMU admits them together with the USB controllers', as standing
//! devices. [`activate`] then shows the resource and moves the console and
//! /dev/fb0 onto it. Without a virtio-gpu, or if any step fails, the
//! firmware framebuffer stays the display.
//!
//! Flushing: the host only sees what the guest flushes.
//!
//! - The console reports the rectangle it drew after each write, and the
//!   same goes for write(2) to /dev/fb0. Damage accumulates in one atomic
//!   word, and whoever holds the GPU transfers and flushes it. A caller
//!   waits (briefly) for a flush already in progress rather than leave its
//!   own damage behind, so the last line written is always shown.
//! - A domain that maps /dev/fb0 writes it without the kernel seeing, so
//!   while a domain owns the screen the 1 kHz Linux timer tick flushes the
//!   whole surface at [`REFRESH_HZ`]. The tick never waits: when a flush
//!   is still in progress it tries again on the next tick.
//!
//! The control queue carries many commands at once, each a descriptor
//! chain returned when the device is done with it, in whatever order: a
//! flush, a setup command the caller waits for, or a fenced 3D submission
//! that comes back only once the host has run it. The device is polled,
//! never interrupting. The GPU sits behind a latch that
//! is only ever tried, never waited on, because the console reaches it
//! from any context, interrupt handlers and code holding ranked locks
//! included: a caller that finds it held leaves its damage for the holder
//! or the next tick.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ginux_drm::{Blob, Cache, Errno, Features, Mapping};

use ginux_virtio_gpu::{self as protocol, Command, Damage, DisplayInfo, Mode, Rect};

use super::device_memory::{DmaBuffer, Mmio};
use super::virtio::{self, Probe, Segment, SplitQueue, Transport};
use super::{pci, say, wait_until_ms};
use crate::framebuffer::{self, Display, Scanout};

/// The one resource the driver creates: the display surface.
const RESOURCE: u32 = 1;
/// Descriptors in the control queue.
const QUEUE_SIZE: u16 = 64;
/// Command slots, each a request with its response; one per chain in
/// flight.
const SLOTS: usize = 32;
/// Command slots fenced submissions leave free for calls that wait for
/// their reply (blob creation and mapping, contexts).
const RESERVED_SLOTS: usize = 4;
/// Bytes per command slot: the request, then the response (a capset's
/// data included).
const SLOT_BYTES: usize = 4096;
const RESPONSE_OFFSET: usize = 512;
/// Pages of command slots.
const COMMAND_PAGES: usize = SLOTS * SLOT_BYTES / PAGE_SIZE;
/// The largest surface the driver backs (1920x1080 fits); larger host modes
/// fall back. The I/O MMU maps the surface with the USB controllers' DMA in
/// one standing table of at most 16 frames, so it cannot grow much.
const MAX_SURFACE_BYTES: usize = 8 << 20;
/// The mode used when the host enables no scanout that fits.
const FALLBACK_MODE: Mode = Mode {
    width: 1280,
    height: 800,
};
/// Full-surface flushes per second while a domain draws through /dev/fb0.
const REFRESH_HZ: u64 = 60;
/// Assumed timestamp-counter rate when the timer cannot tell.
const FALLBACK_COUNTER_HZ: u64 = 3_000_000_000;
/// How long boot waits for each setup command.
const SETUP_TIMEOUT_MS: u64 = 1000;
/// How long a console write waits for an earlier flush to complete.
const PRESENT_WAIT_MS: u64 = 20;
/// Flushes one present call makes for damage that arrived meanwhile.
const PRESENT_ROUNDS: usize = 4;
const PAGE_SIZE: usize = 4096;
/// The 3D features Venus needs, taken when the host offers them all.
const THREE_D_FEATURES: u64 =
    protocol::FEATURE_VIRGL | protocol::FEATURE_RESOURCE_BLOB | protocol::FEATURE_CONTEXT_INIT;
/// Submissions are copied into chunks of this many bytes...
const PAYLOAD_CHUNK: usize = 64 * 1024;
/// ...of which there are this many (one bit each in a u16).
const PAYLOAD_CHUNKS: usize = 16;
/// How long a 3D command, or waiting for room on the queue, may take.
const THREE_D_TIMEOUT_MS: u64 = 2000;

const _: () = assert!(SLOTS * SLOT_BYTES == COMMAND_PAGES * PAGE_SIZE && SLOTS <= 64);
const _: () = assert!(
    RESPONSE_OFFSET >= protocol::MAX_REQUEST
        && SLOT_BYTES - RESPONSE_OFFSET >= protocol::MAX_RESPONSE
);

/// Finds the first virtio-gpu on bus 0 or behind its bridges. Reads PCI
/// configuration space only, apart from sizing the register BAR.
pub(crate) fn discover() -> Option<Probe> {
    let mut found = None;
    pci::for_each_reachable_function(|identity| {
        if found.is_none()
            && identity.vendor == virtio::VENDOR
            && identity.device == protocol::DEVICE_ID
        {
            found = virtio::probe(identity.address);
        }
    });
    found
}

/// Why the GPU did not become the display, or a flush failed.
// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum Error {
    Transport(virtio::Error),
    /// The frame allocator had no contiguous run for a buffer.
    Memory,
    /// The device did not use a batch in time.
    Timeout,
    Command(Command, protocol::Error),
}

impl From<virtio::Error> for Error {
    fn from(error: virtio::Error) -> Self {
        Self::Transport(error)
    }
}

/// What a chain in flight is for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Purpose {
    /// A transfer or flush of the display surface.
    Display,
    /// A command whose caller waits for its reply in its slot.
    Reply,
    /// A fenced submission; the fence signals when it comes back.
    Fence(u64),
}

#[derive(Clone, Copy)]
struct Pending {
    command: Command,
    slot: usize,
    purpose: Purpose,
    /// Payload chunks the chain reads, one bit each, freed with it.
    payload: u16,
}

/// The device and its control queue. Fields drop in order: the transport
/// resets the device before the queue and command memory return to the
/// allocator.
struct Device {
    transport: Transport,
    control: SplitQueue,
    /// [`SLOTS`] request/response pairs.
    commands: DmaBuffer,
    /// Slots in use, one bit each.
    slots_used: u64,
    /// Slots whose reply came back: their outcome, until the caller reads it.
    replies: [Option<Result<(), Error>>; SLOTS],
    /// What each in-flight chain, by head descriptor, is.
    pending: [Option<Pending>; QUEUE_SIZE as usize],
    /// Display chains in flight.
    display_in_flight: u8,
    /// The first error a display chain came back with, since last taken.
    display_error: Option<Error>,
    /// Payload chunks in use, one bit each.
    payload_used: u16,
}

impl Device {
    fn open(probe: &Probe, registers: Mmio, wanted: u64) -> Result<(Self, u64), Error> {
        let transport = Transport::new(probe, registers)?;
        // The 3D features are taken when the host offers all that Venus
        // needs, and reported either way.
        let offered = transport.negotiate(wanted)?;
        let ring = DmaBuffer::allocate(2).ok_or(Error::Memory)?;
        let control = transport.queue(protocol::CONTROL_QUEUE, QUEUE_SIZE, ring)?;
        let commands = DmaBuffer::allocate(COMMAND_PAGES).ok_or(Error::Memory)?;
        transport.ready();
        let device = Self {
            transport,
            control,
            commands,
            slots_used: 0,
            replies: [None; SLOTS],
            pending: [None; QUEUE_SIZE as usize],
            display_in_flight: 0,
            display_error: None,
            payload_used: 0,
        };
        Ok((device, offered))
    }

    /// Puts `command` (with `fence`, if any) on the queue in a free slot,
    /// followed by `payload` (device address and length) when it has one.
    /// Returns the slot, or `None` when no slot or descriptors are free.
    fn push(
        &mut self,
        command: Command,
        fence: Option<protocol::Fence>,
        payload: Option<(u64, u32, u16)>,
        purpose: Purpose,
    ) -> Option<usize> {
        let slot = (0..SLOTS).find(|slot| self.slots_used & (1 << slot) == 0)?;
        let request = match fence {
            Some(fence) => command.encode_fenced(fence),
            None => command.encode(),
        };
        let base = slot * SLOT_BYTES;
        self.commands.write_bytes(base, request.as_bytes());
        // A reply the device never wrote then reads as type zero.
        self.commands
            .write_bytes(base + RESPONSE_OFFSET, &[0; protocol::HEADER_SIZE]);
        let request_segment = Segment {
            address: self.commands.device_address(base),
            length: request.as_bytes().len() as u32,
            writable: false,
        };
        let response = Segment {
            address: self.commands.device_address(base + RESPONSE_OFFSET),
            length: command.response_len().min(SLOT_BYTES - RESPONSE_OFFSET) as u32,
            writable: true,
        };
        let head = match payload {
            Some((address, length, _)) => self.control.push(&[
                request_segment,
                Segment {
                    address,
                    length,
                    writable: false,
                },
                response,
            ]),
            None => self.control.push(&[request_segment, response]),
        }?;
        self.slots_used |= 1 << slot;
        self.replies[slot] = None;
        self.pending[usize::from(head)] = Some(Pending {
            command,
            slot,
            purpose,
            payload: payload.map_or(0, |(.., chunks)| chunks),
        });
        if purpose == Purpose::Display {
            self.display_in_flight += 1;
        }
        Some(slot)
    }

    /// Takes in every chain the device has finished: records the replies
    /// callers wait for and the display's errors, and frees the rest.
    fn reap(&mut self) {
        while let Some((head, _)) = self.control.pop() {
            let Some(pending) = self
                .pending
                .get_mut(usize::from(head))
                .and_then(Option::take)
            else {
                continue;
            };
            self.payload_used &= !pending.payload;
            let mut header = [0_u8; protocol::HEADER_SIZE];
            self.commands
                .read_bytes(pending.slot * SLOT_BYTES + RESPONSE_OFFSET, &mut header);
            // A reply's body is decoded whole by `call`; the header says
            // whether the device failed it. Other commands reply with a
            // header alone.
            let outcome = if pending.purpose == Purpose::Reply {
                match protocol::Response::parse(&header) {
                    Ok(protocol::Response::Error(code)) => Err(protocol::Error::Device(code)),
                    Ok(_) => Ok(()),
                    Err(error) => Err(error),
                }
            } else {
                pending.command.check(&header)
            }
            .map_err(|error| Error::Command(pending.command, error));
            match pending.purpose {
                Purpose::Reply => {
                    self.replies[pending.slot] = Some(outcome);
                    continue;
                }
                Purpose::Display => {
                    self.display_in_flight = self.display_in_flight.saturating_sub(1);
                    if let (Err(error), None) = (outcome, self.display_error) {
                        self.display_error = Some(error);
                    }
                }
                Purpose::Fence(_) => {}
            }
            self.slots_used &= !(1 << pending.slot);
        }
    }

    /// Whether fence `fence` has signalled: its submission came back.
    fn fence_done(&mut self, fence: u64) -> bool {
        self.reap();
        !self
            .pending
            .iter()
            .flatten()
            .any(|pending| pending.purpose == Purpose::Fence(fence))
    }

    /// Runs `command`, waiting up to `milliseconds` for its reply, and
    /// copies the reply's bytes after the header into `data`.
    fn call(
        &mut self,
        command: Command,
        payload: Option<(u64, u32, u16)>,
        data: &mut [u8],
        milliseconds: u64,
    ) -> Result<protocol::Reply, Error> {
        let mut slot = None;
        wait_until_ms(milliseconds, || {
            self.reap();
            slot = self.push(command, None, payload, Purpose::Reply);
            slot.is_some()
        });
        let slot = slot.ok_or(Error::Timeout)?;
        let mut done = false;
        wait_until_ms(milliseconds, || {
            self.reap();
            done = self.replies[slot].is_some();
            done
        });
        if !done {
            // The slot stays taken: the device may still write it.
            return Err(Error::Timeout);
        }
        let outcome = self.replies[slot].take().unwrap_or(Err(Error::Timeout));
        let mut response = [0_u8; SLOT_BYTES - RESPONSE_OFFSET];
        let length = command.response_len().min(response.len());
        self.commands
            .read_bytes(slot * SLOT_BYTES + RESPONSE_OFFSET, &mut response[..length]);
        self.slots_used &= !(1 << slot);
        outcome?;
        let tail = &response[protocol::HEADER_SIZE.min(length)..length];
        let copied = tail.len().min(data.len());
        data[..copied].copy_from_slice(&tail[..copied]);
        command
            .reply(&response[..length])
            .map_err(|error| Error::Command(command, error))
    }

    /// Runs `commands` one after another at boot, waiting for each.
    fn execute(&mut self, commands: &[Command]) -> Result<(), Error> {
        for command in commands {
            self.call(*command, None, &mut [], SETUP_TIMEOUT_MS)?;
        }
        Ok(())
    }
}

/// The GPU with its display surface: resource [`RESOURCE`], backed by
/// `surface`, which the console draws into and domains map as /dev/fb0.
/// The device drops first, so it stops reading the surface before the
/// surface's frames go back.
struct Gpu {
    device: Device,
    surface: DmaBuffer,
    scanout: u32,
    mode: Mode,
    /// Timestamp-counter ticks between full-surface refreshes.
    refresh_period: u64,
    last_refresh: u64,
    /// Venus's 3D contexts, when the host offers them.
    three_d: Option<ThreeD>,
}

/// A blob resource and who holds it.
struct Resource {
    id: u32,
    context: u32,
    references: u32,
    /// Where it is mapped in the host-visible region (offset, size) and
    /// how the host asks for it to be cached.
    mapping: Option<(u64, u64, Cache)>,
}

/// The 3D side: the host's capsets, the host-visible region blobs are
/// mapped into, the blob resources, and the submission payload area.
struct ThreeD {
    /// (id, newest version, data size) of each capset.
    capsets: Vec<(u32, u32, u32)>,
    /// The host-visible region: physical address and length.
    host_visible: (u64, u64),
    /// Ranges of it in use, (offset, size), sorted by offset.
    mapped: Vec<(u64, u64)>,
    resources: Vec<Resource>,
    next_resource: u32,
    next_context: u32,
    next_fence: u64,
    /// [`PAYLOAD_CHUNKS`] chunks of [`PAYLOAD_CHUNK`] bytes.
    payload: DmaBuffer,
}

impl Gpu {
    /// Opens the device, asks the host for its preferred mode, and creates
    /// a resource of that size backed by fresh contiguous frames.
    fn open(probe: &Probe, registers: Mmio) -> Result<(Self, u64), Error> {
        let (mut device, offered) = Device::open(probe, registers, THREE_D_FEATURES)?;
        let mut modes = [0_u8; protocol::MAX_RESPONSE - protocol::HEADER_SIZE];
        device.call(Command::GetDisplayInfo, None, &mut modes, SETUP_TIMEOUT_MS)?;
        let mut reply = [0_u8; protocol::MAX_RESPONSE];
        reply[..4].copy_from_slice(&0x1101_u32.to_le_bytes());
        reply[protocol::HEADER_SIZE..].copy_from_slice(&modes);
        let info = DisplayInfo::parse(&reply)
            .map_err(|error| Error::Command(Command::GetDisplayInfo, error))?;
        let scanouts = device.transport.device_u32(protocol::CONFIG_NUM_SCANOUTS) as usize;
        let (scanout, mode) = info.choose(scanouts, MAX_SURFACE_BYTES, FALLBACK_MODE);
        let bytes = mode.bytes().ok_or(Error::Memory)?;
        let surface = DmaBuffer::allocate(bytes.div_ceil(PAGE_SIZE)).ok_or(Error::Memory)?;
        device.execute(&[
            Command::ResourceCreate2d {
                resource: RESOURCE,
                format: protocol::Format::B8G8R8X8,
                width: mode.width,
                height: mode.height,
            },
            Command::AttachBacking {
                resource: RESOURCE,
                address: surface.device_address(0),
                length: bytes as u32,
            },
        ])?;
        let counter_hz =
            crate::arch::x86_64::timer::monotonic_frequency().unwrap_or(FALLBACK_COUNTER_HZ);
        let three_d = ThreeD::open(&mut device, probe, offered);
        let gpu = Self {
            device,
            surface,
            scanout,
            mode,
            refresh_period: counter_hz / REFRESH_HZ,
            last_refresh: 0,
            three_d,
        };
        Ok((gpu, offered))
    }

    fn full(&self) -> Rect {
        Rect::full(self.mode.width, self.mode.height)
    }

    /// The display /dev/fb0 and the console see: the surface, tightly
    /// packed blue-green-red-unused pixels.
    fn display(&self) -> Display {
        let line_length = self.mode.width * protocol::BYTES_PER_PIXEL;
        Display {
            physical: self.surface.region().0,
            width: self.mode.width,
            height: self.mode.height,
            line_length,
            length: line_length as usize * self.mode.height as usize,
            bgrx: true,
            scanout: Scanout::VirtioGpu,
        }
    }

    /// Whether a periodic full refresh is due, starting the next period if
    /// so.
    fn refresh_due(&mut self) -> bool {
        let now = crate::arch::x86_64::timer::timestamp_counter();
        if now.wrapping_sub(self.last_refresh) < self.refresh_period {
            return false;
        }
        self.last_refresh = now;
        true
    }

    /// Finishes the flush in flight, waiting up to `wait_ms` for it, then
    /// starts one for the pending `damage`. Returns the outcome of the
    /// flush that finished, or `None` when the earlier one is still running
    /// (and the damage stays pending).
    fn flush(&mut self, damage: &AtomicU64, wait_ms: Option<u64>) -> Option<Result<(), Error>> {
        let device = &mut self.device;
        match wait_ms {
            Some(milliseconds) => {
                wait_until_ms(milliseconds, || {
                    device.reap();
                    device.display_in_flight == 0
                });
            }
            None => device.reap(),
        }
        if self.device.display_in_flight != 0 {
            return None;
        }
        let outcome = self.device.display_error.take().map_or(Ok(()), Err);
        let taken = Damage::from_bits(damage.swap(Damage::EMPTY.bits(), Ordering::AcqRel));
        let Some(rect) = taken
            .rect()
            .map(|rect| rect.clamp(self.mode.width, self.mode.height))
            .filter(|rect| !rect.is_empty())
        else {
            return Some(outcome);
        };
        let stride = u64::from(self.mode.width * protocol::BYTES_PER_PIXEL);
        let offset =
            u64::from(rect.y) * stride + u64::from(rect.x) * u64::from(protocol::BYTES_PER_PIXEL);
        // The flush follows the transfer on the queue, which the device
        // processes in order.
        let transfer = Command::TransferToHost2d {
            resource: RESOURCE,
            rect,
            offset,
        };
        let flush = Command::ResourceFlush {
            resource: RESOURCE,
            rect,
        };
        if !self.device.control.has_room(4)
            || self
                .device
                .push(transfer, None, None, Purpose::Display)
                .is_none()
        {
            add_damage(damage, taken);
            return Some(outcome);
        }
        if self
            .device
            .push(flush, None, None, Purpose::Display)
            .is_none()
        {
            add_damage(damage, taken);
        }
        Some(outcome)
    }
}

impl ThreeD {
    /// The 3D side, if the host offered every feature Venus needs and a
    /// host-visible region: reads its capsets.
    fn open(device: &mut Device, probe: &Probe, offered: u64) -> Option<Self> {
        if offered & THREE_D_FEATURES != THREE_D_FEATURES {
            return None;
        }
        let host_visible = probe
            .shared_memory(protocol::SHM_ID_HOST_VISIBLE)
            .filter(|(address, length)| *address != 0 && *length != 0)?;
        let count = device
            .transport
            .device_u32(protocol::CONFIG_NUM_CAPSETS)
            .min(16);
        if count == 0 {
            say!("ginux: virtio-gpu 3D: the device reports no capsets\n");
        }
        let mut capsets = Vec::new();
        for index in 0..count {
            match device.call(
                Command::GetCapsetInfo { index },
                None,
                &mut [],
                SETUP_TIMEOUT_MS,
            ) {
                Ok(protocol::Reply::CapsetInfo {
                    id,
                    max_version,
                    max_size,
                }) => {
                    if capsets.try_reserve(1).is_ok() {
                        capsets.push((id, max_version, max_size));
                    }
                }
                reply => say!(
                    "ginux: virtio-gpu 3D: capset {} of {}: {:?}\n",
                    index,
                    count,
                    reply
                ),
            }
        }
        let payload = DmaBuffer::allocate(PAYLOAD_CHUNKS * PAYLOAD_CHUNK / PAGE_SIZE)?;
        Some(Self {
            capsets,
            host_visible,
            mapped: Vec::new(),
            resources: Vec::new(),
            next_resource: RESOURCE + 1,
            next_context: 1,
            next_fence: 1,
            payload,
        })
    }

    fn features(&self) -> Features {
        Features {
            three_d: true,
            blob: true,
            host_visible: true,
            context_init: true,
            capsets: self
                .capsets
                .iter()
                .filter(|(id, ..)| *id < 64)
                .fold(0, |mask, (id, ..)| mask | 1 << id),
        }
    }

    fn resource(&mut self, id: u32) -> Result<&mut Resource, Errno> {
        self.resources
            .iter_mut()
            .find(|resource| resource.id == id)
            .ok_or(Errno::NoEnt)
    }

    /// A free page-aligned range of `size` bytes of the host-visible
    /// region, first fit; recorded as in use.
    fn allocate_range(&mut self, size: u64) -> Result<u64, Errno> {
        let size = size.next_multiple_of(PAGE_SIZE as u64);
        let mut start = 0_u64;
        let mut position = self.mapped.len();
        for (index, (offset, length)) in self.mapped.iter().enumerate() {
            if offset.saturating_sub(start) >= size {
                position = index;
                break;
            }
            start = offset + length;
        }
        if start
            .checked_add(size)
            .is_none_or(|end| end > self.host_visible.1)
        {
            return Err(Errno::NoMem);
        }
        self.mapped.try_reserve(1).map_err(|_| Errno::NoMem)?;
        self.mapped.insert(position, (start, size));
        Ok(start)
    }
}

fn errno(error: Error) -> Errno {
    match error {
        Error::Memory => Errno::NoMem,
        Error::Timeout => Errno::Busy,
        Error::Command(_, protocol::Error::Device(protocol::ErrorCode::OutOfMemory)) => {
            Errno::NoMem
        }
        Error::Command(_, protocol::Error::Device(protocol::ErrorCode::InvalidParameter)) => {
            Errno::Inval
        }
        _ => Errno::Io,
    }
}

/// Runs `f` with the GPU's device and 3D side, waiting for a flush that
/// holds the GPU (system calls only; interrupt handlers never wait).
fn with_three_d<R>(
    f: impl FnOnce(&mut Device, &mut ThreeD) -> Result<R, Errno>,
) -> Result<R, Errno> {
    let mut claim = None;
    crate::linux_profile::span(crate::linux_profile::Span::GpuClaimWait, || {
        wait_until_ms(THREE_D_TIMEOUT_MS, || {
            claim = SCANOUT.claim();
            claim.is_some()
        })
    });
    let mut claim = claim.ok_or(Errno::Busy)?;
    let gpu = claim.gpu().ok_or(Errno::NoSys)?;
    let three_d = gpu.three_d.as_mut().ok_or(Errno::NoSys)?;
    f(&mut gpu.device, three_d)
}

/// Whether the GPU offers Venus contexts (a DRM render node).
pub(crate) fn has_three_d() -> bool {
    THREE_D_CAPSETS.load(Ordering::Acquire) != 0
}

/// Blob mappings logged so far (the first few show how the host caches them).
static MAPS_LOGGED: AtomicU32 = AtomicU32::new(0);

/// The capsets of the 3D side, one bit per id, published at activation.
static THREE_D_CAPSETS: AtomicU64 = AtomicU64::new(0);
/// The GPU's PCI (bus, device, function), packed, published at activation.
static PCI_ADDRESS: AtomicU64 = AtomicU64::new(0);

/// The GPU's PCI bus, device and function.
pub(crate) fn pci_address() -> (u8, u8, u8) {
    let packed = PCI_ADDRESS.load(Ordering::Acquire);
    ((packed >> 16) as u8, (packed >> 8) as u8, packed as u8)
}

/// The physical address where blob `resource` is mapped, and its caching,
/// if it is mapped.
pub(crate) fn mapped_physical(resource: u32) -> Option<(u64, Cache)> {
    with_three_d(|_, three_d| {
        let base = three_d.host_visible.0;
        three_d
            .resource(resource)?
            .mapping
            .map(|(offset, _, cache)| (base + offset, cache))
            .ok_or(Errno::Inval)
    })
    .ok()
}

/// Whether fence `fence` has signalled. Never waits: while the GPU is busy
/// elsewhere it reports not yet, and the caller looks again.
pub(crate) fn fence_signaled(fence: u64) -> bool {
    let Some(mut claim) = SCANOUT.claim() else {
        return false;
    };
    claim.gpu().is_none_or(|gpu| gpu.device.fence_done(fence))
}

/// The GPU as the DRM layer sees it.
pub(crate) struct VirtioGpu;

impl ginux_drm::Gpu for VirtioGpu {
    fn features(&self) -> Features {
        let capsets = THREE_D_CAPSETS.load(Ordering::Acquire);
        Features {
            three_d: capsets != 0,
            blob: capsets != 0,
            host_visible: capsets != 0,
            context_init: capsets != 0,
            capsets,
        }
    }

    fn capset(&mut self, id: u32, version: u32, output: &mut [u8]) -> Result<usize, Errno> {
        with_three_d(|device, three_d| {
            let &(_, max_version, size) = three_d
                .capsets
                .iter()
                .find(|(capset, ..)| *capset == id)
                .ok_or(Errno::Inval)?;
            if version > max_version {
                return Err(Errno::Inval);
            }
            let command = Command::GetCapset { id, version, size };
            device
                .call(command, None, output, THREE_D_TIMEOUT_MS)
                .map_err(errno)?;
            Ok(size as usize)
        })
    }

    fn create_context(&mut self, capset: u32) -> Result<u32, Errno> {
        with_three_d(|device, three_d| {
            let context = three_d.next_context;
            three_d.next_context = context.checked_add(1).ok_or(Errno::NoMem)?;
            device
                .call(
                    Command::CtxCreate { context, capset },
                    None,
                    &mut [],
                    THREE_D_TIMEOUT_MS,
                )
                .map_err(errno)?;
            Ok(context)
        })
    }

    fn destroy_context(&mut self, context: u32) {
        let _ = with_three_d(|device, _| {
            device
                .call(
                    Command::CtxDestroy { context },
                    None,
                    &mut [],
                    THREE_D_TIMEOUT_MS,
                )
                .map_err(errno)
        });
    }

    fn create_blob(&mut self, blob: Blob) -> Result<u32, Errno> {
        with_three_d(|device, three_d| {
            let resource = three_d.next_resource;
            three_d.next_resource = resource.checked_add(1).ok_or(Errno::NoMem)?;
            three_d.resources.try_reserve(1).map_err(|_| Errno::NoMem)?;
            let create = Command::ResourceCreateBlob {
                context: blob.context,
                resource,
                memory: blob.memory,
                flags: blob.flags,
                id: blob.id,
                size: blob.size,
            };
            device
                .call(create, None, &mut [], THREE_D_TIMEOUT_MS)
                .map_err(errno)?;
            let attach = Command::CtxAttachResource {
                context: blob.context,
                resource,
            };
            if let Err(error) = device.call(attach, None, &mut [], THREE_D_TIMEOUT_MS) {
                let _ = device.call(
                    Command::ResourceUnref { resource },
                    None,
                    &mut [],
                    THREE_D_TIMEOUT_MS,
                );
                return Err(errno(error));
            }
            three_d.resources.push(Resource {
                id: resource,
                context: blob.context,
                references: 1,
                mapping: None,
            });
            Ok(resource)
        })
    }

    fn map(&mut self, resource: u32, size: u64) -> Result<Mapping, Errno> {
        with_three_d(|device, three_d| {
            if three_d.resource(resource)?.mapping.is_some() {
                return Err(Errno::Inval);
            }
            let offset = three_d.allocate_range(size)?;
            let command = Command::ResourceMapBlob { resource, offset };
            let cache = match device.call(command, None, &mut [], THREE_D_TIMEOUT_MS) {
                Ok(protocol::Reply::MapInfo(cache)) => cache,
                Ok(_) | Err(_) => {
                    three_d.mapped.retain(|(start, _)| *start != offset);
                    return Err(Errno::Io);
                }
            };
            let cache = match cache {
                protocol::MapCache::Uncached => Cache::Uncached,
                protocol::MapCache::WriteCombined => Cache::WriteCombined,
                protocol::MapCache::Cached | protocol::MapCache::None => Cache::Cached,
            };
            if MAPS_LOGGED.fetch_add(1, Ordering::Relaxed) < 48 {
                say!(
                    "ginux: virtio-gpu 3D: blob {} mapped, {} bytes, {:?}\n",
                    resource,
                    size,
                    cache
                );
            }
            three_d.resource(resource)?.mapping = Some((offset, size, cache));
            Ok(Mapping {
                physical: three_d.host_visible.0 + offset,
                cache,
            })
        })
    }

    fn submit(
        &mut self,
        context: u32,
        ring: Option<u8>,
        commands: &[u8],
        fenced: bool,
    ) -> Result<Option<u64>, Errno> {
        if commands.len() > PAYLOAD_CHUNK * PAYLOAD_CHUNKS {
            return Err(Errno::Inval);
        }
        with_three_d(|device, three_d| {
            crate::linux_profile::span(crate::linux_profile::Span::GpuSubmit, || {
                let chunks = commands.len().div_ceil(PAYLOAD_CHUNK);
                let run = if chunks == 0 {
                    0
                } else {
                    (1_u32 << chunks) - 1
                } as u16;
                // A slot, descriptors and a run of free chunks, leaving slots
                // for calls that wait for their reply; with none, the caller
                // runs other work and submits again (`Errno::Again`) rather
                // than holding the CPU until the GPU finishes earlier work.
                device.reap();
                let free_slots = SLOTS - device.slots_used.count_ones() as usize;
                let first = (0..=PAYLOAD_CHUNKS - chunks)
                    .find(|first| device.payload_used & (run << first) == 0)
                    .filter(|_| free_slots > RESERVED_SLOTS && device.control.has_room(3))
                    .ok_or(Errno::Again)?;
                let fence = three_d.next_fence;
                three_d.next_fence += 1;
                let payload = (!commands.is_empty()).then(|| {
                    let base = first * PAYLOAD_CHUNK;
                    three_d.payload.write_bytes(base, commands);
                    (
                        three_d.payload.device_address(base),
                        commands.len() as u32,
                        run << first,
                    )
                });
                if let Some((.., chunks)) = payload {
                    device.payload_used |= chunks;
                }
                let command = Command::Submit3d {
                    context,
                    size: commands.len() as u32,
                };
                let pushed = device.push(
                    command,
                    Some(protocol::Fence { id: fence, ring }),
                    payload,
                    Purpose::Fence(fence),
                );
                if pushed.is_none() {
                    if let Some((.., chunks)) = payload {
                        device.payload_used &= !chunks;
                    }
                    return Err(Errno::Again);
                }
                Ok(fenced.then_some(fence))
            })
        })
    }

    fn wait(&mut self, _resource: u32, nowait: bool) -> Result<(), Errno> {
        // Submissions are not tracked by resource: wait for all of them. A
        // wait that may block reports `Errno::Again`, and the caller runs
        // other work and asks again.
        with_three_d(|device, _| {
            device.reap();
            let busy = device
                .pending
                .iter()
                .flatten()
                .any(|pending| matches!(pending.purpose, Purpose::Fence(_)));
            match (busy, nowait) {
                (false, _) => Ok(()),
                (true, true) => Err(Errno::Busy),
                (true, false) => Err(Errno::Again),
            }
        })
    }

    fn retain(&mut self, resource: u32) {
        let _ = with_three_d(|_, three_d| {
            let resource = three_d.resource(resource)?;
            resource.references = resource.references.saturating_add(1);
            Ok(())
        });
    }

    fn release(&mut self, resource: u32) {
        let _ = with_three_d(|device, three_d| {
            let entry = three_d.resource(resource)?;
            entry.references -= 1;
            if entry.references != 0 {
                return Ok(());
            }
            let (context, mapping) = (entry.context, entry.mapping);
            three_d.resources.retain(|entry| entry.id != resource);
            if let Some((offset, ..)) = mapping {
                let _ = device.call(
                    Command::ResourceUnmapBlob { resource },
                    None,
                    &mut [],
                    THREE_D_TIMEOUT_MS,
                );
                three_d.mapped.retain(|(start, _)| *start != offset);
            }
            for command in [
                Command::CtxDetachResource { context, resource },
                Command::ResourceUnref { resource },
            ] {
                let _ = device.call(command, None, &mut [], THREE_D_TIMEOUT_MS);
            }
            Ok(())
        });
    }
}

/// Adds `more` to the damage word, from any context.
fn add_damage(damage: &AtomicU64, more: Damage) {
    if more.is_empty() {
        return;
    }
    let mut current = damage.load(Ordering::Acquire);
    loop {
        let merged = Damage::from_bits(current).union(more).bits();
        match damage.compare_exchange_weak(current, merged, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// The GPU that scans out the console and /dev/fb0, once [`activate`] has
/// installed it, with the damage waiting to be flushed.
struct ScanoutOwner {
    /// Held by whoever is using `gpu`. Only ever tried, never waited on.
    held: AtomicBool,
    /// Pending damage as [`Damage::bits`]; updated without holding `held`.
    damage: AtomicU64,
    /// Set once a flush has failed and been reported.
    failure_reported: AtomicBool,
    gpu: UnsafeCell<Option<Gpu>>,
}

// SAFETY: `gpu` is reached only through a Claim, and `held` admits one
// Claim at a time on any CPU (acquire on taking it, release on dropping
// it). The other fields are atomics.
unsafe impl Sync for ScanoutOwner {}

static SCANOUT: ScanoutOwner = ScanoutOwner {
    held: AtomicBool::new(false),
    damage: AtomicU64::new(0),
    failure_reported: AtomicBool::new(false),
    gpu: UnsafeCell::new(None),
};

/// Exclusive use of the scanout GPU until dropped.
struct Claim<'a> {
    owner: &'a ScanoutOwner,
}

impl ScanoutOwner {
    /// The GPU, or `None` while another context is using it.
    fn claim(&self) -> Option<Claim<'_>> {
        // Lazily: a Claim made for a latch someone else holds would release
        // it when dropped.
        (!self.held.swap(true, Ordering::Acquire)).then(|| Claim { owner: self })
    }

    /// Flushes pending damage. With `wait_ms`, waits that long for a flush
    /// already in progress and repeats for damage added meanwhile; without
    /// it, gives up at once if the GPU is busy. `refresh` adds the whole
    /// surface when a periodic refresh is due.
    fn flush(&self, wait_ms: Option<u64>, refresh: bool) {
        for _ in 0..PRESENT_ROUNDS {
            let outcome = {
                let Some(mut claim) = self.claim() else {
                    return;
                };
                let Some(gpu) = claim.gpu() else {
                    return;
                };
                if refresh && gpu.refresh_due() {
                    add_damage(&self.damage, Damage::of(gpu.full()));
                }
                gpu.flush(&self.damage, wait_ms)
            };
            // Reported after the claim is released: the report is console
            // output, which comes back here.
            if let Some(Err(error)) = outcome {
                if !self.failure_reported.swap(true, Ordering::Relaxed) {
                    say!("ginux: virtio-gpu flush failed: {:?}\n", error);
                }
            }
            if wait_ms.is_none() || self.damage.load(Ordering::Acquire) == 0 {
                return;
            }
        }
    }
}

impl Claim<'_> {
    fn gpu(&mut self) -> Option<&mut Gpu> {
        // SAFETY: this claim holds `held`, so no other reference to `gpu`
        // exists until it drops.
        unsafe { (*self.owner.gpu.get()).as_mut() }
    }

    fn install(&mut self, gpu: Gpu) {
        // SAFETY: as for gpu.
        unsafe { *self.owner.gpu.get() = Some(gpu) };
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
    }
}

/// A GPU whose display resource exists and is backed, but not yet shown.
pub(crate) struct Prepared {
    gpu: Gpu,
    offered: u64,
    /// Whether the I/O MMU admitted the GPU's DMA.
    admitted: bool,
}

/// Opens the virtio-gpu found by [`discover`] and creates its display
/// resource in the mode the host prefers. DMA translation must be off.
/// Returns `None`, leaving the device reset, if any step fails.
///
/// # Safety
///
/// `registers` must map `probe.registers` uncached for the rest of the
/// kernel's life, and nothing else may drive the device.
pub(crate) unsafe fn prepare(probe: &Probe, registers: usize) -> Option<Prepared> {
    let function = probe.function;
    // SAFETY: the caller's contract.
    let registers = unsafe { Mmio::new(registers, probe.registers.1) };
    match Gpu::open(probe, registers) {
        Ok((gpu, offered)) => Some(Prepared {
            gpu,
            offered,
            admitted: false,
        }),
        Err(error) => {
            say!(
                "ginux: virtio-gpu {:02x}:{:02x}.{}: {:?}; keeping the firmware framebuffer\n",
                function.bus,
                function.device,
                function.function,
                error
            );
            None
        }
    }
}

/// A standing I/O MMU admission: (bus, device, function) of each device,
/// and the (start, length) of each DMA region they may reach.
type Admit<'a> = &'a dyn Fn(&[(u8, u8, u8)], &[(u64, u64)]) -> bool;

impl Prepared {
    /// The GPU's DMA regions: its control ring, its command page and the
    /// surface.
    /// The ring, the command slots, the surface and, with 3D, the
    /// submission payload area: `(regions, count)`.
    fn regions(&self) -> ([(u64, u64); 4], usize) {
        let mut regions = [
            self.gpu.device.control.region(),
            self.gpu.device.commands.region(),
            self.gpu.surface.region(),
            (0, 0),
        ];
        let count = match &self.gpu.three_d {
            Some(three_d) => {
                regions[3] = three_d.payload.region();
                4
            }
            None => 3,
        };
        (regions, count)
    }

    /// Admits the GPU through `admit`, which grants standing access once,
    /// together with another driver's `functions` and `regions`. When the
    /// two do not fit together the other driver is admitted alone, and the
    /// GPU is not. Returns whether the other driver was admitted.
    pub(crate) fn admit_alongside(
        &mut self,
        functions: &[(u8, u8, u8)],
        regions: &[(u64, u64)],
        admit: Admit<'_>,
    ) -> bool {
        const LIMIT: usize = 8;
        let (own, count) = self.regions();
        let own = &own[..count];
        if functions.len() < LIMIT && regions.len() + own.len() <= LIMIT {
            let mut all_functions = [(0, 0, 0); LIMIT];
            let mut all_regions = [(0, 0); LIMIT];
            all_functions[..functions.len()].copy_from_slice(functions);
            all_functions[functions.len()] = self.gpu.device.transport.address();
            all_regions[..regions.len()].copy_from_slice(regions);
            all_regions[regions.len()..regions.len() + own.len()].copy_from_slice(own);
            if admit(
                &all_functions[..=functions.len()],
                &all_regions[..regions.len() + own.len()],
            ) {
                self.admitted = true;
                return true;
            }
        }
        admit(functions, regions)
    }

    /// Admits the GPU by itself, when no other driver needs admission.
    pub(crate) fn admit_alone(&mut self, admit: Admit<'_>) {
        let (regions, count) = self.regions();
        self.admitted = admit(&[self.gpu.device.transport.address()], &regions[..count]);
    }
}

/// Shows the prepared GPU's surface on its scanout and moves the console
/// and /dev/fb0 onto it. A GPU the I/O MMU did not admit is reset instead,
/// leaving the firmware framebuffer as the display. Called once, at boot.
pub(crate) fn activate(prepared: Prepared) {
    let Prepared {
        mut gpu,
        offered,
        admitted,
    } = prepared;
    let (bus, device, function) = gpu.device.transport.address();
    if !admitted {
        say!(
            "ginux: virtio-gpu {:02x}:{:02x}.{}: the I/O MMU did not admit it; keeping the firmware framebuffer\n",
            bus,
            device,
            function
        );
        return;
    }
    let shown = gpu.device.execute(&[Command::SetScanout {
        scanout: gpu.scanout,
        resource: RESOURCE,
        rect: gpu.full(),
    }]);
    if let Err(error) = shown {
        say!(
            "ginux: virtio-gpu {:02x}:{:02x}.{}: {:?}; keeping the firmware framebuffer\n",
            bus,
            device,
            function,
            error
        );
        return;
    }
    let display = gpu.display();
    let base = gpu.surface.kernel_address();
    let (mode, scanout) = (gpu.mode, gpu.scanout);
    let capsets = gpu
        .three_d
        .as_ref()
        .map_or(0, |three_d| three_d.features().capsets);
    let host_visible = gpu.three_d.as_ref().map(|three_d| three_d.host_visible);
    {
        let Some(mut claim) = SCANOUT.claim() else {
            return;
        };
        if claim.gpu().is_some() {
            return;
        }
        claim.install(gpu);
    }
    // SAFETY: the surface now belongs to SCANOUT, which never drops or
    // replaces its GPU, so `base` maps `display.length` bytes of it, at
    // `display.physical`, for the rest of the kernel's life.
    if !unsafe { framebuffer::adopt(display, base) } {
        say!("ginux: virtio-gpu: the console did not move to the GPU surface\n");
        return;
    }
    say!(
        "ginux: virtio-gpu {:02x}:{:02x}.{} display {}x{} on scanout {}; host features",
        bus,
        device,
        function,
        mode.width,
        mode.height,
        scanout
    );
    let mut any = false;
    for (bit, name) in [
        (protocol::FEATURE_VIRGL, "virgl"),
        (protocol::FEATURE_EDID, "edid"),
        (protocol::FEATURE_RESOURCE_BLOB, "blob"),
        (protocol::FEATURE_CONTEXT_INIT, "context-init"),
    ] {
        if offered & bit != 0 {
            say!(" {}", name);
            any = true;
        }
    }
    say!("{}\n", if any { "" } else { " none" });
    if let Some((address, length)) = host_visible {
        say!(
            "ginux: virtio-gpu 3D: capsets {:#x}, host-visible region {:#x}+{:#x}\n",
            capsets,
            address,
            length
        );
        PCI_ADDRESS.store(
            u64::from(bus) << 16 | u64::from(device) << 8 | u64::from(function),
            Ordering::Release,
        );
        THREE_D_CAPSETS.store(capsets, Ordering::Release);
    }
}

/// Queues `rect` of the surface for the host and flushes it, waiting
/// briefly for a flush already in progress.
pub(crate) fn present(rect: Rect) {
    add_damage(&SCANOUT.damage, Damage::of(rect));
    SCANOUT.flush(Some(PRESENT_WAIT_MS), false);
}

/// From the Linux timer tick: refreshes the whole surface periodically
/// while a domain draws through /dev/fb0 (`owned`), and retries damage an
/// earlier call left pending. Never waits.
pub(crate) fn refresh(owned: bool) {
    if owned || SCANOUT.damage.load(Ordering::Relaxed) != 0 {
        SCANOUT.flush(None, owned);
    }
}
