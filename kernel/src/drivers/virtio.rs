#![forbid(unsafe_code)]
//! Modern (1.x) virtio over PCI for drivers in the kernel, polled.
//!
//! [`probe`] reads a function's virtio capabilities from configuration space
//! before the kernel builds its page tables, so that the one BAR range they
//! live in can join the device window. [`Transport`] then drives the common
//! configuration through that mapping (reset, feature negotiation, queue
//! setup, status), and [`SplitQueue`] is a split virtqueue that carries
//! descriptor chains: any number in flight, each returned when the device
//! has used it, in whatever order it finishes them. There are no
//! interrupts: MSI-X stays off and INTx is masked, and drivers poll the
//! used ring.
//!
//! This is separate from the reference block and network transport in
//! `arch/x86_64/pci.rs`, which hands those devices to ring-3 services; the
//! drivers here keep their device in the kernel.

use super::device_memory::{DmaBuffer, Mmio};
use super::pci::Function;
use super::wait_until_ms;

pub(crate) const VENDOR: u16 = 0x1af4;
/// The device conforms to virtio 1.x.
const FEATURE_VERSION_1: u64 = 1 << 32;
/// The device's DMA goes through the platform's I/O MMU.
const FEATURE_ACCESS_PLATFORM: u64 = 1 << 33;

const PCI_STATUS_CAPABILITIES: u32 = 1 << 20;
const PCI_CAPABILITY_POINTER: u8 = 0x34;
const CAPABILITY_VENDOR_SPECIFIC: u8 = 0x09;
const CAPABILITY_LIMIT: usize = 48;
const CONFIG_COMMON: u8 = 1;
const CONFIG_NOTIFY: u8 = 2;
const CONFIG_DEVICE: u8 = 4;
/// A shared memory region (`VIRTIO_PCI_CAP_SHARED_MEMORY_CFG`), described
/// by a 64-bit capability.
const CONFIG_SHARED_MEMORY: u8 = 8;
/// The largest register span mapped for one device.
const MAX_REGISTER_SPAN: u64 = 64 * 1024;

const COMMON_DEVICE_FEATURE_SELECT: usize = 0x00;
const COMMON_DEVICE_FEATURE: usize = 0x04;
const COMMON_DRIVER_FEATURE_SELECT: usize = 0x08;
const COMMON_DRIVER_FEATURE: usize = 0x0c;
const COMMON_DEVICE_STATUS: usize = 0x14;
const COMMON_QUEUE_SELECT: usize = 0x16;
const COMMON_QUEUE_SIZE: usize = 0x18;
const COMMON_QUEUE_ENABLE: usize = 0x1c;
const COMMON_QUEUE_NOTIFY_OFF: usize = 0x1e;
const COMMON_QUEUE_DESC: usize = 0x20;
const COMMON_QUEUE_DRIVER: usize = 0x28;
const COMMON_QUEUE_DEVICE: usize = 0x30;
const COMMON_LENGTH: usize = 0x38;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

const DESCRIPTOR_NEXT: u16 = 1;
const DESCRIPTOR_WRITE: u16 = 2;
const DESCRIPTOR_SIZE: usize = 16;

/// A configuration structure's place in the register span.
#[derive(Clone, Copy)]
struct Window {
    offset: usize,
    length: usize,
}

/// Where a virtio function's configuration structures are, found from its
/// PCI capabilities.
#[derive(Clone, Copy)]
pub(crate) struct Probe {
    pub(crate) function: Function,
    /// Physical address and length of the BAR range holding the common,
    /// notification and device-specific structures.
    pub(crate) registers: (u64, usize),
    common: Window,
    notify: Window,
    device: Window,
    notify_multiplier: u32,
    /// The device's shared memory regions: (id, physical address, length).
    pub(crate) shared_memory: [Option<(u8, u64, u64)>; 2],
}

impl Probe {
    /// Shared memory region `id`: its physical address and length.
    pub(crate) fn shared_memory(&self, id: u8) -> Option<(u64, u64)> {
        self.shared_memory
            .iter()
            .flatten()
            .find(|(region, ..)| *region == id)
            .map(|(_, address, length)| (*address, *length))
    }
}

/// One `virtio_pci_cap`: which structure, in which BAR, at what offset.
#[derive(Clone, Copy)]
struct Capability {
    bar: u8,
    offset: u64,
    length: u64,
}

fn config_byte(function: Function, offset: u8) -> u8 {
    (function.read_u32(offset & !3) >> ((offset & 3) * 8)) as u8
}

/// Finds the common, notification and device configuration structures of
/// a modern virtio function. All three must sit in one memory BAR, within
/// [`MAX_REGISTER_SPAN`] of each other. Reads configuration space only,
/// apart from sizing the BAR.
pub(crate) fn probe(function: Function) -> Option<Probe> {
    if function.read_u32(0x04) & PCI_STATUS_CAPABILITIES == 0 {
        return None;
    }
    let mut common = None;
    let mut notify = None;
    let mut device = None;
    let mut notify_multiplier = 0;
    let mut shared_memory = [None; 2];
    let mut pointer = config_byte(function, PCI_CAPABILITY_POINTER) & 0xfc;
    for _ in 0..CAPABILITY_LIMIT {
        if pointer < 0x40 {
            break;
        }
        let next = config_byte(function, pointer + 1) & 0xfc;
        let length = config_byte(function, pointer + 2);
        let kind = config_byte(function, pointer + 3);
        let slot = match kind {
            _ if config_byte(function, pointer) != CAPABILITY_VENDOR_SPECIFIC || length < 16 => {
                None
            }
            CONFIG_COMMON => Some(&mut common),
            CONFIG_NOTIFY if length >= 20 => Some(&mut notify),
            CONFIG_DEVICE => Some(&mut device),
            _ => None,
        };
        let bar = config_byte(function, pointer + 4);
        if kind == CONFIG_SHARED_MEMORY
            && config_byte(function, pointer) == CAPABILITY_VENDOR_SPECIFIC
            && length >= 24
            && bar < 6
        {
            let id = config_byte(function, pointer + 5);
            let high = |offset: u8| u64::from(function.read_u32(pointer + offset)) << 32;
            let offset = u64::from(function.read_u32(pointer + 8)) | high(16);
            let size = u64::from(function.read_u32(pointer + 12)) | high(20);
            let base = function.memory_bar(bar);
            if let (Some(slot), Some(address)) = (
                shared_memory.iter_mut().find(|slot| slot.is_none()),
                base.and_then(|base| base.checked_add(offset)),
            ) {
                *slot = Some((id, address, size));
            }
        }
        // The first usable structure of each type is the one to use.
        if let Some(slot) = slot.filter(|slot| slot.is_none() && bar < 6) {
            if kind == CONFIG_NOTIFY {
                notify_multiplier = function.read_u32(pointer + 16);
            }
            *slot = Some(Capability {
                bar,
                offset: u64::from(function.read_u32(pointer + 8)),
                length: u64::from(function.read_u32(pointer + 12)),
            });
        }
        pointer = next;
    }
    let (common, notify, device) = (common?, notify?, device?);
    let bar = common.bar;
    if notify.bar != bar || device.bar != bar {
        return None;
    }
    let start = common.offset.min(notify.offset).min(device.offset);
    let end = [common, notify, device]
        .iter()
        .map(|capability| capability.offset.checked_add(capability.length))
        .try_fold(0_u64, |end, last| last.map(|last| end.max(last)))?;
    let base = function.memory_bar(bar)?;
    let size = function.memory_bar_size(bar)?;
    if end > size || end - start > MAX_REGISTER_SPAN || common.length < COMMON_LENGTH as u64 {
        return None;
    }
    let window = |capability: Capability| Window {
        offset: (capability.offset - start) as usize,
        length: capability.length as usize,
    };
    Some(Probe {
        function,
        registers: (base.checked_add(start)?, (end - start) as usize),
        common: window(common),
        notify: window(notify),
        device: window(device),
        notify_multiplier,
        shared_memory,
    })
}

/// Why a device did not come up.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    /// The mapped registers do not cover the probed structures.
    Registers,
    /// The device did not finish a reset.
    Reset,
    /// The device is not virtio 1.x, or refused the features offered.
    Features,
    /// The queue does not exist or cannot take the ring.
    Queue,
}

/// The common configuration of a device, with its notification and
/// device-specific structures. Dropping it resets the device and turns
/// off bus mastering, so it stops all DMA before its owner's buffers go.
pub(crate) struct Transport {
    function: Function,
    common: Mmio,
    notify: Mmio,
    device: Mmio,
    notify_multiplier: u32,
}

impl Transport {
    /// Takes the device found by `probe`, whose register span `registers`
    /// maps, enabling memory decoding and bus mastering.
    pub(crate) fn new(probe: &Probe, registers: Mmio) -> Result<Self, Error> {
        let window = |window: Window| registers.window(window.offset, window.length);
        let (Some(common), Some(notify), Some(device)) = (
            window(probe.common),
            window(probe.notify),
            window(probe.device),
        ) else {
            return Err(Error::Registers);
        };
        probe.function.enable_memory_and_bus_master();
        Ok(Self {
            function: probe.function,
            common,
            notify,
            device,
            notify_multiplier: probe.notify_multiplier,
        })
    }

    fn status(&self) -> u8 {
        self.common.read(COMMON_DEVICE_STATUS)
    }

    fn add_status(&self, bits: u8) {
        self.common
            .write(COMMON_DEVICE_STATUS, self.status() | bits);
    }

    /// Resets the device, which forgets its queues and features and stops
    /// its DMA.
    pub(crate) fn reset(&self) -> Result<(), Error> {
        self.common.write(COMMON_DEVICE_STATUS, 0_u8);
        if wait_until_ms(100, || self.status() == 0) {
            Ok(())
        } else {
            Err(Error::Reset)
        }
    }

    /// Resets the device and agrees on features: virtio 1.x, the platform
    /// I/O MMU when the device uses it, and whichever of `wanted` the device
    /// offers. Returns everything the device offered.
    pub(crate) fn negotiate(&self, wanted: u64) -> Result<u64, Error> {
        self.reset()?;
        self.add_status(STATUS_ACKNOWLEDGE);
        self.add_status(STATUS_DRIVER);
        let mut offered = 0_u64;
        for half in 0..2_u32 {
            self.common.write(COMMON_DEVICE_FEATURE_SELECT, half);
            offered |= u64::from(self.common.read::<u32>(COMMON_DEVICE_FEATURE)) << (32 * half);
        }
        if offered & FEATURE_VERSION_1 == 0 {
            self.add_status(STATUS_FAILED);
            return Err(Error::Features);
        }
        let accepted = offered & (wanted | FEATURE_VERSION_1 | FEATURE_ACCESS_PLATFORM);
        for half in 0..2_u32 {
            self.common.write(COMMON_DRIVER_FEATURE_SELECT, half);
            self.common
                .write(COMMON_DRIVER_FEATURE, (accepted >> (32 * half)) as u32);
        }
        self.add_status(STATUS_FEATURES_OK);
        if self.status() & STATUS_FEATURES_OK == 0 {
            self.add_status(STATUS_FAILED);
            return Err(Error::Features);
        }
        Ok(offered)
    }

    /// Hands queue `index` a ring of at most `size` entries in `ring` and
    /// enables it. `size` must be a power of two.
    pub(crate) fn queue(
        &self,
        index: u16,
        size: u16,
        ring: DmaBuffer,
    ) -> Result<SplitQueue, Error> {
        self.common.write(COMMON_QUEUE_SELECT, index);
        let maximum: u16 = self.common.read(COMMON_QUEUE_SIZE);
        // A split ring may be smaller than the device's maximum, but its
        // size stays a power of two.
        let size = size.min(maximum);
        if size == 0 || !size.is_power_of_two() {
            return Err(Error::Queue);
        }
        let layout = RingLayout::new(size);
        if layout.end > ring.len() {
            return Err(Error::Queue);
        }
        let notify_offset = usize::from(self.common.read::<u16>(COMMON_QUEUE_NOTIFY_OFF))
            .checked_mul(self.notify_multiplier as usize)
            .ok_or(Error::Queue)?;
        let notify = self.notify.window(notify_offset, 2).ok_or(Error::Queue)?;
        self.common.write(COMMON_QUEUE_SIZE, size);
        for (register, offset) in [
            (COMMON_QUEUE_DESC, 0),
            (COMMON_QUEUE_DRIVER, layout.available),
            (COMMON_QUEUE_DEVICE, layout.used),
        ] {
            // 64-bit fields are written as two 32-bit halves, low first.
            let address = ring.device_address(offset);
            self.common.write(register, address as u32);
            self.common.write(register + 4, (address >> 32) as u32);
        }
        self.common.write(COMMON_QUEUE_ENABLE, 1_u16);
        if usize::from(size) > MAX_QUEUE_SIZE {
            return Err(Error::Queue);
        }
        let mut free = [0_u16; MAX_QUEUE_SIZE];
        for (slot, descriptor) in free.iter_mut().zip(0..size) {
            *slot = descriptor;
        }
        Ok(SplitQueue {
            ring,
            layout,
            notify,
            index,
            size,
            next_available: 0,
            used_seen: 0,
            free,
            free_count: size,
            chains: [[0; MAX_SEGMENTS]; MAX_QUEUE_SIZE],
            chain_lengths: [0; MAX_QUEUE_SIZE],
            in_flight: 0,
        })
    }

    /// Tells the device the driver is ready; queues may be used from now.
    pub(crate) fn ready(&self) {
        self.add_status(STATUS_DRIVER_OK);
    }

    /// A 32-bit field of the device-specific configuration.
    pub(crate) fn device_u32(&self, offset: usize) -> u32 {
        self.device.read(offset)
    }

    /// The function's (bus, device, function), for I/O MMU admission.
    pub(crate) fn address(&self) -> (u8, u8, u8) {
        (
            self.function.bus,
            self.function.device,
            self.function.function,
        )
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.reset();
        self.function.disable_bus_master();
    }
}

/// Byte offsets of a split ring's three parts in its buffer.
#[derive(Clone, Copy)]
struct RingLayout {
    available: usize,
    used: usize,
    end: usize,
}

impl RingLayout {
    fn new(size: u16) -> Self {
        let size = usize::from(size);
        let available = size * DESCRIPTOR_SIZE;
        // flags, idx, ring[size], used_event; the used ring is 4-aligned.
        let used = (available + 6 + 2 * size).next_multiple_of(4);
        Self {
            available,
            used,
            end: used + 6 + 8 * size,
        }
    }
}

/// One buffer of a descriptor chain, in DMA memory.
#[derive(Clone, Copy)]
pub(crate) struct Segment {
    pub(crate) address: u64,
    pub(crate) length: u32,
    /// The device writes it (a response); otherwise it reads it.
    pub(crate) writable: bool,
}

/// The most buffers one chain has: a request, a payload, a response.
pub(crate) const MAX_SEGMENTS: usize = 3;
/// The largest queue a [`SplitQueue`] runs.
pub(crate) const MAX_QUEUE_SIZE: usize = 64;

/// A split virtqueue. [`SplitQueue::push`] puts a chain of buffers on the
/// available ring and returns its head descriptor; [`SplitQueue::pop`]
/// returns chains as the device finishes with them, in the order it does,
/// and frees their descriptors.
pub(crate) struct SplitQueue {
    ring: DmaBuffer,
    layout: RingLayout,
    notify: Mmio,
    index: u16,
    size: u16,
    next_available: u16,
    used_seen: u16,
    /// Free descriptors, a stack of `free_count`.
    free: [u16; MAX_QUEUE_SIZE],
    free_count: u16,
    /// The descriptors of the chain each in-flight head starts.
    chains: [[u16; MAX_SEGMENTS]; MAX_QUEUE_SIZE],
    chain_lengths: [u8; MAX_QUEUE_SIZE],
    /// Chains the device has not used yet.
    in_flight: u16,
}

impl SplitQueue {
    /// The ring's DMA region, for I/O MMU admission.
    pub(crate) fn region(&self) -> (u64, u64) {
        self.ring.region()
    }

    /// Whether a chain of `segments` buffers fits now.
    pub(crate) fn has_room(&self, segments: usize) -> bool {
        usize::from(self.free_count) >= segments
    }

    /// Puts a chain of `segments` (the device-read ones first) on the
    /// available ring and notifies the device. Returns its head, or `None`
    /// when too few descriptors are free.
    pub(crate) fn push(&mut self, segments: &[Segment]) -> Option<u16> {
        if segments.is_empty()
            || segments.len() > MAX_SEGMENTS
            || usize::from(self.free_count) < segments.len()
        {
            return None;
        }
        let mut descriptors = [0_u16; MAX_SEGMENTS];
        for descriptor in descriptors.iter_mut().take(segments.len()) {
            self.free_count -= 1;
            *descriptor = self.free[usize::from(self.free_count)];
        }
        for (position, segment) in segments.iter().enumerate() {
            let last = position + 1 == segments.len();
            let flags = if segment.writable {
                DESCRIPTOR_WRITE
            } else {
                0
            } | if last { 0 } else { DESCRIPTOR_NEXT };
            let next = if last { 0 } else { descriptors[position + 1] };
            self.descriptor(
                descriptors[position],
                (segment.address, segment.length),
                flags,
                next,
            );
        }
        let head = descriptors[0];
        self.chains[usize::from(head)] = descriptors;
        self.chain_lengths[usize::from(head)] = segments.len() as u8;
        let mask = self.size - 1;
        let entry = usize::from(self.next_available & mask);
        self.ring.write(self.layout.available + 4 + 2 * entry, head);
        self.next_available = self.next_available.wrapping_add(1);
        self.in_flight += 1;
        // The descriptors and ring entry must be visible before the index
        // that publishes them, and the index before the notification.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.ring
            .write(self.layout.available + 2, self.next_available);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.notify.write(0, self.index);
        Some(head)
    }

    fn descriptor(&self, index: u16, (address, length): (u64, u32), flags: u16, next: u16) {
        let offset = usize::from(index) * DESCRIPTOR_SIZE;
        self.ring.write(offset, address);
        self.ring.write(offset + 8, length);
        self.ring.write(offset + 12, flags);
        self.ring.write(offset + 14, next);
    }

    /// The next chain the device has used: its head and the bytes it wrote.
    /// Its descriptors are free again; its buffers may be read now.
    pub(crate) fn pop(&mut self) -> Option<(u16, u32)> {
        let used: u16 = self.ring.read(self.layout.used + 2);
        if used == self.used_seen {
            return None;
        }
        // Entries written before the index are read after it.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let mask = self.size - 1;
        let entry = self.layout.used + 4 + 8 * usize::from(self.used_seen & mask);
        let head: u32 = self.ring.read(entry);
        let written: u32 = self.ring.read(entry + 4);
        self.used_seen = self.used_seen.wrapping_add(1);
        let head = u16::try_from(head).ok().filter(|head| *head < self.size)?;
        let length = usize::from(self.chain_lengths[usize::from(head)]);
        for descriptor in &self.chains[usize::from(head)][..length] {
            self.free[usize::from(self.free_count)] = *descriptor;
            self.free_count += 1;
        }
        self.chain_lengths[usize::from(head)] = 0;
        self.in_flight = self.in_flight.saturating_sub(1);
        Some((head, written))
    }
}
