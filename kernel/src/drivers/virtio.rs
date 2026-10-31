#![forbid(unsafe_code)]
//! Modern (1.x) virtio over PCI for drivers in the kernel, polled.
//!
//! [`probe`] reads a function's virtio capabilities from configuration space
//! before the kernel builds its page tables, so that the one BAR range they
//! live in can join the device window. [`Transport`] then drives the common
//! configuration through that mapping (reset, feature negotiation, queue
//! setup, status), and [`SplitQueue`] is a split virtqueue that carries
//! request/response descriptor chains. There are no interrupts: MSI-X stays
//! off and INTx is masked, and drivers poll the used ring.
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
        Ok(SplitQueue {
            ring,
            layout,
            notify,
            index,
            size,
            next_available: 0,
            used_seen: 0,
            outstanding: 0,
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

/// A request the device reads followed by a response it writes, both in
/// DMA memory: (device address, length).
#[derive(Clone, Copy)]
pub(crate) struct Chain {
    pub(crate) request: (u64, u32),
    pub(crate) response: (u64, u32),
}

/// A split virtqueue used one batch at a time: the driver submits a batch
/// of two-descriptor chains and polls until the device has used them all
/// before submitting the next. Chain `n` of a batch always occupies
/// descriptors `2n` and `2n + 1`, so no free list is needed.
pub(crate) struct SplitQueue {
    ring: DmaBuffer,
    layout: RingLayout,
    notify: Mmio,
    index: u16,
    size: u16,
    next_available: u16,
    used_seen: u16,
    /// Chains of the current batch the device has not used yet.
    outstanding: u16,
}

impl SplitQueue {
    /// The most chains one batch can hold.
    pub(crate) fn capacity(&self) -> usize {
        usize::from(self.size / 2)
    }

    /// The ring's DMA region, for I/O MMU admission.
    pub(crate) fn region(&self) -> (u64, u64) {
        self.ring.region()
    }

    /// Submits `chains` as one batch and notifies the device. Returns false,
    /// submitting nothing, while an earlier batch is outstanding or when
    /// the batch does not fit.
    pub(crate) fn submit(&mut self, chains: &[Chain]) -> bool {
        if self.outstanding != 0 || chains.is_empty() || chains.len() > self.capacity() {
            return false;
        }
        let mask = self.size - 1;
        for (slot, chain) in chains.iter().enumerate() {
            let head = (slot * 2) as u16;
            self.descriptor(head, chain.request, DESCRIPTOR_NEXT, head + 1);
            self.descriptor(head + 1, chain.response, DESCRIPTOR_WRITE, 0);
            let entry = (self.next_available.wrapping_add(slot as u16) & mask) as usize;
            self.ring.write(self.layout.available + 4 + 2 * entry, head);
        }
        self.next_available = self.next_available.wrapping_add(chains.len() as u16);
        self.outstanding = chains.len() as u16;
        // The descriptors and ring entries must be visible before the index
        // that publishes them, and the index before the notification.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.ring
            .write(self.layout.available + 2, self.next_available);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        self.notify.write(0, self.index);
        true
    }

    fn descriptor(&self, index: u16, (address, length): (u64, u32), flags: u16, next: u16) {
        let offset = usize::from(index) * DESCRIPTOR_SIZE;
        self.ring.write(offset, address);
        self.ring.write(offset + 8, length);
        self.ring.write(offset + 12, flags);
        self.ring.write(offset + 14, next);
    }

    /// Whether the device has used every chain submitted so far. Responses
    /// may be read once this returns true.
    pub(crate) fn idle(&mut self) -> bool {
        if self.outstanding == 0 {
            return true;
        }
        let used: u16 = self.ring.read(self.layout.used + 2);
        let done = used.wrapping_sub(self.used_seen).min(self.outstanding);
        self.used_seen = self.used_seen.wrapping_add(done);
        self.outstanding -= done;
        // Responses written before the index are read after it.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        self.outstanding == 0
    }
}
