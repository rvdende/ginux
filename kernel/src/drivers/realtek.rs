//! Realtek RTL8125 and RTL8168-family Ethernet controllers.
//!
//! `probe` only reads registers: the MAC address, the chip identifier, and
//! the PHY link state. `Controller` resets an RTL8125 or RTL8126 and moves
//! frames through polled descriptor rings, following the register layout of
//! Linux's r8169 driver. It skips the chip-specific tuning that driver
//! applies and relies on the link firmware negotiated; it has not been run
//! on hardware yet.

use core::ptr::{addr_of, addr_of_mut};

use super::net::{Nic, FRAME_LIMIT};
use super::pci::{Function, Identity};
use super::{wait_until_ms, DmaPage, DmaRegion};

const VENDOR_REALTEK: u16 = 0x10ec;
const MAC_ADDRESS: usize = 0x00;
const MULTICAST_FILTER: usize = 0x08;
const TRANSMIT_RING_LOW: usize = 0x20;
const TRANSMIT_RING_HIGH: usize = 0x24;
const CHIP_COMMAND: usize = 0x37;
const INTERRUPT_MASK_8125: usize = 0x38;
const INTERRUPT_STATUS_8125: usize = 0x3c;
const TRANSMIT_CONFIG: usize = 0x40;
const RECEIVE_CONFIG: usize = 0x44;
const CONFIG_LOCK: usize = 0x50;
const PHY_STATUS: usize = 0x6c;
const TRANSMIT_POLL_8125: usize = 0x90;
const RECEIVE_MAX_SIZE: usize = 0xda;
const RECEIVE_RING_LOW: usize = 0xe4;
const RECEIVE_RING_HIGH: usize = 0xe8;
const COMMAND_RESET: u8 = 0x10;
const COMMAND_RECEIVE: u8 = 0x08;
const COMMAND_TRANSMIT: u8 = 0x04;
const CONFIG_UNLOCKED: u8 = 0xc0;
const CONFIG_LOCKED: u8 = 0x00;
const ACCEPT_BROADCAST: u32 = 0x08;
const ACCEPT_MULTICAST: u32 = 0x04;
const ACCEPT_MY_ADDRESS: u32 = 0x02;
/// RX_FETCH_DFLT_8125 and an unlimited DMA burst, as r8169 sets them.
const RECEIVE_DEFAULTS_8125: u32 = 8 << 27 | 7 << 8;
/// Unlimited DMA burst, the standard inter-frame gap, and automatic FIFO.
const TRANSMIT_DEFAULTS_8125: u32 = 7 << 8 | 3 << 24 | 1 << 7;
const PHY_FULL_DUPLEX: u16 = 0x0001;
const PHY_LINK: u16 = 0x0002;
const PHY_10_MBPS: u16 = 0x0004;
const PHY_100_MBPS: u16 = 0x0008;
const PHY_1000_MBPS: u16 = 0x0010;
const PHY_2500_MBPS: u16 = 0x0400;
const DESCRIPTOR_OWNED: u32 = 1 << 31;
const DESCRIPTOR_RING_END: u32 = 1 << 30;
const DESCRIPTOR_FIRST: u32 = 1 << 29;
const DESCRIPTOR_LAST: u32 = 1 << 28;
const RECEIVE_ERROR: u32 = 1 << 21;
const RECEIVE_DESCRIPTORS: usize = 32;
const TRANSMIT_DESCRIPTORS: usize = 8;
const BUFFER_SIZE: usize = 2048;
const TRANSMIT_TIMEOUT_MS: u64 = 100;
const LINK_TIMEOUT_MS: u64 = 5000;

static mut RECEIVE_RING: DmaPage = DmaPage::ZERO;
static mut TRANSMIT_RING: DmaPage = DmaPage::ZERO;
static mut RECEIVE_BUFFERS: [DmaPage; RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096] =
    [DmaPage::ZERO; RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096];
static mut TRANSMIT_BUFFERS: [DmaPage; TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096] =
    [DmaPage::ZERO; TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096];

/// What the controller reports about itself and its link.
pub(crate) struct Report {
    pub(crate) mac: [u8; 6],
    /// The chip identifier, bits 30:20 of TxConfig as r8169 masks them.
    pub(crate) chip: u32,
    /// Link speed in Mb/s, or `None` without a link.
    pub(crate) speed: Option<u32>,
    pub(crate) full_duplex: bool,
}

/// Returns whether `device` is an RTL8125 or RTL8168-family controller.
pub(crate) fn is_supported(device: &Identity) -> bool {
    device.vendor == VENDOR_REALTEK && matches!(device.device, 0x8125 | 0x8126 | 0x8161 | 0x8168)
}

/// Returns whether `Controller` can drive `device`: the 2.5 and 5 Gb/s
/// RTL8125 and RTL8126, whose register layout differs from the RTL8168.
pub(crate) fn can_transfer(device: &Identity) -> bool {
    device.vendor == VENDOR_REALTEK && matches!(device.device, 0x8125 | 0x8126)
}

/// The memory Realtek controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 4] {
    [
        DmaRegion::of(addr_of!(RECEIVE_RING)),
        DmaRegion::of(addr_of!(TRANSMIT_RING)),
        DmaRegion::of(addr_of!(RECEIVE_BUFFERS)),
        DmaRegion::of(addr_of!(TRANSMIT_BUFFERS)),
    ]
}

/// Reads the identity and link state of a supported controller.
///
/// # Safety
///
/// `function` must be a supported controller whose memory BAR is identity
/// mapped. Reading these registers has no side effects.
pub(crate) unsafe fn probe(function: Function) -> Option<Report> {
    // BAR 0 is I/O space on these chips; the registers are mirrored in BAR 2.
    let base = function.memory_bar(2)? as usize;
    function.enable_memory();
    let mut mac = [0_u8; 6];
    for (index, value) in mac.iter_mut().enumerate() {
        *value = read8(base, MAC_ADDRESS + index);
    }
    let transmit = read32(base, TRANSMIT_CONFIG);
    let (speed, full_duplex) = link(base);
    Some(Report {
        mac,
        chip: (transmit >> 20) & 0x7cf,
        speed,
        full_duplex,
    })
}

/// Decodes PHYstatus into a link speed and duplex.
fn link(base: usize) -> (Option<u32>, bool) {
    let phy = read16(base, PHY_STATUS);
    let speed = if phy & PHY_2500_MBPS != 0 {
        2500
    } else if phy & PHY_1000_MBPS != 0 {
        1000
    } else if phy & PHY_100_MBPS != 0 {
        100
    } else if phy & PHY_10_MBPS != 0 {
        10
    } else {
        0
    };
    (
        (phy & PHY_LINK != 0).then_some(speed),
        phy & PHY_FULL_DUPLEX != 0,
    )
}

/// A running RTL8125 or RTL8126.
pub(crate) struct Controller {
    base: usize,
    mac: [u8; 6],
    next_receive: usize,
    next_transmit: usize,
}

impl Controller {
    /// Resets the controller, starts its rings, and waits for the link to
    /// come back.
    ///
    /// # Safety
    ///
    /// `function` must satisfy `can_transfer`, nothing else may drive it,
    /// and its registers and this driver's DMA pages must be identity
    /// mapped. Only one controller may be open at a time.
    pub(crate) unsafe fn open(function: Function) -> Option<Self> {
        let base = function.memory_bar(2)? as usize;
        function.enable_memory_and_bus_master();
        let mut mac = [0_u8; 6];
        for (index, value) in mac.iter_mut().enumerate() {
            *value = read8(base, MAC_ADDRESS + index);
        }
        write32(base, INTERRUPT_MASK_8125, 0);
        write8(base, CHIP_COMMAND, COMMAND_RESET);
        if !wait_until_ms(100, || read8(base, CHIP_COMMAND) & COMMAND_RESET == 0) {
            return None;
        }
        write32(base, INTERRUPT_MASK_8125, 0);
        write32(base, INTERRUPT_STATUS_8125, u32::MAX);

        let receive_ring = addr_of_mut!(RECEIVE_RING).cast::<u32>();
        for index in 0..RECEIVE_DESCRIPTORS {
            write_descriptor(
                receive_ring,
                index,
                receive_buffer(index),
                receive_ready(index),
            );
        }
        let transmit_ring = addr_of_mut!(TRANSMIT_RING).cast::<u32>();
        for index in 0..TRANSMIT_DESCRIPTORS {
            let end = if index == TRANSMIT_DESCRIPTORS - 1 {
                DESCRIPTOR_RING_END
            } else {
                0
            };
            write_descriptor(transmit_ring, index, transmit_buffer(index), end);
        }

        write8(base, CONFIG_LOCK, CONFIG_UNLOCKED);
        write32(
            base,
            TRANSMIT_RING_HIGH,
            (transmit_ring as u64 >> 32) as u32,
        );
        write32(base, TRANSMIT_RING_LOW, transmit_ring as u32);
        write32(base, RECEIVE_RING_HIGH, (receive_ring as u64 >> 32) as u32);
        write32(base, RECEIVE_RING_LOW, receive_ring as u32);
        write16(base, RECEIVE_MAX_SIZE, BUFFER_SIZE as u16);
        write8(base, CONFIG_LOCK, CONFIG_LOCKED);
        write8(base, CHIP_COMMAND, COMMAND_TRANSMIT | COMMAND_RECEIVE);
        write32(
            base,
            RECEIVE_CONFIG,
            RECEIVE_DEFAULTS_8125 | ACCEPT_BROADCAST | ACCEPT_MULTICAST | ACCEPT_MY_ADDRESS,
        );
        write32(base, MULTICAST_FILTER, u32::MAX);
        write32(base, MULTICAST_FILTER + 4, u32::MAX);
        write32(base, TRANSMIT_CONFIG, TRANSMIT_DEFAULTS_8125);
        // The reset restarts autonegotiation.
        let _ = wait_until_ms(LINK_TIMEOUT_MS, || link(base).0.is_some());
        Some(Self {
            base,
            mac,
            next_receive: 0,
            next_transmit: 0,
        })
    }

    /// The link speed in Mb/s, or `None` without a link.
    pub(crate) fn link_speed(&self) -> Option<u32> {
        link(self.base).0
    }
}

impl Nic for Controller {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> bool {
        if frame.len() > FRAME_LIMIT {
            return false;
        }
        let index = self.next_transmit;
        let ring = addr_of_mut!(TRANSMIT_RING).cast::<u32>();
        // SAFETY: the descriptor and its buffer belong to this driver, and
        // the controller released the descriptor (checked below).
        unsafe {
            if ring.add(index * 4).read_volatile() & DESCRIPTOR_OWNED != 0 {
                return false;
            }
            let buffer = transmit_buffer(index);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
            // Pad to the 60-byte minimum; the controller appends the FCS.
            let length = frame.len().max(60);
            buffer.add(frame.len()).write_bytes(0, length - frame.len());
            let end = if index == TRANSMIT_DESCRIPTORS - 1 {
                DESCRIPTOR_RING_END
            } else {
                0
            };
            write_descriptor(
                ring,
                index,
                buffer,
                DESCRIPTOR_OWNED | end | DESCRIPTOR_FIRST | DESCRIPTOR_LAST | length as u32,
            );
        }
        self.next_transmit = (index + 1) % TRANSMIT_DESCRIPTORS;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write16(self.base, TRANSMIT_POLL_8125, 1);
        wait_until_ms(TRANSMIT_TIMEOUT_MS, || {
            // SAFETY: the controller clears the owned bit once it is done.
            unsafe { ring.add(index * 4).read_volatile() & DESCRIPTOR_OWNED == 0 }
        })
    }

    fn receive(&mut self, buffer: &mut [u8; FRAME_LIMIT]) -> Option<usize> {
        let index = self.next_receive;
        let ring = addr_of_mut!(RECEIVE_RING).cast::<u32>();
        // SAFETY: the descriptor belongs to this driver; the controller
        // cleared its owned bit after writing the buffer.
        unsafe {
            let status = ring.add(index * 4).read_volatile();
            if status & DESCRIPTOR_OWNED != 0 {
                return None;
            }
            let length = (status & 0x3fff) as usize;
            let complete = status & (DESCRIPTOR_FIRST | DESCRIPTOR_LAST)
                == DESCRIPTOR_FIRST | DESCRIPTOR_LAST
                && status & RECEIVE_ERROR == 0
                && length > 4;
            // The length includes the FCS.
            let copied = if complete {
                let copied = (length - 4).min(FRAME_LIMIT);
                core::ptr::copy_nonoverlapping(receive_buffer(index), buffer.as_mut_ptr(), copied);
                copied
            } else {
                0
            };
            write_descriptor(ring, index, receive_buffer(index), receive_ready(index));
            self.next_receive = (index + 1) % RECEIVE_DESCRIPTORS;
            // An errored frame is dropped; report an empty frame so callers
            // keep polling.
            Some(copied)
        }
    }
}

/// The first word of a receive descriptor handed to the controller.
fn receive_ready(index: usize) -> u32 {
    let end = if index == RECEIVE_DESCRIPTORS - 1 {
        DESCRIPTOR_RING_END
    } else {
        0
    };
    DESCRIPTOR_OWNED | end | BUFFER_SIZE as u32
}

/// Writes descriptor `index`: its buffer address, then its first word, so
/// the controller never sees an owned descriptor without its buffer.
///
/// # Safety
///
/// `ring` must be one of this driver's descriptor rings with room for
/// `index`.
unsafe fn write_descriptor(ring: *mut u32, index: usize, buffer: *mut u8, first: u32) {
    let descriptor = ring.add(index * 4);
    descriptor.add(1).write_volatile(0);
    descriptor.add(2).write_volatile(buffer as u32);
    descriptor
        .add(3)
        .write_volatile((buffer as u64 >> 32) as u32);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    descriptor.write_volatile(first);
}

fn receive_buffer(index: usize) -> *mut u8 {
    // SAFETY: index is below RECEIVE_DESCRIPTORS, so the offset stays in
    // the buffer array.
    unsafe {
        addr_of_mut!(RECEIVE_BUFFERS)
            .cast::<u8>()
            .add(index * BUFFER_SIZE)
    }
}

fn transmit_buffer(index: usize) -> *mut u8 {
    // SAFETY: as for receive_buffer.
    unsafe {
        addr_of_mut!(TRANSMIT_BUFFERS)
            .cast::<u8>()
            .add(index * BUFFER_SIZE)
    }
}

fn read8(base: usize, offset: usize) -> u8 {
    // SAFETY: callers pass identity-mapped controller registers.
    unsafe { ((base + offset) as *const u8).read_volatile() }
}

fn read16(base: usize, offset: usize) -> u16 {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *const u16).read_volatile() }
}

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write8(base: usize, offset: usize, value: u8) {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *mut u8).write_volatile(value) }
}

fn write16(base: usize, offset: usize, value: u16) {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *mut u16).write_volatile(value) }
}

fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: as for read8.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) }
}
