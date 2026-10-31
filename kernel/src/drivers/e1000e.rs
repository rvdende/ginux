//! Intel 82574 (e1000e) Ethernet, as QEMU emulates it, with polled transmit
//! and receive through legacy descriptors.
//!
//! The driver exists to test the shared network code in QEMU; the PCs it is
//! aimed at mostly carry Realtek controllers.

use core::ptr::{addr_of, addr_of_mut};

use super::net::{Nic, FRAME_LIMIT};
use super::pci::{Function, Identity};
use super::{delay_ms, wait_until_ms, DmaPage, DmaRegion};

const VENDOR_INTEL: u16 = 0x8086;
const DEVICE_82574: u16 = 0x10d3;
const CONTROL: usize = 0x0000;
const STATUS: usize = 0x0008;
const INTERRUPT_MASK_CLEAR: usize = 0x00d8;
const RECEIVE_CONTROL: usize = 0x0100;
const TRANSMIT_CONTROL: usize = 0x0400;
const MULTICAST_TABLE: usize = 0x5200;
const RECEIVE_ADDRESS_LOW: usize = 0x5400;
const RECEIVE_ADDRESS_HIGH: usize = 0x5404;
const RECEIVE_BASE_LOW: usize = 0x2800;
const RECEIVE_BASE_HIGH: usize = 0x2804;
const RECEIVE_LENGTH: usize = 0x2808;
const RECEIVE_HEAD: usize = 0x2810;
const RECEIVE_TAIL: usize = 0x2818;
const TRANSMIT_BASE_LOW: usize = 0x3800;
const TRANSMIT_BASE_HIGH: usize = 0x3804;
const TRANSMIT_LENGTH: usize = 0x3808;
const TRANSMIT_HEAD: usize = 0x3810;
const TRANSMIT_TAIL: usize = 0x3818;
const CONTROL_SET_LINK_UP: u32 = 1 << 6;
const CONTROL_RESET: u32 = 1 << 26;
const STATUS_LINK_UP: u32 = 1 << 1;
const RECEIVE_ENABLE: u32 = 1 << 1;
const RECEIVE_BROADCAST: u32 = 1 << 15;
const RECEIVE_STRIP_CRC: u32 = 1 << 26;
const TRANSMIT_ENABLE: u32 = 1 << 1;
const TRANSMIT_PAD_SHORT: u32 = 1 << 3;
const TRANSMIT_COLLISION_THRESHOLD: u32 = 0x0f << 4;
const TRANSMIT_COLLISION_DISTANCE: u32 = 0x3f << 12;
const ADDRESS_VALID: u32 = 1 << 31;
const DESCRIPTOR_DONE: u8 = 1 << 0;
const DESCRIPTOR_END_OF_PACKET: u8 = 1 << 0;
const COMMAND_INSERT_FCS: u8 = 1 << 1;
const COMMAND_REPORT_STATUS: u8 = 1 << 3;
const RECEIVE_DESCRIPTORS: usize = 32;
const TRANSMIT_DESCRIPTORS: usize = 8;
const BUFFER_SIZE: usize = 2048;
const TRANSMIT_TIMEOUT_MS: u64 = 100;

static mut RECEIVE_RING: DmaPage = DmaPage::ZERO;
static mut TRANSMIT_RING: DmaPage = DmaPage::ZERO;
static mut RECEIVE_BUFFERS: [DmaPage; RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096] =
    [DmaPage::ZERO; RECEIVE_DESCRIPTORS * BUFFER_SIZE / 4096];
static mut TRANSMIT_BUFFERS: [DmaPage; TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096] =
    [DmaPage::ZERO; TRANSMIT_DESCRIPTORS * BUFFER_SIZE / 4096];

/// Returns whether `device` is an 82574.
pub(crate) fn is_supported(device: &Identity) -> bool {
    device.vendor == VENDOR_INTEL && device.device == DEVICE_82574
}

/// The memory 82574 controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 4] {
    [
        DmaRegion::of(addr_of!(RECEIVE_RING)),
        DmaRegion::of(addr_of!(TRANSMIT_RING)),
        DmaRegion::of(addr_of!(RECEIVE_BUFFERS)),
        DmaRegion::of(addr_of!(TRANSMIT_BUFFERS)),
    ]
}

/// A running controller.
pub(crate) struct Controller {
    base: usize,
    mac: [u8; 6],
    next_receive: usize,
    next_transmit: usize,
}

impl Controller {
    /// Resets the controller and starts its receive and transmit rings.
    ///
    /// # Safety
    ///
    /// `function` must be an 82574 that nothing else drives, with its
    /// registers and this driver's DMA pages identity mapped. Only one
    /// controller may be open at a time.
    pub(crate) unsafe fn open(function: Function) -> Option<Self> {
        let base = function.memory_bar(0)? as usize;
        function.enable_memory_and_bus_master();
        write32(base, INTERRUPT_MASK_CLEAR, u32::MAX);
        write32(base, CONTROL, read32(base, CONTROL) | CONTROL_RESET);
        delay_ms(1);
        if !wait_until_ms(100, || read32(base, CONTROL) & CONTROL_RESET == 0) {
            return None;
        }
        write32(base, INTERRUPT_MASK_CLEAR, u32::MAX);
        write32(base, CONTROL, read32(base, CONTROL) | CONTROL_SET_LINK_UP);

        // The controller loads its address from the EEPROM at reset.
        let low = read32(base, RECEIVE_ADDRESS_LOW).to_le_bytes();
        let high = read32(base, RECEIVE_ADDRESS_HIGH);
        let mac = [
            low[0],
            low[1],
            low[2],
            low[3],
            high as u8,
            (high >> 8) as u8,
        ];
        write32(base, RECEIVE_ADDRESS_HIGH, high | ADDRESS_VALID);
        for index in 0..128 {
            write32(base, MULTICAST_TABLE + index * 4, 0);
        }

        let receive_ring = addr_of_mut!(RECEIVE_RING).cast::<u64>();
        for index in 0..RECEIVE_DESCRIPTORS {
            receive_ring
                .add(index * 2)
                .write_volatile(receive_buffer(index) as u64);
            receive_ring.add(index * 2 + 1).write_volatile(0);
        }
        let transmit_ring = addr_of_mut!(TRANSMIT_RING).cast::<u64>();
        for index in 0..TRANSMIT_DESCRIPTORS * 2 {
            transmit_ring.add(index).write_volatile(0);
        }
        write64(
            base,
            RECEIVE_BASE_LOW,
            RECEIVE_BASE_HIGH,
            receive_ring as u64,
        );
        write32(base, RECEIVE_LENGTH, (RECEIVE_DESCRIPTORS * 16) as u32);
        write32(base, RECEIVE_HEAD, 0);
        write32(base, RECEIVE_TAIL, (RECEIVE_DESCRIPTORS - 1) as u32);
        write64(
            base,
            TRANSMIT_BASE_LOW,
            TRANSMIT_BASE_HIGH,
            transmit_ring as u64,
        );
        write32(base, TRANSMIT_LENGTH, (TRANSMIT_DESCRIPTORS * 16) as u32);
        write32(base, TRANSMIT_HEAD, 0);
        write32(base, TRANSMIT_TAIL, 0);
        // A 2048-byte buffer size is the default encoding (BSIZE 0).
        write32(
            base,
            RECEIVE_CONTROL,
            RECEIVE_ENABLE | RECEIVE_BROADCAST | RECEIVE_STRIP_CRC,
        );
        write32(
            base,
            TRANSMIT_CONTROL,
            TRANSMIT_ENABLE
                | TRANSMIT_PAD_SHORT
                | TRANSMIT_COLLISION_THRESHOLD
                | TRANSMIT_COLLISION_DISTANCE,
        );
        Some(Self {
            base,
            mac,
            next_receive: 0,
            next_transmit: 0,
        })
    }

    /// Whether the link is up.
    pub(crate) fn link_up(&self) -> bool {
        read32(self.base, STATUS) & STATUS_LINK_UP != 0
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
        // SAFETY: the descriptor and its buffer belong to this driver, and
        // the controller is done with them (checked below before reuse).
        unsafe {
            let buffer = transmit_buffer(index);
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buffer, frame.len());
            let descriptor = addr_of_mut!(TRANSMIT_RING).cast::<u64>().add(index * 2);
            descriptor.write_volatile(buffer as u64);
            let command = COMMAND_REPORT_STATUS | COMMAND_INSERT_FCS | DESCRIPTOR_END_OF_PACKET;
            descriptor
                .add(1)
                .write_volatile(frame.len() as u64 | u64::from(command) << 24);
        }
        self.next_transmit = (index + 1) % TRANSMIT_DESCRIPTORS;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write32(self.base, TRANSMIT_TAIL, self.next_transmit as u32);
        wait_until_ms(TRANSMIT_TIMEOUT_MS, || {
            // SAFETY: the status byte is written back by the controller.
            let status = unsafe {
                addr_of!(TRANSMIT_RING)
                    .cast::<u8>()
                    .add(index * 16 + 12)
                    .read_volatile()
            };
            status & DESCRIPTOR_DONE != 0
        })
    }

    fn receive(&mut self, buffer: &mut [u8; FRAME_LIMIT]) -> Option<usize> {
        let index = self.next_receive;
        // SAFETY: the descriptor belongs to this driver; the controller set
        // its done bit after writing the buffer.
        unsafe {
            let descriptor = addr_of_mut!(RECEIVE_RING).cast::<u8>().add(index * 16);
            let status = descriptor.add(12).read_volatile();
            if status & DESCRIPTOR_DONE == 0 {
                return None;
            }
            let length = usize::from(descriptor.add(8).cast::<u16>().read_volatile());
            let copied = length.min(FRAME_LIMIT);
            core::ptr::copy_nonoverlapping(receive_buffer(index), buffer.as_mut_ptr(), copied);
            descriptor.add(12).write_volatile(0);
            self.next_receive = (index + 1) % RECEIVE_DESCRIPTORS;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            write32(self.base, RECEIVE_TAIL, index as u32);
            Some(copied)
        }
    }
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

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: callers pass identity-mapped controller registers.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: as for read32.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) }
}

fn write64(base: usize, low: usize, high: usize, value: u64) {
    write32(base, low, value as u32);
    write32(base, high, (value >> 32) as u32);
}
