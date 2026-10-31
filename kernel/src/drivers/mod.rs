//! Device drivers for physical hardware, independent of the QEMU reference
//! devices that the main boot path is built around.
//!
//! These drivers poll instead of taking interrupts, use page-aligned static DMA
//! buffers, and access registers through the identity map, so they work both
//! in hardware bring-up mode (on the firmware page tables) and later from the
//! main kernel.

pub(crate) mod ahci;
pub(crate) mod amd_iommu;
pub(crate) mod e1000e;
pub(crate) mod gpt;
pub(crate) mod keyboard;
pub(crate) mod net;
pub(crate) mod nvme;
pub(crate) mod pci;
pub(crate) mod realtek;
pub(crate) mod xhci;

use core::fmt::Write;

/// Formats into the console (serial when present, and the framebuffer),
/// expanding `\n` to `\r\n` for serial terminals.
pub(crate) struct Console;

impl Write for Console {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let mut lines = text.split('\n');
        if let Some(first) = lines.next() {
            crate::serial_write_raw(first.as_bytes());
        }
        for line in lines {
            crate::serial_write_raw(b"\r\n");
            crate::serial_write_raw(line.as_bytes());
        }
        Ok(())
    }
}

macro_rules! say {
    ($($argument:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(
            &mut $crate::drivers::Console,
            format_args!($($argument)*),
        );
    }};
}
pub(crate) use say;

/// A disk that reads fixed-size blocks into a driver-owned buffer.
pub(crate) trait BlockDevice {
    fn block_size(&self) -> u32;

    /// Reads `count` blocks starting at `block`, at most one 4 KiB page.
    fn read_blocks(&mut self, block: u64, count: u32) -> Option<&[u8]>;
}

/// Memory a driver lets its device reach by DMA, which the I/O MMU maps for
/// that device and no other.
#[derive(Clone, Copy)]
pub(crate) struct DmaRegion {
    pub(crate) start: u64,
    pub(crate) length: u64,
}

impl DmaRegion {
    fn of<T>(object: *const T) -> Self {
        Self {
            start: object as u64,
            length: core::mem::size_of::<T>() as u64,
        }
    }
}

/// A 4 KiB page usable as a DMA buffer: the kernel image is identity mapped,
/// so its address is also its physical address.
#[repr(C, align(4096))]
pub(crate) struct DmaPage(pub(crate) [u8; 4096]);

impl DmaPage {
    pub(crate) const ZERO: Self = Self([0; 4096]);
}

/// Waits until `ready` returns true or roughly `seconds` have elapsed.
pub(crate) fn wait_until(seconds: u64, ready: impl FnMut() -> bool) -> bool {
    wait_until_ms(seconds.saturating_mul(1000), ready)
}

/// Spins for at least `milliseconds`.
pub(crate) fn delay_ms(milliseconds: u64) {
    wait_until_ms(milliseconds, || false);
}

/// Waits until `ready` returns true or roughly `milliseconds` have elapsed.
///
/// The bound assumes a timestamp counter of at most 5 GHz, so it never waits
/// less than requested; slower counters wait proportionally longer.
pub(crate) fn wait_until_ms(milliseconds: u64, mut ready: impl FnMut() -> bool) -> bool {
    let start = crate::arch::x86_64::timer::timestamp_counter();
    let limit = milliseconds.saturating_mul(5_000_000);
    loop {
        if ready() {
            return true;
        }
        if crate::arch::x86_64::timer::timestamp_counter().wrapping_sub(start) > limit {
            return false;
        }
        core::hint::spin_loop();
    }
}
