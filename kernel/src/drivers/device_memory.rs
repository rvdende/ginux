//! The unsafe floor under the virtio drivers: device registers and DMA
//! memory, each behind a bounds-checked handle.
//!
//! Everything above this module is safe Rust. It hands out two kinds of
//! memory:
//!
//! - [`Mmio`], a range of one device's registers that the kernel mapped
//!   uncached. Creating one is the only unsafe step: the caller vouches for
//!   the mapping.
//! - [`DmaBuffer`], physically contiguous kernel frames that a device reads
//!   and writes by DMA at their physical addresses (the I/O MMU, when it
//!   translates, maps them one to one). The frames come from the frame
//!   allocator, owned by the kernel, and are scrubbed and returned when the
//!   buffer drops.
//!
//! Every access is volatile, since the device changes registers and DMA
//! memory behind the compiler's back, and no Rust reference to either is
//! ever formed: a `&[u8]` over memory that a device writes would be
//! undefined behaviour. An access outside a handle's range, or misaligned
//! for its width, reads as all ones and writes nothing, the way an
//! unclaimed bus cycle behaves, instead of reaching memory the handle does
//! not own. Neither handle is `Sync`: a driver that shares one between
//! contexts has to serialize access itself.

use core::cell::Cell;
use core::marker::PhantomData;

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameLease, FrameOwner};

const PAGE_SIZE: usize = 4096;

mod sealed {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
}

/// An integer that devices read and write in one access.
pub(crate) trait Word: sealed::Sealed + Copy {
    /// What a read outside the handle returns.
    const ONES: Self;
}

impl Word for u8 {
    const ONES: Self = u8::MAX;
}

impl Word for u16 {
    const ONES: Self = u16::MAX;
}

impl Word for u32 {
    const ONES: Self = u32::MAX;
}

impl Word for u64 {
    const ONES: Self = u64::MAX;
}

/// The address of `size` bytes at `offset` in `base..base + length`, if
/// they lie inside it and `offset` is a multiple of `align`.
fn span(base: usize, length: usize, offset: usize, size: usize, align: usize) -> Option<usize> {
    let end = offset.checked_add(size)?;
    (end <= length && offset.is_multiple_of(align)).then(|| base + offset)
}

/// A range of device registers mapped uncached.
pub(crate) struct Mmio {
    base: usize,
    length: usize,
    _not_sync: PhantomData<Cell<u8>>,
}

impl Mmio {
    /// Wraps `length` bytes of registers at virtual address `base`.
    ///
    /// # Safety
    ///
    /// `base..base + length` must map registers of one device uncached for
    /// as long as this value and any [`Mmio::window`] of it are used, and
    /// only the driver holding them may access those registers.
    pub(crate) unsafe fn new(base: usize, length: usize) -> Self {
        Self {
            base,
            length,
            _not_sync: PhantomData,
        }
    }

    /// The `length` bytes at `offset`, if they lie inside this range.
    pub(crate) fn window(&self, offset: usize, length: usize) -> Option<Self> {
        let base = span(self.base, self.length, offset, length, 1)?;
        Some(Self {
            base,
            length,
            _not_sync: PhantomData,
        })
    }

    pub(crate) fn read<T: Word>(&self, offset: usize) -> T {
        let size = core::mem::size_of::<T>();
        match span(self.base, self.length, offset, size, size) {
            // SAFETY: new's contract maps the whole range, and span keeps
            // the aligned access inside it.
            Some(address) => unsafe { (address as *const T).read_volatile() },
            None => T::ONES,
        }
    }

    pub(crate) fn write<T: Word>(&self, offset: usize, value: T) {
        let size = core::mem::size_of::<T>();
        if let Some(address) = span(self.base, self.length, offset, size, size) {
            // SAFETY: as for read.
            unsafe { (address as *mut T).write_volatile(value) };
        }
    }
}

/// Physically contiguous, zeroed kernel memory that a device reaches by
/// DMA.
pub(crate) struct DmaBuffer {
    first: FrameLease,
    pages: usize,
    /// Where the kernel reaches the frames: their direct-map alias.
    base: usize,
    _not_sync: PhantomData<Cell<u8>>,
}

impl DmaBuffer {
    /// Takes `pages` contiguous zeroed frames from the frame allocator.
    pub(crate) fn allocate(pages: usize) -> Option<Self> {
        let (first, pages) = memory::allocate_contiguous_extent(FrameOwner::KERNEL, pages)?;
        // The allocator only hands out frames inside the direct map.
        let Some(base) = paging::direct_map_range_address(first.address(), pages * PAGE_SIZE)
        else {
            let _ = memory::scrub_and_release_contiguous_extent(FrameOwner::KERNEL, first, pages);
            return None;
        };
        Some(Self {
            first,
            pages,
            base,
            _not_sync: PhantomData,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.pages * PAGE_SIZE
    }

    /// The address the device uses for byte `offset` of the buffer.
    pub(crate) fn device_address(&self, offset: usize) -> u64 {
        self.first.address() + offset.min(self.len()) as u64
    }

    /// The buffer's physical range (start, length), for I/O MMU admission.
    pub(crate) fn region(&self) -> (u64, u64) {
        (self.first.address(), self.len() as u64)
    }

    /// The kernel virtual address of the first byte. Writing through it is
    /// the caller's responsibility; the buffer itself stays valid until it
    /// drops.
    pub(crate) fn kernel_address(&self) -> usize {
        self.base
    }

    pub(crate) fn read<T: Word>(&self, offset: usize) -> T {
        let size = core::mem::size_of::<T>();
        match span(self.base, self.len(), offset, size, size) {
            // SAFETY: the direct map covers the whole extent, which this
            // buffer owns until it drops, and span keeps the access inside.
            Some(address) => unsafe { (address as *const T).read_volatile() },
            None => T::ONES,
        }
    }

    pub(crate) fn write<T: Word>(&self, offset: usize, value: T) {
        let size = core::mem::size_of::<T>();
        if let Some(address) = span(self.base, self.len(), offset, size, size) {
            // SAFETY: as for read.
            unsafe { (address as *mut T).write_volatile(value) };
        }
    }

    /// Copies `bytes` to `offset`, or nothing if they do not fit.
    pub(crate) fn write_bytes(&self, offset: usize, bytes: &[u8]) {
        if let Some(address) = span(self.base, self.len(), offset, bytes.len(), 1) {
            for (index, byte) in bytes.iter().enumerate() {
                // SAFETY: as for read; every byte lies inside the span.
                unsafe { (address as *mut u8).add(index).write_volatile(*byte) };
            }
        }
    }

    /// Fills `bytes` from `offset`, with ones if they do not fit.
    pub(crate) fn read_bytes(&self, offset: usize, bytes: &mut [u8]) {
        match span(self.base, self.len(), offset, bytes.len(), 1) {
            Some(address) => {
                for (index, byte) in bytes.iter_mut().enumerate() {
                    // SAFETY: as for read; every byte lies inside the span.
                    *byte = unsafe { (address as *const u8).add(index).read_volatile() };
                }
            }
            None => bytes.fill(u8::MAX),
        }
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        // The owner stops the device before its buffers drop, so nothing
        // reaches these frames once they are back in the allocator.
        let _ =
            memory::scrub_and_release_contiguous_extent(FrameOwner::KERNEL, self.first, self.pages);
    }
}
