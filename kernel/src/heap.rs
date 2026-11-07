//! The kernel heap behind `alloc`: memory for kernel objects whose number or
//! size is only known at run time, such as tasks, kernel stacks and tables
//! that grow.
//!
//! Requests of up to 2016 bytes come from slabs (`ginux_slab`): a frame per
//! slab, one size class each, as in Linux's slab allocators. A slab whose
//! objects are all freed goes back to the frame allocator, but for a few
//! kept for the next slab of any class (`ginux_slab::SPARE_EMPTY`), so a
//! burst of kernel objects leaves no memory behind once it is over.
//! Larger requests take a run of contiguous frames of their own and return
//! it to the frame allocator when freed. All heap memory is reached through
//! the direct map.
//!
//! The heap lock ranks just below the frame allocator's, because a refill
//! takes frames while holding it. So the heap must not be used while holding
//! the frame allocator lock or any lock ranked above it.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use ginux_slab::{Frames, Slabs};

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameOwner};
use crate::sync::{IrqSpinLock, LockRank};

const PAGE_SIZE: usize = 4096;

const _: () = assert!(ginux_slab::FRAME_SIZE == PAGE_SIZE);

struct KernelHeap {
    slabs: IrqSpinLock<Slabs>,
}

/// Frames the heap holds: its slabs (kept empty ones included) and the
/// frame runs of live large allocations.
static HEAP_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// Frames the heap's slabs hold (/proc/meminfo's Slab).
static SLAB_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// The kernel's frames outside the heap. Checks that a lifecycle gives back
/// what it took compare this.
pub(crate) fn kernel_frames_outside_heap() -> Option<usize> {
    memory::owner_live_frame_count(FrameOwner::KERNEL)?
        .checked_sub(HEAP_FRAMES.load(Ordering::Acquire))
}

/// The bytes the heap's slabs hold.
pub(crate) fn slab_bytes() -> usize {
    SLAB_FRAMES.load(Ordering::Acquire) * PAGE_SIZE
}

#[global_allocator]
static KERNEL_HEAP: KernelHeap = KernelHeap {
    slabs: IrqSpinLock::new(LockRank::KERNEL_HEAP, Slabs::new()),
};

/// The slab class serving `layout`, or `None` for a frame-run allocation.
fn size_class(layout: Layout) -> Option<usize> {
    ginux_slab::class_for(layout.size(), layout.align())
}

/// Slab frames from the frame allocator, through the direct map.
struct KernelFrames;

impl Frames for KernelFrames {
    fn allocate(&mut self) -> Option<usize> {
        let [frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
        let address = frame.direct_map_address()?;
        HEAP_FRAMES.fetch_add(1, Ordering::AcqRel);
        SLAB_FRAMES.fetch_add(1, Ordering::AcqRel);
        Some(address)
    }

    fn release(&mut self, frame: usize) {
        let released = paging::direct_map_physical(frame)
            .and_then(|physical| memory::live_frame_lease(FrameOwner::KERNEL, physical))
            .is_some_and(|lease| memory::scrub_and_release_frames(FrameOwner::KERNEL, &[lease]));
        if !released {
            crate::kernel_fail("ginux: kernel heap released a slab it never took\r\n");
        }
        HEAP_FRAMES.fetch_sub(1, Ordering::AcqRel);
        SLAB_FRAMES.fetch_sub(1, Ordering::AcqRel);
    }
}

impl KernelHeap {
    fn allocate_object(&self, class: usize) -> *mut u8 {
        let mut slabs = self.slabs.lock();
        // SAFETY: KernelFrames gives whole kernel frames through the direct
        // map, page aligned, writable and used by nothing else until the
        // slabs release them.
        unsafe { slabs.allocate(class, &mut KernelFrames) }.unwrap_or(ptr::null_mut())
    }

    fn free_object(&self, class: usize, object: *mut u8) {
        if paging::direct_map_physical(object as usize).is_none() {
            crate::kernel_fail("ginux: kernel heap free of a pointer it never allocated\r\n");
        }
        let mut slabs = self.slabs.lock();
        // SAFETY: as in allocate_object; the caller gives back an object of
        // this class that it no longer uses.
        if unsafe { slabs.free(class, object, &mut KernelFrames) }.is_err() {
            crate::kernel_fail("ginux: kernel heap free of a pointer it never allocated\r\n");
        }
    }
}

fn page_count(layout: Layout) -> usize {
    layout.size().div_ceil(PAGE_SIZE)
}

/// Allocates zeroed contiguous frames for a request too large for a slab.
fn allocate_pages(layout: Layout) -> *mut u8 {
    if layout.align() > PAGE_SIZE {
        return ptr::null_mut();
    }
    let count = page_count(layout);
    memory::allocate_contiguous_extent(FrameOwner::KERNEL, count)
        .and_then(|(first, count)| {
            HEAP_FRAMES.fetch_add(count, Ordering::AcqRel);
            paging::direct_map_range_address(first.address(), count * PAGE_SIZE)
        })
        .map_or(ptr::null_mut(), |address| address as *mut u8)
}

fn free_pages(pointer: *mut u8, layout: Layout) {
    let released = paging::direct_map_physical(pointer as usize)
        .and_then(|physical| memory::live_frame_lease(FrameOwner::KERNEL, physical))
        .is_some_and(|first| {
            memory::scrub_and_release_contiguous_extent(
                FrameOwner::KERNEL,
                first,
                page_count(layout),
            )
        });
    if !released {
        crate::kernel_fail("ginux: kernel heap free of frames it never allocated\r\n");
    }
    HEAP_FRAMES.fetch_sub(page_count(layout), Ordering::AcqRel);
}

// SAFETY: slab objects are distinct, aligned to their class size (which
// covers the layout's size and alignment) and handed out once until freed;
// frame runs are page aligned and owned by the kernel until freed.
unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match size_class(layout) {
            Some(class) => self.allocate_object(class),
            None => allocate_pages(layout),
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        match size_class(layout) {
            Some(class) => self.free_object(class, pointer),
            None => free_pages(pointer, layout),
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        match size_class(layout) {
            Some(class) => {
                let object = self.allocate_object(class);
                if !object.is_null() {
                    // SAFETY: the object is at least `layout.size()` bytes.
                    unsafe { ptr::write_bytes(object, 0, layout.size()) };
                }
                object
            }
            // The frame allocator hands out zeroed frames.
            None => allocate_pages(layout),
        }
    }
}

/// Exercises both allocation paths at boot, so a broken heap fails here
/// rather than in whatever first uses it.
pub(crate) fn verify() -> bool {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    let small: Vec<Box<u64>> = (0..600_u64).map(Box::new).collect();
    let small_intact = small.iter().map(|value| **value).eq(0..600);
    let mut large: Vec<u8> = Vec::with_capacity(3 * PAGE_SIZE + 1);
    large.resize(large.capacity(), 0xa5);
    let large_intact = large.iter().all(|byte| *byte == 0xa5);
    drop(small);
    drop(large);
    let reused: Vec<Box<u64>> = (0..600_u64).map(Box::new).collect();
    small_intact && large_intact && reused.iter().map(|value| **value).eq(0..600)
}
