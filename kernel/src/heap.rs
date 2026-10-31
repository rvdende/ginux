//! The kernel heap behind `alloc`: memory for kernel objects whose number or
//! size is only known at run time, such as tasks, kernel stacks and tables
//! that grow.
//!
//! Requests of up to 2 KiB come from slabs: one free list per power-of-two
//! size class, refilled a frame at a time, as in Linux's slab allocators.
//! Larger requests take a run of contiguous frames of their own and return
//! it to the frame allocator when freed. All heap memory is reached through
//! the direct map. Slab frames stay with their class once carved; giving
//! empty slabs back is left for when memory pressure needs it.
//!
//! The heap lock ranks just below the frame allocator's, because a refill
//! takes frames while holding it. So the heap must not be used while holding
//! the frame allocator lock or any lock ranked above it.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameOwner};
use crate::sync::{IrqSpinLock, LockRank};

const PAGE_SIZE: usize = 4096;

/// Object sizes of the slab classes. Each divides a frame evenly, so objects
/// are aligned to their size.
const CLASS_SIZES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];

/// Heads of the free lists, one per class: the direct-map address of a free
/// object, whose first word holds the address of the next (0 ends a list).
struct FreeLists([usize; CLASS_SIZES.len()]);

struct KernelHeap {
    free: IrqSpinLock<FreeLists>,
}

#[global_allocator]
static KERNEL_HEAP: KernelHeap = KernelHeap {
    free: IrqSpinLock::new(LockRank::KERNEL_HEAP, FreeLists([0; CLASS_SIZES.len()])),
};

/// The slab class serving `layout`, or `None` for a frame-run allocation.
fn size_class(layout: Layout) -> Option<usize> {
    let size = layout.size().max(layout.align());
    CLASS_SIZES.iter().position(|class| size <= *class)
}

impl KernelHeap {
    fn allocate_object(&self, class: usize) -> *mut u8 {
        let mut free = self.free.lock();
        if free.0[class] == 0 {
            let Some(slab) = new_slab(CLASS_SIZES[class]) else {
                return ptr::null_mut();
            };
            free.0[class] = slab;
        }
        let object = free.0[class];
        // SAFETY: every list entry is a free object inside a heap slab whose
        // first word was written by `new_slab` or `free_object`.
        free.0[class] = unsafe { (object as *const usize).read() };
        object as *mut u8
    }

    fn free_object(&self, class: usize, object: *mut u8) {
        let address = object as usize;
        if !address.is_multiple_of(CLASS_SIZES[class])
            || paging::direct_map_physical(address).is_none()
        {
            crate::kernel_fail("ginux: kernel heap free of a pointer it never allocated\r\n");
        }
        let mut free = self.free.lock();
        // SAFETY: the caller gives back an object of this class that it no
        // longer uses, so its first word may hold the list link.
        unsafe { (address as *mut usize).write(free.0[class]) };
        free.0[class] = address;
    }
}

/// Carves a zeroed frame into objects of `size` bytes, links them into a
/// list and returns its head.
fn new_slab(size: usize) -> Option<usize> {
    let [frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    let base = frame.direct_map_address()?;
    for offset in (0..PAGE_SIZE).step_by(size) {
        let next = if offset + size < PAGE_SIZE {
            base + offset + size
        } else {
            0
        };
        // SAFETY: the frame was just allocated to the kernel and is mapped
        // writable through the direct map; nothing else refers to it.
        unsafe { ((base + offset) as *mut usize).write(next) };
    }
    Some(base)
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
