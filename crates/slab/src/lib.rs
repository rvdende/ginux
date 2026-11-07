//! The kernel heap's slabs: small objects carved out of frames, one size
//! class per frame, and the frames given back once nothing in them is
//! live.
//!
//! Each slab is one frame. Its objects fill the frame but for a footer at
//! its end, which keeps the slab's class, how many of its objects are
//! live, the head of its own free list, and its links in its class's list
//! of partial slabs (those with an object free). An object's slab is the
//! frame it lies in, so freeing needs no lookup. A slab whose last live
//! object is freed leaves its class: up to [`SPARE_EMPTY`] such frames are
//! kept for the next slab of any class, so a size that comes and goes does
//! not carve and give back a frame each time; past that the frame goes
//! back to whoever provided it ([`Frames`]).
//!
//! The sizes below 256 bytes are powers of two; the larger ones are what
//! fills the 4032 bytes before the footer exactly (448, 672, 1008, 2016),
//! so no class loses a whole object to the footer. Each object is aligned
//! to the largest power of two dividing its class size.
//!
//! This is the heap's bookkeeping alone: the frames come from the kernel's
//! frame allocator through [`Frames`], and the host tests give it frames
//! of their own.
#![no_std]

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;

/// A slab's size: one frame.
pub const FRAME_SIZE: usize = 4096;

/// The bytes at a slab's end that hold its [`Footer`].
const FOOTER_SIZE: usize = 64;

/// The bytes of a slab its objects fill.
const AREA: usize = FRAME_SIZE - FOOTER_SIZE;

/// Object sizes of the classes.
pub const CLASS_SIZES: [usize; 9] = [16, 32, 64, 128, 256, 448, 672, 1008, 2016];

/// How many classes there are.
pub const CLASS_COUNT: usize = CLASS_SIZES.len();

/// Empty slabs kept for reuse at most; more go back to the frame source.
pub const SPARE_EMPTY: usize = 16;

/// A carved slab's footer, and an empty kept one's.
const SLAB_MAGIC: u64 = 0x6769_6e75_7853_6c62;
const EMPTY_MAGIC: u64 = 0x6769_6e75_7845_6d70;

/// What a slab keeps about itself, in its last [`FOOTER_SIZE`] bytes.
#[repr(C)]
struct Footer {
    magic: u64,
    class: usize,
    live: usize,
    /// The first free object's address, or 0; each free object's first
    /// word holds the next one's.
    free: usize,
    /// The next and previous slab (frame address, 0 for none) in its
    /// class's partial list, or in the list of empty slabs.
    next: usize,
    previous: usize,
}

const _: () = assert!(core::mem::size_of::<Footer>() <= FOOTER_SIZE);

/// Where slab frames come from and go back to.
pub trait Frames {
    /// A fresh frame: its address, aligned to [`FRAME_SIZE`], writable and
    /// used by nothing else until released. None when there is none.
    fn allocate(&mut self) -> Option<usize>;

    /// Takes back a frame [`Frames::allocate`] gave.
    fn release(&mut self, frame: usize);
}

/// A free the slabs refused: the pointer is no object of theirs, or not
/// one of that class, or not live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreeError {
    NotASlab,
    WrongClass,
    Misaligned,
    NotLive,
}

/// The alignment every object of class `class` has.
pub const fn class_alignment(class: usize) -> usize {
    let size = CLASS_SIZES[class];
    1 << size.trailing_zeros()
}

/// How many objects a slab of class `class` holds.
pub const fn class_capacity(class: usize) -> usize {
    AREA / CLASS_SIZES[class]
}

/// The class that serves `size` bytes aligned to `align` (a power of
/// two), if a slab can.
pub fn class_for(size: usize, align: usize) -> Option<usize> {
    let size = size.max(1);
    (0..CLASS_COUNT).find(|class| CLASS_SIZES[*class] >= size && class_alignment(*class) >= align)
}

/// The slabs of every class.
pub struct Slabs {
    /// Each class's partial slabs, by the first one's frame address.
    partial: [usize; CLASS_COUNT],
    /// The empty slabs kept, by the first one's frame address.
    empty: usize,
    empty_count: usize,
    /// Frames held: carved slabs and kept empty ones.
    held: usize,
}

impl Default for Slabs {
    fn default() -> Self {
        Self::new()
    }
}

/// The footer of the slab at frame address `frame`.
fn footer(frame: usize) -> *mut Footer {
    (frame + AREA) as *mut Footer
}

impl Slabs {
    pub const fn new() -> Self {
        Self {
            partial: [0; CLASS_COUNT],
            empty: 0,
            empty_count: 0,
            held: 0,
        }
    }

    /// Frames the slabs hold, carved or kept empty.
    pub fn held_frames(&self) -> usize {
        self.held
    }

    /// Empty frames kept for reuse.
    pub fn empty_frames(&self) -> usize {
        self.empty_count
    }

    /// An object of class `class`, from a partial slab, or a slab carved
    /// from a kept empty frame or a new one. None when `frames` has none.
    ///
    /// # Safety
    ///
    /// Every frame `frames` gives must be [`FRAME_SIZE`] bytes at an
    /// address aligned to it, writable, and used by nothing else until
    /// these slabs release it; objects freed here must be ones these slabs
    /// gave, of the class given.
    pub unsafe fn allocate(&mut self, class: usize, frames: &mut impl Frames) -> Option<*mut u8> {
        if class >= CLASS_COUNT {
            return None;
        }
        let slab = match self.partial[class] {
            0 => {
                let frame = match self.take_empty() {
                    Some(frame) => frame,
                    None => {
                        let frame = frames.allocate()?;
                        if !frame.is_multiple_of(FRAME_SIZE) || frame == 0 {
                            frames.release(frame);
                            return None;
                        }
                        self.held += 1;
                        frame
                    }
                };
                // SAFETY: the frame is ours alone (a fresh one or a kept
                // empty one, which no object refers to).
                unsafe { carve(frame, class) };
                // SAFETY: the slab was just carved.
                unsafe { self.push_partial(class, frame) };
                frame
            }
            slab => slab,
        };
        let footer = footer(slab);
        // SAFETY: partial slabs are carved slabs of this class with a free
        // object; their footers and free objects are ours to read and
        // write.
        unsafe {
            let object = (*footer).free;
            (*footer).free = (object as *const usize).read();
            (*footer).live += 1;
            if (*footer).free == 0 {
                self.unlink_partial(class, slab);
            }
            Some(object as *mut u8)
        }
    }

    /// Gives back `object` of class `class`. A slab left with no live
    /// object is kept empty, or released to `frames` once
    /// [`SPARE_EMPTY`] are kept.
    ///
    /// # Safety
    ///
    /// As for [`Slabs::allocate`]; `object` must no longer be used. The
    /// checks catch a pointer into no slab or a slab of another class, but
    /// not every pointer into memory that is not a slab.
    pub unsafe fn free(
        &mut self,
        class: usize,
        object: *mut u8,
        frames: &mut impl Frames,
    ) -> Result<(), FreeError> {
        let address = object as usize;
        let frame = address & !(FRAME_SIZE - 1);
        let offset = address - frame;
        if class >= CLASS_COUNT || frame == 0 || offset >= AREA {
            return Err(FreeError::NotASlab);
        }
        let footer = footer(frame);
        // SAFETY: the caller frees an object these slabs gave, so its
        // frame is one of their slabs, whose footer is theirs.
        unsafe {
            if (*footer).magic != SLAB_MAGIC {
                return Err(FreeError::NotASlab);
            }
            if (*footer).class != class {
                return Err(FreeError::WrongClass);
            }
            if !offset.is_multiple_of(CLASS_SIZES[class])
                || offset / CLASS_SIZES[class] >= class_capacity(class)
            {
                return Err(FreeError::Misaligned);
            }
            if (*footer).live == 0 {
                return Err(FreeError::NotLive);
            }
            let was_full = (*footer).free == 0;
            (address as *mut usize).write((*footer).free);
            (*footer).free = address;
            (*footer).live -= 1;
            if (*footer).live == 0 {
                if !was_full {
                    self.unlink_partial(class, frame);
                }
                self.retire(frame, frames);
            } else if was_full {
                self.push_partial(class, frame);
            }
        }
        Ok(())
    }

    /// Keeps empty slab `frame` for reuse, or releases it.
    ///
    /// # Safety
    ///
    /// `frame` is a slab of these slabs with no live object, in no list.
    unsafe fn retire(&mut self, frame: usize, frames: &mut impl Frames) {
        if self.empty_count >= SPARE_EMPTY {
            // SAFETY: the footer is ours until the frame goes.
            unsafe { (*footer(frame)).magic = 0 };
            self.held -= 1;
            frames.release(frame);
            return;
        }
        let footer = footer(frame);
        // SAFETY: as above.
        unsafe {
            (*footer).magic = EMPTY_MAGIC;
            (*footer).next = self.empty;
            (*footer).previous = 0;
        }
        self.empty = frame;
        self.empty_count += 1;
    }

    fn take_empty(&mut self) -> Option<usize> {
        let frame = self.empty;
        if frame == 0 {
            return None;
        }
        // SAFETY: kept empty frames are ours and their footers link them.
        self.empty = unsafe { (*footer(frame)).next };
        self.empty_count -= 1;
        Some(frame)
    }

    /// # Safety
    ///
    /// `frame` is a carved slab of `class` in no list.
    unsafe fn push_partial(&mut self, class: usize, frame: usize) {
        let head = self.partial[class];
        // SAFETY: the slab and the list's head are carved slabs of ours.
        unsafe {
            (*footer(frame)).next = head;
            (*footer(frame)).previous = 0;
            if head != 0 {
                (*footer(head)).previous = frame;
            }
        }
        self.partial[class] = frame;
    }

    /// # Safety
    ///
    /// `frame` is a slab in `class`'s partial list.
    unsafe fn unlink_partial(&mut self, class: usize, frame: usize) {
        // SAFETY: the slab and its neighbours are carved slabs of ours.
        unsafe {
            let (next, previous) = ((*footer(frame)).next, (*footer(frame)).previous);
            if previous == 0 {
                self.partial[class] = next;
            } else {
                (*footer(previous)).next = next;
            }
            if next != 0 {
                (*footer(next)).previous = previous;
            }
            (*footer(frame)).next = 0;
            (*footer(frame)).previous = 0;
        }
    }
}

/// Carves `frame` into objects of `class`, all free.
///
/// # Safety
///
/// `frame` is a frame of [`FRAME_SIZE`] bytes that nothing else uses.
unsafe fn carve(frame: usize, class: usize) {
    let size = CLASS_SIZES[class];
    let count = class_capacity(class);
    for index in 0..count {
        let object = frame + index * size;
        let next = if index + 1 < count { object + size } else { 0 };
        // SAFETY: the object lies in the frame, which is ours.
        unsafe { (object as *mut usize).write(next) };
    }
    // SAFETY: the footer lies in the frame.
    unsafe {
        footer(frame).write(Footer {
            magic: SLAB_MAGIC,
            class,
            live: 0,
            free: frame,
            next: 0,
            previous: 0,
        });
    }
}
