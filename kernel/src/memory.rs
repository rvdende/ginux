//! Physical frame allocator.
//!
//! Every page of usable RAM has an 8-byte metadata word (generation, owner
//! slot, a live flag and a sharer count), a bit in a free bitmap and a
//! 2-byte charge: the memory cgroup a user page is charged to
//! (`linux_cgroup`), uncharged when the frame is freed. The tables are sized to
//! the installed memory and carved from it at boot, so lookups are O(1) and no
//! compile-time table limits how much memory can be in use.
//!
//! Single frames are taken lowest-first, which keeps page tables and DMA
//! buffers below 4 GiB for as long as possible. Large contiguous extents, such
//! as OCI layer staging and unpacked image filesystems, are taken
//! highest-first so they do not exhaust low memory.

use crate::sync::{IrqSpinLock, LockRank};
use crate::{
    arch::x86_64::paging, BootInfo, UefiMemoryDescriptor, EFI_BOOT_SERVICES_CODE,
    EFI_BOOT_SERVICES_DATA, EFI_CONVENTIONAL_MEMORY,
};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

const PAGE_SIZE: u64 = 4096;
const LOW_MEMORY_LIMIT: u64 = 1024 * 1024;
const DOMAIN_FRAME_LIMIT: usize = 192;
/// Owner slots besides the kernel (slot 0).
const OWNER_SLOTS: usize = 255;
const META_OWNER: u64 = 0xff;
const META_LIVE: u64 = 1 << 8;
/// How many address spaces besides the first map a frame. Fork shares a
/// private page copy-on-write instead of copying it; releasing a shared frame
/// drops one mapping instead of freeing the page, so a page is freed only
/// when its last mapping goes, as Linux's page map count does.
const META_SHARERS_SHIFT: u32 = 9;
const META_SHARER: u64 = 1 << META_SHARERS_SHIFT;
const META_SHARERS_MAX: u64 = (1 << 23) - 1;
const META_SHARERS: u64 = META_SHARERS_MAX << META_SHARERS_SHIFT;
const META_GENERATION_SHIFT: u32 = 32;

struct PhysicalMemoryOwner {
    initialized: AtomicBool,
    runtime_extent_starts: [AtomicU64; crate::control_abi::DOMAIN_LIMIT],
    runtime_extent_counts: [AtomicUsize; crate::control_abi::DOMAIN_LIMIT],
    /// The allocator's metadata table and how many frames it covers, set
    /// once before `initialized`: whether a frame is live and the kernel's
    /// can be read without the lock (`kernel_frame_metadata`), since the
    /// kernel's owner slot never changes and metadata words are written
    /// atomically.
    metadata_table: AtomicPtr<u64>,
    metadata_frames: AtomicUsize,
    /// Set when `allocate_user_frames` refused a request because only the
    /// kernel's reserve was left; the fault path takes it to tell running
    /// out of memory from a bad access.
    user_frames_refused: AtomicBool,
    allocator: IrqSpinLock<MaybeUninit<FrameAllocator>>,
}

static PHYSICAL_MEMORY: PhysicalMemoryOwner = PhysicalMemoryOwner {
    initialized: AtomicBool::new(false),
    runtime_extent_starts: [const { AtomicU64::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    runtime_extent_counts: [const { AtomicUsize::new(0) }; crate::control_abi::DOMAIN_LIMIT],
    metadata_table: AtomicPtr::new(core::ptr::null_mut()),
    metadata_frames: AtomicUsize::new(0),
    user_frames_refused: AtomicBool::new(false),
    allocator: IrqSpinLock::new(LockRank::PHYSICAL_MEMORY, MaybeUninit::uninit()),
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Process snapshots contain many leases. Keep the wire-like lease record
// compact; callers obtain fields through by-value accessors so no reference
// to a potentially unaligned packed field escapes.
#[repr(C, packed)]
pub(crate) struct FrameLease {
    address: u64,
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FrameOwner(u64);

impl FrameOwner {
    pub(crate) const KERNEL: Self = Self(0);

    pub(crate) const fn domain(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    const fn is_kernel(self) -> bool {
        self.0 == 0
    }
}

impl FrameLease {
    pub(crate) const EMPTY: Self = Self {
        address: 0,
        generation: 0,
    };

    pub(crate) const fn address(self) -> u64 {
        self.address
    }

    pub(crate) const fn generation(self) -> u32 {
        self.generation
    }

    pub(crate) const fn from_parts(address: u64, generation: u32) -> Option<Self> {
        if address < LOW_MEMORY_LIMIT || !address.is_multiple_of(PAGE_SIZE) || generation == 0 {
            None
        } else {
            Some(Self {
                address,
                generation,
            })
        }
    }

    pub(crate) fn direct_map_address(self) -> Option<usize> {
        paging::direct_map_range_address(self.address, PAGE_SIZE as usize)
    }
}

/// The allocator state. `metadata` and `free` point at tables covering the
/// frames `first_frame..first_frame + frames`.
pub(crate) struct FrameAllocator {
    first_frame: u64,
    frames: usize,
    metadata: *mut u64,
    free: *mut u64,
    /// Each frame's memory cgroup charge (`linux_cgroup::Slot`, 0 for none),
    /// or null for an allocator that charges nothing (the self-test's).
    charges: *mut u16,
    /// Lowest bitmap word that may hold a free bit.
    cursor: usize,
    free_frames: u64,
    allocated_frames: u64,
    reclaimed_boot_service_frames: u64,
    owner_limit: usize,
    owners: [u64; OWNER_SLOTS],
    owner_counts: [usize; OWNER_SLOTS + 1],
}

// SAFETY: the table pointers address boot-carved RAM that the allocator owns
// for the kernel's lifetime; the PHYSICAL_MEMORY lock serializes all access.
unsafe impl Send for FrameAllocator {}

impl FrameAllocator {
    /// Creates an empty allocator over caller-provided tables.
    ///
    /// # Safety
    ///
    /// `metadata` must hold `frames` words and `free` `frames.div_ceil(64)`
    /// words, both zeroed and valid for the allocator's lifetime, and
    /// `charges`, unless null, `frames` zeroed half-words.
    unsafe fn with_tables(
        first_frame: u64,
        frames: usize,
        metadata: *mut u64,
        free: *mut u64,
        charges: *mut u16,
        owner_limit: usize,
    ) -> Self {
        Self {
            first_frame,
            frames,
            metadata,
            free,
            charges,
            cursor: 0,
            free_frames: 0,
            allocated_frames: 0,
            reclaimed_boot_service_frames: 0,
            owner_limit,
            owners: [0; OWNER_SLOTS],
            owner_counts: [0; OWNER_SLOTS + 1],
        }
    }

    fn words(&self) -> usize {
        self.frames.div_ceil(64)
    }

    fn index(&self, address: u64) -> Option<usize> {
        if address < LOW_MEMORY_LIMIT || !address.is_multiple_of(PAGE_SIZE) {
            return None;
        }
        let frame = (address / PAGE_SIZE).checked_sub(self.first_frame)?;
        let index = usize::try_from(frame).ok()?;
        (index < self.frames).then_some(index)
    }

    fn address(&self, index: usize) -> u64 {
        (self.first_frame + index as u64) * PAGE_SIZE
    }

    fn metadata(&self, index: usize) -> u64 {
        // SAFETY: index < frames, which the metadata table covers; the words
        // are aligned and only ever accessed atomically.
        unsafe { AtomicU64::from_ptr(self.metadata.add(index)).load(Ordering::Acquire) }
    }

    fn set_metadata(&mut self, index: usize, value: u64) {
        // SAFETY: as for metadata. Lock-free readers (kernel_frame_metadata)
        // may load the word concurrently.
        unsafe { AtomicU64::from_ptr(self.metadata.add(index)).store(value, Ordering::Release) }
    }

    /// Records that frame `index` is charged to memory cgroup `slot`.
    fn set_charge(&mut self, index: usize, slot: u16) {
        if !self.charges.is_null() && index < self.frames {
            // SAFETY: charges covers frames half-words (with_tables) and the
            // allocator lock serializes access.
            unsafe { self.charges.add(index).write(slot) };
        }
    }

    /// Takes the memory cgroup frame `index` is charged to (0 for none).
    fn take_charge(&mut self, index: usize) -> u16 {
        if self.charges.is_null() || index >= self.frames {
            return 0;
        }
        // SAFETY: as for set_charge.
        unsafe {
            let charge = self.charges.add(index);
            let slot = charge.read();
            charge.write(0);
            slot
        }
    }

    /// The memory cgroup frame `index` is charged to (0 for none).
    fn charge(&self, index: usize) -> u16 {
        if self.charges.is_null() || index >= self.frames {
            return 0;
        }
        // SAFETY: as for set_charge.
        unsafe { self.charges.add(index).read() }
    }

    fn is_free(&self, index: usize) -> bool {
        // SAFETY: index / 64 < words(), which the bitmap covers.
        unsafe { self.free.add(index / 64).read() & (1 << (index % 64)) != 0 }
    }

    fn mark_free(&mut self, index: usize, free: bool) {
        // SAFETY: as for is_free.
        unsafe {
            let word = self.free.add(index / 64);
            if free {
                word.write(word.read() | 1 << (index % 64));
            } else {
                word.write(word.read() & !(1 << (index % 64)));
            }
        }
        if free {
            self.free_frames += 1;
            self.cursor = self.cursor.min(index / 64);
        } else {
            self.free_frames -= 1;
        }
    }

    /// Adds `start..end` as allocatable memory.
    fn add_free_range(&mut self, start: u64, end: u64) {
        let mut address = start.max(LOW_MEMORY_LIMIT).div_ceil(PAGE_SIZE) * PAGE_SIZE;
        while address + PAGE_SIZE <= end {
            if let Some(index) = self.index(address) {
                if !self.is_free(index) {
                    self.mark_free(index, true);
                }
            }
            address += PAGE_SIZE;
        }
    }

    /// Removes `start..end` from the allocatable memory.
    fn remove_free_range(&mut self, start: u64, end: u64) {
        let mut address = start / PAGE_SIZE * PAGE_SIZE;
        while address < end {
            if let Some(index) = self.index(address) {
                if self.is_free(index) {
                    self.mark_free(index, false);
                }
            }
            address += PAGE_SIZE;
        }
    }

    fn slot(&self, owner: FrameOwner) -> Option<usize> {
        if owner.is_kernel() {
            return Some(0);
        }
        self.owners
            .iter()
            .position(|raw| *raw == owner.0)
            .map(|position| position + 1)
    }

    fn slot_or_new(&mut self, owner: FrameOwner) -> Option<usize> {
        if let Some(slot) = self.slot(owner) {
            return Some(slot);
        }
        let position = self.owners.iter().position(|raw| *raw == 0)?;
        self.owners[position] = owner.0;
        Some(position + 1)
    }

    fn owner_live_count(&self, owner: FrameOwner) -> usize {
        self.slot(owner).map_or(0, |slot| self.owner_counts[slot])
    }

    fn budget_allows(&self, owner: FrameOwner, count: usize) -> bool {
        owner.is_kernel()
            || self
                .owner_live_count(owner)
                .checked_add(count)
                .is_some_and(|total| total <= self.owner_limit)
    }

    /// Marks a free frame live for `slot` with `generation`.
    fn issue(&mut self, index: usize, slot: usize, generation: u32) -> FrameLease {
        self.mark_free(index, false);
        self.set_metadata(
            index,
            u64::from(generation) << META_GENERATION_SHIFT | META_LIVE | slot as u64,
        );
        self.owner_counts[slot] += 1;
        self.allocated_frames += 1;
        FrameLease {
            address: self.address(index),
            generation,
        }
    }

    fn next_generation(&self, index: usize) -> Option<u32> {
        ((self.metadata(index) >> META_GENERATION_SHIFT) as u32).checked_add(1)
    }

    fn lowest_free(&mut self) -> Option<usize> {
        for word in self.cursor..self.words() {
            // SAFETY: word < words(), which the bitmap covers.
            let bits = unsafe { self.free.add(word).read() };
            if bits != 0 {
                self.cursor = word;
                return Some(word * 64 + bits.trailing_zeros() as usize);
            }
        }
        self.cursor = self.words();
        None
    }

    /// The free bits of bitmap word `word`, with the bits past the last
    /// frame clear.
    fn free_word(&self, word: usize) -> u64 {
        // SAFETY: word < words(), which the bitmap covers.
        let bits = unsafe { self.free.add(word).read() };
        let valid = self.frames - word * 64;
        if valid >= 64 {
            bits
        } else {
            bits & ((1 << valid) - 1)
        }
    }

    /// Finds `count` consecutive free frames, searching upward (the lowest
    /// run) or downward (the highest), a bitmap word at a time: frame by
    /// frame, every large heap allocation walked the fragmented low memory
    /// of a busy domain, a millisecond each, several per fork.
    fn free_run(&self, count: usize, highest_first: bool) -> Option<usize> {
        if count == 0 || count > self.frames {
            return None;
        }
        // Bit p of the result is set where frames p..p + count of the word
        // are all free (count < 64).
        let windows = |bits: u64| {
            let (mut mask, mut span) = (bits, 1);
            while span < count {
                let shift = (count - span).min(span);
                mask &= mask >> shift;
                span += shift;
            }
            mask
        };
        // Free frames next to the word being looked at, on the side the
        // search came from.
        let mut run = 0;
        if highest_first {
            for word in (0..self.words()).rev() {
                let bits = self.free_word(word);
                let top = (!bits).leading_zeros() as usize;
                if run + top >= count {
                    return Some(word * 64 + 64 + run - count);
                }
                if top == 64 {
                    run += 64;
                    continue;
                }
                let inside = if count < 64 { windows(bits) } else { 0 };
                if inside != 0 {
                    return Some(word * 64 + 63 - inside.leading_zeros() as usize);
                }
                run = (!bits).trailing_zeros() as usize;
            }
        } else {
            for word in 0..self.words() {
                let bits = self.free_word(word);
                let bottom = (!bits).trailing_zeros() as usize;
                if run + bottom >= count {
                    return Some(word * 64 - run);
                }
                if bottom == 64 {
                    run += 64;
                    continue;
                }
                let inside = if count < 64 { windows(bits) } else { 0 };
                if inside != 0 {
                    return Some(word * 64 + inside.trailing_zeros() as usize);
                }
                run = (!bits).leading_zeros() as usize;
            }
        }
        None
    }

    fn allocate_one(&mut self, owner: FrameOwner) -> Option<FrameLease> {
        if !self.budget_allows(owner, 1) {
            return None;
        }
        let index = self.lowest_free()?;
        let generation = self.next_generation(index)?;
        let slot = self.slot_or_new(owner)?;
        Some(self.issue(index, slot, generation))
    }

    pub(crate) fn reserve<const N: usize>(&mut self, owner: FrameOwner) -> Option<[FrameLease; N]> {
        if N == 0 || self.free_frames < N as u64 || !self.budget_allows(owner, N) {
            return None;
        }
        self.slot_or_new(owner)?;
        let mut frames = [FrameLease::EMPTY; N];
        for (index, frame) in frames.iter_mut().enumerate() {
            match self.allocate_one(owner) {
                Some(lease) => *frame = lease,
                None => {
                    let _ = self.release_slice(owner, &frames[..index]);
                    return None;
                }
            }
        }
        Some(frames)
    }

    /// Issues `count` contiguous frames sharing one generation and returns the first.
    fn reserve_run(
        &mut self,
        owner: FrameOwner,
        count: usize,
        highest_first: bool,
    ) -> Option<FrameLease> {
        if count == 0 || !self.budget_allows(owner, count) {
            return None;
        }
        let start = self.free_run(count, highest_first)?;
        let generation = (start..start + count).try_fold(1_u32, |generation, index| {
            Some(generation.max(self.next_generation(index)?))
        })?;
        let slot = self.slot_or_new(owner)?;
        for index in start..start + count {
            self.issue(index, slot, generation);
        }
        Some(FrameLease {
            address: self.address(start),
            generation,
        })
    }

    pub(crate) fn reserve_contiguous<const N: usize>(
        &mut self,
        owner: FrameOwner,
    ) -> Option<[FrameLease; N]> {
        let first = self.reserve_run(owner, N, false)?;
        Some(core::array::from_fn(|index| FrameLease {
            address: first.address + index as u64 * PAGE_SIZE,
            generation: first.generation,
        }))
    }

    fn reserve_contiguous_extent(&mut self, owner: FrameOwner, count: usize) -> Option<FrameLease> {
        self.reserve_run(owner, count, true)
    }

    fn release_contiguous_extent(
        &mut self,
        owner: FrameOwner,
        start: FrameLease,
        count: usize,
    ) -> bool {
        if !self.can_release_contiguous_extent(owner, start, count) {
            return false;
        }
        let Some(first) = self.index(start.address) else {
            return false;
        };
        for index in first..first + count {
            self.retire(index);
        }
        true
    }

    /// Returns whether `count` frames from `start` are live leases of one
    /// generation held by `owner`, so the extent may be released.
    fn can_release_contiguous_extent(
        &self,
        owner: FrameOwner,
        start: FrameLease,
        count: usize,
    ) -> bool {
        let Some(first) = self.index(start.address) else {
            return false;
        };
        count != 0
            && start.generation != 0
            && first
                .checked_add(count)
                .is_some_and(|end| end <= self.frames)
            && (0..count).all(|offset| {
                self.lease_matches(
                    FrameLease {
                        address: start.address + offset as u64 * PAGE_SIZE,
                        generation: start.generation,
                    },
                    Some(owner),
                )
            })
    }

    /// Returns whether `frame` is live with its generation and, when given,
    /// held by `owner`.
    fn lease_matches(&self, frame: FrameLease, owner: Option<FrameOwner>) -> bool {
        let Some(index) = self.index(frame.address) else {
            return false;
        };
        let metadata = self.metadata(index);
        metadata & META_LIVE != 0
            && (metadata >> META_GENERATION_SHIFT) as u32 == frame.generation
            && owner.is_none_or(|owner| {
                self.slot(owner)
                    .is_some_and(|slot| (metadata & META_OWNER) as usize == slot)
            })
    }

    fn can_release(&self, owner: FrameOwner, frames: &[FrameLease]) -> bool {
        !frames.is_empty()
            && self.allocated_frames >= frames.len() as u64
            && frames.iter().enumerate().all(|(index, frame)| {
                frame.generation != 0
                    && !frames[..index]
                        .iter()
                        .any(|prior| prior.address == frame.address)
                    && self.lease_matches(*frame, Some(owner))
            })
    }

    fn sharers(&self, index: usize) -> u64 {
        (self.metadata(index) & META_SHARERS) >> META_SHARERS_SHIFT
    }

    /// Whether another address space also maps the live `frame`.
    fn is_shared(&self, frame: FrameLease) -> bool {
        self.lease_matches(frame, None)
            && self
                .index(frame.address)
                .is_some_and(|index| self.sharers(index) != 0)
    }

    /// Records one more mapping of each of `frames`, all or none.
    fn share_slice(&mut self, owner: FrameOwner, frames: &[FrameLease]) -> bool {
        if !self.can_release(owner, frames)
            || frames.iter().any(|frame| {
                self.index(frame.address)
                    .is_none_or(|index| self.sharers(index) == META_SHARERS_MAX)
            })
        {
            return false;
        }
        for frame in frames {
            if let Some(index) = self.index(frame.address) {
                self.set_metadata(index, self.metadata(index) + META_SHARER);
            }
        }
        true
    }

    /// Ends a live frame's lease. A frame whose generation is exhausted is
    /// never handed out again.
    fn retire(&mut self, index: usize) {
        // The page's memory cgroup is charged until its last mapping goes.
        let charge = self.take_charge(index);
        if charge != 0 {
            let (slot, kind) = charge_parts(charge);
            crate::linux_cgroup::uncharge_kind(slot, kind);
        }
        let metadata = self.metadata(index);
        let slot = (metadata & META_OWNER) as usize;
        self.set_metadata(index, metadata & !(META_LIVE | META_OWNER | META_SHARERS));
        self.owner_counts[slot] -= 1;
        if slot != 0 && self.owner_counts[slot] == 0 {
            self.owners[slot - 1] = 0;
        }
        self.allocated_frames -= 1;
        if (metadata >> META_GENERATION_SHIFT) as u32 != u32::MAX {
            self.mark_free(index, true);
        }
    }

    fn release_slice(&mut self, owner: FrameOwner, frames: &[FrameLease]) -> bool {
        if frames.is_empty() {
            return true;
        }
        if !self.can_release(owner, frames) {
            return false;
        }
        for frame in frames {
            if let Some(index) = self.index(frame.address) {
                if self.sharers(index) == 0 {
                    self.retire(index);
                } else {
                    self.set_metadata(index, self.metadata(index) - META_SHARER);
                }
            }
        }
        true
    }

    pub(crate) fn release<const N: usize>(
        &mut self,
        owner: FrameOwner,
        frames: [FrameLease; N],
    ) -> bool {
        N != 0 && self.release_slice(owner, &frames)
    }

    fn transfer_owner(&mut self, from: FrameOwner, to: FrameOwner) -> Option<usize> {
        if from == to || from.is_kernel() || to.is_kernel() {
            return None;
        }
        let from_slot = self.slot(from)?;
        let count = self.owner_counts[from_slot];
        if count == 0 || !self.budget_allows(to, count) {
            return None;
        }
        match self.slot(to) {
            // The new owner holds nothing yet: relabel the slot in place.
            None => self.owners[from_slot - 1] = to.0,
            Some(to_slot) => {
                for index in 0..self.frames {
                    let metadata = self.metadata(index);
                    if metadata & META_LIVE != 0 && (metadata & META_OWNER) as usize == from_slot {
                        self.set_metadata(index, metadata & !META_OWNER | to_slot as u64);
                    }
                }
                self.owner_counts[to_slot] += count;
                self.owner_counts[from_slot] = 0;
                self.owners[from_slot - 1] = 0;
            }
        }
        Some(count)
    }

    fn owns(&self, owner: FrameOwner, frames: &[FrameLease]) -> bool {
        frames
            .iter()
            .all(|frame| self.lease_matches(*frame, Some(owner)))
    }

    fn tracks_any(&self, frames: &[FrameLease]) -> bool {
        frames.iter().any(|frame| self.lease_matches(*frame, None))
    }

    fn owns_addresses(&self, owner: FrameOwner, addresses: &[u64]) -> bool {
        let Some(slot) = self.slot(owner) else {
            return false;
        };
        !addresses.is_empty()
            && addresses.iter().all(|address| {
                self.index(*address).is_some_and(|index| {
                    let metadata = self.metadata(index);
                    metadata & META_LIVE != 0 && (metadata & META_OWNER) as usize == slot
                })
            })
    }

    fn live_lease(&self, owner: FrameOwner, address: u64) -> Option<FrameLease> {
        let index = self.index(address)?;
        let metadata = self.metadata(index);
        let slot = self.slot(owner)?;
        (metadata & META_LIVE != 0 && (metadata & META_OWNER) as usize == slot).then_some(
            FrameLease {
                address,
                generation: (metadata >> META_GENERATION_SHIFT) as u32,
            },
        )
    }

    /// Takes `count` contiguous frames out of circulation without a lease,
    /// for a domain's runtime extent, and returns the first address.
    fn carve(&mut self, count: usize) -> Option<u64> {
        let start = self.free_run(count, false)?;
        for index in start..start + count {
            self.mark_free(index, false);
        }
        Some(self.address(start))
    }
}

/// The usable memory types in a UEFI memory map, and whether each is boot
/// services memory reclaimed after ExitBootServices.
fn usable(descriptor: &UefiMemoryDescriptor) -> Option<bool> {
    match descriptor.memory_type {
        EFI_CONVENTIONAL_MEMORY => Some(false),
        EFI_BOOT_SERVICES_CODE | EFI_BOOT_SERVICES_DATA => Some(true),
        _ => None,
    }
}

fn for_each_descriptor(boot_info: &BootInfo, mut visit: impl FnMut(UefiMemoryDescriptor)) {
    let count = boot_info.memory_map_size / boot_info.memory_descriptor_size;
    for index in 0..count {
        // SAFETY: kernel_main validated the memory-map bounds and descriptor size.
        visit(unsafe {
            core::ptr::read_unaligned(
                boot_info
                    .memory_map
                    .add(index * boot_info.memory_descriptor_size)
                    .cast::<UefiMemoryDescriptor>(),
            )
        });
    }
}

fn descriptor_end(descriptor: &UefiMemoryDescriptor) -> Option<u64> {
    descriptor
        .page_count
        .checked_mul(PAGE_SIZE)
        .and_then(|size| descriptor.physical_start.checked_add(size))
}

/// Builds the allocator over usable memory below `ceiling`, the end of the
/// kernel's direct map.
pub(crate) fn initialize(boot_info: &BootInfo, ceiling: u64) -> bool {
    if PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return false;
    }
    let (mut highest, mut largest) = (0_u64, (0_u64, 0_u64));
    let mut malformed = false;
    for_each_descriptor(boot_info, |descriptor| {
        if usable(&descriptor).is_none() {
            return;
        }
        let Some(end) = descriptor_end(&descriptor) else {
            malformed = true;
            return;
        };
        let start = descriptor.physical_start.max(LOW_MEMORY_LIMIT);
        let end = end.min(ceiling);
        if start < end {
            highest = highest.max(end);
            if end - start > largest.1 - largest.0 {
                largest = (start, end);
            }
        }
    });
    if malformed || highest == 0 {
        return false;
    }
    let frames = (highest / PAGE_SIZE) as usize;
    let metadata_bytes = frames as u64 * 8;
    let bitmap_bytes = frames.div_ceil(64) as u64 * 8;
    let charge_bytes = frames as u64 * 2;
    // Place the tables at the top of the largest usable range.
    let tables_size =
        (metadata_bytes + bitmap_bytes + charge_bytes).div_ceil(PAGE_SIZE) * PAGE_SIZE;
    let Some(tables_start) = largest
        .1
        .checked_sub(tables_size)
        .filter(|start| *start >= largest.0)
        .map(|start| start / PAGE_SIZE * PAGE_SIZE)
    else {
        return false;
    };
    let Some(tables) = paging::direct_map_range_address(tables_start, tables_size as usize) else {
        return false;
    };
    // The IRQ-safe lock makes initialization publication exclusive with
    // later allocator access.
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: the tables lie in usable RAM inside the direct map and are
    // removed from the free pool below before anything can allocate them.
    unsafe {
        core::ptr::write_bytes(tables as *mut u8, 0, tables_size as usize);
        let metadata = tables as *mut u64;
        let free = (tables + metadata_bytes as usize) as *mut u64;
        let charges = (tables + (metadata_bytes + bitmap_bytes) as usize) as *mut u16;
        let mut allocator =
            FrameAllocator::with_tables(0, frames, metadata, free, charges, DOMAIN_FRAME_LIMIT);
        let mut reclaimed = 0;
        for_each_descriptor(boot_info, |descriptor| {
            let (Some(boot_service), Some(end)) =
                (usable(&descriptor), descriptor_end(&descriptor))
            else {
                return;
            };
            let before = allocator.free_frames;
            allocator.add_free_range(descriptor.physical_start, end.min(ceiling));
            if boot_service {
                reclaimed += allocator.free_frames - before;
            }
        });
        allocator.remove_free_range(tables_start, tables_start + tables_size);
        allocator.reclaimed_boot_service_frames = reclaimed;
        if allocator.free_frames == 0 {
            return false;
        }
        storage.write(allocator);
    }
    PHYSICAL_MEMORY
        .metadata_table
        .store(tables as *mut u64, Ordering::Release);
    PHYSICAL_MEMORY
        .metadata_frames
        .store(frames, Ordering::Release);
    PHYSICAL_MEMORY.initialized.store(true, Ordering::Release);
    true
}

pub(crate) fn allocate_frames<const N: usize>(owner: FrameOwner) -> Option<[FrameLease; N]> {
    crate::linux_profile::count_memory(0);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: initialized is published only after the locked storage contains
    // a valid FrameAllocator.
    unsafe {
        let allocator = storage.assume_init_mut();
        let frames = allocator.reserve::<N>(owner)?;
        for frame in &frames {
            let Some(address) = frame.direct_map_address() else {
                let _ = allocator.release(owner, frames);
                return None;
            };
            core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(frames)
    }
}

/// Frames user memory may not take: what the kernel needs to keep running
/// and to tear down the process that ran the machine out of memory (its
/// signal records, page-table walks, the parent's SIGCHLD). Linux keeps a
/// similar watermark (`min_free_kbytes`). One part in 64 of RAM, at least
/// 32 MiB and at most 256 MiB.
fn user_reserve_frames(total_frames: u64) -> u64 {
    const MIN: u64 = (32 << 20) / PAGE_SIZE;
    const MAX: u64 = (256 << 20) / PAGE_SIZE;
    (total_frames / 64).clamp(MIN, MAX)
}

/// Allocates zeroed frames for user memory (anonymous pages, stack growth,
/// copy-on-write copies). Unlike `allocate_frames` it leaves the kernel's
/// reserve free: when only the reserve is left it fails and records that
/// (`take_user_frames_refused`), so the faulting process can be killed as
/// Linux's OOM killer would, while the kernel still has memory to do it.
pub(crate) fn allocate_user_frames<const N: usize>() -> Option<[FrameLease; N]> {
    crate::linux_profile::count_memory(0);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    // The pages are charged to the current process's memory cgroup first,
    // which may reclaim or OOM-kill within it (before the allocator lock is
    // taken); a charge it refuses fails the allocation as running out of
    // memory does.
    let Some(charge) = crate::arch::x86_64::cpu::charge_linux_user_pages(N as u64) else {
        PHYSICAL_MEMORY
            .user_frames_refused
            .store(true, Ordering::Release);
        return None;
    };
    let uncharge = || {
        if charge != 0 {
            crate::linux_cgroup::uncharge(charge, N as u64);
        }
    };
    // Short of memory, what the domain's processes may give up (lazily
    // freed and droppable pages) is taken first, once, without the lock.
    let mut reclaimed = false;
    loop {
        let mut storage = PHYSICAL_MEMORY.allocator.lock();
        // SAFETY: initialized is published only after the locked storage
        // contains a valid FrameAllocator.
        unsafe {
            let allocator = storage.assume_init_mut();
            let total = allocator.free_frames + allocator.allocated_frames;
            if allocator.free_frames < N as u64 + user_reserve_frames(total) {
                if !reclaimed {
                    drop(storage);
                    reclaimed = true;
                    if crate::arch::x86_64::cpu::reclaim_linux_user_pages(N as u64) {
                        continue;
                    }
                }
                PHYSICAL_MEMORY
                    .user_frames_refused
                    .store(true, Ordering::Release);
                uncharge();
                return None;
            }
            let Some(frames) = allocator.reserve::<N>(FrameOwner::KERNEL) else {
                uncharge();
                return None;
            };
            for frame in &frames {
                let Some(address) = frame.direct_map_address() else {
                    let _ = allocator.release(FrameOwner::KERNEL, frames);
                    uncharge();
                    return None;
                };
                core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
            }
            for frame in &frames {
                if let Some(index) = allocator.index(frame.address) {
                    allocator.set_charge(index, charge);
                }
            }
            return Some(frames);
        }
    }
}

/// The memory cgroup `frame` is charged to (0 for none): whose swap a
/// page paged out of it is charged to.
pub(crate) fn frame_charge(frame: FrameLease) -> u16 {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return 0;
    }
    let storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        let allocator = storage.assume_init_ref();
        allocator
            .index(frame.address)
            .map_or(0, |index| charge_parts(allocator.charge(index)).0)
    }
}

/// A frame's charge: the memory cgroup's slot, and in the top bits what the
/// page holds (memory.stat's anon, file or shmem).
const CHARGE_FILE: u16 = 1 << 14;
const CHARGE_SHMEM: u16 = 1 << 15;
const CHARGE_SLOT: u16 = CHARGE_FILE - 1;
const _: () = assert!(crate::linux_cgroup::SLOT_LIMIT <= CHARGE_SLOT as usize);

fn charge_parts(charge: u16) -> (u16, crate::linux_cgroup::PageKind) {
    use crate::linux_cgroup::PageKind;
    let kind = if charge & CHARGE_FILE != 0 {
        PageKind::File
    } else if charge & CHARGE_SHMEM != 0 {
        PageKind::Shmem
    } else {
        PageKind::Anon
    };
    (charge & CHARGE_SLOT, kind)
}

/// Charges a page-cache or shared-memory `frame` the kernel allocated for a
/// file to the current process's memory cgroup, as Linux charges a page
/// cache page to the cgroup of the task that brings it in; a frame charged
/// already keeps its charge.
pub(crate) fn charge_cache_frame(frame: FrameLease, shmem: bool) {
    let Some(slot) = crate::arch::x86_64::cpu::linux_cache_charge_slot() else {
        return;
    };
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        let allocator = storage.assume_init_mut();
        let Some(index) = allocator.index(frame.address) else {
            return;
        };
        if allocator.charge(index) != 0 || !allocator.lease_matches(frame, None) {
            return;
        }
        let (kind, bits) = if shmem {
            (crate::linux_cgroup::PageKind::Shmem, CHARGE_SHMEM)
        } else {
            (crate::linux_cgroup::PageKind::File, CHARGE_FILE)
        };
        crate::linux_cgroup::charge_kind(slot, kind);
        allocator.set_charge(index, slot | bits);
    }
}

/// Allocates a zeroed frame of user memory charged to memory cgroup
/// `slot` whatever its limit says, without reclaim: a page read back from
/// swap for another process (swapoff), whose cgroup it was charged to
/// before it went out.
pub(crate) fn allocate_user_frame_charged_to(slot: u16) -> Option<FrameLease> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_user_frames.
    unsafe {
        let allocator = storage.assume_init_mut();
        let total = allocator.free_frames + allocator.allocated_frames;
        if allocator.free_frames < 1 + user_reserve_frames(total) {
            return None;
        }
        let [frame] = allocator.reserve::<1>(FrameOwner::KERNEL)?;
        let Some(address) = frame.direct_map_address() else {
            let _ = allocator.release(FrameOwner::KERNEL, [frame]);
            return None;
        };
        core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
        if slot != 0 {
            crate::linux_cgroup::force_charge(slot, 1);
            if let Some(index) = allocator.index(frame.address) {
                allocator.set_charge(index, slot);
            }
        }
        Some(frame)
    }
}

/// Whether `allocate_user_frames` refused a request for lack of memory since
/// the last call; clears the record.
pub(crate) fn take_user_frames_refused() -> bool {
    PHYSICAL_MEMORY
        .user_frames_refused
        .swap(false, Ordering::AcqRel)
}

pub(crate) fn allocate_frame_prefix_into(
    owner: FrameOwner,
    output: &mut [FrameLease],
    count: usize,
) -> bool {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || count == 0 || count > output.len() {
        return false;
    }
    output.fill(FrameLease::EMPTY);
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: initialized publishes a valid allocator; the lock serializes the
    // partial reservation and rollback transaction.
    unsafe {
        let allocator = storage.assume_init_mut();
        for index in 0..count {
            let frame = allocator.allocate_one(owner);
            let address = frame.and_then(FrameLease::direct_map_address);
            let (Some(frame), Some(address)) = (frame, address) else {
                if let Some(frame) = frame {
                    let _ = allocator.release_slice(owner, core::slice::from_ref(&frame));
                }
                let _ = allocator.release_slice(owner, &output[..index]);
                output[..index].fill(FrameLease::EMPTY);
                return false;
            };
            core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
            output[index] = frame;
        }
    }
    true
}

pub(crate) fn allocate_contiguous_frames<const N: usize>(
    owner: FrameOwner,
) -> Option<[FrameLease; N]> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: initialized publishes a valid allocator and the lock serializes
    // the contiguous reservation.
    unsafe {
        let allocator = storage.assume_init_mut();
        let frames = allocator.reserve_contiguous::<N>(owner)?;
        for frame in &frames {
            let Some(address) = frame.direct_map_address() else {
                let _ = allocator.release(owner, frames);
                return None;
            };
            core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(frames)
    }
}

pub(crate) fn allocate_contiguous_extent(
    owner: FrameOwner,
    count: usize,
) -> Option<(FrameLease, usize)> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || count == 0 {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        let allocator = storage.assume_init_mut();
        let first = allocator.reserve_contiguous_extent(owner, count)?;
        let length = count.checked_mul(PAGE_SIZE as usize)?;
        let Some(address) = paging::direct_map_range_address(first.address, length) else {
            let _ = allocator.release_contiguous_extent(owner, first, count);
            return None;
        };
        core::ptr::write_bytes(address as *mut u8, 0, length);
        Some((first, count))
    }
}

pub(crate) fn scrub_and_release_contiguous_extent(
    owner: FrameOwner,
    first: FrameLease,
    count: usize,
) -> bool {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || count == 0 {
        return false;
    }
    let Some(length) = count.checked_mul(PAGE_SIZE as usize) else {
        return false;
    };
    let Some(address) = paging::direct_map_range_address(first.address, length) else {
        return false;
    };
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames. Ownership is checked before scrubbing so
    // a stale lease cannot destroy a newer allocation's contents, and the
    // allocator lock prevents another CPU from recycling this extent until
    // both the security scrub and metadata release are complete.
    unsafe {
        let allocator = storage.assume_init_mut();
        if !allocator.can_release_contiguous_extent(owner, first, count) {
            return false;
        }
        core::ptr::write_bytes(address as *mut u8, 0, length);
        allocator.release_contiguous_extent(owner, first, count)
    }
}

pub(crate) fn allocate_runtime_extent<const N: usize>() -> Option<[FrameLease; N]> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || N == 0 {
        return None;
    }
    let slot = crate::arch::x86_64::cpu::current_container_slot()?;
    let existing = PHYSICAL_MEMORY.runtime_extent_starts[slot].load(Ordering::Acquire);
    let count = PHYSICAL_MEMORY.runtime_extent_counts[slot].load(Ordering::Acquire);
    let start = if existing != 0 {
        (count == N).then_some(existing)?
    } else {
        let mut storage = PHYSICAL_MEMORY.allocator.lock();
        // SAFETY: as for allocate_frames.
        let start = unsafe { storage.assume_init_mut().carve(N)? };
        PHYSICAL_MEMORY.runtime_extent_counts[slot].store(N, Ordering::Release);
        PHYSICAL_MEMORY.runtime_extent_starts[slot].store(start, Ordering::Release);
        start
    };
    let frames = core::array::from_fn(|index| FrameLease {
        address: start + index as u64 * PAGE_SIZE,
        generation: 1,
    });
    for frame in &frames {
        let address = frame.direct_map_address()?;
        unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize) };
    }
    Some(frames)
}

pub(crate) fn scrub_runtime_extent<const N: usize>(frames: [FrameLease; N]) -> bool {
    if !runtime_extent_owns(&frames) {
        return false;
    }
    frames.iter().all(|frame| {
        frame.direct_map_address().is_some_and(|address| {
            unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize) };
            true
        })
    })
}

fn runtime_extent_owns(frames: &[FrameLease]) -> bool {
    !frames.is_empty()
        && PHYSICAL_MEMORY
            .runtime_extent_starts
            .iter()
            .zip(&PHYSICAL_MEMORY.runtime_extent_counts)
            .any(|(start, count)| {
                let start = start.load(Ordering::Acquire);
                let count = count.load(Ordering::Acquire);
                let end = start.saturating_add(count as u64 * PAGE_SIZE);
                start != 0
                    && frames.iter().all(|frame| {
                        frame.generation == 1
                            && frame.address >= start
                            && frame.address < end
                            && frame.address.is_multiple_of(PAGE_SIZE)
                    })
            })
}

pub(crate) fn frame_lease_is_runtime(frame: FrameLease) -> bool {
    runtime_extent_owns(&[frame])
}

pub(crate) fn frame_address_is_runtime(address: u64) -> bool {
    FrameLease::from_parts(address, 1).is_some_and(frame_lease_is_runtime)
}

pub(crate) fn release_frames<const N: usize>(owner: FrameOwner, frames: [FrameLease; N]) -> bool {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return false;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { storage.assume_init_mut().release(owner, frames) }
}

pub(crate) fn frame_leases_releasable(owner: FrameOwner, frames: &[FrameLease]) -> bool {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || frames.is_empty() {
        return false;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        storage.assume_init_mut().can_release(owner, frames)
            && frames
                .iter()
                .all(|frame| frame.direct_map_address().is_some())
    }
}

/// The metadata word of the frame at `address` when it is live and the
/// kernel's, read without the allocator lock. The answer is a snapshot, as a
/// locked lookup's is once the lock is dropped.
fn kernel_frame_metadata(address: u64) -> Option<u64> {
    if address < LOW_MEMORY_LIMIT || !address.is_multiple_of(PAGE_SIZE) {
        return None;
    }
    let table = PHYSICAL_MEMORY.metadata_table.load(Ordering::Acquire);
    let index = usize::try_from(address / PAGE_SIZE).ok()?;
    if table.is_null() || index >= PHYSICAL_MEMORY.metadata_frames.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: the table covers metadata_frames words from frame 0 (the boot
    // allocator's first frame) for the kernel's lifetime, and its words are
    // only accessed atomically.
    let metadata = unsafe { AtomicU64::from_ptr(table.add(index)).load(Ordering::Acquire) };
    (metadata & META_LIVE != 0 && metadata & META_OWNER == 0).then_some(metadata)
}

pub(crate) fn live_frame_lease(owner: FrameOwner, address: u64) -> Option<FrameLease> {
    crate::linux_profile::count_memory(7);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    if owner.is_kernel() {
        return kernel_frame_metadata(address).map(|metadata| FrameLease {
            address,
            generation: (metadata >> META_GENERATION_SHIFT) as u32,
        });
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { storage.assume_init_mut().live_lease(owner, address) }
}

pub(crate) fn scrub_and_release_frames(owner: FrameOwner, frames: &[FrameLease]) -> bool {
    crate::linux_profile::count_memory(1);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || frames.is_empty() {
        return false;
    }
    // The allocator lock keeps ownership validation, payload scrubbing, and
    // release one transaction, so a stale lease cannot scrub a newer use.
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        let allocator = storage.assume_init_mut();
        if !allocator.can_release(owner, frames)
            || frames
                .iter()
                .any(|frame| frame.direct_map_address().is_none())
        {
            return false;
        }
        for frame in frames {
            // A frame another address space still maps keeps its contents.
            if allocator.is_shared(*frame) {
                continue;
            }
            let Some(address) = frame.direct_map_address() else {
                return false;
            };
            core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE as usize);
        }
        allocator.release_slice(owner, frames)
    }
}

/// Records that one more address space maps each of `frames`, so releasing
/// them drops that mapping instead of freeing the pages. All or none.
pub(crate) fn share_frames(owner: FrameOwner, frames: &[FrameLease]) -> bool {
    crate::linux_profile::count_memory(2);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) || frames.is_empty() {
        return false;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { storage.assume_init_mut().share_slice(owner, frames) }
}

/// Whether another address space also maps `frame`.
pub(crate) fn frame_is_shared(frame: FrameLease) -> bool {
    crate::linux_profile::count_memory(3);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return false;
    }
    let storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { storage.assume_init_ref().is_shared(frame) }
}

pub(crate) fn transfer_frame_owner(from: FrameOwner, to: FrameOwner) -> Option<usize> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { storage.assume_init_mut().transfer_owner(from, to) }
}

pub(crate) fn frames_owned_by(owner: FrameOwner, frames: &[FrameLease]) -> bool {
    crate::linux_profile::count_memory(4);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return false;
    }
    if owner.is_kernel()
        && frames.iter().all(|frame| {
            kernel_frame_metadata(frame.address).is_some_and(|metadata| {
                (metadata >> META_GENERATION_SHIFT) as u32 == frame.generation
            })
        })
    {
        return true;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        storage.assume_init_mut().owns(owner, frames)
            || owner.is_kernel() && runtime_extent_owns(frames)
    }
}

pub(crate) fn any_frame_lease_live(frames: &[FrameLease]) -> bool {
    crate::linux_profile::count_memory(5);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return false;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { storage.assume_init_mut().tracks_any(frames) }
}

pub(crate) fn frame_addresses_owned_by(owner: FrameOwner, addresses: &[u64]) -> bool {
    crate::linux_profile::count_memory(6);
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return false;
    }
    if owner.is_kernel()
        && !addresses.is_empty()
        && addresses
            .iter()
            .all(|address| kernel_frame_metadata(*address).is_some())
    {
        return true;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        storage.assume_init_mut().owns_addresses(owner, addresses)
            || owner.is_kernel()
                && !addresses.is_empty()
                && PHYSICAL_MEMORY
                    .runtime_extent_starts
                    .iter()
                    .zip(&PHYSICAL_MEMORY.runtime_extent_counts)
                    .any(|(start, count)| {
                        let start = start.load(Ordering::Acquire);
                        let count = count.load(Ordering::Acquire);
                        addresses.iter().all(|address| {
                            start != 0
                                && *address >= start
                                && *address < start.saturating_add(count as u64 * PAGE_SIZE)
                                && address.is_multiple_of(PAGE_SIZE)
                        })
                    })
    }
}

pub(crate) fn owner_live_frame_count(owner: FrameOwner) -> Option<usize> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { Some(storage.assume_init_mut().owner_live_count(owner)) }
}

/// Returns the total and currently free frame counts.
pub(crate) fn frame_counts() -> Option<(u64, u64)> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe {
        let allocator = storage.assume_init_mut();
        let available = allocator.free_frames;
        Some((
            available.checked_add(allocator.allocated_frames)?,
            available,
        ))
    }
}

pub(crate) fn reclaimed_boot_service_frame_count() -> Option<u64> {
    if !PHYSICAL_MEMORY.initialized.load(Ordering::Acquire) {
        return None;
    }
    let mut storage = PHYSICAL_MEMORY.allocator.lock();
    // SAFETY: as for allocate_frames.
    unsafe { Some(storage.assume_init_mut().reclaimed_boot_service_frames) }
}

/// Exercises reservation, release, ownership, budget, and contiguity rules on
/// a private allocator over a synthetic memory map.
pub(crate) fn verify_reservation_invariants() -> bool {
    // Frames 0x100..0x700 (1 MiB to 7 MiB) are tracked.
    const FIRST_FRAME: u64 = 0x100;
    const FRAMES: usize = 0x600;
    static mut METADATA: [u64; FRAMES] = [0; FRAMES];
    static mut FREE: [u64; FRAMES / 64] = [0; FRAMES / 64];
    // SAFETY: the test tables are private to this single-threaded self-test.
    let new_allocator = |ranges: &[(u64, u64)]| unsafe {
        let metadata = core::ptr::addr_of_mut!(METADATA).cast::<u64>();
        let free = core::ptr::addr_of_mut!(FREE).cast::<u64>();
        metadata.write_bytes(0, FRAMES);
        free.write_bytes(0, FRAMES / 64);
        let mut allocator = FrameAllocator::with_tables(
            FIRST_FRAME,
            FRAMES,
            metadata,
            free,
            core::ptr::null_mut(),
            16,
        );
        for (start, end) in ranges {
            allocator.add_free_range(*start, *end);
        }
        allocator
    };
    let owner = FrameOwner(1);
    let other_owner = FrameOwner(2);
    let third_owner = FrameOwner(3);

    let mut allocator = new_allocator(&[(0x10_0000, 0x10_2000), (0x20_0000, 0x20_1000)]);
    let Some(first) = allocator.reserve::<2>(owner) else {
        return false;
    };
    let failed = allocator.reserve::<2>(owner).is_none()
        && allocator.allocated_frames == 2
        && allocator.free_frames == 1;
    let Some(last) = allocator.reserve::<1>(owner) else {
        return false;
    };
    let forged_release_rejected = !allocator.release(
        owner,
        [FrameLease {
            address: 0x30_0000,
            generation: 1,
        }],
    ) && allocator.allocated_frames == 3;
    let wrong_owner_rejected = !allocator.release(other_owner, first);
    let shared_release_kept = allocator.share_slice(owner, &first[..1])
        && allocator.is_shared(first[0])
        && !allocator.share_slice(other_owner, &first[..1])
        && allocator.release(owner, [first[0]])
        && !allocator.is_shared(first[0])
        && allocator.owns(owner, &first)
        && allocator.allocated_frames == 3;
    let released = allocator.release(owner, first);
    let duplicate_rejected = !allocator.release(owner, first);
    let reused = allocator.reserve::<2>(other_owner);
    let stale_release_rejected = !allocator.release(other_owner, first);
    let reuse_bumped_generation = reused.is_some_and(|leases| {
        leases.map(FrameLease::address) == [0x10_0000, 0x10_1000]
            && leases.iter().all(|lease| lease.generation == 2)
    });
    let ownership_transferred = allocator.transfer_owner(owner, other_owner) == Some(1)
        && !allocator.owns(owner, &last)
        && allocator.owns(other_owner, &last)
        && allocator.owner_live_count(owner) == 0
        && allocator.owner_live_count(other_owner) == 3;
    let exhausted = allocator.reserve::<1>(FrameOwner::KERNEL).is_none()
        && allocator.free_frames == 0
        && allocator.allocated_frames == 3;

    let mut budgeted = new_allocator(&[(0x40_0000, 0x40_0000 + 33 * PAGE_SIZE)]);
    let over_budget_atomic = budgeted.reserve::<17>(owner).is_none()
        && budgeted.allocated_frames == 0
        && budgeted.free_frames == 33;
    let budget_filled = budgeted.reserve::<16>(owner).is_some()
        && budgeted.reserve::<1>(owner).is_none()
        && budgeted.reserve::<1>(other_owner).is_some();
    let transfer_over_budget_rejected = budgeted.transfer_owner(owner, other_owner).is_none()
        && budgeted.owner_live_count(owner) == 16
        && budgeted.owner_live_count(other_owner) == 1;
    let bounded_transfer_completed = budgeted.transfer_owner(owner, third_owner) == Some(16)
        && budgeted.owner_live_count(owner) == 0
        && budgeted.owner_live_count(third_owner) == 16;

    let mut contiguous = new_allocator(&[(0x50_0000, 0x50_2000), (0x60_0000, 0x60_4000)]);
    let contiguous_failure_atomic = contiguous.reserve_contiguous::<5>(owner).is_none()
        && contiguous.allocated_frames == 0
        && contiguous.free_frames == 6;
    let contiguous_three = contiguous.reserve_contiguous::<3>(owner);
    let contiguous_two = contiguous.reserve_contiguous::<2>(owner);
    let contiguous_ranges_selected = contiguous_three.map(|frames| frames.map(FrameLease::address))
        == Some([0x60_0000, 0x60_1000, 0x60_2000])
        && contiguous_two.map(|frames| frames.map(FrameLease::address))
            == Some([0x50_0000, 0x50_1000]);
    let contiguous_released = contiguous_three
        .is_some_and(|frames| contiguous.release(owner, frames))
        && contiguous_two.is_some_and(|frames| contiguous.release(owner, frames));
    let contiguous_reused = contiguous.reserve_contiguous::<3>(other_owner);
    let contiguous_recycle_preserved = contiguous_reused.is_some_and(|frames| {
        frames.map(FrameLease::address) == [0x60_0000, 0x60_1000, 0x60_2000]
            && frames.iter().all(|frame| frame.generation == 2)
            && contiguous.release(other_owner, frames)
    });
    let extent = contiguous.reserve_contiguous_extent(owner, 4);
    let extent_highest_first = extent.is_some_and(|first| first.address == 0x60_0000)
        && contiguous.reserve_contiguous_extent(owner, 3).is_none()
        && extent.is_some_and(|first| {
            !contiguous.release_contiguous_extent(other_owner, first, 4)
                && contiguous.release_contiguous_extent(owner, first, 4)
                && contiguous.free_frames == 6
        });

    first.map(FrameLease::address) == [0x10_0000, 0x10_1000]
        && failed
        && last.map(FrameLease::address) == [0x20_0000]
        && forged_release_rejected
        && wrong_owner_rejected
        && shared_release_kept
        && released
        && duplicate_rejected
        && reuse_bumped_generation
        && stale_release_rejected
        && ownership_transferred
        && exhausted
        && allocator.reserve::<0>(owner).is_none()
        && over_budget_atomic
        && budget_filled
        && transfer_over_budget_rejected
        && bounded_transfer_completed
        && contiguous_failure_atomic
        && contiguous_ranges_selected
        && contiguous_released
        && contiguous_recycle_preserved
        && extent_highest_first
}
