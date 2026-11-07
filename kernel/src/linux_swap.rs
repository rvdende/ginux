//! Swap areas: swapon(2) and swapoff(2) on swap files (on a volume) and
//! swap partitions (block devices), the slots anonymous pages are paged
//! out to, /proc/swaps, and /proc/meminfo's SwapTotal and SwapFree.
//!
//! An area is a file or device mkswap prepared: its first page ends in the
//! `SWAPSPACE2` signature and holds the header (version 1, the last page,
//! the bad pages). Activating one checks it as Linux does and makes a map
//! of its pages, Linux's `swap_map`: each holds how many page-table
//! entries name it (a forked child shares its parent's), 0 when free, and
//! the header and the bad pages are never handed out. A swap entry is the
//! area's type (its number, as Linux's swp_type) and the page's offset in
//! it; reclaim takes one for a page it pages out (`allocate`), fork takes
//! another reference (`duplicate`) and a fault that reads the page back,
//! munmap and exit drop one (`free`). Each slot remembers the memory
//! cgroup its page was charged to, whose `memory.swap.current` it counts
//! in until it is freed.
//!
//! A page read back ahead of a fault (MADV_WILLNEED) waits in the swap
//! cache, Linux's swap cache: a frame holding a copy of the slot, which
//! the fault then takes without I/O, and which reclaim may drop at any
//! time, the slot still holding the page. /proc/meminfo's SwapCached
//! counts these frames.
//!
//! The page I/O itself is cpu.rs's (`cpu::linux_swapon`): this module
//! hands out slots and says where they are (`location`). An area being
//! turned off (`begin_drain`) takes no new pages while the pages in it are
//! read back, and goes once none is left (`finish_drain`).
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::linux_cgroup::{self as cgroup, Slot};
use crate::linux_overlay::Handle;
use crate::memory::{self, FrameLease, FrameOwner};
use crate::sync::{LockRank, SpinLock};

const PAGE: usize = 4096;
/// Linux's MAX_SWAPFILES: 32 less the swap types its page tables reserve
/// (migration, hardware poison, PTE markers).
pub(crate) const MAX_SWAPFILES: usize = 27;
/// swapon(2)'s flags: a priority (with SWAP_FLAG_PREFER) and discard.
pub(crate) const SWAP_FLAG_PREFER: u32 = 0x8000;
pub(crate) const SWAP_FLAG_PRIO_MASK: u32 = 0x7fff;
pub(crate) const SWAP_FLAGS_VALID: u32 = SWAP_FLAG_PRIO_MASK | SWAP_FLAG_PREFER | 0x7_0000;
/// The most bad pages a header may list.
const MAX_SWAP_BADPAGES: u32 = 637;
/// Swap types across every domain: an entry has six bits for its type.
const TYPE_LIMIT: u8 = 64;
const TYPE_SHIFT: u32 = 32;
/// A page of the map that is never handed out: the header or a bad page.
const UNUSABLE: u16 = u16::MAX;
/// Swap cache entries per chunk, which is allocated when first needed.
const CACHE_CHUNK: usize = 512;

/// A swap entry: the area's type above `TYPE_SHIFT`, the page's offset in
/// the area below. It fits in 38 bits, which a page-table entry holds.
pub(crate) type Entry = u64;

/// What an area is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Target {
    /// A regular file (of a volume).
    File(Handle),
    /// A block device, by dev_t.
    Device(u32),
}

struct Area {
    instance: usize,
    target: Target,
    /// Its swap type, which its entries carry.
    kind: u8,
    /// The path /proc/swaps shows.
    path: Vec<u8>,
    /// Usable pages: all but the header and the bad pages.
    pages: u64,
    priority: i32,
    /// Per page of the area: the references to it, or `UNUSABLE`.
    map: Vec<u16>,
    /// Per page: the memory cgroup its swap is charged to.
    owners: Vec<Slot>,
    /// Pages in use.
    used: u64,
    /// Where the next search for a free page starts.
    cursor: usize,
    /// swapoff is reading its pages back: no new ones go in.
    draining: bool,
    /// The swap cache: per page, the frame holding a copy of it (EMPTY for
    /// none), in chunks of `CACHE_CHUNK` made as they are first needed.
    cache: Vec<Vec<FrameLease>>,
    cached: u64,
}

impl Area {
    fn cache_slot(&mut self, offset: usize) -> Option<&mut FrameLease> {
        self.cache
            .get_mut(offset / CACHE_CHUNK)?
            .get_mut(offset % CACHE_CHUNK)
            .filter(|frame| **frame != FrameLease::EMPTY)
    }

    /// Frees page `offset`'s swap cache frame, if it has one.
    fn drop_cached(&mut self, offset: usize) {
        if let Some(slot) = self.cache_slot(offset) {
            let frame = core::mem::replace(slot, FrameLease::EMPTY);
            self.cached -= 1;
            let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[frame]);
        }
    }
}

static AREAS: SpinLock<Vec<Area>> = SpinLock::new(LockRank::SWAPS, Vec::new());

fn entry_kind(entry: Entry) -> u8 {
    (entry >> TYPE_SHIFT) as u8
}

fn entry_offset(entry: Entry) -> usize {
    (entry & 0xffff_ffff) as usize
}

fn header_word(header: &[u8; PAGE], at: usize) -> u32 {
    u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
}

/// The usable pages of an area whose first page is `header` and which
/// holds `pages` pages, if the header is a valid version 1 swap header
/// that the area is long enough for (EINVAL otherwise).
pub(crate) fn usable_pages(header: &[u8; PAGE], pages: u64) -> Option<u64> {
    if &header[PAGE - 10..] != b"SWAPSPACE2" {
        return None;
    }
    let (version, last_page, bad_pages) = (
        header_word(header, 1024),
        header_word(header, 1028),
        header_word(header, 1032),
    );
    if version != 1 || bad_pages > MAX_SWAP_BADPAGES {
        return None;
    }
    let max_pages = u64::from(last_page) + 1;
    if max_pages <= 1 || max_pages > pages {
        return None;
    }
    let usable = (max_pages - 1).saturating_sub(u64::from(bad_pages));
    (usable != 0).then_some(usable)
}

/// The areas domain `instance` has on.
pub(crate) fn count(instance: usize) -> usize {
    AREAS
        .lock()
        .iter()
        .filter(|area| area.instance == instance)
        .count()
}

/// Whether `target` is an active area (of any domain).
pub(crate) fn active(target: Target) -> bool {
    AREAS.lock().iter().any(|area| area.target == target)
}

/// Turns area `target` on for `instance`, with the header `header` that
/// `usable_pages` accepted: EBUSY if it already is, EPERM past
/// MAX_SWAPFILES, ENOMEM without memory for its map. Without
/// SWAP_FLAG_PREFER areas get priorities from -2 down, as Linux numbers
/// them.
pub(crate) fn activate(
    instance: usize,
    target: Target,
    path: &[u8],
    header: &[u8; PAGE],
    pages: u64,
    flags: u32,
) -> Result<(), Errno> {
    let size = usize::try_from(header_word(header, 1028))
        .ok()
        .and_then(|last| last.checked_add(1))
        .ok_or(ENOMEM)?;
    let mut stored = Vec::new();
    stored.try_reserve_exact(path.len()).map_err(|_| ENOMEM)?;
    stored.extend_from_slice(path);
    let mut map = Vec::new();
    map.try_reserve_exact(size).map_err(|_| ENOMEM)?;
    map.resize(size, 0_u16);
    let mut owners = Vec::new();
    owners.try_reserve_exact(size).map_err(|_| ENOMEM)?;
    owners.resize(size, cgroup::NO_SLOT);
    // The header is page 0; the bad pages it lists follow its counts.
    map[0] = UNUSABLE;
    for index in 0..header_word(header, 1032) as usize {
        let bad = header_word(header, 1036 + 4 * index) as usize;
        if let Some(page) = map.get_mut(bad) {
            *page = UNUSABLE;
        }
    }
    let mut areas = AREAS.lock();
    if areas.iter().any(|area| area.target == target) {
        return Err(EBUSY);
    }
    if areas
        .iter()
        .filter(|area| area.instance == instance)
        .count()
        >= MAX_SWAPFILES
    {
        return Err(EPERM);
    }
    let kind = (0..TYPE_LIMIT)
        .find(|kind| !areas.iter().any(|area| area.kind == *kind))
        .ok_or(EPERM)?;
    let priority = if flags & SWAP_FLAG_PREFER != 0 {
        (flags & SWAP_FLAG_PRIO_MASK) as i32
    } else {
        areas
            .iter()
            .filter(|area| area.instance == instance)
            .map(|area| area.priority)
            .filter(|priority| *priority < 0)
            .min()
            .unwrap_or(-1)
            - 1
    };
    areas.try_reserve(1).map_err(|_| ENOMEM)?;
    areas.push(Area {
        instance,
        target,
        kind,
        path: stored,
        pages,
        priority,
        map,
        owners,
        used: 0,
        cursor: 1,
        draining: false,
        cache: Vec::new(),
        cached: 0,
    });
    Ok(())
}

/// Starts turning area `target` of `instance` off (EINVAL if it is not
/// on, or is already being turned off): it takes no new pages from now
/// on. Its swap type, whose entries the caller then reads back.
pub(crate) fn begin_drain(instance: usize, target: Target) -> Result<u8, Errno> {
    let mut areas = AREAS.lock();
    let area = areas
        .iter_mut()
        .find(|area| area.instance == instance && area.target == target && !area.draining)
        .ok_or(EINVAL)?;
    area.draining = true;
    Ok(area.kind)
}

/// Pages of the area of type `kind` still in use.
pub(crate) fn used_in(kind: u8) -> u64 {
    AREAS
        .lock()
        .iter()
        .find(|area| area.kind == kind)
        .map_or(0, |area| area.used)
}

/// Gives area `kind` back its pages after a swapoff that could not read
/// them all back.
pub(crate) fn abort_drain(kind: u8) {
    if let Some(area) = AREAS.lock().iter_mut().find(|area| area.kind == kind) {
        area.draining = false;
    }
}

/// Ends area `kind`, whose pages are all back in memory; the areas
/// numbered after it move up, as Linux renumbers them. False if pages are
/// still out in it.
pub(crate) fn finish_drain(kind: u8) -> bool {
    let mut areas = AREAS.lock();
    let Some(index) = areas.iter().position(|area| area.kind == kind) else {
        return true;
    };
    if areas[index].used != 0 {
        return false;
    }
    let removed = areas.remove(index);
    if removed.priority < 0 {
        for area in areas
            .iter_mut()
            .filter(|area| area.instance == removed.instance && area.priority < removed.priority)
        {
            area.priority += 1;
        }
    }
    true
}

/// Whether a swap file is the file of overlay generation `generation`
/// (its volume then stays mounted, as Linux keeps it busy).
pub(crate) fn uses_generation(generation: u32) -> bool {
    AREAS.lock().iter().any(|area| {
        matches!(area.target, Target::File(handle)
            if crate::linux_overlay::generation(handle) == generation)
    })
}

/// Drops domain `instance`'s areas (the domain is going, its processes
/// with it).
pub(crate) fn forget_instance(instance: usize) {
    let mut areas = AREAS.lock();
    for area in areas.iter_mut().filter(|area| area.instance == instance) {
        for (count, owner) in area.map.iter().zip(&area.owners) {
            if *count != 0 && *count != UNUSABLE {
                cgroup::uncharge_swap(*owner, 1);
            }
        }
        for offset in 0..area.map.len() {
            area.drop_cached(offset);
        }
    }
    areas.retain(|area| area.instance != instance);
}

/// Whether domain `instance` has an area with a free page.
pub(crate) fn available(instance: usize) -> bool {
    AREAS
        .lock()
        .iter()
        .any(|area| area.instance == instance && !area.draining && area.used < area.pages)
}

/// Takes a free page of `instance`'s highest-priority area with one, for
/// a page charged to memory cgroup `owner`, whose swap it is charged to:
/// None when no area has room or the cgroup's `memory.swap.max` refuses.
pub(crate) fn allocate(instance: usize, owner: Slot) -> Option<Entry> {
    let mut areas = AREAS.lock();
    let area = areas
        .iter_mut()
        .filter(|area| area.instance == instance && !area.draining && area.used < area.pages)
        .max_by_key(|area| area.priority)?;
    if !cgroup::try_charge_swap(owner, 1) {
        return None;
    }
    let size = area.map.len();
    let start = area.cursor.clamp(1, size.max(1));
    let found = (start..size)
        .chain(1..start)
        .find(|index| area.map[*index] == 0);
    let Some(offset) = found else {
        cgroup::uncharge_swap(owner, 1);
        return None;
    };
    area.map[offset] = 1;
    area.owners[offset] = owner;
    area.used += 1;
    area.cursor = offset + 1;
    Some(u64::from(area.kind) << TYPE_SHIFT | offset as u64)
}

/// Takes another reference to `entry`, for a forked child's copy of the
/// page-table entry naming it. False for an entry no area has.
pub(crate) fn duplicate(entry: Entry) -> bool {
    let mut areas = AREAS.lock();
    let Some(count) = areas
        .iter_mut()
        .find(|area| area.kind == entry_kind(entry))
        .and_then(|area| area.map.get_mut(entry_offset(entry)))
        .filter(|count| **count != 0 && **count != UNUSABLE)
    else {
        return false;
    };
    *count = count.saturating_add(1).min(UNUSABLE - 1);
    true
}

/// Drops a reference to `entry`; its page is free once none is left, and
/// its swap charge goes back to its cgroup.
pub(crate) fn free(entry: Entry) {
    let mut areas = AREAS.lock();
    let Some(area) = areas.iter_mut().find(|area| area.kind == entry_kind(entry)) else {
        return;
    };
    let offset = entry_offset(entry);
    let Some(count) = area.map.get_mut(offset) else {
        return;
    };
    if *count == 0 || *count == UNUSABLE {
        return;
    }
    *count -= 1;
    if *count == 0 {
        area.used -= 1;
        let owner = core::mem::replace(&mut area.owners[offset], cgroup::NO_SLOT);
        cgroup::uncharge_swap(owner, 1);
        area.drop_cached(offset);
    }
}

/// The swap cache's frame holding `entry`'s page, if it has one.
pub(crate) fn cached(entry: Entry) -> Option<FrameLease> {
    let mut areas = AREAS.lock();
    let area = areas
        .iter_mut()
        .find(|area| area.kind == entry_kind(entry))?;
    area.cache_slot(entry_offset(entry)).copied()
}

/// Puts `frame`, a copy of `entry`'s page, in the swap cache: false (the
/// caller keeps the frame) if the entry is free, already cached, or there
/// is no memory for the cache's chunk.
pub(crate) fn insert_cached(entry: Entry, frame: FrameLease) -> bool {
    let mut areas = AREAS.lock();
    let Some(area) = areas.iter_mut().find(|area| area.kind == entry_kind(entry)) else {
        return false;
    };
    let offset = entry_offset(entry);
    if area
        .map
        .get(offset)
        .is_none_or(|count| *count == 0 || *count == UNUSABLE)
    {
        return false;
    }
    let chunk = offset / CACHE_CHUNK;
    if area.cache.len() <= chunk {
        if area
            .cache
            .try_reserve(chunk + 1 - area.cache.len())
            .is_err()
        {
            return false;
        }
        area.cache.resize_with(chunk + 1, Vec::new);
    }
    if area.cache[chunk].is_empty() {
        if area.cache[chunk].try_reserve_exact(CACHE_CHUNK).is_err() {
            return false;
        }
        area.cache[chunk].resize(CACHE_CHUNK, FrameLease::EMPTY);
    }
    let slot = &mut area.cache[chunk][offset % CACHE_CHUNK];
    if *slot != FrameLease::EMPTY {
        return false;
    }
    *slot = frame;
    area.cached += 1;
    true
}

/// Drops up to `budget` frames of `instance`'s swap cache whose memory
/// `wanted` says reclaim is for (by the cgroup the frame is charged to):
/// their pages stay in their slots. How many went.
pub(crate) fn shrink_cache(instance: usize, budget: u64, wanted: impl Fn(Slot) -> bool) -> u64 {
    let mut dropped = 0;
    let mut areas = AREAS.lock();
    for area in areas.iter_mut().filter(|area| area.instance == instance) {
        let mut offset = 0;
        while area.cached != 0 && offset < area.map.len() && dropped < budget {
            if let Some(frame) = area.cache_slot(offset).copied() {
                if wanted(memory::frame_charge(frame)) {
                    area.drop_cached(offset);
                    dropped += 1;
                }
                offset += 1;
            } else {
                // A chunk not made holds nothing.
                offset = if area
                    .cache
                    .get(offset / CACHE_CHUNK)
                    .is_none_or(|chunk| chunk.is_empty())
                {
                    (offset / CACHE_CHUNK + 1) * CACHE_CHUNK
                } else {
                    offset + 1
                };
            }
        }
    }
    dropped
}

/// The pages of `instance`'s swap cache (SwapCached).
pub(crate) fn cached_pages(instance: usize) -> u64 {
    AREAS
        .lock()
        .iter()
        .filter(|area| area.instance == instance)
        .map(|area| area.cached)
        .sum()
}

/// Where `entry`'s page is: its area's target and the page's byte offset
/// in it.
pub(crate) fn location(entry: Entry) -> Option<(Target, u64)> {
    let areas = AREAS.lock();
    let area = areas.iter().find(|area| area.kind == entry_kind(entry))?;
    let offset = entry_offset(entry);
    (offset != 0 && offset < area.map.len()).then_some((area.target, offset as u64 * PAGE as u64))
}

/// The memory cgroup `entry`'s swap is charged to.
pub(crate) fn owner(entry: Entry) -> Slot {
    AREAS
        .lock()
        .iter()
        .find(|area| area.kind == entry_kind(entry))
        .and_then(|area| area.owners.get(entry_offset(entry)).copied())
        .unwrap_or(cgroup::NO_SLOT)
}

/// Whether `entry` is in the area of type `kind`.
pub(crate) fn in_kind(entry: Entry, kind: u8) -> bool {
    entry_kind(entry) == kind
}

/// SwapTotal and SwapFree of domain `instance`, in KiB.
pub(crate) fn totals(instance: usize) -> (u64, u64) {
    let areas = AREAS.lock();
    let mine = || areas.iter().filter(|area| area.instance == instance);
    let total: u64 = mine().map(|area| area.pages).sum();
    let used: u64 = mine().map(|area| area.used).sum();
    let unit = PAGE as u64 / 1024;
    (total * unit, total.saturating_sub(used) * unit)
}

/// /proc/swaps of domain `instance`.
pub(crate) fn proc_swaps(instance: usize) -> Option<Vec<u8>> {
    let mut text = Vec::new();
    let mut push = |bytes: &[u8]| -> Option<()> {
        text.try_reserve(bytes.len()).ok()?;
        text.extend_from_slice(bytes);
        Some(())
    };
    push(b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n")?;
    let areas = AREAS.lock();
    for area in areas.iter().filter(|area| area.instance == instance) {
        // The path with its spaces, tabs, newlines and backslashes
        // escaped as octal, padded to 40 columns.
        let mut length = 0;
        for byte in &area.path {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\\') {
                push(&[
                    b'\\',
                    b'0' + (byte >> 6),
                    b'0' + ((byte >> 3) & 7),
                    b'0' + (byte & 7),
                ])?;
                length += 4;
            } else {
                push(&[*byte])?;
                length += 1;
            }
        }
        for _ in 0..if length < 40 { 40 - length } else { 1 } {
            push(b" ")?;
        }
        push(match area.target {
            Target::Device(_) => b"partition",
            Target::File(_) => b"file\t",
        })?;
        let size = area.pages * (PAGE as u64 / 1024);
        let used = area.used * (PAGE as u64 / 1024);
        push(b"\t")?;
        push(decimal(size).as_bytes_view())?;
        push(if size < 10_000_000 { b"\t\t" } else { b"\t" })?;
        push(decimal(used).as_bytes_view())?;
        push(if used < 10_000_000 { b"\t\t" } else { b"\t" })?;
        push(signed(area.priority).as_bytes_view())?;
        push(b"\n")?;
    }
    Some(text)
}

/// A number's decimal digits, without allocating.
struct Digits {
    bytes: [u8; 21],
    start: usize,
}

impl Digits {
    fn as_bytes_view(&self) -> &[u8] {
        &self.bytes[self.start..]
    }
}

fn decimal(mut value: u64) -> Digits {
    let mut digits = Digits {
        bytes: [0; 21],
        start: 21,
    };
    loop {
        digits.start -= 1;
        digits.bytes[digits.start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return digits;
        }
    }
}

fn signed(value: i32) -> Digits {
    let mut digits = decimal(u64::from(value.unsigned_abs()));
    if value < 0 {
        digits.start -= 1;
        digits.bytes[digits.start] = b'-';
    }
    digits
}

pub(crate) type Errno = u64;
const EPERM: Errno = 1;
const ENOMEM: Errno = 12;
const EBUSY: Errno = 16;
const EINVAL: Errno = 22;
