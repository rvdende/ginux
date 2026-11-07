//! Swap areas: swapon(2) and swapoff(2) on swap files (on a volume) and
//! swap partitions (block devices), /proc/swaps, and /proc/meminfo's
//! SwapTotal and SwapFree.
//!
//! An area is a file or device mkswap prepared: its first page ends in the
//! `SWAPSPACE2` signature and holds the header (version 1, the last page,
//! the bad pages). Activating one checks it as Linux does and counts its
//! pages; Ginux does not page anonymous memory out to it, so an area's
//! pages are all free, which is what /proc/swaps and /proc/meminfo show.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::linux_overlay::Handle;
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
    /// The path /proc/swaps shows.
    path: Vec<u8>,
    /// Usable pages: all but the header and the bad pages.
    pages: u64,
    priority: i32,
}

static AREAS: SpinLock<Vec<Area>> = SpinLock::new(LockRank::SWAPS, Vec::new());

/// The usable pages of an area whose first page is `header` and which
/// holds `pages` pages, if the header is a valid version 1 swap header
/// that the area is long enough for (EINVAL otherwise).
pub(crate) fn usable_pages(header: &[u8; PAGE], pages: u64) -> Option<u64> {
    if &header[PAGE - 10..] != b"SWAPSPACE2" {
        return None;
    }
    let word = |at: usize| {
        u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
    };
    let (version, last_page, bad_pages) = (word(1024), word(1028), word(1032));
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

/// Turns area `target` on for `instance`: EBUSY if it already is, EPERM
/// past MAX_SWAPFILES, ENOMEM without memory for its record. Without
/// SWAP_FLAG_PREFER areas get priorities from -2 down, as Linux numbers
/// them.
pub(crate) fn activate(
    instance: usize,
    target: Target,
    path: &[u8],
    pages: u64,
    flags: u32,
) -> Result<(), Errno> {
    let mut stored = Vec::new();
    stored.try_reserve_exact(path.len()).map_err(|_| ENOMEM)?;
    stored.extend_from_slice(path);
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
        path: stored,
        pages,
        priority,
    });
    Ok(())
}

/// Turns area `target` of `instance` off (EINVAL if it is not on); the
/// areas numbered after it move up, as Linux renumbers them.
pub(crate) fn deactivate(instance: usize, target: Target) -> Result<(), Errno> {
    let mut areas = AREAS.lock();
    let index = areas
        .iter()
        .position(|area| area.instance == instance && area.target == target)
        .ok_or(EINVAL)?;
    let removed = areas.remove(index);
    if removed.priority < 0 {
        for area in areas
            .iter_mut()
            .filter(|area| area.instance == instance && area.priority < removed.priority)
        {
            area.priority += 1;
        }
    }
    Ok(())
}

/// Whether a swap file is the file of overlay generation `generation`
/// (its volume then stays mounted, as Linux keeps it busy).
pub(crate) fn uses_generation(generation: u32) -> bool {
    AREAS.lock().iter().any(|area| {
        matches!(area.target, Target::File(handle)
            if crate::linux_overlay::generation(handle) == generation)
    })
}

/// Drops domain `instance`'s areas (the domain is going).
pub(crate) fn forget_instance(instance: usize) {
    AREAS.lock().retain(|area| area.instance != instance);
}

/// SwapTotal and SwapFree of domain `instance`, in KiB.
pub(crate) fn totals(instance: usize) -> (u64, u64) {
    let total: u64 = AREAS
        .lock()
        .iter()
        .filter(|area| area.instance == instance)
        .map(|area| area.pages * (PAGE as u64 / 1024))
        .sum();
    (total, total)
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
        push(b"\t")?;
        push(decimal(size).as_bytes_view())?;
        push(if size < 10_000_000 { b"\t\t" } else { b"\t" })?;
        push(b"0\t\t")?;
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
