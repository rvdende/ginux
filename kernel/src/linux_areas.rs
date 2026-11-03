//! Each Linux process's memory areas (`ginux-memory-areas`), kept as its
//! mappings change: mmap, munmap, mprotect and mremap record them, a fork
//! copies the parent's, and exec and exit drop them.
//!
//! The page tables stay the authority on what is mapped and how it is
//! protected; the areas add what they cannot say, such as which file and
//! offset a range maps, for `/proc/PID/maps`. Mappings the kernel makes
//! itself (the program image, its stack) are not recorded yet, so a range
//! without an area is still reported from the page tables alone.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

pub(crate) use ginux_memory_areas::{Area, Areas, Backing, Protection, PAGE_SIZE};

use crate::sync::{LockRank, SpinLock};

struct Process {
    instance: usize,
    pid: u32,
    areas: Areas,
}

static PROCESSES: SpinLock<Vec<Process>> = SpinLock::new(LockRank::MEMORY_AREAS, Vec::new());

/// Applies `change` to the areas of `pid` in `instance`, starting an empty
/// set for a process that has none yet.
fn update(instance: usize, pid: u32, change: impl FnOnce(&mut Areas)) {
    let mut processes = PROCESSES.lock();
    let index = match processes
        .iter()
        .position(|process| process.instance == instance && process.pid == pid)
    {
        Some(index) => index,
        None => {
            if processes.try_reserve(1).is_err() {
                return;
            }
            processes.push(Process {
                instance,
                pid,
                areas: Areas::new(),
            });
            processes.len() - 1
        }
    };
    change(&mut processes[index].areas);
}

/// Rounds a mapping length up to whole pages.
fn page_end(start: u64, length: u64) -> Option<u64> {
    start
        .checked_add(length)?
        .checked_next_multiple_of(PAGE_SIZE)
}

/// Records that `pid` mapped `area`, over whatever it had there.
pub(crate) fn map(instance: usize, pid: u32, area: Area) {
    update(instance, pid, |areas| {
        let _ = areas.map(area);
    });
}

/// Records that `pid` unmapped `length` bytes at `start`.
pub(crate) fn unmap(instance: usize, pid: u32, start: u64, length: u64) {
    let Some(end) = page_end(start, length) else {
        return;
    };
    update(instance, pid, |areas| {
        let _ = areas.unmap(start, end);
    });
}

/// Records that `pid` gave `length` bytes at `start` `protection`; parts
/// of the range without an area (mapped by the kernel itself) are skipped.
pub(crate) fn protect(instance: usize, pid: u32, start: u64, length: u64, protection: Protection) {
    let Some(end) = page_end(start, length) else {
        return;
    };
    update(instance, pid, |areas| {
        let overlapping = || {
            areas
                .iter()
                .filter(|area| area.start < end && start < area.end)
                .map(|area| (area.start.max(start), area.end.min(end)))
        };
        let mut pieces = Vec::new();
        if pieces.try_reserve_exact(overlapping().count()).is_err() {
            return;
        }
        pieces.extend(overlapping());
        for (piece_start, piece_end) in pieces {
            let _ = areas.protect(piece_start, piece_end, protection);
        }
    });
}

/// Whether part of `length` bytes at `start` of `pid` may not be made
/// writable (a shared mapping of a read-only or write-sealed file).
pub(crate) fn write_forbidden(instance: usize, pid: u32, start: u64, length: u64) -> bool {
    let Some(end) = page_end(start, length) else {
        return false;
    };
    PROCESSES
        .lock()
        .iter()
        .find(|process| process.instance == instance && process.pid == pid)
        .is_some_and(|process| process.areas.write_forbidden(start, end))
}

/// Records that `pid` moved or resized the mapping of `old_length` bytes
/// at `old_start` to `new_length` bytes at `new_start` (mremap).
pub(crate) fn remap(
    instance: usize,
    pid: u32,
    (old_start, old_length): (u64, u64),
    (new_start, new_length): (u64, u64),
) {
    let (Some(old_end), Some(new_end)) = (
        page_end(old_start, old_length),
        page_end(new_start, new_length),
    ) else {
        return;
    };
    update(instance, pid, |areas| {
        let Some(area) = areas.find(old_start).cloned() else {
            return;
        };
        let backing = match area.backing {
            Backing::File {
                device,
                inode,
                offset,
                path,
            } => Backing::File {
                device,
                inode,
                offset: offset + (old_start - area.start),
                path,
            },
            backing => backing,
        };
        let _ = areas.unmap(old_start, old_end);
        let _ = areas.map(Area {
            start: new_start,
            end: new_end,
            protection: area.protection,
            shared: area.shared,
            may_write: area.may_write,
            backing,
        });
    });
}

/// Gives a forked `child` a copy of its parent's areas.
pub(crate) fn fork(instance: usize, parent: u32, child: u32) {
    let copy = {
        let processes = PROCESSES.lock();
        let Some(parent) = processes
            .iter()
            .find(|process| process.instance == instance && process.pid == parent)
        else {
            return;
        };
        match parent.areas.try_clone() {
            Ok(copy) => copy,
            Err(_) => return,
        }
    };
    update(instance, child, |areas| *areas = copy);
}

/// Drops the areas of `pid`, which executed a new program or ended.
pub(crate) fn forget(instance: usize, pid: u32) {
    PROCESSES
        .lock()
        .retain(|process| process.instance != instance || process.pid != pid);
}

/// Drops every process's areas in `instance`, when its domain stops.
pub(crate) fn forget_instance(instance: usize) {
    PROCESSES
        .lock()
        .retain(|process| process.instance != instance);
}

/// A copy of the areas of `pid`, for reporting them.
pub(crate) fn snapshot(instance: usize, pid: u32) -> Option<Areas> {
    PROCESSES
        .lock()
        .iter()
        .find(|process| process.instance == instance && process.pid == pid)?
        .areas
        .try_clone()
        .ok()
}
