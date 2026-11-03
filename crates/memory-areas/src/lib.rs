#![forbid(unsafe_code)]
//! A process's memory areas: the ranges of its address space it has mapped,
//! each with one protection, sharing and backing, as Linux keeps them in
//! its `vm_area_struct`s.
//!
//! The set stays sorted and non-overlapping. Mapping over existing areas
//! replaces what it covers (as `MAP_FIXED` does), unmapping or changing the
//! protection of part of an area splits it, and neighbours that would read
//! the same in `/proc/PID/maps` merge, so a process sees the areas Linux
//! would show it. Every growth is fallible: the kernel reports an
//! allocation failure instead of panicking.
//!
//! This is pure bookkeeping, so it can be tested on the host; the kernel
//! keeps one set per process and the page tables stay the authority on
//! which pages are present.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub const PAGE_SIZE: u64 = 4096;

/// What an area allows: mmap's `PROT_READ`, `PROT_WRITE` and `PROT_EXEC`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Protection(u8);

impl Protection {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const EXECUTE: Self = Self(4);

    /// The protection given by mmap's `PROT_*` bits (others ignored).
    pub const fn from_bits(bits: u64) -> Self {
        Self((bits & 7) as u8)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn readable(self) -> bool {
        self.0 & 1 != 0
    }

    pub const fn writable(self) -> bool {
        self.0 & 2 != 0
    }

    pub const fn executable(self) -> bool {
        self.0 & 4 != 0
    }
}

/// What an area maps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Backing {
    /// Zero-filled memory.
    Anonymous,
    /// The program break's heap.
    Heap,
    /// The main thread's stack.
    Stack,
    /// Part of a file: its identity, the file offset of the area's start,
    /// and the path `/proc/PID/maps` names it by.
    File {
        device: u64,
        inode: u64,
        offset: u64,
        path: Arc<[u8]>,
    },
}

impl Backing {
    /// The backing of the part of an area that starts `distance` bytes in.
    fn advanced(&self, distance: u64) -> Self {
        match self {
            Self::File {
                device,
                inode,
                offset,
                path,
            } => Self::File {
                device: *device,
                inode: *inode,
                offset: offset + distance,
                path: Arc::clone(path),
            },
            other => other.clone(),
        }
    }

    /// Whether an area with this backing ending where one with `next`
    /// begins forms one contiguous mapping.
    fn continues_into(&self, length: u64, next: &Self) -> bool {
        match (self, next) {
            (
                Self::File {
                    device,
                    inode,
                    offset,
                    ..
                },
                Self::File {
                    device: next_device,
                    inode: next_inode,
                    offset: next_offset,
                    ..
                },
            ) => device == next_device && inode == next_inode && offset + length == *next_offset,
            (Self::File { .. }, _) | (_, Self::File { .. }) => false,
            (backing, next) => backing == next,
        }
    }
}

/// One mapped range: `[start, end)`, page-aligned and not empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Area {
    pub start: u64,
    pub end: u64,
    pub protection: Protection,
    /// `MAP_SHARED`: writes reach the backing and other mappings of it.
    pub shared: bool,
    /// The mapping may be made writable (Linux's VM_MAYWRITE): false for
    /// a shared mapping of a file opened without write access or sealed
    /// against writes, which mprotect may not give PROT_WRITE.
    pub may_write: bool,
    /// Locked in memory (Linux's VM_LOCKED): mlock, mlockall or MAP_LOCKED.
    pub locked: bool,
    pub backing: Backing,
}

impl Area {
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn contains(&self, address: u64) -> bool {
        (self.start..self.end).contains(&address)
    }

    /// The part of this area within `[start, end)`, which must overlap it.
    fn clipped(&self, start: u64, end: u64) -> Self {
        let start = start.max(self.start);
        Self {
            start,
            end: end.min(self.end),
            protection: self.protection,
            shared: self.shared,
            may_write: self.may_write,
            locked: self.locked,
            backing: self.backing.advanced(start - self.start),
        }
    }

    /// Whether `next`, starting where this ends, can be the same area.
    fn merges_with(&self, next: &Self) -> bool {
        self.end == next.start
            && self.protection == next.protection
            && self.shared == next.shared
            && self.may_write == next.may_write
            && self.locked == next.locked
            && self.backing.continues_into(self.len(), &next.backing)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A range is empty, unaligned or past the address space.
    Invalid,
    /// Part of the range is not mapped (Linux's ENOMEM for mprotect).
    Unmapped,
    /// The set could not grow.
    NoMemory,
}

/// A process's areas, sorted by address and never overlapping. A deque, so
/// a process mapping or unmapping areas in address order, at either end of
/// tens of thousands (munmap04 fills vm.max_map_count), moves none of the
/// others.
#[derive(Clone, Debug, Default)]
pub struct Areas {
    areas: VecDeque<Area>,
    /// mlockall(MCL_FUTURE): areas mapped from now on are locked.
    lock_future: bool,
}

fn valid_range(start: u64, end: u64) -> Result<(), Error> {
    if start < end && start.is_multiple_of(PAGE_SIZE) && end.is_multiple_of(PAGE_SIZE) {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

impl Areas {
    pub const fn new() -> Self {
        Self {
            areas: VecDeque::new(),
            lock_future: false,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Area> {
        self.areas.iter()
    }

    pub fn len(&self) -> usize {
        self.areas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.areas.is_empty()
    }

    /// The area holding `address`.
    pub fn find(&self, address: u64) -> Option<&Area> {
        let index = self.areas.partition_point(|area| area.end <= address);
        self.areas.get(index).filter(|area| area.contains(address))
    }

    /// Whether every page of `[start, end)` is in some area.
    pub fn covers(&self, start: u64, end: u64) -> bool {
        let mut next = start;
        for area in self.overlapping(start, end) {
            if area.start > next {
                return false;
            }
            next = area.end;
        }
        next >= end
    }

    /// A copy of this set, as a forked child gets.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let mut areas = VecDeque::new();
        areas
            .try_reserve_exact(self.areas.len())
            .map_err(|_| Error::NoMemory)?;
        areas.extend(self.areas.iter().cloned());
        Ok(Self {
            areas,
            lock_future: self.lock_future,
        })
    }

    /// The copy a forked child gets: the same areas, none of them locked,
    /// as memory locks are not inherited across fork.
    pub fn forked(&self) -> Result<Self, Error> {
        let mut copy = Self {
            lock_future: false,
            ..self.try_clone()?
        };
        copy.lock_all(false);
        Ok(copy)
    }

    /// Maps `area`, replacing whatever it overlaps.
    pub fn map(&mut self, mut area: Area) -> Result<(), Error> {
        valid_range(area.start, area.end)?;
        area.locked |= self.lock_future;
        // Unmapping can split one area in two, and the new area is one more.
        self.areas.try_reserve(2).map_err(|_| Error::NoMemory)?;
        self.remove_range(area.start, area.end);
        let index = self
            .areas
            .partition_point(|existing| existing.start < area.start);
        self.areas.insert(index, area);
        self.merge_around(index);
        Ok(())
    }

    /// Unmaps `[start, end)`; parts of it that are not mapped are fine.
    pub fn unmap(&mut self, start: u64, end: u64) -> Result<(), Error> {
        valid_range(start, end)?;
        self.areas.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.remove_range(start, end);
        Ok(())
    }

    /// Gives `[start, end)` `protection`, which must be wholly mapped.
    pub fn protect(&mut self, start: u64, end: u64, protection: Protection) -> Result<(), Error> {
        self.change(start, end, |area| area.protection = protection)
    }

    /// Locks or unlocks `[start, end)`, which must be wholly mapped.
    pub fn lock(&mut self, start: u64, end: u64, locked: bool) -> Result<(), Error> {
        self.change(start, end, |area| area.locked = locked)
    }

    /// Locks or unlocks every area (mlockall's MCL_CURRENT, munlockall).
    pub fn lock_all(&mut self, locked: bool) {
        for area in &mut self.areas {
            area.locked = locked;
        }
        for index in (0..self.areas.len()).rev() {
            if index < self.areas.len() {
                self.merge_around(index);
            }
        }
    }

    /// Sets whether areas mapped from now on are locked (MCL_FUTURE).
    pub fn set_lock_future(&mut self, locked: bool) {
        self.lock_future = locked;
    }

    /// The bytes of locked areas (VmLck).
    pub fn locked_bytes(&self) -> u64 {
        self.areas
            .iter()
            .filter(|area| area.locked)
            .map(Area::len)
            .sum()
    }

    /// Whether some area overlaps `[start, end)`.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.overlapping(start, end).next().is_some()
    }

    /// Whether unmapping `[start, end)` would split an area in two (an
    /// area starts before it and ends after it).
    pub fn splits(&self, start: u64, end: u64) -> bool {
        self.find(start)
            .is_some_and(|area| area.start < start && end < area.end)
    }

    /// Whether some area overlapping `[start, end)` is locked.
    pub fn locked_in(&self, start: u64, end: u64) -> bool {
        self.overlapping(start, end).any(|area| area.locked)
    }

    /// Applies `apply` to the parts of areas within `[start, end)`, which
    /// must be wholly mapped, splitting and merging areas around them.
    fn change(&mut self, start: u64, end: u64, apply: impl Fn(&mut Area)) -> Result<(), Error> {
        valid_range(start, end)?;
        if !self.covers(start, end) {
            return Err(Error::Unmapped);
        }
        let changed: Vec<Area> = {
            let mut changed = Vec::new();
            let count = self.overlapping(start, end).count();
            changed
                .try_reserve_exact(count)
                .map_err(|_| Error::NoMemory)?;
            changed.extend(self.overlapping(start, end).map(|area| {
                let mut part = area.clipped(start, end);
                apply(&mut part);
                part
            }));
            changed
        };
        self.areas
            .try_reserve(changed.len() + 2)
            .map_err(|_| Error::NoMemory)?;
        self.remove_range(start, end);
        let index = self
            .areas
            .partition_point(|existing| existing.start < start);
        let count = changed.len();
        for (offset, area) in changed.into_iter().enumerate() {
            self.areas.insert(index + offset, area);
        }
        // Merge from the last changed area back, so indexes stay valid.
        for offset in (0..count).rev() {
            self.merge_around(index + offset);
        }
        Ok(())
    }

    /// Whether some area in `[start, end)` may not be made writable.
    pub fn write_forbidden(&self, start: u64, end: u64) -> bool {
        self.overlapping(start, end).any(|area| !area.may_write)
    }

    /// Moves the area at `[old_start, old_start + length)` to `new_start`,
    /// as mremap does when it moves a mapping; the old range must be one
    /// area's part.
    pub fn relocate(&mut self, old_start: u64, length: u64, new_start: u64) -> Result<(), Error> {
        let old_end = old_start.checked_add(length).ok_or(Error::Invalid)?;
        let new_end = new_start.checked_add(length).ok_or(Error::Invalid)?;
        valid_range(old_start, old_end)?;
        valid_range(new_start, new_end)?;
        let area = self
            .find(old_start)
            .filter(|area| area.end >= old_end)
            .ok_or(Error::Unmapped)?
            .clipped(old_start, old_end);
        self.unmap(old_start, old_end)?;
        self.map(Area {
            start: new_start,
            end: new_end,
            ..area
        })
    }

    /// Removes `[start, end)` from every area it overlaps, splitting an
    /// area it falls inside. Capacity for one more area must be reserved.
    fn remove_range(&mut self, start: u64, end: u64) {
        let first = self.areas.partition_point(|area| area.end <= start);
        let mut index = first;
        while index < self.areas.len() && self.areas[index].start < end {
            let area = &self.areas[index];
            let before = (area.start < start).then(|| area.clipped(area.start, start));
            let after = (area.end > end).then(|| area.clipped(end, area.end));
            match (before, after) {
                (Some(before), Some(after)) => {
                    self.areas[index] = before;
                    self.areas.insert(index + 1, after);
                    return;
                }
                (Some(before), None) => {
                    self.areas[index] = before;
                    index += 1;
                }
                (None, Some(after)) => {
                    self.areas[index] = after;
                    return;
                }
                (None, None) => {
                    let _ = self.areas.remove(index);
                }
            }
        }
    }

    /// Joins the area at `index` with neighbours it continues.
    fn merge_around(&mut self, index: usize) {
        if index + 1 < self.areas.len() && self.areas[index].merges_with(&self.areas[index + 1]) {
            if let Some(next) = self.areas.remove(index + 1) {
                self.areas[index].end = next.end;
            }
        }
        if index > 0 && self.areas[index - 1].merges_with(&self.areas[index]) {
            if let Some(area) = self.areas.remove(index) {
                self.areas[index - 1].end = area.end;
            }
        }
    }

    fn overlapping(&self, start: u64, end: u64) -> impl Iterator<Item = &Area> {
        let first = self.areas.partition_point(|area| area.end <= start);
        self.areas
            .range(first..)
            .take_while(move |area| area.start < end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    const RW: Protection = Protection(3);
    const R: Protection = Protection::READ;

    fn anonymous(start: u64, end: u64, protection: Protection) -> Area {
        Area {
            start: start * PAGE_SIZE,
            end: end * PAGE_SIZE,
            protection,
            shared: false,
            may_write: true,
            locked: false,
            backing: Backing::Anonymous,
        }
    }

    fn file(start: u64, end: u64, offset: u64) -> Area {
        Area {
            start: start * PAGE_SIZE,
            end: end * PAGE_SIZE,
            protection: R,
            shared: false,
            may_write: true,
            locked: false,
            backing: Backing::File {
                device: 1,
                inode: 7,
                offset: offset * PAGE_SIZE,
                path: Arc::from(&b"/lib/libc.so"[..]),
            },
        }
    }

    fn ranges(areas: &Areas) -> vec::Vec<(u64, u64, u8)> {
        areas
            .iter()
            .map(|area| {
                (
                    area.start / PAGE_SIZE,
                    area.end / PAGE_SIZE,
                    area.protection.bits(),
                )
            })
            .collect()
    }

    #[test]
    fn neighbours_with_the_same_flags_merge() {
        let mut areas = Areas::new();
        areas.map(anonymous(10, 12, RW)).unwrap();
        areas.map(anonymous(12, 15, RW)).unwrap();
        areas.map(anonymous(8, 10, RW)).unwrap();
        assert_eq!(ranges(&areas), [(8, 15, 3)]);
        areas.map(anonymous(15, 16, R)).unwrap();
        assert_eq!(ranges(&areas), [(8, 15, 3), (15, 16, 1)]);
    }

    #[test]
    fn mapping_over_areas_replaces_what_it_covers() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 10, RW)).unwrap();
        areas.map(anonymous(3, 5, R)).unwrap();
        assert_eq!(ranges(&areas), [(0, 3, 3), (3, 5, 1), (5, 10, 3)]);
        areas.map(anonymous(2, 8, RW)).unwrap();
        assert_eq!(ranges(&areas), [(0, 10, 3)]);
    }

    #[test]
    fn unmapping_splits_and_trims() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 10, RW)).unwrap();
        areas.map(anonymous(20, 30, R)).unwrap();
        areas.unmap(4 * PAGE_SIZE, 6 * PAGE_SIZE).unwrap();
        assert_eq!(ranges(&areas), [(0, 4, 3), (6, 10, 3), (20, 30, 1)]);
        areas.unmap(8 * PAGE_SIZE, 25 * PAGE_SIZE).unwrap();
        assert_eq!(ranges(&areas), [(0, 4, 3), (6, 8, 3), (25, 30, 1)]);
        areas.unmap(100 * PAGE_SIZE, 101 * PAGE_SIZE).unwrap();
        assert_eq!(areas.len(), 3);
    }

    #[test]
    fn overlaps_and_splits() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 10, RW)).unwrap();
        areas.map(anonymous(20, 30, R)).unwrap();
        assert!(areas.overlaps(9 * PAGE_SIZE, 11 * PAGE_SIZE));
        assert!(!areas.overlaps(10 * PAGE_SIZE, 20 * PAGE_SIZE));
        assert!(areas.splits(PAGE_SIZE, 2 * PAGE_SIZE));
        assert!(!areas.splits(0, 2 * PAGE_SIZE));
        assert!(!areas.splits(8 * PAGE_SIZE, 10 * PAGE_SIZE));
        assert!(!areas.splits(12 * PAGE_SIZE, 13 * PAGE_SIZE));
    }

    #[test]
    fn unmapping_in_order_from_either_end() {
        let mut areas = Areas::new();
        for index in 0..100 {
            areas.map(anonymous(index * 3, index * 3 + 1, RW)).unwrap();
        }
        assert_eq!(areas.len(), 100);
        for index in 0..50 {
            areas
                .unmap(index * 3 * PAGE_SIZE, (index * 3 + 1) * PAGE_SIZE)
                .unwrap();
        }
        for index in (50..100).rev() {
            areas
                .unmap(index * 3 * PAGE_SIZE, (index * 3 + 1) * PAGE_SIZE)
                .unwrap();
        }
        assert!(areas.is_empty());
    }

    #[test]
    fn protecting_part_of_an_area_splits_it_and_merges_back() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 10, RW)).unwrap();
        areas.protect(2 * PAGE_SIZE, 4 * PAGE_SIZE, R).unwrap();
        assert_eq!(ranges(&areas), [(0, 2, 3), (2, 4, 1), (4, 10, 3)]);
        areas.protect(2 * PAGE_SIZE, 4 * PAGE_SIZE, RW).unwrap();
        assert_eq!(ranges(&areas), [(0, 10, 3)]);
    }

    #[test]
    fn protecting_a_hole_is_an_error_and_changes_nothing() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 2, RW)).unwrap();
        areas.map(anonymous(3, 5, RW)).unwrap();
        assert_eq!(areas.protect(0, 5 * PAGE_SIZE, R), Err(Error::Unmapped));
        assert_eq!(ranges(&areas), [(0, 2, 3), (3, 5, 3)]);
    }

    #[test]
    fn file_areas_keep_their_offsets_when_split() {
        let mut areas = Areas::new();
        areas.map(file(10, 20, 4)).unwrap();
        areas.unmap(12 * PAGE_SIZE, 13 * PAGE_SIZE).unwrap();
        let offsets: vec::Vec<u64> = areas
            .iter()
            .map(|area| match &area.backing {
                Backing::File { offset, .. } => offset / PAGE_SIZE,
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(offsets, [4, 7]);
        // Mapping the hole back with the matching offset joins the file.
        areas.map(file(12, 13, 6)).unwrap();
        assert_eq!(ranges(&areas), [(10, 20, 1)]);
    }

    #[test]
    fn file_areas_with_unrelated_offsets_stay_apart() {
        let mut areas = Areas::new();
        areas.map(file(0, 2, 0)).unwrap();
        areas.map(file(2, 4, 9)).unwrap();
        assert_eq!(areas.len(), 2);
    }

    #[test]
    fn lookups_find_the_holding_area() {
        let mut areas = Areas::new();
        areas.map(anonymous(4, 8, RW)).unwrap();
        areas.map(anonymous(10, 12, R)).unwrap();
        assert_eq!(
            areas.find(5 * PAGE_SIZE).map(|area| area.start),
            Some(4 * PAGE_SIZE)
        );
        assert!(areas.find(8 * PAGE_SIZE).is_none());
        assert!(areas.covers(4 * PAGE_SIZE, 8 * PAGE_SIZE));
        assert!(!areas.covers(4 * PAGE_SIZE, 11 * PAGE_SIZE));
    }

    #[test]
    fn relocating_moves_part_of_an_area() {
        let mut areas = Areas::new();
        areas.map(file(0, 4, 0)).unwrap();
        areas
            .relocate(2 * PAGE_SIZE, 2 * PAGE_SIZE, 100 * PAGE_SIZE)
            .unwrap();
        assert_eq!(ranges(&areas), [(0, 2, 1), (100, 102, 1)]);
        match &areas.find(100 * PAGE_SIZE).unwrap().backing {
            Backing::File { offset, .. } => assert_eq!(*offset, 2 * PAGE_SIZE),
            _ => unreachable!(),
        }
    }

    #[test]
    fn invalid_ranges_are_refused() {
        let mut areas = Areas::new();
        assert_eq!(areas.map(anonymous(3, 3, RW)), Err(Error::Invalid));
        assert_eq!(areas.unmap(1, PAGE_SIZE), Err(Error::Invalid));
    }

    #[test]
    fn a_clone_is_independent() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 4, RW)).unwrap();
        let mut child = areas.try_clone().unwrap();
        child.unmap(0, PAGE_SIZE).unwrap();
        assert_eq!(ranges(&areas), [(0, 4, 3)]);
        assert_eq!(ranges(&child), [(1, 4, 3)]);
    }

    #[test]
    fn locking_splits_and_merges_and_is_not_inherited() {
        let mut areas = Areas::new();
        areas.map(anonymous(0, 8, RW)).unwrap();
        areas.lock(2 * PAGE_SIZE, 5 * PAGE_SIZE, true).unwrap();
        assert_eq!(areas.len(), 3);
        assert_eq!(areas.locked_bytes(), 3 * PAGE_SIZE);
        assert!(areas.locked_in(4 * PAGE_SIZE, 6 * PAGE_SIZE));
        assert!(!areas.locked_in(5 * PAGE_SIZE, 8 * PAGE_SIZE));
        assert_eq!(
            areas.lock(7 * PAGE_SIZE, 9 * PAGE_SIZE, true),
            Err(Error::Unmapped)
        );
        let child = areas.forked().unwrap();
        assert_eq!(child.locked_bytes(), 0);
        assert_eq!(child.len(), 1);
        areas.lock_all(false);
        assert_eq!(areas.len(), 1);
        areas.set_lock_future(true);
        areas.map(anonymous(10, 12, RW)).unwrap();
        assert_eq!(areas.locked_bytes(), 2 * PAGE_SIZE);
    }
}
