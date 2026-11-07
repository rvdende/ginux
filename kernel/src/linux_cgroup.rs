//! Each domain's cgroup v2 hierarchy, as its memory controller sees it.
//!
//! A cgroup is a directory of the domain's `/sys/fs/cgroup` (the overlay
//! keeps the names; cpu.rs serves the control files in it), and the memory
//! state behind it lives in a slot here: the pages charged to it and to
//! everything below it, its limits, its peak and its events. A process's
//! user pages are charged to its cgroup's slot as the frame allocator hands
//! them out (`memory::allocate_user_frames`) and uncharged when the frame
//! is finally freed: each frame remembers the slot it was charged to, as
//! Linux's `page->memcg_data` does.
//!
//! Slots are plain atomics because charges come from page faults on every
//! CPU and uncharges from the allocator's release path. A removed cgroup's
//! slot lives on, retired, until the last page charged to it is freed (a
//! "dying" memory cgroup in Linux's terms), so a frame never names a slot
//! that has been reused. Linux's `mm/memcontrol.c` and
//! `Documentation/admin-guide/cgroup-v2.rst` are the specification; the
//! rules themselves are in the host-tested `ginux-cgroup` crate.

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
use ginux_cgroup::{Controllers, MemoryEvents, MemoryStat, UNLIMITED};

/// Memory cgroups across all domains, each domain's root included.
pub(crate) const SLOT_LIMIT: usize = 1024;
const INSTANCE_LIMIT: usize = crate::control_abi::DOMAIN_LIMIT + 1;

/// A memory cgroup's slot; 0 is none (an uncharged page).
pub(crate) type Slot = u16;
pub(crate) const NO_SLOT: Slot = 0;

const FREE: u8 = 0;
const LIVE: u8 = 1;
/// Its directory is gone; it stays until the pages charged to it are.
const RETIRED: u8 = 2;

/// `memory.events`' counters, in its order.
#[derive(Clone, Copy)]
pub(crate) enum Event {
    Low = 0,
    High = 1,
    Max = 2,
    Oom = 3,
    OomKill = 4,
    OomGroupKill = 5,
}
const EVENT_COUNT: usize = 6;

/// The limits a memory cgroup's files set.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Limit {
    Max,
    High,
    Low,
    Min,
    SwapMax,
    SwapHigh,
}

struct Memcg {
    state: AtomicU8,
    instance: AtomicU8,
    parent: AtomicU16,
    /// The overlay generation of the cgroup's directory (0 for a root).
    directory: AtomicU32,
    subtree_control: AtomicU8,
    /// `memory.oom.group`: an OOM kill takes every process of the cgroup.
    oom_group: AtomicU8,
    /// Pages charged to it and everything below it.
    usage: AtomicU64,
    peak: AtomicU64,
    max: AtomicU64,
    high: AtomicU64,
    low: AtomicU64,
    min: AtomicU64,
    swap_max: AtomicU64,
    swap_high: AtomicU64,
    swap_usage: AtomicU64,
    swap_peak: AtomicU64,
    /// Pages charged to this cgroup itself (not below it).
    local_usage: AtomicU64,
    /// Of `usage`, page cache (a volume's file pages) and shared memory
    /// (tmpfs files, memfds, MAP_SHARED anonymous memory).
    file: AtomicU64,
    shmem: AtomicU64,
    reclaimed: AtomicU64,
    events: [AtomicU64; EVENT_COUNT],
    local_events: [AtomicU64; EVENT_COUNT],
    /// `memory.swap.events`: high, max and fail.
    swap_events: [AtomicU64; 3],
}

impl Memcg {
    const fn empty() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            instance: AtomicU8::new(0),
            parent: AtomicU16::new(NO_SLOT),
            directory: AtomicU32::new(0),
            subtree_control: AtomicU8::new(0),
            oom_group: AtomicU8::new(0),
            usage: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            max: AtomicU64::new(UNLIMITED),
            high: AtomicU64::new(UNLIMITED),
            low: AtomicU64::new(0),
            min: AtomicU64::new(0),
            swap_max: AtomicU64::new(UNLIMITED),
            swap_high: AtomicU64::new(UNLIMITED),
            swap_usage: AtomicU64::new(0),
            swap_peak: AtomicU64::new(0),
            local_usage: AtomicU64::new(0),
            file: AtomicU64::new(0),
            shmem: AtomicU64::new(0),
            reclaimed: AtomicU64::new(0),
            events: [const { AtomicU64::new(0) }; EVENT_COUNT],
            local_events: [const { AtomicU64::new(0) }; EVENT_COUNT],
            swap_events: [const { AtomicU64::new(0) }; 3],
        }
    }

    fn reset(&self) {
        self.parent.store(NO_SLOT, Ordering::Relaxed);
        self.directory.store(0, Ordering::Relaxed);
        self.subtree_control.store(0, Ordering::Relaxed);
        self.oom_group.store(0, Ordering::Relaxed);
        for counter in [
            &self.usage,
            &self.peak,
            &self.low,
            &self.min,
            &self.swap_usage,
            &self.swap_peak,
            &self.local_usage,
            &self.file,
            &self.shmem,
            &self.reclaimed,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        for limit in [&self.max, &self.high, &self.swap_max, &self.swap_high] {
            limit.store(UNLIMITED, Ordering::Relaxed);
        }
        for event in self
            .events
            .iter()
            .chain(&self.local_events)
            .chain(&self.swap_events)
        {
            event.store(0, Ordering::Relaxed);
        }
    }

    fn limit(&self, limit: Limit) -> &AtomicU64 {
        match limit {
            Limit::Max => &self.max,
            Limit::High => &self.high,
            Limit::Low => &self.low,
            Limit::Min => &self.min,
            Limit::SwapMax => &self.swap_max,
            Limit::SwapHigh => &self.swap_high,
        }
    }
}

struct CgroupOwner {
    /// Slot 0 is never used: it is the tag of an uncharged page.
    slots: [Memcg; SLOT_LIMIT],
    /// Each domain instance's root cgroup, made on first use.
    roots: [AtomicU16; INSTANCE_LIMIT],
    /// Whether some process may have pages reclaim could take (lazily
    /// freed or droppable): until then, nothing is scanned for them.
    reclaimable: AtomicBool,
}

static CGROUPS: CgroupOwner = CgroupOwner {
    slots: [const { Memcg::empty() }; SLOT_LIMIT],
    roots: [const { AtomicU16::new(NO_SLOT) }; INSTANCE_LIMIT],
    reclaimable: AtomicBool::new(false),
};

/// Some process now has pages reclaim may take.
pub(crate) fn note_reclaimable() {
    CGROUPS.reclaimable.store(true, Ordering::Release);
}

/// Whether reclaim may find anything to take.
pub(crate) fn reclaimable() -> bool {
    CGROUPS.reclaimable.load(Ordering::Acquire)
}

/// A complete reclaim pass found nothing to take.
pub(crate) fn clear_reclaimable() {
    CGROUPS.reclaimable.store(false, Ordering::Release);
}

fn memcg(slot: Slot) -> Option<&'static Memcg> {
    (slot != NO_SLOT)
        .then(|| CGROUPS.slots.get(usize::from(slot)))
        .flatten()
}

fn live(slot: Slot) -> Option<&'static Memcg> {
    memcg(slot).filter(|memcg| memcg.state.load(Ordering::Acquire) == LIVE)
}

/// Takes a free slot for a cgroup of `instance` below `parent`.
fn allocate(instance: usize, parent: Slot, directory: u32) -> Option<Slot> {
    let instance = u8::try_from(instance).ok()?;
    (1..SLOT_LIMIT).find_map(|index| {
        let memcg = &CGROUPS.slots[index];
        memcg
            .state
            .compare_exchange(FREE, LIVE, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        memcg.reset();
        memcg.instance.store(instance, Ordering::Relaxed);
        memcg.parent.store(parent, Ordering::Relaxed);
        memcg.directory.store(directory, Ordering::Release);
        Slot::try_from(index).ok()
    })
}

/// The root cgroup of domain instance `instance`, made the first time.
pub(crate) fn root(instance: usize) -> Option<Slot> {
    let cell = CGROUPS.roots.get(instance)?;
    let existing = cell.load(Ordering::Acquire);
    if existing != NO_SLOT {
        return Some(existing);
    }
    let slot = allocate(instance, NO_SLOT, 0)?;
    match cell.compare_exchange(NO_SLOT, slot, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(slot),
        Err(winner) => {
            CGROUPS.slots[usize::from(slot)]
                .state
                .store(FREE, Ordering::Release);
            Some(winner)
        }
    }
}

/// A new cgroup of `instance` below `parent`, for the directory of overlay
/// generation `directory`.
pub(crate) fn create(instance: usize, parent: Slot, directory: u32) -> Option<Slot> {
    live(parent)?;
    allocate(instance, parent, directory)
}

/// The live cgroup of `instance` whose directory has generation
/// `directory`; 0 is the root.
pub(crate) fn find(instance: usize, directory: u32) -> Option<Slot> {
    if directory == 0 {
        return root(instance);
    }
    let instance = u8::try_from(instance).ok()?;
    (1..SLOT_LIMIT).find_map(|index| {
        let memcg = &CGROUPS.slots[index];
        (memcg.state.load(Ordering::Acquire) == LIVE
            && memcg.instance.load(Ordering::Relaxed) == instance
            && memcg.directory.load(Ordering::Acquire) == directory)
            .then(|| Slot::try_from(index).ok())
            .flatten()
    })
}

pub(crate) fn is_root(slot: Slot) -> bool {
    live(slot).is_some_and(|memcg| memcg.parent.load(Ordering::Relaxed) == NO_SLOT)
}

pub(crate) fn parent(slot: Slot) -> Option<Slot> {
    let parent = memcg(slot)?.parent.load(Ordering::Relaxed);
    (parent != NO_SLOT).then_some(parent)
}

pub(crate) fn directory(slot: Slot) -> Option<u32> {
    live(slot).map(|memcg| memcg.directory.load(Ordering::Acquire))
}

/// The live cgroups directly below `slot`.
pub(crate) fn children(slot: Slot) -> impl Iterator<Item = Slot> {
    (1..SLOT_LIMIT).filter_map(move |index| {
        let memcg = &CGROUPS.slots[index];
        (memcg.state.load(Ordering::Acquire) == LIVE
            && memcg.parent.load(Ordering::Relaxed) == slot)
            .then(|| Slot::try_from(index).ok())
            .flatten()
    })
}

/// Whether `slot` is `ancestor` or below it.
pub(crate) fn is_within(slot: Slot, ancestor: Slot) -> bool {
    let mut current = Some(slot);
    while let Some(here) = current {
        if here == ancestor {
            return true;
        }
        current = parent(here);
    }
    false
}

/// `cgroup.subtree_control`.
pub(crate) fn subtree_control(slot: Slot) -> Controllers {
    live(slot).map_or(Controllers::NONE, |memcg| {
        Controllers::from_bits(memcg.subtree_control.load(Ordering::Acquire))
    })
}

pub(crate) fn set_subtree_control(slot: Slot, controllers: Controllers) -> bool {
    live(slot).is_some_and(|memcg| {
        memcg
            .subtree_control
            .store(controllers.bits(), Ordering::Release);
        true
    })
}

/// `cgroup.controllers`: what the parent delegates, everything at a root.
pub(crate) fn controllers(slot: Slot) -> Controllers {
    match parent(slot) {
        Some(parent) => subtree_control(parent),
        None if live(slot).is_some() => Controllers::ALL,
        None => Controllers::NONE,
    }
}

/// Whether the memory controller governs `slot` (its parent delegates
/// it); a root's memory is only accounted.
pub(crate) fn memory_controlled(slot: Slot) -> bool {
    !is_root(slot) && controllers(slot).contains(Controllers::MEMORY)
}

/// Ends the cgroup's directory. The slot is freed once nothing is charged
/// to it and no cgroup below it is left.
pub(crate) fn retire(slot: Slot) {
    if let Some(memcg) = live(slot) {
        memcg.state.store(RETIRED, Ordering::Release);
        free_if_unused(slot);
    }
}

fn free_if_unused(slot: Slot) {
    let mut current = Some(slot);
    while let Some(here) = current {
        let Some(memcg) = memcg(here) else {
            return;
        };
        let child_left = (1..SLOT_LIMIT).any(|index| {
            CGROUPS.slots[index].state.load(Ordering::Acquire) != FREE
                && CGROUPS.slots[index].parent.load(Ordering::Relaxed) == here
        });
        if memcg.state.load(Ordering::Acquire) != RETIRED
            || memcg.usage.load(Ordering::Acquire) != 0
            || memcg.swap_usage.load(Ordering::Acquire) != 0
            || child_left
        {
            return;
        }
        let next = parent(here);
        if memcg
            .state
            .compare_exchange(RETIRED, FREE, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        current = next;
    }
}

/// The cgroup and its ancestors, nearest first.
fn lineage(slot: Slot) -> impl Iterator<Item = &'static Memcg> {
    let mut current = memcg(slot).map(|_| slot);
    core::iter::from_fn(move || {
        let here = current?;
        let memcg = memcg(here)?;
        current = parent(here);
        Some(memcg)
    })
}

/// Charges `pages` to `slot` and its ancestors, unless that takes one of
/// them past its `memory.max`: then nothing is charged and the nearest
/// such cgroup is given back, for reclaim or an OOM kill within it.
pub(crate) fn try_charge(slot: Slot, pages: u64) -> Result<(), Slot> {
    let mut current = Some(slot);
    while let Some(here) = current {
        let Some(memcg) = memcg(here) else {
            break;
        };
        if ginux_cgroup::exceeds(
            memcg.usage.load(Ordering::Acquire),
            pages,
            memcg.max.load(Ordering::Acquire),
        ) {
            return Err(here);
        }
        current = parent(here);
    }
    force_charge(slot, pages);
    Ok(())
}

/// Charges `pages` whatever the limits say (an OOM victim is on its way
/// out, or the page is the kernel's to give).
pub(crate) fn force_charge(slot: Slot, pages: u64) {
    if let Some(own) = memcg(slot) {
        own.local_usage.fetch_add(pages, Ordering::AcqRel);
    }
    for memcg in lineage(slot) {
        let usage = memcg.usage.fetch_add(pages, Ordering::AcqRel) + pages;
        memcg.peak.fetch_max(usage, Ordering::AcqRel);
        if usage > memcg.high.load(Ordering::Acquire) {
            memcg.events[Event::High as usize].fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Gives back `pages` charged to `slot`, as their frames are freed.
pub(crate) fn uncharge(slot: Slot, pages: u64) {
    if let Some(own) = memcg(slot) {
        let _ = own
            .local_usage
            .try_update(Ordering::AcqRel, Ordering::Acquire, |usage| {
                Some(usage.saturating_sub(pages))
            });
    }
    for memcg in lineage(slot) {
        let _ = memcg
            .usage
            .try_update(Ordering::AcqRel, Ordering::Acquire, |usage| {
                Some(usage.saturating_sub(pages))
            });
    }
    if memcg(slot).is_some_and(|memcg| memcg.state.load(Ordering::Acquire) == RETIRED) {
        free_if_unused(slot);
    }
}

/// Charges a page of swap to `slot` and its ancestors, unless that takes
/// one of them past its `memory.swap.max` (counted in its
/// `memory.swap.events` max and fail): then nothing is charged. A page
/// charged to no cgroup is charged nothing.
pub(crate) fn try_charge_swap(slot: Slot, pages: u64) -> bool {
    if memcg(slot).is_none() {
        return true;
    }
    for memcg in lineage(slot) {
        if ginux_cgroup::exceeds(
            memcg.swap_usage.load(Ordering::Acquire),
            pages,
            memcg.swap_max.load(Ordering::Acquire),
        ) {
            memcg.swap_events[1].fetch_add(1, Ordering::Relaxed);
            if let Some(own) = self::memcg(slot) {
                own.swap_events[2].fetch_add(1, Ordering::Relaxed);
            }
            return false;
        }
    }
    for memcg in lineage(slot) {
        let usage = memcg.swap_usage.fetch_add(pages, Ordering::AcqRel) + pages;
        memcg.swap_peak.fetch_max(usage, Ordering::AcqRel);
        if usage > memcg.swap_high.load(Ordering::Acquire) {
            memcg.swap_events[0].fetch_add(1, Ordering::Relaxed);
        }
    }
    true
}

/// Gives back `pages` of swap charged to `slot`, as their slots are freed.
pub(crate) fn uncharge_swap(slot: Slot, pages: u64) {
    for memcg in lineage(slot) {
        let _ = memcg
            .swap_usage
            .try_update(Ordering::AcqRel, Ordering::Acquire, |usage| {
                Some(usage.saturating_sub(pages))
            });
    }
    if memcg(slot).is_some_and(|memcg| memcg.state.load(Ordering::Acquire) == RETIRED) {
        free_if_unused(slot);
    }
}

/// `memory.swap.events`: high, max and fail.
pub(crate) fn swap_events(slot: Slot) -> [u64; 3] {
    memcg(slot).map_or([0; 3], |memcg| {
        [0, 1, 2].map(|index| memcg.swap_events[index].load(Ordering::Relaxed))
    })
}

/// What a charged page holds, for memory.stat.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PageKind {
    Anon,
    /// Page cache: a volume's file page.
    File,
    /// Shared memory: tmpfs, memfd and MAP_SHARED anonymous pages.
    Shmem,
}

/// Charges a page of `kind` to `slot` and its ancestors whatever the limits
/// say (the page cache and shared memory are filled where reclaim cannot
/// run; the next charge past memory.max reclaims them).
pub(crate) fn charge_kind(slot: Slot, kind: PageKind) {
    force_charge(slot, 1);
    for memcg in lineage(slot) {
        match kind {
            PageKind::Anon => {}
            PageKind::File => {
                memcg.file.fetch_add(1, Ordering::AcqRel);
            }
            PageKind::Shmem => {
                memcg.shmem.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

/// Gives back a page of `kind` charged to `slot`, as its frame is freed.
pub(crate) fn uncharge_kind(slot: Slot, kind: PageKind) {
    for memcg in lineage(slot) {
        let counter = match kind {
            PageKind::Anon => continue,
            PageKind::File => &memcg.file,
            PageKind::Shmem => &memcg.shmem,
        };
        let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |pages| {
            Some(pages.saturating_sub(1))
        });
    }
    uncharge(slot, 1);
}

/// Records an event of `slot` in its `memory.events.local` and in the
/// hierarchical `memory.events` of it and its ancestors.
pub(crate) fn note_event(slot: Slot, event: Event) {
    if let Some(own) = memcg(slot) {
        own.local_events[event as usize].fetch_add(1, Ordering::Relaxed);
    }
    for memcg in lineage(slot) {
        memcg.events[event as usize].fetch_add(1, Ordering::Relaxed);
    }
}

/// Records `pages` reclaimed from `slot`'s pages.
pub(crate) fn note_reclaimed(slot: Slot, pages: u64) {
    for memcg in lineage(slot) {
        memcg.reclaimed.fetch_add(pages, Ordering::Relaxed);
    }
}

pub(crate) fn usage(slot: Slot) -> u64 {
    memcg(slot).map_or(0, |memcg| memcg.usage.load(Ordering::Acquire))
}

pub(crate) fn limit(slot: Slot, limit: Limit) -> u64 {
    memcg(slot).map_or(UNLIMITED, |memcg| {
        memcg.limit(limit).load(Ordering::Acquire)
    })
}

pub(crate) fn set_limit(slot: Slot, limit: Limit, pages: u64) -> bool {
    live(slot).is_some_and(|memcg| {
        memcg.limit(limit).store(pages, Ordering::Release);
        true
    })
}

/// `memory.peak` and `memory.swap.peak` written: the peak starts again from
/// what is charged now.
pub(crate) fn reset_peak(slot: Slot, swap: bool) {
    if let Some(memcg) = live(slot) {
        if swap {
            memcg
                .swap_peak
                .store(memcg.swap_usage.load(Ordering::Acquire), Ordering::Release);
        } else {
            memcg
                .peak
                .store(memcg.usage.load(Ordering::Acquire), Ordering::Release);
        }
    }
}

pub(crate) fn oom_group(slot: Slot) -> bool {
    live(slot).is_some_and(|memcg| memcg.oom_group.load(Ordering::Acquire) != 0)
}

pub(crate) fn set_oom_group(slot: Slot, enabled: bool) -> bool {
    live(slot).is_some_and(|memcg| {
        memcg.oom_group.store(u8::from(enabled), Ordering::Release);
        true
    })
}

pub(crate) fn peak(slot: Slot, swap: bool) -> u64 {
    memcg(slot).map_or(0, |memcg| {
        if swap {
            memcg.swap_peak.load(Ordering::Acquire)
        } else {
            memcg.peak.load(Ordering::Acquire)
        }
    })
}

pub(crate) fn swap_usage(slot: Slot) -> u64 {
    memcg(slot).map_or(0, |memcg| memcg.swap_usage.load(Ordering::Acquire))
}

pub(crate) fn events(slot: Slot, local: bool) -> MemoryEvents {
    let Some(memcg) = memcg(slot) else {
        return MemoryEvents::default();
    };
    let counters = if local {
        &memcg.local_events
    } else {
        &memcg.events
    };
    let count = |event: Event| counters[event as usize].load(Ordering::Relaxed);
    MemoryEvents {
        low: count(Event::Low),
        high: count(Event::High),
        max: count(Event::Max),
        oom: count(Event::Oom),
        oom_kill: count(Event::OomKill),
        oom_group_kill: count(Event::OomGroupKill),
    }
}

/// `memory.stat`: anonymous memory, page cache and shared memory.
pub(crate) fn stat(slot: Slot) -> MemoryStat {
    let Some(memcg) = memcg(slot) else {
        return MemoryStat::default();
    };
    let file = memcg.file.load(Ordering::Acquire);
    let shmem = memcg.shmem.load(Ordering::Acquire);
    MemoryStat {
        anon: memcg
            .usage
            .load(Ordering::Acquire)
            .saturating_sub(file + shmem),
        file,
        shmem,
        swapped: memcg.swap_usage.load(Ordering::Acquire),
        reclaimed: memcg.reclaimed.load(Ordering::Relaxed),
        ..MemoryStat::default()
    }
}
