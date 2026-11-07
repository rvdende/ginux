use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use alloc::vec::Vec;

use crate::{control_abi, linux_process, memory};

pub(crate) const THREAD_LIMIT: usize = 16;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
const THREAD_QUEUE_LIMIT: usize = linux_process::PROCESS_LIMIT * THREAD_LIMIT;
const PAGE_SIZE: usize = 4096;
const ENTRY_ALIGNMENT: usize = core::mem::align_of::<Entry>();
const ENTRIES_OFFSET: usize =
    (core::mem::size_of::<PageHeader>() + ENTRY_ALIGNMENT - 1) & !(ENTRY_ALIGNMENT - 1);
const HEADER_PADDING: usize = ENTRIES_OFFSET - core::mem::size_of::<PageHeader>();
const ENTRIES_PER_PAGE: usize = (PAGE_SIZE - ENTRIES_OFFSET) / core::mem::size_of::<Entry>();
const PAGE_PADDING: usize =
    PAGE_SIZE - ENTRIES_OFFSET - ENTRIES_PER_PAGE * core::mem::size_of::<Entry>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    Process,
    Thread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    NoMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pending {
    pub(crate) signal: u8,
    pub(crate) code: i32,
    pub(crate) value: u64,
    pub(crate) sender_pid: u32,
    pub(crate) sender_uid: u32,
}

#[derive(Clone, Copy)]
struct Queue {
    head: memory::FrameLease,
    pages: u64,
    pending: u64,
    next_sequence: u64,
}

impl Queue {
    const EMPTY: Self = Self {
        head: memory::FrameLease::EMPTY,
        pages: 0,
        pending: 0,
        // Sequence numbers only order entries among themselves; starting at
        // 0 keeps the queue tables all-zero, out of the image's data.
        next_sequence: 0,
    };
}

#[repr(C)]
struct PageHeader {
    next: memory::FrameLease,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Entry {
    sequence: u64,
    value: u64,
    code: i32,
    sender_pid: u32,
    sender_uid: u32,
    signal: u8,
    occupied: u8,
    reserved: [u8; 2],
}

impl Entry {
    const EMPTY: Self = Self {
        sequence: 0,
        value: 0,
        code: 0,
        sender_pid: 0,
        sender_uid: 0,
        signal: 0,
        occupied: 0,
        reserved: [0; 2],
    };
}

#[repr(C)]
struct Page {
    header: PageHeader,
    header_padding: [u8; HEADER_PADDING],
    entries: [Entry; ENTRIES_PER_PAGE],
    padding: [u8; PAGE_PADDING],
}

const _: [(); PAGE_SIZE] = [(); core::mem::size_of::<Page>()];

struct SignalRuntimeOwner {
    locks: [AtomicBool; INSTANCE_LIMIT],
    pending_counts: [AtomicU64; INSTANCE_LIMIT],
    /// Each instance's process queues and thread queues, by slot: as long
    /// as the highest slot used so far, grown as slots are first used.
    queues: UnsafeCell<[[Vec<Queue>; 2]; INSTANCE_LIMIT]>,
}

unsafe impl Sync for SignalRuntimeOwner {}

static SIGNAL_RUNTIME: SignalRuntimeOwner = SignalRuntimeOwner {
    locks: [const { AtomicBool::new(false) }; INSTANCE_LIMIT],
    pending_counts: [const { AtomicU64::new(0) }; INSTANCE_LIMIT],
    queues: UnsafeCell::new([const { [Vec::new(), Vec::new()] }; INSTANCE_LIMIT]),
};

struct Guard {
    instance: usize,
}

impl Guard {
    fn acquire(instance: usize) -> Result<Self, Error> {
        let lock = SIGNAL_RUNTIME.locks.get(instance).ok_or(Error::Invalid)?;
        while lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Ok(Self { instance })
    }

    /// The queue of `slot`, the table grown to it first; None past the
    /// limit or without memory. The caller holds no other queue of this
    /// guard's while it uses the one returned, which a growth would move.
    fn queue(&self, scope: Scope, slot: usize) -> Option<&'static mut Queue> {
        let (index, limit) = match scope {
            Scope::Process => (0, linux_process::PROCESS_LIMIT),
            Scope::Thread => (1, THREAD_QUEUE_LIMIT),
        };
        if slot >= limit {
            return None;
        }
        // SAFETY: the guard holds the instance's lock, which serializes
        // every access to its tables.
        let queues = unsafe { &mut (*SIGNAL_RUNTIME.queues.get())[self.instance][index] };
        if queues.len() <= slot {
            queues.try_reserve(slot + 1 - queues.len()).ok()?;
            queues.resize(slot + 1, Queue::EMPTY);
        }
        queues.get_mut(slot)
    }

    /// The queue of `slot` if the table reaches it, without growing it: a
    /// slot past the end has an empty queue. Err past the limit. Readers
    /// and clears use this, so they neither grow the table nor (through a
    /// clear's trim) shrink it back on every call: a fork clearing its
    /// child's 17 queues did both, half a megabyte each time, at slot 1000.
    fn existing(&self, scope: Scope, slot: usize) -> Result<Option<&'static mut Queue>, Error> {
        let (index, limit) = match scope {
            Scope::Process => (0, linux_process::PROCESS_LIMIT),
            Scope::Thread => (1, THREAD_QUEUE_LIMIT),
        };
        if slot >= limit {
            return Err(Error::Invalid);
        }
        // SAFETY: as in `queue`.
        let queues = unsafe { &mut (*SIGNAL_RUNTIME.queues.get())[self.instance][index] };
        Ok(queues.get_mut(slot))
    }

    /// Gives back the empty queues at the end of a table.
    fn trim(&self, scope: Scope) {
        let index = usize::from(scope == Scope::Thread);
        // SAFETY: as in `queue`; no queue of the guard is in use.
        let queues = unsafe { &mut (*SIGNAL_RUNTIME.queues.get())[self.instance][index] };
        while queues
            .last()
            .is_some_and(|queue| queue.pages == 0 && queue.pending == 0)
        {
            queues.pop();
        }
        if queues.capacity() > queues.len().saturating_mul(2).max(64) {
            queues.shrink_to_fit();
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        SIGNAL_RUNTIME.locks[self.instance].store(false, Ordering::Release);
    }
}

fn page(frame: memory::FrameLease) -> Option<&'static Page> {
    Some(unsafe { &*(frame.direct_map_address()? as *const Page) })
}

fn page_mut(frame: memory::FrameLease) -> Option<&'static mut Page> {
    Some(unsafe { &mut *(frame.direct_map_address()? as *mut Page) })
}

fn allocate_page(next: memory::FrameLease) -> Result<memory::FrameLease, Error> {
    let [frame] =
        memory::allocate_frames::<1>(memory::FrameOwner::KERNEL).ok_or(Error::NoMemory)?;
    let Some(address) = frame.direct_map_address() else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return Err(Error::NoMemory);
    };
    unsafe {
        core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE);
        core::ptr::write(
            address as *mut Page,
            Page {
                header: PageHeader { next },
                header_padding: [0; HEADER_PADDING],
                entries: [Entry::EMPTY; ENTRIES_PER_PAGE],
                padding: [0; PAGE_PADDING],
            },
        );
    }
    Ok(frame)
}

fn walk(queue: &Queue, mut visit: impl FnMut(memory::FrameLease, &Page) -> bool) -> bool {
    let mut current = queue.head;
    for _ in 0..queue.pages {
        let Some(item) = page(current) else {
            return false;
        };
        if !visit(current, item) {
            return true;
        }
        current = item.header.next;
    }
    current == memory::FrameLease::EMPTY
}

fn release_empty_pages(queue: &mut Queue) -> bool {
    let mut current = queue.head;
    let mut previous = memory::FrameLease::EMPTY;
    let original_pages = queue.pages;
    for _ in 0..original_pages {
        let Some(item) = page(current) else {
            return false;
        };
        let next = item.header.next;
        if item.entries.iter().all(|entry| entry.occupied == 0) {
            if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[current]) {
                return false;
            }
            if previous == memory::FrameLease::EMPTY {
                queue.head = next;
            } else {
                let Some(previous_page) = page_mut(previous) else {
                    return false;
                };
                previous_page.header.next = next;
            }
            queue.pages -= 1;
        } else {
            previous = current;
        }
        current = next;
    }
    current == memory::FrameLease::EMPTY
}

pub(crate) fn enqueue(
    instance: usize,
    scope: Scope,
    slot: usize,
    pending: Pending,
    realtime: bool,
) -> Result<bool, Error> {
    if !(1..=64).contains(&pending.signal) {
        return Err(Error::Invalid);
    }
    let guard = Guard::acquire(instance)?;
    let queue = guard.queue(scope, slot).ok_or(Error::Invalid)?;
    if !realtime {
        let mut exists = false;
        if !walk(queue, |_, item| {
            exists = item
                .entries
                .iter()
                .any(|entry| entry.occupied != 0 && entry.signal == pending.signal);
            !exists
        }) {
            return Err(Error::Invalid);
        }
        if exists {
            return Ok(false);
        }
    }
    let mut target = None;
    if !walk(queue, |frame, item| {
        target = item
            .entries
            .iter()
            .position(|entry| entry.occupied == 0)
            .map(|index| (frame, index));
        target.is_none()
    }) {
        return Err(Error::Invalid);
    }
    if target.is_none() {
        let frame = allocate_page(queue.head)?;
        queue.head = frame;
        queue.pages = queue.pages.checked_add(1).ok_or(Error::NoMemory)?;
        target = Some((frame, 0));
    }
    let sequence = queue.next_sequence;
    queue.next_sequence = queue.next_sequence.wrapping_add(1);
    let (frame, index) = target.ok_or(Error::Invalid)?;
    page_mut(frame).ok_or(Error::Invalid)?.entries[index] = Entry {
        sequence,
        value: pending.value,
        code: pending.code,
        sender_pid: pending.sender_pid,
        sender_uid: pending.sender_uid,
        signal: pending.signal,
        occupied: 1,
        reserved: [0; 2],
    };
    queue.pending = queue.pending.checked_add(1).ok_or(Error::NoMemory)?;
    SIGNAL_RUNTIME.pending_counts[instance].fetch_add(1, Ordering::Release);
    Ok(true)
}

/// The signals queued in `instance`, for RLIMIT_SIGPENDING.
pub(crate) fn pending_count(instance: usize) -> u64 {
    SIGNAL_RUNTIME
        .pending_counts
        .get(instance)
        .map_or(0, |count| count.load(Ordering::Acquire))
}

pub(crate) fn any_pending(instance: usize) -> bool {
    SIGNAL_RUNTIME
        .pending_counts
        .get(instance)
        .is_some_and(|count| count.load(Ordering::Acquire) != 0)
}

pub(crate) fn pending_mask(instance: usize, scope: Scope, slot: usize) -> Result<u64, Error> {
    let guard = Guard::acquire(instance)?;
    let Some(queue) = guard.existing(scope, slot)? else {
        return Ok(0);
    };
    let mut mask = 0_u64;
    walk(queue, |_, item| {
        for entry in item.entries.iter().filter(|entry| entry.occupied != 0) {
            mask |= 1_u64 << (entry.signal - 1);
        }
        true
    })
    .then_some(mask)
    .ok_or(Error::Invalid)
}

pub(crate) fn peek(
    instance: usize,
    scope: Scope,
    slot: usize,
    requested: u64,
) -> Result<Option<Pending>, Error> {
    let guard = Guard::acquire(instance)?;
    let Some(queue) = guard.existing(scope, slot)? else {
        return Ok(None);
    };
    let mut selected: Option<Entry> = None;
    if !walk(queue, |_, item| {
        for entry in item.entries.iter().copied() {
            if entry.occupied == 0 || requested & (1_u64 << (entry.signal - 1)) == 0 {
                continue;
            }
            if selected.is_none_or(|current| {
                (entry.signal, entry.sequence) < (current.signal, current.sequence)
            }) {
                selected = Some(entry);
            }
        }
        true
    }) {
        return Err(Error::Invalid);
    }
    Ok(selected.map(|entry| Pending {
        signal: entry.signal,
        code: entry.code,
        value: entry.value,
        sender_pid: entry.sender_pid,
        sender_uid: entry.sender_uid,
    }))
}

pub(crate) fn dequeue(
    instance: usize,
    scope: Scope,
    slot: usize,
    requested: u64,
) -> Result<Option<Pending>, Error> {
    let guard = Guard::acquire(instance)?;
    let Some(queue) = guard.existing(scope, slot)? else {
        return Ok(None);
    };
    let mut selected: Option<(memory::FrameLease, usize, Entry)> = None;
    if !walk(queue, |frame, item| {
        for (index, entry) in item.entries.iter().copied().enumerate() {
            if entry.occupied == 0 || requested & (1_u64 << (entry.signal - 1)) == 0 {
                continue;
            }
            if selected.is_none_or(|(_, _, current)| {
                (entry.signal, entry.sequence) < (current.signal, current.sequence)
            }) {
                selected = Some((frame, index, entry));
            }
        }
        true
    }) {
        return Err(Error::Invalid);
    }
    let Some((frame, index, entry)) = selected else {
        return Ok(None);
    };
    page_mut(frame).ok_or(Error::Invalid)?.entries[index] = Entry::EMPTY;
    queue.pending = queue.pending.checked_sub(1).ok_or(Error::Invalid)?;
    SIGNAL_RUNTIME.pending_counts[instance].fetch_sub(1, Ordering::AcqRel);
    if !release_empty_pages(queue) {
        return Err(Error::Invalid);
    }
    Ok(Some(Pending {
        signal: entry.signal,
        code: entry.code,
        value: entry.value,
        sender_pid: entry.sender_pid,
        sender_uid: entry.sender_uid,
    }))
}

pub(crate) fn clear(instance: usize, scope: Scope, slot: usize) -> Result<(), Error> {
    let guard = Guard::acquire(instance)?;
    let Some(queue) = guard.existing(scope, slot)? else {
        return Ok(());
    };
    if queue.pages == 0 && queue.pending == 0 {
        // Already empty: nothing to free, and the table keeps its length.
        return Ok(());
    }
    let mut current = queue.head;
    for _ in 0..queue.pages {
        let next = page(current).ok_or(Error::Invalid)?.header.next;
        if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[current]) {
            return Err(Error::Invalid);
        }
        current = next;
    }
    if current != memory::FrameLease::EMPTY {
        return Err(Error::Invalid);
    }
    let pending = queue.pending;
    *queue = Queue::EMPTY;
    if pending != 0 {
        SIGNAL_RUNTIME.pending_counts[instance].fetch_sub(pending, Ordering::AcqRel);
    }
    guard.trim(scope);
    Ok(())
}

pub(crate) fn verify_dynamic_fifo(instance: usize) -> bool {
    let process = linux_process::PROCESS_LIMIT - 1;
    let thread = process * THREAD_LIMIT + THREAD_LIMIT - 1;
    if clear(instance, Scope::Process, process).is_err()
        || clear(instance, Scope::Thread, thread).is_err()
    {
        return false;
    }
    let standard = Pending {
        signal: 10,
        code: 0,
        value: 1,
        sender_pid: 1,
        sender_uid: 0,
    };
    let standard_coalesced = enqueue(instance, Scope::Process, process, standard, false)
        == Ok(true)
        && enqueue(
            instance,
            Scope::Process,
            process,
            Pending {
                value: 2,
                ..standard
            },
            false,
        ) == Ok(false)
        && any_pending(instance)
        && dequeue(instance, Scope::Process, process, u64::MAX) == Ok(Some(standard))
        && !any_pending(instance);
    let isolated = enqueue(
        instance,
        Scope::Process,
        process,
        Pending {
            signal: 34,
            code: -1,
            value: 3,
            sender_pid: 1,
            sender_uid: 0,
        },
        true,
    ) == Ok(true)
        && enqueue(
            instance,
            Scope::Thread,
            thread,
            Pending {
                signal: 34,
                code: -6,
                value: 4,
                sender_pid: 1,
                sender_uid: 0,
            },
            true,
        ) == Ok(true)
        && any_pending(instance)
        && pending_mask(instance, Scope::Process, process) == Ok(1 << 33)
        && pending_mask(instance, Scope::Thread, thread) == Ok(1 << 33)
        && dequeue(instance, Scope::Thread, thread, u64::MAX)
            == Ok(Some(Pending {
                signal: 34,
                code: -6,
                value: 4,
                sender_pid: 1,
                sender_uid: 0,
            }))
        && dequeue(instance, Scope::Process, process, u64::MAX)
            == Ok(Some(Pending {
                signal: 34,
                code: -1,
                value: 3,
                sender_pid: 1,
                sender_uid: 0,
            }))
        && !any_pending(instance);
    let mut filled = standard_coalesced && isolated;
    for value in 0..=ENTRIES_PER_PAGE as u64 {
        filled &= enqueue(
            instance,
            Scope::Process,
            process,
            Pending {
                signal: 34,
                code: -1,
                value,
                sender_pid: 1,
                sender_uid: 0,
            },
            true,
        ) == Ok(true);
    }
    let two_pages = Guard::acquire(instance)
        .ok()
        .and_then(|guard| {
            guard
                .queue(Scope::Process, process)
                .map(|queue| queue.pages == 2)
        })
        .unwrap_or(false);
    let mut ordered = true;
    for value in 0..=ENTRIES_PER_PAGE as u64 {
        ordered &= dequeue(instance, Scope::Process, process, 1 << 33)
            == Ok(Some(Pending {
                signal: 34,
                code: -1,
                value,
                sender_pid: 1,
                sender_uid: 0,
            }));
    }
    let released = Guard::acquire(instance)
        .ok()
        .and_then(|guard| {
            guard
                .queue(Scope::Process, process)
                .map(|queue| queue.pages == 0 && queue.pending == 0 && !any_pending(instance))
        })
        .unwrap_or(false);
    let clean = clear(instance, Scope::Process, process).is_ok()
        && clear(instance, Scope::Thread, thread).is_ok();
    filled && two_pages && ordered && released && clean
}
