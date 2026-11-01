//! The open files behind eventfd and timerfd descriptors.
//!
//! On Linux each eventfd(2) or timerfd_create(2) call makes one open file,
//! which every descriptor made from it (dup, fork) shares: the counter, the
//! timer and O_NONBLOCK belong to the file, not to a descriptor number or a
//! process. A descriptor names its file by id (kept in the descriptor's
//! offset slot, which these files have no other use for); each file counts
//! the descriptors that refer to it and is free again once the last closes.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Open files of each kind, system-wide.
const LIMIT: usize = 4096;

/// An eventfd: its counter and its flags (EFD_SEMAPHORE, O_NONBLOCK).
pub(crate) struct EventFd {
    references: AtomicU32,
    pub(crate) counter: AtomicU64,
    pub(crate) flags: AtomicU32,
}

/// A timerfd: its clock, flags (O_NONBLOCK), interval and next expiry.
pub(crate) struct TimerFd {
    references: AtomicU32,
    pub(crate) clock: AtomicU8,
    pub(crate) flags: AtomicU32,
    pub(crate) interval: AtomicU64,
    pub(crate) deadline: AtomicU64,
}

static EVENTFDS: [EventFd; LIMIT] = [const {
    EventFd {
        references: AtomicU32::new(0),
        counter: AtomicU64::new(0),
        flags: AtomicU32::new(0),
    }
}; LIMIT];

static TIMERFDS: [TimerFd; LIMIT] = [const {
    TimerFd {
        references: AtomicU32::new(0),
        clock: AtomicU8::new(0),
        flags: AtomicU32::new(0),
        interval: AtomicU64::new(0),
        deadline: AtomicU64::new(0),
    }
}; LIMIT];

/// The kinds of file, for [`retain`] and [`release`].
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    EventFd,
    TimerFd,
}

fn references(kind: Kind, id: u64) -> Option<&'static AtomicU32> {
    let id = usize::try_from(id).ok()?;
    match kind {
        Kind::EventFd => EVENTFDS.get(id).map(|file| &file.references),
        Kind::TimerFd => TIMERFDS.get(id).map(|file| &file.references),
    }
}

/// Takes the first free file of `kind` with its first reference.
fn allocate(kind: Kind) -> Option<u64> {
    (0..LIMIT as u64).find(|id| {
        references(kind, *id).is_some_and(|count| {
            count
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        })
    })
}

/// Makes an eventfd with `initial` and `flags`; returns its id.
pub(crate) fn create_eventfd(initial: u64, flags: u32) -> Option<u64> {
    let id = allocate(Kind::EventFd)?;
    let file = &EVENTFDS[id as usize];
    file.counter.store(initial, Ordering::SeqCst);
    file.flags.store(flags, Ordering::SeqCst);
    Some(id)
}

/// Makes a disarmed timerfd on `clock` with `flags`; returns its id.
pub(crate) fn create_timerfd(clock: u8, flags: u32) -> Option<u64> {
    let id = allocate(Kind::TimerFd)?;
    let file = &TIMERFDS[id as usize];
    file.clock.store(clock, Ordering::SeqCst);
    file.flags.store(flags, Ordering::SeqCst);
    file.interval.store(0, Ordering::SeqCst);
    file.deadline.store(0, Ordering::SeqCst);
    Some(id)
}

/// Open eventfd `id`.
pub(crate) fn eventfd(id: u64) -> Option<&'static EventFd> {
    let file = EVENTFDS.get(usize::try_from(id).ok()?)?;
    (file.references.load(Ordering::Acquire) != 0).then_some(file)
}

/// Open timerfd `id`.
pub(crate) fn timerfd(id: u64) -> Option<&'static TimerFd> {
    let file = TIMERFDS.get(usize::try_from(id).ok()?)?;
    (file.references.load(Ordering::Acquire) != 0).then_some(file)
}

/// Adds a descriptor's reference to open file `id`; false if it is not open.
pub(crate) fn retain(kind: Kind, id: u64) -> bool {
    references(kind, id).is_some_and(|count| {
        count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count != 0).then(|| count.saturating_add(1))
            })
            .is_ok()
    })
}

/// Drops a descriptor's reference to file `id`, freeing it with the last.
pub(crate) fn release(kind: Kind, id: u64) {
    if let Some(count) = references(kind, id) {
        let _ = count.try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            count.checked_sub(1)
        });
    }
}
