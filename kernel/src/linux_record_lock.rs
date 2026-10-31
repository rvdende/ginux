//! POSIX record locks (`fcntl` `F_SETLK`, `F_SETLKW` and `F_GETLK`) and their
//! open-file-description form (`F_OFD_*`).
//!
//! A lock covers a byte range of a file, named by its device and inode, for
//! an owner: the process for classic locks, the open file description for
//! OFD locks. Read locks share a range, a write lock excludes every other
//! owner. An owner's new lock replaces its own locks on the range, splitting
//! them at its edges and merging with neighbours of the same kind, as Linux
//! does.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};

/// A file's identity: its device and inode numbers.
pub(crate) type File = (u64, u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owner {
    Process(u32),
    Description(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Lock {
    pub(crate) file: File,
    pub(crate) owner: Owner,
    /// The process that set the lock, which `F_GETLK` reports.
    pub(crate) pid: u32,
    pub(crate) kind: Kind,
    pub(crate) start: u64,
    /// One past the last byte; `u64::MAX` reaches past any end of file.
    pub(crate) end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// Another owner's lock is in the way.
    Conflict(Lock),
    NoMemory,
}

impl Lock {
    fn overlaps(&self, file: File, start: u64, end: u64) -> bool {
        self.file == file && self.start < end && start < self.end
    }

    fn blocks(&self, owner: Owner, kind: Kind) -> bool {
        self.owner != owner && (kind == Kind::Write || self.kind == Kind::Write)
    }
}

static LOCKS: SpinLock<Vec<Lock>> = SpinLock::new(LockRank::RECORD_LOCKS, Vec::new());

/// The first lock of another owner that keeps `owner` from taking `kind` on
/// `[start, end)` of `file`. Locks of processes `alive` no longer knows are
/// dropped first, which is how an exiting process gives its locks up.
pub(crate) fn conflict(
    file: File,
    owner: Owner,
    (kind, start, end): (Kind, u64, u64),
    alive: impl Fn(u32) -> bool,
) -> Option<Lock> {
    let mut locks = LOCKS.lock();
    locks.retain(|lock| alive(lock.pid));
    locks
        .iter()
        .find(|lock| lock.overlaps(file, start, end) && lock.blocks(owner, kind))
        .copied()
}

/// Gives `owner` a lock of `kind` on `[start, end)` of `file`, or with
/// `None` removes its locks there.
pub(crate) fn set(
    file: File,
    owner: Owner,
    pid: u32,
    (kind, start, end): (Option<Kind>, u64, u64),
    alive: impl Fn(u32) -> bool,
) -> Result<(), Error> {
    let mut locks = LOCKS.lock();
    locks.retain(|lock| alive(lock.pid));
    if let Some(kind) = kind {
        if let Some(blocking) = locks
            .iter()
            .find(|lock| lock.overlaps(file, start, end) && lock.blocks(owner, kind))
        {
            return Err(Error::Conflict(*blocking));
        }
    }
    // Cutting a lock out of the middle of one leaves two pieces, and the new
    // lock is one more.
    locks.try_reserve(2).map_err(|_| Error::NoMemory)?;
    let mut index = 0;
    while index < locks.len() {
        let lock = locks[index];
        if lock.owner != owner || !lock.overlaps(file, start, end) {
            index += 1;
            continue;
        }
        locks.swap_remove(index);
        if lock.start < start {
            locks.push(Lock { end: start, ..lock });
        }
        if end < lock.end {
            locks.push(Lock { start: end, ..lock });
        }
    }
    let Some(kind) = kind else {
        return Ok(());
    };
    let mut merged = Lock {
        file,
        owner,
        pid,
        kind,
        start,
        end,
    };
    // Same-kind neighbours that touch the new range join it.
    locks.retain(|lock| {
        let joins = lock.owner == owner
            && lock.file == file
            && lock.kind == kind
            && lock.start <= merged.end
            && merged.start <= lock.end;
        if joins {
            merged.start = merged.start.min(lock.start);
            merged.end = merged.end.max(lock.end);
        }
        !joins
    });
    locks.push(merged);
    Ok(())
}

/// Drops `owner`'s locks on `file`, as closing any descriptor of a file
/// drops the closing process's locks on it.
pub(crate) fn release(owner: Owner, file: File) {
    LOCKS
        .lock()
        .retain(|lock| lock.owner != owner || lock.file != file);
}

/// Whether `owner` holds any lock, so a close need not look up its file.
pub(crate) fn holds_any(owner: Owner) -> bool {
    LOCKS.lock().iter().any(|lock| lock.owner == owner)
}
