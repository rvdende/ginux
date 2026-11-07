//! File leases (fcntl F_SETLEASE, F_GETLEASE), as Linux's fs/locks.c
//! keeps them: a read lease, which no open for writing may meet, or a
//! write lease, which no other open may, on an open file of the holder.
//!
//! An open (or truncate) that conflicts with another process's lease
//! breaks it: the holder is told (SIGIO) and given
//! `/proc/sys/fs/lease-break-time` seconds to give the lease up or, for a
//! read-only open meeting a write lease, to downgrade it to a read lease;
//! meanwhile the opener waits (or fails with EWOULDBLOCK when it opened
//! with O_NONBLOCK). When the time is up the kernel does it instead.
//!
//! A lease is on a file (its overlay generation, which a volume's files
//! have too) and held by a process's descriptor; it goes when that
//! descriptor no longer has the file open (`valid`).
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

/// A lease's kind (F_RDLCK, F_WRLCK).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Kind {
    Read,
    Write,
}

/// Why a lease cannot be had.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// EAGAIN: a conflicting open or lease, or no lease to give up.
    Conflict,
    NoMemory,
}

/// How the other opens of a file stand, for a new lease on it.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Opens {
    /// Some other descriptor has the file open.
    pub(crate) others: bool,
    /// Some descriptor (the holder's too) has it open for writing.
    pub(crate) writers: bool,
}

/// What an open that may meet leases is to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Breaking {
    /// No lease is in the way (any in the way were given up or timed out).
    Clear,
    /// A lease is being broken: wait and try again.
    Wait,
}

struct Break {
    /// What the lease becomes: a read lease, or none.
    target: Option<Kind>,
    /// When the kernel takes the lease down itself (nanoseconds).
    deadline: u64,
}

struct Lease {
    domain: usize,
    file: u32,
    pid: u32,
    descriptor: u32,
    kind: Kind,
    breaking: Option<Break>,
}

static LEASES: SpinLock<Vec<Lease>> = SpinLock::new(LockRank::LEASES, Vec::new());
/// How many leases there are, across domains: none spares every open the
/// table.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Whether any lease exists.
pub(crate) fn active() -> bool {
    COUNT.load(Ordering::Relaxed) != 0
}

fn recount(leases: &[Lease]) {
    COUNT.store(leases.len(), Ordering::Relaxed);
}

/// F_GETLEASE on `descriptor` of `pid` (holding `file`): its lease, or what
/// it is being broken to.
pub(crate) fn get(domain: usize, pid: u32, descriptor: u32, file: u32) -> Option<Kind> {
    if !active() {
        return None;
    }
    let leases = LEASES.lock();
    let lease = leases.iter().find(|lease| {
        lease.domain == domain
            && lease.pid == pid
            && lease.descriptor == descriptor
            && lease.file == file
    })?;
    match &lease.breaking {
        Some(breaking) => breaking.target,
        None => Some(lease.kind),
    }
}

/// F_SETLEASE on `descriptor` of `pid`, which has `file` open: a lease of
/// `kind`, or none. `opens` tells the file's other opens; `valid` whether
/// another holder's descriptor still has the file (stale leases go).
pub(crate) fn set(
    domain: usize,
    (pid, descriptor, file): (u32, u32, u32),
    kind: Option<Kind>,
    opens: Opens,
    valid: impl Fn(u32, u32) -> bool,
) -> Result<(), Error> {
    let mut leases = LEASES.lock();
    leases.retain(|lease| {
        lease.domain != domain
            || lease.file != file
            || lease.pid == pid && lease.descriptor == descriptor
            || valid(lease.pid, lease.descriptor)
    });
    let own = leases.iter().position(|lease| {
        lease.domain == domain
            && lease.file == file
            && lease.pid == pid
            && lease.descriptor == descriptor
    });
    let Some(kind) = kind else {
        let result = match own {
            Some(index) => {
                leases.remove(index);
                Ok(())
            }
            None => Err(Error::Conflict),
        };
        recount(&leases);
        return result;
    };
    // The opens a lease of this kind may not meet (a write lease: any other
    // open; a read lease: any open for writing); a lease being broken may
    // only go down as far as its break asks.
    let opens_conflict = match kind {
        Kind::Read => opens.writers,
        Kind::Write => opens.others,
    };
    let breaking_to_none = own
        .and_then(|index| leases[index].breaking.as_ref())
        .is_some_and(|breaking| breaking.target.is_none_or(|target| target < kind));
    let others = leases
        .iter()
        .enumerate()
        .filter(|(index, lease)| {
            Some(*index) != own && lease.domain == domain && lease.file == file
        })
        .any(|(_, lease)| {
            kind == Kind::Write || lease.kind == Kind::Write || lease.breaking.is_some()
        });
    if opens_conflict || breaking_to_none || others {
        return Err(Error::Conflict);
    }
    match own {
        Some(index) => {
            let lease = &mut leases[index];
            lease.kind = kind;
            // Downgraded as far as its break asked: the break is over.
            lease.breaking = None;
        }
        None => {
            leases.try_reserve(1).map_err(|_| Error::NoMemory)?;
            leases.push(Lease {
                domain,
                file,
                pid,
                descriptor,
                kind,
                breaking: None,
            });
        }
    }
    recount(&leases);
    Ok(())
}

/// An open of `file` by `pid` (for writing, or a truncate, when `write`)
/// at `now`: the other processes' leases it conflicts with are broken,
/// each holder told once (`notify`, which sends SIGIO), and taken down
/// when `break_time` nanoseconds have passed since. `valid` tells whether a
/// holder's descriptor still has the file (stale leases go).
pub(crate) fn break_for(
    domain: usize,
    (file, pid, write): (u32, u32, bool),
    (now, break_time): (u64, u64),
    valid: impl Fn(u32, u32) -> bool,
    mut notify: impl FnMut(u32, u32),
) -> Breaking {
    if !active() {
        return Breaking::Clear;
    }
    let mut leases = LEASES.lock();
    leases.retain(|lease| {
        lease.domain != domain || lease.file != file || valid(lease.pid, lease.descriptor)
    });
    let mut waiting = false;
    leases.retain_mut(|lease| {
        if lease.domain != domain || lease.file != file || lease.pid == pid {
            return true;
        }
        let conflicts = write || lease.kind == Kind::Write;
        if !conflicts {
            return true;
        }
        let target = if write { None } else { Some(Kind::Read) };
        match &lease.breaking {
            None => {
                lease.breaking = Some(Break {
                    target,
                    deadline: now.saturating_add(break_time),
                });
                notify(lease.pid, lease.descriptor);
                waiting = true;
                true
            }
            Some(breaking) if now >= breaking.deadline => match breaking.target {
                Some(kind) if !write => {
                    lease.kind = kind;
                    lease.breaking = None;
                    true
                }
                _ => false,
            },
            Some(breaking) => {
                // A writer coming after a reader asks for the lease to go.
                if write && breaking.target.is_some() {
                    lease.breaking = Some(Break {
                        target: None,
                        deadline: breaking.deadline,
                    });
                }
                waiting = true;
                true
            }
        }
    });
    recount(&leases);
    if waiting {
        Breaking::Wait
    } else {
        Breaking::Clear
    }
}

/// Domain `domain` stopped: its leases go.
pub(crate) fn forget_domain(domain: usize) {
    let mut leases = LEASES.lock();
    leases.retain(|lease| lease.domain != domain);
    recount(&leases);
}
