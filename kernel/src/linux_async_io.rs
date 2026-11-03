//! Signal-driven I/O (fcntl F_SETOWN, F_SETOWN_EX and O_ASYNC): a pipe
//! or socket descriptor with O_ASYNC set signals its owner (a process, a
//! process group or a thread) when data arrives for it, with F_SETSIG's
//! signal or SIGIO.

use alloc::vec::Vec;

use crate::linux_socket::SlotId;
use crate::sync::{LockRank, SpinLock};

/// Who a descriptor's I/O signals go to (struct f_owner_ex's types).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owner {
    Thread(u32),
    Process(u32),
    Group(u32),
}

/// One process's descriptor with an owner or O_ASYNC.
#[derive(Clone, Copy)]
struct Entry {
    domain: usize,
    pid: u32,
    descriptor: u32,
    /// The socket (or pipe end) the descriptor reads.
    slot: SlotId,
    owner: Option<Owner>,
    async_io: bool,
}

static ENTRIES: SpinLock<Vec<Entry>> = SpinLock::new(LockRank::INOTIFY, Vec::new());

fn update(domain: usize, pid: u32, descriptor: u32, slot: SlotId, change: impl FnOnce(&mut Entry)) {
    let mut entries = ENTRIES.lock();
    let index = match entries.iter().position(|entry| {
        entry.domain == domain && entry.pid == pid && entry.descriptor == descriptor
    }) {
        Some(index) => index,
        None => {
            if entries.try_reserve(1).is_err() {
                return;
            }
            entries.push(Entry {
                domain,
                pid,
                descriptor,
                slot,
                owner: None,
                async_io: false,
            });
            entries.len() - 1
        }
    };
    let entry = &mut entries[index];
    entry.slot = slot;
    change(entry);
}

/// F_SETOWN and F_SETOWN_EX: `owner` (None for 0) gets the descriptor's
/// I/O signals.
pub(crate) fn set_owner(
    domain: usize,
    pid: u32,
    descriptor: u32,
    slot: SlotId,
    owner: Option<Owner>,
) {
    update(domain, pid, descriptor, slot, |entry| entry.owner = owner);
}

/// F_GETOWN and F_GETOWN_EX: the descriptor's owner, if it has one.
pub(crate) fn owner(domain: usize, pid: u32, descriptor: u32) -> Option<Owner> {
    ENTRIES
        .lock()
        .iter()
        .find(|entry| entry.domain == domain && entry.pid == pid && entry.descriptor == descriptor)
        .and_then(|entry| entry.owner)
}

/// F_SETFL's O_ASYNC: whether the descriptor signals its owner.
pub(crate) fn set_async(domain: usize, pid: u32, descriptor: u32, slot: SlotId, enabled: bool) {
    update(domain, pid, descriptor, slot, |entry| {
        entry.async_io = enabled
    });
}

/// `pid` closed `descriptor` (or ended).
pub(crate) fn closed(domain: usize, pid: u32, descriptor: u32) {
    ENTRIES.lock().retain(|entry| {
        !(entry.domain == domain && entry.pid == pid && entry.descriptor == descriptor)
    });
}

/// The descriptors to signal as data arrives for socket `slot`: each
/// O_ASYNC one with an owner, as (pid, descriptor, owner).
pub(crate) fn listeners(domain: usize, slot: SlotId) -> Vec<(u32, u32, Owner)> {
    let entries = ENTRIES.lock();
    let mut listeners = Vec::new();
    for entry in entries
        .iter()
        .filter(|entry| entry.domain == domain && entry.slot == slot && entry.async_io)
    {
        if let Some(owner) = entry.owner {
            if listeners.try_reserve(1).is_ok() {
                listeners.push((entry.pid, entry.descriptor, owner));
            }
        }
    }
    listeners
}
