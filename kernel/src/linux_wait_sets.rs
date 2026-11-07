//! The descriptor sets of poll and select waits too large for a thread's
//! fixed wait snapshot: more pollfds than `LINUX_POLLFD_LIMIT`, or select
//! sets past FD_SETSIZE. A blocked thread's set is kept here, by domain,
//! process and thread slot, from the call that blocks until the wait ends.
#![forbid(unsafe_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};

/// A waiting thread: its domain, process and thread slot.
pub(crate) type Key = (usize, u32, u16);

static SETS: SpinLock<BTreeMap<Key, Vec<u64>>> =
    SpinLock::new(LockRank::WAIT_SETS, BTreeMap::new());

/// Keeps `words` as the set of the wait `key`, in place of any before.
pub(crate) fn store(key: Key, words: Vec<u64>) {
    SETS.lock().insert(key, words);
}

/// A copy of the set of wait `key`; None without one (or memory).
pub(crate) fn load(key: Key) -> Option<Vec<u64>> {
    let sets = SETS.lock();
    let words = sets.get(&key)?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(words.len()).ok()?;
    copy.extend_from_slice(words);
    Some(copy)
}

/// The wait `key` ended: its set goes.
pub(crate) fn remove(key: Key) {
    let mut sets = SETS.lock();
    if !sets.is_empty() {
        sets.remove(&key);
    }
}

/// Domain `domain` stopped: its waits' sets go.
pub(crate) fn forget_domain(domain: usize) {
    SETS.lock().retain(|key, _| key.0 != domain);
}
