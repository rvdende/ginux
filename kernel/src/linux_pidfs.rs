//! What a pidfd still tells about its process once a wait has reaped it:
//! PIDFD_GET_INFO with PIDFD_INFO_EXIT reports the reaped process's wait
//! status. Linux keeps it in the pid the pidfd holds; Ginux keeps the
//! status of each domain's most recently reaped processes, by pid and
//! slot generation, with the PID namespace each lived in, so a pidfd
//! seen from another namespace stays refused.
#![forbid(unsafe_code)]

use alloc::collections::VecDeque;

use crate::sync::{LockRank, SpinLock};

/// How many reaped processes' statuses are kept, across domains: a pidfd
/// of a process reaped longer ago than this reports no exit status.
const KEPT: usize = 4096;

/// One reaped process.
#[derive(Clone, Copy)]
pub(crate) struct Exit {
    instance: usize,
    pid: u32,
    generation: u32,
    /// The PID namespace the process lived in.
    pub(crate) namespace: u32,
    /// Its wait status, as wait4 reports it.
    pub(crate) status: u32,
}

static EXITS: SpinLock<VecDeque<Exit>> = SpinLock::new(LockRank::PIDFS_EXITS, VecDeque::new());

/// Records that process `pid` of slot generation `generation` in domain
/// `instance`, living in PID namespace `namespace`, was reaped with wait
/// status `status`. Without memory the status is not kept.
pub(crate) fn reaped(instance: usize, pid: u32, generation: u32, namespace: u32, status: u32) {
    let mut exits = EXITS.lock();
    if exits.len() >= KEPT {
        exits.pop_front();
    } else if exits.try_reserve(1).is_err() {
        return;
    }
    exits.push_back(Exit {
        instance,
        pid,
        generation,
        namespace,
        status,
    });
}

/// The exit of process `pid` of slot generation `generation` in domain
/// `instance`, if it was reaped recently enough to be kept.
pub(crate) fn exit(instance: usize, pid: u32, generation: u32) -> Option<Exit> {
    EXITS
        .lock()
        .iter()
        .rev()
        .copied()
        .find(|exit| exit.instance == instance && exit.pid == pid && exit.generation == generation)
}

/// Forgets domain `instance`'s reaped processes, as the domain stops.
pub(crate) fn forget_instance(instance: usize) {
    EXITS.lock().retain(|exit| exit.instance != instance);
}
