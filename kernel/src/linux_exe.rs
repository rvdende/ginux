//! Executable paths behind `/proc/self/exe` for processes that executed a
//! file from a domain's root filesystem.
//!
//! musl and glibc resolve `$ORIGIN` in RPATH and RUNPATH through
//! `/proc/self/exe`, so it must name the real program for dynamically linked
//! tools such as rustc to find their libraries. A forked child that has not
//! called execve yet shares its parent's executable, so lookups fall back to
//! the nearest ancestor with a recorded path.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::{
    linux_process,
    sync::{LockRank, SpinLock},
};

/// The longest path recorded, Linux's PATH_MAX; longer ones are not.
const PATH_CAPACITY: usize = 4096;

struct Entry {
    instance: u8,
    pid: u32,
    path: Vec<u8>,
}

static ENTRIES: SpinLock<Vec<Entry>> = SpinLock::new(LockRank::EXECUTABLES, Vec::new());

/// Records that `pid` in `instance` executed `path`. Relative paths are made
/// absolute against the root, and paths that do not fit are not recorded.
pub(crate) fn record(instance: u8, pid: u32, path: &[u8]) {
    let relative = !path.starts_with(b"/");
    let length = path.len() + usize::from(relative);
    if pid == 0 || path.is_empty() || length > PATH_CAPACITY {
        return;
    }
    let mut absolute = Vec::new();
    if absolute.try_reserve_exact(length).is_err() {
        return;
    }
    if relative {
        absolute.push(b'/');
    }
    absolute.extend_from_slice(path);
    let mut entries = ENTRIES.lock();
    // The process's earlier program goes, and so do processes of this
    // domain that have ended, whose pids may be reused.
    entries.retain(|entry| {
        entry.instance != instance
            || entry.pid != pid && linux_process::live_process_slot(entry.pid).is_some()
    });
    if entries.try_reserve(1).is_ok() {
        entries.push(Entry {
            instance,
            pid,
            path: absolute,
        });
    }
}

/// Returns the executable of `pid` in `instance`, inherited from the nearest
/// ancestor when the process has not executed a file itself.
pub(crate) fn lookup(instance: u8, pid: u32) -> Option<Vec<u8>> {
    let entries = ENTRIES.lock();
    let mut current = pid;
    for _ in 0..linux_process::PROCESS_LIMIT {
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.instance == instance && entry.pid == current)
        {
            let mut path = Vec::new();
            path.try_reserve_exact(entry.path.len()).ok()?;
            path.extend_from_slice(&entry.path);
            return Some(path);
        }
        let parent = linux_process::live_process_status(current)?.parent_pid;
        if parent == 0 || parent == current {
            return None;
        }
        current = parent;
    }
    None
}

/// Whether a live process of `instance` is executing the program at
/// absolute `path` (opening it for writing is then ETXTBSY).
pub(crate) fn executing(instance: u8, path: &[u8]) -> bool {
    ENTRIES.lock().iter().any(|entry| {
        entry.instance == instance
            && entry.path == path
            && linux_process::live_process_status(entry.pid)
                .is_some_and(|status| status.state != linux_process::LiveProcessState::Zombie)
    })
}

/// Forgets every path recorded for `instance`, when its domain stops.
pub(crate) fn forget_instance(instance: u8) {
    ENTRIES.lock().retain(|entry| entry.instance != instance);
}
