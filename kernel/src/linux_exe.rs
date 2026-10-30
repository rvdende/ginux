//! Executable paths behind `/proc/self/exe` for processes that executed a
//! file from a domain's root filesystem.
//!
//! musl and glibc resolve `$ORIGIN` in RPATH and RUNPATH through
//! `/proc/self/exe`, so it must name the real program for dynamically linked
//! tools such as rustc to find their libraries. A forked child that has not
//! called execve yet shares its parent's executable, so lookups fall back to
//! the nearest ancestor with a recorded path.

use crate::linux_process;

const PATH_CAPACITY: usize = 256;
const ENTRY_LIMIT: usize = 64;

#[derive(Clone, Copy)]
struct Entry {
    instance: u8,
    pid: u32,
    length: u16,
    path: [u8; PATH_CAPACITY],
}

const EMPTY: Entry = Entry {
    instance: 0,
    pid: 0,
    length: 0,
    path: [0; PATH_CAPACITY],
};

static mut ENTRIES: [Entry; ENTRY_LIMIT] = [EMPTY; ENTRY_LIMIT];
static mut NEXT_VICTIM: usize = 0;

fn entries() -> &'static mut [Entry; ENTRY_LIMIT] {
    // SAFETY: the kernel is single-processor and system calls that reach
    // this module do not nest.
    unsafe { &mut *core::ptr::addr_of_mut!(ENTRIES) }
}

/// Records that `pid` in `instance` executed `path`. Relative paths are made
/// absolute against the root, and paths that do not fit are not recorded.
pub(crate) fn record(instance: u8, pid: u32, path: &[u8]) {
    let relative = !path.starts_with(b"/");
    let length = path.len() + usize::from(relative);
    if pid == 0 || path.is_empty() || length > PATH_CAPACITY {
        return;
    }
    let entries = entries();
    let index = entries
        .iter()
        .position(|entry| entry.length != 0 && entry.instance == instance && entry.pid == pid)
        .or_else(|| entries.iter().position(|entry| entry.length == 0))
        .unwrap_or_else(|| {
            // SAFETY: as for entries().
            unsafe {
                let victim = NEXT_VICTIM;
                NEXT_VICTIM = (victim + 1) % ENTRY_LIMIT;
                victim
            }
        });
    let entry = &mut entries[index];
    entry.instance = instance;
    entry.pid = pid;
    entry.length = length as u16;
    entry.path[0] = b'/';
    entry.path[usize::from(relative)..length].copy_from_slice(path);
}

/// Returns the executable of `pid` in `instance`, inherited from the nearest
/// ancestor when the process has not executed a file itself.
pub(crate) fn lookup(instance: u8, pid: u32) -> Option<&'static [u8]> {
    let entries = entries();
    let mut current = pid;
    for _ in 0..linux_process::PROCESS_LIMIT {
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.length != 0 && entry.instance == instance && entry.pid == current)
        {
            return Some(&entry.path[..usize::from(entry.length)]);
        }
        let parent = linux_process::live_process_status(current)?.parent_pid;
        if parent == 0 || parent == current {
            return None;
        }
        current = parent;
    }
    None
}

/// Forgets every path recorded for `instance`, when its domain stops.
pub(crate) fn forget_instance(instance: u8) {
    for entry in entries()
        .iter_mut()
        .filter(|entry| entry.instance == instance)
    {
        entry.length = 0;
    }
}
