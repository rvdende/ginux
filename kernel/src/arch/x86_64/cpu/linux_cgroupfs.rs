//! The domain's cgroup v2 filesystem at `/sys/fs/cgroup` and its memory
//! controller (`crate::linux_cgroup` keeps the cgroups' memory state).
//!
//! A cgroup is a directory of the domain's overlay; its control files are
//! overlay files whose contents this module writes when they are read
//! (`linux_cgroup_refresh_control`) and whose writes it applies instead of
//! storing (`linux_cgroup_control_write`): moving a process (`cgroup.procs`),
//! delegating the memory controller (`cgroup.subtree_control`), and the
//! memory limits. The memory files appear in a cgroup whose parent delegates
//! the controller, as Linux's do.
//!
//! A process's user pages are charged to its cgroup as they are allocated
//! (`charge_linux_user_pages`). A charge that would take a cgroup past its
//! `memory.max` first reclaims what may be dropped from the cgroup's other
//! processes (`MAP_DROPPABLE` memory, and lazily freed `MADV_FREE` pages not
//! written since), then kills the process of the cgroup that holds the most
//! memory, as Linux's memory-cgroup OOM killer does.

use super::*;

use crate::linux_cgroup::{self as cgroup, Event, Limit, Slot, NO_SLOT};
use ginux_cgroup::{Controllers, Output};

const ROOT: &[u8] = b"sys/fs/cgroup";

/// What a control file holds, as its name says.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Control {
    Procs,
    Events,
    Controllers,
    Subtree,
    Kill,
    Stat,
    MemoryCurrent,
    MemoryMin,
    MemoryLow,
    MemoryHigh,
    MemoryMax,
    MemoryPeak,
    MemoryEvents,
    MemoryEventsLocal,
    MemoryStat,
    MemoryOomGroup,
    MemoryReclaim,
    SwapCurrent,
    SwapHigh,
    SwapMax,
    SwapPeak,
    SwapEvents,
}

/// Every cgroup's files, with their modes.
const CORE_FILES: [(&[u8], Control, u32); 6] = [
    (b"cgroup.procs", Control::Procs, 0o644),
    (b"cgroup.events", Control::Events, 0o444),
    (b"cgroup.controllers", Control::Controllers, 0o444),
    (b"cgroup.subtree_control", Control::Subtree, 0o644),
    (b"cgroup.kill", Control::Kill, 0o200),
    (b"cgroup.stat", Control::Stat, 0o444),
];

/// The root's: no `cgroup.events` or `cgroup.kill`, and of the memory
/// controller's only `memory.stat`.
const ROOT_FILES: [(&[u8], Control, u32); 5] = [
    (b"cgroup.procs", Control::Procs, 0o644),
    (b"cgroup.controllers", Control::Controllers, 0o444),
    (b"cgroup.subtree_control", Control::Subtree, 0o644),
    (b"cgroup.stat", Control::Stat, 0o444),
    (b"memory.stat", Control::MemoryStat, 0o444),
];

/// The memory controller's files in a cgroup it governs.
const MEMORY_FILES: [(&[u8], Control, u32); 16] = [
    (b"memory.current", Control::MemoryCurrent, 0o444),
    (b"memory.min", Control::MemoryMin, 0o644),
    (b"memory.low", Control::MemoryLow, 0o644),
    (b"memory.high", Control::MemoryHigh, 0o644),
    (b"memory.max", Control::MemoryMax, 0o644),
    (b"memory.peak", Control::MemoryPeak, 0o644),
    (b"memory.events", Control::MemoryEvents, 0o444),
    (b"memory.events.local", Control::MemoryEventsLocal, 0o444),
    (b"memory.stat", Control::MemoryStat, 0o444),
    (b"memory.oom.group", Control::MemoryOomGroup, 0o644),
    (b"memory.reclaim", Control::MemoryReclaim, 0o200),
    (b"memory.swap.current", Control::SwapCurrent, 0o444),
    (b"memory.swap.high", Control::SwapHigh, 0o644),
    (b"memory.swap.max", Control::SwapMax, 0o644),
    (b"memory.swap.peak", Control::SwapPeak, 0o644),
    (b"memory.swap.events", Control::SwapEvents, 0o444),
];

/// How often a charge is retried after reclaiming something, as Linux's
/// MAX_RECLAIM_RETRIES.
const RECLAIM_RETRIES: usize = 16;

/// `path` with `/name` appended, in `buffer`.
fn joined<'a>(buffer: &'a mut [u8], path: &[u8], name: &[u8]) -> Option<&'a [u8]> {
    let end = path.len().checked_add(1 + name.len())?;
    let output = buffer.get_mut(..end)?;
    output[..path.len()].copy_from_slice(path);
    output[path.len()] = b'/';
    output[path.len() + 1..].copy_from_slice(name);
    Some(output)
}

/// The cgroup whose directory is the canonical `path` (`sys/fs/cgroup` or
/// below it).
fn cgroup_at(path: &[u8]) -> Option<Slot> {
    let instance = linux_execution_instance();
    if path == ROOT {
        return cgroup::root(instance);
    }
    if !path.starts_with(ROOT) || path.get(ROOT.len()) != Some(&b'/') {
        return None;
    }
    let metadata = crate::linux_overlay::lookup(path)?;
    if metadata.kind != crate::linux_overlay::NodeKind::Directory {
        return None;
    }
    cgroup::find(instance, crate::linux_overlay::generation(metadata.handle))
}

/// The canonical path of cgroup `slot`'s directory, in `buffer`.
fn cgroup_path(slot: Slot, buffer: &mut [u8]) -> Option<usize> {
    if cgroup::is_root(slot) {
        buffer.get_mut(..ROOT.len())?.copy_from_slice(ROOT);
        return Some(ROOT.len());
    }
    let directory = crate::linux_overlay::from_generation(cgroup::directory(slot)?)?;
    crate::linux_overlay::copy_path(directory, buffer)
}

/// The files cgroup `slot` has: its own set, and the memory controller's
/// when its parent delegates it.
fn files_of(slot: Slot) -> impl Iterator<Item = (&'static [u8], Control, u32)> {
    let root = cgroup::is_root(slot);
    let memory = cgroup::memory_controlled(slot);
    ROOT_FILES
        .iter()
        .filter(move |_| root)
        .chain(CORE_FILES.iter().filter(move |_| !root))
        .chain(MEMORY_FILES.iter().filter(move |_| memory))
        .copied()
}

/// The control file `handle` is, with its cgroup.
fn control_file(handle: crate::linux_overlay::Handle) -> Option<(Slot, Control)> {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = crate::linux_overlay::copy_path(handle, &mut path)?;
    let path = &path[..length];
    if !path.starts_with(ROOT) {
        return None;
    }
    let separator = path.iter().rposition(|byte| *byte == b'/')?;
    let (directory, name) = (&path[..separator], &path[separator + 1..]);
    let slot = cgroup_at(directory)?;
    files_of(slot)
        .find(|(file, _, _)| *file == name)
        .map(|(_, control, _)| (slot, control))
}

/// Makes the control files cgroup `slot` should have in its directory at
/// `path` and removes the memory controller's when it no longer governs
/// it.
fn sync_control_files(slot: Slot, path: &[u8]) -> bool {
    let root = cgroup::is_root(slot);
    let memory = cgroup::memory_controlled(slot);
    let mut file = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let wanted = files_of(slot).all(|(name, _, mode)| {
        let Some(file) = joined(&mut file, path, name) else {
            return false;
        };
        crate::linux_overlay::lookup(file).is_some()
            || crate::linux_overlay::create_file(file, mode, b"")
                .is_some_and(|handle| crate::linux_overlay::set_owner(handle, 0, 0))
    });
    if !memory {
        for (name, _, _) in MEMORY_FILES {
            // The root keeps its memory.stat.
            if root && name == b"memory.stat" {
                continue;
            }
            if let Some(file) = joined(&mut file, path, name) {
                let _ = crate::linux_overlay::unlink_path(file);
            }
        }
    }
    wanted
}

/// Makes the root cgroup's control files if they are missing. /proc/mounts
/// shows cgroup2 mounted at /sys/fs/cgroup from the start, so they must
/// exist before anything mounts it.
pub(super) fn linux_cgroup_ensure_root() -> bool {
    cgroup::root(linux_execution_instance()).is_some_and(|slot| sync_control_files(slot, ROOT))
}

/// Makes the cgroup of a directory just made at the canonical `path` below
/// `/sys/fs/cgroup`, and its control files: false if its parent is no
/// cgroup or no slot is left.
pub(super) fn linux_cgroup_mkdir(path: &[u8], directory: crate::linux_overlay::Handle) -> bool {
    let Some(separator) = path.iter().rposition(|byte| *byte == b'/') else {
        return false;
    };
    let Some(parent) = cgroup_at(&path[..separator]) else {
        return false;
    };
    let Some(slot) = cgroup::create(
        linux_execution_instance(),
        parent,
        crate::linux_overlay::generation(directory),
    ) else {
        return false;
    };
    if sync_control_files(slot, path) {
        return true;
    }
    let _ = linux_cgroup_remove_files(slot, path);
    cgroup::retire(slot);
    false
}

fn linux_cgroup_remove_files(slot: Slot, path: &[u8]) -> bool {
    let mut file = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    CORE_FILES
        .iter()
        .chain(MEMORY_FILES.iter())
        .filter(|_| !cgroup::is_root(slot))
        .all(|(name, _, _)| {
            joined(&mut file, path, name).is_some_and(|file| {
                crate::linux_overlay::lookup(file).is_none()
                    || crate::linux_overlay::unlink_path(file)
            })
        })
}

/// Removes the cgroup of directory `directory` (rmdir): EBUSY while
/// processes are in it or below it or a cgroup is left below it. Its
/// control files go with it; the memory charged to it stays charged until
/// freed.
pub(super) fn linux_cgroup_rmdir(directory: crate::linux_overlay::Handle) -> Result<(), u64> {
    let Some(slot) = cgroup::find(
        linux_execution_instance(),
        crate::linux_overlay::generation(directory),
    ) else {
        return Ok(());
    };
    if cgroup_populated(slot) || cgroup::children(slot).next().is_some() {
        return Err(LINUX_EBUSY);
    }
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = crate::linux_overlay::copy_path(directory, &mut path).ok_or(LINUX_EIO)?;
    // Anything there besides the control files keeps the directory.
    let mut cursor = 0;
    while let Some(Some(child)) = crate::linux_overlay::next_child_at(&path[..length], cursor) {
        if !CORE_FILES
            .iter()
            .chain(MEMORY_FILES.iter())
            .any(|(name, _, _)| *name == child.name())
        {
            return Err(LINUX_ENOTEMPTY);
        }
        cursor = child.next_cursor;
    }
    if !linux_cgroup_remove_files(slot, &path[..length]) {
        return Err(LINUX_EBUSY);
    }
    cgroup::retire(slot);
    Ok(())
}

/// `/proc/self/cgroup`: the current process's cgroup as cgroup v2's one
/// line, `0::/` and its path below `/sys/fs/cgroup`.
pub(super) fn linux_proc_cgroup() -> &'static [u8] {
    static mut CGROUP_FILE: [u8; crate::linux_overlay::PATH_CAPACITY + 8] =
        [0; crate::linux_overlay::PATH_CAPACITY + 8];
    // SAFETY: the kernel-entry lock serializes /proc reads, and readers copy
    // the bytes before another read can rewrite them.
    let file = unsafe { &mut *core::ptr::addr_of_mut!(CGROUP_FILE) };
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = process_memcg(current_linux_process_pid())
        .and_then(|slot| cgroup_path(slot, &mut path))
        .unwrap_or(ROOT.len());
    let relative = path.get(ROOT.len()..length).unwrap_or_default();
    let mut output = Output::new(file);
    let written = output.push(b"0::")
        && output.push(if relative.is_empty() { b"/" } else { relative })
        && output.push(b"\n");
    let used = if written { output.len() } else { 0 };
    if used == 0 {
        return LINUX_PROC_CGROUP;
    }
    // SAFETY: as above.
    unsafe { &(&*core::ptr::addr_of!(CGROUP_FILE))[..used] }
}

/// The memory cgroup of the cgroup of directory generation `generation`
/// (0: the root).
fn memcg_of(generation: u32) -> Slot {
    cgroup::find(linux_execution_instance(), generation).unwrap_or(NO_SLOT)
}

/// The cgroup process `pid` is in: its memory cgroup, the domain's root
/// for one not placed yet.
fn process_memcg(pid: u32) -> Option<Slot> {
    match linux_process::live_process_memcg(pid)? {
        NO_SLOT => cgroup::root(linux_execution_instance()),
        slot => Some(slot),
    }
}

/// Whether a process is in cgroup `slot` or below it.
fn cgroup_populated(slot: Slot) -> bool {
    let root = cgroup::root(linux_execution_instance());
    linux_process::live_memcg_members(move |memcg| {
        let memcg = if memcg == NO_SLOT {
            root.unwrap_or(NO_SLOT)
        } else {
            memcg
        };
        cgroup::is_within(memcg, slot)
    })
    .next()
    .is_some()
}

/// Whether processes are in cgroup `slot` itself.
fn cgroup_has_processes(slot: Slot) -> bool {
    let root = cgroup::root(linux_execution_instance());
    linux_process::live_memcg_members(move |memcg| {
        memcg == slot || memcg == NO_SLOT && root == Some(slot)
    })
    .next()
    .is_some()
}

/// Tells watchers of the `cgroup.events` of cgroup `slot` and its
/// ancestors that whether it is populated may have changed.
fn notify_populated(slot: Slot) {
    let mut current = Some(slot);
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let mut file = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    while let Some(here) = current {
        if let Some(length) = cgroup_path(here, &mut path) {
            if let Some(events) = joined(&mut file, &path[..length], b"cgroup.events")
                .and_then(crate::linux_overlay::lookup)
            {
                linux_inotify_overlay_event(events.handle, crate::linux_inotify::IN_MODIFY);
            }
        }
        current = cgroup::parent(here);
    }
    wake_linux_descriptor_waits();
}

/// Places process `pid` in the cgroup of directory generation `generation`
/// (CLONE_INTO_CGROUP): false if that cgroup is gone.
pub(super) fn linux_assign_process_cgroup(pid: u32, generation: u32) -> bool {
    if generation == 0 {
        return true;
    }
    let slot = memcg_of(generation);
    if slot == NO_SLOT {
        return false;
    }
    if linux_process::replace_live_process_cgroup(pid, generation, slot).is_none() {
        return false;
    }
    notify_populated(slot);
    true
}

/// A process has ended: its cgroup may be empty now.
pub(super) fn linux_release_process_cgroup(pid: u32) {
    let slot = process_memcg(pid);
    if linux_process::replace_live_process_cgroup(pid, 0, NO_SLOT).is_some() {
        if let Some(slot) = slot {
            notify_populated(slot);
        }
    }
}

/// Rewrites control file `handle`'s contents from its cgroup's state
/// before it is read; nothing for any other file.
pub(super) fn linux_cgroup_refresh_control(handle: crate::linux_overlay::Handle) {
    let Some((slot, control)) = control_file(handle) else {
        return;
    };
    let mut bytes = [0_u8; PAGE_SIZE];
    let mut output = Output::new(&mut bytes);
    if !write_control(slot, control, &mut output) {
        return;
    }
    let length = output.len();
    let _ = crate::linux_overlay::truncate(handle, 0)
        && crate::linux_overlay::write(handle, 0, &bytes[..length]) == Some(length);
}

fn write_control(slot: Slot, control: Control, output: &mut Output<'_>) -> bool {
    let instance = linux_execution_instance();
    match control {
        Control::Procs => {
            let root = cgroup::root(instance);
            let mut written = true;
            for (pid, _) in linux_process::live_memcg_members(move |memcg| {
                memcg == slot || memcg == NO_SLOT && root == Some(slot)
            }) {
                written &= output.decimal(u64::from(pid)) && output.push(b"\n");
            }
            written
        }
        Control::Events => ginux_cgroup::write_cgroup_events(cgroup_populated(slot), output),
        Control::Controllers => cgroup::controllers(slot).write_names(output),
        Control::Subtree => cgroup::subtree_control(slot).write_names(output),
        Control::Kill | Control::MemoryReclaim => true,
        Control::Stat => {
            let mut descendants = 0_u64;
            let mut pending = [NO_SLOT; 64];
            let mut count = 0;
            pending[0] = slot;
            count += 1;
            while count != 0 {
                count -= 1;
                let here = pending[count];
                for child in cgroup::children(here) {
                    descendants += 1;
                    if count < pending.len() {
                        pending[count] = child;
                        count += 1;
                    }
                }
            }
            output.push(b"nr_descendants ")
                && output.decimal(descendants)
                && output.push(b"\nnr_dying_descendants 0\n")
        }
        Control::MemoryCurrent => ginux_cgroup::write_bytes(cgroup::usage(slot), output),
        Control::MemoryMin => {
            ginux_cgroup::write_memory_limit(cgroup::limit(slot, Limit::Min), output)
        }
        Control::MemoryLow => {
            ginux_cgroup::write_memory_limit(cgroup::limit(slot, Limit::Low), output)
        }
        Control::MemoryHigh => {
            ginux_cgroup::write_memory_limit(cgroup::limit(slot, Limit::High), output)
        }
        Control::MemoryMax => {
            ginux_cgroup::write_memory_limit(cgroup::limit(slot, Limit::Max), output)
        }
        Control::MemoryPeak => ginux_cgroup::write_bytes(cgroup::peak(slot, false), output),
        Control::MemoryEvents => {
            ginux_cgroup::write_memory_events(&cgroup::events(slot, false), output)
        }
        Control::MemoryEventsLocal => {
            ginux_cgroup::write_memory_events(&cgroup::events(slot, true), output)
        }
        Control::MemoryStat => ginux_cgroup::write_memory_stat(&cgroup::stat(slot), output),
        Control::MemoryOomGroup => output.push(if cgroup::oom_group(slot) {
            b"1\n"
        } else {
            b"0\n"
        }),
        Control::SwapCurrent => ginux_cgroup::write_bytes(cgroup::swap_usage(slot), output),
        Control::SwapHigh => {
            ginux_cgroup::write_memory_limit(cgroup::limit(slot, Limit::SwapHigh), output)
        }
        Control::SwapMax => {
            ginux_cgroup::write_memory_limit(cgroup::limit(slot, Limit::SwapMax), output)
        }
        Control::SwapPeak => ginux_cgroup::write_bytes(cgroup::peak(slot, true), output),
        Control::SwapEvents => {
            let [high, max, fail] = cgroup::swap_events(slot);
            ginux_cgroup::write_swap_events(high, max, fail, output)
        }
    }
}

fn rules_error(error: ginux_cgroup::Error) -> u64 {
    match error {
        ginux_cgroup::Error::Invalid => LINUX_EINVAL,
        ginux_cgroup::Error::NotAvailable => LINUX_ENOENT,
        ginux_cgroup::Error::Busy => LINUX_EBUSY,
    }
}

/// Applies a write of `input` to control file `handle`: Some(the count or
/// an error) for a control file, None for any other file.
pub(super) fn linux_cgroup_control_write(
    handle: crate::linux_overlay::Handle,
    input: &[u8],
) -> Option<u64> {
    let (slot, control) = control_file(handle)?;
    Some(match apply_control(slot, control, input) {
        Ok(()) => input.len() as u64,
        Err(error) => error,
    })
}

/// `linux_cgroup_control_write` for `count` bytes at user `address`; a
/// control file's write is one page at most, as kernfs takes it.
pub(super) fn linux_cgroup_user_write(
    handle: crate::linux_overlay::Handle,
    address: u64,
    count: usize,
) -> Option<u64> {
    control_file(handle)?;
    let mut input = [0_u8; PAGE_SIZE];
    let length = count.min(input.len());
    if !copy_from_linux_user(address, &mut input[..length]) {
        return Some(LINUX_EFAULT);
    }
    linux_cgroup_control_write(handle, &input[..length])
}

fn apply_control(slot: Slot, control: Control, input: &[u8]) -> Result<(), u64> {
    match control {
        Control::Procs => move_process(slot, ginux_cgroup::parse_pid(input).map_err(rules_error)?),
        Control::Subtree => change_subtree_control(slot, input),
        Control::Kill => {
            if trimmed(input) != b"1" {
                return Err(LINUX_ERANGE);
            }
            for (pid, _) in
                linux_process::live_memcg_members(move |memcg| cgroup::is_within(memcg, slot))
            {
                let _ = linux_queue_process_signal(pid, LINUX_SIGKILL, LINUX_SI_KERNEL, None);
            }
            Ok(())
        }
        Control::MemoryMin => set_limit(slot, Limit::Min, input),
        Control::MemoryLow => set_limit(slot, Limit::Low, input),
        Control::SwapHigh => set_limit(slot, Limit::SwapHigh, input),
        Control::SwapMax => set_limit(slot, Limit::SwapMax, input),
        Control::MemoryHigh => {
            set_limit(slot, Limit::High, input)?;
            let high = cgroup::limit(slot, Limit::High);
            let excess = cgroup::usage(slot).saturating_sub(high);
            if excess != 0 {
                let _ = linux_memcg_reclaim(slot, excess, 0);
            }
            Ok(())
        }
        Control::MemoryMax => {
            set_limit(slot, Limit::Max, input)?;
            enforce_max(slot);
            Ok(())
        }
        Control::MemoryPeak => {
            cgroup::reset_peak(slot, false);
            Ok(())
        }
        Control::SwapPeak => {
            cgroup::reset_peak(slot, true);
            Ok(())
        }
        Control::MemoryOomGroup => match trimmed(input) {
            b"0" => cgroup::set_oom_group(slot, false)
                .then_some(())
                .ok_or(LINUX_EINVAL),
            b"1" => cgroup::set_oom_group(slot, true)
                .then_some(())
                .ok_or(LINUX_EINVAL),
            _ => Err(LINUX_EINVAL),
        },
        Control::MemoryReclaim => {
            // "N[KMG] [swappiness=...]": the amount to reclaim comes first.
            let amount = trimmed(input)
                .split(|byte| byte.is_ascii_whitespace())
                .next()
                .unwrap_or_default();
            let pages = ginux_cgroup::parse_memory_limit(amount).map_err(rules_error)?;
            if pages == 0 || linux_memcg_reclaim(slot, pages, 0) >= pages {
                Ok(())
            } else {
                Err(LINUX_EAGAIN)
            }
        }
        Control::Events
        | Control::Controllers
        | Control::Stat
        | Control::MemoryCurrent
        | Control::MemoryEvents
        | Control::MemoryEventsLocal
        | Control::MemoryStat
        | Control::SwapCurrent
        | Control::SwapEvents => Err(LINUX_EINVAL),
    }
}

fn trimmed(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |end| end + 1);
    &input[start..end.max(start)]
}

fn set_limit(slot: Slot, limit: Limit, input: &[u8]) -> Result<(), u64> {
    let pages = ginux_cgroup::parse_memory_limit(input).map_err(rules_error)?;
    cgroup::set_limit(slot, limit, pages)
        .then_some(())
        .ok_or(LINUX_ENODEV)
}

/// A lowered `memory.max`: reclaim down to it, and if that is not enough
/// kill within the cgroup (Linux's memory_max_write).
fn enforce_max(slot: Slot) {
    for _ in 0..RECLAIM_RETRIES {
        let max = cgroup::limit(slot, Limit::Max);
        let usage = cgroup::usage(slot);
        if usage <= max {
            return;
        }
        cgroup::note_event(slot, Event::Max);
        if linux_memcg_reclaim(slot, usage - max, 0) == 0 {
            // The victim's memory is freed as it ends.
            cgroup::note_event(slot, Event::Oom);
            let _ = linux_memcg_oom_kill(slot, 0);
            return;
        }
    }
}

/// Moves process `pid` (the writer for 0) into cgroup `slot`.
fn move_process(slot: Slot, pid: u32) -> Result<(), u64> {
    let pid = if pid == 0 {
        current_linux_process_pid()
    } else {
        pid
    };
    if linux_process::live_process_status(pid)
        .is_none_or(|status| status.state == linux_process::LiveProcessState::Zombie)
    {
        return Err(LINUX_ESRCH);
    }
    ginux_cgroup::may_hold_processes(cgroup::is_root(slot), cgroup::subtree_control(slot))
        .map_err(rules_error)?;
    let generation = if cgroup::is_root(slot) {
        0
    } else {
        cgroup::directory(slot).ok_or(LINUX_ENODEV)?
    };
    let previous = process_memcg(pid);
    linux_process::replace_live_process_cgroup(pid, generation, slot).ok_or(LINUX_ESRCH)?;
    if let Some(previous) = previous {
        notify_populated(previous);
    }
    notify_populated(slot);
    Ok(())
}

fn change_subtree_control(slot: Slot, input: &[u8]) -> Result<(), u64> {
    let change = ginux_cgroup::parse_subtree_control(input).map_err(rules_error)?;
    let children_delegate = cgroup::children(slot).fold(Controllers::NONE, |all, child| {
        all.union(cgroup::subtree_control(child))
    });
    let state = ginux_cgroup::SubtreeState {
        current: cgroup::subtree_control(slot),
        available: cgroup::controllers(slot),
        root: cgroup::is_root(slot),
        has_processes: cgroup_has_processes(slot),
        children_delegate,
    };
    let updated = ginux_cgroup::apply_subtree_change(state, change).map_err(rules_error)?;
    if !cgroup::set_subtree_control(slot, updated) {
        return Err(LINUX_ENODEV);
    }
    // The children gain or lose the memory controller's files.
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    for child in cgroup::children(slot) {
        if let Some(length) = cgroup_path(child, &mut path) {
            if !sync_control_files(child, &path[..length]) {
                return Err(LINUX_ENOSPC);
            }
        }
    }
    Ok(())
}

/// Charges `pages` user pages about to be allocated to the current
/// process's memory cgroup: Some(the cgroup's slot), or Some(0) outside a
/// domain; None when the cgroup's limit refuses them after reclaim and the
/// current process was chosen to die for them.
pub(crate) fn charge_linux_user_pages(pages: u64) -> Option<u16> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || current_linux_thread_handle().is_none()
    {
        return Some(NO_SLOT);
    }
    let pid = current_linux_process_pid();
    let Some(slot) = process_memcg(pid) else {
        return Some(NO_SLOT);
    };
    let mut retries = 0;
    loop {
        let Err(over) = cgroup::try_charge(slot, pages) else {
            return Some(slot);
        };
        cgroup::note_event(over, Event::Max);
        if retries < RECLAIM_RETRIES && linux_memcg_reclaim(over, pages, pid) != 0 {
            retries += 1;
            continue;
        }
        cgroup::note_event(over, Event::Oom);
        return match linux_memcg_oom_kill(over, pid) {
            // Another process dies for the memory: this charge goes on
            // while its pages are freed.
            Some(victim) if victim != pid => {
                cgroup::force_charge(slot, pages);
                Some(slot)
            }
            _ => None,
        };
    }
}

/// The memory cgroup a page-cache or shared-memory page brought in now is
/// charged to: the current process's, or none outside a domain's process.
pub(crate) fn linux_cache_charge_slot() -> Option<u16> {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || current_linux_thread_handle().is_none()
    {
        return None;
    }
    process_memcg(current_linux_process_pid())
}

/// Reclaims what the current domain's other processes may give up when
/// the machine is short of memory: true if anything was.
pub(crate) fn reclaim_linux_user_pages(pages: u64) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || current_linux_thread_handle().is_none()
    {
        return false;
    }
    // Nothing to take, nothing to scan for: a machine short of frames asks
    // at every allocation.
    if !cgroup::reclaimable()
        && !crate::linux_swap::available(linux_execution_instance())
        && !(crate::sync::rank_available(crate::sync::LockRank::VOLUMES)
            && crate::linux_blockfs::any_cached())
    {
        return false;
    }
    let reclaimed = cgroup::root(linux_execution_instance())
        .is_some_and(|root| linux_memcg_reclaim(root, pages, current_linux_process_pid()) != 0);
    if !reclaimed {
        cgroup::clear_reclaimable();
    }
    reclaimed
}

/// Whether process `pid`'s page tables may be changed from here: it is not
/// running on a CPU (whose translations of them would go stale).
fn linux_process_quiescent(pid: u32) -> bool {
    pid != current_linux_process_pid()
        && linux_live_process_bank(pid, linux_execution_instance()).is_none()
}

/// Reclaims up to `pages` pages from the processes of cgroup `slot` and
/// below it, other than `except` and any running on a CPU: what they mapped
/// droppable (MAP_DROPPABLE), what they freed lazily (MADV_FREE) and have
/// not written since, then their private anonymous pages, paged out to
/// swap. The current process gives up its own pages too when nothing of
/// its own is in use by the kernel (`except` 0, a control file's write, or
/// a user page fault: `linux_own_pages_reclaimable`). The count reclaimed.
pub(super) fn linux_memcg_reclaim(slot: Slot, pages: u64, except: u32) -> u64 {
    let instance = linux_execution_instance();
    let root = cgroup::root(instance).unwrap_or(NO_SLOT);
    let mut members = [0_u32; 64];
    let mut count = 0;
    let mut running = [0_u32; 64];
    let mut running_count = 0;
    let current = current_linux_process_pid();
    for (pid, _) in linux_process::live_memcg_members(move |memcg| {
        cgroup::is_within(if memcg == NO_SLOT { root } else { memcg }, slot)
    }) {
        if pid == except || pid == current {
            continue;
        }
        if linux_process_quiescent(pid) {
            if count < members.len() {
                members[count] = pid;
                count += 1;
            }
        } else if running_count < running.len() {
            running[running_count] = pid;
            running_count += 1;
        }
    }
    // Clean page cache goes first: it costs no I/O to drop.
    let mut reclaimed = linux_reclaim_page_cache(slot, pages, false);
    for pid in &members[..count] {
        if reclaimed >= pages {
            break;
        }
        reclaimed += linux_reclaim_process_pages(instance, *pid, pages - reclaimed);
    }
    // A process running user code on another CPU can still have pages
    // paged out: each leaf is made non-present and that CPU's translation
    // shot down before the page is copied, and the kernel-entry lock keeps
    // its threads out of the kernel meanwhile. (Dropping its pages is left
    // to when it stops: its registry lists change with them.)
    for pid in &running[..running_count] {
        if reclaimed >= pages {
            break;
        }
        if let Some(root) = linux_process::live_process_root(*pid) {
            reclaimed += address_space::with_live_linux_process_root(root, || {
                linux_swap_out_current(*pid, pages - reclaimed)
            })
            .unwrap_or(0);
        }
    }
    if reclaimed < pages
        && (except == 0 || except == current && linux_own_pages_reclaimable())
        && process_memcg(current).is_some_and(|memcg| cgroup::is_within(memcg, slot))
    {
        reclaimed += linux_reclaim_active_pages(current, pages - reclaimed);
    }
    // Nothing above the cgroups' memory.low: their page cache goes below
    // it, each such cgroup counting a low event, as Linux's second pass.
    if reclaimed == 0 {
        reclaimed += linux_reclaim_page_cache(slot, pages, true);
    }
    // Last, the swap cache's copies of pages still in swap.
    if reclaimed < pages {
        reclaimed += crate::linux_swap::shrink_cache(instance, pages - reclaimed, |memcg| {
            cgroup::is_within(if memcg == NO_SLOT { root } else { memcg }, slot)
        });
    }
    if reclaimed != 0 {
        cgroup::note_reclaimed(slot, reclaimed);
    }
    reclaimed
}

/// A cgroup of a reclaim's subtree, with the protection memory.min and
/// memory.low give it against that reclaim.
struct LinuxMemcgProtection {
    slot: Slot,
    usage: u64,
    min: u64,
    low: u64,
}

/// Each cgroup of `root`'s subtree, root first, with its effective
/// protection as Linux's mem_cgroup_calculate_protection works it out
/// (without memory_recursiveprot): a child of the root has its own
/// memory.min and memory.low; one further down, the part of its usage its
/// setting covers, scaled down when its siblings' protected usage overruns
/// what their parent is protected for (effective_protection).
fn linux_memcg_protection(root: Slot) -> Vec<LinuxMemcgProtection> {
    fn effective(usage: u64, setting: u64, parent: u64, siblings: u64) -> u64 {
        let protected = usage.min(setting);
        if siblings > parent && siblings != 0 {
            (u128::from(protected) * u128::from(parent) / u128::from(siblings)) as u64
        } else {
            protected
        }
    }
    fn visit(node: Slot, root: Slot, min: u64, low: u64, out: &mut Vec<LinuxMemcgProtection>) {
        let mut children = Vec::new();
        for child in cgroup::children(node) {
            if children.try_reserve(1).is_err() {
                return;
            }
            children.push(child);
        }
        let protected = |limit: Limit| -> u64 {
            children
                .iter()
                .map(|child| cgroup::usage(*child).min(cgroup::limit(*child, limit)))
                .sum()
        };
        let (min_sum, low_sum) = (protected(Limit::Min), protected(Limit::Low));
        for child in children {
            let usage = cgroup::usage(child);
            let (child_min, child_low) = (
                cgroup::limit(child, Limit::Min),
                cgroup::limit(child, Limit::Low),
            );
            let (emin, elow) = if node == root {
                (child_min, child_low)
            } else {
                (
                    effective(usage, child_min, min, min_sum),
                    effective(usage, child_low, low, low_sum),
                )
            };
            if out.try_reserve(1).is_err() {
                return;
            }
            out.push(LinuxMemcgProtection {
                slot: child,
                usage,
                min: emin,
                low: elow,
            });
            visit(child, root, emin, elow, out);
        }
    }
    let mut out = Vec::new();
    if out.try_reserve(1).is_ok() {
        out.push(LinuxMemcgProtection {
            slot: root,
            usage: cgroup::usage(root),
            min: 0,
            low: 0,
        });
        visit(root, root, 0, 0, &mut out);
    }
    out
}

/// Where the next page-cache reclaim starts among a subtree's cgroups, so
/// successive ones spread over them, as Linux's reclaim walks every memcg.
static LINUX_CACHE_RECLAIM_ROTOR: AtomicU32 = AtomicU32::new(0);

/// Drops up to `pages` (at least a cluster) of the clean page cache charged
/// to the cgroups of `slot`'s subtree, none below its effective memory.min,
/// nor below its memory.low unless `below_low`, when each cgroup reclaimed
/// below it counts a low event (memory.events). The count dropped.
fn linux_reclaim_page_cache(slot: Slot, pages: u64, below_low: bool) -> u64 {
    const CLUSTER: u64 = 32;
    let budget = pages.max(CLUSTER);
    let root = cgroup::root(linux_execution_instance()).unwrap_or(NO_SLOT);
    let cgroups = linux_memcg_protection(slot);
    if cgroups.is_empty() {
        return 0;
    }
    let start = LINUX_CACHE_RECLAIM_ROTOR.fetch_add(1, Ordering::Relaxed) as usize % cgroups.len();
    let mut dropped = 0;
    for index in (start..cgroups.len()).chain(0..start) {
        if dropped >= budget {
            break;
        }
        let cgroup = &cgroups[index];
        let protection = if below_low {
            cgroup.min
        } else {
            cgroup.min.max(cgroup.low)
        };
        let room = cgroup.usage.saturating_sub(protection);
        if room == 0 {
            continue;
        }
        let wanted = cgroup.slot;
        let taken =
            crate::linux_blockfs::reclaim_page_cache((budget - dropped).min(room), |memcg| {
                (if memcg == NO_SLOT { root } else { memcg }) == wanted
            });
        if taken != 0 && below_low && cgroup.usage <= cgroup.low {
            cgroup::note_event(cgroup.slot, Event::Low);
        }
        dropped += taken;
    }
    dropped
}

/// Reclaims up to `budget` pages of process `pid`, which is not running.
fn linux_reclaim_process_pages(_instance: usize, pid: u32, budget: u64) -> u64 {
    let Some(root) = linux_process::live_process_root(pid) else {
        return 0;
    };
    address_space::with_live_linux_process_root(root, || linux_reclaim_active_pages(pid, budget))
        .unwrap_or(0)
}

/// Reclaims up to `budget` pages of process `pid`, whose address space is
/// the active one: droppable pages and lazily freed ones first, which cost
/// no I/O, then pages paged out to swap.
fn linux_reclaim_active_pages(pid: u32, budget: u64) -> u64 {
    let instance = linux_execution_instance();
    let mut reclaimed = if cgroup::reclaimable() {
        linux_drop_active_pages(instance, pid, budget)
    } else {
        0
    };
    if reclaimed < budget {
        reclaimed += linux_swap_out_current(pid, budget - reclaimed);
    }
    reclaimed
}

/// Drops up to `budget` droppable or lazily freed pages of process `pid`,
/// whose address space is the active one.
fn linux_drop_active_pages(instance: usize, pid: u32, budget: u64) -> u64 {
    let Some(areas) = crate::linux_areas::snapshot(instance, pid) else {
        return 0;
    };
    let mut ranges = [(0_u64, 0_u64); 32];
    let mut count = 0;
    for area in areas.iter() {
        if area.backing == crate::linux_areas::Backing::Droppable && count < ranges.len() {
            ranges[count] = (area.start, area.end);
            count += 1;
        }
    }
    let mut reclaimed = 0;
    for (start, end) in &ranges[..count] {
        let mut page = *start;
        while page < *end && reclaimed < budget {
            if linux_drop_private_page(page) {
                reclaimed += 1;
            }
            page += PAGE_SIZE as u64;
        }
    }
    if reclaimed < budget {
        reclaimed += linux_reclaim_lazyfree_pages(budget - reclaimed);
    }
    if reclaimed != 0 {
        // The registry's list of the process's pages is out of date; its
        // release reads its page tables instead.
        let _ = linux_process::mark_live_process_address_space_stale(pid);
    }
    reclaimed
}

/// Takes the frame of the active address space's private page at `address`
/// and leaves the page reserved, so its next touch reads zeros, as
/// MADV_DONTNEED does. False for a page with no frame of its own.
fn linux_drop_private_page(address: u64) -> bool {
    let state = address_space::current_linux_runtime_page(address);
    let Some(frame) = state.frame else {
        return false;
    };
    if !state.occupied || state.shared || state.file || state.sealed {
        return false;
    }
    let removed = address_space::remove_current_linux_runtime_page(address);
    if removed.frame != Some(frame)
        || address_space::reserve_current_linux_runtime_page(
            address,
            state.protection,
            false,
            false,
        ) != Some(None)
    {
        return false;
    }
    if state.dontfork {
        let _ = address_space::set_current_linux_runtime_page_dontfork(address, true);
    }
    if state.wipeonfork {
        let _ = address_space::set_current_linux_runtime_page_wipeonfork(address, true);
    }
    release_linux_runtime_frame(frame)
}

/// Drops up to `budget` of the active address space's lazily freed pages
/// that were not written since MADV_FREE.
fn linux_reclaim_lazyfree_pages(budget: u64) -> u64 {
    let mut reclaimed = 0;
    let mut pages = [0_u64; 64];
    loop {
        let found = address_space::current_linux_lazyfree_pages(&mut pages);
        if found == 0 {
            return reclaimed;
        }
        let mut progress = false;
        for address in &pages[..found] {
            if reclaimed >= budget {
                return reclaimed;
            }
            if linux_drop_private_page(*address) {
                reclaimed += 1;
                progress = true;
            }
        }
        if !progress {
            return reclaimed;
        }
    }
}

/// Kills the process of cgroup `slot` or below it that holds the most
/// memory (Linux's oom_badness), or every process of the cgroup when its
/// `memory.oom.group` says so: the victim's pid. `current` (0 for none) is
/// the process charging, which may be the one chosen.
pub(super) fn linux_memcg_oom_kill(slot: Slot, current: u32) -> Option<u32> {
    let instance = linux_execution_instance();
    let root = cgroup::root(instance).unwrap_or(NO_SLOT);
    let within = |memcg: Slot| cgroup::is_within(if memcg == NO_SLOT { root } else { memcg }, slot);
    // A victim already dying frees what is wanted: no other is killed.
    if let Some(victim) = linux_process::live_memcg_members(within)
        .map(|(pid, _)| pid)
        .find(|pid| linux_process::live_process_killed(*pid))
    {
        return Some(victim);
    }
    let total = memory::frame_counts().map_or(0, |(total, _)| total);
    let mut candidates = [(0_u32, None::<i64>); 64];
    let mut count = 0;
    for (pid, oom_score_adj) in linux_process::live_memcg_members(within) {
        if pid == 1 || count >= candidates.len() {
            continue;
        }
        let resident = if pid == current {
            Some(address_space::current_linux_resident_pages())
        } else {
            linux_process::live_process_root(pid).and_then(|root| {
                address_space::with_live_linux_process_root(
                    root,
                    address_space::current_linux_resident_pages,
                )
            })
        };
        candidates[count] = (
            pid,
            ginux_cgroup::oom_badness(resident.unwrap_or(0), 0, 0, oom_score_adj, total),
        );
        count += 1;
    }
    let victim = ginux_cgroup::choose_oom_victim(candidates[..count].iter().copied())?;
    let victim_memcg = process_memcg(victim).unwrap_or(slot);
    let group = cgroup::oom_group(victim_memcg);
    serial_write("ginux: memory cgroup out of memory: killed process ");
    serial_write_u64(u64::from(victim));
    serial_write("\r\n");
    if group {
        cgroup::note_event(slot, Event::OomGroupKill);
        for (pid, _) in linux_process::live_memcg_members(move |memcg| memcg == victim_memcg) {
            if pid != current {
                let _ = linux_queue_process_signal(pid, LINUX_SIGKILL, LINUX_SI_KERNEL, None);
            }
            cgroup::note_event(slot, Event::OomKill);
            linux_process::note_live_process_killed(pid);
        }
    } else {
        if victim != current {
            let _ = linux_queue_process_signal(victim, LINUX_SIGKILL, LINUX_SI_KERNEL, None);
        }
        cgroup::note_event(slot, Event::OomKill);
        linux_process::note_live_process_killed(victim);
    }
    Some(victim)
}
