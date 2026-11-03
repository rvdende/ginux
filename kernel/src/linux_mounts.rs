//! The filesystems a domain's processes mount on top of its root, with the
//! options that matter to the system calls that later touch paths under
//! them: a read-only mount makes every change below it fail with EROFS.
//!
//! The root, /proc and /sys/fs/cgroup are the kernel's own and are not
//! listed here. Mounts are kept per domain rather than per mount namespace;
//! a filesystem mounted over a directory shows whatever the overlay holds
//! beneath it, and unmounting a tmpfs drops what was created there.
//! /proc/PID/mountinfo does not list them yet.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};

/// Changes below the mount fail with EROFS (MS_RDONLY).
pub(crate) const READ_ONLY: u32 = 1 << 0;
/// Set-user-ID and set-group-ID bits are ignored (MS_NOSUID).
pub(crate) const NO_SUID: u32 = 1 << 1;
/// Device files cannot be opened (MS_NODEV).
pub(crate) const NO_DEVICES: u32 = 1 << 2;
/// Programs cannot be executed (MS_NOEXEC).
pub(crate) const NO_EXEC: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The path is not a mount point (EINVAL).
    NotMounted,
    /// The table could not grow (ENOMEM).
    NoMemory,
}

/// One mount: where, of what, and with which options.
pub(crate) struct Mount {
    instance: usize,
    pub(crate) id: u32,
    /// The canonical mount point, without a leading slash.
    pub(crate) path: Vec<u8>,
    pub(crate) filesystem: Vec<u8>,
    pub(crate) flags: u32,
}

struct Mounts {
    mounts: Vec<Mount>,
    /// How often each domain's mount table changed (mount, remount,
    /// unmount): a /proc/mounts reader that saw an older count is told of
    /// the change (POLLPRI).
    changes: Vec<(usize, u32)>,
    /// Ids continue after the kernel's own mounts (root, /proc, cgroup).
    next_id: u32,
}

static MOUNTS: SpinLock<Mounts> = SpinLock::new(
    LockRank::MOUNTS,
    Mounts {
        mounts: Vec::new(),
        changes: Vec::new(),
        next_id: 4,
    },
);

fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

/// Mounts `filesystem` at canonical `path` in `instance`, on top of
/// whatever is mounted there; returns the mount's id.
pub(crate) fn mount(
    instance: usize,
    path: &[u8],
    filesystem: &[u8],
    flags: u32,
) -> Result<u32, Error> {
    let mount = Mount {
        instance,
        id: 0,
        path: copy(path)?,
        filesystem: copy(filesystem)?,
        flags,
    };
    let mut table = MOUNTS.lock();
    table.mounts.try_reserve(1).map_err(|_| Error::NoMemory)?;
    let id = table.next_id;
    table.next_id = id.wrapping_add(1);
    table.mounts.push(Mount { id, ..mount });
    changed(&mut table, instance);
    Ok(id)
}

/// The topmost mount at canonical `path` in `instance`, as an index.
fn topmost(table: &Mounts, instance: usize, path: &[u8]) -> Option<usize> {
    table
        .mounts
        .iter()
        .rposition(|mount| mount.instance == instance && mount.path == path)
}

/// Changes the options of the topmost mount at canonical `path`
/// (MS_REMOUNT).
pub(crate) fn remount(instance: usize, path: &[u8], flags: u32) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let index = topmost(&table, instance, path).ok_or(Error::NotMounted)?;
    table.mounts[index].flags = flags;
    changed(&mut table, instance);
    Ok(())
}

/// Removes the topmost mount at canonical `path` and returns its filesystem
/// type.
pub(crate) fn unmount(instance: usize, path: &[u8]) -> Result<Vec<u8>, Error> {
    let mut table = MOUNTS.lock();
    let index = topmost(&table, instance, path).ok_or(Error::NotMounted)?;
    let filesystem = table.mounts.remove(index).filesystem;
    changed(&mut table, instance);
    Ok(filesystem)
}

/// Counts a change to `instance`'s mount table.
fn changed(table: &mut Mounts, instance: usize) {
    if let Some((_, count)) = table
        .changes
        .iter_mut()
        .find(|(owner, _)| *owner == instance)
    {
        *count = count.wrapping_add(1);
    } else if table.changes.try_reserve(1).is_ok() {
        table.changes.push((instance, 1));
    }
}

/// How often `instance`'s mount table has changed.
pub(crate) fn changes(instance: usize) -> u32 {
    MOUNTS
        .lock()
        .changes
        .iter()
        .find(|(owner, _)| *owner == instance)
        .map_or(0, |(_, count)| *count)
}

/// Something is mounted at canonical `path`.
pub(crate) fn is_mount_point(instance: usize, path: &[u8]) -> bool {
    topmost(&MOUNTS.lock(), instance, path).is_some()
}

/// The options of the mount canonical `path` lies on: the deepest mount
/// point at or above it (0 for the root's own files).
pub(crate) fn flags_at(instance: usize, path: &[u8]) -> u32 {
    let table = MOUNTS.lock();
    table
        .mounts
        .iter()
        .filter(|mount| mount.instance == instance && covers(&mount.path, path))
        .max_by_key(|mount| (mount.path.len(), mount.id))
        .map_or(0, |mount| mount.flags)
}

/// The id of the mount canonical `path` lies on: the deepest mount point
/// at or above it (0 for the root's own files). Two paths on different
/// mounts cannot be linked or renamed into one another (EXDEV).
pub(crate) fn mount_id_at(instance: usize, path: &[u8]) -> u32 {
    let table = MOUNTS.lock();
    table
        .mounts
        .iter()
        .filter(|mount| mount.instance == instance && covers(&mount.path, path))
        .max_by_key(|mount| (mount.path.len(), mount.id))
        .map_or(0, |mount| mount.id)
}

/// `path` is the mount point `point` or lies below it.
fn covers(point: &[u8], path: &[u8]) -> bool {
    point.is_empty()
        || path
            .strip_prefix(point)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
}

/// Drops `instance`'s mounts when its domain stops.
pub(crate) fn forget_instance(instance: usize) {
    let mut table = MOUNTS.lock();
    table.mounts.retain(|mount| mount.instance != instance);
    table.changes.retain(|(owner, _)| *owner != instance);
}
