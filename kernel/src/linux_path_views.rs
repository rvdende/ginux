//! The mount each process reached its open directories and files through,
//! for the paths it is shown: getcwd, /proc/self/fd and /proc/self/cwd,
//! and the start of a walk relative to a directory.
//!
//! Linux keeps a (mount, dentry) pair for each. Ginux's descriptors and
//! working directory keep the file only (an image handle or an overlay
//! node), whose own path is its storage path: through a bind mount of
//! /etc on /mnt/x, /mnt/x/hosts opens the image's etc/hosts, whose path is
//! /etc/hosts. This table adds the mount: for each file a process reached
//! through a mount that leads elsewhere, that mount's point and target,
//! so the file shows as the point followed by its path below the target.
//! A file whose path is no longer below the target (renamed away) shows
//! by its own path again.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

/// The file a view is of.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Key {
    /// An image file, by its handle.
    Image(u16),
    /// An overlay node, by its generation.
    Overlay(u32),
}

struct View {
    instance: usize,
    pid: u32,
    key: Key,
    /// The mount point, canonical (no leading slash).
    point: Vec<u8>,
    /// The storage path the mount point leads to.
    target: Vec<u8>,
}

/// The views a process keeps at most; the oldest goes first.
const PROCESS_LIMIT: usize = 64;

static VIEWS: SpinLock<Vec<View>> = SpinLock::new(LockRank::PATH_VIEWS, Vec::new());
/// How many views there are: none spares every path the table.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Whether any process has a view: none spares every path the table.
pub(crate) fn any() -> bool {
    COUNT.load(Ordering::Relaxed) != 0
}

fn copy(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len()).ok()?;
    copied.extend_from_slice(bytes);
    Some(copied)
}

/// Records that `pid` reached `key`'s file through the mount at `point`
/// that leads to `target`, or (`None`) through no such mount.
pub(crate) fn record(instance: usize, pid: u32, key: Key, mount: Option<(&[u8], &[u8])>) {
    if mount.is_none() && COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }
    let view = mount.and_then(|(point, target)| {
        Some(View {
            instance,
            pid,
            key,
            point: copy(point)?,
            target: copy(target)?,
        })
    });
    let mut views = VIEWS.lock();
    views.retain(|view| view.instance != instance || view.pid != pid || view.key != key);
    if let Some(view) = view {
        let held = views
            .iter()
            .filter(|view| view.instance == instance && view.pid == pid)
            .count();
        if held >= PROCESS_LIMIT {
            if let Some(oldest) = views
                .iter()
                .position(|view| view.instance == instance && view.pid == pid)
            {
                views.remove(oldest);
            }
        }
        if views.try_reserve(1).is_ok() {
            views.push(view);
        }
    }
    COUNT.store(views.len(), Ordering::Relaxed);
}

/// The path `pid` is shown for `key`'s file, whose own (storage) path is
/// `stored`: through the mount it reached it by, if `stored` is still
/// below that mount's target. None to show `stored` itself.
pub(crate) fn shown(instance: usize, pid: u32, key: Key, stored: &[u8]) -> Option<Vec<u8>> {
    if COUNT.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let views = VIEWS.lock();
    let view = views
        .iter()
        .find(|view| view.instance == instance && view.pid == pid && view.key == key)?;
    let rest = if view.target.is_empty() {
        stored
    } else {
        match stored.strip_prefix(view.target.as_slice())? {
            [] => &[][..],
            [b'/', rest @ ..] => rest,
            _ => return None,
        }
    };
    let mut path = Vec::new();
    path.try_reserve_exact(view.point.len() + 1 + rest.len())
        .ok()?;
    path.extend_from_slice(&view.point);
    if !view.point.is_empty() && !rest.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(rest);
    Some(path)
}

/// Gives forked `child` the views of `parent` (and none another process
/// that had its pid left).
pub(crate) fn fork(instance: usize, parent: u32, child: u32) {
    if COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut views = VIEWS.lock();
    views.retain(|view| view.instance != instance || view.pid != child);
    let mut copies = Vec::new();
    for view in views
        .iter()
        .filter(|view| view.instance == instance && view.pid == parent)
    {
        let (Some(point), Some(target)) = (copy(&view.point), copy(&view.target)) else {
            continue;
        };
        if copies.try_reserve(1).is_err() {
            break;
        }
        copies.push(View {
            instance,
            pid: child,
            key: view.key,
            point,
            target,
        });
    }
    if views.try_reserve(copies.len()).is_ok() {
        views.extend(copies);
    }
    COUNT.store(views.len(), Ordering::Relaxed);
}

/// Drops `pid`'s views (it ended).
pub(crate) fn forget(instance: usize, pid: u32) {
    if COUNT.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut views = VIEWS.lock();
    views.retain(|view| view.instance != instance || view.pid != pid);
    COUNT.store(views.len(), Ordering::Relaxed);
}

/// Drops domain `instance`'s views (it stopped).
pub(crate) fn forget_instance(instance: usize) {
    let mut views = VIEWS.lock();
    views.retain(|view| view.instance != instance);
    COUNT.store(views.len(), Ordering::Relaxed);
}
