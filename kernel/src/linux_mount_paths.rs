//! Where a path leads through a domain's mounts: the storage path of the
//! file a process's path names.
//!
//! The root filesystem's files are stored at the paths processes see. A
//! filesystem mounted on top of it (a tmpfs, a volume, an overlay) is
//! stored elsewhere, below a storage root of its own that no process can
//! name: one component, a NUL byte and the filesystem's number
//! ([`storage_root`]). A mount leads its mount point to a place in some
//! filesystem's storage, its target: a new filesystem's root, or for a
//! bind mount the source directory's storage path (which is a plain path
//! for the root filesystem). Paths a mount does not lead anywhere (the
//! root, /proc, sysfs, devtmpfs) are their own storage paths.
//!
//! Which mount a path is on follows Linux's mount tree, not the deepest
//! mount point: the walk starts at the root mount and, at each mount,
//! crosses into the child mounted at the first mount point the path passes
//! (the topmost one there: mounts on one point stack, each on the one
//! before), so a mount hidden under a later one leads nowhere until that
//! one goes. [`crate::linux_mounts`] publishes each namespace's tree here
//! whenever it changes; this table ranks above the locks of the tables
//! whose holders make files, since every path a file call is given passes
//! through [`storage`].
//!
//! [`crate::linux_overlay`] turns paths into storage paths as calls come
//! in, and storage paths back into paths ([`visible`]) for the paths it
//! gives out (a descriptor's, a working directory's).
#![forbid(unsafe_code)]

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::linux_mounts::Space;
use crate::sync::{LockRank, SpinLock};

/// One mount, as path resolution needs it.
pub(crate) struct Route {
    pub(crate) space: Space,
    pub(crate) id: u32,
    pub(crate) parent: u32,
    /// The canonical mount point.
    pub(crate) point: Vec<u8>,
    /// The storage path the mount point leads to, or `None` for a mount
    /// whose files are found by the paths themselves.
    pub(crate) target: Option<Vec<u8>>,
}

static ROUTES: SpinLock<Vec<Route>> = SpinLock::new(LockRank::MOUNT_ROUTES, Vec::new());
/// How many routes lead somewhere, across all domains: none spares every
/// path the table.
static REDIRECTS: AtomicUsize = AtomicUsize::new(0);
/// How many routes lead to a root filesystem path (bind mounts of its
/// directories), across all domains.
static ROOT_BINDS: AtomicUsize = AtomicUsize::new(0);

/// The id of the root mount (`crate::linux_mounts::ROOT_ID`).
const ROOT_ID: u32 = crate::linux_mounts::ROOT_ID;

/// The storage root of filesystem number `number`.
pub(crate) fn storage_root(number: u32) -> Vec<u8> {
    let mut root = Vec::new();
    root.push(0);
    let mut digits = [0_u8; 10];
    let mut value = number;
    let mut count = 0;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    root.extend(digits[..count].iter().rev());
    root
}

/// The anonymous device (0:N, as stat(2) encodes it) of filesystem
/// number `number`: minors from 2^16 up, past the mount ids other mounts'
/// devices are.
pub(crate) fn storage_device(number: u32) -> u32 {
    let minor = 0x1_0000_u32.wrapping_add(number) & 0xf_ffff;
    (minor & 0xff) | ((minor & !0xff) << 12)
}

/// The root filesystem's device, 0:1, as /proc/self/mountinfo and
/// statmount name the root mount's.
pub(crate) const ROOT_DEVICE: u32 = 1;

/// The device (stat's st_dev) of an overlay file at storage path `path`:
/// its filesystem's below a storage root, else the root filesystem's.
/// Every identity the kernel keeps for a file (stat, memory areas, the
/// shared mappings' lookup in `linux_overlay::paged_file`) comes from
/// here, so they agree.
pub(crate) fn device_of(path: &[u8]) -> u32 {
    let Some(rest) = path.strip_prefix(&[0]) else {
        return ROOT_DEVICE;
    };
    let digits = rest.iter().take_while(|byte| byte.is_ascii_digit());
    let number = digits.fold(0_u32, |number, digit| {
        number
            .wrapping_mul(10)
            .wrapping_add(u32::from(digit - b'0'))
    });
    storage_device(number)
}

/// Whether `path` is a storage path below some filesystem's storage root,
/// which no process can name.
pub(crate) fn is_storage(path: &[u8]) -> bool {
    path.first() == Some(&0)
}

/// `path` relative to mount point `point`, if it is the point or below it.
fn below<'a>(point: &[u8], path: &'a [u8]) -> Option<&'a [u8]> {
    if point.is_empty() {
        return Some(path);
    }
    match path.strip_prefix(point)? {
        [] => Some(&[]),
        [b'/', rest @ ..] => Some(rest),
        _ => None,
    }
}

fn join(base: &[u8], relative: &[u8]) -> Option<Vec<u8>> {
    let mut path = Vec::new();
    path.try_reserve_exact(base.len() + 1 + relative.len())
        .ok()?;
    path.extend_from_slice(base);
    if !base.is_empty() && !relative.is_empty() {
        path.push(b'/');
    }
    path.extend_from_slice(relative);
    Some(path)
}

/// The current process's mount table.
pub(crate) fn current_space() -> Space {
    Space {
        instance: crate::arch::x86_64::cpu::current_linux_execution_instance(),
        namespace: crate::linux_mount::current_handle()
            .map_or(0, crate::linux_mount::MountNamespaceHandle::id),
    }
}

/// The index of the mount `path` is on in `space`, walking the mount tree
/// from the root; `None` for the root mount itself.
fn resolve(routes: &[Route], space: Space, path: &[u8]) -> Option<usize> {
    let mut current = ROOT_ID;
    let mut found = None;
    loop {
        // The child of the mount reached so far at the first mount point
        // the path passes; among several there, the newest.
        let next = routes
            .iter()
            .enumerate()
            .filter(|(_, route)| {
                route.space == space
                    && route.parent == current
                    && below(&route.point, path).is_some()
            })
            .min_by_key(|(index, route)| (route.point.len(), usize::MAX - index))
            .map(|(index, _)| index);
        let Some(index) = next else {
            return found;
        };
        current = routes[index].id;
        found = Some(index);
    }
}

/// The storage path canonical `path` of the current process leads to: the
/// path itself on the root filesystem and the mounts that lead nowhere.
pub(crate) fn storage(path: &[u8]) -> Cow<'_, [u8]> {
    if REDIRECTS.load(Ordering::Relaxed) == 0 || is_storage(path) {
        return Cow::Borrowed(path);
    }
    // A mount that leads a path to itself (a directory bound onto itself)
    // changes nothing about it.
    match storage_in(current_space(), path) {
        Some(stored) if stored != path => Cow::Owned(stored),
        _ => Cow::Borrowed(path),
    }
}

/// The storage path canonical `path` leads to in `space`, if a mount leads
/// it elsewhere.
pub(crate) fn storage_in(space: Space, path: &[u8]) -> Option<Vec<u8>> {
    let routes = ROUTES.lock();
    let route = &routes[resolve(&routes, space, path)?];
    let target = route.target.as_deref()?;
    join(target, below(&route.point, path)?)
}

/// The path of the current process that leads to `storage`, the reverse
/// of [`storage`]: through the mount whose target holds it, one that a
/// path still reaches if there is one, the shortest such path; `storage`
/// itself when no mount leads there.
pub(crate) fn visible(storage: &[u8]) -> Cow<'_, [u8]> {
    if REDIRECTS.load(Ordering::Relaxed) == 0 {
        return Cow::Borrowed(storage);
    }
    let space = current_space();
    let routes = ROUTES.lock();
    // A root filesystem file a path reaches as itself keeps that path.
    if !is_storage(storage)
        && resolve(&routes, space, storage).is_none_or(|index| routes[index].target.is_none())
    {
        return Cow::Borrowed(storage);
    }
    let mut best: Option<(bool, Vec<u8>)> = None;
    for (index, route) in routes.iter().enumerate() {
        if route.space != space {
            continue;
        }
        let Some(rest) = route
            .target
            .as_deref()
            .and_then(|target| below(target, storage))
        else {
            continue;
        };
        let Some(path) = join(&route.point, rest) else {
            continue;
        };
        let reached = resolve(&routes, space, &route.point) == Some(index);
        let better = match &best {
            None => true,
            Some((best_reached, best_path)) => {
                reached && !best_reached || reached == *best_reached && path.len() < best_path.len()
            }
        };
        if better {
            best = Some((reached, path));
        }
    }
    match best {
        // A root filesystem path that no bind mount reaches is its own.
        Some((false, _)) if !is_storage(storage) => Cow::Borrowed(storage),
        Some((_, path)) => Cow::Owned(path),
        None => Cow::Borrowed(storage),
    }
}

/// Replaces domain `instance`'s routes with `routes` (its mount tables
/// changed).
pub(crate) fn publish(instance: usize, routes: Vec<Route>) {
    let mut table = ROUTES.lock();
    table.retain(|route| route.space.instance != instance);
    if table.try_reserve(routes.len()).is_ok() {
        table.extend(routes);
    }
    count_routes(&table);
}

fn count_routes(table: &[Route]) {
    REDIRECTS.store(
        table.iter().filter(|route| route.target.is_some()).count(),
        Ordering::Relaxed,
    );
    ROOT_BINDS.store(
        table
            .iter()
            .filter(|route| {
                route
                    .target
                    .as_deref()
                    .is_some_and(|target| !is_storage(target))
            })
            .count(),
        Ordering::Relaxed,
    );
}

/// Whether some mount leads paths to a root filesystem directory (a bind
/// mount of one), whose image files then show at other paths.
pub(crate) fn root_bound() -> bool {
    ROOT_BINDS.load(Ordering::Relaxed) != 0
}

/// Drops `instance`'s routes when its domain stops.
pub(crate) fn forget_instance(instance: usize) {
    let mut table = ROUTES.lock();
    table.retain(|route| route.space.instance != instance);
    count_routes(&table);
}
