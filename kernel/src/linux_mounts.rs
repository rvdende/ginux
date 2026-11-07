//! The filesystems a domain's processes mount on top of its root, with the
//! options that matter to the system calls that later touch paths under
//! them: a read-only mount makes every change below it fail with EROFS.
//!
//! The root, /proc and /sys/fs/cgroup are the kernel's own and are not
//! listed here. Each mount namespace of a domain has its own table: a new
//! namespace starts with copies of its parent's mounts (new ids, the same
//! peer groups), and its mounts go with it.
//!
//! The mounts form Linux's tree: each sits on the mount its point was on
//! when it was made (`parent`), mounts on one point stack, and a path is
//! on the mount the tree walk reaches ([`crate::linux_mount_paths`], to
//! which every change publishes the table). A new tmpfs, volume or
//! overlay is a filesystem of its own (`superblock`), whose files are
//! stored below its storage root, and its mount leads there (`target`);
//! a bind mount leads to its source's storage, so it shows the source's
//! files, and a filesystem lives while any mount of it does: the last one
//! to go takes its files ([`Gone`]). The kernel's own filesystems (/proc,
//! sysfs, devtmpfs, ...) are found by their paths, so mounts of them lead
//! nowhere.
//!
//! Propagation is tracked as Linux shows it (peer groups, masters,
//! unbindable), but mounts and unmounts are not yet propagated to peers.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

/// Changes below the mount fail with EROFS (MS_RDONLY).
pub(crate) const READ_ONLY: u32 = 1 << 0;
/// Set-user-ID and set-group-ID bits are ignored (MS_NOSUID).
pub(crate) const NO_SUID: u32 = 1 << 1;
/// Device files cannot be opened (MS_NODEV).
pub(crate) const NO_DEVICES: u32 = 1 << 2;
/// Programs cannot be executed (MS_NOEXEC).
pub(crate) const NO_EXEC: u32 = 1 << 3;
/// Access times are not updated (MS_NOATIME).
pub(crate) const NO_ATIME: u32 = 1 << 4;
/// Directories' access times are not updated (MS_NODIRATIME).
pub(crate) const NO_DIRATIME: u32 = 1 << 5;
/// Symlinks are not followed (MS_NOSYMFOLLOW).
pub(crate) const NO_SYMFOLLOW: u32 = 1 << 6;
/// Every access updates the access time (MS_STRICTATIME): neither relatime,
/// the default, nor noatime.
pub(crate) const STRICT_ATIME: u32 = 1 << 7;

/// The id of the root mount, which every other mount sits on top of.
pub(crate) const ROOT_ID: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The path is not a mount point, or the source is unbindable (EINVAL).
    NotMounted,
    /// The table could not grow (ENOMEM).
    NoMemory,
}

/// One mount table: a domain's (`instance`) mount namespace (`namespace`,
/// its id; 0 outside one).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Space {
    pub(crate) instance: usize,
    pub(crate) namespace: u32,
}

/// How a mount takes part in mount propagation (mount(2)'s MS_SHARED,
/// MS_PRIVATE, MS_SLAVE and MS_UNBINDABLE).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Propagation {
    Shared,
    Private,
    Slave,
    Unbindable,
}

/// A mount's propagation state as /proc/PID/mountinfo and statmount show
/// it: its peer group ("shared:N"), the peer group it receives from
/// ("master:N"), 0 for none, and whether it may be bind mounted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Sharing {
    pub(crate) peer_group: u32,
    pub(crate) master: u32,
    pub(crate) unbindable: bool,
}

/// One mount: where, of what, and with which options.
pub(crate) struct Mount {
    space: Space,
    pub(crate) id: u32,
    /// The mount this one sits on ([`ROOT_ID`] for the root).
    pub(crate) parent: u32,
    /// The canonical mount point, without a leading slash.
    pub(crate) path: Vec<u8>,
    /// The directory of the filesystem shown at the mount point, without a
    /// leading slash: empty unless a bind mount of a subdirectory.
    pub(crate) root: Vec<u8>,
    pub(crate) source: Vec<u8>,
    pub(crate) filesystem: Vec<u8>,
    pub(crate) flags: u32,
    /// The filesystem's number when it is stored below a storage root of
    /// its own (a tmpfs, a volume, an overlay); 0 for one that is not.
    pub(crate) superblock: u32,
    /// The storage path the mount point leads to, if any.
    pub(crate) target: Option<Vec<u8>>,
    /// The device the filesystem is on, as stat(2) encodes it: an
    /// anonymous 0:N, or the disk of a filesystem mounted from one.
    pub(crate) device: u32,
    /// A bind mount: it shows a filesystem another mount made.
    pub(crate) bind: bool,
    pub(crate) sharing: Sharing,
    /// umount2's MNT_EXPIRE marked the mount: the number of path walks
    /// through it since (one more MNT_EXPIRE with nothing else using it
    /// unmounts it).
    expiry: Option<u32>,
}

/// A filesystem whose last mount went: its files go with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Gone {
    pub(crate) superblock: u32,
    pub(crate) filesystem: Vec<u8>,
}

/// The filesystem a bind mount copies when its source is not on a domain
/// mount: one of the kernel's own (root, /proc, cgroup2).
pub(crate) struct KernelFilesystem<'a> {
    pub(crate) filesystem: &'a [u8],
    pub(crate) source: &'a [u8],
    pub(crate) device: u32,
}

struct Mounts {
    mounts: Vec<Mount>,
    /// How often each domain's mount table changed (mount, remount,
    /// unmount): a /proc/mounts reader that saw an older count is told of
    /// the change (POLLPRI).
    changes: Vec<(usize, u32)>,
    /// Ids continue after the kernel's own mounts (root, /proc, cgroup).
    next_id: u32,
    /// Peer group ids start at 1, as Linux's do.
    next_group: u32,
    /// Filesystem numbers, from 1.
    next_superblock: u32,
}

static MOUNTS: SpinLock<Mounts> = SpinLock::new(
    LockRank::MOUNTS,
    Mounts {
        mounts: Vec::new(),
        changes: Vec::new(),
        next_id: 4,
        next_group: 1,
        next_superblock: 1,
    },
);

fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

/// `path` is the mount point `point` or lies below it.
fn covers(point: &[u8], path: &[u8]) -> bool {
    point.is_empty()
        || path
            .strip_prefix(point)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
}

impl Mounts {
    fn allocate_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        id
    }

    fn allocate_group(&mut self) -> u32 {
        let group = self.next_group;
        self.next_group = group.wrapping_add(1).max(1);
        group
    }

    /// The topmost mount at canonical `path`, as an index: the mount a
    /// path reaches there, if its point is `path`.
    fn topmost(&self, space: Space, path: &[u8]) -> Option<usize> {
        self.covering(space, path)
            .filter(|index| self.mounts[*index].path == path)
    }

    /// The mount canonical `path` lies on, by the mount tree: from the root,
    /// into the child at the first mount point on the way (the newest of
    /// those there), until none is left.
    fn covering(&self, space: Space, path: &[u8]) -> Option<usize> {
        let mut current = ROOT_ID;
        let mut found = None;
        loop {
            let next = self
                .mounts
                .iter()
                .enumerate()
                .filter(|(_, mount)| {
                    mount.space == space && mount.parent == current && covers(&mount.path, path)
                })
                .min_by_key(|(index, mount)| (mount.path.len(), usize::MAX - index))
                .map(|(index, _)| index);
            let Some(index) = next else {
                return found;
            };
            current = self.mounts[index].id;
            found = Some(index);
        }
    }

    /// Whether a mount of `instance` other than `except` shows filesystem
    /// `superblock`.
    fn superblock_mounted(&self, instance: usize, superblock: u32, except: u32) -> bool {
        self.mounts.iter().any(|mount| {
            mount.space.instance == instance && mount.id != except && mount.superblock == superblock
        })
    }

    /// What goes with `mount` once it is out of the table: its filesystem,
    /// when no other mount shows it.
    fn gone_with(&self, mount: &Mount) -> Option<Gone> {
        (mount.superblock != 0
            && !self.superblock_mounted(mount.space.instance, mount.superblock, mount.id))
        .then(|| Gone {
            superblock: mount.superblock,
            filesystem: mount.filesystem.clone(),
        })
    }

    fn sharing_of(&self, id: u32) -> Sharing {
        self.mounts
            .iter()
            .find(|mount| mount.id == id)
            .map_or_else(Sharing::default, |mount| mount.sharing)
    }

    /// Adds `mount` at its path in its space, on top of the mount there;
    /// below a shared mount it is shared too (in a new group unless it is
    /// already in one).
    fn attach(&mut self, mut mount: Mount) -> Result<u32, Error> {
        self.mounts.try_reserve(1).map_err(|_| Error::NoMemory)?;
        mount.id = self.allocate_id();
        mount.parent = self
            .covering(mount.space, &mount.path)
            .map_or(ROOT_ID, |index| self.mounts[index].id);
        if self.sharing_of(mount.parent).peer_group != 0 && mount.sharing.peer_group == 0 {
            mount.sharing.peer_group = self.allocate_group();
        }
        let id = mount.id;
        let instance = mount.space.instance;
        let parent = mount.parent;
        self.mounts.push(mount);
        self.propagate(self.mounts.len() - 1, parent)?;
        self.changed(instance);
        Ok(id)
    }

    /// Mount propagation: the mount at `index`, just attached on mount
    /// `parent`, gets a copy on each other member of `parent`'s peer group
    /// (a peer of the new mount's own group) and on each mount that
    /// receives from that group (a slave of it), at the same place below
    /// it. A copy goes under whatever that mount already has there, as
    /// Linux tucks a propagated mount beneath an existing one.
    fn propagate(&mut self, index: usize, parent: u32) -> Result<(), Error> {
        let Some(origin) = self.mounts.iter().find(|mount| mount.id == parent) else {
            return Ok(());
        };
        let group = origin.sharing.peer_group;
        if group == 0 {
            return Ok(());
        }
        let (space, origin_point, origin_root) =
            (origin.space, copy(&origin.path)?, copy(&origin.root)?);
        let mount = &self.mounts[index];
        let Some(rest) = mount.path.strip_prefix(origin_point.as_slice()) else {
            return Ok(());
        };
        let rest = copy(rest)?;
        let receivers: Vec<(u32, Vec<u8>, bool)> = self
            .mounts
            .iter()
            .filter(|receiver| {
                receiver.space == space
                    && receiver.id != parent
                    && receiver.id != mount.id
                    && receiver.root == origin_root
                    && (receiver.sharing.peer_group == group || receiver.sharing.master == group)
            })
            .map(|receiver| {
                (
                    receiver.id,
                    receiver.path.clone(),
                    receiver.sharing.peer_group == group,
                )
            })
            .collect();
        for (receiver, point, peer) in receivers {
            let id = self.allocate_id();
            let mount = &self.mounts[index];
            let mut path = point;
            path.try_reserve(rest.len()).map_err(|_| Error::NoMemory)?;
            if path.is_empty() {
                path.extend_from_slice(rest.strip_prefix(b"/").unwrap_or(&rest));
            } else {
                path.extend_from_slice(&rest);
            }
            let sharing = if peer {
                mount.sharing
            } else {
                Sharing {
                    peer_group: 0,
                    master: mount.sharing.peer_group,
                    unbindable: false,
                }
            };
            let copy_of = Mount {
                space,
                id,
                parent: receiver,
                path,
                root: copy(&mount.root)?,
                source: copy(&mount.source)?,
                filesystem: copy(&mount.filesystem)?,
                flags: mount.flags,
                superblock: mount.superblock,
                target: mount.target.as_deref().map(copy).transpose()?,
                device: mount.device,
                bind: true,
                sharing,
                expiry: None,
            };
            if let Some(below) = self.mounts.iter_mut().find(|child| {
                child.space == space && child.parent == receiver && child.path == copy_of.path
            }) {
                below.parent = id;
            }
            self.mounts.try_reserve(1).map_err(|_| Error::NoMemory)?;
            self.mounts.push(copy_of);
        }
        Ok(())
    }

    /// Whether mount `id` lies below mount `ancestor` in the tree (or is it).
    fn descends_from(&self, space: Space, mut id: u32, ancestor: u32) -> bool {
        for _ in 0..=self.mounts.len() {
            if id == ancestor {
                return true;
            }
            match self
                .mounts
                .iter()
                .find(|mount| mount.space == space && mount.id == id)
            {
                Some(mount) => id = mount.parent,
                None => return false,
            }
        }
        false
    }

    /// Counts a change to `instance`'s mount table, and publishes its
    /// tree to path resolution.
    fn changed(&mut self, instance: usize) {
        let mut routes = Vec::new();
        for mount in self
            .mounts
            .iter()
            .filter(|mount| mount.space.instance == instance)
        {
            let (Ok(point), Ok(target)) = (
                copy(&mount.path),
                mount.target.as_deref().map(copy).transpose(),
            ) else {
                continue;
            };
            if routes.try_reserve(1).is_ok() {
                routes.push(crate::linux_mount_paths::Route {
                    space: mount.space,
                    id: mount.id,
                    parent: mount.parent,
                    point,
                    target,
                    bind: mount.bind,
                });
            }
        }
        crate::linux_mount_paths::publish(instance, routes);
        STRICT_ATIME_MOUNTS.store(
            self.mounts
                .iter()
                .filter(|mount| mount.flags & STRICT_ATIME != 0)
                .count(),
            Ordering::Relaxed,
        );
        if let Some((_, count)) = self
            .changes
            .iter_mut()
            .find(|(owner, _)| *owner == instance)
        {
            *count = count.wrapping_add(1);
        } else if self.changes.try_reserve(1).is_ok() {
            self.changes.push((instance, 1));
        }
    }

    /// Whether another member of `peer_group` than mount `id` exists.
    fn has_other_peers(&self, peer_group: u32, id: u32) -> bool {
        peer_group != 0
            && self
                .mounts
                .iter()
                .any(|mount| mount.id != id && mount.sharing.peer_group == peer_group)
    }
}

/// Mounts with strictatime, across all domains: while there are none, a
/// read whose relatime rule leaves the access time alone needs no mount
/// lookup.
static STRICT_ATIME_MOUNTS: AtomicUsize = AtomicUsize::new(0);

/// Whether any mount has strictatime.
pub(crate) fn any_strict_atime() -> bool {
    STRICT_ATIME_MOUNTS.load(Ordering::Relaxed) != 0
}

/// A number for a new filesystem stored below a root of its own
/// (`crate::linux_mount_paths::storage_root`).
pub(crate) fn new_superblock() -> u32 {
    let mut table = MOUNTS.lock();
    let superblock = table.next_superblock;
    table.next_superblock = superblock.wrapping_add(1).max(1);
    superblock
}

/// Mounts `filesystem` (from `source`) at canonical `path` in `space`, on
/// top of whatever is mounted there: filesystem `superblock` (0 for one of
/// the kernel's own, found by its paths), stored below its storage root;
/// returns the mount's id.
pub(crate) fn mount(
    space: Space,
    path: &[u8],
    source: &[u8],
    filesystem: &[u8],
    flags: u32,
    superblock: u32,
) -> Result<u32, Error> {
    let target = (superblock != 0).then(|| crate::linux_mount_paths::storage_root(superblock));
    let mount = Mount {
        space,
        id: 0,
        parent: ROOT_ID,
        path: copy(path)?,
        root: Vec::new(),
        source: copy(source)?,
        filesystem: copy(filesystem)?,
        flags,
        superblock,
        target,
        device: 0,
        bind: false,
        sharing: Sharing::default(),
        expiry: None,
    };
    let mut table = MOUNTS.lock();
    let id = table.attach(mount)?;
    // Each new filesystem is an anonymous device of its own: one stored
    // below a storage root the device its files show.
    let device = if superblock != 0 {
        crate::linux_mount_paths::storage_device(superblock)
    } else {
        id
    };
    if let Some(mount) = table
        .mounts
        .iter_mut()
        .find(|mount| mount.space == space && mount.id == id)
    {
        mount.device = device;
    }
    Ok(id)
}

/// Records that mount `id` of `space` is on block device `device` (a
/// filesystem mounted from a disk), instead of an anonymous device.
pub(crate) fn set_device(space: Space, id: u32, device: u32) {
    let mut table = MOUNTS.lock();
    if let Some(mount) = table
        .mounts
        .iter_mut()
        .find(|mount| mount.space == space && mount.id == id)
    {
        mount.device = device;
    }
}

/// Bind mounts canonical `source` at canonical `target` in `space`
/// (MS_BIND), with the mounts below `source` too when `recursive`. The
/// copy shows the filesystem `source` lies on (`kernel` when that is not a
/// domain mount), joins its peer group and its master, as Linux's bind
/// mounts do. An unbindable source is EINVAL.
pub(crate) fn bind(
    space: Space,
    source: &[u8],
    target: &[u8],
    recursive: bool,
    kernel: &KernelFilesystem,
) -> Result<u32, Error> {
    let mut table = MOUNTS.lock();
    let covering = table.covering(space, source);
    // The copy leads where the source leads: below the source mount's
    // target, or to the root filesystem's own path.
    let (superblock, bound) = match covering {
        Some(index) => {
            let mount = &table.mounts[index];
            let rest = &source[mount.path.len()..];
            let rest = rest.strip_prefix(b"/").unwrap_or(rest);
            let bound = match &mount.target {
                Some(target) => {
                    let mut bound = copy(target)?;
                    if !rest.is_empty() {
                        bound
                            .try_reserve(rest.len() + 1)
                            .map_err(|_| Error::NoMemory)?;
                        bound.push(b'/');
                        bound.extend_from_slice(rest);
                    }
                    Some(bound)
                }
                None => None,
            };
            (mount.superblock, bound)
        }
        None if kernel.filesystem == b"ginux-root" => (0, Some(copy(source)?)),
        None => (0, None),
    };
    let (filesystem, mount_source, root, flags, device, sharing) = match covering {
        Some(index) => {
            let mount = &table.mounts[index];
            if mount.sharing.unbindable {
                return Err(Error::NotMounted);
            }
            let rest = &source[mount.path.len()..];
            let rest = rest.strip_prefix(b"/").unwrap_or(rest);
            let mut root = copy(&mount.root)?;
            if !rest.is_empty() {
                root.try_reserve(rest.len() + 1)
                    .map_err(|_| Error::NoMemory)?;
                if !root.is_empty() {
                    root.push(b'/');
                }
                root.extend_from_slice(rest);
            }
            (
                copy(&mount.filesystem)?,
                copy(&mount.source)?,
                root,
                mount.flags,
                mount.device,
                Sharing {
                    unbindable: false,
                    ..mount.sharing
                },
            )
        }
        None => (
            copy(kernel.filesystem)?,
            copy(kernel.source)?,
            copy(source)?,
            0,
            kernel.device,
            Sharing::default(),
        ),
    };
    // The mounts below the source go along with MS_REC, except
    // unbindable ones.
    let mut below = Vec::new();
    if recursive {
        for mount in table.mounts.iter().filter(|mount| {
            mount.space == space
                && mount.path.len() > source.len()
                && covers(source, &mount.path)
                && !mount.sharing.unbindable
        }) {
            let mut path = copy(target)?;
            let rest = &mount.path[source.len()..];
            let rest = if target.is_empty() {
                rest.strip_prefix(b"/").unwrap_or(rest)
            } else {
                rest
            };
            path.try_reserve(rest.len()).map_err(|_| Error::NoMemory)?;
            path.extend_from_slice(rest);
            below.try_reserve(1).map_err(|_| Error::NoMemory)?;
            below.push(Mount {
                space,
                id: 0,
                parent: ROOT_ID,
                path,
                root: copy(&mount.root)?,
                source: copy(&mount.source)?,
                filesystem: copy(&mount.filesystem)?,
                flags: mount.flags,
                superblock: mount.superblock,
                target: mount.target.as_deref().map(copy).transpose()?,
                device: mount.device,
                bind: true,
                sharing: Sharing {
                    unbindable: false,
                    ..mount.sharing
                },
                expiry: None,
            });
        }
    }
    let id = table.attach(Mount {
        space,
        id: 0,
        parent: ROOT_ID,
        path: copy(target)?,
        root,
        source: mount_source,
        filesystem,
        flags,
        superblock,
        target: bound,
        device,
        bind: true,
        sharing,
        expiry: None,
    })?;
    for mount in below {
        table.attach(mount)?;
    }
    Ok(id)
}

/// Sets the options of mount `id` of `space` (a detached mount's, once
/// attached).
pub(crate) fn set_flags(space: Space, id: u32, flags: u32) {
    let mut table = MOUNTS.lock();
    if let Some(mount) = table
        .mounts
        .iter_mut()
        .find(|mount| mount.space == space && mount.id == id)
    {
        mount.flags = flags;
        table.changed(space.instance);
    }
}

/// Puts mount `id` of `space` beneath the other mounts at its mount point
/// (move_mount's MOVE_MOUNT_BENEATH): they now sit on top of it.
pub(crate) fn put_beneath(space: Space, id: u32) {
    let mut table = MOUNTS.lock();
    let Some(index) = table
        .mounts
        .iter()
        .position(|mount| mount.space == space && mount.id == id)
    else {
        return;
    };
    let path = table.mounts[index].path.clone();
    let Some(first) = table
        .mounts
        .iter()
        .position(|mount| mount.space == space && mount.path == path)
    else {
        return;
    };
    if first < index {
        let mount = table.mounts.remove(index);
        // The old bottom mount now sits on the new one.
        let parent = table.mounts[first].parent;
        table.mounts[first].parent = id;
        table.mounts.insert(first, Mount { parent, ..mount });
        table.changed(space.instance);
    }
}

/// Puts mount `to` of `space` in the peer group of mount `from`
/// (move_mount's MOVE_MOUNT_SET_GROUP), with its master too.
pub(crate) fn share_group(space: Space, from: u32, to: u32) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let sharing = table
        .mounts
        .iter()
        .find(|mount| mount.space == space && mount.id == from)
        .ok_or(Error::NotMounted)?
        .sharing;
    let target = table
        .mounts
        .iter_mut()
        .find(|mount| mount.space == space && mount.id == to)
        .ok_or(Error::NotMounted)?;
    target.sharing = Sharing {
        unbindable: false,
        ..sharing
    };
    table.changed(space.instance);
    Ok(())
}

/// Moves the topmost mount at canonical `from`, with the mounts below it,
/// to canonical `to` (MS_MOVE, move_mount).
pub(crate) fn move_tree(space: Space, from: &[u8], to: &[u8]) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let top = table.topmost(space, from).ok_or(Error::NotMounted)?;
    let mut moved = Vec::new();
    for (index, mount) in table.mounts.iter().enumerate() {
        if mount.space != space {
            continue;
        }
        let rest = if index == top {
            Some(&b""[..])
        } else if index > top && mount.path.len() > from.len() && covers(from, &mount.path) {
            Some(&mount.path[from.len()..])
        } else {
            None
        };
        if let Some(rest) = rest {
            let rest = if to.is_empty() {
                rest.strip_prefix(b"/").unwrap_or(rest)
            } else {
                rest
            };
            let mut path = copy(to)?;
            path.try_reserve(rest.len()).map_err(|_| Error::NoMemory)?;
            path.extend_from_slice(rest);
            moved.try_reserve(1).map_err(|_| Error::NoMemory)?;
            moved.push((index, path));
        }
    }
    let parent = table
        .covering(space, to)
        .map_or(ROOT_ID, |index| table.mounts[index].id);
    for (index, path) in moved {
        table.mounts[index].path = path;
    }
    table.mounts[top].parent = parent;
    table.changed(space.instance);
    Ok(())
}

/// Changes the options of the topmost mount at canonical `path`
/// (MS_REMOUNT).
pub(crate) fn remount(space: Space, path: &[u8], flags: u32) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let index = table.topmost(space, path).ok_or(Error::NotMounted)?;
    table.mounts[index].flags = flags;
    table.changed(space.instance);
    Ok(())
}

/// Sets `set` and clears `clear` in the options of the topmost mount at
/// canonical `path` and, when `recursive`, of every mount below it
/// (mount_setattr). The kernel's mount points (`kernel_point`) have no
/// options here, but `recursive` reaches the mounts on them.
pub(crate) fn change_options(
    space: Space,
    path: &[u8],
    (set, clear): (u32, u32),
    recursive: bool,
    kernel_point: bool,
) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let top = table.topmost(space, path);
    if top.is_none() && !kernel_point {
        return Err(Error::NotMounted);
    }
    for (index, mount) in table.mounts.iter_mut().enumerate() {
        let selected = Some(index) == top
            || recursive
                && mount.space == space
                && mount.path.len() > path.len()
                && covers(path, &mount.path);
        if selected {
            mount.flags = mount.flags & !clear | set;
        }
    }
    table.changed(space.instance);
    Ok(())
}

/// Changes the propagation of the topmost mount at canonical `path` and,
/// when `recursive`, of every mount below it, as Linux's mount(2) and
/// mount_setattr do: a shared mount gets a peer group of its own if it has
/// none; a slave receives from the peers it leaves (or keeps its master
/// when it had none); private and unbindable mounts leave both. The
/// kernel's mount points (`kernel_point`) take no state here, but
/// `recursive` reaches the mounts on them.
pub(crate) fn set_propagation(
    space: Space,
    path: &[u8],
    propagation: Propagation,
    recursive: bool,
    kernel_point: bool,
) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let top = table.topmost(space, path);
    if top.is_none() && !kernel_point {
        return Err(Error::NotMounted);
    }
    for index in 0..table.mounts.len() {
        let mount = &table.mounts[index];
        let selected = Some(index) == top
            || recursive
                && mount.space == space
                && mount.path.len() > path.len()
                && covers(path, &mount.path);
        if !selected {
            continue;
        }
        let (id, sharing) = (table.mounts[index].id, table.mounts[index].sharing);
        let sharing = match propagation {
            Propagation::Shared => Sharing {
                peer_group: if sharing.peer_group == 0 {
                    table.allocate_group()
                } else {
                    sharing.peer_group
                },
                ..sharing
            },
            Propagation::Slave => Sharing {
                peer_group: 0,
                master: if table.has_other_peers(sharing.peer_group, id) {
                    sharing.peer_group
                } else {
                    sharing.master
                },
                unbindable: false,
            },
            Propagation::Private => Sharing::default(),
            Propagation::Unbindable => Sharing {
                unbindable: true,
                ..Sharing::default()
            },
        };
        table.mounts[index].sharing = sharing;
    }
    table.changed(space.instance);
    Ok(())
}

/// Removes the topmost mount at canonical `path`; returns its filesystem
/// when no other mount (of any namespace) shows it any more. The mounts on
/// top of it, if any, now sit on what it sat on.
pub(crate) fn unmount(space: Space, path: &[u8]) -> Result<Option<Gone>, Error> {
    let mut table = MOUNTS.lock();
    let index = table.topmost(space, path).ok_or(Error::NotMounted)?;
    let mount = table.mounts.remove(index);
    if mount.expiry.is_some() {
        EXPIRY_MARKS.fetch_sub(1, Ordering::Relaxed);
    }
    for child in table
        .mounts
        .iter_mut()
        .filter(|child| child.space == space && child.parent == mount.id)
    {
        child.parent = mount.parent;
    }
    let gone = table.gone_with(&mount);
    table.changed(space.instance);
    Ok(gone)
}

/// The filesystem that would go with the topmost mount at canonical `path`
/// if it were unmounted: its number, if no other mount shows it, and its
/// storage root.
pub(crate) fn last_mount_of(space: Space, path: &[u8]) -> Option<(u32, Vec<u8>)> {
    let table = MOUNTS.lock();
    let mount = &table.mounts[table.topmost(space, path)?];
    table.gone_with(mount).map(|gone| {
        (
            gone.superblock,
            crate::linux_mount_paths::storage_root(gone.superblock),
        )
    })
}

/// The filesystem number and storage root of the topmost mount at
/// canonical `path`, when it has a storage root of its own.
pub(crate) fn superblock_at(space: Space, path: &[u8]) -> Option<(u32, Vec<u8>)> {
    let table = MOUNTS.lock();
    let superblock = table.mounts[table.topmost(space, path)?].superblock;
    (superblock != 0).then(|| {
        (
            superblock,
            crate::linux_mount_paths::storage_root(superblock),
        )
    })
}

/// Gives the namespace `to` copies of the mounts of `from` (a new mount
/// namespace): new ids, the same peer groups and masters.
pub(crate) fn copy_space(from: Space, to: Space) -> Result<(), Error> {
    let mut table = MOUNTS.lock();
    let mut copies = Vec::new();
    let mut ids = Vec::new();
    for mount in table.mounts.iter().filter(|mount| mount.space == from) {
        copies.try_reserve(1).map_err(|_| Error::NoMemory)?;
        ids.try_reserve(1).map_err(|_| Error::NoMemory)?;
        ids.push(mount.id);
        copies.push(Mount {
            space: to,
            id: 0,
            parent: mount.parent,
            path: copy(&mount.path)?,
            root: copy(&mount.root)?,
            source: copy(&mount.source)?,
            filesystem: copy(&mount.filesystem)?,
            flags: mount.flags,
            superblock: mount.superblock,
            target: mount.target.as_deref().map(copy).transpose()?,
            device: mount.device,
            bind: mount.bind,
            sharing: mount.sharing,
            expiry: None,
        });
    }
    table
        .mounts
        .try_reserve(copies.len())
        .map_err(|_| Error::NoMemory)?;
    // Parents are earlier in the table, so their new ids are known first.
    let mut new_ids: Vec<u32> = Vec::new();
    new_ids
        .try_reserve(copies.len())
        .map_err(|_| Error::NoMemory)?;
    for mut mount in copies {
        mount.id = table.allocate_id();
        mount.parent = ids
            .iter()
            .position(|old| *old == mount.parent)
            .and_then(|at| new_ids.get(at).copied())
            .unwrap_or(ROOT_ID);
        new_ids.push(mount.id);
        table.mounts.push(mount);
    }
    table.changed(to.instance);
    Ok(())
}

/// Drops the mounts of `space` (its namespace is gone) and calls `drop`
/// with each filesystem that goes with them.
pub(crate) fn drop_space(space: Space, mut drop: impl FnMut(Gone)) {
    let mut table = MOUNTS.lock();
    let mut dropped = Vec::new();
    let mut index = 0;
    while index < table.mounts.len() {
        if table.mounts[index].space != space {
            index += 1;
            continue;
        }
        let mount = table.mounts.remove(index);
        if mount.superblock != 0 && dropped.try_reserve(1).is_ok() {
            dropped.push((mount.superblock, mount.filesystem));
        }
    }
    // Another namespace may still have the filesystem mounted.
    let mut gone: Vec<Gone> = Vec::new();
    for (superblock, filesystem) in dropped {
        if !table.superblock_mounted(space.instance, superblock, 0)
            && !gone.iter().any(|gone| gone.superblock == superblock)
            && gone.try_reserve(1).is_ok()
        {
            gone.push(Gone {
                superblock,
                filesystem,
            });
        }
    }
    table.changed(space.instance);
    core::mem::drop(table);
    for gone in gone {
        drop(gone);
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

/// Mounts MNT_EXPIRE has marked, across all domains: while there are
/// none, path walks skip noting their use.
static EXPIRY_MARKS: AtomicUsize = AtomicUsize::new(0);

/// umount2's MNT_EXPIRE on the topmost mount at canonical `path`: the
/// first call marks it and is EAGAIN; one after which nothing but this
/// call's own path walk used the mount (`walks` of them) lets it go.
pub(crate) fn expire(space: Space, path: &[u8]) -> Result<bool, Error> {
    let mut table = MOUNTS.lock();
    let index = table.topmost(space, path).ok_or(Error::NotMounted)?;
    let mount = &mut table.mounts[index];
    match mount.expiry {
        Some(walks) if walks <= 1 => {
            mount.expiry = None;
            EXPIRY_MARKS.fetch_sub(1, Ordering::Relaxed);
            Ok(true)
        }
        Some(_) => {
            mount.expiry = Some(0);
            Ok(false)
        }
        None => {
            mount.expiry = Some(0);
            EXPIRY_MARKS.fetch_add(1, Ordering::Relaxed);
            Ok(false)
        }
    }
}

/// A path walk reached canonical `path`: the mount it lies on is in use,
/// which an MNT_EXPIRE mark counts.
pub(crate) fn note_walk(space: Space, path: &[u8]) {
    if EXPIRY_MARKS.load(Ordering::Relaxed) == 0 {
        return;
    }
    let mut table = MOUNTS.lock();
    if let Some(index) = table.covering(space, path) {
        if let Some(walks) = &mut table.mounts[index].expiry {
            *walks = walks.saturating_add(1);
        }
    }
}

/// The unique-id order listing of listmount(2): calls `listed` with the
/// local id of each mount of `space` that lies at or below canonical
/// `directory` of mount `origin` (by the tree and the path).
pub(crate) fn for_each_below(
    space: Space,
    origin: u32,
    directory: &[u8],
    mut listed: impl FnMut(u32),
) {
    let table = MOUNTS.lock();
    for mount in table.mounts.iter().filter(|mount| mount.space == space) {
        if table.descends_from(space, mount.id, origin) && covers(directory, &mount.path) {
            listed(mount.id);
        }
    }
}

/// The mount a process's root at canonical `path` is on: the one the
/// path reaches, or below the mounts stacked on it since at that point,
/// the first of them (a root stays on the mount it was made on).
pub(crate) fn root_mount_at(space: Space, path: &[u8]) -> u32 {
    let table = MOUNTS.lock();
    let Some(mut index) = table.covering(space, path) else {
        return ROOT_ID;
    };
    while table.mounts[index].path == path {
        let parent = table.mounts[index].parent;
        match table
            .mounts
            .iter()
            .position(|mount| mount.space == space && mount.id == parent && mount.path == path)
        {
            Some(below) => index = below,
            None => break,
        }
    }
    table.mounts[index].id
}

/// Something is mounted at canonical `path`.
pub(crate) fn is_mount_point(space: Space, path: &[u8]) -> bool {
    MOUNTS.lock().topmost(space, path).is_some()
}

/// The id of the topmost mount at canonical `path`.
pub(crate) fn topmost_id(space: Space, path: &[u8]) -> Option<u32> {
    let table = MOUNTS.lock();
    table
        .topmost(space, path)
        .map(|index| table.mounts[index].id)
}

/// The options of the mount canonical `path` lies on, by the mount tree
/// (0 for the root's own files).
pub(crate) fn flags_at(space: Space, path: &[u8]) -> u32 {
    let table = MOUNTS.lock();
    table
        .covering(space, path)
        .map_or(0, |index| table.mounts[index].flags)
}

/// Whether canonical `path` lies on a mount of `filesystem` (by the mount
/// tree): a file under a hugetlbfs mount is made of huge pages.
pub(crate) fn on_filesystem(space: Space, path: &[u8], filesystem: &[u8]) -> bool {
    let table = MOUNTS.lock();
    table
        .covering(space, path)
        .is_some_and(|index| table.mounts[index].filesystem == filesystem)
}

/// The id of the mount canonical `path` lies on, by the mount tree
/// ([`ROOT_ID`] for the root's own files). Two paths on
/// different mounts cannot be linked or renamed into one another (EXDEV).
pub(crate) fn mount_id_at(space: Space, path: &[u8]) -> u32 {
    let table = MOUNTS.lock();
    table
        .covering(space, path)
        .map_or(ROOT_ID, |index| table.mounts[index].id)
}

/// Runs `inspect` on the mount `id` of `space`.
pub(crate) fn with_mount<R>(space: Space, id: u32, inspect: impl FnOnce(&Mount) -> R) -> Option<R> {
    let table = MOUNTS.lock();
    table
        .mounts
        .iter()
        .find(|mount| mount.space == space && mount.id == id)
        .map(inspect)
}

/// Runs `inspect` on each mount of `space`, oldest first.
pub(crate) fn for_each(space: Space, mut inspect: impl FnMut(&Mount)) {
    let table = MOUNTS.lock();
    for mount in table.mounts.iter().filter(|mount| mount.space == space) {
        inspect(mount);
    }
}

/// Drops `instance`'s mounts when its domain stops.
pub(crate) fn forget_instance(instance: usize) {
    let mut table = MOUNTS.lock();
    table
        .mounts
        .retain(|mount| mount.space.instance != instance);
    table.changes.retain(|(owner, _)| *owner != instance);
    crate::linux_mount_paths::forget_instance(instance);
    crate::linux_path_views::forget_instance(instance);
}
