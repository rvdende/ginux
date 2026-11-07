//! The filesystems a domain's processes mount on top of its root, with the
//! options that matter to the system calls that later touch paths under
//! them: a read-only mount makes every change below it fail with EROFS.
//!
//! The root, /proc and /sys/fs/cgroup are the kernel's own and are not
//! listed here. Each mount namespace of a domain has its own table: a new
//! namespace starts with copies of its parent's mounts (new ids, the same
//! peer groups), and its mounts go with it. A filesystem mounted over a
//! directory shows whatever the overlay holds beneath it, and so does a
//! bind mount: it is recorded (mountinfo, statmount, umount, propagation)
//! but does not redirect the paths below it to its source. Unmounting a
//! tmpfs drops what was created there unless another namespace still has
//! it mounted.
//!
//! Propagation is tracked as Linux shows it (peer groups, masters,
//! unbindable), but mounts and unmounts are not yet propagated to peers.
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
/// Access times are not updated (MS_NOATIME).
pub(crate) const NO_ATIME: u32 = 1 << 4;

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
    /// The mode, owner and group the mount point directory had before the
    /// mount's root took its place, to give back when the filesystem goes.
    pub(crate) covered: Option<Attributes>,
    /// The device the filesystem is on, as stat(2) encodes it: an
    /// anonymous 0:N, or the disk of a filesystem mounted from one.
    pub(crate) device: u32,
    /// A bind mount: it shows a filesystem another mount made.
    pub(crate) bind: bool,
    pub(crate) sharing: Sharing,
}

/// A filesystem whose files went with its last mount: the mount point
/// gets back the attributes it had before (`covered`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Gone {
    pub(crate) covered: Option<Attributes>,
}

/// A directory's mode, owner and group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Attributes {
    pub(crate) mode: u32,
    pub(crate) owner: u32,
    pub(crate) group: u32,
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
}

static MOUNTS: SpinLock<Mounts> = SpinLock::new(
    LockRank::MOUNTS,
    Mounts {
        mounts: Vec::new(),
        changes: Vec::new(),
        next_id: 4,
        next_group: 1,
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

    /// The topmost mount at canonical `path`, as an index.
    fn topmost(&self, space: Space, path: &[u8]) -> Option<usize> {
        self.mounts
            .iter()
            .rposition(|mount| mount.space == space && mount.path == path)
    }

    /// The mount canonical `path` lies on: the deepest mount point at or
    /// above it, the newest of those mounted there.
    fn covering(&self, space: Space, path: &[u8]) -> Option<usize> {
        self.mounts
            .iter()
            .enumerate()
            .filter(|(_, mount)| mount.space == space && covers(&mount.path, path))
            .max_by_key(|(index, mount)| (mount.path.len(), *index))
            .map(|(index, _)| index)
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
        self.mounts.push(mount);
        self.changed(instance);
        Ok(id)
    }

    /// Counts a change to `instance`'s mount table.
    fn changed(&mut self, instance: usize) {
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

    /// A non-bind tmpfs mount at `path` in `instance` other than `except`.
    fn tmpfs_mounted(&self, instance: usize, path: &[u8], except: u32) -> bool {
        self.mounts.iter().any(|mount| {
            mount.space.instance == instance
                && mount.id != except
                && mount.path == path
                && !mount.bind
                && drops_files(&mount.filesystem)
        })
    }
}

/// A filesystem whose files live only while it is mounted.
fn drops_files(filesystem: &[u8]) -> bool {
    matches!(filesystem, b"tmpfs" | b"ramfs" | b"devtmpfs")
}

/// Mounts `filesystem` (from `source`) at canonical `path` in `space`, on
/// top of whatever is mounted there (`covered`: the mount point's own
/// attributes, when the mount's root replaces them); returns the mount's id.
pub(crate) fn mount(
    space: Space,
    path: &[u8],
    source: &[u8],
    filesystem: &[u8],
    flags: u32,
    covered: Option<Attributes>,
) -> Result<u32, Error> {
    let mount = Mount {
        space,
        id: 0,
        parent: ROOT_ID,
        path: copy(path)?,
        root: Vec::new(),
        source: copy(source)?,
        filesystem: copy(filesystem)?,
        flags,
        covered,
        device: 0,
        bind: false,
        sharing: Sharing::default(),
    };
    let mut table = MOUNTS.lock();
    let id = table.attach(mount)?;
    if let Some(mount) = table.mounts.last_mut() {
        // Each new filesystem is an anonymous device of its own.
        mount.device = id;
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
                covered: None,
                device: mount.device,
                bind: true,
                sharing: Sharing {
                    unbindable: false,
                    ..mount.sharing
                },
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
        covered: None,
        device,
        bind: true,
        sharing,
    })?;
    for mount in below {
        table.attach(mount)?;
    }
    Ok(id)
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

/// Removes the topmost mount at canonical `path`; returns what went with
/// it when the files below `path` go too (a tmpfs no other namespace still
/// has mounted there).
pub(crate) fn unmount(space: Space, path: &[u8]) -> Result<Option<Gone>, Error> {
    let mut table = MOUNTS.lock();
    let index = table.topmost(space, path).ok_or(Error::NotMounted)?;
    let mount = table.mounts.remove(index);
    table.changed(space.instance);
    Ok((!mount.bind
        && drops_files(&mount.filesystem)
        && !table.tmpfs_mounted(space.instance, path, mount.id))
    .then_some(Gone {
        covered: mount.covered,
    }))
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
            covered: mount.covered,
            device: mount.device,
            bind: mount.bind,
            sharing: mount.sharing,
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
/// with each mount point whose files go with them.
pub(crate) fn drop_space(space: Space, mut drop: impl FnMut(&[u8], Gone)) {
    let mut table = MOUNTS.lock();
    let mut gone = Vec::new();
    let mut index = 0;
    while index < table.mounts.len() {
        if table.mounts[index].space != space {
            index += 1;
            continue;
        }
        let mount = table.mounts.remove(index);
        if !mount.bind && drops_files(&mount.filesystem) && gone.try_reserve(1).is_ok() {
            gone.push((mount.path, mount.covered));
        }
    }
    // Another namespace may still have the filesystem mounted there.
    gone.retain(|(path, _)| !table.tmpfs_mounted(space.instance, path, 0));
    table.changed(space.instance);
    core::mem::drop(table);
    for (path, covered) in &gone {
        drop(path, Gone { covered: *covered });
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
pub(crate) fn is_mount_point(space: Space, path: &[u8]) -> bool {
    MOUNTS.lock().topmost(space, path).is_some()
}

/// The options of the mount canonical `path` lies on: the deepest mount
/// point at or above it (0 for the root's own files).
pub(crate) fn flags_at(space: Space, path: &[u8]) -> u32 {
    let table = MOUNTS.lock();
    table
        .covering(space, path)
        .map_or(0, |index| table.mounts[index].flags)
}

/// The id of the mount canonical `path` lies on: the deepest mount point
/// at or above it ([`ROOT_ID`] for the root's own files). Two paths on
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
}
