//! The objects of the new mount API: filesystem contexts (fsopen(2),
//! fspick(2)), which collect a filesystem's parameters before it is made or
//! reconfigured, and detached mounts (fsmount(2), open_tree(2) with
//! OPEN_TREE_CLONE), which move_mount(2) attaches to a mount point.
//!
//! A descriptor names its object by id as an object slot of the socket
//! table ([`CLASS_CONTEXT`], [`CLASS_MOUNT`]), so dup, fork, SCM_RIGHTS and
//! close count it; the last close drops it. A detached mount is a
//! description of what to mount (a new filesystem from its context, or a
//! copy of a mounted tree) with its mount attributes, not yet a filesystem
//! of its own: attaching it mounts it as mount(2) would.
//!
//! Parameters are checked as Linux's VFS does: the superblock flags (ro,
//! rw, sync, ...) are taken by any filesystem; "source" by every one; a
//! filesystem with a parameter table accepts only its own keys; and one on
//! the legacy interface (ext2) gathers the rest into the comma-separated
//! option string mount(2) would get, up to a page.
#![forbid(unsafe_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};

/// The object class of filesystem context descriptors.
pub(crate) const CLASS_CONTEXT: u8 = 13;
/// The object class of detached mount descriptors.
pub(crate) const CLASS_MOUNT: u8 = 14;

const PAGE_SIZE: usize = 4096;

/// Where a context is in its life, as Linux's `fs_context_phase`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    /// Taking parameters for a new filesystem (fsopen).
    Create,
    /// Made (FSCONFIG_CMD_CREATE), waiting for fsmount.
    AwaitingMount,
    /// Taking parameters to reconfigure a filesystem (fspick, or a context
    /// after its fsmount).
    Reconfigure,
    /// A command failed; the context takes nothing more.
    Failed,
}

/// Why a parameter or command was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// EINVAL: an unknown key, a second source, a value of the wrong type,
    /// options past a page.
    Invalid,
    /// EBUSY: the context is in the wrong phase.
    Busy,
    /// ENOMEM.
    NoMemory,
    /// No such object (EBADF).
    Gone,
}

/// A parameter's value, as fsconfig(2) passed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Value<'a> {
    Flag,
    String(&'a [u8]),
    /// A binary blob, a path or a descriptor: nothing the legacy interface
    /// or a superblock flag takes beyond its name.
    Other,
}

/// One filesystem context.
pub(crate) struct Context {
    instance: usize,
    pub(crate) filesystem: Vec<u8>,
    pub(crate) phase: Phase,
    pub(crate) source: Option<Vec<u8>>,
    /// The legacy option string ("a=b,c"), or the new interface's
    /// parameters in the same form.
    pub(crate) data: Vec<u8>,
    /// Read-only (true) or read-write (false) when "ro" or "rw" was given.
    pub(crate) read_only: Option<bool>,
    /// The canonical mount point a context of fspick reconfigures.
    pub(crate) picked: Option<Vec<u8>>,
}

/// What a detached mount mounts when attached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Tree {
    /// A new filesystem, from a context.
    New {
        filesystem: Vec<u8>,
        source: Option<Vec<u8>>,
        data: Vec<u8>,
    },
    /// A copy of the mount at canonical `path` (with the mounts below it
    /// when `recursive`), as a bind mount makes.
    Clone { path: Vec<u8>, recursive: bool },
}

/// One detached mount.
pub(crate) struct Detached {
    instance: usize,
    pub(crate) tree: Tree,
    /// Its options (`crate::linux_mounts` flags).
    pub(crate) flags: u32,
    /// The canonical path it was attached at, once move_mount attached it.
    pub(crate) attached: Option<Vec<u8>>,
}

struct Objects {
    next_id: u64,
    contexts: BTreeMap<u64, Context>,
    mounts: BTreeMap<u64, Detached>,
}

static OBJECTS: SpinLock<Objects> = SpinLock::new(
    LockRank::FS_CONTEXTS,
    Objects {
        next_id: 1,
        contexts: BTreeMap::new(),
        mounts: BTreeMap::new(),
    },
);

fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

/// A filesystem on Linux's legacy mount interface: its options go into
/// one string, and it takes no path, blob or descriptor parameter.
pub(crate) fn legacy(filesystem: &[u8]) -> bool {
    filesystem == b"ext2"
}

/// The parameters a filesystem with a parameter table takes (besides the
/// superblock flags and "source"); None for one that takes any.
fn parameters(filesystem: &[u8]) -> Option<&'static [&'static [u8]]> {
    const SHMEM: &[&[u8]] = &[
        b"gid",
        b"huge",
        b"mode",
        b"mpol",
        b"nr_blocks",
        b"nr_inodes",
        b"size",
        b"uid",
        b"inode32",
        b"inode64",
        b"noswap",
        b"quota",
        b"usrquota",
        b"grpquota",
        b"usrquota_block_hardlimit",
        b"usrquota_inode_hardlimit",
        b"grpquota_block_hardlimit",
        b"grpquota_inode_hardlimit",
        b"casefold",
        b"strict_encoding",
    ];
    const RAMFS: &[&[u8]] = &[b"mode"];
    const PROC: &[&[u8]] = &[b"gid", b"hidepid", b"subset"];
    const OVERLAY: &[&[u8]] = &[
        b"lowerdir",
        b"lowerdir+",
        b"datadir+",
        b"upperdir",
        b"workdir",
        b"default_permissions",
        b"redirect_dir",
        b"index",
        b"uuid",
        b"nfs_export",
        b"userxattr",
        b"xino",
        b"metacopy",
        b"verity",
        b"volatile",
    ];
    match filesystem {
        b"tmpfs" | b"devtmpfs" => Some(SHMEM),
        b"ramfs" => Some(RAMFS),
        b"proc" => Some(PROC),
        b"overlay" => Some(OVERLAY),
        _ => None,
    }
}

/// The superblock flags every filesystem takes: whether `key` is one, and
/// for "ro" and "rw" which way it sets read-only.
fn superblock_flag(key: &[u8]) -> Option<Option<bool>> {
    match key {
        b"ro" => Some(Some(true)),
        b"rw" => Some(Some(false)),
        b"dirsync" | b"lazytime" | b"mand" | b"posixacl" | b"sync" | b"async" | b"nolazytime"
        | b"nomand" => Some(None),
        _ => None,
    }
}

impl Context {
    /// Takes parameter `key` with `value`, as Linux's vfs_parse_fs_param.
    fn parse(&mut self, key: &[u8], value: Value) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Create | Phase::Reconfigure) {
            return Err(Error::Busy);
        }
        if let Some(read_only) = superblock_flag(key) {
            if read_only.is_some() {
                self.read_only = read_only;
            }
            return Ok(());
        }
        let source = |context: &mut Self| match value {
            Value::String(string) if context.source.is_none() => {
                context.source = Some(copy(string)?);
                Ok(())
            }
            _ => Err(Error::Invalid),
        };
        if legacy(&self.filesystem) {
            if key == b"source" {
                return source(self);
            }
            let length = match value {
                Value::Flag => key.len(),
                Value::String(string) => key.len() + 1 + string.len(),
                Value::Other => return Err(Error::Invalid),
            };
            if self.data.len() + length + 2 > PAGE_SIZE
                || key.contains(&b',')
                || matches!(value, Value::String(string) if string.contains(&b','))
            {
                return Err(Error::Invalid);
            }
            return self.append(key, value);
        }
        if !key.is_empty() && parameters(&self.filesystem).is_none_or(|known| known.contains(&key))
        {
            if key == b"source" {
                return source(self);
            }
            return self.append(key, value);
        }
        if key == b"source" {
            return source(self);
        }
        Err(Error::Invalid)
    }

    /// Adds `key` (`=value`) to the option string.
    fn append(&mut self, key: &[u8], value: Value) -> Result<(), Error> {
        let value = match value {
            Value::String(string) => Some(string),
            _ => None,
        };
        let length = usize::from(!self.data.is_empty())
            + key.len()
            + value.map_or(0, |value| value.len() + 1);
        self.data.try_reserve(length).map_err(|_| Error::NoMemory)?;
        if !self.data.is_empty() {
            self.data.push(b',');
        }
        self.data.extend_from_slice(key);
        if let Some(value) = value {
            self.data.push(b'=');
            self.data.extend_from_slice(value);
        }
        Ok(())
    }
}

/// Makes a context for a new `filesystem` (fsopen); returns its id.
pub(crate) fn open(instance: usize, filesystem: &[u8]) -> Result<u64, Error> {
    insert_context(Context {
        instance,
        filesystem: copy(filesystem)?,
        phase: Phase::Create,
        source: None,
        data: Vec::new(),
        read_only: None,
        picked: None,
    })
}

/// Makes a context to reconfigure the `filesystem` mounted at canonical
/// `path` (fspick); returns its id.
pub(crate) fn pick(instance: usize, filesystem: &[u8], path: &[u8]) -> Result<u64, Error> {
    insert_context(Context {
        instance,
        filesystem: copy(filesystem)?,
        phase: Phase::Reconfigure,
        source: None,
        data: Vec::new(),
        read_only: None,
        picked: Some(copy(path)?),
    })
}

fn insert_context(context: Context) -> Result<u64, Error> {
    let mut objects = OBJECTS.lock();
    let id = objects.next_id;
    objects.next_id += 1;
    objects.contexts.insert(id, context);
    Ok(id)
}

/// Takes parameter `key` with `value` into context `id` (fsconfig's
/// FSCONFIG_SET_*).
pub(crate) fn set(id: u64, key: &[u8], value: Value) -> Result<(), Error> {
    OBJECTS
        .lock()
        .contexts
        .get_mut(&id)
        .ok_or(Error::Gone)?
        .parse(key, value)
}

/// Runs `inspect` on context `id`.
pub(crate) fn with_context<R>(id: u64, inspect: impl FnOnce(&Context) -> R) -> Option<R> {
    OBJECTS.lock().contexts.get(&id).map(inspect)
}

/// Moves context `id` to `phase` (a command's outcome).
pub(crate) fn set_phase(id: u64, phase: Phase) {
    if let Some(context) = OBJECTS.lock().contexts.get_mut(&id) {
        context.phase = phase;
    }
}

/// After a reconfiguration: the context forgets the flags it applied, as
/// Linux's vfs_clean_context leaves it ready for more.
pub(crate) fn clean(id: u64) {
    if let Some(context) = OBJECTS.lock().contexts.get_mut(&id) {
        context.read_only = None;
        context.data.clear();
        context.phase = Phase::Reconfigure;
    }
}

/// Makes a detached mount of what context `id` created (fsmount), with
/// options `flags`; the context then reconfigures it. Returns the mount's
/// id.
pub(crate) fn mount_context(id: u64, flags: u32) -> Result<u64, Error> {
    let mut objects = OBJECTS.lock();
    let context = objects.contexts.get_mut(&id).ok_or(Error::Gone)?;
    match context.phase {
        Phase::AwaitingMount => {}
        Phase::Reconfigure => return Err(Error::Busy),
        Phase::Create | Phase::Failed => return Err(Error::Invalid),
    }
    let tree = Tree::New {
        filesystem: copy(&context.filesystem)?,
        source: context.source.as_deref().map(copy).transpose()?,
        data: copy(&context.data)?,
    };
    let instance = context.instance;
    context.phase = Phase::Reconfigure;
    context.read_only = None;
    let mount = objects.next_id;
    objects.next_id += 1;
    objects.mounts.insert(
        mount,
        Detached {
            instance,
            tree,
            flags,
            attached: None,
        },
    );
    Ok(mount)
}

/// Makes a detached copy of the mount at canonical `path` (open_tree's
/// OPEN_TREE_CLONE), with options `flags`; returns its id.
pub(crate) fn clone_tree(
    instance: usize,
    path: &[u8],
    recursive: bool,
    flags: u32,
) -> Result<u64, Error> {
    let tree = Tree::Clone {
        path: copy(path)?,
        recursive,
    };
    let mut objects = OBJECTS.lock();
    let id = objects.next_id;
    objects.next_id += 1;
    objects.mounts.insert(
        id,
        Detached {
            instance,
            tree,
            flags,
            attached: None,
        },
    );
    Ok(id)
}

/// Runs `inspect` on detached mount `id`.
pub(crate) fn with_mount<R>(id: u64, inspect: impl FnOnce(&Detached) -> R) -> Option<R> {
    OBJECTS.lock().mounts.get(&id).map(inspect)
}

/// Sets `set` and clears `clear` in detached mount `id`'s options
/// (mount_setattr on its descriptor).
pub(crate) fn change_mount_flags(id: u64, set: u32, clear: u32) -> bool {
    OBJECTS
        .lock()
        .mounts
        .get_mut(&id)
        .map(|mount| mount.flags = mount.flags & !clear | set)
        .is_some()
}

/// Records that detached mount `id` is attached at canonical `path`.
pub(crate) fn attached(id: u64, path: &[u8]) -> Result<(), Error> {
    let path = copy(path)?;
    OBJECTS
        .lock()
        .mounts
        .get_mut(&id)
        .ok_or(Error::Gone)?
        .attached = Some(path);
    Ok(())
}

/// Drops object `class`/`id` after its last descriptor closed.
pub(crate) fn release(class: u8, id: u64) {
    let mut objects = OBJECTS.lock();
    match class {
        CLASS_CONTEXT => {
            objects.contexts.remove(&id);
        }
        CLASS_MOUNT => {
            objects.mounts.remove(&id);
        }
        _ => {}
    }
}

/// Drops `instance`'s objects when its domain stops.
pub(crate) fn forget_instance(instance: usize) {
    let mut objects = OBJECTS.lock();
    objects
        .contexts
        .retain(|_, context| context.instance != instance);
    objects.mounts.retain(|_, mount| mount.instance != instance);
}
