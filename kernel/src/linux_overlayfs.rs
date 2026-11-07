//! overlayfs, Linux's union filesystem (`mount -t overlay -o
//! lowerdir=...,upperdir=...,workdir=...`): one or more read-only lower
//! directory trees merged under a writable upper one at a mount point. It
//! is not [`crate::linux_overlay`], the kernel's view of a domain's files
//! (whose name comes from layering the image's files under the domain's
//! own); an overlay mount plugs in beneath that view as a mounted volume
//! does ([`crate::linux_blockfs`]): `linux_overlay` hands a path at or
//! below an overlay's mount point, and a handle of an overlay's file, to
//! this module, which works on the layers through `linux_overlay` again.
//!
//! The layers follow Linux's on-disk format, so they mean the same to
//! Linux and to programs that look at them: a whiteout (a character device
//! 0:0) in a layer hides a name of the layers below it, and a directory
//! with the xattr `trusted.overlay.opaque` = "y" hides everything the
//! layers below have under its name. A name resolves to the topmost layer
//! that has it; a directory that several layers have is merged, and lists
//! the names of all of them that no whiteout hides.
//!
//! An overlay's file has a handle of its own (a generation from
//! [`GENERATIONS`], which neither the domain's own files nor volumes use),
//! naming the file by its path below the mount: it stays the same file
//! when a change copies it up from a lower layer into the upper one (its
//! data, mode, owner and times, after its directories), so descriptors, a
//! working directory and inotify watches keep following it, and its path
//! is the mount's, not a layer's. Removing a name of a lower layer leaves
//! a whiteout in the upper one; a directory made where a whiteout was is
//! opaque. Renaming a directory a lower layer has is EXDEV, as Linux's
//! without redirect_dir. A file whose last name goes stays readable
//! through the descriptors that have it open, and its upper file stays
//! allocated until they close ([`pinned`]).
//!
//! The work directory is checked and given its `work` subdirectory as
//! Linux does, but copy-up does not stage files there. Layers must lie
//! outside the mount point.
#![forbid(unsafe_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::x86_64::cpu;
use crate::linux_overlay::{self as overlay, Child, Handle, Metadata, NodeKind};
use crate::sync::{LockRank, SpinLock};

/// Overlay file generations: below the volumes', which start at 2^30.
const GENERATIONS: core::ops::Range<u32> = 0x2000_0000..0x4000_0000;
/// The xattr that makes an upper directory opaque.
const OPAQUE: &[u8] = b"trusted.overlay.opaque";
/// How much of a file a copy-up moves at a time.
const COPY_CHUNK: usize = 4096;

/// Why an overlay operation failed, as Linux's errno.
pub(crate) type Errno = u64;
const ENOENT: Errno = 2;
const EIO: Errno = 5;
const EXDEV: Errno = 18;
const EEXIST: Errno = 17;
const ENOTDIR: Errno = 20;
const ENOTEMPTY: Errno = 39;
const EROFS: Errno = 30;
const ENOMEM: Errno = 12;

/// How a rename treats its target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RenameMode {
    Replace,
    NoReplace,
    Exchange,
}

/// One overlay mount.
#[derive(Clone)]
struct Mount {
    id: u64,
    instance: usize,
    /// The canonical mount point.
    point: Vec<u8>,
    /// The writable layer, if any (without one the mount is read-only).
    upper: Option<Vec<u8>>,
    /// The read-only layers, topmost first.
    lowers: Vec<Vec<u8>>,
    /// The device stat(2) shows for the mount's files.
    device: u32,
}

impl Mount {
    /// The layers, topmost first: the upper one, then the lowers.
    fn layers(&self) -> impl Iterator<Item = &[u8]> {
        self.upper
            .iter()
            .chain(self.lowers.iter())
            .map(Vec::as_slice)
    }

    fn is_upper(&self, layer: usize) -> bool {
        layer == 0 && self.upper.is_some()
    }
}

/// An overlay file handed out: the mount it is on and its path there.
struct Inode {
    mount: u64,
    relative: Vec<u8>,
    /// The inode number stat(2) shows.
    inode: u64,
    /// After its last name went: the layer's file it still reads.
    unlinked: Option<Handle>,
}

struct Overlays {
    mounts: Vec<Mount>,
    inodes: BTreeMap<u32, Inode>,
    /// The generation of each (mount, path) handed out and still named.
    named: BTreeMap<(u64, Vec<u8>), u32>,
    next_generation: u32,
    next_mount: u64,
    /// The last merged directory listing (mount, path, names), which a
    /// listing read in several calls keeps using after its first.
    listing: Option<(u64, Vec<u8>, Vec<Vec<u8>>)>,
}

static OVERLAYS: SpinLock<Overlays> = SpinLock::new(
    LockRank::OVERLAY_MOUNTS,
    Overlays {
        mounts: Vec::new(),
        inodes: BTreeMap::new(),
        named: BTreeMap::new(),
        next_generation: GENERATIONS.start,
        next_mount: 1,
        listing: None,
    },
);

/// Overlay mounts across all domains, so that path walks skip the table
/// while there are none.
static MOUNTED: AtomicUsize = AtomicUsize::new(0);

fn instance() -> usize {
    cpu::current_linux_execution_instance()
}

fn copy(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).ok()?;
    copy.extend_from_slice(bytes);
    Some(copy)
}

/// `base`/`relative`, either of which may be empty.
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

/// The proper prefixes of `relative`, shortest first: the directories a
/// walk to it passes through below the root.
fn prefixes(relative: &[u8]) -> impl Iterator<Item = &[u8]> {
    relative
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .map(|(at, _)| &relative[..at])
}

fn is_whiteout(metadata: &Metadata) -> bool {
    metadata.kind == NodeKind::CharacterDevice && metadata.device == 0
}

fn is_opaque(metadata: &Metadata) -> bool {
    let mut value = [0_u8; 2];
    metadata.kind == NodeKind::Directory
        && matches!(
            overlay::get_xattr_chunk(metadata.handle, OPAQUE, 0, &mut value),
            Some((1, 1))
        )
        && value[0] == b'y'
}

/// Makes the upper layer's directory `handle` opaque.
fn set_opaque(handle: Handle) {
    let _ = overlay::set_xattr_from(handle, OPAQUE, 1, false, false, |_, bytes| {
        bytes.fill(b'y');
        true
    });
}

/// Whether any overlay is mounted, in any domain.
pub(crate) fn active() -> bool {
    MOUNTED.load(Ordering::Relaxed) != 0
}

/// Whether `handle` is an overlay file's.
pub(crate) fn owns(handle: Handle) -> bool {
    GENERATIONS.contains(&overlay::generation(handle))
}

/// The overlay mount of this domain canonical `path` lies on, if a volume
/// mounted deeper does not take it, with the path below the mount point.
fn route(path: &[u8]) -> Option<(Mount, Vec<u8>)> {
    if !active() {
        return None;
    }
    let instance = instance();
    let (mount, relative) = {
        let table = OVERLAYS.lock();
        let mount = table
            .mounts
            .iter()
            .filter(|mount| mount.instance == instance && below(&mount.point, path).is_some())
            .max_by_key(|mount| mount.point.len())?;
        (mount.clone(), copy(below(&mount.point, path)?)?)
    };
    if crate::linux_blockfs::point_depth(path).is_some_and(|depth| depth > mount.point.len()) {
        return None;
    }
    Some((mount, relative))
}

/// Whether canonical `path` lies on an overlay.
pub(crate) fn covers(path: &[u8]) -> bool {
    route(path).is_some()
}

/// What a walk to a path below an overlay's root finds.
struct Walk {
    /// The topmost layer that shows a file there, and that file.
    found: Option<(usize, Metadata)>,
    /// The layers whose directories there make up the merged directory,
    /// topmost first.
    merged: Vec<usize>,
    /// Whether a lower layer's file there would show if the upper layer
    /// had none: removing the name then needs a whiteout.
    lower: bool,
}

/// Walks to `relative` through the layers: each name on the way resolves
/// to the topmost layer that has it, and a whiteout, a file or an opaque
/// directory there hides what the layers below have.
fn walk(mount: &Mount, relative: &[u8]) -> Walk {
    let mut walk = Walk {
        found: None,
        merged: Vec::new(),
        lower: false,
    };
    let layers: Vec<&[u8]> = mount.layers().collect();
    let lookup =
        |layer: &[u8], step: &[u8]| join(layer, step).and_then(|path| overlay::lookup(&path));
    // The layers whose directory at the walk's place takes part.
    let mut live = layers.len();
    for step in prefixes(relative) {
        let mut found = None;
        for (index, layer) in layers.iter().enumerate().take(live) {
            let Some(metadata) = lookup(layer, step) else {
                continue;
            };
            if is_whiteout(&metadata) || metadata.kind != NodeKind::Directory {
                // A file on the way ends the walk unless a directory above
                // it already took the name.
                live = index;
                break;
            }
            if found.is_none() {
                found = Some(index);
            }
            if is_opaque(&metadata) {
                live = index + 1;
                break;
            }
        }
        if found.is_none() {
            return walk;
        }
    }
    let first_lower = usize::from(mount.upper.is_some());
    walk.lower = (first_lower..live)
        .find_map(|index| lookup(layers[index], relative))
        .is_some_and(|metadata| !is_whiteout(&metadata));
    for (index, layer) in layers.iter().enumerate().take(live) {
        let Some(metadata) = lookup(layer, relative) else {
            continue;
        };
        if is_whiteout(&metadata) {
            break;
        }
        let directory = metadata.kind == NodeKind::Directory;
        match walk.found {
            None => walk.found = Some((index, metadata)),
            Some((_, top)) if top.kind != NodeKind::Directory || !directory => break,
            Some(_) => {}
        }
        if !directory {
            break;
        }
        if walk.merged.try_reserve(1).is_err() {
            break;
        }
        walk.merged.push(index);
        if is_opaque(&metadata) {
            break;
        }
    }
    walk
}

/// The topmost layer that has `relative`, and its file there.
fn resolve(mount: &Mount, relative: &[u8]) -> Option<(usize, Metadata)> {
    walk(mount, relative).found
}

/// The handle of the overlay file at `relative` of mount `mount`, made on
/// first use; `real` is the layer's file there now, whose inode number a
/// new one shows.
fn handle_for(mount: u64, relative: &[u8], real: Handle) -> Option<Handle> {
    let mut table = OVERLAYS.lock();
    let key = (mount, copy(relative)?);
    if let Some(generation) = table.named.get(&key) {
        let generation = *generation;
        let inode = table.inodes.get(&generation)?.inode;
        return Some(Handle::volume(generation, inode));
    }
    let generation = table.next_generation;
    if !GENERATIONS.contains(&generation) {
        return None;
    }
    table.next_generation += 1;
    table.inodes.insert(
        generation,
        Inode {
            mount,
            relative: copy(relative)?,
            inode: real.inode(),
            unlinked: None,
        },
    );
    table.named.insert(key, generation);
    Some(Handle::volume(generation, real.inode()))
}

/// The mount and path of an overlay handle, or the file it still reads
/// once unlinked.
enum Found {
    Named(Mount, Vec<u8>),
    Unlinked(Mount, Handle),
}

fn find(handle: Handle) -> Option<Found> {
    let table = OVERLAYS.lock();
    let inode = table.inodes.get(&overlay::generation(handle))?;
    let mount = table
        .mounts
        .iter()
        .find(|mount| mount.id == inode.mount)?
        .clone();
    Some(match inode.unlinked {
        Some(real) => Found::Unlinked(mount, real),
        None => Found::Named(mount, copy(&inode.relative)?),
    })
}

/// `real`'s metadata as the overlay file `handle` shows it.
fn shown(mount: &Mount, handle: Handle, real: Metadata) -> Metadata {
    Metadata {
        handle,
        filesystem: mount.device,
        ..real
    }
}

/// What lookup of canonical `path` finds: `None` if the path is not on an
/// overlay, else its file there, if any.
pub(crate) fn lookup(path: &[u8]) -> Option<Option<Metadata>> {
    let (mount, relative) = route(path)?;
    Some((|| {
        let (_, real) = resolve(&mount, &relative)?;
        let handle = handle_for(mount.id, &relative, real.handle)?;
        Some(shown(&mount, handle, real))
    })())
}

pub(crate) fn from_generation(generation: u32) -> Option<Handle> {
    let table = OVERLAYS.lock();
    let inode = table.inodes.get(&generation)?;
    Some(Handle::volume(generation, inode.inode))
}

/// The layer's file overlay file `handle` reads now.
pub(crate) fn real(handle: Handle) -> Option<Handle> {
    match find(handle)? {
        Found::Named(mount, relative) => resolve(&mount, &relative).map(|(_, real)| real.handle),
        Found::Unlinked(_, real) => Some(real),
    }
}

pub(crate) fn metadata(handle: Handle) -> Option<Metadata> {
    match find(handle)? {
        Found::Named(mount, relative) => {
            let (_, real) = resolve(&mount, &relative)?;
            Some(shown(&mount, handle, real))
        }
        Found::Unlinked(mount, real) => {
            let real = overlay::metadata(real)?;
            Some(Metadata {
                links: 0,
                ..shown(&mount, handle, real)
            })
        }
    }
}

pub(crate) fn linked(handle: Handle) -> bool {
    matches!(find(handle), Some(Found::Named(mount, relative)) if resolve(&mount, &relative).is_some())
}

pub(crate) fn copy_path(handle: Handle, output: &mut [u8]) -> Option<usize> {
    let table = OVERLAYS.lock();
    let inode = table.inodes.get(&overlay::generation(handle))?;
    let mount = table.mounts.iter().find(|mount| mount.id == inode.mount)?;
    let path = join(&mount.point, &inode.relative)?;
    output.get_mut(..path.len())?.copy_from_slice(&path);
    Some(path.len())
}

/// Makes sure the directories above `relative` are in the upper layer,
/// copying each a lower layer has up with its mode, owner and times.
fn copy_up_parents(mount: &Mount, relative: &[u8]) -> Result<(), Errno> {
    let upper = mount.upper.as_deref().ok_or(EROFS)?;
    for prefix in prefixes(relative) {
        let (layer, metadata) = resolve(mount, prefix).ok_or(ENOENT)?;
        if metadata.kind != NodeKind::Directory {
            return Err(ENOTDIR);
        }
        if mount.is_upper(layer) {
            continue;
        }
        let path = join(upper, prefix).ok_or(ENOMEM)?;
        let made = overlay::create_directory(&path, metadata.mode).ok_or(EIO)?;
        copy_attributes(made, &metadata);
    }
    Ok(())
}

/// Gives the copied-up file `made` the mode, owner and times of `source`.
fn copy_attributes(made: Handle, source: &Metadata) {
    let _ = overlay::set_owner(made, source.owner, source.group)
        && overlay::set_mode(made, source.mode)
        && overlay::set_times(made, source.atime, source.mtime);
}

/// The upper layer's file of overlay file `handle`, copied up first when a
/// lower layer has it: what a change to the file works on.
pub(crate) fn copy_up(handle: Handle) -> Option<Handle> {
    match find(handle)? {
        Found::Unlinked(_, real) => Some(real),
        Found::Named(mount, relative) => copy_up_path(&mount, &relative).ok(),
    }
}

fn copy_up_path(mount: &Mount, relative: &[u8]) -> Result<Handle, Errno> {
    let (layer, source) = resolve(mount, relative).ok_or(ENOENT)?;
    if mount.is_upper(layer) {
        return Ok(source.handle);
    }
    let upper = mount.upper.as_deref().ok_or(EROFS)?;
    copy_up_parents(mount, relative)?;
    let target = join(upper, relative).ok_or(ENOMEM)?;
    let made = match source.kind {
        NodeKind::File => {
            let made = overlay::create_file(&target, source.mode, &[]).ok_or(EIO)?;
            let mut chunk = [0_u8; COPY_CHUNK];
            let mut offset = 0;
            while offset < source.size {
                let read = overlay::read(source.handle, offset, &mut chunk).ok_or(EIO)?;
                if read == 0 {
                    break;
                }
                if overlay::write(made, offset, &chunk[..read]) != Some(read) {
                    let _ = overlay::unlink_path(&target);
                    return Err(EIO);
                }
                offset += read;
            }
            made
        }
        NodeKind::Directory => overlay::create_directory(&target, source.mode).ok_or(EIO)?,
        NodeKind::Symlink => {
            let mut link = [0_u8; overlay::PATH_CAPACITY];
            let length = overlay::read(source.handle, 0, &mut link).ok_or(EIO)?;
            overlay::create_symlink(&target, &link[..length]).ok_or(EIO)?
        }
        NodeKind::Fifo => overlay::create_fifo(&target, source.mode).ok_or(EIO)?,
        NodeKind::Socket => overlay::create_socket(&target, source.mode).ok_or(EIO)?,
        NodeKind::CharacterDevice | NodeKind::BlockDevice => {
            overlay::create_device(&target, source.kind, source.mode, source.device).ok_or(EIO)?
        }
    };
    copy_attributes(made, &source);
    Ok(made)
}

/// Removes a whiteout at the upper layer's canonical `path`; whether one
/// was there.
fn remove_whiteout(path: &[u8]) -> bool {
    overlay::lookup(path).is_some_and(|metadata| is_whiteout(&metadata))
        && overlay::unlink_path(path)
}

/// Leaves a whiteout at `relative` in the upper layer, hiding the lower
/// layers' file there.
fn add_whiteout(mount: &Mount, relative: &[u8]) -> bool {
    let Some(path) = mount
        .upper
        .as_deref()
        .and_then(|upper| join(upper, relative))
    else {
        return false;
    };
    overlay::create_device(&path, NodeKind::CharacterDevice, 0, 0).is_some()
}

/// Creates the file at canonical `path` with `make`, which makes it at the
/// upper layer's path it is given: `None` if `path` is not on an overlay,
/// else the new file's handle, if made. A directory made where a lower
/// layer's name was hidden is opaque.
pub(crate) fn create(
    path: &[u8],
    directory: bool,
    make: impl FnOnce(&[u8]) -> Option<Handle>,
) -> Option<Option<Handle>> {
    let (mount, relative) = route(path)?;
    Some((|| {
        if relative.is_empty() || resolve(&mount, &relative).is_some() {
            return None;
        }
        copy_up_parents(&mount, &relative).ok()?;
        let target = join(mount.upper.as_deref()?, &relative)?;
        // A lower layer's name the whiteout hid stays hidden below a new
        // directory.
        let whiteout = remove_whiteout(&target);
        let real = make(&target)?;
        if directory && whiteout {
            set_opaque(real);
        }
        invalidate_listing();
        handle_for(mount.id, &relative, real)
    })())
}

/// The upper layer's path where a file arriving at canonical `path` (an
/// O_TMPFILE directory, a hard link, a linkat of an unnamed file) goes,
/// its directories copied up and a whiteout there removed: `None` if
/// `path` is not on an overlay.
pub(crate) fn prepare_upper(path: &[u8]) -> Option<Option<Vec<u8>>> {
    let (mount, relative) = route(path)?;
    Some((|| {
        copy_up_parents(&mount, &relative).ok()?;
        if !relative.is_empty() && resolve(&mount, &relative).is_none() {
            let target = join(mount.upper.as_deref()?, &relative)?;
            remove_whiteout(&target);
            invalidate_listing();
            return Some(target);
        }
        let (layer, _) = resolve(&mount, &relative)?;
        if !mount.is_upper(layer) {
            copy_up_path(&mount, &relative).ok()?;
        }
        join(mount.upper.as_deref()?, &relative)
    })())
}

/// Removes the overlay's name at canonical `path` (a file, or an empty
/// directory): the upper layer's file goes, and a lower layer's is hidden
/// by a whiteout. `None` if `path` is not on an overlay.
pub(crate) fn remove(path: &[u8]) -> Option<bool> {
    let (mount, relative) = route(path)?;
    Some(remove_relative(&mount, &relative).is_ok())
}

/// [`remove`] of the name overlay file `handle` has: `None` if it is not
/// an overlay file.
pub(crate) fn unlink(handle: Handle) -> Option<bool> {
    if !owns(handle) {
        return None;
    }
    Some(match find(handle) {
        Some(Found::Named(mount, relative)) => remove_relative(&mount, &relative).is_ok(),
        _ => false,
    })
}

fn remove_relative(mount: &Mount, relative: &[u8]) -> Result<(), Errno> {
    if relative.is_empty() {
        return Err(EIO);
    }
    let found = walk(mount, relative);
    let (layer, real) = found.found.ok_or(ENOENT)?;
    let directory = real.kind == NodeKind::Directory;
    let upper = mount.upper.as_deref().ok_or(EROFS)?;
    let target = join(upper, relative).ok_or(ENOMEM)?;
    if mount.is_upper(layer) {
        if directory {
            // The whiteouts it holds go with it.
            clear_whiteouts(&target);
            if !overlay::unlink(real.handle) {
                return Err(ENOTEMPTY);
            }
            forget_name(mount.id, relative, real.handle);
        } else {
            // Forgotten first, so that the file is held for the overlay's
            // descriptors when its upper file loses its name.
            forget_name(mount.id, relative, real.handle);
            if !overlay::unlink_path(&target) {
                return Err(EIO);
            }
        }
    } else {
        copy_up_parents(mount, relative)?;
        forget_name(mount.id, relative, real.handle);
    }
    if found.lower && !add_whiteout(mount, relative) {
        return Err(EIO);
    }
    Ok(())
}

/// Removes the whiteouts directly in the upper layer's directory `path`.
fn clear_whiteouts(path: &[u8]) {
    let mut whiteouts = Vec::new();
    let mut cursor = 0;
    while let Some(Some(child)) = overlay::next_child_at(path, cursor) {
        cursor = child.next_cursor;
        if is_whiteout(&child.metadata) {
            if let Some(name) = join(path, child.name()) {
                if whiteouts.try_reserve(1).is_ok() {
                    whiteouts.push(name);
                }
            }
        }
    }
    for whiteout in whiteouts {
        let _ = overlay::unlink_path(&whiteout);
    }
}

/// The name `relative` of mount `mount` is gone: a handle given out for it
/// keeps reading `real`, and the name gets a new handle when it comes back.
fn forget_name(mount: u64, relative: &[u8], real: Handle) {
    let mut table = OVERLAYS.lock();
    let Some(key) = copy(relative).map(|relative| (mount, relative)) else {
        return;
    };
    if let Some(generation) = table.named.remove(&key) {
        if let Some(inode) = table.inodes.get_mut(&generation) {
            inode.unlinked = Some(real);
        }
    }
    table.listing = None;
}

/// Handles named below `from` of mount `mount` are now below `to`.
fn moved(mount: u64, from: &[u8], to: &[u8]) {
    let mut table = OVERLAYS.lock();
    let keys: Vec<(u64, Vec<u8>)> = table
        .named
        .keys()
        .filter(|(owner, path)| *owner == mount && below(from, path).is_some())
        .cloned()
        .collect();
    let mut renamed = Vec::new();
    for key in keys {
        let Some(generation) = table.named.remove(&key) else {
            continue;
        };
        let Some(path) = below(from, &key.1).and_then(|rest| join(to, rest)) else {
            continue;
        };
        if let Some(inode) = table.inodes.get_mut(&generation) {
            inode.relative = path.clone();
        }
        renamed.push(((mount, path), generation));
    }
    table.named.extend(renamed);
    table.listing = None;
}

fn invalidate_listing() {
    OVERLAYS.lock().listing = None;
}

/// Renames the upper layer's canonical `from` to `to`.
fn rename_upper(from: &[u8], to: &[u8], mode: RenameMode) -> Result<(), Errno> {
    if crate::linux_blockfs::covers(from) {
        let mode = match mode {
            RenameMode::Replace => ginux_ext2::RenameMode::Replace,
            RenameMode::NoReplace => ginux_ext2::RenameMode::NoReplace,
            RenameMode::Exchange => ginux_ext2::RenameMode::Exchange,
        };
        return crate::linux_blockfs::rename_with(from, to, mode).unwrap_or(Err(EXDEV));
    }
    match (mode, overlay::lookup(to)) {
        (RenameMode::Exchange, _) => {
            let mut temporary = copy(from).ok_or(ENOMEM)?;
            temporary.extend_from_slice(b".ginux-exchange");
            return if overlay::rename_path(from, &temporary)
                && overlay::rename_path(to, from)
                && overlay::rename_path(&temporary, to)
            {
                Ok(())
            } else {
                Err(EIO)
            };
        }
        (RenameMode::NoReplace, Some(_)) => return Err(EEXIST),
        (_, Some(target)) => {
            let removed = if target.kind == NodeKind::Directory {
                overlay::unlink(target.handle)
            } else {
                overlay::unlink_path(to)
            };
            if !removed {
                return Err(ENOTEMPTY);
            }
        }
        (_, None) => {}
    }
    if overlay::rename_path(from, to) {
        Ok(())
    } else {
        Err(EIO)
    }
}

/// rename(2) of canonical `from` to `to`, both on the same overlay: `None`
/// if `from` is not on one, else the errno of a failure.
pub(crate) fn rename(from: &[u8], to: &[u8], mode: RenameMode) -> Option<Result<(), Errno>> {
    let (mount, old) = route(from)?;
    Some((|| {
        let (target_mount, new) = route(to).ok_or(EXDEV)?;
        if target_mount.id != mount.id {
            return Err(EXDEV);
        }
        if old.is_empty() || new.is_empty() {
            return Err(EXDEV);
        }
        let source_walk = walk(&mount, &old);
        let (layer, source) = source_walk.found.ok_or(ENOENT)?;
        let target_walk = walk(&mount, &new);
        let target = target_walk.found;
        if mode == RenameMode::NoReplace && target.is_some() {
            return Err(EEXIST);
        }
        // A directory a lower layer has cannot move (no redirect_dir).
        let lower_directory = |found: &Option<(usize, Metadata)>, lower: bool| {
            found.as_ref().is_some_and(|(layer, metadata)| {
                metadata.kind == NodeKind::Directory && (lower || !mount.is_upper(*layer))
            })
        };
        if lower_directory(&Some((layer, source)), source_walk.lower)
            || mode == RenameMode::Exchange && lower_directory(&target, target_walk.lower)
        {
            return Err(EXDEV);
        }
        if mode == RenameMode::Exchange && target.is_none() {
            return Err(ENOENT);
        }
        let upper = mount.upper.as_deref().ok_or(EROFS)?;
        copy_up_path(&mount, &old)?;
        if mode == RenameMode::Exchange {
            copy_up_path(&mount, &new)?;
        } else {
            copy_up_parents(&mount, &new)?;
        }
        let upper_old = join(upper, &old).ok_or(ENOMEM)?;
        let upper_new = join(upper, &new).ok_or(ENOMEM)?;
        // A directory taking the place of a lower layer's name hides it.
        let mut opaque = false;
        if mode != RenameMode::Exchange {
            match target {
                Some((target_layer, target)) => {
                    if target.kind == NodeKind::Directory {
                        if mount.is_upper(target_layer) {
                            clear_whiteouts(&upper_new);
                        }
                        opaque = target_walk.lower;
                    }
                    forget_name(mount.id, &new, target.handle);
                }
                None => opaque = remove_whiteout(&upper_new),
            }
        }
        rename_upper(&upper_old, &upper_new, mode)?;
        if mode == RenameMode::Exchange {
            exchanged(mount.id, &old, &new);
        } else {
            moved(mount.id, &old, &new);
            if source_walk.lower && !add_whiteout(&mount, &old) {
                return Err(EIO);
            }
        }
        if opaque && source.kind == NodeKind::Directory {
            if let Some((_, renamed)) = resolve(&mount, &new) {
                set_opaque(renamed.handle);
            }
        }
        Ok(())
    })())
}

/// The handles named `first` and `second` of mount `mount` swap names.
fn exchanged(mount: u64, first: &[u8], second: &[u8]) {
    let mut marker = Vec::new();
    marker.extend_from_slice(b"\0exchange");
    moved(mount, first, &marker);
    moved(mount, second, first);
    moved(mount, &marker, second);
}

/// Gives the overlay file `target` another name, canonical `path` on the
/// same overlay: `None` if `target` is not an overlay file.
pub(crate) fn create_link(path: &[u8], target: Handle) -> Option<bool> {
    if !owns(target) {
        return None;
    }
    Some(
        (|| {
            let real = copy_up(target)?;
            let upper = prepare_upper(path)??;
            overlay::create_link(&upper, real).then_some(())
        })()
        .is_some(),
    )
}

/// The entry of the merged directory canonical `path` after `cursor`, a
/// place among its names: `None` if the path is not on an overlay. A
/// listing is made when read from its start and kept for the reads after.
pub(crate) fn next_child_at(path: &[u8], cursor: usize) -> Option<Option<Option<Child>>> {
    let (mount, relative) = route(path)?;
    let kept = {
        let table = OVERLAYS.lock();
        match &table.listing {
            Some((id, directory, names))
                if cursor != 0 && *id == mount.id && *directory == relative =>
            {
                Some(names.get(cursor).and_then(|name| copy(name)))
            }
            _ => None,
        }
    };
    let name = match kept {
        Some(name) => name,
        None => {
            let Some(names) = list(&mount, &relative) else {
                return Some(None);
            };
            let name = names.get(cursor).and_then(|name| copy(name));
            OVERLAYS.lock().listing = Some((mount.id, relative, names));
            name
        }
    };
    let Some(name) = name else {
        return Some(Some(None));
    };
    let child = join(path, &name).and_then(|child| lookup(&child).flatten());
    Some(Some(
        child.map(|metadata| Child::new(cursor + 1, metadata, &name)),
    ))
}

/// The names of the merged directory `relative`: the upper layer's, then
/// each lower one's that no layer above has or whites out.
fn list(mount: &Mount, relative: &[u8]) -> Option<Vec<Vec<u8>>> {
    let layers: Vec<&[u8]> = mount.layers().collect();
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut hidden: Vec<Vec<u8>> = Vec::new();
    for index in walk(mount, relative).merged {
        let directory = join(layers[index], relative)?;
        let mut cursor = 0;
        while let Some(Some(child)) = overlay::next_child_at(&directory, cursor) {
            cursor = child.next_cursor;
            let name = child.name();
            if names.iter().chain(hidden.iter()).any(|seen| seen == name) {
                continue;
            }
            let list = if is_whiteout(&child.metadata) {
                &mut hidden
            } else {
                &mut names
            };
            list.try_reserve(1).ok()?;
            list.push(copy(name)?);
        }
    }
    Some(names)
}

/// Mounts an overlay at canonical `point` of upper layer `upper` (none for
/// a read-only one) over `lowers` (topmost first), its files on `device`.
pub(crate) fn mount(
    point: &[u8],
    upper: Option<&[u8]>,
    lowers: &[&[u8]],
    device: u32,
) -> Result<(), Errno> {
    let mut stored = Vec::new();
    stored.try_reserve_exact(lowers.len()).map_err(|_| ENOMEM)?;
    for lower in lowers {
        stored.push(copy(lower).ok_or(ENOMEM)?);
    }
    let upper = match upper {
        Some(upper) => Some(copy(upper).ok_or(ENOMEM)?),
        None => None,
    };
    let point = copy(point).ok_or(ENOMEM)?;
    let mut table = OVERLAYS.lock();
    table.mounts.try_reserve(1).map_err(|_| ENOMEM)?;
    let id = table.next_mount;
    table.next_mount += 1;
    table.mounts.push(Mount {
        id,
        instance: instance(),
        point,
        upper,
        lowers: stored,
        device,
    });
    MOUNTED.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// The topmost overlay of this domain mounted at canonical `point`.
fn mounted_at(table: &Overlays, point: &[u8]) -> Option<usize> {
    let instance = instance();
    table
        .mounts
        .iter()
        .rposition(|mount| mount.instance == instance && mount.point == point)
}

/// The generations of the overlay at `point` that are given out, for the
/// caller's check that none is in use.
pub(crate) fn generations_at(point: &[u8]) -> Option<Vec<u32>> {
    let table = OVERLAYS.lock();
    let id = table.mounts[mounted_at(&table, point)?].id;
    Some(
        table
            .inodes
            .iter()
            .filter(|(_, inode)| inode.mount == id)
            .map(|(generation, _)| *generation)
            .collect(),
    )
}

/// Unmounts the overlay at canonical `point`; whether one was there.
pub(crate) fn unmount(point: &[u8]) -> bool {
    let mut table = OVERLAYS.lock();
    let Some(index) = mounted_at(&table, point) else {
        return false;
    };
    let id = table.mounts.remove(index).id;
    table.inodes.retain(|_, inode| inode.mount != id);
    table.named.retain(|(mount, _), _| *mount != id);
    table.listing = None;
    MOUNTED.fetch_sub(1, Ordering::Relaxed);
    true
}

/// Moves the overlays mounted at or below canonical `from` to `to`.
pub(crate) fn move_point(from: &[u8], to: &[u8]) {
    let instance = instance();
    let mut table = OVERLAYS.lock();
    for mount in table
        .mounts
        .iter_mut()
        .filter(|mount| mount.instance == instance)
    {
        if let Some(point) = below(from, &mount.point).and_then(|rest| join(to, rest)) {
            mount.point = point;
        }
    }
}

/// Drops the handles of unlinked overlay files that `in_use` says nothing
/// holds any more.
pub(crate) fn reclaim(in_use: impl Fn(u32) -> bool) {
    let unlinked: Vec<u32> = OVERLAYS
        .lock()
        .inodes
        .iter()
        .filter(|(_, inode)| inode.unlinked.is_some())
        .map(|(generation, _)| *generation)
        .collect();
    let gone: Vec<u32> = unlinked
        .into_iter()
        .filter(|generation| !in_use(*generation))
        .collect();
    if gone.is_empty() {
        return;
    }
    let mut table = OVERLAYS.lock();
    for generation in gone {
        table.inodes.remove(&generation);
    }
}

/// Whether a layer's file of generation `real` is still read through an
/// unlinked overlay file that `in_use` says is held.
pub(crate) fn pinned(real: u32, in_use: impl Fn(u32) -> bool) -> bool {
    if !active() {
        return false;
    }
    let holders: Vec<u32> = OVERLAYS
        .lock()
        .inodes
        .iter()
        .filter(|(_, inode)| {
            inode
                .unlinked
                .is_some_and(|handle| overlay::generation(handle) == real)
        })
        .map(|(generation, _)| *generation)
        .collect();
    holders.into_iter().any(in_use)
}

/// Drops this domain's overlays when its files go.
pub(crate) fn forget_instance() {
    let instance = instance();
    let mut table = OVERLAYS.lock();
    let gone: Vec<u64> = table
        .mounts
        .iter()
        .filter(|mount| mount.instance == instance)
        .map(|mount| mount.id)
        .collect();
    table.mounts.retain(|mount| mount.instance != instance);
    table.inodes.retain(|_, inode| !gone.contains(&inode.mount));
    table.named.retain(|(mount, _), _| !gone.contains(mount));
    table.listing = None;
    MOUNTED.fetch_sub(gone.len(), Ordering::Relaxed);
}
