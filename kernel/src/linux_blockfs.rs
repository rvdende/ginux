//! Filesystems on block devices that a domain mounts with mount(2): ext2
//! (`ginux-ext2`) on a loop device or a RAM disk.
//!
//! The overlay's path and handle interface is the kernel's view of files,
//! and a mounted volume plugs in beneath it: [`crate::linux_overlay`] hands
//! a path at or below a volume's mount point, and a handle of a volume's
//! file, to this module, so every system call that goes through the overlay
//! (open, read, write, stat, getdents, mkdir, unlink, rename, xattrs, ...)
//! works on the volume unchanged. A volume owns everything below its mount
//! point; what the overlay held there stays hidden until the unmount.
//!
//! A volume file's handle carries a generation from [`GENERATIONS`], a range
//! the overlay's own never reach, so descriptors (which keep only the
//! generation) find the volume and the inode again. A file whose last name
//! goes while a descriptor, a working directory or a mapping still has it
//! stays allocated on the disk, as Linux keeps an unlinked open file, and
//! is freed by [`reclaim`] once nothing does.
//!
//! The volume reads and writes its device directly: a loop device's
//! backing file through the overlay (the mount holds the device open, so
//! the binding stays put until the unmount, as Linux's loop driver keeps
//! it), and a RAM disk through its driver. The table lock ranks above the
//! locks whose holders make or remove files (loop devices, pseudo-terminals:
//! every path walk looks at the volumes) and below the RAM disks', which
//! volume I/O takes.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use ginux_ext2::{Change, Error, Filesystem, Kind, Options, RenameMode, Timestamp, XattrMode};

use crate::arch::x86_64::cpu;
use crate::linux_overlay::{Child, Handle, Metadata, NodeKind};
use crate::memory;
use crate::sync::{LockRank, SpinLock};

/// Volume file generations: below the overlay's, which start at 2^31.
const GENERATIONS: core::ops::Range<u32> = 0x4000_0000..0x8000_0000;
/// The `FS_*_FL` inode flags `FS_IOC_GETFLAGS` shows and sets on ext2.
const USER_FLAGS: u32 = 0x0003_dfff;

/// The block device a volume lives on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// Loop device `minor`, open as object `open`, bound to `backing` from
    /// byte `offset` for `size` bytes.
    Loop {
        minor: u32,
        open: u64,
        backing: Handle,
        offset: u64,
        size: u64,
    },
    /// RAM disk `minor`, open as object `open`, of `size` bytes.
    Ram { minor: u32, open: u64, size: u64 },
}

impl Source {
    /// The device number stat(2) shows for the volume's files.
    pub(crate) fn device(self) -> u32 {
        let (major, minor) = match self {
            Self::Loop { minor, .. } => (crate::linux_loop::MAJOR, minor),
            Self::Ram { minor, .. } => (crate::linux_ramdisk::MAJOR, minor),
        };
        cpu::linux_device_number(major, minor)
    }
}

/// The device under a mounted filesystem, and the counters its I/O goes
/// into (a loop device's stat file).
pub(crate) struct Disk(Source, Option<Arc<crate::linux_loop::IoCounters>>);

impl Disk {
    fn count(&self, write: bool, bytes: usize) {
        if let Some(io) = &self.1 {
            io.count(write, bytes);
        }
    }
}

impl ginux_ext2::BlockDevice for Disk {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> ginux_ext2::Result<()> {
        self.count(false, buffer.len());
        match self.0 {
            Source::Loop {
                backing,
                offset: start,
                size,
                ..
            } => {
                if offset + buffer.len() as u64 > size {
                    return Err(Error::Io);
                }
                let at = usize::try_from(start + offset).map_err(|_| Error::Io)?;
                let read = crate::linux_overlay::read(backing, at, buffer).ok_or(Error::Io)?;
                // The backing file reads as zeros past its end.
                buffer[read..].fill(0);
                Ok(())
            }
            Source::Ram { open, .. } => match crate::linux_ramdisk::read_at(open, offset, buffer) {
                Ok(read) if read == buffer.len() => Ok(()),
                _ => Err(Error::Io),
            },
        }
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> ginux_ext2::Result<()> {
        self.count(true, data.len());
        match self.0 {
            Source::Loop {
                backing,
                offset: start,
                size,
                ..
            } => {
                if offset + data.len() as u64 > size {
                    return Err(Error::Io);
                }
                let at = usize::try_from(start + offset).map_err(|_| Error::Io)?;
                match crate::linux_overlay::write(backing, at, data) {
                    Some(written) if written == data.len() => Ok(()),
                    _ => Err(Error::Io),
                }
            }
            Source::Ram { open, .. } => match crate::linux_ramdisk::write_at(open, offset, data) {
                Ok(written) if written == data.len() => Ok(()),
                _ => Err(Error::Io),
            },
        }
    }

    fn size(&self) -> u64 {
        match self.0 {
            Source::Loop { size, .. } | Source::Ram { size, .. } => size,
        }
    }
}

struct Volume {
    /// Tells volumes apart across a lock release.
    id: u64,
    instance: usize,
    /// The canonical mount point, without a leading slash ("" for none).
    point: Vec<u8>,
    source: Source,
    filesystem: Filesystem<Disk>,
    /// Generations given out, both ways.
    generations: BTreeMap<u32, u32>,
    inodes: BTreeMap<u32, u32>,
    /// Each inode's path below the mount point, as last looked up.
    paths: BTreeMap<u32, Vec<u8>>,
    /// Inodes with no name left, kept while something has them open.
    orphans: BTreeSet<u32>,
    /// O_TMPFILE files not yet named, and whether linkat may name them.
    temporaries: BTreeMap<u32, bool>,
    /// The pipe socket behind each FIFO opened.
    fifo_sockets: BTreeMap<u32, crate::linux_socket::SlotId>,
    /// Unmounted lazily (MNT_DETACH) while files were open: no path leads
    /// to it, and it goes once they are closed.
    detached: bool,
    /// The page cache: the pages of each file read lately or mapped
    /// shared, in an overlay page cache node.
    caches: BTreeMap<u32, Cache>,
    /// Pages the caches hold, which [`CACHE_LIMIT`] bounds.
    cached_pages: usize,
}

/// One file's cached pages.
#[derive(Clone, Copy)]
struct Cache {
    pages: Handle,
    /// Mapped shared since it was last written back: its pages may be
    /// newer than the disk's.
    mapped: bool,
}

/// Pages a volume's caches hold before unmapped ones are dropped: 32 MiB.
const CACHE_LIMIT: usize = 8192;
const PAGE: usize = 4096;

struct Volumes {
    volumes: Vec<Volume>,
    next_generation: u32,
    next_id: u64,
}

static VOLUMES: SpinLock<Volumes> = SpinLock::new(
    LockRank::VOLUMES,
    Volumes {
        volumes: Vec::new(),
        next_generation: GENERATIONS.start,
        next_id: 0,
    },
);

/// Why a mount failed, as Linux's errno.
pub(crate) type Errno = u64;
const EBUSY: Errno = 16;
const EINVAL: Errno = 22;
const ENOMEM: Errno = 12;

fn errno(error: Error) -> Errno {
    error.errno()
}

fn instance() -> usize {
    cpu::current_linux_execution_instance()
}

fn now() -> Timestamp {
    let (seconds, nanoseconds) = cpu::linux_realtime_now();
    Timestamp::new(seconds, nanoseconds as u32)
}

/// `path` relative to mount point `point`, if it is the point or below it.
fn below<'a>(point: &[u8], path: &'a [u8]) -> Option<&'a [u8]> {
    if point.is_empty() {
        return Some(path);
    }
    let rest = path.strip_prefix(point)?;
    match rest {
        [] => Some(rest),
        [b'/', rest @ ..] => Some(rest),
        _ => None,
    }
}

/// A path's directory and last name ("" and the path for a top entry).
fn split(relative: &[u8]) -> (&[u8], &[u8]) {
    match relative.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => (&relative[..slash], &relative[slash + 1..]),
        None => (&[], relative),
    }
}

fn node_kind(kind: Kind) -> NodeKind {
    match kind {
        Kind::File => NodeKind::File,
        Kind::Directory => NodeKind::Directory,
        Kind::Symlink => NodeKind::Symlink,
        Kind::Fifo => NodeKind::Fifo,
        Kind::Socket => NodeKind::Socket,
        Kind::CharacterDevice => NodeKind::CharacterDevice,
        Kind::BlockDevice => NodeKind::BlockDevice,
    }
}

fn time(timestamp: Timestamp) -> (i64, i64) {
    (timestamp.seconds, i64::from(timestamp.nanoseconds))
}

fn timestamp(time: (i64, i64)) -> Timestamp {
    Timestamp::new(time.0, time.1.clamp(0, 999_999_999) as u32)
}

impl Volumes {
    /// The volume of this domain `path` lies on (the deepest), and the path
    /// below its mount point.
    fn at<'a>(&mut self, path: &'a [u8]) -> Option<(&mut Volume, &'a [u8])> {
        let index = volume_index(self, path)?;
        let volume = &mut self.volumes[index];
        let relative = below(&volume.point, path)?;
        Some((volume, relative))
    }

    fn of(&mut self, handle: Handle) -> Option<(&mut Volume, u32)> {
        let generation = crate::linux_overlay::generation(handle);
        self.volumes.iter_mut().find_map(|volume| {
            let inode = *volume.generations.get(&generation)?;
            Some((volume, inode))
        })
    }

    fn handle(&mut self, index: usize, inode: u32) -> Handle {
        let volume = &mut self.volumes[index];
        let generation = match volume.inodes.get(&inode) {
            Some(generation) => *generation,
            None => {
                let generation = self.next_generation;
                self.next_generation = (generation + 1).min(GENERATIONS.end - 1);
                volume.inodes.insert(inode, generation);
                volume.generations.insert(generation, inode);
                generation
            }
        };
        Handle::volume(generation, u64::from(inode))
    }
}

impl Volume {
    /// The page cache of `inode`, made if `make`.
    fn cache(&mut self, inode: u32, make: bool) -> Option<Cache> {
        if let Some(cache) = self.caches.get(&inode) {
            return Some(*cache);
        }
        if !make {
            return None;
        }
        let size = self.filesystem.stat(inode).ok()?.size as usize;
        let pages = crate::linux_overlay::create_page_cache(size)?;
        let cache = Cache {
            pages,
            mapped: false,
        };
        self.caches.insert(inode, cache);
        Some(cache)
    }

    /// Page `index` of `inode`, cached first if `populate`; None for a page
    /// past the file's end.
    fn page(&mut self, inode: u32, index: usize, populate: bool) -> Option<[u8; PAGE]> {
        let mut page = [0_u8; PAGE];
        if let Some(cache) = self.caches.get(&inode) {
            if crate::linux_overlay::read_cached_page(cache.pages, index, &mut page) {
                return Some(page);
            }
        }
        let read = self
            .filesystem
            .read(inode, (index * PAGE) as u64, &mut page)
            .ok()?;
        if read == 0 {
            return None;
        }
        if populate {
            if self.cached_pages >= CACHE_LIMIT {
                self.drop_caches(Some(inode));
            }
            if let Some(cache) = self.cache(inode, true) {
                if crate::linux_overlay::fill_cached_page(cache.pages, index, &page) {
                    self.cached_pages += 1;
                }
            }
        }
        Some(page)
    }

    /// Writes the pages of `inode`'s cache back to the disk if a shared
    /// mapping may have changed them.
    fn write_back(&mut self, inode: u32) {
        let unmapped = !crate::linux_overlay::mapped_shared(Handle::volume(
            self.inodes.get(&inode).copied().unwrap_or(0),
            u64::from(inode),
        ));
        self.write_back_range(inode, 0, usize::MAX);
        if unmapped {
            if let Some(cache) = self.caches.get_mut(&inode) {
                cache.mapped = false;
            }
        }
    }

    /// Writes back the cached pages of `inode` from byte `start` to `end`
    /// that a shared mapping may have changed.
    fn write_back_range(&mut self, inode: u32, start: usize, end: usize) {
        let Some(cache) = self.caches.get(&inode).filter(|cache| cache.mapped) else {
            return;
        };
        let pages = cache.pages;
        let Ok(size) = self.filesystem.stat(inode).map(|stat| stat.size as usize) else {
            return;
        };
        let mut page = [0_u8; PAGE];
        for index in start / PAGE..end.min(size).div_ceil(PAGE) {
            if crate::linux_overlay::read_cached_page(pages, index, &mut page) {
                let length = (size - index * PAGE).min(PAGE);
                let _ = self
                    .filesystem
                    .write(inode, (index * PAGE) as u64, &page[..length]);
            }
        }
    }

    /// Drops the page caches no shared mapping maps (but `keep`'s), after
    /// writing back what mappings changed.
    fn drop_caches(&mut self, keep: Option<u32>) {
        let inodes: Vec<u32> = self.caches.keys().copied().collect();
        for inode in inodes {
            self.write_back(inode);
            if Some(inode) == keep {
                continue;
            }
            let file = Handle::volume(
                self.inodes.get(&inode).copied().unwrap_or(0),
                u64::from(inode),
            );
            if let Some(cache) = self.caches.get(&inode) {
                if crate::linux_overlay::release_page_cache(cache.pages, file) {
                    self.caches.remove(&inode);
                }
            }
        }
        // What stays is counted again from scratch as it fills.
        self.cached_pages = 0;
    }

    /// Brings the cached pages of `inode` from `start` to `end` up to date
    /// with the disk after a write, and the cache's size with the file's.
    fn refresh_cache(&mut self, inode: u32, start: usize, end: usize) {
        let Some(cache) = self.caches.get(&inode).copied() else {
            return;
        };
        if let Ok(stat) = self.filesystem.stat(inode) {
            let _ = crate::linux_overlay::resize_page_cache(cache.pages, stat.size as usize);
        }
        for index in start / PAGE..end.div_ceil(PAGE) {
            if !crate::linux_overlay::page_cached(cache.pages, index) {
                continue;
            }
            let mut page = [0_u8; PAGE];
            if self
                .filesystem
                .read(inode, (index * PAGE) as u64, &mut page)
                .is_ok()
            {
                let _ = crate::linux_overlay::fill_cached_page(cache.pages, index, &page);
            }
        }
    }

    /// Forgets `inode`'s cache (its file is gone, or the volume), whose
    /// file had generation `generation`.
    fn forget_cache(&mut self, inode: u32, generation: u32) {
        if let Some(cache) = self.caches.remove(&inode) {
            let file = Handle::volume(generation, u64::from(inode));
            let _ = crate::linux_overlay::release_page_cache(cache.pages, file);
        }
    }

    /// Writes back and forgets every cache (the volume goes).
    fn forget_caches(&mut self) {
        let inodes: Vec<u32> = self.caches.keys().copied().collect();
        for inode in inodes {
            self.write_back(inode);
            let generation = self.inodes.get(&inode).copied().unwrap_or(0);
            self.forget_cache(inode, generation);
        }
    }

    /// Whether paths of `instance` reach the volume.
    fn visible(&self, instance: usize) -> bool {
        self.instance == instance && !self.detached
    }

    /// The inode at `relative`, walking from the root: ENOENT for a missing
    /// name, ENOTDIR through a file.
    fn resolve(&mut self, relative: &[u8]) -> Result<u32, Error> {
        let mut inode = ginux_ext2::ROOT_INODE;
        for name in relative.split(|byte| *byte == b'/') {
            if name.is_empty() {
                continue;
            }
            inode = self.filesystem.lookup(inode, name)?;
        }
        Ok(inode)
    }

    fn metadata(&mut self, inode: u32, handle: Handle) -> Option<Metadata> {
        let stat = self.filesystem.stat(inode).ok()?;
        Some(Metadata {
            handle,
            kind: node_kind(stat.kind),
            mode: stat.mode,
            owner: stat.owner,
            group: stat.group,
            links: stat.links,
            device: stat.device,
            attributes: stat.flags & USER_FLAGS,
            size: stat.size as usize,
            atime: time(stat.atime),
            mtime: time(stat.mtime),
            ctime: time(stat.ctime),
            filesystem: self.source.device(),
            sectors: stat.blocks,
            block_size: self.filesystem.block_size(),
            btime: stat.crtime.map(time),
        })
    }

    fn remember(&mut self, inode: u32, relative: &[u8]) {
        let mut path = Vec::new();
        if path.try_reserve_exact(relative.len()).is_ok() {
            path.extend_from_slice(relative);
            self.paths.insert(inode, path);
        }
    }

    /// Notes that `inode` lost a name; one with none left is an orphan.
    fn lost_name(&mut self, inode: u32) {
        if self
            .filesystem
            .stat(inode)
            .is_ok_and(|stat| stat.links == 0)
        {
            self.orphans.insert(inode);
        }
    }

    /// Paths below `from` now lie below `to` (and, when `exchanged`, those
    /// below `to` below `from`).
    fn moved(&mut self, from: &[u8], to: &[u8], exchanged: bool) {
        for path in self.paths.values_mut() {
            let (rest, base) = match below(from, path) {
                Some(rest) => (rest, to),
                None => match below(to, path).filter(|_| exchanged) {
                    Some(rest) => (rest, from),
                    None => continue,
                },
            };
            let mut moved = Vec::new();
            if moved
                .try_reserve_exact(base.len() + 1 + rest.len())
                .is_err()
            {
                continue;
            }
            moved.extend_from_slice(base);
            if !rest.is_empty() {
                if !moved.is_empty() {
                    moved.push(b'/');
                }
                moved.extend_from_slice(rest);
            }
            *path = moved;
        }
    }
}

/// Whether `handle` is a volume file's.
pub(crate) fn owns(handle: Handle) -> bool {
    GENERATIONS.contains(&crate::linux_overlay::generation(handle))
}

/// Whether some volume of this domain is mounted (its symlinks then need
/// following on path walks).
pub(crate) fn any_mounted() -> bool {
    let instance = instance();
    VOLUMES
        .lock()
        .volumes
        .iter()
        .any(|volume| volume.visible(instance))
}

/// Whether canonical `path` lies on a volume.
pub(crate) fn covers(path: &[u8]) -> bool {
    VOLUMES.lock().at(path).is_some()
}

/// What `lookup` of canonical `path` finds: `None` if the path is not on a
/// volume, else the file there, if any.
pub(crate) fn lookup(path: &[u8]) -> Option<Option<Metadata>> {
    let mut table = VOLUMES.lock();
    let index = volume_index(&table, path)?;
    let volume = &mut table.volumes[index];
    let relative = below(&volume.point, path)?;
    let Ok(inode) = volume.resolve(relative) else {
        return Some(None);
    };
    volume.remember(inode, relative);
    let handle = table.handle(index, inode);
    Some(table.volumes[index].metadata(inode, handle))
}

fn volume_index(table: &Volumes, path: &[u8]) -> Option<usize> {
    let instance = instance();
    table
        .volumes
        .iter()
        .enumerate()
        .filter(|(_, volume)| volume.visible(instance) && below(&volume.point, path).is_some())
        .max_by_key(|(_, volume)| volume.point.len())
        .map(|(index, _)| index)
}

pub(crate) fn from_generation(generation: u32) -> Option<Handle> {
    let table = VOLUMES.lock();
    table.volumes.iter().find_map(|volume| {
        let inode = *volume.generations.get(&generation)?;
        Some(Handle::volume(generation, u64::from(inode)))
    })
}

pub(crate) fn metadata(handle: Handle) -> Option<Metadata> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    volume.metadata(inode, handle)
}

pub(crate) fn linked(handle: Handle) -> bool {
    metadata(handle).is_some_and(|metadata| metadata.links > 0)
}

/// The canonical path of `handle`'s file, as last looked up.
pub(crate) fn copy_path(handle: Handle, output: &mut [u8]) -> Option<usize> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let relative = if inode == ginux_ext2::ROOT_INODE {
        &[][..]
    } else {
        volume.paths.get(&inode)?.as_slice()
    };
    let separator = usize::from(!volume.point.is_empty() && !relative.is_empty());
    let length = volume.point.len() + separator + relative.len();
    let output = output.get_mut(..length)?;
    output[..volume.point.len()].copy_from_slice(&volume.point);
    if separator == 1 {
        output[volume.point.len()] = b'/';
    }
    output[volume.point.len() + separator..].copy_from_slice(relative);
    Some(length)
}

/// The entry of directory `path` after `cursor` (a byte offset in the
/// directory), `.` and `..` left out; `None` if `path` is not on a volume.
pub(crate) fn next_child_at(path: &[u8], cursor: usize) -> Option<Option<Option<Child>>> {
    let mut table = VOLUMES.lock();
    let index = volume_index(&table, path)?;
    let volume = &mut table.volumes[index];
    let relative = below(&volume.point, path)?;
    let Ok(directory) = volume.resolve(relative) else {
        return Some(None);
    };
    let mut offset = cursor as u64;
    loop {
        let (entry, next) = match volume.filesystem.read_dir(directory, offset) {
            Ok(Some(found)) => found,
            Ok(None) => return Some(Some(None)),
            Err(_) => return Some(None),
        };
        offset = next;
        if entry.name() == b"." || entry.name() == b".." {
            continue;
        }
        let mut child_path = Vec::new();
        if child_path
            .try_reserve_exact(relative.len() + 1 + entry.name().len())
            .is_ok()
        {
            child_path.extend_from_slice(relative);
            if !relative.is_empty() {
                child_path.push(b'/');
            }
            child_path.extend_from_slice(entry.name());
            volume.remember(entry.inode, &child_path);
        }
        let handle = table.handle(index, entry.inode);
        let metadata = table.volumes[index].metadata(entry.inode, handle)?;
        return Some(Some(Some(Child::new(
            next as usize,
            metadata,
            entry.name(),
        ))));
    }
}

/// What a new file is.
#[derive(Clone, Copy)]
pub(crate) enum New<'a> {
    File(&'a [u8]),
    Directory,
    Symlink(&'a [u8]),
    Fifo,
    Socket,
    Device(NodeKind, u32),
}

/// Creates the file at canonical `path` with `mode`, `owner` and `group`;
/// `None` if the path is not on a volume, else the handle, if made.
pub(crate) fn create(
    path: &[u8],
    new: New,
    mode: u32,
    owner: u32,
    group: u32,
) -> Option<Option<Handle>> {
    let now = now();
    let mut table = VOLUMES.lock();
    let index = volume_index(&table, path)?;
    let volume = &mut table.volumes[index];
    let relative = below(&volume.point, path)?;
    let (parent_path, name) = split(relative);
    let Ok(parent) = volume.resolve(parent_path) else {
        return Some(None);
    };
    let filesystem = &mut volume.filesystem;
    let made = match new {
        New::Symlink(target) => filesystem.symlink(parent, name, target, owner, group, now),
        New::File(_) => filesystem.create(parent, name, Kind::File, mode, owner, group, 0, now),
        New::Directory => {
            filesystem.create(parent, name, Kind::Directory, mode, owner, group, 0, now)
        }
        New::Fifo => filesystem.create(parent, name, Kind::Fifo, mode, owner, group, 0, now),
        New::Socket => filesystem.create(parent, name, Kind::Socket, mode, owner, group, 0, now),
        New::Device(kind, device) => {
            let kind = if kind == NodeKind::BlockDevice {
                Kind::BlockDevice
            } else {
                Kind::CharacterDevice
            };
            filesystem.create(parent, name, kind, mode, owner, group, device, now)
        }
    };
    let Ok(inode) = made else {
        return Some(None);
    };
    if let New::File(initial) = new {
        if !initial.is_empty() && volume.filesystem.write(inode, 0, initial) != Ok(initial.len()) {
            let _ = volume.filesystem.unlink(parent, name, now);
            let _ = volume.filesystem.release(inode, now);
            return Some(None);
        }
    }
    volume.remember(inode, relative);
    Some(Some(table.handle(index, inode)))
}

/// An O_TMPFILE file in directory `path`: made under a scratch name and
/// unlinked at once, kept until linkat names it or nothing has it open.
pub(crate) fn create_temporary(
    path: &[u8],
    mode: u32,
    owner: u32,
    group: u32,
    linkable: bool,
) -> Option<Option<Handle>> {
    const NAME: &[u8] = b".ginux-o-tmpfile";
    let now = now();
    let mut table = VOLUMES.lock();
    let index = volume_index(&table, path)?;
    let volume = &mut table.volumes[index];
    let relative = below(&volume.point, path)?;
    let Ok(parent) = volume.resolve(relative) else {
        return Some(None);
    };
    let Ok(inode) = volume
        .filesystem
        .create(parent, NAME, Kind::File, mode, owner, group, 0, now)
    else {
        return Some(None);
    };
    if volume.filesystem.unlink(parent, NAME, now).is_err() {
        return Some(None);
    }
    volume.orphans.insert(inode);
    volume.temporaries.insert(inode, linkable);
    volume.remember(inode, relative);
    Some(Some(table.handle(index, inode)))
}

/// linkat(2) of an O_TMPFILE file to canonical `path`.
pub(crate) fn link_unnamed(
    path: &[u8],
    handle: Handle,
) -> Option<Result<(), crate::linux_overlay::LinkError>> {
    use crate::linux_overlay::LinkError;
    let now = now();
    let mut table = VOLUMES.lock();
    let path_volume = volume_index(&table, path);
    let (volume, inode) = table.of(handle)?;
    let point = volume.point.clone();
    if path_volume.is_none() || below(&point, path).is_none() {
        return Some(Err(LinkError::CrossDevice));
    }
    if volume.temporaries.get(&inode) != Some(&true) {
        return Some(Err(LinkError::Gone));
    }
    let relative = below(&point, path)?;
    let (parent_path, name) = split(relative);
    let Ok(parent) = volume.resolve(parent_path) else {
        return Some(Err(LinkError::Failed));
    };
    match volume.filesystem.link(parent, name, inode, now) {
        Ok(()) => {
            volume.temporaries.remove(&inode);
            volume.orphans.remove(&inode);
            volume.remember(inode, relative);
            Some(Ok(()))
        }
        Err(Error::Exists) => Some(Err(LinkError::Exists)),
        Err(_) => Some(Err(LinkError::Failed)),
    }
}

/// Reads `handle`'s file at `offset`: a regular file's data or a
/// symlink's target.
pub(crate) fn read(handle: Handle, offset: usize, output: &mut [u8]) -> Option<usize> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let filesystem = &mut volume.filesystem;
    match filesystem.stat(inode).ok()?.kind {
        Kind::File => {
            // Through the page cache, which reads fill.
            let size = filesystem.stat(inode).ok()?.size as usize;
            let end = offset.saturating_add(output.len()).min(size);
            let mut position = offset;
            while position < end {
                let within = position % PAGE;
                let length = (end - position).min(PAGE - within);
                let page = volume.page(inode, position / PAGE, true)?;
                output[position - offset..position - offset + length]
                    .copy_from_slice(&page[within..within + length]);
                position += length;
            }
            Some(end.saturating_sub(offset))
        }
        Kind::Symlink => {
            let mut target = [0; 4096];
            let length = filesystem.read_link(inode, &mut target).ok()?;
            let target = target.get(offset.min(length)..length)?;
            let copied = target.len().min(output.len());
            output[..copied].copy_from_slice(&target[..copied]);
            Some(copied)
        }
        _ => None,
    }
}

/// The frame holding page `index` of `handle`'s file in the page cache
/// (cached first if `load`): what a shared mapping of the page maps.
pub(crate) fn cached_frame(handle: Handle, index: usize, load: bool) -> Option<memory::FrameLease> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let cache = volume.cache(inode, load)?;
    if load && !crate::linux_overlay::page_cached(cache.pages, index) {
        // A page past the end maps as zeros, as a hole would.
        let page = volume.page(inode, index, false).unwrap_or([0; PAGE]);
        if !crate::linux_overlay::fill_cached_page(cache.pages, index, &page) {
            return None;
        }
        volume.cached_pages += 1;
    }
    if load {
        crate::linux_overlay::memfd_frame(cache.pages, index)
    } else {
        crate::linux_overlay::paged_frame(cache.pages, index)
    }
}

/// mmap(MAP_SHARED) of `handle`'s file: its mappings map its cached pages,
/// which go back to the disk at msync, fsync, sync and unmount.
pub(crate) fn map_shared(handle: Handle) -> bool {
    let mut table = VOLUMES.lock();
    let Some((volume, inode)) = table.of(handle) else {
        return false;
    };
    if volume.filesystem.stat(inode).map(|stat| stat.kind) != Ok(Kind::File) {
        return false;
    }
    match volume.cache(inode, true) {
        Some(_) => {
            if let Some(cache) = volume.caches.get_mut(&inode) {
                cache.mapped = true;
            }
            true
        }
        None => false,
    }
}

/// The volume file with cached pages that is `inode` on device `device`.
pub(crate) fn cached_file(device: u64, inode: u64) -> Option<Handle> {
    let mut table = VOLUMES.lock();
    let index = table.volumes.iter().position(|volume| {
        u64::from(volume.source.device()) == device
            && u32::try_from(inode).is_ok_and(|inode| volume.caches.contains_key(&inode))
    })?;
    Some(table.handle(index, u32::try_from(inode).ok()?))
}

/// How many bytes of `handle`'s file from `offset` (up to `length`) the
/// page cache holds: what an RWF_NOWAIT read may read without the disk.
pub(crate) fn cached_bytes(handle: Handle, offset: usize, length: usize) -> Option<usize> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let size = volume.filesystem.stat(inode).ok()?.size as usize;
    let end = offset.saturating_add(length).min(size);
    let Some(cache) = volume.cache(inode, false) else {
        return Some(0);
    };
    let mut position = offset;
    while position < end && crate::linux_overlay::page_cached(cache.pages, position / PAGE) {
        position = (position / PAGE + 1) * PAGE;
    }
    Some(position.min(end).saturating_sub(offset))
}

/// Writes back what shared mappings changed, on every volume (msync,
/// fsync, sync).
pub(crate) fn write_back_all() {
    for volume in &mut VOLUMES.lock().volumes {
        let inodes: Vec<u32> = volume.caches.keys().copied().collect();
        for inode in inodes {
            volume.write_back(inode);
        }
    }
}

/// /proc/sys/vm/drop_caches: drops the cached pages no shared mapping
/// maps, as Linux drops clean page cache.
pub(crate) fn drop_caches() {
    for volume in &mut VOLUMES.lock().volumes {
        volume.drop_caches(None);
    }
}

/// Writes `handle`'s file at `offset` and marks it modified.
pub(crate) fn write(handle: Handle, offset: usize, input: &[u8]) -> Option<usize> {
    let now = now();
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    // Pages a mapping changed go to the disk first, so the write lands on
    // them.
    volume.write_back_range(inode, offset, offset.saturating_add(input.len()));
    let written = volume.filesystem.write(inode, offset as u64, input).ok()?;
    volume.refresh_cache(inode, offset, offset + written);
    if written != 0 {
        let _ = volume.filesystem.change(
            inode,
            &Change {
                mtime: Some(now),
                ctime: Some(now),
                ..Change::default()
            },
        );
    }
    Some(written)
}

/// What fallocate(2) asks of a volume's file.
#[derive(Clone, Copy)]
pub(crate) enum Allocation {
    /// Allocate (FALLOC_FL_KEEP_SIZE: without growing the file).
    Allocate {
        keep_size: bool,
    },
    PunchHole,
    ZeroRange {
        keep_size: bool,
    },
    CollapseRange,
    InsertRange,
}

/// fallocate(2) on `handle`'s file, from `offset` for `length` bytes;
/// marks it modified when it changes the data or the size.
pub(crate) fn fallocate(
    handle: Handle,
    allocation: Allocation,
    offset: u64,
    length: u64,
) -> Option<Result<(), Errno>> {
    let now = now();
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    // What mappings changed reaches the disk before the blocks move.
    volume.write_back(inode);
    let size = volume.filesystem.stat(inode).ok()?.size;
    let filesystem = &mut volume.filesystem;
    let result = match allocation {
        Allocation::Allocate { keep_size } => filesystem.allocate(inode, offset, length, keep_size),
        Allocation::PunchHole => filesystem.punch_hole(inode, offset, length),
        Allocation::ZeroRange { keep_size } => {
            filesystem.zero_range(inode, offset, length, keep_size)
        }
        Allocation::CollapseRange => filesystem.collapse_range(inode, offset, length),
        Allocation::InsertRange => filesystem.insert_range(inode, offset, length),
    };
    let new_size = volume.filesystem.stat(inode).ok()?.size;
    // Shifted ranges move every page after them.
    let end = match allocation {
        Allocation::CollapseRange | Allocation::InsertRange => size.max(new_size),
        _ => offset.saturating_add(length).min(size.max(new_size)),
    };
    volume.refresh_cache(inode, offset as usize, end as usize);
    let changed = !matches!(allocation, Allocation::Allocate { .. }) || new_size != size;
    if result.is_ok() && changed {
        let _ = volume.filesystem.change(
            inode,
            &Change {
                mtime: Some(now),
                ctime: Some(now),
                ..Change::default()
            },
        );
    }
    Some(result.map_err(errno))
}

/// Where the next data (`data`) or hole of `handle`'s file at or after
/// `offset` starts (lseek's SEEK_DATA and SEEK_HOLE); `None` within for
/// ENXIO.
pub(crate) fn seek(handle: Handle, offset: u64, data: bool) -> Option<Option<u64>> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    volume.write_back(inode);
    volume.filesystem.seek(inode, offset, data).ok()
}

pub(crate) fn truncate(handle: Handle, size: usize) -> Option<bool> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    volume.write_back(inode);
    let truncated = volume.filesystem.truncate(inode, size as u64).is_ok();
    if let Some(cache) = volume.cache(inode, false) {
        // Cut-off pages read as zeros if the file grows again.
        let _ = crate::linux_overlay::truncate(cache.pages, size);
    }
    Some(truncated)
}

/// Applies `change` to `handle`'s file.
pub(crate) fn change(handle: Handle, change: &Change) -> Option<bool> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    Some(volume.filesystem.change(inode, change).is_ok())
}

/// chmod(2): the mode, and the change time.
pub(crate) fn set_mode(handle: Handle, mode: u32) -> Option<bool> {
    change(
        handle,
        &Change {
            mode: Some(mode),
            ctime: Some(now()),
            ..Change::default()
        },
    )
}

pub(crate) fn set_attributes(handle: Handle, attributes: u32) -> Option<bool> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let flags = volume.filesystem.stat(inode).ok()?.flags;
    let flags = flags & !USER_FLAGS | attributes & USER_FLAGS;
    Some(
        volume
            .filesystem
            .change(
                inode,
                &Change {
                    flags: Some(flags),
                    ..Change::default()
                },
            )
            .is_ok(),
    )
}

/// chown(2): the owner and group, and the change time.
pub(crate) fn set_owner(handle: Handle, owner: u32, group: u32) -> Option<bool> {
    change(
        handle,
        &Change {
            owner: Some(owner),
            group: Some(group),
            ctime: Some(now()),
            ..Change::default()
        },
    )
}

pub(crate) fn touch_modified(handle: Handle, now: (i64, i64)) -> Option<bool> {
    change(
        handle,
        &Change {
            mtime: Some(timestamp(now)),
            ctime: Some(timestamp(now)),
            ..Change::default()
        },
    )
}

/// Sets `handle`'s access time alone (a read's update).
pub(crate) fn touch_accessed(handle: Handle, time: (i64, i64)) -> Option<bool> {
    change(
        handle,
        &Change {
            atime: Some(timestamp(time)),
            ..Change::default()
        },
    )
}

pub(crate) fn set_times(handle: Handle, atime: (i64, i64), mtime: (i64, i64)) -> Option<bool> {
    change(
        handle,
        &Change {
            atime: Some(timestamp(atime)),
            mtime: Some(timestamp(mtime)),
            ctime: Some(now()),
            ..Change::default()
        },
    )
}

pub(crate) fn fifo_socket(handle: Handle) -> Option<Option<crate::linux_socket::SlotId>> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    Some(volume.fifo_sockets.get(&inode).copied())
}

pub(crate) fn set_fifo_socket(handle: Handle, slot: crate::linux_socket::SlotId) -> Option<bool> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    volume.fifo_sockets.insert(inode, slot);
    Some(true)
}

/// Sets extended attribute `name`; the value comes from `fill` a chunk at
/// a time, as the overlay's does.
pub(crate) fn set_xattr_from<F>(
    handle: Handle,
    name: &[u8],
    value_size: usize,
    create_only: bool,
    replace_only: bool,
    mut fill: F,
) -> Option<bool>
where
    F: FnMut(usize, &mut [u8]) -> bool,
{
    let mut value = Vec::new();
    if value.try_reserve_exact(value_size).is_err() {
        return Some(false);
    }
    value.resize(value_size, 0);
    if !value.is_empty() && !fill(0, &mut value) {
        return Some(false);
    }
    let mode = match (create_only, replace_only) {
        (true, _) => XattrMode::Create,
        (_, true) => XattrMode::Replace,
        _ => XattrMode::Any,
    };
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let set = volume
        .filesystem
        .set_xattr(inode, name, &value, mode)
        .is_ok();
    if set {
        let _ = volume.filesystem.change(
            inode,
            &Change {
                ctime: Some(now()),
                ..Change::default()
            },
        );
    }
    Some(set)
}

/// Copies attribute `name`'s value from `offset` into `output`; returns its
/// size and how much was copied.
pub(crate) fn get_xattr_chunk(
    handle: Handle,
    name: &[u8],
    offset: usize,
    output: &mut [u8],
) -> Option<Option<(usize, usize)>> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let Ok(value) = volume.filesystem.get_xattr(inode, name) else {
        return Some(None);
    };
    Some(Some(copy_chunk(&value, offset, output)))
}

pub(crate) fn list_xattrs_chunk(
    handle: Handle,
    offset: usize,
    output: &mut [u8],
) -> Option<Option<(usize, usize)>> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let Ok(names) = volume.filesystem.list_xattrs(inode) else {
        return Some(None);
    };
    Some(Some(copy_chunk(&names, offset, output)))
}

fn copy_chunk(bytes: &[u8], offset: usize, output: &mut [u8]) -> (usize, usize) {
    let source = bytes.get(offset..).unwrap_or(&[]);
    let copied = source.len().min(output.len());
    output[..copied].copy_from_slice(&source[..copied]);
    (bytes.len(), copied)
}

pub(crate) fn remove_xattr(handle: Handle, name: &[u8]) -> Option<bool> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    let removed = volume.filesystem.remove_xattr(inode, name).is_ok();
    if removed {
        let _ = volume.filesystem.change(
            inode,
            &Change {
                ctime: Some(now()),
                ..Change::default()
            },
        );
    }
    Some(removed)
}

/// Gives `target`'s file the further name canonical `path`.
pub(crate) fn create_link(path: &[u8], target: Handle) -> Option<bool> {
    let now = now();
    let mut table = VOLUMES.lock();
    let path_volume = volume_index(&table, path);
    let (volume, inode) = table.of(target)?;
    let point = volume.point.clone();
    let Some(relative) = below(&point, path).filter(|_| path_volume.is_some()) else {
        return Some(false);
    };
    let (parent_path, name) = split(relative);
    let Ok(parent) = volume.resolve(parent_path) else {
        return Some(false);
    };
    Some(volume.filesystem.link(parent, name, inode, now).is_ok())
}

/// Removes the name canonical `path` (a file, or an empty directory).
pub(crate) fn unlink_path(path: &[u8]) -> Option<bool> {
    let now = now();
    let mut table = VOLUMES.lock();
    let (volume, relative) = table.at(path)?;
    if relative.is_empty() {
        return Some(false);
    }
    let (parent_path, name) = split(relative);
    let Ok(parent) = volume.resolve(parent_path) else {
        return Some(false);
    };
    let Ok(inode) = volume.filesystem.lookup(parent, name) else {
        return Some(false);
    };
    let removed = match volume.filesystem.stat(inode).map(|stat| stat.kind) {
        Ok(Kind::Directory) => volume.filesystem.rmdir(parent, name, now),
        Ok(_) => volume.filesystem.unlink(parent, name, now),
        Err(error) => Err(error),
    };
    if removed.is_err() {
        return Some(false);
    }
    volume.lost_name(inode);
    Some(true)
}

/// Removes `handle`'s name (as last looked up).
pub(crate) fn unlink(handle: Handle) -> Option<bool> {
    let mut path = Vec::new();
    path.try_reserve_exact(crate::linux_overlay::PATH_CAPACITY)
        .ok()?;
    path.resize(crate::linux_overlay::PATH_CAPACITY, 0);
    let length = copy_path(handle, &mut path)?;
    unlink_path(&path[..length])
}

/// Renames canonical `from` to `to`, replacing what `to` names.
pub(crate) fn rename_path(from: &[u8], to: &[u8]) -> Option<bool> {
    rename_with(from, to, RenameMode::Replace).map(|result| result.is_ok())
}

/// Renames canonical `from` to `to` as `mode` says; `None` if `from` is
/// not on a volume, else the errno of a failure.
pub(crate) fn rename_with(from: &[u8], to: &[u8], mode: RenameMode) -> Option<Result<(), Errno>> {
    let now = now();
    let mut table = VOLUMES.lock();
    let from_volume = volume_index(&table, from)?;
    if volume_index(&table, to) != Some(from_volume) {
        // Different filesystems: EXDEV.
        return Some(Err(18));
    }
    let volume = &mut table.volumes[from_volume];
    let point = volume.point.clone();
    let (Some(old), Some(new)) = (below(&point, from), below(&point, to)) else {
        return Some(Err(18));
    };
    if old.is_empty() || new.is_empty() {
        return Some(Err(EBUSY));
    }
    let (old_parent_path, old_name) = split(old);
    let (new_parent_path, new_name) = split(new);
    let parents = volume
        .resolve(old_parent_path)
        .and_then(|old_parent| Ok((old_parent, volume.resolve(new_parent_path)?)));
    let (old_parent, new_parent) = match parents {
        Ok(parents) => parents,
        Err(error) => return Some(Err(errno(error))),
    };
    let moved = volume.filesystem.lookup(old_parent, old_name).ok();
    let target = volume.filesystem.lookup(new_parent, new_name).ok();
    match volume
        .filesystem
        .rename(old_parent, old_name, new_parent, new_name, mode, now)
    {
        Ok(replaced) => {
            if mode == RenameMode::Exchange {
                volume.moved(old, new, true);
            } else {
                volume.moved(old, new, false);
            }
            if let Some(replaced) = replaced {
                volume.lost_name(replaced);
            }
            if let (Some(moved), Some(target)) = (moved, target) {
                if mode == RenameMode::Exchange {
                    volume.remember(target, old);
                }
                volume.remember(moved, new);
            } else if let Some(moved) = moved {
                volume.remember(moved, new);
            }
            Some(Ok(()))
        }
        Err(error) => Some(Err(errno(error))),
    }
}

/// Renames `handle`'s file to canonical `path`.
pub(crate) fn rename(handle: Handle, path: &[u8]) -> Option<bool> {
    let mut from = Vec::new();
    from.try_reserve_exact(crate::linux_overlay::PATH_CAPACITY)
        .ok()?;
    from.resize(crate::linux_overlay::PATH_CAPACITY, 0);
    let length = copy_path(handle, &mut from)?;
    rename_path(&from[..length], path)
}

/// Frees the orphans nothing has open any more: `in_use` says whether a
/// generation is still held by a descriptor or working directory. It runs
/// without the table lock, since it looks at every process.
pub(crate) fn reclaim(in_use: impl Fn(u32) -> bool) -> Vec<Source> {
    let candidates: Vec<(u64, u32, Option<u32>)> = VOLUMES
        .lock()
        .volumes
        .iter()
        .flat_map(|volume| {
            volume
                .orphans
                .iter()
                .map(|inode| (volume.id, *inode, volume.inodes.get(inode).copied()))
        })
        .collect();
    let unused: Vec<(u64, u32)> = candidates
        .into_iter()
        .filter(|(_, _, generation)| !generation.is_some_and(&in_use))
        .map(|(volume, inode, _)| (volume, inode))
        .collect();
    let detached: Vec<(u64, Vec<u32>)> = VOLUMES
        .lock()
        .volumes
        .iter()
        .filter(|volume| volume.detached)
        .map(|volume| (volume.id, volume.generations.keys().copied().collect()))
        .collect();
    let idle: Vec<u64> = detached
        .into_iter()
        .filter(|(_, generations)| !generations.iter().copied().any(&in_use))
        .map(|(id, _)| id)
        .collect();
    let finished = finish_detached(&idle);
    if unused.is_empty() {
        return finished;
    }
    let now = now();
    let mut table = VOLUMES.lock();
    for (id, inode) in unused {
        let Some(volume) = table.volumes.iter_mut().find(|volume| volume.id == id) else {
            continue;
        };
        if !volume.orphans.remove(&inode) {
            continue;
        }
        volume.temporaries.remove(&inode);
        volume.fifo_sockets.remove(&inode);
        volume.paths.remove(&inode);
        let generation = volume.inodes.get(&inode).copied().unwrap_or(0);
        volume.forget_cache(inode, generation);
        if let Some(generation) = volume.inodes.remove(&inode) {
            volume.generations.remove(&generation);
        }
        let _ = volume.filesystem.release(inode, now);
    }
    finished
}

/// Unmounts the detached volumes `ids`, whose files are all closed;
/// returns their devices, for the caller to release.
fn finish_detached(ids: &[u64]) -> Vec<Source> {
    let gone: Vec<Volume> = {
        let mut table = VOLUMES.lock();
        let (gone, kept) = core::mem::take(&mut table.volumes)
            .into_iter()
            .partition(|volume| volume.detached && ids.contains(&volume.id));
        table.volumes = kept;
        gone
    };
    let now = now();
    gone.into_iter()
        .filter_map(|mut volume| {
            volume.forget_caches();
            for inode in core::mem::take(&mut volume.orphans) {
                let _ = volume.filesystem.release(inode, now);
            }
            let source = volume.source;
            volume.filesystem.unmount(now).ok().map(|_| source)
        })
        .collect()
}

/// Whether some volume keeps a file that lost its last name while open,
/// or was unmounted lazily: [`reclaim`] has work.
pub(crate) fn has_orphans() -> bool {
    VOLUMES
        .lock()
        .volumes
        .iter()
        .any(|volume| volume.detached || !volume.orphans.is_empty())
}

/// MNT_DETACH of the volume at canonical `point` while its files are in
/// use: it leaves the namespace now and goes when they are closed.
pub(crate) fn detach(point: &[u8]) -> bool {
    let mut table = VOLUMES.lock();
    let Some(index) = mounted_at(&table, point) else {
        return false;
    };
    table.volumes[index].detached = true;
    true
}

// ---- mounting ----

/// Mounts the ext2 filesystem on `source` at canonical `point` in this
/// domain. The device stays the caller's to release on failure.
pub(crate) fn mount(
    point: &[u8],
    source: Source,
    io: Option<Arc<crate::linux_loop::IoCounters>>,
    read_only: bool,
    fs_type: ginux_ext2::FsType,
) -> Result<(), Errno> {
    let mut stored = Vec::new();
    stored.try_reserve_exact(point.len()).map_err(|_| ENOMEM)?;
    stored.extend_from_slice(point);
    let filesystem = Filesystem::mount(
        Disk(source, io),
        Options {
            read_only,
            now: now(),
            fs_type,
        },
    )
    .map_err(|error| match error {
        Error::Io | Error::NoMemory | Error::ReadOnly => errno(error),
        _ => EINVAL,
    })?;
    let mut table = VOLUMES.lock();
    table.volumes.try_reserve(1).map_err(|_| ENOMEM)?;
    let id = table.next_id;
    table.next_id += 1;
    table.volumes.push(Volume {
        id,
        instance: instance(),
        point: stored,
        source,
        filesystem,
        generations: BTreeMap::new(),
        inodes: BTreeMap::new(),
        paths: BTreeMap::new(),
        orphans: BTreeSet::new(),
        temporaries: BTreeMap::new(),
        fifo_sockets: BTreeMap::new(),
        detached: false,
        caches: BTreeMap::new(),
        cached_pages: 0,
    });
    Ok(())
}

/// Whether block device `device` (a dev_t) backs a mounted volume.
pub(crate) fn device_mounted(device: u32) -> bool {
    VOLUMES
        .lock()
        .volumes
        .iter()
        .any(|volume| volume.source.device() == device)
}

/// The topmost volume of this domain mounted exactly at canonical `point`.
fn mounted_at(table: &Volumes, point: &[u8]) -> Option<usize> {
    let instance = instance();
    table
        .volumes
        .iter()
        .rposition(|volume| volume.visible(instance) && volume.point == point)
}

/// The generations of the volume at `point` that are given out, for the
/// caller's check that none is open.
pub(crate) fn generations_at(point: &[u8]) -> Option<Vec<u32>> {
    let table = VOLUMES.lock();
    let index = mounted_at(&table, point)?;
    Some(table.volumes[index].generations.keys().copied().collect())
}

/// Unmounts the volume at canonical `point` (the caller has checked none
/// of its files is in use, [`generations_at`]), freeing the files that
/// lost their names. Returns its device, for the caller to release; `None`
/// if no volume is mounted there.
pub(crate) fn unmount(point: &[u8]) -> Option<Result<Source, Errno>> {
    let mut table = VOLUMES.lock();
    let index = mounted_at(&table, point)?;
    let mut volume = table.volumes.remove(index);
    drop(table);
    let now = now();
    volume.forget_caches();
    for inode in core::mem::take(&mut volume.orphans) {
        let _ = volume.filesystem.release(inode, now);
    }
    let source = volume.source;
    Some(
        volume
            .filesystem
            .unmount(now)
            .map(|_| source)
            .map_err(errno),
    )
}

/// MS_REMOUNT of the volume at canonical `point`: read-only or writable.
pub(crate) fn remount(point: &[u8], read_only: bool) -> Option<Result<(), Errno>> {
    let mut table = VOLUMES.lock();
    let index = mounted_at(&table, point)?;
    Some(
        table.volumes[index]
            .filesystem
            .set_read_only(read_only, now())
            .map_err(errno),
    )
}

/// Writes every volume's superblock counts (sync(2), syncfs(2)).
pub(crate) fn sync_all() {
    for volume in &mut VOLUMES.lock().volumes {
        let inodes: Vec<u32> = volume.caches.keys().copied().collect();
        for inode in inodes {
            volume.write_back(inode);
        }
        let _ = volume.filesystem.sync();
    }
}

/// Where `handle`'s data from `start` for `length` bytes lies on the disk.
pub(crate) fn extents(handle: Handle, start: u64, length: u64) -> Option<Vec<ginux_ext2::Extent>> {
    let mut table = VOLUMES.lock();
    let (volume, inode) = table.of(handle)?;
    volume.filesystem.extents(inode, start, length).ok()
}

/// The volume `handle`'s file is on, and the largest file it holds
/// (`s_maxbytes`): copy_file_range copies within one filesystem only.
pub(crate) fn volume_of(handle: Handle) -> Option<(u64, u64)> {
    let mut table = VOLUMES.lock();
    let (volume, _) = table.of(handle)?;
    Some((volume.id, volume.filesystem.max_file_size()))
}

/// statfs(2) of the volume `handle`'s file is on.
pub(crate) fn statfs_of(handle: Handle) -> Option<ginux_ext2::Statfs> {
    let mut table = VOLUMES.lock();
    let (volume, _) = table.of(handle)?;
    Some(volume.filesystem.statfs())
}

/// Drops this domain's volumes when its overlay goes, without writing
/// them back: their devices go with the domain too.
pub(crate) fn forget_instance() {
    let instance = instance();
    let removed: Vec<Volume> = {
        let mut table = VOLUMES.lock();
        let (gone, kept) = core::mem::take(&mut table.volumes)
            .into_iter()
            .partition(|volume| volume.instance == instance);
        table.volumes = kept;
        gone
    };
    drop(removed);
}
