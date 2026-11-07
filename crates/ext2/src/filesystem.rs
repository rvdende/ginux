//! A mounted ext2, ext3 or ext4 filesystem: allocation, block maps, file
//! data, and the operations that change the namespace.

use alloc::vec;
use alloc::vec::Vec;

use crate::bytes::{set_u32, u32_at};
use crate::cache::BlockCache;
use crate::checksum::crc32c;
use crate::extent::{self, ExtentMap, Run};
use crate::inode::{
    Inode, Kind, Stat, Time, BLOCK_POINTERS, DIRECT_BLOCKS, EXTENTS_FL, FAST_SYMLINK_MAX, INDEX_FL,
};
use crate::layout::{
    GroupDescriptor, Superblock, COMPAT_HAS_JOURNAL, GROUP_BLOCK_UNINIT, GROUP_INODE_UNINIT,
    INCOMPAT_FILETYPE, INCOMPAT_RECOVER, RO_COMPAT_LARGE_FILE, RO_COMPAT_SPARSE_SUPER,
    SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE,
};
use crate::{BlockDevice, Error, Result, Timestamp, NAME_MAX, ROOT_INODE};

/// The most names an inode may have: `EXT2_LINK_MAX`, and ext4's.
const EXT2_LINK_MAX: u16 = 32000;
const EXT4_LINK_MAX: u16 = 65000;
/// The largest file Linux allows anywhere (`MAX_LFS_FILESIZE` on 64-bit).
const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// The filesystem type a mount asks for. Linux's ext2 driver takes only
/// ext2's features; ext3 (served by the ext4 driver) needs a journal and
/// takes no ext4 feature; ext4 takes every feature this driver knows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FsType {
    Ext2,
    Ext3,
    Ext4,
}

/// How to mount.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub read_only: bool,
    /// The time of the mount, recorded in the superblock.
    pub now: Timestamp,
    pub fs_type: FsType,
}

/// Whether `superblock` may be mounted as `fs_type` (Linux's
/// `ext2_feature_set_ok`/`ext3_feature_set_ok`).
fn type_allows(superblock: &Superblock, fs_type: FsType, read_only: bool) -> bool {
    // What ext2 and ext3 know: in incompat the file type (and ext3 a
    // journal to recover), in ro_compat sparse_super and large_file.
    let (incompat, ro_compat) = match fs_type {
        FsType::Ext4 => return true,
        FsType::Ext2 => (
            INCOMPAT_FILETYPE,
            RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE,
        ),
        FsType::Ext3 => (
            INCOMPAT_FILETYPE | INCOMPAT_RECOVER,
            RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE,
        ),
    };
    if fs_type == FsType::Ext3 && superblock.compat() & COMPAT_HAS_JOURNAL == 0 {
        return false;
    }
    superblock.incompat() & !incompat == 0
        && (read_only || superblock.ro_compat() & !ro_compat == 0)
}

/// What a rename does about the destination name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameMode {
    /// Replace it if it exists (rename(2)).
    Replace,
    /// Fail with EEXIST if it exists (RENAME_NOREPLACE).
    NoReplace,
    /// Swap the two names, which must both exist (RENAME_EXCHANGE).
    Exchange,
}

/// What `statfs(2)` reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Statfs {
    pub block_size: u32,
    /// Blocks for data: all of them less the filesystem's own metadata.
    pub blocks: u64,
    pub free_blocks: u64,
    /// Free blocks less those reserved for root.
    pub available_blocks: u64,
    pub inodes: u64,
    pub free_inodes: u64,
    pub name_max: u32,
    /// The filesystem id, from the UUID as Linux folds it.
    pub id: [u32; 2],
}

/// A run of a file's data on the disk, in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    pub logical: u64,
    pub physical: u64,
    pub length: u64,
}

/// Changes to an inode's attributes ([`Filesystem::change`]); each field
/// left `None` stays.
#[derive(Clone, Copy, Debug, Default)]
pub struct Change {
    pub mode: Option<u32>,
    pub owner: Option<u32>,
    pub group: Option<u32>,
    pub flags: Option<u32>,
    pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
    pub ctime: Option<Timestamp>,
}

pub struct Filesystem<D: BlockDevice> {
    pub(crate) device: D,
    pub(crate) superblock: Superblock,
    groups: Vec<GroupDescriptor>,
    pub(crate) cache: BlockCache,
    pub(crate) block_size: u32,
    read_only: bool,
    /// The free counts or state changed since the superblock was written.
    superblock_dirty: bool,
    next_generation: u32,
    /// The seed of every metadata checksum, with metadata_csum.
    pub(crate) seed: Option<u32>,
    descriptor_size: usize,
    link_max: u16,
}

impl<D: BlockDevice> Filesystem<D> {
    /// Mounts the filesystem on `device`. EINVAL if it is not ext2/3/4,
    /// uses a feature this driver does not know or one `options.fs_type`
    /// does not take; a filesystem that only cannot be written (an unknown
    /// read-only feature) mounts read-only only.
    ///
    /// A journal (ext3, ext4) is left as it is: changes go straight to
    /// their places, as on ext2, and the journal stays empty. One that
    /// holds transactions to replay (a filesystem not cleanly unmounted by
    /// a journalling driver) is refused, EINVAL.
    pub fn mount(mut device: D, options: Options) -> Result<Self> {
        let mut raw = vec![0; SUPERBLOCK_SIZE];
        if device.size() < SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE as u64 {
            return Err(Error::Invalid);
        }
        device.read_at(SUPERBLOCK_OFFSET, &mut raw)?;
        let superblock = Superblock::parse(raw)?;
        if !type_allows(&superblock, options.fs_type, options.read_only) {
            return Err(Error::Invalid);
        }
        if !options.read_only && !superblock.writable() {
            return Err(Error::ReadOnly);
        }
        let block_size = superblock.block_size();
        if u64::from(superblock.blocks_count()) * u64::from(block_size) > device.size() {
            return Err(Error::Invalid);
        }
        let group_count = superblock.group_count();
        if u64::from(group_count) * u64::from(superblock.inodes_per_group())
            < u64::from(superblock.inodes_count())
        {
            return Err(Error::Invalid);
        }
        let descriptor_size = superblock.descriptor_size();
        let table_bytes = group_count as usize * descriptor_size;
        let mut table = Vec::new();
        table
            .try_reserve_exact(table_bytes)
            .map_err(|_| Error::NoMemory)?;
        table.resize(table_bytes, 0);
        let table_start = u64::from(superblock.first_data_block() + 1) * u64::from(block_size);
        device.read_at(table_start, &mut table)?;
        let groups = table
            .chunks_exact(descriptor_size)
            .map(|bytes| GroupDescriptor::parse(bytes, descriptor_size))
            .collect::<Result<Vec<_>>>()?;
        let blocks = superblock.blocks_count();
        let inode_table_blocks = (superblock.inodes_per_group() as usize * superblock.inode_size())
            .div_ceil(block_size as usize) as u32;
        if groups.iter().any(|group| {
            group.block_bitmap >= blocks
                || group.inode_bitmap >= blocks
                || group.inode_table.saturating_add(inode_table_blocks) > blocks
                || group.block_bitmap < superblock.first_data_block()
        }) {
            return Err(Error::Corrupt);
        }
        let seed = superblock
            .metadata_csum()
            .then(|| superblock.checksum_seed());
        let link_max = match options.fs_type {
            FsType::Ext2 => EXT2_LINK_MAX,
            FsType::Ext3 | FsType::Ext4 => EXT4_LINK_MAX,
        };
        let mut filesystem = Self {
            device,
            superblock,
            groups,
            cache: BlockCache::new(block_size as usize),
            block_size,
            read_only: options.read_only,
            superblock_dirty: false,
            next_generation: options.now.seconds as u32,
            seed,
            descriptor_size,
            link_max,
        };
        if !filesystem.read_only {
            filesystem
                .superblock
                .mark_mounted(options.now.seconds as u32);
            filesystem.write_superblock()?;
        }
        Ok(filesystem)
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Makes the filesystem read-only or writable again (a remount).
    pub fn set_read_only(&mut self, read_only: bool, now: Timestamp) -> Result<()> {
        if read_only == self.read_only {
            return Ok(());
        }
        if read_only {
            self.superblock.mark_clean(now.seconds as u32);
            self.write_superblock()?;
        } else {
            if !self.superblock.writable() {
                return Err(Error::ReadOnly);
            }
            self.superblock.mark_mounted(now.seconds as u32);
            self.write_superblock()?;
        }
        self.read_only = read_only;
        Ok(())
    }

    /// Writes what the superblock counts and marks the filesystem clean;
    /// the device is the caller's again.
    pub fn unmount(mut self, now: Timestamp) -> Result<D> {
        if !self.read_only {
            self.superblock.mark_clean(now.seconds as u32);
            self.write_superblock()?;
        }
        Ok(self.device)
    }

    /// Writes the superblock's counts (sync(2)); everything else is already
    /// on the device.
    pub fn sync(&mut self) -> Result<()> {
        if self.superblock_dirty && !self.read_only {
            self.write_superblock()?;
        }
        Ok(())
    }

    fn write_superblock(&mut self) -> Result<()> {
        self.device
            .write_at(SUPERBLOCK_OFFSET, self.superblock.encode())?;
        self.superblock_dirty = false;
        Ok(())
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// The device, for the caller's own use (its identity, say).
    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn statfs(&mut self) -> Statfs {
        let overhead = self.overhead();
        let superblock = &self.superblock;
        let free = u64::from(superblock.free_blocks());
        let uuid = superblock.uuid();
        let word =
            |at: usize| u32::from_le_bytes([uuid[at], uuid[at + 1], uuid[at + 2], uuid[at + 3]]);
        Statfs {
            block_size: self.block_size,
            blocks: u64::from(superblock.blocks_count()).saturating_sub(overhead),
            free_blocks: free,
            available_blocks: free.saturating_sub(u64::from(superblock.reserved_blocks())),
            inodes: u64::from(superblock.inodes_count()),
            free_inodes: u64::from(superblock.free_inodes()),
            name_max: NAME_MAX as u32,
            id: [word(0) ^ word(8), word(4) ^ word(12)],
        }
    }

    /// Blocks the filesystem keeps for itself: the boot block, each
    /// group's superblock and descriptor copies, bitmaps and inode table,
    /// and the journal, as Linux's ext4 counts them (or the count mke2fs
    /// recorded).
    fn overhead(&mut self) -> u64 {
        let recorded = self.superblock.overhead_blocks();
        if recorded != 0 {
            return u64::from(recorded);
        }
        let journal = match self.superblock.journal_inode() {
            Some(number) => self
                .read_inode(number)
                .map_or(0, |inode| inode.size() / u64::from(self.block_size)),
            None => 0,
        };
        let superblock = &self.superblock;
        let (descriptor_blocks, reserved_descriptors) = superblock.descriptor_blocks();
        let inode_table = (superblock.inodes_per_group() as u64 * superblock.inode_size() as u64)
            .div_ceil(u64::from(self.block_size));
        let copies = (0..self.groups.len() as u32)
            .filter(|group| superblock.has_superblock_copy(*group))
            .count() as u64;
        u64::from(superblock.first_data_block())
            + copies * (1 + u64::from(descriptor_blocks) + u64::from(reserved_descriptors))
            + self.groups.len() as u64 * (2 + inode_table)
            + journal
    }

    /// The largest file the filesystem holds (Linux's `s_maxbytes`): what
    /// extents can map with the extents feature, else what block maps can.
    pub fn max_file_size(&self) -> u64 {
        if self.superblock.extents() {
            // 32-bit file block numbers; i_blocks counts 2^32 sectors at
            // most without huge_file.
            let blocks = if self.superblock.huge_file() {
                u64::from(u32::MAX)
            } else {
                u64::from(u32::MAX) / u64::from(self.block_size / 512)
            };
            return (blocks * u64::from(self.block_size)).min(MAX_LFS_FILESIZE);
        }
        self.block_map_limit()
    }

    /// The largest file `inode`'s mapping can hold.
    fn file_size_limit(&self, inode: &Inode) -> u64 {
        if inode.uses_extents() {
            self.max_file_size()
        } else {
            self.block_map_limit()
        }
    }

    /// The largest file the block maps (and `i_blocks`) can describe.
    fn block_map_limit(&self) -> u64 {
        let pointers = u64::from(self.block_size / 4);
        let data_blocks =
            DIRECT_BLOCKS as u64 + pointers + pointers * pointers + pointers * pointers * pointers;
        // i_blocks counts sectors in 32 bits (no huge_file), metadata too.
        let sectors_per_block = u64::from(self.block_size / 512);
        let sector_limit = (u64::from(u32::MAX) / sectors_per_block)
            .saturating_sub(1 + pointers + 1 + pointers * pointers);
        data_blocks
            .min(sector_limit)
            .saturating_mul(u64::from(self.block_size))
            .min(MAX_LFS_FILESIZE)
    }

    fn check_writable(&self) -> Result<()> {
        if self.read_only {
            Err(Error::ReadOnly)
        } else {
            Ok(())
        }
    }

    pub(crate) fn valid_block(&self, block: u32) -> Result<u32> {
        if block >= self.superblock.first_data_block() && block < self.superblock.blocks_count() {
            Ok(block)
        } else {
            Err(Error::Corrupt)
        }
    }

    // ---- inodes ----

    /// Where inode `number` lives: its inode table block and the offset
    /// within it.
    fn inode_location(&self, number: u32) -> Result<(u32, usize)> {
        if number == 0 || number > self.superblock.inodes_count() {
            return Err(Error::NotFound);
        }
        let index = number - 1;
        let per_group = self.superblock.inodes_per_group();
        let group = self
            .groups
            .get((index / per_group) as usize)
            .ok_or(Error::Corrupt)?;
        let byte = (index % per_group) as usize * self.superblock.inode_size();
        let block = group.inode_table + (byte / self.block_size as usize) as u32;
        Ok((block, byte % self.block_size as usize))
    }

    pub(crate) fn read_inode(&mut self, number: u32) -> Result<Inode> {
        let (block, offset) = self.inode_location(number)?;
        let size = self.superblock.inode_size();
        let bytes = self.cache.get(&mut self.device, block)?;
        let mut raw = Vec::new();
        raw.try_reserve_exact(size).map_err(|_| Error::NoMemory)?;
        raw.extend_from_slice(&bytes[offset..offset + size]);
        Ok(Inode::from_raw(raw, number))
    }

    pub(crate) fn write_inode(&mut self, number: u32, inode: &Inode) -> Result<()> {
        let (block, offset) = self.inode_location(number)?;
        match self.seed {
            Some(seed) => {
                let mut sealed = inode.clone();
                sealed.set_checksum(seed);
                self.cache
                    .write(&mut self.device, block, offset, sealed.raw())
            }
            None => self
                .cache
                .write(&mut self.device, block, offset, inode.raw()),
        }
    }

    /// An inode in use: one with a type (a freed inode keeps its mode, so
    /// the bitmap is the authority, but a zero mode is never in use).
    fn live_inode(&mut self, number: u32) -> Result<Inode> {
        let inode = self.read_inode(number)?;
        if inode.kind().is_none() {
            return Err(Error::NotFound);
        }
        Ok(inode)
    }

    pub fn stat(&mut self, number: u32) -> Result<Stat> {
        self.live_inode(number)?.stat(number).ok_or(Error::Corrupt)
    }

    /// Applies `change` to inode `number`.
    pub fn change(&mut self, number: u32, change: &Change) -> Result<()> {
        self.check_writable()?;
        let mut inode = self.live_inode(number)?;
        if let Some(mode) = change.mode {
            inode.set_mode(inode.mode() & 0o170000 | (mode & 0o7777) as u16);
        }
        if change.owner.is_some() || change.group.is_some() {
            let owner = change.owner.unwrap_or(inode.owner());
            let group = change.group.unwrap_or(inode.group());
            inode.set_owner(owner, group);
        }
        if let Some(flags) = change.flags {
            inode.set_flags(flags);
        }
        for (which, time) in [
            (Time::Access, change.atime),
            (Time::Modify, change.mtime),
            (Time::Change, change.ctime),
        ] {
            if let Some(time) = time {
                inode.set_time(which, time);
            }
        }
        self.write_inode(number, &inode)
    }

    /// The group whose inode `number` is.
    pub(crate) fn group_of_inode(&self, number: u32) -> u32 {
        (number.saturating_sub(1)) / self.superblock.inodes_per_group()
    }

    /// The first block of group `group`.
    pub(crate) fn group_start(&self, group: u32) -> u32 {
        self.superblock.first_data_block() + group * self.superblock.blocks_per_group()
    }

    fn write_group(&mut self, group: u32) -> Result<()> {
        let (encoded, size) = self.groups[group as usize].encode(group, self.seed);
        let byte = group as usize * self.descriptor_size;
        let block =
            self.superblock.first_data_block() + 1 + (byte / self.block_size as usize) as u32;
        self.cache.write(
            &mut self.device,
            block,
            byte % self.block_size as usize,
            &encoded[..size],
        )
    }

    /// A zeroed bitmap block with the bits past `used` set, as Linux pads
    /// a group's bitmaps.
    fn padded_bitmap(&self, used: u32) -> Result<Vec<u8>> {
        let mut bitmap = self.zeroed_block()?;
        for bit in used..self.block_size * 8 {
            bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
        }
        Ok(bitmap)
    }

    /// The inode bitmap of `group`, written out first if the group's has
    /// never been (INODE_UNINIT: no inode of it was ever used).
    fn inode_bitmap(&mut self, group: u32) -> Result<u32> {
        let descriptor = self.groups.get(group as usize).ok_or(Error::Corrupt)?;
        let bitmap = descriptor.inode_bitmap;
        if self.seed.is_some() && descriptor.flags & GROUP_INODE_UNINIT != 0 {
            let contents = self.padded_bitmap(self.superblock.inodes_per_group())?;
            self.cache.replace(&mut self.device, bitmap, contents)?;
            self.groups[group as usize].flags &= !GROUP_INODE_UNINIT;
            self.seal_inode_bitmap(group)?;
            self.write_group(group)?;
        }
        Ok(bitmap)
    }

    /// The block bitmap of `group`, built first if the group's has never
    /// been written (BLOCK_UNINIT): its own superblock and descriptor
    /// copies and whatever group metadata lies in it are in use.
    fn block_bitmap(&mut self, group: u32) -> Result<u32> {
        let descriptor = self.groups.get(group as usize).ok_or(Error::Corrupt)?;
        let bitmap = descriptor.block_bitmap;
        if self.seed.is_none() || descriptor.flags & GROUP_BLOCK_UNINIT == 0 {
            return Ok(bitmap);
        }
        let start = self.group_start(group);
        let in_group = self
            .superblock
            .blocks_per_group()
            .min(self.superblock.blocks_count() - start);
        let mut contents = self.padded_bitmap(in_group)?;
        let mut mark = |block: u32| {
            if (start..start + in_group).contains(&block) {
                let bit = block - start;
                contents[(bit / 8) as usize] |= 1 << (bit % 8);
            }
        };
        if self.superblock.has_superblock_copy(group) {
            let (table, reserved) = self.superblock.descriptor_blocks();
            for block in start..start + 1 + table + reserved {
                mark(block);
            }
        }
        let table_blocks = (self.superblock.inodes_per_group() as usize
            * self.superblock.inode_size())
        .div_ceil(self.block_size as usize) as u32;
        for other in &self.groups {
            mark(other.block_bitmap);
            mark(other.inode_bitmap);
            for block in other.inode_table..other.inode_table.saturating_add(table_blocks) {
                mark(block);
            }
        }
        self.cache.replace(&mut self.device, bitmap, contents)?;
        self.groups[group as usize].flags &= !GROUP_BLOCK_UNINIT;
        self.seal_block_bitmap(group)?;
        self.write_group(group)?;
        Ok(bitmap)
    }

    /// Brings group `group`'s block bitmap checksum up to date (the
    /// caller writes the descriptor).
    fn seal_block_bitmap(&mut self, group: u32) -> Result<()> {
        if let Some(seed) = self.seed {
            let bitmap = self.groups[group as usize].block_bitmap;
            let length = (self.superblock.blocks_per_group() / 8) as usize;
            let bytes = self.cache.get(&mut self.device, bitmap)?;
            self.groups[group as usize].block_bitmap_checksum = crc32c(seed, &bytes[..length]);
        }
        Ok(())
    }

    fn seal_inode_bitmap(&mut self, group: u32) -> Result<()> {
        if let Some(seed) = self.seed {
            let bitmap = self.groups[group as usize].inode_bitmap;
            let length = (self.superblock.inodes_per_group() / 8) as usize;
            let bytes = self.cache.get(&mut self.device, bitmap)?;
            self.groups[group as usize].inode_bitmap_checksum = crc32c(seed, &bytes[..length]);
        }
        Ok(())
    }

    /// Allocates an inode for a new file of `kind`, near `parent`'s group
    /// (a directory goes to the group with the most free inodes, which
    /// spreads directories as Linux's allocator does).
    fn allocate_inode(&mut self, parent: u32, kind: Kind) -> Result<u32> {
        if self.superblock.free_inodes() == 0 {
            return Err(Error::NoSpace);
        }
        let count = self.groups.len() as u32;
        let start = if kind == Kind::Directory {
            (0..count)
                .max_by_key(|group| (self.groups[*group as usize].free_inodes, u32::MAX - group))
                .unwrap_or(0)
        } else {
            self.group_of_inode(parent).min(count - 1)
        };
        let per_group = self.superblock.inodes_per_group();
        for step in 0..count {
            let group = (start + step) % count;
            if self.groups[group as usize].free_inodes == 0 {
                continue;
            }
            let bitmap = self.inode_bitmap(group)?;
            let first = if group == 0 {
                self.superblock.first_inode() - 1
            } else {
                0
            };
            let Some(bit) =
                find_clear_bit(self.cache.get(&mut self.device, bitmap)?, first, per_group)
            else {
                continue;
            };
            self.change_bits(bitmap, bit, 1, true)?;
            let descriptor = &mut self.groups[group as usize];
            descriptor.free_inodes -= 1;
            if kind == Kind::Directory {
                descriptor.used_directories = descriptor.used_directories.saturating_add(1);
            }
            // The inodes past the last one used are never read (with
            // checksums, e2fsck and Linux skip them).
            let unused_from = per_group - u32::from(descriptor.unused_inodes);
            if self.seed.is_some() && bit >= unused_from {
                descriptor.unused_inodes = (per_group - bit - 1) as u16;
            }
            self.seal_inode_bitmap(group)?;
            self.write_group(group)?;
            let free = self.superblock.free_inodes() - 1;
            self.superblock.set_free_inodes(free);
            self.superblock_dirty = true;
            return Ok(group * per_group + bit + 1);
        }
        Err(Error::NoSpace)
    }

    fn free_inode(&mut self, number: u32, directory: bool) -> Result<()> {
        let group = self.group_of_inode(number);
        let bit = (number - 1) % self.superblock.inodes_per_group();
        let bitmap = self.inode_bitmap(group)?;
        self.change_bits(bitmap, bit, 1, false)?;
        let descriptor = &mut self.groups[group as usize];
        descriptor.free_inodes = descriptor.free_inodes.saturating_add(1);
        if directory {
            descriptor.used_directories = descriptor.used_directories.saturating_sub(1);
        }
        self.seal_inode_bitmap(group)?;
        self.write_group(group)?;
        let free = self.superblock.free_inodes() + 1;
        self.superblock.set_free_inodes(free);
        self.superblock_dirty = true;
        Ok(())
    }

    /// Sets or clears bits `start..start + count` of the bitmap in block
    /// `bitmap`; EUCLEAN if one already was.
    fn change_bits(&mut self, bitmap: u32, start: u32, count: u32, set: bool) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let first = (start / 8) as usize;
        let last = ((start + count - 1) / 8) as usize;
        let current = self
            .cache
            .get(&mut self.device, bitmap)?
            .get(first..=last)
            .ok_or(Error::Corrupt)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(current.len())
            .map_err(|_| Error::NoMemory)?;
        bytes.extend_from_slice(current);
        for bit in start..start + count {
            let (byte, mask) = ((bit / 8) as usize - first, 1 << (bit % 8));
            if (bytes[byte] & mask != 0) == set {
                return Err(Error::Corrupt);
            }
            bytes[byte] ^= mask;
        }
        self.cache.write(&mut self.device, bitmap, first, &bytes)
    }

    // ---- blocks ----

    /// Allocates a block, preferring group `goal`; the caller fills it.
    pub(crate) fn allocate_block(&mut self, goal: u32) -> Result<u32> {
        let goal = self.group_start(goal.min(self.groups.len() as u32 - 1));
        Ok(self.allocate_blocks(goal, 1)?.0)
    }

    /// Allocates up to `count` (at least one) blocks in a row, the first
    /// free at or after block `goal` (wrapping around the disk); returns
    /// the first and how many.
    pub(crate) fn allocate_blocks(&mut self, goal: u32, count: u32) -> Result<(u32, u32)> {
        if self.superblock.free_blocks() == 0 {
            return Err(Error::NoSpace);
        }
        let groups = self.groups.len() as u32;
        let per_group = self.superblock.blocks_per_group();
        let first_data = self.superblock.first_data_block();
        let total = self.superblock.blocks_count();
        let goal = goal.clamp(first_data, total - 1) - first_data;
        let (start_group, start_bit) = (goal / per_group, goal % per_group);
        // The goal's group from the goal, the others, then the goal's group
        // from its start.
        for step in 0..=groups {
            let group = (start_group + step) % groups;
            let from = if step == 0 { start_bit } else { 0 };
            if self.groups[group as usize].free_blocks == 0 {
                continue;
            }
            let in_group = per_group.min(total - first_data - group * per_group);
            let bitmap = self.block_bitmap(group)?;
            let bytes = self.cache.get(&mut self.device, bitmap)?;
            let Some(bit) = find_clear_bit(bytes, from, in_group) else {
                continue;
            };
            let free = u32::from(self.groups[group as usize].free_blocks);
            let mut length = 1;
            while length < count.min(free)
                && bit + length < in_group
                && !test_bit(bytes, bit + length)
            {
                length += 1;
            }
            self.change_bits(bitmap, bit, length, true)?;
            self.groups[group as usize].free_blocks -= length as u16;
            self.seal_block_bitmap(group)?;
            self.write_group(group)?;
            let free = self.superblock.free_blocks().saturating_sub(length);
            self.superblock.set_free_blocks(free);
            self.superblock_dirty = true;
            return Ok((first_data + group * per_group + bit, length));
        }
        Err(Error::NoSpace)
    }

    pub(crate) fn free_block(&mut self, block: u32) -> Result<()> {
        self.free_run(block, 1)
    }

    /// Frees blocks `block..block + count`.
    pub(crate) fn free_run(&mut self, mut block: u32, mut count: u32) -> Result<()> {
        let per_group = self.superblock.blocks_per_group();
        while count > 0 {
            let block_checked = self.valid_block(block)?;
            let relative = block_checked - self.superblock.first_data_block();
            let group = relative / per_group;
            let bit = relative % per_group;
            let length = count.min(per_group - bit);
            if u64::from(block) + u64::from(length) > u64::from(self.superblock.blocks_count()) {
                return Err(Error::Corrupt);
            }
            let bitmap = self.block_bitmap(group)?;
            self.change_bits(bitmap, bit, length, false)?;
            for freed in block..block + length {
                self.cache.forget(freed);
            }
            let descriptor = &mut self.groups[group as usize];
            descriptor.free_blocks = descriptor.free_blocks.saturating_add(length as u16);
            self.seal_block_bitmap(group)?;
            self.write_group(group)?;
            let free = self.superblock.free_blocks() + length;
            self.superblock.set_free_blocks(free);
            self.superblock_dirty = true;
            block += length;
            count -= length;
        }
        Ok(())
    }

    /// A zeroed block of the block size.
    pub(crate) fn zeroed_block(&self) -> Result<Vec<u8>> {
        let mut block = Vec::new();
        block
            .try_reserve_exact(self.block_size as usize)
            .map_err(|_| Error::NoMemory)?;
        block.resize(self.block_size as usize, 0);
        Ok(block)
    }

    pub(crate) fn sectors_per_block(&self) -> u64 {
        u64::from(self.block_size / 512)
    }

    /// The path through the block map to file block `index`: the inode's
    /// pointer, then the entry in each indirect block.
    fn block_path(&self, index: u64) -> Result<(usize, [usize; 3], usize)> {
        let pointers = u64::from(self.block_size / 4);
        let mut rest = index;
        if rest < DIRECT_BLOCKS as u64 {
            return Ok((rest as usize, [0; 3], 0));
        }
        rest -= DIRECT_BLOCKS as u64;
        if rest < pointers {
            return Ok((DIRECT_BLOCKS, [rest as usize, 0, 0], 1));
        }
        rest -= pointers;
        if rest < pointers * pointers {
            return Ok((
                DIRECT_BLOCKS + 1,
                [(rest / pointers) as usize, (rest % pointers) as usize, 0],
                2,
            ));
        }
        rest -= pointers * pointers;
        if rest < pointers * pointers * pointers {
            return Ok((
                DIRECT_BLOCKS + 2,
                [
                    (rest / (pointers * pointers)) as usize,
                    (rest / pointers % pointers) as usize,
                    (rest % pointers) as usize,
                ],
                3,
            ));
        }
        Err(Error::FileTooBig)
    }

    /// The block holding file block `index` of `inode`, or `None` for a
    /// hole. With `allocate`, a hole is filled (indirect blocks too) near
    /// group `goal`; the second value says the data block is new, so the
    /// caller must write all of it. Changes the inode's pointers and block
    /// count, which the caller writes back.
    pub(crate) fn map_block(
        &mut self,
        inode: &mut Inode,
        index: u64,
        allocate: Option<u32>,
    ) -> Result<Option<(u32, bool)>> {
        if inode.uses_extents() {
            return self.map_extent(inode, index, allocate.is_some());
        }
        let (root, offsets, depth) = self.block_path(index)?;
        let mut block = inode.block(root);
        let mut fresh = false;
        if block == 0 {
            let Some(goal) = allocate else {
                return Ok(None);
            };
            block = self.allocate_block(goal)?;
            if depth > 0 {
                let zeros = self.zeroed_block()?;
                self.cache.replace(&mut self.device, block, zeros)?;
            }
            fresh = true;
            inode.set_block(root, block);
            inode.set_sectors(inode.sectors() + self.sectors_per_block());
        } else {
            self.valid_block(block)?;
        }
        for (level, offset) in offsets.iter().take(depth).enumerate() {
            let at = offset * 4;
            let next = u32_at(self.cache.get(&mut self.device, block)?, at);
            if next != 0 {
                block = self.valid_block(next)?;
                fresh = false;
                continue;
            }
            let Some(goal) = allocate else {
                return Ok(None);
            };
            let new = self.allocate_block(goal)?;
            if level + 1 < depth {
                let zeros = self.zeroed_block()?;
                self.cache.replace(&mut self.device, new, zeros)?;
            }
            self.cache
                .write(&mut self.device, block, at, &new.to_le_bytes())?;
            inode.set_sectors(inode.sectors() + self.sectors_per_block());
            block = new;
            fresh = true;
        }
        Ok(Some((block, fresh)))
    }

    /// `map_block` for an extent-mapped inode.
    fn map_extent(
        &mut self,
        inode: &mut Inode,
        index: u64,
        allocate: bool,
    ) -> Result<Option<(u32, bool)>> {
        let index = u32::try_from(index).map_err(|_| Error::FileTooBig)?;
        if let Some(run) = self.find_run(inode, index)? {
            if !run.unwritten {
                return Ok(Some((run.block(index), false)));
            }
        }
        if !allocate {
            return Ok(None);
        }
        let mut map = self.load_extents(inode)?;
        let result = self.map_for_write(inode, &mut map, index, 1);
        self.store_extents(inode, &mut map)?;
        result.map(Some)
    }

    /// The block for writing file block `index` of `map`: allocated (with
    /// up to `want` blocks after it, which the hole must have room for) or
    /// made written. The second value says it is new: the caller writes
    /// all of it.
    fn map_for_write(
        &mut self,
        inode: &mut Inode,
        map: &mut ExtentMap,
        index: u32,
        want: u32,
    ) -> Result<(u32, bool)> {
        match map.find(index) {
            Some(run) if !run.unwritten => Ok((run.block(index), false)),
            Some(run) => {
                map.mark_written(index)?;
                if let Err(error) = self.reserve_tree(inode, map) {
                    map.mark_unwritten(u64::from(index), u64::from(index) + 1)?;
                    return Err(error);
                }
                Ok((run.block(index), true))
            }
            None => {
                let run = self.allocate_run(inode, map, index, want, false)?;
                Ok((run.physical, true))
            }
        }
    }

    /// Frees every data block of `inode` from file block `keep` on, and the
    /// indirect blocks that leaves empty.
    pub(crate) fn free_blocks_from(&mut self, inode: &mut Inode, keep: u64) -> Result<()> {
        if inode.uses_extents() {
            let mut map = self.load_extents(inode)?;
            let freed = map.remove(keep, u64::MAX)?;
            self.store_extents(inode, &mut map)?;
            return self.release_runs(inode, &freed);
        }
        let pointers = u64::from(self.block_size / 4);
        let mut freed = 0_u64;
        for index in (keep.min(DIRECT_BLOCKS as u64) as usize)..DIRECT_BLOCKS {
            let block = inode.block(index);
            if block != 0 {
                self.free_block(block)?;
                inode.set_block(index, 0);
                freed += 1;
            }
        }
        let mut base = DIRECT_BLOCKS as u64;
        let mut span = pointers;
        for level in 1..=3 {
            let root = DIRECT_BLOCKS + level - 1;
            let block = inode.block(root);
            if block != 0 {
                if keep <= base {
                    freed += self.free_tree(block, level)?;
                    inode.set_block(root, 0);
                } else if keep < base + span {
                    freed += self.trim_tree(block, level, keep - base)?;
                }
            }
            base += span;
            span *= pointers;
        }
        let sectors = inode
            .sectors()
            .saturating_sub(freed * self.sectors_per_block());
        inode.set_sectors(sectors);
        Ok(())
    }

    fn pointers_of(&mut self, block: u32) -> Result<Vec<u32>> {
        let bytes = self.cache.get(&mut self.device, block)?;
        Ok(bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|entry| u32::from_le_bytes(*entry))
            .collect())
    }

    /// Frees the tree under the indirect block `block` of `level` (1: its
    /// entries are data blocks) and `block` itself; returns how many.
    fn free_tree(&mut self, block: u32, level: usize) -> Result<u64> {
        self.valid_block(block)?;
        let mut freed = 0;
        if level > 0 {
            for entry in self.pointers_of(block)? {
                if entry != 0 {
                    freed += self.free_tree(entry, level - 1)?;
                }
            }
        }
        self.free_block(block)?;
        Ok(freed + 1)
    }

    /// Frees what lies past the first `keep` data blocks under the
    /// indirect block `block` of `level`, which keeps at least one.
    fn trim_tree(&mut self, block: u32, level: usize, keep: u64) -> Result<u64> {
        self.valid_block(block)?;
        let pointers = u64::from(self.block_size / 4);
        let child_span = pointers.pow(level as u32 - 1);
        let first_whole = keep.div_ceil(child_span) as usize;
        let entries = self.pointers_of(block)?;
        let mut freed = 0;
        for entry in entries.iter().skip(first_whole) {
            if *entry != 0 {
                freed += self.free_tree(*entry, level - 1)?;
            }
        }
        if first_whole < entries.len() {
            let zeros = vec![0_u8; (entries.len() - first_whole) * 4];
            self.cache
                .write(&mut self.device, block, first_whole * 4, &zeros)?;
        }
        let partial = keep % child_span;
        if partial != 0 {
            let child = entries[(keep / child_span) as usize];
            if child != 0 {
                freed += self.trim_tree(child, level - 1, partial)?;
            }
        }
        Ok(freed)
    }

    // ---- file data ----

    /// Reads inode `number`'s data at `offset` into `buffer`; returns how
    /// much (short at the end of the file). Holes read as zeros.
    pub fn read(&mut self, number: u32, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut inode = self.live_inode(number)?;
        match inode.kind() {
            Some(Kind::Directory) => return Err(Error::IsDirectory),
            Some(Kind::File) => {}
            _ => return Err(Error::Invalid),
        }
        self.read_data(&mut inode, offset, buffer)
    }

    pub(crate) fn read_data(
        &mut self,
        inode: &mut Inode,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let size = inode.size();
        if offset >= size {
            return Ok(0);
        }
        let length = (buffer.len() as u64).min(size - offset) as usize;
        let block_size = u64::from(self.block_size);
        let mut done = 0;
        while done < length {
            let position = offset + done as u64;
            let within = (position % block_size) as usize;
            let chunk = (length - done).min(block_size as usize - within);
            let target = &mut buffer[done..done + chunk];
            match self.map_block(inode, position / block_size, None)? {
                Some((block, _)) => self
                    .device
                    .read_at(u64::from(block) * block_size + within as u64, target)?,
                None => target.fill(0),
            }
            done += chunk;
        }
        Ok(length)
    }

    /// Writes `data` at `offset` of inode `number`, allocating blocks as
    /// it goes; returns how much it wrote, short if the disk filled after
    /// some of it (ENOSPC if none). The caller sets the times.
    pub fn write(&mut self, number: u32, offset: u64, data: &[u8]) -> Result<usize> {
        self.check_writable()?;
        let mut inode = self.live_inode(number)?;
        match inode.kind() {
            Some(Kind::Directory) => return Err(Error::IsDirectory),
            Some(Kind::File) => {}
            _ => return Err(Error::Invalid),
        }
        let limit = self.file_size_limit(&inode);
        if data.is_empty() {
            return Ok(0);
        }
        if offset >= limit {
            return Err(Error::FileTooBig);
        }
        let data = &data[..(data.len() as u64).min(limit - offset) as usize];
        let goal = self.group_of_inode(number);
        let result = if inode.uses_extents() {
            self.write_extents(&mut inode, offset, data)
        } else {
            self.write_data(&mut inode, goal, offset, data)
        };
        let written = match result {
            Ok(written) | Err((written, _)) if written > 0 => written,
            Ok(written) => written,
            Err((_, error)) => {
                // Blocks may have been allocated for the failed write.
                self.write_inode(number, &inode)?;
                return Err(error);
            }
        };
        let end = offset + written as u64;
        if end > inode.size() {
            inode.set_size(end);
            if end > i32::MAX as u64 {
                self.superblock.add_ro_compat(RO_COMPAT_LARGE_FILE);
                self.superblock_dirty = true;
            }
        }
        self.write_inode(number, &inode)?;
        Ok(written)
    }

    /// `write_data` for an extent-mapped inode: the map is loaded once,
    /// holes are allocated a run at a time, and the map is stored once.
    fn write_extents(
        &mut self,
        inode: &mut Inode,
        offset: u64,
        data: &[u8],
    ) -> core::result::Result<usize, (usize, Error)> {
        let mut map = self.load_extents(inode).map_err(|error| (0, error))?;
        let result = self.write_mapped(inode, &mut map, offset, data);
        // What got allocated is recorded, even after a failure.
        let stored = self.store_extents(inode, &mut map);
        match (result, stored) {
            (Ok(written), Ok(())) => Ok(written),
            (Err(failure), _) => Err(failure),
            (Ok(_), Err(error)) => Err((0, error)),
        }
    }

    fn write_mapped(
        &mut self,
        inode: &mut Inode,
        map: &mut ExtentMap,
        offset: u64,
        data: &[u8],
    ) -> core::result::Result<usize, (usize, Error)> {
        let block_size = u64::from(self.block_size);
        let end_block = (offset + data.len() as u64).div_ceil(block_size);
        // File blocks this write allocated: each is written whole.
        let mut fresh = 0..0;
        let mut done = 0;
        while done < data.len() {
            let position = offset + done as u64;
            let index = position / block_size;
            let within = (position % block_size) as usize;
            let chunk = (data.len() - done).min(block_size as usize - within);
            let source = &data[done..done + chunk];
            let index = u32::try_from(index).map_err(|_| (done, Error::FileTooBig))?;
            let hole_end = map
                .next_start(index)
                .map_or(end_block, |start| u64::from(start).min(end_block));
            let want = hole_end.saturating_sub(u64::from(index)).max(1) as u32;
            let (block, new) = self
                .map_for_write(inode, map, index, want)
                .map_err(|error| (done, error))?;
            if new {
                if let Some(run) = map.find(index) {
                    fresh = index..(run.end().min(hole_end) as u32).max(index + 1);
                }
            }
            let whole = new || fresh.contains(&index);
            let start = u64::from(block) * block_size;
            let result = if whole && chunk < block_size as usize {
                self.zeroed_block().and_then(|mut contents| {
                    contents[within..within + chunk].copy_from_slice(source);
                    self.device.write_at(start, &contents)
                })
            } else {
                self.device.write_at(start + within as u64, source)
            };
            result.map_err(|error| (done, error))?;
            done += chunk;
        }
        Ok(done)
    }

    /// Allocates the blocks of inode `number` (extent-mapped) from
    /// `offset` for `length` bytes as unwritten extents, which read as
    /// zeros (fallocate(2)); with `keep_size` the size stays, else it grows
    /// to cover them. The caller sets the times.
    pub fn allocate(
        &mut self,
        number: u32,
        offset: u64,
        length: u64,
        keep_size: bool,
    ) -> Result<()> {
        self.check_writable()?;
        let mut inode = self.live_inode(number)?;
        match inode.kind() {
            Some(Kind::Directory) => return Err(Error::IsDirectory),
            Some(Kind::File) => {}
            _ => return Err(Error::Invalid),
        }
        if !inode.uses_extents() {
            return Err(Error::Unsupported);
        }
        let end = offset.checked_add(length).ok_or(Error::FileTooBig)?;
        if end > self.max_file_size() {
            return Err(Error::FileTooBig);
        }
        let block_size = u64::from(self.block_size);
        let mut map = self.load_extents(&inode)?;
        let mut index = offset / block_size;
        let last = end.div_ceil(block_size);
        let mut result = Ok(());
        while index < last {
            let at = index as u32;
            if let Some(run) = map.find(at) {
                index = run.end();
                continue;
            }
            let hole_end = map
                .next_start(at)
                .map_or(last, |start| u64::from(start).min(last));
            match self.allocate_run(&mut inode, &mut map, at, (hole_end - index) as u32, true) {
                Ok(run) => index += u64::from(run.length),
                Err(error) => {
                    result = Err(error);
                    break;
                }
            }
        }
        self.store_extents(&mut inode, &mut map)?;
        if result.is_ok() && !keep_size && end > inode.size() {
            inode.set_size(end);
            if end > i32::MAX as u64 {
                self.superblock.add_ro_compat(RO_COMPAT_LARGE_FILE);
                self.superblock_dirty = true;
            }
        }
        self.write_inode(number, &inode)?;
        result
    }

    /// Punches a hole in inode `number` (extent-mapped) from `offset` for
    /// `length` bytes (FALLOC_FL_PUNCH_HOLE): the whole blocks in it are
    /// freed and the rest of it is zeroed; the size stays. The caller sets
    /// the times.
    pub fn punch_hole(&mut self, number: u32, offset: u64, length: u64) -> Result<()> {
        self.check_writable()?;
        let mut inode = self.live_inode(number)?;
        match inode.kind() {
            Some(Kind::Directory) => return Err(Error::IsDirectory),
            Some(Kind::File) => {}
            _ => return Err(Error::Invalid),
        }
        if !inode.uses_extents() {
            return Err(Error::Unsupported);
        }
        let size = inode.size();
        if offset >= size || length == 0 {
            return Ok(());
        }
        let block_size = u64::from(self.block_size);
        // Past the end of the file the hole reaches the end of its last
        // block (Linux's goes to the page's end).
        let end = offset
            .saturating_add(length)
            .min(size.div_ceil(block_size) * block_size);
        let first_whole = offset.div_ceil(block_size);
        let last_whole = end / block_size;
        // The partial blocks at either end are zeroed where written.
        for (from, to) in [
            (offset, end.min(first_whole * block_size)),
            ((last_whole * block_size).max(offset), end),
        ] {
            if from >= to {
                continue;
            }
            if let Some((block, _)) = self.map_block(&mut inode, from / block_size, None)? {
                let zeros = vec![0_u8; (to - from) as usize];
                self.device
                    .write_at(u64::from(block) * block_size + from % block_size, &zeros)?;
            }
            if first_whole > last_whole {
                break;
            }
        }
        if first_whole < last_whole {
            let mut map = self.load_extents(&inode)?;
            let freed = map.remove(first_whole, last_whole)?;
            self.reserve_tree(&mut inode, &mut map)?;
            self.store_extents(&mut inode, &mut map)?;
            self.release_runs(&mut inode, &freed)?;
        }
        self.write_inode(number, &inode)
    }

    /// An extent-mapped regular file, for the fallocate modes.
    fn extent_file(&mut self, number: u32) -> Result<Inode> {
        self.check_writable()?;
        let inode = self.live_inode(number)?;
        match inode.kind() {
            Some(Kind::Directory) => return Err(Error::IsDirectory),
            Some(Kind::File) => {}
            _ => return Err(Error::Invalid),
        }
        if !inode.uses_extents() {
            return Err(Error::Unsupported);
        }
        Ok(inode)
    }

    /// Zeroes `offset..offset + length` of inode `number` (extent-mapped,
    /// FALLOC_FL_ZERO_RANGE): its whole blocks become unwritten, holes in
    /// it are allocated unwritten, and the partial blocks at its ends are
    /// zeroed; with `keep_size` the size stays, else it grows to cover the
    /// range. The caller sets the times.
    pub fn zero_range(
        &mut self,
        number: u32,
        offset: u64,
        length: u64,
        keep_size: bool,
    ) -> Result<()> {
        let inode = self.extent_file(number)?;
        let end = offset.checked_add(length).ok_or(Error::FileTooBig)?;
        if end > self.max_file_size() {
            return Err(Error::FileTooBig);
        }
        let block_size = u64::from(self.block_size);
        let first_whole = offset.div_ceil(block_size);
        let last_whole = end / block_size;
        drop(inode);
        self.zero_partial_blocks(number, offset, end)?;
        let mut inode = self.live_inode(number)?;
        if first_whole < last_whole {
            let mut map = self.load_extents(&inode)?;
            map.mark_unwritten(first_whole, last_whole)?;
            self.reserve_tree(&mut inode, &mut map)?;
            self.store_extents(&mut inode, &mut map)?;
            self.write_inode(number, &inode)?;
        }
        // The holes, edges too, are allocated (unwritten) as fallocate does.
        self.allocate(number, offset, length, keep_size)
    }

    /// Zeroes the parts of `offset..end` of inode `number` that lie in
    /// blocks only partly inside it, where those blocks are written.
    fn zero_partial_blocks(&mut self, number: u32, offset: u64, end: u64) -> Result<()> {
        let mut inode = self.live_inode(number)?;
        let block_size = u64::from(self.block_size);
        let first_whole = offset.div_ceil(block_size);
        let last_whole = end / block_size;
        for (from, to) in [
            (offset, end.min(first_whole * block_size)),
            ((last_whole * block_size).max(offset), end),
        ] {
            if from < to {
                if let Some((block, _)) = self.map_block(&mut inode, from / block_size, None)? {
                    let zeros = vec![0_u8; (to - from) as usize];
                    self.device
                        .write_at(u64::from(block) * block_size + from % block_size, &zeros)?;
                }
            }
            if first_whole > last_whole {
                break;
            }
        }
        Ok(())
    }

    /// Removes blocks `offset..offset + length` (block-aligned, before the
    /// end) from inode `number`, moving the rest of the file down
    /// (FALLOC_FL_COLLAPSE_RANGE). The caller sets the times.
    pub fn collapse_range(&mut self, number: u32, offset: u64, length: u64) -> Result<()> {
        let mut inode = self.extent_file(number)?;
        let block_size = u64::from(self.block_size);
        let end = offset.checked_add(length).ok_or(Error::Invalid)?;
        if !offset.is_multiple_of(block_size) || !length.is_multiple_of(block_size) || length == 0 {
            return Err(Error::Invalid);
        }
        if end >= inode.size() {
            return Err(Error::Invalid);
        }
        let (first, last) = (offset / block_size, end / block_size);
        let mut map = self.load_extents(&inode)?;
        let freed = map.remove(first, last)?;
        map.shift(last as u32, -((last - first) as i64))?;
        self.reserve_tree(&mut inode, &mut map)?;
        self.store_extents(&mut inode, &mut map)?;
        self.release_runs(&mut inode, &freed)?;
        inode.set_size(inode.size() - length);
        self.write_inode(number, &inode)
    }

    /// Opens a hole of `length` bytes at `offset` (block-aligned, before
    /// the end) of inode `number`, moving the rest of the file up
    /// (FALLOC_FL_INSERT_RANGE). The caller sets the times.
    pub fn insert_range(&mut self, number: u32, offset: u64, length: u64) -> Result<()> {
        let mut inode = self.extent_file(number)?;
        let block_size = u64::from(self.block_size);
        if !offset.is_multiple_of(block_size) || !length.is_multiple_of(block_size) || length == 0 {
            return Err(Error::Invalid);
        }
        if offset >= inode.size() {
            return Err(Error::Invalid);
        }
        let size = inode.size().checked_add(length).ok_or(Error::FileTooBig)?;
        if size > self.max_file_size() {
            return Err(Error::FileTooBig);
        }
        let mut map = self.load_extents(&inode)?;
        map.shift((offset / block_size) as u32, (length / block_size) as i64)?;
        self.reserve_tree(&mut inode, &mut map)?;
        self.store_extents(&mut inode, &mut map)?;
        inode.set_size(size);
        if size > i32::MAX as u64 {
            self.superblock.add_ro_compat(RO_COMPAT_LARGE_FILE);
            self.superblock_dirty = true;
        }
        self.write_inode(number, &inode)
    }

    /// Where the next data (`data`) or hole of inode `number` at or after
    /// byte `offset` starts (SEEK_DATA, SEEK_HOLE); `None` at or past the
    /// end of the file (ENXIO). Unwritten blocks are holes; the end of the
    /// file is one.
    pub fn seek(&mut self, number: u32, offset: u64, data: bool) -> Result<Option<u64>> {
        let mut inode = self.live_inode(number)?;
        let size = inode.size();
        if offset >= size {
            return Ok(None);
        }
        let block_size = u64::from(self.block_size);
        let last = size.div_ceil(block_size);
        let mut index = offset / block_size;
        if inode.uses_extents() {
            let map = self.load_extents(&inode)?;
            while index < last {
                let at = index as u32;
                match map.find(at) {
                    Some(run) if !run.unwritten => {
                        if data {
                            break;
                        }
                        index = run.end();
                    }
                    Some(run) => {
                        if !data {
                            break;
                        }
                        index = run.end();
                    }
                    None => {
                        if !data {
                            break;
                        }
                        index = map.next_start(at).map_or(last, u64::from);
                    }
                }
            }
        } else {
            while index < last {
                let mapped = self.map_block(&mut inode, index, None)?.is_some();
                if mapped == data {
                    break;
                }
                index += 1;
            }
        }
        let found = (index * block_size).max(offset);
        Ok(if found < size {
            Some(found)
        } else if data {
            None
        } else {
            Some(size)
        })
    }

    /// Writes `data` at `offset`; on failure, how much got written first.
    fn write_data(
        &mut self,
        inode: &mut Inode,
        goal: u32,
        offset: u64,
        data: &[u8],
    ) -> core::result::Result<usize, (usize, Error)> {
        let block_size = u64::from(self.block_size);
        let mut done = 0;
        while done < data.len() {
            let position = offset + done as u64;
            let within = (position % block_size) as usize;
            let chunk = (data.len() - done).min(block_size as usize - within);
            let source = &data[done..done + chunk];
            let (block, fresh) = match self.map_block(inode, position / block_size, Some(goal)) {
                Ok(Some(mapped)) => mapped,
                Ok(None) => return Err((done, Error::Io)),
                Err(error) => return Err((done, error)),
            };
            let start = u64::from(block) * block_size;
            let result = if fresh && chunk < block_size as usize {
                // A new block is all written, so no stale bytes show.
                self.zeroed_block().and_then(|mut whole| {
                    whole[within..within + chunk].copy_from_slice(source);
                    self.device.write_at(start, &whole)
                })
            } else {
                self.device.write_at(start + within as u64, source)
            };
            if let Err(error) = result {
                return Err((done, error));
            }
            done += chunk;
        }
        Ok(done)
    }

    /// Sets inode `number`'s size: a smaller one frees the blocks past it
    /// and zeroes the rest of its last block, so growing again reads zeros;
    /// a larger one leaves a hole. The caller sets the times.
    pub fn truncate(&mut self, number: u32, size: u64) -> Result<()> {
        self.check_writable()?;
        let mut inode = self.live_inode(number)?;
        match inode.kind() {
            Some(Kind::Directory) => return Err(Error::IsDirectory),
            Some(Kind::File) => {}
            _ => return Err(Error::Invalid),
        }
        if size > self.file_size_limit(&inode) {
            return Err(Error::FileTooBig);
        }
        let block_size = u64::from(self.block_size);
        if size < inode.size() {
            self.free_blocks_from(&mut inode, size.div_ceil(block_size))?;
            let within = (size % block_size) as usize;
            if within != 0 {
                if let Some((block, _)) = self.map_block(&mut inode, size / block_size, None)? {
                    let zeros = vec![0_u8; block_size as usize - within];
                    self.device
                        .write_at(u64::from(block) * block_size + within as u64, &zeros)?;
                }
            }
        }
        inode.set_size(size);
        if size > i32::MAX as u64 {
            self.superblock.add_ro_compat(RO_COMPAT_LARGE_FILE);
            self.superblock_dirty = true;
        }
        self.write_inode(number, &inode)
    }

    /// Where inode `number`'s data from byte `start` for `length` bytes lies
    /// on the disk (FS_IOC_FIEMAP): runs of blocks contiguous in the file
    /// and on the disk, holes left out.
    pub fn extents(&mut self, number: u32, start: u64, length: u64) -> Result<Vec<Extent>> {
        let mut inode = self.live_inode(number)?;
        if inode.kind() != Some(Kind::File) {
            return Err(Error::Invalid);
        }
        let block_size = u64::from(self.block_size);
        let end = start.saturating_add(length).min(inode.size());
        let mut extents: Vec<Extent> = Vec::new();
        for index in start / block_size..end.div_ceil(block_size) {
            let Some((block, _)) = self.map_block(&mut inode, index, None)? else {
                continue;
            };
            let logical = index * block_size;
            let physical = u64::from(block) * block_size;
            match extents.last_mut() {
                Some(last)
                    if last.logical + last.length == logical
                        && last.physical + last.length == physical =>
                {
                    last.length += block_size;
                }
                _ => {
                    extents.try_reserve(1).map_err(|_| Error::NoMemory)?;
                    extents.push(Extent {
                        logical,
                        physical,
                        length: block_size,
                    });
                }
            }
        }
        Ok(extents)
    }

    /// A symlink's target, into `buffer`; returns its length.
    pub fn read_link(&mut self, number: u32, buffer: &mut [u8]) -> Result<usize> {
        let mut inode = self.live_inode(number)?;
        if inode.kind() != Some(Kind::Symlink) {
            return Err(Error::Invalid);
        }
        let size = inode.size() as usize;
        if self.fast_symlink(&inode) {
            let target = inode.block_bytes().get(..size).ok_or(Error::Corrupt)?;
            let length = size.min(buffer.len());
            buffer[..length].copy_from_slice(&target[..length]);
            return Ok(length);
        }
        let length = size.min(buffer.len());
        self.read_data(&mut inode, 0, &mut buffer[..length])
    }

    /// A symlink whose target is in the block pointers: it has no data
    /// block (only, perhaps, an attribute block).
    fn fast_symlink(&self, inode: &Inode) -> bool {
        let attribute_sectors = if inode.xattr_block() != 0 {
            self.sectors_per_block()
        } else {
            0
        };
        inode.sectors() == attribute_sectors && (inode.size() as usize) < FAST_SYMLINK_MAX
    }

    // ---- the namespace ----

    fn check_name(name: &[u8]) -> Result<()> {
        if name.is_empty() || name.contains(&b'/') || name.contains(&0) {
            return Err(Error::Invalid);
        }
        if name.len() > NAME_MAX {
            return Err(Error::NameTooLong);
        }
        Ok(())
    }

    fn directory_inode(&mut self, number: u32) -> Result<Inode> {
        let inode = self.live_inode(number)?;
        if inode.kind() != Some(Kind::Directory) {
            return Err(Error::NotDirectory);
        }
        Ok(inode)
    }

    /// A fresh inode of `kind` for a new file in `parent`.
    fn new_inode(
        &mut self,
        parent: u32,
        kind: Kind,
        mode: u32,
        owner: u32,
        group: u32,
        now: Timestamp,
    ) -> Result<(u32, Inode)> {
        let number = self.allocate_inode(parent, kind)?;
        let mut inode = Inode::from_raw(vec![0; self.superblock.inode_size()], number);
        if self.superblock.inode_size() > 128 {
            inode.set_extra_isize(self.superblock.want_extra_isize());
        }
        // With extents, files, directories and symlinks map their data
        // with them, from an empty tree (a fast symlink drops it again).
        if self.superblock.extents() && matches!(kind, Kind::File | Kind::Directory | Kind::Symlink)
        {
            inode.set_flags(EXTENTS_FL);
            extent::empty_root(inode.block_bytes_mut());
        }
        inode.set_mode(kind.mode_bits() | (mode & 0o7777) as u16);
        inode.set_owner(owner, group);
        inode.set_links(1);
        for which in [Time::Access, Time::Modify, Time::Change, Time::Create] {
            inode.set_time(which, now);
        }
        self.next_generation = self.next_generation.wrapping_add(1);
        inode.set_generation(self.next_generation);
        Ok((number, inode))
    }

    /// Marks directory `number` changed at `now` (an entry came or went),
    /// with `links` added to its link count.
    fn touch_directory(&mut self, number: u32, links: i32, now: Timestamp) -> Result<()> {
        let mut inode = self.read_inode(number)?;
        let count = i32::from(inode.links()) + links;
        inode.set_links(count.clamp(0, i32::from(u16::MAX)) as u16);
        // The directory's own index no longer matches once a plain entry
        // changes it (EXT2_INDEX_FL).
        inode.set_flags(inode.flags() & !INDEX_FL);
        inode.set_time(Time::Modify, now);
        inode.set_time(Time::Change, now);
        self.write_inode(number, &inode)
    }

    /// Creates `name` in directory `parent`: a regular file, directory,
    /// FIFO, socket or device file (`device` its number). Returns the new
    /// inode.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        parent: u32,
        name: &[u8],
        kind: Kind,
        mode: u32,
        owner: u32,
        group: u32,
        device: u32,
        now: Timestamp,
    ) -> Result<u32> {
        self.check_writable()?;
        Self::check_name(name)?;
        if kind == Kind::Symlink {
            return Err(Error::Invalid);
        }
        let parent_inode = self.directory_inode(parent)?;
        if parent_inode.links() == 0 {
            return Err(Error::NotFound);
        }
        if self.find_entry(parent, name)?.is_some() {
            return Err(Error::Exists);
        }
        if kind == Kind::Directory && parent_inode.links() >= self.link_max {
            return Err(Error::TooManyLinks);
        }
        let (number, mut inode) = self.new_inode(parent, kind, mode, owner, group, now)?;
        if matches!(kind, Kind::CharacterDevice | Kind::BlockDevice) {
            inode.set_device(device);
        }
        if kind == Kind::Directory {
            inode.set_links(2);
            let block = match self.allocate_block(self.group_of_inode(number)) {
                Ok(block) => block,
                Err(error) => {
                    self.free_inode(number, true)?;
                    return Err(error);
                }
            };
            let contents = self.empty_directory_block(&inode, parent)?;
            self.cache.replace(&mut self.device, block, contents)?;
            self.attach_first_block(&mut inode, block)?;
            inode.set_size(u64::from(self.block_size));
        }
        self.write_inode(number, &inode)?;
        if let Err(error) = self.add_entry(parent, name, number, kind) {
            self.discard_inode(number, &mut inode)?;
            return Err(error);
        }
        let links = i32::from(kind == Kind::Directory);
        self.touch_directory(parent, links, now)?;
        Ok(number)
    }

    /// Frees a new inode whose entry could not be made.
    fn discard_inode(&mut self, number: u32, inode: &mut Inode) -> Result<()> {
        self.free_blocks_from(inode, 0)?;
        inode.set_links(0);
        self.write_inode(number, inode)?;
        self.free_inode(number, inode.kind() == Some(Kind::Directory))
    }

    /// Creates the symlink `name` in `parent` pointing at `target`.
    pub fn symlink(
        &mut self,
        parent: u32,
        name: &[u8],
        target: &[u8],
        owner: u32,
        group: u32,
        now: Timestamp,
    ) -> Result<u32> {
        self.check_writable()?;
        Self::check_name(name)?;
        if target.is_empty() {
            return Err(Error::NotFound);
        }
        if target.len() >= self.block_size as usize {
            return Err(Error::NameTooLong);
        }
        let parent_inode = self.directory_inode(parent)?;
        if parent_inode.links() == 0 {
            return Err(Error::NotFound);
        }
        if self.find_entry(parent, name)?.is_some() {
            return Err(Error::Exists);
        }
        let (number, mut inode) =
            self.new_inode(parent, Kind::Symlink, 0o777, owner, group, now)?;
        if target.len() < FAST_SYMLINK_MAX {
            inode.set_flags(inode.flags() & !EXTENTS_FL);
            inode.block_bytes_mut().fill(0);
            inode.block_bytes_mut()[..target.len()].copy_from_slice(target);
        } else {
            let block = match self.allocate_block(self.group_of_inode(number)) {
                Ok(block) => block,
                Err(error) => {
                    self.free_inode(number, false)?;
                    return Err(error);
                }
            };
            let mut contents = self.zeroed_block()?;
            contents[..target.len()].copy_from_slice(target);
            self.device
                .write_at(u64::from(block) * u64::from(self.block_size), &contents)?;
            self.attach_first_block(&mut inode, block)?;
        }
        inode.set_size(target.len() as u64);
        self.write_inode(number, &inode)?;
        if let Err(error) = self.add_entry(parent, name, number, Kind::Symlink) {
            self.discard_inode(number, &mut inode)?;
            return Err(error);
        }
        self.touch_directory(parent, 0, now)?;
        Ok(number)
    }

    /// Gives inode `number` (not a directory) the further name `name` in
    /// `parent`.
    pub fn link(&mut self, parent: u32, name: &[u8], number: u32, now: Timestamp) -> Result<()> {
        self.check_writable()?;
        Self::check_name(name)?;
        let parent_inode = self.directory_inode(parent)?;
        if parent_inode.links() == 0 {
            return Err(Error::NotFound);
        }
        let mut inode = self.live_inode(number)?;
        let kind = inode.kind().ok_or(Error::Corrupt)?;
        if kind == Kind::Directory {
            return Err(Error::Unsupported);
        }
        if inode.links() >= self.link_max {
            return Err(Error::TooManyLinks);
        }
        if self.find_entry(parent, name)?.is_some() {
            return Err(Error::Exists);
        }
        self.add_entry(parent, name, number, kind)?;
        inode.set_links(inode.links() + 1);
        inode.set_time(Time::Change, now);
        self.write_inode(number, &inode)?;
        self.touch_directory(parent, 0, now)
    }

    /// Removes the name `name` (not a directory) from `parent`; returns its
    /// inode, which [`Filesystem::release`] frees once it has no names and
    /// is not open.
    pub fn unlink(&mut self, parent: u32, name: &[u8], now: Timestamp) -> Result<u32> {
        self.check_writable()?;
        Self::check_name(name)?;
        self.directory_inode(parent)?;
        let (number, _) = self.find_entry(parent, name)?.ok_or(Error::NotFound)?;
        let mut inode = self.live_inode(number)?;
        if inode.kind() == Some(Kind::Directory) {
            return Err(Error::IsDirectory);
        }
        self.remove_entry(parent, name)?;
        inode.set_links(inode.links().saturating_sub(1));
        inode.set_time(Time::Change, now);
        self.write_inode(number, &inode)?;
        self.touch_directory(parent, 0, now)?;
        Ok(number)
    }

    /// Removes the empty directory `name` from `parent`; returns its inode
    /// (see [`Filesystem::unlink`]).
    pub fn rmdir(&mut self, parent: u32, name: &[u8], now: Timestamp) -> Result<u32> {
        self.check_writable()?;
        if name == b"." {
            return Err(Error::Invalid);
        }
        if name == b".." {
            return Err(Error::NotEmpty);
        }
        Self::check_name(name)?;
        self.directory_inode(parent)?;
        let (number, _) = self.find_entry(parent, name)?.ok_or(Error::NotFound)?;
        let mut inode = self.live_inode(number)?;
        if inode.kind() != Some(Kind::Directory) {
            return Err(Error::NotDirectory);
        }
        if !self.directory_empty(number)? {
            return Err(Error::NotEmpty);
        }
        self.remove_entry(parent, name)?;
        inode.set_links(0);
        inode.set_time(Time::Change, now);
        self.write_inode(number, &inode)?;
        self.touch_directory(parent, -1, now)?;
        Ok(number)
    }

    /// Whether directory `ancestor` is `number` or lies above it.
    fn is_ancestor(&mut self, ancestor: u32, mut number: u32) -> Result<bool> {
        for _ in 0..self.superblock.inodes_count() {
            if number == ancestor {
                return Ok(true);
            }
            if number == ROOT_INODE {
                return Ok(false);
            }
            let (parent, _) = self.find_entry(number, b"..")?.ok_or(Error::Corrupt)?;
            number = parent;
        }
        Err(Error::Corrupt)
    }

    /// Renames `old_name` in `old_parent` to `new_name` in `new_parent`.
    /// Returns the inode that lost a name when the destination was replaced,
    /// for [`Filesystem::release`].
    #[allow(clippy::too_many_arguments)]
    pub fn rename(
        &mut self,
        old_parent: u32,
        old_name: &[u8],
        new_parent: u32,
        new_name: &[u8],
        mode: RenameMode,
        now: Timestamp,
    ) -> Result<Option<u32>> {
        self.check_writable()?;
        for name in [old_name, new_name] {
            if name == b"." || name == b".." {
                return Err(Error::Invalid);
            }
            Self::check_name(name)?;
        }
        self.directory_inode(old_parent)?;
        let new_parent_inode = self.directory_inode(new_parent)?;
        let (moved, moved_kind) = self
            .find_entry(old_parent, old_name)?
            .ok_or(Error::NotFound)?;
        let moved_kind = moved_kind.map_or_else(|| self.kind_of(moved), Ok)?;
        let target = self.find_entry(new_parent, new_name)?;
        if mode == RenameMode::Exchange {
            let (other, other_kind) = target.ok_or(Error::NotFound)?;
            let other_kind = other_kind.map_or_else(|| self.kind_of(other), Ok)?;
            return self
                .exchange(
                    (old_parent, old_name, moved, moved_kind),
                    (new_parent, new_name, other, other_kind),
                    now,
                )
                .map(|()| None);
        }
        if let Some((existing, _)) = target {
            if existing == moved {
                return Ok(None);
            }
            if mode == RenameMode::NoReplace {
                return Err(Error::Exists);
            }
        }
        let moving_directory = moved_kind == Kind::Directory;
        if moving_directory && old_parent != new_parent && self.is_ancestor(moved, new_parent)? {
            return Err(Error::Invalid);
        }
        let replaced = match target {
            Some((existing, existing_kind)) => {
                let existing_kind = existing_kind.map_or_else(|| self.kind_of(existing), Ok)?;
                match (moving_directory, existing_kind == Kind::Directory) {
                    (true, false) => return Err(Error::NotDirectory),
                    (false, true) => return Err(Error::IsDirectory),
                    (true, true) if !self.directory_empty(existing)? => {
                        return Err(Error::NotEmpty)
                    }
                    _ => {}
                }
                Some((existing, existing_kind))
            }
            None => None,
        };
        if moving_directory
            && old_parent != new_parent
            && replaced.is_none()
            && new_parent_inode.links() >= self.link_max
        {
            return Err(Error::TooManyLinks);
        }
        match replaced {
            Some(_) => self.set_entry(new_parent, new_name, moved, moved_kind)?,
            None => self.add_entry(new_parent, new_name, moved, moved_kind)?,
        }
        self.remove_entry(old_parent, old_name)?;
        let mut moved_inode = self.read_inode(moved)?;
        moved_inode.set_time(Time::Change, now);
        self.write_inode(moved, &moved_inode)?;
        let mut new_parent_links = 0;
        let mut old_parent_links = 0;
        if moving_directory && old_parent != new_parent {
            self.set_entry(moved, b"..", new_parent, Kind::Directory)?;
            old_parent_links -= 1;
            new_parent_links += 1;
        }
        if let Some((existing, existing_kind)) = replaced {
            let mut inode = self.read_inode(existing)?;
            if existing_kind == Kind::Directory {
                inode.set_links(0);
                new_parent_links -= 1;
            } else {
                inode.set_links(inode.links().saturating_sub(1));
            }
            inode.set_time(Time::Change, now);
            self.write_inode(existing, &inode)?;
        }
        if old_parent == new_parent {
            self.touch_directory(old_parent, old_parent_links + new_parent_links, now)?;
        } else {
            self.touch_directory(old_parent, old_parent_links, now)?;
            self.touch_directory(new_parent, new_parent_links, now)?;
        }
        Ok(replaced.map(|(existing, _)| existing))
    }

    /// RENAME_EXCHANGE: each name takes the other's inode.
    fn exchange(
        &mut self,
        (first_parent, first_name, first, first_kind): (u32, &[u8], u32, Kind),
        (second_parent, second_name, second, second_kind): (u32, &[u8], u32, Kind),
        now: Timestamp,
    ) -> Result<()> {
        if first == second {
            return Ok(());
        }
        if first_parent != second_parent
            && (first_kind == Kind::Directory && self.is_ancestor(first, second_parent)?
                || second_kind == Kind::Directory && self.is_ancestor(second, first_parent)?)
        {
            return Err(Error::Invalid);
        }
        self.set_entry(first_parent, first_name, second, second_kind)?;
        self.set_entry(second_parent, second_name, first, first_kind)?;
        let mut first_links = 0;
        let mut second_links = 0;
        if first_parent != second_parent {
            if first_kind == Kind::Directory {
                self.set_entry(first, b"..", second_parent, Kind::Directory)?;
                first_links -= 1;
                second_links += 1;
            }
            if second_kind == Kind::Directory {
                self.set_entry(second, b"..", first_parent, Kind::Directory)?;
                second_links -= 1;
                first_links += 1;
            }
        }
        for number in [first, second] {
            let mut inode = self.read_inode(number)?;
            inode.set_time(Time::Change, now);
            self.write_inode(number, &inode)?;
        }
        if first_parent == second_parent {
            self.touch_directory(first_parent, 0, now)
        } else {
            self.touch_directory(first_parent, first_links, now)?;
            self.touch_directory(second_parent, second_links, now)
        }
    }

    pub(crate) fn kind_of(&mut self, number: u32) -> Result<Kind> {
        self.live_inode(number)?.kind().ok_or(Error::Corrupt)
    }

    /// Frees inode `number` and its blocks if it has no names left; the
    /// caller calls this once nothing has it open. Returns whether it went.
    pub fn release(&mut self, number: u32, now: Timestamp) -> Result<bool> {
        if self.read_only {
            return Ok(false);
        }
        let mut inode = match self.live_inode(number) {
            Ok(inode) => inode,
            Err(Error::NotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        if inode.links() != 0 {
            return Ok(false);
        }
        let group = self.group_of_inode(number);
        let bit = (number - 1) % self.superblock.inodes_per_group();
        let bitmap = self.groups[group as usize].inode_bitmap;
        if !test_bit(self.cache.get(&mut self.device, bitmap)?, bit) {
            return Ok(false);
        }
        let kind = inode.kind();
        let fast_symlink = kind == Some(Kind::Symlink) && self.fast_symlink(&inode);
        let device_file = matches!(kind, Some(Kind::CharacterDevice | Kind::BlockDevice));
        if fast_symlink || device_file {
            // The pointers hold the target or device, not blocks.
            for index in 0..BLOCK_POINTERS {
                inode.set_block(index, 0);
            }
            inode.set_sectors(inode.sectors().saturating_sub(if inode.xattr_block() != 0 {
                self.sectors_per_block()
            } else {
                0
            }));
        } else {
            self.free_blocks_from(&mut inode, 0)?;
        }
        self.drop_xattr_block(&mut inode)?;
        inode.set_size(0);
        inode.set_deletion_time(now.seconds as u32);
        self.write_inode(number, &inode)?;
        self.free_inode(number, kind == Some(Kind::Directory))?;
        Ok(true)
    }

    /// Makes `block` the only block of a new inode's data (block 0), in
    /// its block map or extent tree.
    fn attach_first_block(&mut self, inode: &mut Inode, block: u32) -> Result<()> {
        if inode.uses_extents() {
            let mut map = ExtentMap::new();
            map.insert(Run {
                logical: 0,
                physical: block,
                length: 1,
                unwritten: false,
            })?;
            self.store_extents(inode, &mut map)?;
        } else {
            inode.set_block(0, block);
        }
        inode.set_sectors(inode.sectors() + self.sectors_per_block());
        Ok(())
    }

    /// The first block of new directory `directory`: `.` and `..`.
    fn empty_directory_block(&self, directory: &Inode, parent: u32) -> Result<Vec<u8>> {
        let mut block = self.zeroed_block()?;
        set_u32(&mut block, 0, directory.number());
        crate::bytes::set_u16(&mut block, 4, 12);
        block[6] = 1;
        block[7] = Kind::Directory.entry_type();
        block[8] = b'.';
        set_u32(&mut block, 12, parent);
        crate::bytes::set_u16(&mut block, 16, (self.directory_space() - 12) as u16);
        block[18] = 2;
        block[19] = Kind::Directory.entry_type();
        block[20..22].copy_from_slice(b"..");
        self.seal_new_directory_block(directory, &mut block);
        Ok(block)
    }
}

/// The first clear bit of `bitmap` in `start..end`.
fn find_clear_bit(bitmap: &[u8], start: u32, end: u32) -> Option<u32> {
    let end = end.min(bitmap.len() as u32 * 8);
    let mut bit = start;
    while bit < end {
        let byte = bitmap[(bit / 8) as usize];
        if byte == 0xff && bit.is_multiple_of(8) {
            bit += 8;
            continue;
        }
        if byte & (1 << (bit % 8)) == 0 {
            return Some(bit);
        }
        bit += 1;
    }
    None
}

fn test_bit(bitmap: &[u8], bit: u32) -> bool {
    bitmap
        .get((bit / 8) as usize)
        .is_some_and(|byte| byte & (1 << (bit % 8)) != 0)
}
