//! The superblock and the block group descriptors.

use alloc::vec::Vec;

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::checksum::crc32c;
use crate::{Error, Result, MAGIC};

/// Where the superblock starts, whatever the block size.
pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
/// A group descriptor without the 64-bit feature, and the most with it.
pub(crate) const DESCRIPTOR_SIZE: usize = 32;
pub(crate) const DESCRIPTOR_SIZE_MAX: usize = 64;
/// Where the superblock keeps its own checksum.
const SUPERBLOCK_CHECKSUM: usize = 0x3fc;

/// `s_state`: unmounted cleanly; errors found.
const STATE_VALID: u16 = 1;
const STATE_ERROR: u16 = 2;
/// `s_creator_os` of Linux, whose inodes alone carry checksums.
const CREATOR_LINUX: u32 = 0;

/// Where the superblock records the errors found (`s_error_count`, then
/// the first error's time, inode, block, function and line, then the
/// last's) and the high bytes and codes of each (`s_first_error_time_hi`
/// on).
const ERROR_COUNT: usize = 0x194;
const FIRST_ERROR: usize = 0x198;
const LAST_ERROR: usize = 0x1cc;
const ERROR_HIGHS: usize = 0x278;

// s_feature_compat: nothing in it stops a driver. A journal is kept but
// not written (see `Filesystem::mount`).
pub(crate) const COMPAT_HAS_JOURNAL: u32 = 0x4;
// s_feature_incompat: a driver must know each of these to mount at all.
pub(crate) const INCOMPAT_FILETYPE: u32 = 0x2;
/// The journal holds transactions not yet written to their places.
pub(crate) const INCOMPAT_RECOVER: u32 = 0x4;
pub(crate) const INCOMPAT_EXTENTS: u32 = 0x40;
pub(crate) const INCOMPAT_64BIT: u32 = 0x80;
pub(crate) const INCOMPAT_FLEX_BG: u32 = 0x200;
pub(crate) const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_SUPPORTED: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG | INCOMPAT_CSUM_SEED;
// s_feature_ro_compat: a driver must know each of these to write.
pub(crate) const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
pub(crate) const RO_COMPAT_LARGE_FILE: u32 = 0x2;
pub(crate) const RO_COMPAT_HUGE_FILE: u32 = 0x8;
pub(crate) const RO_COMPAT_DIR_NLINK: u32 = 0x20;
pub(crate) const RO_COMPAT_EXTRA_ISIZE: u32 = 0x40;
pub(crate) const RO_COMPAT_METADATA_CSUM: u32 = 0x400;
/// Quotas in hidden system inodes, and project ids in inodes.
pub(crate) const RO_COMPAT_QUOTA: u32 = 0x100;
pub(crate) const RO_COMPAT_PROJECT: u32 = 0x2000;
const RO_COMPAT_SUPPORTED: u32 = RO_COMPAT_QUOTA
    | RO_COMPAT_PROJECT
    | RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;

/// Group descriptor flags (`bg_flags`).
pub(crate) const GROUP_INODE_UNINIT: u16 = 0x1;
pub(crate) const GROUP_BLOCK_UNINIT: u16 = 0x2;

/// The superblock, kept as its raw bytes so that the fields this driver
/// does not use are written back unchanged.
pub(crate) struct Superblock {
    raw: Vec<u8>,
}

impl Superblock {
    /// The superblock in `raw`, checked to be one this driver mounts; with
    /// `checked`, its checksum is checked first (EBADMSG), as Linux's ext4
    /// checks it right after the magic number and checksum type.
    pub(crate) fn parse(raw: Vec<u8>, checked: bool) -> Result<Self> {
        let superblock = Self { raw };
        if superblock.raw.len() != SUPERBLOCK_SIZE || u16_at(&superblock.raw, 56) != MAGIC {
            return Err(Error::Invalid);
        }
        // metadata_csum is crc32c (s_checksum_type 1).
        if superblock.metadata_csum() && superblock.raw[0x175] != 1 {
            return Err(Error::Invalid);
        }
        if checked && !superblock.checksum_valid() {
            return Err(Error::BadChecksum);
        }
        let log = superblock.u32(24);
        if log > 6
            || superblock.blocks_per_group() == 0
            || superblock.inodes_per_group() == 0
            || superblock.inodes_count() == 0
            || superblock.blocks_count() <= superblock.first_data_block()
        {
            return Err(Error::Invalid);
        }
        let inode_size = superblock.inode_size();
        if inode_size < 128
            || !inode_size.is_power_of_two()
            || inode_size as u32 > superblock.block_size()
            || superblock.blocks_per_group() > superblock.block_size() * 8
            || superblock.inodes_per_group() > superblock.block_size() * 8
        {
            return Err(Error::Invalid);
        }
        // Directory entries are read with their file type byte; a journal
        // that needs replaying is not replayed here.
        if superblock.incompat() & !INCOMPAT_SUPPORTED != 0
            || superblock.incompat() & INCOMPAT_FILETYPE == 0
            || superblock.incompat() & INCOMPAT_RECOVER != 0
        {
            return Err(Error::Invalid);
        }
        // More than 2^32 blocks does not fit this driver's block numbers.
        if superblock.is_64bit() {
            let size = superblock.descriptor_size();
            if superblock.u32(0x150) != 0
                || !(DESCRIPTOR_SIZE..=DESCRIPTOR_SIZE_MAX).contains(&size)
                || !size.is_power_of_two()
            {
                return Err(Error::Invalid);
            }
        }
        Ok(superblock)
    }

    /// Whether the superblock's own checksum holds (without metadata_csum
    /// there is none to hold).
    pub(crate) fn checksum_valid(&self) -> bool {
        !self.metadata_csum() || u32_at(&self.raw, SUPERBLOCK_CHECKSUM) == self.checksum()
    }

    /// The superblock's bytes, with its checksum brought up to date.
    pub(crate) fn encode(&mut self) -> &[u8] {
        if self.metadata_csum() {
            let checksum = self.checksum();
            set_u32(&mut self.raw, SUPERBLOCK_CHECKSUM, checksum);
        }
        &self.raw
    }

    fn checksum(&self) -> u32 {
        crc32c(!0, &self.raw[..SUPERBLOCK_CHECKSUM])
    }

    fn u32(&self, at: usize) -> u32 {
        u32_at(&self.raw, at)
    }

    pub(crate) fn inodes_count(&self) -> u32 {
        self.u32(0)
    }

    pub(crate) fn blocks_count(&self) -> u32 {
        self.u32(4)
    }

    pub(crate) fn reserved_blocks(&self) -> u32 {
        self.u32(8)
    }

    pub(crate) fn free_blocks(&self) -> u32 {
        self.u32(12)
    }

    pub(crate) fn set_free_blocks(&mut self, count: u32) {
        set_u32(&mut self.raw, 12, count);
        if self.is_64bit() {
            set_u32(&mut self.raw, 0x158, 0);
        }
    }

    pub(crate) fn free_inodes(&self) -> u32 {
        self.u32(16)
    }

    pub(crate) fn set_free_inodes(&mut self, count: u32) {
        set_u32(&mut self.raw, 16, count);
    }

    pub(crate) fn first_data_block(&self) -> u32 {
        self.u32(20)
    }

    pub(crate) fn block_size(&self) -> u32 {
        1024 << self.u32(24)
    }

    pub(crate) fn blocks_per_group(&self) -> u32 {
        self.u32(32)
    }

    pub(crate) fn inodes_per_group(&self) -> u32 {
        self.u32(40)
    }

    pub(crate) fn group_count(&self) -> u32 {
        (self.blocks_count() - self.first_data_block()).div_ceil(self.blocks_per_group())
    }

    fn revision(&self) -> u32 {
        self.u32(76)
    }

    /// The first inode files may use; those before it are reserved.
    pub(crate) fn first_inode(&self) -> u32 {
        if self.revision() == 0 {
            11
        } else {
            self.u32(84)
        }
    }

    pub(crate) fn inode_size(&self) -> usize {
        if self.revision() == 0 {
            128
        } else {
            usize::from(u16_at(&self.raw, 88))
        }
    }

    pub(crate) fn compat(&self) -> u32 {
        self.u32(92)
    }

    pub(crate) fn incompat(&self) -> u32 {
        self.u32(96)
    }

    pub(crate) fn ro_compat(&self) -> u32 {
        self.u32(100)
    }

    pub(crate) fn has_journal(&self) -> bool {
        self.compat() & COMPAT_HAS_JOURNAL != 0
    }

    pub(crate) fn extents(&self) -> bool {
        self.incompat() & INCOMPAT_EXTENTS != 0
    }

    pub(crate) fn is_64bit(&self) -> bool {
        self.incompat() & INCOMPAT_64BIT != 0
    }

    pub(crate) fn metadata_csum(&self) -> bool {
        self.ro_compat() & RO_COMPAT_METADATA_CSUM != 0
    }

    pub(crate) fn huge_file(&self) -> bool {
        self.ro_compat() & RO_COMPAT_HUGE_FILE != 0
    }

    /// The bytes a group descriptor takes.
    pub(crate) fn descriptor_size(&self) -> usize {
        if self.is_64bit() {
            usize::from(u16_at(&self.raw, 0xfe))
        } else {
            DESCRIPTOR_SIZE
        }
    }

    /// The seed of every metadata checksum: stored, or the UUID's.
    pub(crate) fn checksum_seed(&self) -> u32 {
        if self.incompat() & INCOMPAT_CSUM_SEED != 0 {
            self.u32(0x270)
        } else {
            crc32c(!0, &self.raw[104..120])
        }
    }

    /// The blocks mke2fs counted as the filesystem's own (s_overhead_clusters),
    /// 0 if it did not.
    pub(crate) fn overhead_blocks(&self) -> u32 {
        self.u32(0x248)
    }

    /// Quotas in hidden system inodes (the quota feature).
    pub(crate) fn quota(&self) -> bool {
        self.ro_compat() & RO_COMPAT_QUOTA != 0
    }

    /// Project ids in the inodes (the project feature).
    pub(crate) fn project(&self) -> bool {
        self.ro_compat() & RO_COMPAT_PROJECT != 0
    }

    /// The user, group and project quota inodes (0 for none).
    pub(crate) fn quota_inodes(&self) -> [u32; 3] {
        if !self.quota() {
            return [0; 3];
        }
        [self.u32(0x240), self.u32(0x244), self.u32(0x26c)]
    }

    /// The inode of an internal journal.
    pub(crate) fn journal_inode(&self) -> Option<u32> {
        let number = self.u32(0xe0);
        (self.has_journal() && number != 0).then_some(number)
    }

    /// Whether every feature that writing depends on is known.
    pub(crate) fn writable(&self) -> bool {
        self.ro_compat() & !RO_COMPAT_SUPPORTED == 0
    }

    pub(crate) fn uuid(&self) -> [u8; 16] {
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&self.raw[104..120]);
        uuid
    }

    /// The extra inode bytes new inodes reserve (`s_want_extra_isize`).
    pub(crate) fn want_extra_isize(&self) -> u16 {
        let wanted = u16_at(&self.raw, 350);
        if wanted == 0 && self.inode_size() > 128 {
            32
        } else {
            wanted
        }
    }

    /// Marks the filesystem mounted (not clean) at `now`, counting the
    /// mount, as Linux does on a read-write mount.
    pub(crate) fn mark_mounted(&mut self, now: u32) {
        let state = u16_at(&self.raw, 58);
        set_u16(&mut self.raw, 58, state & !STATE_VALID);
        set_u32(&mut self.raw, 44, now);
        set_u32(&mut self.raw, 48, now);
        let count = u16_at(&self.raw, 52);
        set_u16(&mut self.raw, 52, count.wrapping_add(1));
    }

    /// What the filesystem does on finding an error unless the mount says
    /// otherwise (`s_errors`: 1 continue, 2 remount read-only, 3 panic).
    pub(crate) fn error_behaviour(&self) -> u16 {
        u16_at(&self.raw, 60)
    }

    /// Whether inodes carry checksums: Linux's ext4 checks them only on a
    /// filesystem Linux made.
    pub(crate) fn linux_made(&self) -> bool {
        self.u32(72) == CREATOR_LINUX
    }

    /// Records an error found at `now` on inode `inode` and block `block`
    /// (0 for none), with ext4's code for its errno (`EXT4_ERR_*`): the
    /// state says the filesystem has errors, which e2fsck then checks.
    pub(crate) fn note_error(&mut self, now: u64, inode: u32, block: u64, code: u8) {
        let state = u16_at(&self.raw, 58);
        set_u16(&mut self.raw, 58, state | STATE_ERROR);
        let count = self.u32(ERROR_COUNT);
        set_u32(&mut self.raw, ERROR_COUNT, count.saturating_add(1));
        let first_time = self.u32(FIRST_ERROR) != 0 || self.raw[ERROR_HIGHS] != 0;
        let time = now as u32;
        let time_high = (now >> 32) as u8;
        if !first_time {
            set_u32(&mut self.raw, FIRST_ERROR, time);
            set_u32(&mut self.raw, FIRST_ERROR + 4, inode);
            self.raw[FIRST_ERROR + 8..FIRST_ERROR + 16].copy_from_slice(&block.to_le_bytes());
            self.raw[ERROR_HIGHS] = time_high;
            self.raw[ERROR_HIGHS + 2] = code;
        }
        set_u32(&mut self.raw, LAST_ERROR, time);
        set_u32(&mut self.raw, LAST_ERROR + 4, inode);
        self.raw[LAST_ERROR + 12..LAST_ERROR + 20].copy_from_slice(&block.to_le_bytes());
        self.raw[ERROR_HIGHS + 1] = time_high;
        self.raw[ERROR_HIGHS + 3] = code;
    }

    /// Marks the filesystem cleanly unmounted at `now`.
    pub(crate) fn mark_clean(&mut self, now: u32) {
        let state = u16_at(&self.raw, 58);
        set_u16(&mut self.raw, 58, state | STATE_VALID);
        set_u32(&mut self.raw, 48, now);
    }

    /// Notes a feature a write has started to depend on, such as a file
    /// larger than 2 GiB (`RO_COMPAT_LARGE_FILE`).
    pub(crate) fn add_ro_compat(&mut self, feature: u32) {
        let features = self.ro_compat();
        set_u32(&mut self.raw, 100, features | feature);
    }

    /// The groups that hold a copy of the superblock and descriptors: all
    /// of them, or with `sparse_super` 0, 1 and the powers of 3, 5 and 7.
    pub(crate) fn has_superblock_copy(&self, group: u32) -> bool {
        if self.ro_compat() & RO_COMPAT_SPARSE_SUPER == 0 || group <= 1 {
            return true;
        }
        [3, 5, 7].into_iter().any(|base| {
            let mut power = base;
            while power < group {
                power *= base;
            }
            power == group
        })
    }

    /// Blocks of the descriptor table, and the blocks reserved after it for
    /// growth (`s_reserved_gdt_blocks`).
    pub(crate) fn descriptor_blocks(&self) -> (u32, u32) {
        let table = (self.group_count() as usize * self.descriptor_size())
            .div_ceil(self.block_size() as usize) as u32;
        (table, u32::from(u16_at(&self.raw, 206)))
    }
}

/// One block group's descriptor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GroupDescriptor {
    pub(crate) block_bitmap: u32,
    pub(crate) inode_bitmap: u32,
    pub(crate) inode_table: u32,
    pub(crate) free_blocks: u16,
    pub(crate) free_inodes: u16,
    pub(crate) used_directories: u16,
    pub(crate) flags: u16,
    /// Inodes at the end of the group's table never used (with checksums).
    pub(crate) unused_inodes: u16,
    pub(crate) block_bitmap_checksum: u32,
    pub(crate) inode_bitmap_checksum: u32,
    size: usize,
    raw: [u8; DESCRIPTOR_SIZE_MAX],
}

impl GroupDescriptor {
    /// The descriptor in `bytes` (`size` bytes of it); EUCLEAN for one
    /// whose numbers do not fit 32 bits.
    pub(crate) fn parse(bytes: &[u8], size: usize) -> Result<Self> {
        let mut raw = [0; DESCRIPTOR_SIZE_MAX];
        raw[..size].copy_from_slice(&bytes[..size]);
        let wide = size >= DESCRIPTOR_SIZE_MAX;
        let high_u32 = |at: usize| if wide { u32_at(&raw, at) } else { 0 };
        let high_u16 = |at: usize| if wide { u16_at(&raw, at) } else { 0 };
        if high_u32(0x20) | high_u32(0x24) | high_u32(0x28) != 0
            || high_u16(0x2c) | high_u16(0x2e) | high_u16(0x30) | high_u16(0x32) != 0
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            block_bitmap: u32_at(&raw, 0),
            inode_bitmap: u32_at(&raw, 4),
            inode_table: u32_at(&raw, 8),
            free_blocks: u16_at(&raw, 12),
            free_inodes: u16_at(&raw, 14),
            used_directories: u16_at(&raw, 16),
            flags: u16_at(&raw, 0x12),
            unused_inodes: u16_at(&raw, 0x1c),
            block_bitmap_checksum: u32::from(u16_at(&raw, 0x18)) | u32::from(high_u16(0x38)) << 16,
            inode_bitmap_checksum: u32::from(u16_at(&raw, 0x1a)) | u32::from(high_u16(0x3a)) << 16,
            size,
            raw,
        })
    }

    /// Whether the descriptor's checksum (metadata_csum, `seed`) holds for
    /// group `group`.
    pub(crate) fn checksum_valid(&self, group: u32, seed: u32) -> bool {
        let (encoded, _) = self.encode(group, Some(seed));
        u16_at(&encoded, 0x1e) == u16_at(&self.raw, 0x1e)
    }

    /// The descriptor's bytes; with `seed`, its checksum (metadata_csum) for
    /// group `group` too.
    pub(crate) fn encode(
        &self,
        group: u32,
        seed: Option<u32>,
    ) -> ([u8; DESCRIPTOR_SIZE_MAX], usize) {
        let mut raw = self.raw;
        set_u32(&mut raw, 0, self.block_bitmap);
        set_u32(&mut raw, 4, self.inode_bitmap);
        set_u32(&mut raw, 8, self.inode_table);
        set_u16(&mut raw, 12, self.free_blocks);
        set_u16(&mut raw, 14, self.free_inodes);
        set_u16(&mut raw, 16, self.used_directories);
        if let Some(seed) = seed {
            set_u16(&mut raw, 0x12, self.flags);
            set_u16(&mut raw, 0x1c, self.unused_inodes);
            set_u16(&mut raw, 0x18, self.block_bitmap_checksum as u16);
            set_u16(&mut raw, 0x1a, self.inode_bitmap_checksum as u16);
            if self.size >= DESCRIPTOR_SIZE_MAX {
                set_u16(&mut raw, 0x38, (self.block_bitmap_checksum >> 16) as u16);
                set_u16(&mut raw, 0x3a, (self.inode_bitmap_checksum >> 16) as u16);
            }
            let crc = crc32c(seed, &group.to_le_bytes());
            let crc = crate::checksum::crc32c_skipping(crc, &raw[..self.size], 0x1e..0x20);
            set_u16(&mut raw, 0x1e, crc as u16);
        }
        (raw, self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn sparse_superblock_groups() {
        let mut raw = vec![0; SUPERBLOCK_SIZE];
        set_u32(&mut raw, 100, RO_COMPAT_SPARSE_SUPER);
        let superblock = Superblock { raw };
        let copies: Vec<u32> = (0..60)
            .filter(|group| superblock.has_superblock_copy(*group))
            .collect();
        assert_eq!(copies, [0, 1, 3, 5, 7, 9, 25, 27, 49]);
    }
}
