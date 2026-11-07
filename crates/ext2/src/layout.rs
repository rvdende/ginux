//! The superblock and the block group descriptors.

use alloc::vec::Vec;

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::{Error, Result, MAGIC};

/// Where the superblock starts, whatever the block size.
pub(crate) const SUPERBLOCK_OFFSET: u64 = 1024;
pub(crate) const SUPERBLOCK_SIZE: usize = 1024;
/// An ext2 group descriptor (without the 64-bit feature).
pub(crate) const DESCRIPTOR_SIZE: usize = 32;

/// `s_state`: unmounted cleanly.
const STATE_VALID: u16 = 1;

// s_feature_incompat: a driver must know each of these to mount at all.
pub(crate) const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_SUPPORTED: u32 = INCOMPAT_FILETYPE;
// s_feature_ro_compat: a driver must know each of these to write.
pub(crate) const RO_COMPAT_SPARSE_SUPER: u32 = 0x1;
pub(crate) const RO_COMPAT_LARGE_FILE: u32 = 0x2;
const RO_COMPAT_SUPPORTED: u32 = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE;

/// The superblock, kept as its raw bytes so that the fields this driver
/// does not use are written back unchanged.
pub(crate) struct Superblock {
    raw: Vec<u8>,
}

impl Superblock {
    pub(crate) fn parse(raw: Vec<u8>) -> Result<Self> {
        let superblock = Self { raw };
        if superblock.raw.len() != SUPERBLOCK_SIZE || u16_at(&superblock.raw, 56) != MAGIC {
            return Err(Error::Invalid);
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
        // Directory entries are read with their file type byte.
        if superblock.incompat() & !INCOMPAT_SUPPORTED != 0
            || superblock.incompat() & INCOMPAT_FILETYPE == 0
        {
            return Err(Error::Invalid);
        }
        Ok(superblock)
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
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

    pub(crate) fn incompat(&self) -> u32 {
        self.u32(96)
    }

    pub(crate) fn ro_compat(&self) -> u32 {
        self.u32(100)
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
    raw: [u8; DESCRIPTOR_SIZE],
}

impl GroupDescriptor {
    pub(crate) fn parse(bytes: &[u8]) -> Self {
        let mut raw = [0; DESCRIPTOR_SIZE];
        raw.copy_from_slice(&bytes[..DESCRIPTOR_SIZE]);
        Self {
            block_bitmap: u32_at(&raw, 0),
            inode_bitmap: u32_at(&raw, 4),
            inode_table: u32_at(&raw, 8),
            free_blocks: u16_at(&raw, 12),
            free_inodes: u16_at(&raw, 14),
            used_directories: u16_at(&raw, 16),
            raw,
        }
    }

    pub(crate) fn encode(&self) -> [u8; DESCRIPTOR_SIZE] {
        let mut raw = self.raw;
        set_u32(&mut raw, 0, self.block_bitmap);
        set_u32(&mut raw, 4, self.inode_bitmap);
        set_u32(&mut raw, 8, self.inode_table);
        set_u16(&mut raw, 12, self.free_blocks);
        set_u16(&mut raw, 14, self.free_inodes);
        set_u16(&mut raw, 16, self.used_directories);
        raw
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
