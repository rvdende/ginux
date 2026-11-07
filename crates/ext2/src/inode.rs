//! Inodes, kept as their raw on-disk bytes with typed accessors, so the
//! fields this driver does not interpret are written back unchanged.

use alloc::vec::Vec;

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::Timestamp;

/// The twelve direct block pointers and the three indirect ones.
pub(crate) const DIRECT_BLOCKS: usize = 12;
pub(crate) const BLOCK_POINTERS: usize = 15;
/// A symlink target shorter than this lives in the block pointers.
pub(crate) const FAST_SYMLINK_MAX: usize = 60;
/// The base inode, before the extra fields.
const GOOD_OLD_INODE_SIZE: usize = 128;
/// Inode flags: the data is mapped by an extent tree (ext4), and a
/// directory has a hash index.
pub(crate) const EXTENTS_FL: u32 = 0x8_0000;
pub(crate) const INDEX_FL: u32 = 0x1000;
/// Inode flags quota files get while quotas are on, and project
/// inheritance (new inodes take the directory's project id).
pub(crate) const IMMUTABLE_FL: u32 = 0x10;
pub(crate) const NOATIME_FL: u32 = 0x80;
pub(crate) const PROJINHERIT_FL: u32 = 0x2000_0000;
/// Where a large inode keeps its project id.
const PROJECT_ID: usize = 0x9c;
/// Where the inode's checksum halves live (metadata_csum).
const CHECKSUM_LO: usize = 0x7c;
const CHECKSUM_HI: usize = 0x82;

const MODE_TYPE: u16 = 0o170000;

/// What an inode is: the file type bits of its mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl Kind {
    pub(crate) const fn mode_bits(self) -> u16 {
        match self {
            Self::Fifo => 0o010000,
            Self::CharacterDevice => 0o020000,
            Self::Directory => 0o040000,
            Self::BlockDevice => 0o060000,
            Self::File => 0o100000,
            Self::Symlink => 0o120000,
            Self::Socket => 0o140000,
        }
    }

    pub(crate) fn from_mode(mode: u16) -> Option<Self> {
        Some(match mode & MODE_TYPE {
            0o010000 => Self::Fifo,
            0o020000 => Self::CharacterDevice,
            0o040000 => Self::Directory,
            0o060000 => Self::BlockDevice,
            0o100000 => Self::File,
            0o120000 => Self::Symlink,
            0o140000 => Self::Socket,
            _ => return None,
        })
    }

    /// The directory entry's file type byte (the `filetype` feature).
    pub(crate) const fn entry_type(self) -> u8 {
        match self {
            Self::File => 1,
            Self::Directory => 2,
            Self::CharacterDevice => 3,
            Self::BlockDevice => 4,
            Self::Fifo => 5,
            Self::Socket => 6,
            Self::Symlink => 7,
        }
    }
}

/// What `stat(2)` shows of an inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stat {
    pub inode: u32,
    pub kind: Kind,
    /// The permission bits, with set-user-ID, set-group-ID and sticky.
    pub mode: u32,
    pub owner: u32,
    pub group: u32,
    pub links: u32,
    pub size: u64,
    /// Space used, in 512-byte sectors.
    pub blocks: u64,
    /// A device file's device number, as Linux encodes `dev_t`.
    pub device: u32,
    /// The inode flags (`FS_*_FL`, the same bits as `FS_IOC_GETFLAGS`).
    pub flags: u32,
    pub generation: u32,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    /// The creation time, where the inode has room for one.
    pub crtime: Option<Timestamp>,
}

#[derive(Clone)]
pub(crate) struct Inode {
    raw: Vec<u8>,
    /// Which inode this is (its checksums depend on it).
    number: u32,
}

/// Where a time's seconds live, and its extra field (epoch bits and
/// nanoseconds) in a large inode.
#[derive(Clone, Copy)]
pub(crate) enum Time {
    Access,
    Change,
    Modify,
    Create,
}

impl Time {
    const fn offsets(self) -> (usize, usize) {
        match self {
            Self::Access => (8, 140),
            Self::Change => (12, 132),
            Self::Modify => (16, 136),
            Self::Create => (144, 148),
        }
    }
}

impl Inode {
    pub(crate) fn from_raw(raw: Vec<u8>, number: u32) -> Self {
        Self { raw, number }
    }

    pub(crate) fn number(&self) -> u32 {
        self.number
    }

    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub(crate) fn mode(&self) -> u16 {
        u16_at(&self.raw, 0)
    }

    pub(crate) fn set_mode(&mut self, mode: u16) {
        set_u16(&mut self.raw, 0, mode);
    }

    pub(crate) fn kind(&self) -> Option<Kind> {
        Kind::from_mode(self.mode())
    }

    pub(crate) fn owner(&self) -> u32 {
        u32::from(u16_at(&self.raw, 2)) | u32::from(u16_at(&self.raw, 120)) << 16
    }

    pub(crate) fn group(&self) -> u32 {
        u32::from(u16_at(&self.raw, 24)) | u32::from(u16_at(&self.raw, 122)) << 16
    }

    pub(crate) fn set_owner(&mut self, owner: u32, group: u32) {
        set_u16(&mut self.raw, 2, owner as u16);
        set_u16(&mut self.raw, 120, (owner >> 16) as u16);
        set_u16(&mut self.raw, 24, group as u16);
        set_u16(&mut self.raw, 122, (group >> 16) as u16);
    }

    /// The size; `i_size_high` counts only for regular files.
    pub(crate) fn size(&self) -> u64 {
        let high = if self.kind() == Some(Kind::File) {
            u64::from(u32_at(&self.raw, 108)) << 32
        } else {
            0
        };
        u64::from(u32_at(&self.raw, 4)) | high
    }

    pub(crate) fn set_size(&mut self, size: u64) {
        set_u32(&mut self.raw, 4, size as u32);
        set_u32(&mut self.raw, 108, (size >> 32) as u32);
    }

    pub(crate) fn links(&self) -> u16 {
        u16_at(&self.raw, 26)
    }

    pub(crate) fn set_links(&mut self, links: u16) {
        set_u16(&mut self.raw, 26, links);
    }

    /// Space used in 512-byte sectors (`i_blocks`).
    pub(crate) fn sectors(&self) -> u64 {
        u64::from(u32_at(&self.raw, 28)) | u64::from(u16_at(&self.raw, 116)) << 32
    }

    pub(crate) fn set_sectors(&mut self, sectors: u64) {
        set_u32(&mut self.raw, 28, sectors as u32);
        set_u16(&mut self.raw, 116, (sectors >> 32) as u16);
    }

    pub(crate) fn flags(&self) -> u32 {
        u32_at(&self.raw, 32)
    }

    pub(crate) fn set_flags(&mut self, flags: u32) {
        set_u32(&mut self.raw, 32, flags);
    }

    pub(crate) fn block(&self, index: usize) -> u32 {
        u32_at(&self.raw, 40 + index * 4)
    }

    pub(crate) fn set_block(&mut self, index: usize, block: u32) {
        set_u32(&mut self.raw, 40 + index * 4, block);
    }

    /// The block pointers' bytes, where a fast symlink keeps its target.
    pub(crate) fn block_bytes(&self) -> &[u8] {
        &self.raw[40..40 + BLOCK_POINTERS * 4]
    }

    pub(crate) fn block_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.raw[40..40 + BLOCK_POINTERS * 4]
    }

    /// The project id (0 where the inode has no room for one).
    pub(crate) fn project(&self) -> u32 {
        if self.has_extra(PROJECT_ID + 4) {
            u32_at(&self.raw, PROJECT_ID)
        } else {
            0
        }
    }

    pub(crate) fn set_project(&mut self, project: u32) {
        if self.has_extra(PROJECT_ID + 4) {
            set_u32(&mut self.raw, PROJECT_ID, project);
        }
    }

    pub(crate) fn generation(&self) -> u32 {
        u32_at(&self.raw, 100)
    }

    pub(crate) fn set_generation(&mut self, generation: u32) {
        set_u32(&mut self.raw, 100, generation);
    }

    /// The extended attribute block (`i_file_acl`), 0 if none.
    pub(crate) fn xattr_block(&self) -> u32 {
        u32_at(&self.raw, 104)
    }

    pub(crate) fn set_xattr_block(&mut self, block: u32) {
        set_u32(&mut self.raw, 104, block);
    }

    pub(crate) fn set_deletion_time(&mut self, seconds: u32) {
        set_u32(&mut self.raw, 20, seconds);
    }

    /// The extra bytes a large inode uses past the base 128.
    pub(crate) fn extra_isize(&self) -> usize {
        if self.raw.len() <= GOOD_OLD_INODE_SIZE {
            0
        } else {
            usize::from(u16_at(&self.raw, 128))
        }
    }

    pub(crate) fn set_extra_isize(&mut self, size: u16) {
        if self.raw.len() > GOOD_OLD_INODE_SIZE {
            set_u16(&mut self.raw, 128, size);
        }
    }

    /// Whether the extra fields reach past byte `end` of the inode.
    fn has_extra(&self, end: usize) -> bool {
        GOOD_OLD_INODE_SIZE + self.extra_isize() >= end && self.raw.len() >= end
    }

    pub(crate) fn time(&self, which: Time) -> Option<Timestamp> {
        let (base, extra) = which.offsets();
        if matches!(which, Time::Create) && !self.has_extra(extra + 4) {
            return None;
        }
        let low = i64::from(u32_at(&self.raw, base) as i32);
        if !self.has_extra(extra + 4) {
            return Some(Timestamp::new(low, 0));
        }
        let extra = u32_at(&self.raw, extra);
        Some(Timestamp::new(
            low + (i64::from(extra & 3) << 32),
            (extra >> 2).min(999_999_999),
        ))
    }

    pub(crate) fn set_time(&mut self, which: Time, time: Timestamp) {
        let (base, extra) = which.offsets();
        let has_extra = self.has_extra(extra + 4);
        if matches!(which, Time::Create) && !has_extra {
            return;
        }
        if !has_extra {
            // Only 32 signed bits of seconds fit.
            let seconds = time.seconds.clamp(i64::from(i32::MIN), i64::from(i32::MAX));
            set_u32(&mut self.raw, base, seconds as i32 as u32);
            return;
        }
        let seconds = time
            .seconds
            .clamp(i64::from(i32::MIN), i64::from(i32::MIN) + (4 << 32) - 1);
        let low = seconds as i32;
        let epoch = ((seconds - i64::from(low)) >> 32) as u32 & 3;
        set_u32(&mut self.raw, base, low as u32);
        set_u32(
            &mut self.raw,
            extra,
            epoch | time.nanoseconds.min(999_999_999) << 2,
        );
    }

    /// A device file's number, kept in the first block pointers (the old
    /// 16-bit encoding in the first, else the new one in the second).
    pub(crate) fn device(&self) -> u32 {
        let old = self.block(0);
        if old != 0 {
            let major = (old >> 8) & 0xff;
            let minor = old & 0xff;
            return encode_device(major, minor);
        }
        self.block(1)
    }

    pub(crate) fn set_device(&mut self, device: u32) {
        let (major, minor) = decode_device(device);
        if major < 256 && minor < 256 {
            self.set_block(0, major << 8 | minor);
            self.set_block(1, 0);
        } else {
            self.set_block(0, 0);
            self.set_block(1, device);
        }
        self.set_block(2, 0);
    }

    /// The space after the extra fields of a large inode, where extended
    /// attributes may live: (start, end) within the inode.
    pub(crate) fn xattr_area(&self) -> Option<(usize, usize)> {
        let start = GOOD_OLD_INODE_SIZE + self.extra_isize();
        (self.raw.len() > GOOD_OLD_INODE_SIZE && start + 4 <= self.raw.len())
            .then_some((start, self.raw.len()))
    }

    pub(crate) fn raw_mut(&mut self) -> &mut [u8] {
        &mut self.raw
    }

    pub(crate) fn uses_extents(&self) -> bool {
        self.flags() & EXTENTS_FL != 0
    }

    /// The seed of the checksums of what the inode owns (itself, its
    /// extent and directory blocks): the filesystem's `seed` over its
    /// number and generation.
    pub(crate) fn checksum_seed(&self, seed: u32) -> u32 {
        let crc = crate::checksum::crc32c(seed, &self.number.to_le_bytes());
        crate::checksum::crc32c(crc, &self.generation().to_le_bytes())
    }

    /// Whether the inode has room for the upper half of its checksum.
    fn has_checksum_hi(&self) -> bool {
        self.raw.len() > GOOD_OLD_INODE_SIZE && self.extra_isize() >= 4
    }

    /// Stores the inode's own checksum (metadata_csum).
    pub(crate) fn set_checksum(&mut self, seed: u32) {
        let seed = self.checksum_seed(seed);
        set_u16(&mut self.raw, CHECKSUM_LO, 0);
        if self.has_checksum_hi() {
            set_u16(&mut self.raw, CHECKSUM_HI, 0);
        }
        let crc = crate::checksum::crc32c(seed, &self.raw);
        set_u16(&mut self.raw, CHECKSUM_LO, crc as u16);
        if self.has_checksum_hi() {
            set_u16(&mut self.raw, CHECKSUM_HI, (crc >> 16) as u16);
        }
    }

    /// Whether the inode's own checksum (metadata_csum) holds: over all its
    /// bytes with the checksum's halves read as zeros, only the lower half
    /// compared where the inode has no room for the upper.
    pub(crate) fn checksum_valid(&self, seed: u32) -> bool {
        use crate::checksum::{crc32c, crc32c_skipping};
        let seed = self.checksum_seed(seed);
        let (head, tail) = self.raw.split_at(CHECKSUM_HI);
        let crc = crc32c_skipping(seed, head, CHECKSUM_LO..CHECKSUM_LO + 2);
        let mut stored = u32::from(u16_at(&self.raw, CHECKSUM_LO));
        if self.has_checksum_hi() {
            stored |= u32::from(u16_at(&self.raw, CHECKSUM_HI)) << 16;
            crc32c_skipping(crc, tail, 0..2) == stored
        } else {
            crc32c(crc, tail) & 0xffff == stored
        }
    }

    pub(crate) fn stat(&self, inode: u32) -> Option<Stat> {
        let kind = self.kind()?;
        Some(Stat {
            inode,
            kind,
            mode: u32::from(self.mode() & 0o7777),
            owner: self.owner(),
            group: self.group(),
            links: u32::from(self.links()),
            size: self.size(),
            blocks: self.sectors(),
            device: match kind {
                Kind::CharacterDevice | Kind::BlockDevice => self.device(),
                _ => 0,
            },
            flags: self.flags(),
            generation: self.generation(),
            atime: self.time(Time::Access).unwrap_or_default(),
            mtime: self.time(Time::Modify).unwrap_or_default(),
            ctime: self.time(Time::Change).unwrap_or_default(),
            crtime: self.time(Time::Create),
        })
    }
}

/// Linux's `dev_t` from a major and minor number (`new_encode_dev`).
pub(crate) const fn encode_device(major: u32, minor: u32) -> u32 {
    (minor & 0xff) | (major & 0xfff) << 8 | (minor & !0xff) << 12
}

pub(crate) const fn decode_device(device: u32) -> (u32, u32) {
    (
        (device >> 8) & 0xfff,
        (device & 0xff) | (device >> 12) & 0xfff00,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn times_keep_nanoseconds_and_epochs_in_large_inodes() {
        let mut inode = Inode::from_raw(vec![0; 256], 12);
        inode.set_extra_isize(32);
        for time in [
            Timestamp::new(0, 0),
            Timestamp::new(-1, 5),
            Timestamp::new(1_700_000_000, 123_456_789),
            Timestamp::new(i64::from(i32::MAX) + 10, 1),
        ] {
            inode.set_time(Time::Modify, time);
            assert_eq!(inode.time(Time::Modify), Some(time));
        }
        let mut small = Inode::from_raw(vec![0; 128], 12);
        small.set_time(Time::Modify, Timestamp::new(7, 9));
        assert_eq!(small.time(Time::Modify), Some(Timestamp::new(7, 0)));
        assert_eq!(small.time(Time::Create), None);
    }

    #[test]
    fn devices_round_trip_both_encodings() {
        let mut inode = Inode::from_raw(vec![0; 128], 12);
        for (major, minor) in [(1, 3), (7, 0), (259, 70000), (8, 300)] {
            inode.set_device(encode_device(major, minor));
            assert_eq!(decode_device(inode.device()), (major, minor));
        }
    }
}
