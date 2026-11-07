#![forbid(unsafe_code)]
//! A read-write ext2 filesystem on a block device, as `mke2fs -t ext2`
//! makes it and Linux mounts it.
//!
//! The on-disk format is the specification (the ext2 and ext4 layout
//! documents): a superblock at byte 1024, block groups each with a block
//! bitmap, an inode bitmap and an inode table, inodes that map their data
//! through twelve direct blocks and single, double and triple indirect
//! blocks, linear directories of variable-length entries, fast and slow
//! symlinks, and extended attributes in an attribute block. Inodes larger
//! than 128 bytes keep nanosecond times and a creation time in their extra
//! fields, as Linux's ext4 driver does for ext2. Features beyond those
//! (journals that need recovery, extents, 64-bit groups, checksums) are
//! refused at mount time.
//!
//! The filesystem works on inode numbers; mapping paths to inodes, open
//! files and permissions are the caller's. An inode whose last name goes
//! keeps its data until the caller says nothing has it open any more
//! ([`Filesystem::release`]), as Linux keeps an unlinked open file.
//!
//! Metadata blocks (bitmaps, inode tables, indirect blocks, directories)
//! are cached and written through, a range at a time; file data goes to the
//! device directly. Nothing here allocates without being able to report
//! it, and nothing panics on a corrupt image: every on-disk value is
//! checked before it is used.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod cache;
mod directory;
mod filesystem;
mod inode;
mod layout;
mod xattr;

pub use directory::Entry;
pub use filesystem::{Change, Filesystem, Options, RenameMode, Statfs};
pub use inode::{Kind, Stat};
pub use xattr::XattrMode;

/// The inode of every ext2 filesystem's root directory.
pub const ROOT_INODE: u32 = 2;
/// The longest name a directory entry holds.
pub const NAME_MAX: usize = 255;
/// The superblock's magic number, also `statfs(2)`'s `f_type`.
pub const MAGIC: u16 = 0xef53;

/// Why an operation failed. [`Error::errno`] gives Linux's error number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// ENOENT
    NotFound,
    /// EEXIST
    Exists,
    /// ENOTDIR
    NotDirectory,
    /// EISDIR
    IsDirectory,
    /// ENOTEMPTY
    NotEmpty,
    /// ENOSPC: no free block or inode, or no room for an attribute.
    NoSpace,
    /// EIO: the device failed.
    Io,
    /// EUCLEAN: the image contradicts itself.
    Corrupt,
    /// ENAMETOOLONG
    NameTooLong,
    /// EROFS
    ReadOnly,
    /// EINVAL: not an ext2 image this driver can mount, or a bad argument.
    Invalid,
    /// EMLINK
    TooManyLinks,
    /// EFBIG
    FileTooBig,
    /// ENODATA: no such attribute.
    NoData,
    /// ERANGE: an attribute too large.
    Range,
    /// EOPNOTSUPP
    Unsupported,
    /// ENOMEM
    NoMemory,
    /// E2BIG: an attribute value larger than a block can hold.
    TooBig,
}

impl Error {
    /// Linux's error number for the failure.
    pub const fn errno(self) -> u64 {
        match self {
            Self::NotFound => 2,
            Self::Io => 5,
            Self::TooBig => 7,
            Self::NoMemory => 12,
            Self::Exists => 17,
            Self::NotDirectory => 20,
            Self::IsDirectory => 21,
            Self::Invalid => 22,
            Self::FileTooBig => 27,
            Self::NoSpace => 28,
            Self::ReadOnly => 30,
            Self::TooManyLinks => 31,
            Self::Range => 34,
            Self::NameTooLong => 36,
            Self::NotEmpty => 39,
            Self::NoData => 61,
            Self::Unsupported => 95,
            Self::Corrupt => 117,
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// The disk an ext2 filesystem lives on, addressed in bytes.
pub trait BlockDevice {
    /// Fills `buffer` from the device at byte `offset`.
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()>;
    /// Writes `data` to the device at byte `offset`.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    /// The device's size in bytes.
    fn size(&self) -> u64;
}

/// A point in time: seconds since the epoch and nanoseconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl Timestamp {
    pub const fn new(seconds: i64, nanoseconds: u32) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }
}

/// Little-endian field access within on-disk structures.
pub(crate) mod bytes {
    pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes([bytes[at], bytes[at + 1]])
    }

    pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    pub(crate) fn set_u16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn set_u32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}
