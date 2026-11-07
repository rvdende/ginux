//! Directories: blocks of variable-length entries (inode, record length,
//! name length, file type, name), searched linearly. With metadata_csum
//! each block ends in a 12-byte checksum entry (an empty entry of type
//! 0xde holding the block's checksum), which entries never take; in a
//! hash-indexed directory the index blocks (the root, block 0, and the
//! nodes, each one empty entry spanning the block) instead end their
//! index in an 8-byte tail holding its checksum.

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::checksum::crc32c;
use crate::inode::{Inode, Kind, INDEX_FL};
use crate::{BlockDevice, Error, Filesystem, Result, NAME_MAX, ROOT_INODE};

/// How a directory entry's reference is broken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Damage {
    /// The number is not one an entry may name: the directory is at fault.
    Number,
    /// The inode named has no links or no file type: it is at fault.
    Inode,
    /// The inode named fails its checksum: it is at fault, and the failure
    /// is already recorded ([`Filesystem::take_failures`]).
    Checksum,
}

/// The fixed part of an entry.
const HEADER: usize = 8;
/// The checksum entry ending a directory block, and its file type.
const TAIL: usize = 12;
const TAIL_TYPE: u8 = 0xde;

fn has_tail(bytes: &[u8]) -> bool {
    let Some(at) = bytes.len().checked_sub(TAIL) else {
        return false;
    };
    u32_at(bytes, at) == 0
        && usize::from(u16_at(bytes, at + 4)) == TAIL
        && bytes[at + 6] == 0
        && bytes[at + 7] == TAIL_TYPE
}

/// Whether leaf block `bytes` of a directory whose checksums start from
/// `seed` ends in a checksum entry that holds.
fn leaf_checksum_valid(bytes: &[u8], seed: u32) -> bool {
    let at = bytes.len() - TAIL;
    has_tail(bytes) && crc32c(seed, &bytes[..at]) == u32_at(bytes, at + 8)
}

/// Whether `bytes` is an index node of a hash-indexed directory: one empty
/// entry spanning the block.
fn is_index_node(bytes: &[u8]) -> bool {
    u32_at(bytes, 0) == 0 && usize::from(u16_at(bytes, 4)) == bytes.len()
}

/// Whether index block `bytes` (the root or a node) of a hash-indexed
/// directory whose checksums start from `seed` has a checksum that holds:
/// over the block up to its last index entry, then the tail's reserved
/// word and a zero checksum. The index's count and limit follow the root's
/// `.`, `..` and 8-byte root information, or a node's empty entry.
fn index_checksum_valid(bytes: &[u8], seed: u32) -> bool {
    let block_size = bytes.len();
    let first = usize::from(u16_at(bytes, 4));
    let count_at = if first == block_size {
        HEADER
    } else if first == 12
        && usize::from(u16_at(bytes, 16)) == block_size - 12
        && u32_at(bytes, 24) == 0
        && bytes[29] == 8
    {
        32
    } else {
        return false;
    };
    let limit = usize::from(u16_at(bytes, count_at));
    let count = usize::from(u16_at(bytes, count_at + 2));
    let tail = count_at + limit * 8;
    if count > limit || tail + 8 > block_size {
        return false;
    }
    let crc = crc32c(seed, &bytes[..count_at + count * 8]);
    let crc = crc32c(crc, &bytes[tail..tail + 4]);
    crc32c(crc, &[0; 4]) == u32_at(bytes, tail + 4)
}

/// Where a block's entries end: before its checksum entry, if it has one.
fn entries_end(bytes: &[u8], checksums: bool) -> usize {
    if checksums && has_tail(bytes) {
        bytes.len() - TAIL
    } else {
        bytes.len()
    }
}

/// One name in a directory.
#[derive(Clone)]
pub struct Entry {
    pub inode: u32,
    /// The type the entry records, if it records one.
    pub kind: Option<Kind>,
    name_length: u8,
    name: [u8; NAME_MAX],
}

impl Entry {
    pub fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_length)]
    }
}

/// An entry's header as found at some offset of a directory block.
#[derive(Clone, Copy)]
struct Record {
    inode: u32,
    length: usize,
    name_length: usize,
    file_type: u8,
}

/// The space an entry with an `name_length`-byte name needs.
const fn entry_size(name_length: usize) -> usize {
    (HEADER + name_length + 3) & !3
}

fn kind_of_entry(file_type: u8) -> Option<Kind> {
    Some(match file_type {
        1 => Kind::File,
        2 => Kind::Directory,
        3 => Kind::CharacterDevice,
        4 => Kind::BlockDevice,
        5 => Kind::Fifo,
        6 => Kind::Socket,
        7 => Kind::Symlink,
        _ => return None,
    })
}

/// The entry at `at` of directory block `block`, checked to lie within it.
fn record(block: &[u8], at: usize) -> Result<Record> {
    if at + HEADER > block.len() {
        return Err(Error::Corrupt);
    }
    let record = Record {
        inode: u32_at(block, at),
        length: usize::from(u16_at(block, at + 4)),
        name_length: usize::from(block[at + 6]),
        file_type: block[at + 7],
    };
    if record.length < HEADER
        || !record.length.is_multiple_of(4)
        || at + record.length > block.len()
        || HEADER + record.name_length > record.length
    {
        return Err(Error::Corrupt);
    }
    Ok(record)
}

/// An entry's bytes: header and name.
fn encode(inode: u32, length: usize, name: &[u8], kind: Kind) -> ([u8; HEADER + NAME_MAX], usize) {
    let mut bytes = [0; HEADER + NAME_MAX];
    set_u32(&mut bytes, 0, inode);
    set_u16(&mut bytes, 4, length as u16);
    bytes[6] = name.len() as u8;
    bytes[7] = kind.entry_type();
    bytes[HEADER..HEADER + name.len()].copy_from_slice(name);
    (bytes, HEADER + name.len())
}

/// Where an entry was found: its block, offset and the entry before it in
/// the block.
struct Found {
    block: u32,
    at: usize,
    previous: Option<(usize, usize)>,
    record: Record,
}

impl<D: BlockDevice> Filesystem<D> {
    /// The bytes of a directory block its entries may use.
    pub(crate) fn directory_space(&self) -> usize {
        self.block_size as usize - if self.seed.is_some() { TAIL } else { 0 }
    }

    /// Ends a new block of `directory` with its checksum entry.
    pub(crate) fn seal_new_directory_block(&self, directory: &Inode, block: &mut [u8]) {
        let Some(seed) = self.seed else {
            return;
        };
        let at = block.len() - TAIL;
        block[at..].fill(0);
        set_u16(block, at + 4, TAIL as u16);
        block[at + 7] = TAIL_TYPE;
        let checksum = crc32c(directory.checksum_seed(seed), &block[..at]);
        set_u32(block, at + 8, checksum);
    }

    /// Brings the checksum of block `block` of `directory` up to date after
    /// a change (a block without a checksum entry, an htree node, has its
    /// checksum elsewhere and is left).
    fn seal_directory_block(&mut self, directory: u32, block: u32) -> Result<()> {
        let Some(seed) = self.seed else {
            return Ok(());
        };
        let seed = self.read_inode(directory)?.checksum_seed(seed);
        let bytes = self.cache.get(&mut self.device, block)?;
        if !has_tail(bytes) {
            return Ok(());
        }
        let at = bytes.len() - TAIL;
        let checksum = crc32c(seed, &bytes[..at]);
        self.cache
            .write(&mut self.device, block, at + 8, &checksum.to_le_bytes())
    }

    /// Block `block`, file block `index` of `directory`, checked against
    /// its checksum as Linux's ext4 checks a directory block it reads: a
    /// leaf by its checksum entry, the root and nodes of a hash index by
    /// the index's. EBADMSG, reported against the directory, if it fails.
    fn directory_block(&mut self, directory: &Inode, index: u64, block: u32) -> Result<&[u8]> {
        if let Some(seed) = self.seed.filter(|_| self.verify) {
            let seed = directory.checksum_seed(seed);
            let indexed = directory.flags() & INDEX_FL != 0;
            let valid = |bytes: &[u8]| {
                if indexed && (index == 0 || is_index_node(bytes)) {
                    index_checksum_valid(bytes, seed)
                } else {
                    leaf_checksum_valid(bytes, seed)
                }
            };
            if self
                .cache
                .get_verified(&mut self.device, block, valid)?
                .is_none()
            {
                let error = Error::BadChecksum;
                return Err(self.report(directory.number(), u64::from(block), error));
            }
        }
        self.cache.get(&mut self.device, block)
    }

    /// Makes hash-indexed `directory` a plain linear directory before it
    /// changes, with metadata_csum: the index blocks' (and the root's)
    /// last entries give up the space of a checksum entry, which every
    /// block then ends in. (Without checksums, clearing the index flag is
    /// all it takes: the index blocks read as empty entries.)
    fn drop_index(&mut self, directory: u32) -> Result<()> {
        if self.seed.is_none() {
            return Ok(());
        }
        let (mut inode, blocks) = self.directory_blocks(directory)?;
        if inode.flags() & INDEX_FL == 0 {
            return Ok(());
        }
        for (index, block) in blocks {
            let bytes = self.directory_block(&inode, index, block)?;
            if has_tail(bytes) {
                continue;
            }
            let mut at = 0;
            let mut last = None;
            while at < bytes.len() {
                let record = record(bytes, at)?;
                last = Some((at, record));
                at += record.length;
            }
            let (at, last) = last.ok_or(Error::Corrupt)?;
            let used = if last.inode == 0 {
                HEADER
            } else {
                entry_size(last.name_length)
            };
            if last.length < used + TAIL {
                return Err(Error::NoSpace);
            }
            let mut contents = alloc::vec::Vec::new();
            contents
                .try_reserve_exact(bytes.len())
                .map_err(|_| Error::NoMemory)?;
            contents.extend_from_slice(bytes);
            set_u16(&mut contents, at + 4, (last.length - TAIL) as u16);
            self.seal_new_directory_block(&inode, &mut contents);
            self.cache.replace(&mut self.device, block, contents)?;
        }
        inode.set_flags(inode.flags() & !INDEX_FL);
        self.write_inode(directory, &inode)
    }

    /// Directory `directory`'s inode and its data blocks, in order (holes
    /// skipped), each with its place in the directory.
    fn directory_blocks(&mut self, directory: u32) -> Result<(Inode, alloc::vec::Vec<(u64, u32)>)> {
        let mut inode = self.read_inode(directory)?;
        if inode.kind() != Some(Kind::Directory) {
            return Err(Error::NotDirectory);
        }
        let count = inode.size() / u64::from(self.block_size);
        let mut blocks = alloc::vec::Vec::new();
        for index in 0..count {
            if let Some((block, _)) = self.map_block(&mut inode, index, None)? {
                blocks.try_reserve(1).map_err(|_| Error::NoMemory)?;
                blocks.push((index, block));
            }
        }
        Ok((inode, blocks))
    }

    /// Finds `name` in `directory`.
    fn find(&mut self, directory: u32, name: &[u8]) -> Result<Option<Found>> {
        let (inode, blocks) = self.directory_blocks(directory)?;
        for (index, block) in blocks {
            let bytes = self.directory_block(&inode, index, block)?;
            let mut at = 0;
            let mut previous = None;
            while at < bytes.len() {
                let record = record(bytes, at)?;
                if record.inode != 0
                    && &bytes[at + HEADER..at + HEADER + record.name_length] == name
                {
                    return Ok(Some(Found {
                        block,
                        at,
                        previous,
                        record,
                    }));
                }
                previous = Some((at, record.length));
                at += record.length;
            }
        }
        Ok(None)
    }

    /// The inode `name` names in `directory`, with the type its entry
    /// records.
    pub(crate) fn find_entry(
        &mut self,
        directory: u32,
        name: &[u8],
    ) -> Result<Option<(u32, Option<Kind>)>> {
        Ok(self
            .find(directory, name)?
            .map(|found| (found.record.inode, kind_of_entry(found.record.file_type))))
    }

    /// The inode `name` names in `directory` (ENOENT if none).
    pub fn lookup(&mut self, directory: u32, name: &[u8]) -> Result<u32> {
        if name.len() > NAME_MAX {
            return Err(Error::NameTooLong);
        }
        self.find_entry(directory, name)?
            .map(|(inode, _)| inode)
            .ok_or(Error::NotFound)
    }

    /// What is wrong with a directory entry naming inode `number`, as
    /// Linux's ext4 lookup finds it (EFSCORRUPTED): `None` for a sound
    /// reference. An entry may name the root or an inode from the first
    /// unreserved one up; the inode must have links and a file type, and
    /// (unless it was never used: no links and no mode) a checksum that
    /// holds.
    pub fn damaged_reference(&mut self, number: u32) -> Option<Damage> {
        if number != ROOT_INODE
            && (number < self.superblock.first_inode() || number > self.superblock.inodes_count())
        {
            return Some(Damage::Number);
        }
        match self.load_inode(number) {
            Ok(inode) if inode.links() == 0 && inode.mode() == 0 => return Some(Damage::Inode),
            Err(Error::Corrupt) => return Some(Damage::Inode),
            Err(_) => return None,
            Ok(_) => {}
        }
        match self.read_inode(number) {
            Ok(inode) if inode.links() == 0 || inode.kind().is_none() => Some(Damage::Inode),
            Ok(_) => None,
            Err(Error::BadChecksum) => Some(Damage::Checksum),
            Err(Error::Corrupt) => Some(Damage::Inode),
            Err(_) => None,
        }
    }

    /// The first entry of `directory` at or after byte `offset`, and the
    /// offset after it; `None` at the end. `.` and `..` are entries too.
    /// A block of a linear directory that fails its checksum is passed
    /// over (and reported), as Linux's ext4 readdir passes over it; in a
    /// hash-indexed directory, which Linux reads through its index, it
    /// fails the read (EBADMSG).
    pub fn read_dir(&mut self, directory: u32, offset: u64) -> Result<Option<(Entry, u64)>> {
        let block_size = u64::from(self.block_size);
        let mut inode = self.read_inode(directory)?;
        if inode.kind() != Some(Kind::Directory) {
            return Err(Error::NotDirectory);
        }
        let indexed = inode.flags() & INDEX_FL != 0;
        let count = inode.size() / block_size;
        let mut index = offset / block_size;
        let mut from = (offset % block_size) as usize;
        while index < count {
            if let Some((block, _)) = self.map_block(&mut inode, index, None)? {
                let bytes = match self.directory_block(&inode, index, block) {
                    Ok(bytes) => bytes,
                    Err(Error::BadChecksum) if !indexed => {
                        index += 1;
                        from = 0;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let mut at = 0;
                while at < bytes.len() {
                    let record = record(bytes, at)?;
                    if at >= from && record.inode != 0 {
                        let mut entry = Entry {
                            inode: record.inode,
                            kind: kind_of_entry(record.file_type),
                            name_length: record.name_length as u8,
                            name: [0; NAME_MAX],
                        };
                        entry.name[..record.name_length]
                            .copy_from_slice(&bytes[at + HEADER..at + HEADER + record.name_length]);
                        let next = index * block_size + (at + record.length) as u64;
                        return Ok(Some((entry, next)));
                    }
                    at += record.length;
                }
            }
            index += 1;
            from = 0;
        }
        Ok(None)
    }

    /// Whether `directory` holds nothing but `.` and `..`.
    pub(crate) fn directory_empty(&mut self, directory: u32) -> Result<bool> {
        let mut offset = 0;
        while let Some((entry, next)) = self.read_dir(directory, offset)? {
            if entry.name() != b"." && entry.name() != b".." {
                return Ok(false);
            }
            offset = next;
        }
        Ok(true)
    }

    /// Adds the entry `name` for `inode` to `directory`, in the first gap
    /// that fits or in a new block.
    pub(crate) fn add_entry(
        &mut self,
        directory: u32,
        name: &[u8],
        inode: u32,
        kind: Kind,
    ) -> Result<()> {
        self.drop_index(directory)?;
        let needed = entry_size(name.len());
        let checksums = self.seed.is_some();
        let (inode_of_directory, blocks) = self.directory_blocks(directory)?;
        for (index, block) in blocks {
            let bytes = self.directory_block(&inode_of_directory, index, block)?;
            let end = entries_end(bytes, checksums);
            let mut at = 0;
            let mut gap = None;
            while at < end {
                let record = record(bytes, at)?;
                let used = if record.inode == 0 {
                    0
                } else {
                    entry_size(record.name_length)
                };
                if record.length - used >= needed {
                    gap = Some((at, record, used));
                    break;
                }
                at += record.length;
            }
            let Some((at, record, used)) = gap else {
                continue;
            };
            if used == 0 {
                let (bytes, length) = encode(inode, record.length, name, kind);
                self.cache
                    .write(&mut self.device, block, at, &bytes[..length])?;
            } else {
                let (bytes, length) = encode(inode, record.length - used, name, kind);
                self.cache
                    .write(&mut self.device, block, at + used, &bytes[..length])?;
                self.cache.write(
                    &mut self.device,
                    block,
                    at + 4,
                    &(used as u16).to_le_bytes(),
                )?;
            }
            return self.seal_directory_block(directory, block);
        }
        // No room: the directory grows by a block holding just this entry.
        let mut directory_inode = self.read_inode(directory)?;
        let block_size = u64::from(self.block_size);
        let index = directory_inode.size() / block_size;
        let goal = (directory - 1) / self.superblock.inodes_per_group();
        let (block, _) = self
            .map_block(&mut directory_inode, index, Some(goal))?
            .ok_or(Error::Io)?;
        let mut contents = self.zeroed_block()?;
        let (bytes, length) = encode(inode, self.directory_space(), name, kind);
        contents[..length].copy_from_slice(&bytes[..length]);
        self.seal_new_directory_block(&directory_inode, &mut contents);
        self.cache.replace(&mut self.device, block, contents)?;
        directory_inode.set_size((index + 1) * block_size);
        self.write_inode(directory, &directory_inode)
    }

    /// Removes the entry `name` from `directory`: the entry before it in
    /// its block takes its space, or, first in the block, it is cleared.
    pub(crate) fn remove_entry(&mut self, directory: u32, name: &[u8]) -> Result<()> {
        self.drop_index(directory)?;
        let found = self.find(directory, name)?.ok_or(Error::NotFound)?;
        match found.previous {
            Some((previous, length)) => {
                let merged = (length + found.record.length) as u16;
                self.cache.write(
                    &mut self.device,
                    found.block,
                    previous + 4,
                    &merged.to_le_bytes(),
                )?;
            }
            None => self.cache.write(
                &mut self.device,
                found.block,
                found.at,
                &0_u32.to_le_bytes(),
            )?,
        }
        self.seal_directory_block(directory, found.block)
    }

    /// Points the existing entry `name` of `directory` at `inode`.
    pub(crate) fn set_entry(
        &mut self,
        directory: u32,
        name: &[u8],
        inode: u32,
        kind: Kind,
    ) -> Result<()> {
        self.drop_index(directory)?;
        let found = self.find(directory, name)?.ok_or(Error::NotFound)?;
        self.cache.write(
            &mut self.device,
            found.block,
            found.at,
            &inode.to_le_bytes(),
        )?;
        self.cache.write(
            &mut self.device,
            found.block,
            found.at + 7,
            &[kind.entry_type()],
        )?;
        self.seal_directory_block(directory, found.block)
    }
}
