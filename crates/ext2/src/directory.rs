//! Directories: blocks of variable-length entries (inode, record length,
//! name length, file type, name), searched linearly.

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::inode::Kind;
use crate::{BlockDevice, Error, Filesystem, Result, NAME_MAX};

/// The fixed part of an entry.
const HEADER: usize = 8;

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
    /// The data blocks of directory `directory`, in order (holes skipped).
    fn directory_blocks(&mut self, directory: u32) -> Result<alloc::vec::Vec<u32>> {
        let mut inode = self.read_inode(directory)?;
        if inode.kind() != Some(Kind::Directory) {
            return Err(Error::NotDirectory);
        }
        let count = inode.size() / u64::from(self.block_size);
        let mut blocks = alloc::vec::Vec::new();
        for index in 0..count {
            if let Some((block, _)) = self.map_block(&mut inode, index, None)? {
                blocks.try_reserve(1).map_err(|_| Error::NoMemory)?;
                blocks.push(block);
            }
        }
        Ok(blocks)
    }

    /// Finds `name` in `directory`.
    fn find(&mut self, directory: u32, name: &[u8]) -> Result<Option<Found>> {
        for block in self.directory_blocks(directory)? {
            let bytes = self.cache.get(&mut self.device, block)?;
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

    /// The first entry of `directory` at or after byte `offset`, and the
    /// offset after it; `None` at the end. `.` and `..` are entries too.
    pub fn read_dir(&mut self, directory: u32, offset: u64) -> Result<Option<(Entry, u64)>> {
        let block_size = u64::from(self.block_size);
        let mut inode = self.read_inode(directory)?;
        if inode.kind() != Some(Kind::Directory) {
            return Err(Error::NotDirectory);
        }
        let count = inode.size() / block_size;
        let mut index = offset / block_size;
        let mut from = (offset % block_size) as usize;
        while index < count {
            if let Some((block, _)) = self.map_block(&mut inode, index, None)? {
                let bytes = self.cache.get(&mut self.device, block)?;
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
        let needed = entry_size(name.len());
        for block in self.directory_blocks(directory)? {
            let bytes = self.cache.get(&mut self.device, block)?;
            let mut at = 0;
            let mut gap = None;
            while at < bytes.len() {
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
                return self
                    .cache
                    .write(&mut self.device, block, at, &bytes[..length]);
            }
            let (bytes, length) = encode(inode, record.length - used, name, kind);
            self.cache
                .write(&mut self.device, block, at + used, &bytes[..length])?;
            return self.cache.write(
                &mut self.device,
                block,
                at + 4,
                &(used as u16).to_le_bytes(),
            );
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
        let (bytes, length) = encode(inode, self.block_size as usize, name, kind);
        contents[..length].copy_from_slice(&bytes[..length]);
        self.cache.replace(&mut self.device, block, contents)?;
        directory_inode.set_size((index + 1) * block_size);
        self.write_inode(directory, &directory_inode)
    }

    /// Removes the entry `name` from `directory`: the entry before it in
    /// its block takes its space, or, first in the block, it is cleared.
    pub(crate) fn remove_entry(&mut self, directory: u32, name: &[u8]) -> Result<()> {
        let found = self.find(directory, name)?.ok_or(Error::NotFound)?;
        match found.previous {
            Some((previous, length)) => {
                let merged = (length + found.record.length) as u16;
                self.cache.write(
                    &mut self.device,
                    found.block,
                    previous + 4,
                    &merged.to_le_bytes(),
                )
            }
            None => self.cache.write(
                &mut self.device,
                found.block,
                found.at,
                &0_u32.to_le_bytes(),
            ),
        }
    }

    /// Points the existing entry `name` of `directory` at `inode`.
    pub(crate) fn set_entry(
        &mut self,
        directory: u32,
        name: &[u8],
        inode: u32,
        kind: Kind,
    ) -> Result<()> {
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
        )
    }
}
