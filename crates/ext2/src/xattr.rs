//! Extended attributes, in an inode's attribute block (`i_file_acl`), as
//! ext2 keeps them. Attributes Linux's ext4 driver put in a large inode's
//! spare bytes are read too; a change moves them all into the block.
//!
//! A block starts with a 32-byte header (magic, reference count, block
//! count, hash), then the entries sorted by name, each with its value's
//! offset and size and a hash of name and value; the values fill the block
//! from its end. A block several inodes share is copied before it changes.

use alloc::vec::Vec;

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::checksum::{crc32c, crc32c_skipping};
use crate::inode::Inode;
use crate::{BlockDevice, Error, Filesystem, Result};

const MAGIC: u32 = 0xea02_0000;
const BLOCK_HEADER: usize = 32;
const ENTRY_HEADER: usize = 16;
/// Where a block keeps its checksum (metadata_csum).
const BLOCK_CHECKSUM: usize = 0x10;

/// The name prefixes ext2 stores as an index byte, and the prefix each
/// stands for. The POSIX ACL names (2 and 3) need the ACL format, which is
/// not kept, so they are refused.
const PREFIXES: [(u8, &[u8]); 3] = [(1, b"user."), (4, b"trusted."), (6, b"security.")];

/// What setting an attribute requires of the name (setxattr's flags).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XattrMode {
    /// Create or replace.
    Any,
    /// XATTR_CREATE: fail with EEXIST if it exists.
    Create,
    /// XATTR_REPLACE: fail with ENODATA if it does not.
    Replace,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Attribute {
    index: u8,
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Attribute {
    /// The order entries keep in a block: index, name length, name.
    fn key(&self) -> (u8, usize, &[u8]) {
        (self.index, self.name.len(), &self.name)
    }

    fn full_name(&self, output: &mut Vec<u8>) -> Result<()> {
        let prefix = PREFIXES
            .iter()
            .find(|(index, _)| *index == self.index)
            .map(|(_, prefix)| *prefix)
            .ok_or(Error::Corrupt)?;
        output
            .try_reserve(prefix.len() + self.name.len() + 1)
            .map_err(|_| Error::NoMemory)?;
        output.extend_from_slice(prefix);
        output.extend_from_slice(&self.name);
        output.push(0);
        Ok(())
    }
}

/// The index and suffix ext2 stores `name` as (EOPNOTSUPP for a namespace
/// it does not keep).
fn split_name(name: &[u8]) -> Result<(u8, &[u8])> {
    PREFIXES
        .iter()
        .find_map(|(index, prefix)| name.strip_prefix(*prefix).map(|rest| (*index, rest)))
        .ok_or(Error::Unsupported)
}

/// An entry's hash, of its name (as signed bytes) and its value (as
/// little-endian words, zero-padded).
fn entry_hash(name: &[u8], value: &[u8]) -> u32 {
    let mut hash = 0_u32;
    for byte in name {
        hash = (hash << 5) ^ (hash >> 27) ^ (*byte as i8 as i32 as u32);
    }
    for word in value.chunks(4) {
        let mut padded = [0; 4];
        padded[..word.len()].copy_from_slice(word);
        hash = (hash << 16) ^ (hash >> 16) ^ u32::from_le_bytes(padded);
    }
    hash
}

/// Parses the entries starting at `entries` of `area`, whose values lie
/// at `value_base` plus their offset.
fn parse_entries(
    area: &[u8],
    entries: usize,
    value_base: usize,
    output: &mut Vec<Attribute>,
) -> Result<()> {
    let mut at = entries;
    while at + 4 <= area.len() && u32_at(area, at) != 0 {
        if at + ENTRY_HEADER > area.len() {
            return Err(Error::Corrupt);
        }
        let name_length = usize::from(area[at]);
        let index = area[at + 1];
        let value_offset = usize::from(u16_at(area, at + 2));
        let value_inode = u32_at(area, at + 4);
        let value_size = u32_at(area, at + 8) as usize;
        let name_end = at + ENTRY_HEADER + name_length;
        let value_start = value_base + value_offset;
        if name_end > area.len() || value_inode != 0 || value_start + value_size > area.len() {
            return Err(Error::Corrupt);
        }
        let mut name = Vec::new();
        let mut value = Vec::new();
        name.try_reserve_exact(name_length)
            .and_then(|()| value.try_reserve_exact(value_size))
            .map_err(|_| Error::NoMemory)?;
        name.extend_from_slice(&area[at + ENTRY_HEADER..name_end]);
        value.extend_from_slice(&area[value_start..value_start + value_size]);
        output.try_reserve(1).map_err(|_| Error::NoMemory)?;
        output.push(Attribute { index, name, value });
        at = (name_end + 3) & !3;
    }
    Ok(())
}

impl<D: BlockDevice> Filesystem<D> {
    /// Every attribute of `inode`: its own bytes' first, then its block's.
    fn attributes(&mut self, inode: &Inode) -> Result<Vec<Attribute>> {
        let mut attributes = Vec::new();
        if let Some((start, end)) = inode.xattr_area() {
            let area = &inode.raw()[start..end];
            if u32_at(area, 0) == MAGIC {
                parse_entries(area, 4, 4, &mut attributes)?;
            }
        }
        let block = inode.xattr_block();
        if block != 0 {
            let bytes = self.xattr_block(inode, block)?;
            parse_entries(bytes, BLOCK_HEADER, 0, &mut attributes)?;
        }
        Ok(attributes)
    }

    /// Attribute block `block` of `inode`, checked as Linux's ext4 checks
    /// one it reads: its header (EUCLEAN), then its checksum (EBADMSG,
    /// reported against the inode).
    fn xattr_block(&mut self, inode: &Inode, block: u32) -> Result<&[u8]> {
        let bytes = self.cache.get(&mut self.device, block)?;
        if u32_at(bytes, 0) != MAGIC || u32_at(bytes, 8) != 1 {
            return Err(Error::Corrupt);
        }
        if let Some(seed) = self.seed.filter(|_| self.verify) {
            let valid = |bytes: &[u8]| {
                let seed = crc32c(seed, &u64::from(block).to_le_bytes());
                let checksum = crc32c_skipping(seed, bytes, BLOCK_CHECKSUM..BLOCK_CHECKSUM + 4);
                checksum == u32_at(bytes, BLOCK_CHECKSUM)
            };
            if self
                .cache
                .get_verified(&mut self.device, block, valid)?
                .is_none()
            {
                let error = Error::BadChecksum;
                return Err(self.report(inode.number(), u64::from(block), error));
            }
        }
        self.cache.get(&mut self.device, block)
    }

    /// The value of attribute `name` of inode `number` (ENODATA if none).
    pub fn get_xattr(&mut self, number: u32, name: &[u8]) -> Result<Vec<u8>> {
        let (index, suffix) = split_name(name)?;
        let inode = self.read_inode(number)?;
        self.attributes(&inode)?
            .into_iter()
            .find(|attribute| attribute.index == index && attribute.name == suffix)
            .map(|attribute| attribute.value)
            .ok_or(Error::NoData)
    }

    /// The names of inode `number`'s attributes, each ending in a NUL, as
    /// listxattr(2) returns them.
    pub fn list_xattrs(&mut self, number: u32) -> Result<Vec<u8>> {
        let inode = self.read_inode(number)?;
        let mut names = Vec::new();
        for attribute in self.attributes(&inode)? {
            attribute.full_name(&mut names)?;
        }
        Ok(names)
    }

    /// Sets attribute `name` of inode `number` to `value`.
    pub fn set_xattr(
        &mut self,
        number: u32,
        name: &[u8],
        value: &[u8],
        mode: XattrMode,
    ) -> Result<()> {
        self.check_writable()?;
        let (index, suffix) = split_name(name)?;
        if suffix.is_empty() || suffix.len() > 255 {
            return Err(Error::Range);
        }
        let mut inode = self.read_inode(number)?;
        let mut attributes = self.attributes(&inode)?;
        let existing = attributes
            .iter()
            .position(|attribute| attribute.index == index && attribute.name == suffix);
        match (existing, mode) {
            (Some(_), XattrMode::Create) => return Err(Error::Exists),
            (None, XattrMode::Replace) => return Err(Error::NoData),
            _ => {}
        }
        let mut stored = Vec::new();
        stored
            .try_reserve_exact(value.len())
            .map_err(|_| Error::NoMemory)?;
        stored.extend_from_slice(value);
        match existing {
            Some(position) => attributes[position].value = stored,
            None => {
                let mut name = Vec::new();
                name.try_reserve_exact(suffix.len())
                    .map_err(|_| Error::NoMemory)?;
                name.extend_from_slice(suffix);
                attributes.try_reserve(1).map_err(|_| Error::NoMemory)?;
                attributes.push(Attribute {
                    index,
                    name,
                    value: stored,
                });
            }
        }
        self.store_attributes(number, &mut inode, attributes)
    }

    /// Removes attribute `name` of inode `number` (ENODATA if none).
    pub fn remove_xattr(&mut self, number: u32, name: &[u8]) -> Result<()> {
        self.check_writable()?;
        let (index, suffix) = split_name(name)?;
        let mut inode = self.read_inode(number)?;
        let mut attributes = self.attributes(&inode)?;
        let position = attributes
            .iter()
            .position(|attribute| attribute.index == index && attribute.name == suffix)
            .ok_or(Error::NoData)?;
        attributes.remove(position);
        self.store_attributes(number, &mut inode, attributes)
    }

    /// Writes `attributes` as inode `number`'s whole set, in its block.
    fn store_attributes(
        &mut self,
        number: u32,
        inode: &mut Inode,
        mut attributes: Vec<Attribute>,
    ) -> Result<()> {
        attributes.sort_by(|a, b| a.key().cmp(&b.key()));
        let contents = if attributes.is_empty() {
            None
        } else {
            Some(self.encode_block(&attributes)?)
        };
        // Attributes in the inode's own bytes move to the block.
        if let Some((start, end)) = inode.xattr_area() {
            inode.raw_mut()[start..end].fill(0);
        }
        let old = inode.xattr_block();
        let shared = old != 0 && u32_at(self.cache.get(&mut self.device, old)?, 4) > 1;
        let block = match (contents.is_some(), old) {
            (true, 0) => {
                let block =
                    self.allocate_block((number - 1) / self.superblock.inodes_per_group())?;
                inode.set_sectors(inode.sectors() + u64::from(self.block_size / 512));
                block
            }
            (true, old) if shared => {
                self.release_shared(old)?;
                self.allocate_block((number - 1) / self.superblock.inodes_per_group())?
            }
            (true, old) => old,
            (false, _) => {
                self.drop_xattr_block(inode)?;
                return self.write_inode(number, inode);
            }
        };
        if let Some(mut contents) = contents {
            if let Some(checksum) = self.xattr_block_checksum(block, &contents) {
                set_u32(&mut contents, BLOCK_CHECKSUM, checksum);
            }
            self.cache.replace(&mut self.device, block, contents)?;
        }
        inode.set_xattr_block(block);
        self.write_inode(number, inode)
    }

    /// Lays out an attribute block: sorted entries after the header,
    /// values from the end. ENOSPC if they do not fit.
    fn encode_block(&self, attributes: &[Attribute]) -> Result<Vec<u8>> {
        let mut block = self.zeroed_block()?;
        set_u32(&mut block, 0, MAGIC);
        set_u32(&mut block, 4, 1);
        set_u32(&mut block, 8, 1);
        let mut entry = BLOCK_HEADER;
        let mut values_start = block.len();
        let mut block_hash = 0_u32;
        for attribute in attributes {
            let entry_size = (ENTRY_HEADER + attribute.name.len() + 3) & !3;
            let value_size = (attribute.value.len() + 3) & !3;
            // The end marker needs four zero bytes after the last entry.
            if entry + entry_size + 4 > values_start.saturating_sub(value_size) {
                return Err(Error::NoSpace);
            }
            values_start -= value_size;
            let value_offset = if attribute.value.is_empty() {
                0
            } else {
                values_start
            };
            block[values_start..values_start + attribute.value.len()]
                .copy_from_slice(&attribute.value);
            let hash = entry_hash(&attribute.name, &attribute.value);
            block[entry] = attribute.name.len() as u8;
            block[entry + 1] = attribute.index;
            set_u16(&mut block, entry + 2, value_offset as u16);
            set_u32(&mut block, entry + 4, 0);
            set_u32(&mut block, entry + 8, attribute.value.len() as u32);
            set_u32(&mut block, entry + 12, hash);
            block[entry + ENTRY_HEADER..entry + ENTRY_HEADER + attribute.name.len()]
                .copy_from_slice(&attribute.name);
            block_hash = (block_hash << 16) ^ (block_hash >> 16) ^ hash;
            entry += entry_size;
        }
        set_u32(&mut block, 12, block_hash);
        Ok(block)
    }

    /// The checksum of attribute block `block` holding `bytes`
    /// (metadata_csum): seeded by the block's number, over the block with
    /// its checksum field read as zero.
    fn xattr_block_checksum(&self, block: u32, bytes: &[u8]) -> Option<u32> {
        let seed = crc32c(self.seed?, &u64::from(block).to_le_bytes());
        Some(crc32c_skipping(
            seed,
            bytes,
            BLOCK_CHECKSUM..BLOCK_CHECKSUM + 4,
        ))
    }

    /// Takes one reference off a shared attribute block.
    fn release_shared(&mut self, block: u32) -> Result<()> {
        let references = u32_at(self.cache.get(&mut self.device, block)?, 4);
        self.cache.write(
            &mut self.device,
            block,
            4,
            &references.saturating_sub(1).to_le_bytes(),
        )?;
        if self.seed.is_some() {
            let bytes = self.cache.get(&mut self.device, block)?;
            let bytes: Vec<u8> = bytes.to_vec();
            if let Some(checksum) = self.xattr_block_checksum(block, &bytes) {
                self.cache.write(
                    &mut self.device,
                    block,
                    BLOCK_CHECKSUM,
                    &checksum.to_le_bytes(),
                )?;
            }
        }
        Ok(())
    }

    /// Detaches inode's attribute block, freeing it unless shared.
    pub(crate) fn drop_xattr_block(&mut self, inode: &mut Inode) -> Result<()> {
        let block = inode.xattr_block();
        if block == 0 {
            return Ok(());
        }
        let references = u32_at(self.xattr_block(inode, block)?, 4);
        if references > 1 {
            self.release_shared(block)?;
        } else {
            self.free_block(block)?;
        }
        inode.set_xattr_block(0);
        inode.set_sectors(
            inode
                .sectors()
                .saturating_sub(u64::from(self.block_size / 512)),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_split_into_index_and_suffix() {
        assert_eq!(split_name(b"user.foo").unwrap(), (1, &b"foo"[..]));
        assert_eq!(
            split_name(b"security.selinux").unwrap(),
            (6, &b"selinux"[..])
        );
        assert_eq!(
            split_name(b"system.posix_acl_access"),
            Err(Error::Unsupported)
        );
        assert_eq!(split_name(b"other.x"), Err(Error::Unsupported));
    }

    #[test]
    fn hashes_follow_the_format() {
        // Name only: each byte shifts in five bits.
        assert_eq!(entry_hash(b"a", b""), 0x61);
        assert_eq!(entry_hash(b"ab", b""), (0x61 << 5) ^ 0x62);
        // A value word mixes in sixteen bits at a time.
        assert_eq!(entry_hash(b"", b"\x01"), 1);
    }
}
