//! A write-through cache of metadata blocks: bitmaps, inode tables,
//! indirect blocks, directories and attribute blocks.
//!
//! A change writes only the bytes it touched to the device, so the device
//! always holds what the cache does. File data bypasses the cache; a block
//! that is freed leaves it, so a metadata block reused for data (or the
//! reverse) is never read back stale.
//!
//! A block whose checksum held when it was read is marked verified, as
//! Linux marks a buffer, so it is not checked again while it stays: the
//! changes made to it since were made here, and sealed. One read again
//! from the device is checked again.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::{BlockDevice, Error, Result};

/// Blocks kept: 4 MiB of 4 KiB blocks.
const CAPACITY: usize = 1024;

pub(crate) struct BlockCache {
    block_size: usize,
    blocks: BTreeMap<u32, Vec<u8>>,
    /// Cached blocks, oldest first, for eviction.
    order: VecDeque<u32>,
    /// Cached blocks whose checksum held.
    verified: BTreeSet<u32>,
}

impl BlockCache {
    pub(crate) fn new(block_size: usize) -> Self {
        Self {
            block_size,
            blocks: BTreeMap::new(),
            order: VecDeque::new(),
            verified: BTreeSet::new(),
        }
    }

    /// Block `block`, read from `device` unless cached.
    pub(crate) fn get<D: BlockDevice>(&mut self, device: &mut D, block: u32) -> Result<&[u8]> {
        if !self.blocks.contains_key(&block) {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(self.block_size)
                .map_err(|_| Error::NoMemory)?;
            bytes.resize(self.block_size, 0);
            device.read_at(u64::from(block) * self.block_size as u64, &mut bytes)?;
            self.insert(block, bytes)?;
        }
        self.blocks.get(&block).map(Vec::as_slice).ok_or(Error::Io)
    }

    fn insert(&mut self, block: u32, bytes: Vec<u8>) -> Result<()> {
        while self.blocks.len() >= CAPACITY {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.blocks.remove(&oldest);
            self.verified.remove(&oldest);
        }
        self.order.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.order.push_back(block);
        self.blocks.insert(block, bytes);
        Ok(())
    }

    /// Writes `data` at byte `offset` of block `block`, in the cache and on
    /// the device.
    pub(crate) fn write<D: BlockDevice>(
        &mut self,
        device: &mut D,
        block: u32,
        offset: usize,
        data: &[u8],
    ) -> Result<()> {
        let end = offset.checked_add(data.len()).ok_or(Error::Invalid)?;
        if end > self.block_size {
            return Err(Error::Invalid);
        }
        let start = u64::from(block) * self.block_size as u64 + offset as u64;
        device.write_at(start, data)?;
        if let Some(cached) = self.blocks.get_mut(&block) {
            cached[offset..end].copy_from_slice(data);
        }
        Ok(())
    }

    /// Writes all of block `block` (a newly allocated metadata block).
    pub(crate) fn replace<D: BlockDevice>(
        &mut self,
        device: &mut D,
        block: u32,
        data: Vec<u8>,
    ) -> Result<()> {
        if data.len() != self.block_size {
            return Err(Error::Invalid);
        }
        device.write_at(u64::from(block) * self.block_size as u64, &data)?;
        if let Some(cached) = self.blocks.get_mut(&block) {
            *cached = data;
            Ok(())
        } else {
            self.insert(block, data)
        }
    }

    /// Drops block `block`, which is no longer metadata.
    pub(crate) fn forget(&mut self, block: u32) {
        if self.blocks.remove(&block).is_some() {
            self.order.retain(|cached| *cached != block);
        }
        self.verified.remove(&block);
    }

    /// Block `block`, read from `device` unless cached, checked with
    /// `valid` unless it was since it was read: `None` if it fails.
    pub(crate) fn get_verified<D: BlockDevice>(
        &mut self,
        device: &mut D,
        block: u32,
        valid: impl FnOnce(&[u8]) -> bool,
    ) -> Result<Option<&[u8]>> {
        let checked = self.blocks.contains_key(&block) && self.verified.contains(&block);
        if !checked {
            if !valid(self.get(device, block)?) {
                return Ok(None);
            }
            self.verified.insert(block);
        }
        self.get(device, block).map(Some)
    }
}
