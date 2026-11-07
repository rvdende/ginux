//! Extent trees (ext4's `extents` feature): a file's blocks as runs of
//! blocks contiguous both in the file and on the disk, kept in a tree
//! whose root is the inode's 60 bytes of block pointers.
//!
//! A node is a 12-byte header (magic, entries, capacity, depth) and
//! 12-byte entries. A leaf's (depth 0) entries are extents: first file
//! block, length, first disk block. An index node's entries are its
//! children: first file block and the child's disk block. A length over
//! 32768 marks an unwritten extent (allocated by fallocate, it reads as
//! zeros) of the length less 32768. With metadata_csum each tree block
//! ends in a checksum over its entries, seeded by its inode.
//!
//! Lookups walk the tree. A change loads the whole map as a sorted list of
//! runs, edits the list and writes the tree back from it, reusing the
//! tree's own blocks: the tree is always as shallow as the runs allow.

use alloc::vec::Vec;

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::checksum::crc32c;
use crate::inode::Inode;
use crate::{BlockDevice, Error, Filesystem, Result};

const MAGIC: u16 = 0xf30a;
const HEADER: usize = 12;
const ENTRY: usize = 12;
/// The entries the inode's block pointers hold.
const ROOT_CAPACITY: usize = 4;
/// The longest written run, and the longest unwritten one.
const MAX_WRITTEN: u32 = 32768;
const MAX_UNWRITTEN: u32 = 32767;
/// A deeper tree is corrupt (Linux's limit too).
const MAX_DEPTH: u16 = 5;

/// Blocks `logical..logical + length` of a file, on the disk from
/// `physical`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Run {
    pub(crate) logical: u32,
    pub(crate) physical: u32,
    pub(crate) length: u32,
    /// Allocated but never written: reads as zeros.
    pub(crate) unwritten: bool,
}

impl Run {
    pub(crate) fn end(&self) -> u64 {
        u64::from(self.logical) + u64::from(self.length)
    }

    fn limit(&self) -> u32 {
        if self.unwritten {
            MAX_UNWRITTEN
        } else {
            MAX_WRITTEN
        }
    }

    /// The disk block holding file block `index`, which the run covers.
    pub(crate) fn block(&self, index: u32) -> u32 {
        self.physical + (index - self.logical)
    }

    /// Whether `next` carries on from this run in the file and on the disk.
    fn joins(&self, next: &Run) -> bool {
        self.unwritten == next.unwritten
            && self.end() == u64::from(next.logical)
            && u64::from(self.physical) + u64::from(self.length) == u64::from(next.physical)
            && self.length + next.length <= self.limit()
    }

    fn encode(&self) -> [u8; ENTRY] {
        let mut entry = [0; ENTRY];
        set_u32(&mut entry, 0, self.logical);
        let length = if self.unwritten {
            self.length + MAX_WRITTEN
        } else {
            self.length
        };
        set_u16(&mut entry, 4, length as u16);
        set_u32(&mut entry, 8, self.physical);
        entry
    }
}

/// A file's extents, loaded to be changed and stored again.
pub(crate) struct ExtentMap {
    runs: Vec<Run>,
    /// The tree's own blocks (below the root), reused when it is stored.
    blocks: Vec<u32>,
}

/// Disk blocks a change let go: (first block, count).
pub(crate) type Freed = Vec<(u32, u32)>;

impl ExtentMap {
    pub(crate) fn new() -> Self {
        Self {
            runs: Vec::new(),
            blocks: Vec::new(),
        }
    }

    /// The run holding file block `index`, or where one would go.
    fn position(&self, index: u32) -> core::result::Result<usize, usize> {
        let at = self.runs.partition_point(|run| run.logical <= index);
        if at > 0 && u64::from(index) < self.runs[at - 1].end() {
            Ok(at - 1)
        } else {
            Err(at)
        }
    }

    pub(crate) fn find(&self, index: u32) -> Option<Run> {
        self.position(index).ok().map(|at| self.runs[at])
    }

    /// Where the hole at file block `index` ends: the next run's start.
    pub(crate) fn next_start(&self, index: u32) -> Option<u32> {
        let at = self.runs.partition_point(|run| run.logical <= index);
        self.runs.get(at).map(|run| run.logical)
    }

    /// The last run before file block `index`.
    pub(crate) fn before(&self, index: u32) -> Option<Run> {
        let at = self.runs.partition_point(|run| run.logical < index);
        at.checked_sub(1).map(|at| self.runs[at])
    }

    /// Adds `run`, which must lie in a hole, joined to its neighbours where
    /// it carries them on.
    pub(crate) fn insert(&mut self, run: Run) -> Result<()> {
        let Err(at) = self.position(run.logical) else {
            return Err(Error::Corrupt);
        };
        if run.length == 0
            || self
                .runs
                .get(at)
                .is_some_and(|next| u64::from(next.logical) < run.end())
        {
            return Err(Error::Corrupt);
        }
        self.runs.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.runs.insert(at, run);
        self.join_around(at);
        Ok(())
    }

    fn join_around(&mut self, at: usize) {
        if at + 1 < self.runs.len() && self.runs[at].joins(&self.runs[at + 1]) {
            self.runs[at].length += self.runs[at + 1].length;
            self.runs.remove(at + 1);
        }
        if at > 0 && self.runs[at - 1].joins(&self.runs[at]) {
            self.runs[at - 1].length += self.runs[at].length;
            self.runs.remove(at);
        }
    }

    /// Takes file blocks `start..end` out of the map; returns the disk
    /// blocks they held.
    pub(crate) fn remove(&mut self, start: u64, end: u64) -> Result<Freed> {
        let mut freed = Vec::new();
        let mut kept = Vec::new();
        kept.try_reserve(self.runs.len() + 1)
            .map_err(|_| Error::NoMemory)?;
        for run in &self.runs {
            let (first, last) = (u64::from(run.logical), run.end());
            if last <= start || first >= end {
                kept.push(*run);
                continue;
            }
            let cut_start = first.max(start);
            let cut_end = last.min(end);
            if first < cut_start {
                kept.push(Run {
                    length: (cut_start - first) as u32,
                    ..*run
                });
            }
            freed.try_reserve(1).map_err(|_| Error::NoMemory)?;
            freed.push((
                run.physical + (cut_start - first) as u32,
                (cut_end - cut_start) as u32,
            ));
            if cut_end < last {
                kept.push(Run {
                    logical: cut_end as u32,
                    physical: run.physical + (cut_end - first) as u32,
                    length: (last - cut_end) as u32,
                    unwritten: run.unwritten,
                });
            }
        }
        self.runs = kept;
        Ok(freed)
    }

    /// Marks file block `index` of an unwritten run written (it is about
    /// to be): the run splits around it.
    pub(crate) fn mark_written(&mut self, index: u32) -> Result<()> {
        let Ok(at) = self.position(index) else {
            return Err(Error::Corrupt);
        };
        let run = self.runs[at];
        if !run.unwritten {
            return Ok(());
        }
        let offset = index - run.logical;
        self.runs.try_reserve(2).map_err(|_| Error::NoMemory)?;
        self.runs.remove(at);
        let mut next = at;
        if offset > 0 {
            self.runs.insert(
                next,
                Run {
                    length: offset,
                    ..run
                },
            );
            next += 1;
        }
        let written = next;
        self.runs.insert(
            next,
            Run {
                logical: index,
                physical: run.physical + offset,
                length: 1,
                unwritten: false,
            },
        );
        if offset + 1 < run.length {
            self.runs.insert(
                next + 1,
                Run {
                    logical: index + 1,
                    physical: run.physical + offset + 1,
                    length: run.length - offset - 1,
                    unwritten: true,
                },
            );
        }
        self.join_around(written);
        Ok(())
    }

    /// Splits the run holding file block `index`, so that one starts there.
    fn split_at(&mut self, index: u32) -> Result<()> {
        let Ok(at) = self.position(index) else {
            return Ok(());
        };
        let run = self.runs[at];
        if run.logical == index {
            return Ok(());
        }
        let offset = index - run.logical;
        self.runs.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.runs[at].length = offset;
        self.runs.insert(
            at + 1,
            Run {
                logical: index,
                physical: run.physical + offset,
                length: run.length - offset,
                unwritten: run.unwritten,
            },
        );
        Ok(())
    }

    /// Moves every run from file block `from` on by `delta` blocks (into
    /// a hole: collapsing or inserting a range).
    pub(crate) fn shift(&mut self, from: u32, delta: i64) -> Result<()> {
        self.split_at(from)?;
        let first = self.runs.partition_point(|run| run.logical < from);
        for run in &mut self.runs[first..] {
            let logical = i64::from(run.logical) + delta;
            if logical < 0 || logical + i64::from(run.length) > i64::from(u32::MAX) {
                return Err(Error::FileTooBig);
            }
            run.logical = logical as u32;
        }
        if self
            .runs
            .windows(2)
            .any(|pair| pair[0].end() > u64::from(pair[1].logical))
        {
            return Err(Error::Corrupt);
        }
        if first < self.runs.len() {
            self.join_around(first);
        }
        Ok(())
    }

    /// The written parts of file blocks `start..end`.
    fn written_within(&self, start: u64, end: u64) -> Vec<Run> {
        self.runs
            .iter()
            .filter(|run| !run.unwritten && run.end() > start && u64::from(run.logical) < end)
            .map(|run| {
                let first = u64::from(run.logical).max(start);
                let last = run.end().min(end);
                Run {
                    logical: first as u32,
                    physical: run.physical + (first - u64::from(run.logical)) as u32,
                    length: (last - first) as u32,
                    unwritten: false,
                }
            })
            .collect()
    }

    /// Marks the written blocks of `start..end` unwritten: they keep their
    /// disk blocks and read as zeros.
    pub(crate) fn mark_unwritten(&mut self, start: u64, end: u64) -> Result<()> {
        for piece in self.written_within(start, end) {
            self.remove(u64::from(piece.logical), piece.end())?;
            self.insert(Run {
                unwritten: true,
                ..piece
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn runs(&self) -> &[Run] {
        &self.runs
    }
}

/// Tree blocks (below the root) a map of `runs` runs needs.
fn tree_blocks(runs: usize, per_block: usize) -> usize {
    let mut total = 0;
    let mut count = runs;
    while count > ROOT_CAPACITY {
        count = count.div_ceil(per_block);
        total += count;
    }
    total
}

/// A node's header, checked against the bytes it heads.
struct Node {
    entries: usize,
    depth: u16,
}

fn node(bytes: &[u8]) -> Result<Node> {
    if bytes.len() < HEADER || u16_at(bytes, 0) != MAGIC {
        return Err(Error::Corrupt);
    }
    let entries = usize::from(u16_at(bytes, 2));
    let capacity = usize::from(u16_at(bytes, 4));
    let depth = u16_at(bytes, 6);
    if entries > capacity || HEADER + capacity * ENTRY > bytes.len() || depth > MAX_DEPTH {
        return Err(Error::Corrupt);
    }
    Ok(Node { entries, depth })
}

/// Whether tree block `bytes` of an inode whose checksums start from
/// `seed` has a checksum that holds: after the entries it has room for
/// (its header's capacity), over everything before. A block whose header
/// is itself broken is left to [`node`] to refuse (EUCLEAN), as Linux
/// checks the header before the checksum.
fn tree_checksum_valid(bytes: &[u8], seed: u32) -> bool {
    if node(bytes).is_err() {
        return true;
    }
    let tail = HEADER + usize::from(u16_at(bytes, 4)) * ENTRY;
    tail + 4 <= bytes.len() && crc32c(seed, &bytes[..tail]) == u32_at(bytes, tail)
}

fn write_header(bytes: &mut [u8], entries: usize, capacity: usize, depth: u16) {
    set_u16(bytes, 0, MAGIC);
    set_u16(bytes, 2, entries as u16);
    set_u16(bytes, 4, capacity as u16);
    set_u16(bytes, 6, depth);
    set_u32(bytes, 8, 0);
}

/// An empty tree's root, for a new inode's block pointers.
pub(crate) fn empty_root(root: &mut [u8]) {
    root.fill(0);
    write_header(root, 0, ROOT_CAPACITY, 0);
}

fn leaf_entry(bytes: &[u8], index: usize) -> Result<Run> {
    let at = HEADER + index * ENTRY;
    let length = u32::from(u16_at(bytes, at + 4));
    // Block numbers past 32 bits do not fit a filesystem this driver mounts.
    if u16_at(bytes, at + 6) != 0 || length == 0 {
        return Err(Error::Corrupt);
    }
    let (length, unwritten) = if length > MAX_WRITTEN {
        (length - MAX_WRITTEN, true)
    } else {
        (length, false)
    };
    Ok(Run {
        logical: u32_at(bytes, at),
        physical: u32_at(bytes, at + 8),
        length,
        unwritten,
    })
}

/// An index entry's child block.
fn child(bytes: &[u8], index: usize) -> Result<u32> {
    let at = HEADER + index * ENTRY;
    if u16_at(bytes, at + 8) != 0 {
        return Err(Error::Corrupt);
    }
    Ok(u32_at(bytes, at + 4))
}

/// The entries of a node whose first file block is at most `index`.
fn entries_up_to(bytes: &[u8], entries: usize, index: u32) -> usize {
    let (mut low, mut high) = (0, entries);
    while low < high {
        let middle = (low + high) / 2;
        if u32_at(bytes, HEADER + middle * ENTRY) <= index {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    low
}

/// One step of a lookup: the answer, or the child to go on in.
enum Step {
    Found(Option<Run>),
    Descend(u32, u16),
}

fn step(bytes: &[u8], index: u32, depth: Option<u16>) -> Result<Step> {
    let node = node(bytes)?;
    if depth.is_some_and(|depth| depth != node.depth) {
        return Err(Error::Corrupt);
    }
    let count = entries_up_to(bytes, node.entries, index);
    if count == 0 {
        return Ok(Step::Found(None));
    }
    if node.depth == 0 {
        let run = leaf_entry(bytes, count - 1)?;
        return Ok(Step::Found((u64::from(index) < run.end()).then_some(run)));
    }
    Ok(Step::Descend(child(bytes, count - 1)?, node.depth - 1))
}

/// Adds a node's runs to `runs`, or its children (last first) to `pending`.
fn collect(
    bytes: &[u8],
    depth: Option<u16>,
    runs: &mut Vec<Run>,
    pending: &mut Vec<(u32, u16)>,
) -> Result<()> {
    let node = node(bytes)?;
    if depth.is_some_and(|depth| depth != node.depth) {
        return Err(Error::Corrupt);
    }
    if node.depth == 0 {
        runs.try_reserve(node.entries)
            .map_err(|_| Error::NoMemory)?;
        for index in 0..node.entries {
            runs.push(leaf_entry(bytes, index)?);
        }
    } else {
        pending
            .try_reserve(node.entries)
            .map_err(|_| Error::NoMemory)?;
        for index in (0..node.entries).rev() {
            pending.push((child(bytes, index)?, node.depth - 1));
        }
    }
    Ok(())
}

impl<D: BlockDevice> Filesystem<D> {
    /// Entries a tree block holds (its checksum fits after them).
    fn entries_per_block(&self) -> usize {
        (self.block_size as usize - HEADER) / ENTRY
    }

    /// Tree block `block` of `inode`, checked against its checksum
    /// (EBADMSG, reported against the inode, if it fails).
    fn tree_block(&mut self, inode: &Inode, block: u32) -> Result<&[u8]> {
        if let Some(seed) = self.seed.filter(|_| self.verify) {
            let seed = inode.checksum_seed(seed);
            let valid = |bytes: &[u8]| tree_checksum_valid(bytes, seed);
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

    fn check_run(&self, run: &Run) -> Result<()> {
        if run.physical < self.superblock.first_data_block()
            || u64::from(run.physical) + u64::from(run.length)
                > u64::from(self.superblock.blocks_count())
        {
            return Err(Error::Corrupt);
        }
        Ok(())
    }

    /// The run of extent-mapped `inode` that holds file block `index`.
    pub(crate) fn find_run(&mut self, inode: &Inode, index: u32) -> Result<Option<Run>> {
        let mut next = step(inode.block_bytes(), index, None)?;
        loop {
            match next {
                Step::Found(run) => {
                    if let Some(run) = &run {
                        self.check_run(run)?;
                    }
                    return Ok(run);
                }
                Step::Descend(block, depth) => {
                    let block = self.valid_block(block)?;
                    next = step(self.tree_block(inode, block)?, index, Some(depth))?;
                }
            }
        }
    }

    /// The whole extent map of `inode`, checked.
    pub(crate) fn load_extents(&mut self, inode: &Inode) -> Result<ExtentMap> {
        let mut map = ExtentMap::new();
        let mut pending = Vec::new();
        collect(inode.block_bytes(), None, &mut map.runs, &mut pending)?;
        while let Some((block, depth)) = pending.pop() {
            let block = self.valid_block(block)?;
            map.blocks.try_reserve(1).map_err(|_| Error::NoMemory)?;
            map.blocks.push(block);
            let bytes = self.tree_block(inode, block)?;
            collect(bytes, Some(depth), &mut map.runs, &mut pending)?;
        }
        if map
            .runs
            .windows(2)
            .any(|pair| pair[0].end() > u64::from(pair[1].logical))
        {
            return Err(Error::Corrupt);
        }
        for run in &map.runs {
            self.check_run(run)?;
        }
        Ok(map)
    }

    /// Makes sure `map` has the tree blocks its runs need, so that storing
    /// it cannot run out of space; on failure (ENOSPC) it has the blocks it
    /// had. A change edits the map first, then reserves, and on failure
    /// undoes the edit or drops the map.
    pub(crate) fn reserve_tree(&mut self, inode: &mut Inode, map: &mut ExtentMap) -> Result<()> {
        let needed = tree_blocks(map.runs.len(), self.entries_per_block());
        let had = map.blocks.len();
        while map.blocks.len() < needed {
            let block = map
                .blocks
                .try_reserve(1)
                .map_err(|_| Error::NoMemory)
                .and_then(|()| self.allocate_block(self.group_of_inode(inode.number())));
            match block {
                Ok(block) => map.blocks.push(block),
                Err(error) => {
                    while map.blocks.len() > had {
                        if let Some(block) = map.blocks.pop() {
                            self.free_block(block)?;
                        }
                    }
                    return Err(error);
                }
            }
        }
        let added = (map.blocks.len().saturating_sub(had)) as u64;
        inode.set_sectors(inode.sectors() + added * self.sectors_per_block());
        Ok(())
    }

    /// Writes `map` back as `inode`'s tree (the root into the inode, which
    /// the caller writes), freeing tree blocks it no longer needs.
    pub(crate) fn store_extents(&mut self, inode: &mut Inode, map: &mut ExtentMap) -> Result<()> {
        let per_block = self.entries_per_block();
        let needed = tree_blocks(map.runs.len(), per_block);
        self.reserve_tree(inode, map)?;
        let seed = self.seed.map(|seed| inode.checksum_seed(seed));
        let mut entries: Vec<[u8; ENTRY]> = Vec::new();
        entries
            .try_reserve_exact(map.runs.len())
            .map_err(|_| Error::NoMemory)?;
        entries.extend(map.runs.iter().map(Run::encode));
        let mut depth = 0_u16;
        let mut used = 0;
        while entries.len() > ROOT_CAPACITY {
            let mut parents: Vec<[u8; ENTRY]> = Vec::new();
            parents
                .try_reserve_exact(entries.len().div_ceil(per_block))
                .map_err(|_| Error::NoMemory)?;
            for chunk in entries.chunks(per_block) {
                let block = map.blocks[used];
                used += 1;
                let mut bytes = self.zeroed_block()?;
                write_header(&mut bytes, chunk.len(), per_block, depth);
                for (index, entry) in chunk.iter().enumerate() {
                    bytes[HEADER + index * ENTRY..][..ENTRY].copy_from_slice(entry);
                }
                if let Some(seed) = seed {
                    let tail = HEADER + per_block * ENTRY;
                    let checksum = crc32c(seed, &bytes[..tail]);
                    set_u32(&mut bytes, tail, checksum);
                }
                let mut parent = [0; ENTRY];
                parent[..4].copy_from_slice(&chunk[0][..4]);
                set_u32(&mut parent, 4, block);
                parents.push(parent);
                self.cache.replace(&mut self.device, block, bytes)?;
            }
            entries = parents;
            depth += 1;
        }
        let root = inode.block_bytes_mut();
        root.fill(0);
        write_header(root, entries.len(), ROOT_CAPACITY, depth);
        for (index, entry) in entries.iter().enumerate() {
            root[HEADER + index * ENTRY..][..ENTRY].copy_from_slice(entry);
        }
        while map.blocks.len() > needed {
            if let Some(block) = map.blocks.pop() {
                self.free_block(block)?;
                inode.set_sectors(inode.sectors().saturating_sub(self.sectors_per_block()));
            }
        }
        Ok(())
    }

    /// Allocates up to `count` blocks, contiguous on the disk, for the hole
    /// at file block `index` of `map` (which `count` must not overrun);
    /// returns the new run.
    pub(crate) fn allocate_run(
        &mut self,
        inode: &mut Inode,
        map: &mut ExtentMap,
        index: u32,
        count: u32,
        unwritten: bool,
    ) -> Result<Run> {
        let limit = if unwritten {
            MAX_UNWRITTEN
        } else {
            MAX_WRITTEN
        };
        // Carry on from the run before, where the disk allows.
        let goal = match map.before(index) {
            Some(run) => run
                .physical
                .saturating_add(index - run.logical)
                .min(self.superblock.blocks_count() - 1),
            None => self.group_start(self.group_of_inode(inode.number())),
        };
        let (physical, length) = self.allocate_blocks(goal, count.clamp(1, limit))?;
        let run = Run {
            logical: index,
            physical,
            length,
            unwritten,
        };
        if let Err(error) = map.insert(run) {
            self.free_run(physical, length)?;
            return Err(error);
        }
        if let Err(error) = self.reserve_tree(inode, map) {
            map.remove(u64::from(index), run.end())?;
            self.free_run(physical, length)?;
            return Err(error);
        }
        inode.set_sectors(inode.sectors() + u64::from(length) * self.sectors_per_block());
        Ok(run)
    }

    /// Frees what `freed` lists, which `inode` held.
    pub(crate) fn release_runs(&mut self, inode: &mut Inode, freed: &Freed) -> Result<()> {
        for (block, count) in freed {
            self.free_run(*block, *count)?;
            let sectors = u64::from(*count) * self.sectors_per_block();
            inode.set_sectors(inode.sectors().saturating_sub(sectors));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(logical: u32, physical: u32, length: u32, unwritten: bool) -> Run {
        Run {
            logical,
            physical,
            length,
            unwritten,
        }
    }

    #[test]
    fn inserting_joins_runs_that_carry_on() {
        let mut map = ExtentMap::new();
        map.insert(run(0, 100, 1, false)).unwrap();
        map.insert(run(1, 101, 1, false)).unwrap();
        map.insert(run(3, 103, 1, false)).unwrap();
        assert_eq!(map.runs(), [run(0, 100, 2, false), run(3, 103, 1, false)]);
        map.insert(run(2, 102, 1, false)).unwrap();
        assert_eq!(map.runs(), [run(0, 100, 4, false)]);
        // Not on the disk after it, or of the other kind: kept apart.
        map.insert(run(4, 200, 1, false)).unwrap();
        map.insert(run(5, 201, 1, true)).unwrap();
        assert_eq!(map.runs().len(), 3);
        assert_eq!(map.insert(run(4, 300, 1, false)), Err(Error::Corrupt));
        assert_eq!(map.insert(run(6, 300, 1, false)), Ok(()));
        assert_eq!(map.find(5), Some(run(5, 201, 1, true)));
        assert_eq!(map.find(7), None);
        assert_eq!(map.next_start(4), Some(5));
        assert_eq!(map.before(4), Some(run(0, 100, 4, false)));
    }

    #[test]
    fn removing_splits_the_runs_it_cuts() {
        let mut map = ExtentMap::new();
        map.insert(run(0, 100, 10, false)).unwrap();
        map.insert(run(20, 300, 5, true)).unwrap();
        let freed = map.remove(4, 22).unwrap();
        assert_eq!(freed, [(104, 6), (300, 2)]);
        assert_eq!(map.runs(), [run(0, 100, 4, false), run(22, 302, 3, true)]);
        assert_eq!(map.remove(0, u64::MAX).unwrap(), [(100, 4), (302, 3)]);
        assert!(map.runs().is_empty());
    }

    #[test]
    fn writing_into_an_unwritten_run_splits_it() {
        let mut map = ExtentMap::new();
        map.insert(run(0, 100, 2, false)).unwrap();
        map.insert(run(2, 102, 6, true)).unwrap();
        map.mark_written(4).unwrap();
        assert_eq!(
            map.runs(),
            [
                run(0, 100, 2, false),
                run(2, 102, 2, true),
                run(4, 104, 1, false),
                run(5, 105, 3, true)
            ]
        );
        map.mark_written(2).unwrap();
        map.mark_written(3).unwrap();
        assert_eq!(map.runs(), [run(0, 100, 5, false), run(5, 105, 3, true)]);
    }

    #[test]
    fn ranges_collapse_insert_and_zero() {
        let mut map = ExtentMap::new();
        map.insert(run(0, 100, 10, false)).unwrap();
        map.insert(run(20, 300, 5, false)).unwrap();
        // Collapsing blocks 2..4: their blocks go, the rest moves down.
        let freed = map.remove(2, 4).unwrap();
        assert_eq!(freed, [(102, 2)]);
        map.shift(4, -2).unwrap();
        assert_eq!(
            map.runs(),
            [
                run(0, 100, 2, false),
                run(2, 104, 6, false),
                run(18, 300, 5, false)
            ]
        );
        // Inserting two blocks at 5 splits the run there.
        map.shift(5, 2).unwrap();
        assert_eq!(
            map.runs(),
            [
                run(0, 100, 2, false),
                run(2, 104, 3, false),
                run(7, 107, 3, false),
                run(20, 300, 5, false)
            ]
        );
        map.mark_unwritten(1, 3).unwrap();
        assert_eq!(map.find(1), Some(run(1, 101, 1, true)));
        assert_eq!(map.find(2), Some(run(2, 104, 1, true)));
        assert_eq!(map.find(3), Some(run(3, 105, 2, false)));
    }

    #[test]
    fn trees_are_as_shallow_as_the_runs_allow() {
        assert_eq!(tree_blocks(4, 340), 0);
        assert_eq!(tree_blocks(5, 340), 1);
        assert_eq!(tree_blocks(340 * 4, 340), 4);
        assert_eq!(tree_blocks(340 * 4 + 1, 340), 5 + 1);
    }

    #[test]
    fn lookups_walk_a_root() {
        let mut root = [0_u8; 60];
        empty_root(&mut root);
        for (index, extent) in [run(0, 50, 3, false), run(10, 80, 2, true)]
            .iter()
            .enumerate()
        {
            root[HEADER + index * ENTRY..][..ENTRY].copy_from_slice(&extent.encode());
        }
        set_u16(&mut root, 2, 2);
        let found = |index| match step(&root, index, None).unwrap() {
            Step::Found(run) => run,
            Step::Descend(..) => unreachable!(),
        };
        assert_eq!(found(2), Some(run(0, 50, 3, false)));
        assert_eq!(found(3), None);
        assert_eq!(found(11), Some(run(10, 80, 2, true)));
        assert_eq!(found(12), None);
    }
}
