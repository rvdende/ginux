//! io_uring(7): rings of submission and completion queue entries that a
//! process shares with the kernel through mmap, and the buffers registered
//! with them.
//!
//! Each ring is an instance of its domain named by the open file
//! description its descriptor refers to. The process maps the submission
//! ring, the completion ring and the submission entries as three areas
//! (Ginux does not offer IORING_FEAT_SINGLE_MMAP), and the kernel keeps
//! where each was mapped: io_uring_enter reads the entries the process
//! queued there and runs them at once, in order, posting each one's
//! completion before it reads the next, so nothing is ever in flight.
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};

/// The most submission entries a ring may have (IORING_MAX_ENTRIES).
pub(crate) const MAX_ENTRIES: u32 = 32_768;
/// The most completion entries a ring may have (IORING_MAX_CQ_ENTRIES).
pub(crate) const MAX_CQ_ENTRIES: u32 = 2 * MAX_ENTRIES;
/// The most buffers one IORING_REGISTER_BUFFERS may register.
pub(crate) const MAX_BUFFERS: u32 = 16_384;
/// The largest registered buffer (1 GiB, as in Linux).
pub(crate) const MAX_BUFFER_LENGTH: u64 = 1 << 30;
/// The size of a submission entry (struct io_uring_sqe).
pub(crate) const SQE_SIZE: u64 = 64;
/// The size of a completion entry (struct io_uring_cqe).
pub(crate) const CQE_SIZE: u64 = 16;

/// Where the fields of the submission ring lie, from its start (struct
/// io_sqring_offsets): head, tail, ring mask, ring entries, flags, dropped
/// and the array of entry indices.
pub(crate) const SQ_HEAD: u64 = 0;
pub(crate) const SQ_TAIL: u64 = 4;
pub(crate) const SQ_RING_MASK: u64 = 8;
pub(crate) const SQ_RING_ENTRIES: u64 = 12;
pub(crate) const SQ_FLAGS: u64 = 16;
pub(crate) const SQ_DROPPED: u64 = 20;
pub(crate) const SQ_ARRAY: u64 = 24;
/// Where the fields of the completion ring lie (struct
/// io_cqring_offsets): head, tail, ring mask, ring entries, overflow,
/// flags and the completion entries, aligned for their 64-bit user data.
pub(crate) const CQ_HEAD: u64 = 0;
pub(crate) const CQ_TAIL: u64 = 4;
pub(crate) const CQ_RING_MASK: u64 = 8;
pub(crate) const CQ_RING_ENTRIES: u64 = 12;
pub(crate) const CQ_OVERFLOW: u64 = 16;
pub(crate) const CQ_FLAGS: u64 = 20;
pub(crate) const CQ_CQES: u64 = 32;

/// The three areas a process maps, by their mmap offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Region {
    /// IORING_OFF_SQ_RING.
    SubmissionRing,
    /// IORING_OFF_CQ_RING.
    CompletionRing,
    /// IORING_OFF_SQES.
    SubmissionEntries,
}

impl Region {
    pub(crate) fn from_offset(offset: u64) -> Option<Self> {
        match offset {
            0 => Some(Self::SubmissionRing),
            0x0800_0000 => Some(Self::CompletionRing),
            0x1000_0000 => Some(Self::SubmissionEntries),
            _ => None,
        }
    }

    /// The area's size in bytes for a ring of `rings`' sizes.
    pub(crate) fn size(self, rings: &Rings) -> u64 {
        match self {
            Self::SubmissionRing => SQ_ARRAY + u64::from(rings.sq_entries) * 4,
            Self::CompletionRing => CQ_CQES + u64::from(rings.cq_entries) * CQE_SIZE,
            Self::SubmissionEntries => u64::from(rings.sq_entries) * SQE_SIZE,
        }
    }
}

/// A ring's sizes and where its areas are mapped (0 until they are).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rings {
    pub(crate) sq_entries: u32,
    pub(crate) cq_entries: u32,
    pub(crate) sq: u64,
    pub(crate) cq: u64,
    pub(crate) sqes: u64,
}

/// A registered (fixed) buffer: READ_FIXED and WRITE_FIXED name it by
/// index and must stay inside it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Buffer {
    pub(crate) address: u64,
    pub(crate) length: u64,
}

impl Buffer {
    /// Whether `length` bytes at `address` lie inside the buffer.
    pub(crate) fn holds(&self, address: u64, length: u64) -> bool {
        address >= self.address
            && address
                .checked_add(length)
                .is_some_and(|end| end <= self.address + self.length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// No such ring.
    NotFound,
    /// Buffers are registered already (EBUSY).
    Busy,
    /// No buffers are registered (ENXIO).
    NoBuffers,
    /// A range outside the source's buffers (EINVAL).
    Invalid,
    NoMemory,
}

struct Ring {
    domain: usize,
    id: u64,
    /// The process that made it: a child closing an inherited descriptor
    /// leaves the ring to it, as with inotify instances.
    creator: u32,
    rings: Rings,
    buffers: Vec<Buffer>,
}

static RINGS: SpinLock<Vec<Ring>> = SpinLock::new(LockRank::IO_URING, Vec::new());

/// The ring sizes io_uring_setup gives for `entries` submissions, and for
/// `cq_entries` completions when IORING_SETUP_CQSIZE asks for them; with
/// `clamp` (IORING_SETUP_CLAMP) sizes past the limits are cut down to them.
pub(crate) fn sizes(entries: u32, cq_entries: Option<u32>, clamp: bool) -> Option<(u32, u32)> {
    if entries == 0 || entries > MAX_ENTRIES && !clamp {
        return None;
    }
    let sq_entries = entries.min(MAX_ENTRIES).next_power_of_two();
    let cq_entries = match cq_entries {
        Some(0) => return None,
        Some(count) if count > MAX_CQ_ENTRIES && !clamp => return None,
        Some(count) => {
            let count = count.min(MAX_CQ_ENTRIES).next_power_of_two();
            if count < sq_entries {
                return None;
            }
            count
        }
        None => sq_entries * 2,
    };
    Some((sq_entries, cq_entries))
}

/// A new ring `id` of `domain` with these sizes.
pub(crate) fn create(
    domain: usize,
    id: u64,
    creator: u32,
    sq_entries: u32,
    cq_entries: u32,
) -> bool {
    let mut rings = RINGS.lock();
    if rings.try_reserve(1).is_err() {
        return false;
    }
    rings.retain(|ring| ring.domain != domain || ring.id != id);
    rings.push(Ring {
        domain,
        id,
        creator,
        rings: Rings {
            sq_entries,
            cq_entries,
            sq: 0,
            cq: 0,
            sqes: 0,
        },
        buffers: Vec::new(),
    });
    true
}

/// Ring `id` goes when its creator closes its last descriptor of it
/// (`closer`), and every ring of a domain with the domain (`id` None).
pub(crate) fn release(domain: usize, id: Option<u64>, closer: u32) {
    RINGS.lock().retain(|ring| {
        ring.domain != domain || id.is_some_and(|id| ring.id != id || ring.creator != closer)
    });
}

fn with_ring<T>(domain: usize, id: u64, action: impl FnOnce(&mut Ring) -> T) -> Option<T> {
    RINGS
        .lock()
        .iter_mut()
        .find(|ring| ring.domain == domain && ring.id == id)
        .map(action)
}

/// Ring `id`'s sizes and mapped areas.
pub(crate) fn rings(domain: usize, id: u64) -> Option<Rings> {
    with_ring(domain, id, |ring| ring.rings)
}

/// The process mapped `region` of ring `id` at `address`.
pub(crate) fn mapped(domain: usize, id: u64, region: Region, address: u64) -> bool {
    with_ring(domain, id, |ring| match region {
        Region::SubmissionRing => ring.rings.sq = address,
        Region::CompletionRing => ring.rings.cq = address,
        Region::SubmissionEntries => ring.rings.sqes = address,
    })
    .is_some()
}

/// IORING_REGISTER_BUFFERS: `buffers` become ring `id`'s fixed buffers.
pub(crate) fn register_buffers(domain: usize, id: u64, buffers: Vec<Buffer>) -> Result<(), Error> {
    with_ring(domain, id, |ring| {
        if !ring.buffers.is_empty() {
            return Err(Error::Busy);
        }
        ring.buffers = buffers;
        Ok(())
    })
    .ok_or(Error::NotFound)?
}

/// IORING_UNREGISTER_BUFFERS.
pub(crate) fn unregister_buffers(domain: usize, id: u64) -> Result<(), Error> {
    with_ring(domain, id, |ring| {
        if ring.buffers.is_empty() {
            return Err(Error::NoBuffers);
        }
        ring.buffers = Vec::new();
        Ok(())
    })
    .ok_or(Error::NotFound)?
}

/// Fixed buffer `index` of ring `id`.
pub(crate) fn buffer(domain: usize, id: u64, index: usize) -> Option<Buffer> {
    with_ring(domain, id, |ring| ring.buffers.get(index).copied()).flatten()
}

/// IORING_REGISTER_CLONE_BUFFERS: ring `target` gets `count` of ring
/// `source`'s buffers from `source_offset` on (all of them from there for
/// 0) at `target_offset`; with `replace` it may already have buffers.
pub(crate) fn clone_buffers(
    domain: usize,
    target: u64,
    source: u64,
    (source_offset, target_offset, count): (u32, u32, u32),
    replace: bool,
) -> Result<(), Error> {
    let mut rings = RINGS.lock();
    let find = |id| {
        rings
            .iter()
            .position(|ring| ring.domain == domain && ring.id == id)
            .ok_or(Error::NotFound)
    };
    let source_index = find(source)?;
    let target_index = find(target)?;
    if !rings[target_index].buffers.is_empty() && !replace {
        return Err(Error::Busy);
    }
    let from = &rings[source_index].buffers;
    if from.is_empty() {
        return Err(Error::NoBuffers);
    }
    let start = source_offset as usize;
    let count = if count == 0 {
        from.len().checked_sub(start).ok_or(Error::Invalid)?
    } else {
        count as usize
    };
    let end = start.checked_add(count).ok_or(Error::Invalid)?;
    let cloned = from.get(start..end).ok_or(Error::Invalid)?;
    let total = (target_offset as usize)
        .checked_add(count)
        .filter(|total| *total <= MAX_BUFFERS as usize)
        .ok_or(Error::Invalid)?;
    let mut buffers = Vec::new();
    buffers
        .try_reserve_exact(total)
        .map_err(|_| Error::NoMemory)?;
    buffers.resize(target_offset as usize, Buffer::default());
    buffers.extend_from_slice(cloned);
    rings[target_index].buffers = buffers;
    Ok(())
}
