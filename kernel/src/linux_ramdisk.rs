//! RAM disks, `/dev/ramN` (block major 1), as Linux's `brd` driver offers
//! them: sixteen disks of 4 MiB (its default `rd_nr` and `rd_size`) that
//! read as zeros until written. Linux loads `brd` when a 1:N device file is
//! first opened; here the disks are always there, and each domain has its
//! own. A disk keeps the pages written to it on the kernel heap until its
//! domain's overlay is torn down.
//!
//! Open disks are object slots of the socket table ([`CLASS_DISK`]), as open
//! loop devices are; the block layer's ioctls and lseek are the loop
//! module's ([`linux_loop::block_ioctl`], [`linux_loop::block_seek`]).

use alloc::{collections::BTreeMap, vec, vec::Vec};

use crate::arch::x86_64::cpu;
use crate::linux_loop::{self, Caller, Error, Geometry};
use crate::sync::{LockRank, SpinLock};

/// The object class of an open RAM disk in the socket table.
pub(crate) const CLASS_DISK: u8 = 6;
/// The block device major number of RAM disks.
pub(crate) const MAJOR: u32 = 1;
const DISK_COUNT: u32 = 16;
pub(crate) const DISK_SIZE: u64 = 4 << 20;
const PAGE_SIZE: u64 = 4096;
const SECTOR_SIZE: u32 = 512;

/// The pages of a disk written so far, by page number.
type Disk = BTreeMap<u64, Vec<u8>>;

/// One domain's disks, by minor number, made when first opened.
struct Domain {
    disks: Vec<Disk>,
    /// Counts the domain's lives, as the loop devices' do.
    epoch: u64,
}

struct Open {
    domain: usize,
    epoch: u64,
    minor: u32,
    position: u64,
    readable: bool,
    writable: bool,
}

struct RamDisks {
    domains: Vec<Domain>,
    /// Open disks, by object id.
    opens: Vec<Option<Open>>,
}

impl RamDisks {
    fn domain(&mut self, domain: usize) -> &mut Domain {
        if self.domains.len() <= domain {
            self.domains.resize_with(domain + 1, || Domain {
                disks: Vec::new(),
                epoch: 0,
            });
        }
        let disks = &mut self.domains[domain];
        if disks.disks.is_empty() {
            disks.disks.resize_with(DISK_COUNT as usize, Disk::new);
        }
        disks
    }

    fn open(&self, id: u64) -> Result<&Open, Error> {
        self.opens
            .get(id as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::BadDescriptor)
    }

    /// The disk open `id` refers to.
    fn disk_of(&mut self, id: u64) -> Result<&mut Disk, Error> {
        let open = self.open(id)?;
        let (domain, epoch, minor) = (open.domain, open.epoch, open.minor);
        let disks = self.domain(domain);
        if disks.epoch != epoch {
            return Err(Error::NoDevice);
        }
        disks.disks.get_mut(minor as usize).ok_or(Error::NoDevice)
    }
}

static RAM_DISKS: SpinLock<RamDisks> = SpinLock::new(
    LockRank::RAM_DISKS,
    RamDisks {
        domains: Vec::new(),
        opens: Vec::new(),
    },
);

fn current_domain() -> usize {
    cpu::current_container_slot().map_or(0, |slot| slot + 1)
}

/// Opens RAM disk `minor` of the calling domain; returns the open's object
/// id. ENXIO for a minor past the disks.
pub(crate) fn open(minor: u32, readable: bool, writable: bool) -> Result<u64, Error> {
    if minor >= DISK_COUNT {
        return Err(Error::NoDevice);
    }
    let mut disks = RAM_DISKS.lock();
    let domain = current_domain();
    let epoch = disks.domain(domain).epoch;
    let open = Open {
        domain,
        epoch,
        minor,
        position: 0,
        readable,
        writable,
    };
    let id = match disks.opens.iter().position(Option::is_none) {
        Some(index) => {
            disks.opens[index] = Some(open);
            index
        }
        None => {
            disks.opens.push(Some(open));
            disks.opens.len() - 1
        }
    };
    Ok(id as u64)
}

/// Forgets open `class`/`id` after its last descriptor closed; the disk
/// keeps its contents.
pub(crate) fn release(class: u8, id: u64) {
    if class == CLASS_DISK {
        if let Some(open) = RAM_DISKS.lock().opens.get_mut(id as usize) {
            *open = None;
        }
    }
}

/// Frees the calling domain's disks with its overlay.
pub(crate) fn forget_domain() {
    let mut disks = RAM_DISKS.lock();
    if let Some(domain) = disks.domains.get_mut(current_domain()) {
        domain.disks = Vec::new();
        domain.epoch += 1;
    }
}

pub(crate) fn minor(id: u64) -> Option<u32> {
    RAM_DISKS.lock().open(id).ok().map(|open| open.minor)
}

pub(crate) fn position(id: u64) -> Result<u64, Error> {
    RAM_DISKS.lock().open(id).map(|open| open.position)
}

pub(crate) fn set_position(id: u64, position: u64) {
    if let Some(open) = RAM_DISKS
        .lock()
        .opens
        .get_mut(id as usize)
        .and_then(Option::as_mut)
    {
        open.position = position;
    }
}

pub(crate) fn seek(id: u64, offset: i64, whence: u32) -> Result<u64, Error> {
    let mut disks = RAM_DISKS.lock();
    let open = disks.open(id)?;
    let target = linux_loop::block_seek(open.position, DISK_SIZE, offset, whence)?;
    if let Some(open) = disks.opens.get_mut(id as usize).and_then(Option::as_mut) {
        open.position = target;
    }
    Ok(target)
}

/// How many bytes of `length` at `position` open `id` may read or write.
fn span(
    disks: &RamDisks,
    id: u64,
    position: u64,
    length: usize,
    write: bool,
) -> Result<usize, Error> {
    let open = disks.open(id)?;
    if write && !open.writable || !write && !open.readable {
        return Err(Error::BadDescriptor);
    }
    if length == 0 {
        return Ok(0);
    }
    if position >= DISK_SIZE {
        return if write { Err(Error::NoSpace) } else { Ok(0) };
    }
    Ok((length as u64).min(DISK_SIZE - position) as usize)
}

/// The page holding disk offset `at`, the offset within it, and how much of
/// `remaining` bytes it holds from there.
fn page_span(at: u64, remaining: usize) -> (u64, usize, usize) {
    let within = (at % PAGE_SIZE) as usize;
    (
        at / PAGE_SIZE,
        within,
        remaining.min(PAGE_SIZE as usize - within),
    )
}

/// Reads the disk of open `id` at `position` into `output`; returns how
/// much it read (short at the disk's end).
pub(crate) fn read_at(id: u64, position: u64, output: &mut [u8]) -> Result<usize, Error> {
    let mut disks = RAM_DISKS.lock();
    let length = span(&disks, id, position, output.len(), false)?;
    let disk = disks.disk_of(id)?;
    let mut done = 0;
    while done < length {
        let (page, within, chunk) = page_span(position + done as u64, length - done);
        let output = &mut output[done..done + chunk];
        match disk.get(&page) {
            Some(page) => output.copy_from_slice(&page[within..within + chunk]),
            None => output.fill(0),
        }
        done += chunk;
    }
    Ok(length)
}

/// Writes `input` to the disk of open `id` at `position`; returns how much
/// it wrote (short at the disk's end, ENOSPC at or past it).
pub(crate) fn write_at(id: u64, position: u64, input: &[u8]) -> Result<usize, Error> {
    let mut disks = RAM_DISKS.lock();
    let length = span(&disks, id, position, input.len(), true)?;
    let disk = disks.disk_of(id)?;
    let mut done = 0;
    while done < length {
        let (page, within, chunk) = page_span(position + done as u64, length - done);
        disk.entry(page)
            .or_insert_with(|| vec![0; PAGE_SIZE as usize])[within..within + chunk]
            .copy_from_slice(&input[done..done + chunk]);
        done += chunk;
    }
    Ok(length)
}

/// An ioctl on open RAM disk `id`: the block layer's; the driver has none
/// of its own (ENOTTY).
pub(crate) fn ioctl(
    id: u64,
    request: u32,
    argument: u64,
    caller: &mut impl Caller,
) -> Result<u64, Error> {
    RAM_DISKS.lock().open(id)?;
    let geometry = Geometry {
        size: DISK_SIZE,
        block_size: SECTOR_SIZE,
        read_only: false,
        partscan: true,
    };
    linux_loop::block_ioctl(&geometry, request, argument, caller).unwrap_or(Err(Error::NotTty))
}
