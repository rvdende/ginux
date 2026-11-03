//! Loop block devices, `/dev/loopN` (major 7), and their control device
//! `/dev/loop-control` (10:237), as Linux's `loop` driver offers them: a
//! loop device shows a file as a block device.
//!
//! Each domain has its own devices, numbered from 0, eight to start with
//! (Linux's default `max_loop`). LOOP_SET_FD or LOOP_CONFIGURE binds a
//! device to a backing file (an overlay file), and reads and writes of the
//! device go to that file from the device's offset, up to its size limit.
//! Open devices are object slots of the socket table ([`CLASS_DEVICE`]), so
//! `dup`, `fork` and `close` count a device's openers as Linux counts a
//! disk's: the last close of a device marked for autoclear (or detached by
//! LOOP_CLR_FD while open) unbinds it. The device files and the sysfs
//! attributes (`/sys/block/loopN`) are made and rewritten in the domain's
//! overlay the next time a path under `/dev` or `/sys` is walked after the
//! device changed, as udev and sysfs would show the change.
//!
//! Partition tables are not scanned: LO_FLAGS_PARTSCAN is kept and shown,
//! but no `loopNpM` devices appear. A loop device cannot back another one
//! (EINVAL).

use alloc::{format, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::cpu;
use crate::linux_overlay::{self, Handle, NodeKind};
use crate::sync::{LockRank, SpinLock};

/// Object classes in the socket table: an open loop device, and an open
/// `/dev/loop-control`.
pub(crate) const CLASS_DEVICE: u8 = 4;
pub(crate) const CLASS_CONTROL: u8 = 5;

/// The block device major number of loop devices.
pub(crate) const MAJOR: u32 = 7;
/// `/dev/loop-control`, a misc character device.
pub(crate) const CONTROL_MAJOR: u32 = 10;
pub(crate) const CONTROL_MINOR: u32 = 237;

const CONTROL_PATH: &[u8] = b"dev/loop-control";
/// Devices a domain starts with.
const INITIAL_DEVICES: u32 = 8;
/// Device minors fit Linux's 20 bits.
const MINOR_LIMIT: u64 = 1 << 20;
/// The `disk` group, which owns block devices.
const DISK_GROUP: u32 = 6;
const SECTOR_SIZE: u64 = 512;
const PAGE_SIZE: u64 = 4096;
const NAME_SIZE: usize = 64;
const KEY_SIZE: u32 = 32;

const FLAG_READ_ONLY: u32 = 1;
const FLAG_AUTOCLEAR: u32 = 4;
const FLAG_PARTSCAN: u32 = 8;
const FLAG_DIRECT_IO: u32 = 16;
/// What LOOP_SET_STATUS may set, and of that what it may clear.
const SET_STATUS_SETTABLE: u32 = FLAG_AUTOCLEAR | FLAG_PARTSCAN;
const SET_STATUS_CLEARABLE: u32 = FLAG_AUTOCLEAR;
const CONFIGURE_SETTABLE: u32 = FLAG_READ_ONLY | FLAG_AUTOCLEAR | FLAG_PARTSCAN | FLAG_DIRECT_IO;

const LOOP_SET_FD: u32 = 0x4c00;
const LOOP_CLR_FD: u32 = 0x4c01;
const LOOP_SET_STATUS: u32 = 0x4c02;
const LOOP_GET_STATUS: u32 = 0x4c03;
const LOOP_SET_STATUS64: u32 = 0x4c04;
const LOOP_GET_STATUS64: u32 = 0x4c05;
const LOOP_CHANGE_FD: u32 = 0x4c06;
const LOOP_SET_CAPACITY: u32 = 0x4c07;
const LOOP_SET_DIRECT_IO: u32 = 0x4c08;
const LOOP_SET_BLOCK_SIZE: u32 = 0x4c09;
const LOOP_CONFIGURE: u32 = 0x4c0a;
const LOOP_CTL_ADD: u32 = 0x4c80;
const LOOP_CTL_REMOVE: u32 = 0x4c81;
const LOOP_CTL_GET_FREE: u32 = 0x4c82;

// The block layer's own ioctls, which every block device answers.
const BLKROSET: u32 = 0x125d;
const BLKROGET: u32 = 0x125e;
const BLKRRPART: u32 = 0x125f;
const BLKGETSIZE: u32 = 0x1260;
const BLKFLSBUF: u32 = 0x1261;
const BLKSSZGET: u32 = 0x1268;
const BLKIOMIN: u32 = 0x1278;
const BLKIOOPT: u32 = 0x1279;
const BLKALIGNOFF: u32 = 0x127a;
const BLKPBSZGET: u32 = 0x127b;
const BLKDISCARDZEROES: u32 = 0x127c;
const BLKROTATIONAL: u32 = 0x127e;
const BLKBSZGET: u32 = 0x8008_1270;
const BLKGETSIZE64: u32 = 0x8008_1272;

/// `struct loop_info`, `struct loop_info64` and `struct loop_config` on
/// x86-64.
const INFO_SIZE: usize = 168;
const INFO64_SIZE: usize = 232;
const CONFIG_SIZE: usize = 304;

/// Why a loop operation failed, as Linux's errno.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// EPERM
    Permission,
    /// EIO
    Io,
    /// ENXIO: the device is not bound, or is going away.
    NoDevice,
    /// EBADF
    BadDescriptor,
    /// EACCES
    Access,
    /// EFAULT
    Fault,
    /// EBUSY
    Busy,
    /// EEXIST
    Exists,
    /// ENODEV: no loop device has that number.
    NoSuchDevice,
    /// EINVAL
    Invalid,
    /// ENOSPC: a write at or past the device's end.
    NoSpace,
    /// ENOTTY: an ioctl the device does not have.
    NotTty,
    /// ENOSYS: an unknown loop-control request.
    NotImplemented,
    /// EOVERFLOW
    Overflow,
}

impl Error {
    pub(crate) fn number(self) -> u64 {
        match self {
            Self::Permission => 1,
            Self::Io => 5,
            Self::NoDevice => 6,
            Self::BadDescriptor => 9,
            Self::Access => 13,
            Self::Fault => 14,
            Self::Busy => 16,
            Self::Exists => 17,
            Self::NotTty => 25,
            Self::NoSuchDevice => 19,
            Self::Invalid => 22,
            Self::NoSpace => 28,
            Self::NotImplemented => 38,
            Self::Overflow => 75,
        }
    }
}

/// What a file descriptor handed to LOOP_SET_FD, LOOP_CONFIGURE or
/// LOOP_CHANGE_FD refers to.
pub(crate) enum Backing {
    /// A regular overlay file, and whether the descriptor may write it.
    File { handle: Handle, writable: bool },
    /// An open loop device (its object id).
    Loop(u64),
    /// Anything else open: a directory, pipe, socket or device.
    Other,
}

/// What a loop ioctl needs from the calling process.
pub(crate) trait Caller {
    /// Copies `output.len()` bytes in from user memory at `address`.
    fn copy_in(&self, address: u64, output: &mut [u8]) -> bool;
    /// Copies `input` out to user memory at `address`.
    fn copy_out(&mut self, address: u64, input: &[u8]) -> bool;
    /// The file descriptor `descriptor` refers to (EBADF if none).
    fn backing(&mut self, descriptor: u32) -> Result<Backing, Error>;
    /// Whether the caller has CAP_SYS_ADMIN.
    fn administrator(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Unbound,
    Bound,
    /// Detached while open: cleared at its last close, and not opened again
    /// meanwhile.
    Rundown,
}

struct Device {
    state: State,
    backing: Option<Handle>,
    offset: u64,
    size_limit: u64,
    /// LO_FLAGS_*.
    flags: u32,
    block_size: u32,
    /// The device's size in 512-byte sectors, as last computed from its
    /// backing file (LOOP_SET_CAPACITY computes it again).
    sectors: u64,
    file_name: [u8; NAME_SIZE],
    /// Open file descriptions of the device.
    openers: u32,
    /// The device file and attributes need rewriting.
    stale: bool,
}

impl Device {
    const fn new() -> Self {
        Self {
            state: State::Unbound,
            backing: None,
            offset: 0,
            size_limit: 0,
            flags: 0,
            block_size: SECTOR_SIZE as u32,
            sectors: 0,
            file_name: [0; NAME_SIZE],
            openers: 0,
            stale: true,
        }
    }

    fn bound(&self) -> Result<Handle, Error> {
        match (self.state, self.backing) {
            (State::Bound, Some(handle)) => Ok(handle),
            _ => Err(Error::NoDevice),
        }
    }

    fn read_only(&self) -> bool {
        self.state != State::Unbound && self.flags & FLAG_READ_ONLY != 0
    }

    fn size(&self) -> u64 {
        self.sectors * SECTOR_SIZE
    }

    /// The size the device would have on `backing` with its offset and
    /// limit, in sectors.
    fn sectors_on(&self, backing: Handle) -> u64 {
        let length = linux_overlay::metadata(backing).map_or(0, |metadata| metadata.size as u64);
        let mut size = length.saturating_sub(self.offset);
        if self.size_limit > 0 {
            size = size.min(self.size_limit);
        }
        size / SECTOR_SIZE
    }

    /// Goes back to unbound, as at the last close after LOOP_CLR_FD.
    fn clear(&mut self) {
        *self = Self {
            openers: self.openers,
            ..Self::new()
        };
    }
}

/// One domain's devices, by minor number (`None`: removed).
struct Domain {
    devices: Vec<Option<Device>>,
    /// Minors removed since their files were last rewritten.
    removed: Vec<u32>,
    /// Counts the domain's lives: an open from before its overlay was torn
    /// down no longer counts as an opener.
    epoch: u64,
    initialized: bool,
}

impl Domain {
    const fn new() -> Self {
        Self {
            devices: Vec::new(),
            removed: Vec::new(),
            epoch: 0,
            initialized: false,
        }
    }

    fn device(&mut self, minor: u32) -> Option<&mut Device> {
        self.devices.get_mut(minor as usize)?.as_mut()
    }

    /// Adds device `minor`; false if it exists.
    fn add(&mut self, minor: u32) -> bool {
        let index = minor as usize;
        if self.devices.len() <= index {
            self.devices.resize_with(index + 1, || None);
        }
        if self.devices[index].is_some() {
            return false;
        }
        self.devices[index] = Some(Device::new());
        self.removed.retain(|removed| *removed != minor);
        true
    }
}

/// An open file description of a loop device.
struct Open {
    domain: usize,
    epoch: u64,
    minor: u32,
    position: u64,
    readable: bool,
    writable: bool,
}

struct Loops {
    domains: Vec<Domain>,
    /// Open loop devices, by object id.
    opens: Vec<Option<Open>>,
}

impl Loops {
    /// The calling domain's devices, made the first time.
    fn domain(&mut self, domain: usize) -> &mut Domain {
        if self.domains.len() <= domain {
            self.domains.resize_with(domain + 1, Domain::new);
        }
        let devices = &mut self.domains[domain];
        if !devices.initialized {
            devices.initialized = true;
            for minor in 0..INITIAL_DEVICES {
                devices.add(minor);
            }
        }
        devices
    }

    fn open(&self, id: u64) -> Result<&Open, Error> {
        self.opens
            .get(id as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::BadDescriptor)
    }

    /// The device open `id` refers to.
    fn device_of(&mut self, id: u64) -> Result<&mut Device, Error> {
        let open = self.open(id)?;
        let (domain, epoch, minor) = (open.domain, open.epoch, open.minor);
        let devices = self.domain(domain);
        if devices.epoch != epoch {
            return Err(Error::NoDevice);
        }
        devices.device(minor).ok_or(Error::NoDevice)
    }
}

static LOOPS: SpinLock<Loops> = SpinLock::new(
    LockRank::LOOP,
    Loops {
        domains: Vec::new(),
        opens: Vec::new(),
    },
);

/// Set while [`ensure_nodes`] writes the files: making one walks its path,
/// which comes back here.
static MAKING_NODES: AtomicBool = AtomicBool::new(false);

/// The calling domain's index in [`Loops::domains`].
fn current_domain() -> usize {
    cpu::current_container_slot().map_or(0, |slot| slot + 1)
}

/// Opens loop device `minor` of the calling domain; returns the open's
/// object id. ENXIO if there is no such device or it is going away.
pub(crate) fn open(minor: u32, readable: bool, writable: bool) -> Result<u64, Error> {
    let mut loops = LOOPS.lock();
    let domain = current_domain();
    let devices = loops.domain(domain);
    let epoch = devices.epoch;
    let device = devices.device(minor).ok_or(Error::NoDevice)?;
    if device.state == State::Rundown {
        return Err(Error::NoDevice);
    }
    device.openers += 1;
    let open = Open {
        domain,
        epoch,
        minor,
        position: 0,
        readable,
        writable,
    };
    let id = match loops.opens.iter().position(Option::is_none) {
        Some(index) => {
            loops.opens[index] = Some(open);
            index
        }
        None => {
            loops.opens.push(Some(open));
            loops.opens.len() - 1
        }
    };
    Ok(id as u64)
}

/// Releases object `class`/`id` after its last descriptor closed: an open
/// loop device's last close clears it if it was detached or is marked for
/// autoclear. Objects of other classes are not this module's.
pub(crate) fn release(class: u8, id: u64) {
    if class != CLASS_DEVICE {
        return;
    }
    let mut loops = LOOPS.lock();
    let Some(open) = loops.opens.get_mut(id as usize).and_then(Option::take) else {
        return;
    };
    let devices = loops.domain(open.domain);
    if devices.epoch != open.epoch {
        return;
    }
    let Some(device) = devices.device(open.minor) else {
        return;
    };
    device.openers = device.openers.saturating_sub(1);
    if device.openers > 0 {
        return;
    }
    if device.state == State::Bound && device.flags & FLAG_AUTOCLEAR != 0 {
        device.state = State::Rundown;
    }
    if device.state == State::Rundown {
        device.clear();
    }
}

/// Forgets the calling domain's devices, whose backing files go with its
/// overlay: the domain starts again with fresh devices.
pub(crate) fn forget_domain() {
    let mut loops = LOOPS.lock();
    let domain = current_domain();
    if let Some(devices) = loops.domains.get_mut(domain) {
        let epoch = devices.epoch + 1;
        *devices = Domain::new();
        devices.epoch = epoch;
    }
}

/// The minor number of the device open `id` refers to.
pub(crate) fn minor(id: u64) -> Option<u32> {
    LOOPS.lock().open(id).ok().map(|open| open.minor)
}

/// The file position of open `id`.
pub(crate) fn position(id: u64) -> Result<u64, Error> {
    LOOPS.lock().open(id).map(|open| open.position)
}

pub(crate) fn set_position(id: u64, position: u64) {
    if let Some(open) = LOOPS
        .lock()
        .opens
        .get_mut(id as usize)
        .and_then(Option::as_mut)
    {
        open.position = position;
    }
}

/// lseek(2) on open `id`: positions run from 0 to the device's size.
pub(crate) fn seek(id: u64, offset: i64, whence: u32) -> Result<u64, Error> {
    let mut loops = LOOPS.lock();
    let position = loops.open(id)?.position;
    let size = loops.device_of(id).map_or(0, |device| device.size());
    let target = block_seek(position, size, offset, whence)?;
    if let Some(open) = loops.opens.get_mut(id as usize).and_then(Option::as_mut) {
        open.position = target;
    }
    Ok(target)
}

/// Where lseek(2) moves a block device's file `position`: anywhere from 0
/// to the device's `size` (EINVAL past it), all of it data.
pub(crate) fn block_seek(position: u64, size: u64, offset: i64, whence: u32) -> Result<u64, Error> {
    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    const SEEK_END: u32 = 2;
    const SEEK_DATA: u32 = 3;
    const SEEK_HOLE: u32 = 4;
    let target = match whence {
        SEEK_SET => i128::from(offset),
        SEEK_CUR => i128::from(position) + i128::from(offset),
        SEEK_END => i128::from(size) + i128::from(offset),
        SEEK_DATA | SEEK_HOLE => {
            if offset < 0 || offset as u64 >= size {
                return Err(Error::NoDevice);
            }
            if whence == SEEK_DATA {
                i128::from(offset)
            } else {
                i128::from(size)
            }
        }
        _ => return Err(Error::Invalid),
    };
    if target < 0 || target > i128::from(size) {
        return Err(Error::Invalid);
    }
    Ok(target as u64)
}

/// Where I/O of open `id` at `position` goes: the backing file, the file
/// offset and how many bytes of `length` the device holds from there.
fn span(
    id: u64,
    position: u64,
    length: usize,
    write: bool,
) -> Result<Option<(Handle, u64, usize)>, Error> {
    let mut loops = LOOPS.lock();
    let open = loops.open(id)?;
    if write && !open.writable || !write && !open.readable {
        return Err(Error::BadDescriptor);
    }
    let device = loops.device_of(id)?;
    if write && device.read_only() {
        return Err(Error::Permission);
    }
    if length == 0 {
        return Ok(None);
    }
    let size = device.size();
    if position >= size {
        return if write { Err(Error::NoSpace) } else { Ok(None) };
    }
    let length = (length as u64).min(size - position) as usize;
    let backing = device.backing.ok_or(Error::Io)?;
    Ok(Some((backing, device.offset + position, length)))
}

/// Reads the device of open `id` at `position` into `output`; returns how
/// much it read (short at the device's end). The backing file reads as
/// zeros past its own end.
pub(crate) fn read_at(id: u64, position: u64, output: &mut [u8]) -> Result<usize, Error> {
    let Some((backing, start, length)) = span(id, position, output.len(), false)? else {
        return Ok(0);
    };
    let output = &mut output[..length];
    let mut done = 0;
    while done < length {
        let at = usize::try_from(start + done as u64).map_err(|_| Error::Io)?;
        match linux_overlay::read(backing, at, &mut output[done..]).ok_or(Error::Io)? {
            0 => break,
            read => done += read,
        }
    }
    output[done..].fill(0);
    Ok(length)
}

/// Writes `input` to the device of open `id` at `position`; returns how
/// much it wrote (short at the device's end, ENOSPC at or past it).
pub(crate) fn write_at(id: u64, position: u64, input: &[u8]) -> Result<usize, Error> {
    let Some((backing, start, length)) = span(id, position, input.len(), true)? else {
        return Ok(0);
    };
    let at = usize::try_from(start).map_err(|_| Error::Io)?;
    match linux_overlay::write(backing, at, &input[..length]) {
        Some(written) if written == length => Ok(length),
        _ => Err(Error::Io),
    }
}

/// A `struct loop_info64` (or a `struct loop_info` widened to one).
#[derive(Clone, Copy)]
struct Info {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; NAME_SIZE],
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap_or_default())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap_or_default())
}

impl Info {
    const EMPTY: Self = Self {
        device: 0,
        inode: 0,
        rdevice: 0,
        offset: 0,
        size_limit: 0,
        number: 0,
        encrypt_type: 0,
        encrypt_key_size: 0,
        flags: 0,
        file_name: [0; NAME_SIZE],
    };

    fn from_info64(bytes: &[u8]) -> Self {
        let mut file_name = [0; NAME_SIZE];
        file_name.copy_from_slice(&bytes[56..56 + NAME_SIZE]);
        Self {
            device: u64_at(bytes, 0),
            inode: u64_at(bytes, 8),
            rdevice: u64_at(bytes, 16),
            offset: u64_at(bytes, 24),
            size_limit: u64_at(bytes, 32),
            number: u32_at(bytes, 40),
            encrypt_type: u32_at(bytes, 44),
            encrypt_key_size: u32_at(bytes, 48),
            flags: u32_at(bytes, 52),
            file_name,
        }
    }

    /// The old `struct loop_info`: no size limit, and its encryption
    /// fields are not taken.
    fn from_info(bytes: &[u8]) -> Self {
        let mut file_name = [0; NAME_SIZE];
        file_name.copy_from_slice(&bytes[48..48 + NAME_SIZE]);
        Self {
            device: u64_at(bytes, 8),
            inode: u64_at(bytes, 16),
            rdevice: u64_at(bytes, 24),
            // An int, sign-extended (a negative offset overflows).
            offset: u32_at(bytes, 32) as i32 as i64 as u64,
            number: u32_at(bytes, 0),
            flags: u32_at(bytes, 44),
            file_name,
            ..Self::EMPTY
        }
    }

    fn to_info64(self) -> [u8; INFO64_SIZE] {
        let mut bytes = [0; INFO64_SIZE];
        bytes[0..8].copy_from_slice(&self.device.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.inode.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.rdevice.to_ne_bytes());
        bytes[24..32].copy_from_slice(&self.offset.to_ne_bytes());
        bytes[32..40].copy_from_slice(&self.size_limit.to_ne_bytes());
        bytes[40..44].copy_from_slice(&self.number.to_ne_bytes());
        bytes[52..56].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[56..56 + NAME_SIZE].copy_from_slice(&self.file_name);
        bytes
    }

    /// The old `struct loop_info`; EOVERFLOW if the offset does not fit
    /// its int.
    fn to_info(self) -> Result<[u8; INFO_SIZE], Error> {
        let offset = i32::try_from(self.offset).map_err(|_| Error::Overflow)?;
        let mut bytes = [0; INFO_SIZE];
        bytes[0..4].copy_from_slice(&self.number.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.device.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.inode.to_ne_bytes());
        bytes[24..32].copy_from_slice(&self.rdevice.to_ne_bytes());
        bytes[32..36].copy_from_slice(&offset.to_ne_bytes());
        bytes[44..48].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[48..48 + NAME_SIZE].copy_from_slice(&self.file_name);
        Ok(bytes)
    }
}

/// Takes the settings of `info` that LOOP_SET_STATUS and LOOP_CONFIGURE
/// set: offset, size limit, file name and flags.
fn set_from_info(device: &mut Device, info: &Info) -> Result<(), Error> {
    if info.encrypt_key_size > KEY_SIZE || info.encrypt_type != 0 {
        return Err(Error::Invalid);
    }
    if info.offset > i64::MAX as u64 || info.size_limit > i64::MAX as u64 {
        return Err(Error::Overflow);
    }
    device.offset = info.offset;
    device.size_limit = info.size_limit;
    device.file_name = info.file_name;
    device.file_name[NAME_SIZE - 1] = 0;
    device.flags = info.flags;
    Ok(())
}

/// A logical block size the block layer takes: a power of two from 512
/// bytes to a page.
fn valid_block_size(size: u64) -> bool {
    (SECTOR_SIZE..=PAGE_SIZE).contains(&size) && size.is_power_of_two()
}

/// The file `backing` refers to, for device `minor` of open `id` to read
/// and write: a regular file (EINVAL otherwise), and not the device itself
/// (EBADF).
fn backing_file(loops: &Loops, id: u64, backing: Backing) -> Result<(Handle, bool), Error> {
    match backing {
        Backing::File { handle, writable } => Ok((handle, writable)),
        Backing::Loop(other) => {
            let this = loops.open(id)?;
            match loops.open(other) {
                Ok(open)
                    if open.domain == this.domain
                        && open.epoch == this.epoch
                        && open.minor == this.minor =>
                {
                    Err(Error::BadDescriptor)
                }
                _ => Err(Error::Invalid),
            }
        }
        Backing::Other => Err(Error::Invalid),
    }
}

/// LOOP_SET_FD (`config` all zero but its descriptor) and LOOP_CONFIGURE.
fn configure(id: u64, config: &[u8; CONFIG_SIZE], caller: &mut impl Caller) -> Result<u64, Error> {
    let backing = caller.backing(u32_at(config, 0))?;
    let block_size = u32_at(config, 4);
    let info = Info::from_info64(&config[8..8 + INFO64_SIZE]);
    let mut loops = LOOPS.lock();
    let device_writable = loops.open(id)?.writable;
    if loops.device_of(id)?.state != State::Unbound {
        return Err(Error::Busy);
    }
    let (handle, file_writable) = backing_file(&loops, id, backing)?;
    if info.flags & !CONFIGURE_SETTABLE != 0 {
        return Err(Error::Invalid);
    }
    let mut configured = Device::new();
    set_from_info(&mut configured, &info)?;
    if block_size != 0 && !valid_block_size(u64::from(block_size)) {
        return Err(Error::Invalid);
    }
    let device = loops.device_of(id)?;
    if !file_writable || !device_writable {
        configured.flags |= FLAG_READ_ONLY;
    }
    if block_size != 0 {
        configured.block_size = block_size;
    }
    configured.sectors = configured.sectors_on(handle);
    configured.backing = Some(handle);
    configured.state = State::Bound;
    configured.openers = device.openers;
    *device = configured;
    Ok(0)
}

/// LOOP_CHANGE_FD: a read-only device moves to another file of the same
/// size.
fn change_backing(id: u64, descriptor: u32, caller: &mut impl Caller) -> Result<u64, Error> {
    let backing = caller.backing(descriptor)?;
    let mut loops = LOOPS.lock();
    let device = loops.device_of(id)?;
    let old = device.bound()?;
    if device.flags & FLAG_READ_ONLY == 0 {
        return Err(Error::Invalid);
    }
    let (handle, _) = backing_file(&loops, id, backing)?;
    let device = loops.device_of(id)?;
    if device.sectors_on(handle) != device.sectors_on(old) {
        return Err(Error::Invalid);
    }
    device.backing = Some(handle);
    device.stale = true;
    Ok(0)
}

/// LOOP_SET_STATUS and LOOP_SET_STATUS64.
fn set_status(id: u64, info: &Info) -> Result<u64, Error> {
    let mut loops = LOOPS.lock();
    let device = loops.device_of(id)?;
    let backing = device.bound()?;
    let previous = device.flags;
    let resized = device.offset != info.offset || device.size_limit != info.size_limit;
    set_from_info(device, info)?;
    device.flags &= SET_STATUS_SETTABLE;
    device.flags |= previous & !SET_STATUS_SETTABLE;
    device.flags |= previous & !SET_STATUS_CLEARABLE;
    if resized {
        device.sectors = device.sectors_on(backing);
    }
    device.stale = true;
    Ok(0)
}

/// LOOP_GET_STATUS and LOOP_GET_STATUS64: the device's settings and its
/// backing file's identity.
fn status(id: u64) -> Result<Info, Error> {
    let mut loops = LOOPS.lock();
    let minor = loops.open(id)?.minor;
    let device = loops.device_of(id)?;
    let backing = device.bound()?;
    Ok(Info {
        inode: backing.inode(),
        offset: device.offset,
        size_limit: device.size_limit,
        number: minor,
        flags: device.flags,
        file_name: device.file_name,
        ..Info::EMPTY
    })
}

/// LOOP_CLR_FD: the device is cleared at its last close; with no other
/// opener, nothing opens it again meanwhile.
fn detach(id: u64) -> Result<u64, Error> {
    let mut loops = LOOPS.lock();
    let device = loops.device_of(id)?;
    device.bound()?;
    device.flags |= FLAG_AUTOCLEAR;
    if device.openers == 1 {
        device.state = State::Rundown;
    }
    device.stale = true;
    Ok(0)
}

/// LOOP_SET_CAPACITY, LOOP_SET_DIRECT_IO and LOOP_SET_BLOCK_SIZE.
fn simple(id: u64, request: u32, argument: u64) -> Result<u64, Error> {
    let mut loops = LOOPS.lock();
    let device = loops.device_of(id)?;
    let backing = device.bound()?;
    match request {
        LOOP_SET_CAPACITY => device.sectors = device.sectors_on(backing),
        // Overlay files take O_DIRECT, so direct I/O is always possible.
        LOOP_SET_DIRECT_IO if argument != 0 => device.flags |= FLAG_DIRECT_IO,
        LOOP_SET_DIRECT_IO => device.flags &= !FLAG_DIRECT_IO,
        _ if u64::from(device.block_size) == argument => {}
        _ if valid_block_size(argument) => device.block_size = argument as u32,
        _ => return Err(Error::Invalid),
    }
    device.stale = true;
    Ok(0)
}

/// What the block layer's ioctls report of a block device: its size in
/// bytes, logical block size, whether it is read-only and whether its
/// partitions may be read again.
pub(crate) struct Geometry {
    pub(crate) size: u64,
    pub(crate) block_size: u32,
    pub(crate) read_only: bool,
    pub(crate) partscan: bool,
}

fn geometry(id: u64) -> Result<Geometry, Error> {
    let mut loops = LOOPS.lock();
    let device = loops.device_of(id)?;
    Ok(Geometry {
        size: device.size(),
        block_size: device.block_size,
        read_only: device.read_only(),
        partscan: device.flags & FLAG_PARTSCAN != 0,
    })
}

/// The block layer's own ioctls on a block device of `geometry`; None for
/// its driver's.
pub(crate) fn block_ioctl(
    geometry: &Geometry,
    request: u32,
    argument: u64,
    caller: &mut impl Caller,
) -> Option<Result<u64, Error>> {
    let value: u64 = match request {
        BLKGETSIZE64 => geometry.size,
        BLKGETSIZE => geometry.size / SECTOR_SIZE,
        BLKSSZGET | BLKPBSZGET | BLKIOMIN => u64::from(geometry.block_size),
        BLKBSZGET => PAGE_SIZE,
        BLKROGET => u64::from(geometry.read_only),
        BLKIOOPT | BLKALIGNOFF | BLKDISCARDZEROES | BLKROTATIONAL => 0,
        BLKFLSBUF | BLKROSET | BLKRRPART => {
            return Some(if !caller.administrator() {
                Err(Error::Access)
            } else if request == BLKRRPART && !geometry.partscan {
                Err(Error::Invalid)
            } else {
                Ok(0)
            })
        }
        _ => return None,
    };
    let copied = match request {
        BLKGETSIZE64 | BLKGETSIZE | BLKBSZGET => caller.copy_out(argument, &value.to_ne_bytes()),
        BLKROTATIONAL => caller.copy_out(argument, &(value as u16).to_ne_bytes()),
        _ => caller.copy_out(argument, &(value as u32).to_ne_bytes()),
    };
    Some(if copied { Ok(0) } else { Err(Error::Fault) })
}

/// An ioctl on open loop device `id`.
pub(crate) fn ioctl(
    id: u64,
    request: u32,
    argument: u64,
    caller: &mut impl Caller,
) -> Result<u64, Error> {
    if let Some(result) = block_ioctl(&geometry(id)?, request, argument, caller) {
        return result;
    }
    let writable = LOOPS.lock().open(id)?.writable;
    // Changing a device takes an open for writing, or CAP_SYS_ADMIN.
    let may_change = writable || caller.administrator();
    match request {
        LOOP_SET_FD => {
            let mut config = [0; CONFIG_SIZE];
            config[..4].copy_from_slice(&(argument as u32).to_ne_bytes());
            configure(id, &config, caller)
        }
        LOOP_CONFIGURE => {
            let mut config = [0; CONFIG_SIZE];
            if !caller.copy_in(argument, &mut config) {
                return Err(Error::Fault);
            }
            configure(id, &config, caller)
        }
        LOOP_CHANGE_FD => change_backing(id, argument as u32, caller),
        LOOP_CLR_FD => detach(id),
        LOOP_SET_STATUS | LOOP_SET_STATUS64 if !may_change => Err(Error::Permission),
        LOOP_SET_STATUS => {
            let mut info = [0; INFO_SIZE];
            if !caller.copy_in(argument, &mut info) {
                return Err(Error::Fault);
            }
            set_status(id, &Info::from_info(&info))
        }
        LOOP_SET_STATUS64 => {
            let mut info = [0; INFO64_SIZE];
            if !caller.copy_in(argument, &mut info) {
                return Err(Error::Fault);
            }
            set_status(id, &Info::from_info64(&info))
        }
        LOOP_GET_STATUS | LOOP_GET_STATUS64 if argument == 0 => Err(Error::Invalid),
        LOOP_GET_STATUS => {
            let info = status(id)?.to_info()?;
            if caller.copy_out(argument, &info) {
                Ok(0)
            } else {
                Err(Error::Fault)
            }
        }
        LOOP_GET_STATUS64 => {
            let info = status(id)?.to_info64();
            if caller.copy_out(argument, &info) {
                Ok(0)
            } else {
                Err(Error::Fault)
            }
        }
        LOOP_SET_CAPACITY | LOOP_SET_DIRECT_IO | LOOP_SET_BLOCK_SIZE if !may_change => {
            Err(Error::Permission)
        }
        LOOP_SET_CAPACITY | LOOP_SET_DIRECT_IO | LOOP_SET_BLOCK_SIZE => {
            simple(id, request, argument)
        }
        _ => Err(Error::Invalid),
    }
}

/// An ioctl on `/dev/loop-control`: adds a device, removes an unused one,
/// or finds (adding if need be) an unbound one. Returns its number.
pub(crate) fn control(request: u32, argument: u64) -> Result<u64, Error> {
    let mut loops = LOOPS.lock();
    let devices = loops.domain(current_domain());
    // The device number is an int.
    let index = argument as u32 as i32;
    match request {
        LOOP_CTL_ADD => {
            let minor = match u32::try_from(index) {
                Ok(minor) => minor,
                Err(_) => free_minor(devices)?,
            };
            if u64::from(minor) >= MINOR_LIMIT {
                return Err(Error::Invalid);
            }
            if !devices.add(minor) {
                return Err(Error::Exists);
            }
            Ok(u64::from(minor))
        }
        LOOP_CTL_REMOVE => {
            let minor = u32::try_from(index).map_err(|_| Error::Invalid)?;
            let device = devices.device(minor).ok_or(Error::NoSuchDevice)?;
            if device.state != State::Unbound || device.openers > 0 {
                return Err(Error::Busy);
            }
            devices.devices[minor as usize] = None;
            devices.removed.push(minor);
            Ok(0)
        }
        LOOP_CTL_GET_FREE => {
            let unbound = devices.devices.iter().position(|device| {
                device
                    .as_ref()
                    .is_some_and(|device| device.state == State::Unbound)
            });
            let minor = match unbound {
                Some(minor) => minor as u32,
                None => {
                    let minor = free_minor(devices)?;
                    devices.add(minor);
                    minor
                }
            };
            Ok(u64::from(minor))
        }
        _ => Err(Error::NotImplemented),
    }
}

/// The lowest number no device has.
fn free_minor(devices: &Domain) -> Result<u32, Error> {
    let minor = devices
        .devices
        .iter()
        .position(Option::is_none)
        .unwrap_or(devices.devices.len());
    u32::try_from(minor)
        .ok()
        .filter(|minor| u64::from(*minor) < MINOR_LIMIT)
        .ok_or(Error::NoSpace)
}

/// What a device's sysfs attributes show.
struct Attributes {
    minor: u32,
    sectors: u64,
    read_only: bool,
    block_size: u32,
    /// The `loop` attributes of a bound device: backing file, offset, size
    /// limit and flags.
    bound: Option<(Vec<u8>, u64, u64, u32)>,
}

/// The backing file's path as Linux shows it: absolute, and marked if the
/// file was deleted.
fn backing_path(handle: Handle) -> Vec<u8> {
    let mut path = [0_u8; linux_overlay::PATH_CAPACITY];
    let length = linux_overlay::copy_path(handle, &mut path).unwrap_or(0);
    let mut shown = Vec::new();
    shown.push(b'/');
    shown.extend_from_slice(&path[..length]);
    if !linux_overlay::linked(handle) {
        shown.extend_from_slice(b" (deleted)");
    }
    shown
}

/// Makes `/dev/loop-control`, each device's `/dev/loopN` and its sysfs
/// directory (`/sys/block/loopN`, linked from `/sys/dev/block/7:N`), and
/// rewrites the attributes of devices that changed, in the calling domain's
/// overlay.
pub(crate) fn ensure_nodes() {
    if MAKING_NODES.swap(true, Ordering::Acquire) {
        return;
    }
    let fresh = linux_overlay::lookup(CONTROL_PATH).is_none();
    let (changed, removed) = {
        let mut loops = LOOPS.lock();
        let devices = loops.domain(current_domain());
        let removed = core::mem::take(&mut devices.removed);
        let mut changed = Vec::new();
        for (minor, device) in devices.devices.iter_mut().enumerate() {
            let Some(device) = device.as_mut().filter(|device| fresh || device.stale) else {
                continue;
            };
            device.stale = false;
            let bound = device
                .backing
                .filter(|_| device.state != State::Unbound)
                .map(|backing| {
                    (
                        backing_path(backing),
                        device.offset,
                        device.size_limit,
                        device.flags,
                    )
                });
            changed.push(Attributes {
                minor: minor as u32,
                sectors: device.sectors,
                read_only: device.read_only(),
                block_size: device.block_size,
                bound,
            });
        }
        (changed, removed)
    };
    if fresh || !changed.is_empty() || !removed.is_empty() {
        make_nodes(fresh, &changed, &removed);
    }
    MAKING_NODES.store(false, Ordering::Release);
}

fn root_owned(handle: Option<Handle>, group: u32) {
    if let Some(handle) = handle {
        let _ = linux_overlay::set_owner(handle, 0, group);
    }
}

fn make_directory(path: &[u8]) {
    if linux_overlay::lookup(path).is_none() && crate::published_rootfs::exact_entry(path).is_none()
    {
        root_owned(linux_overlay::create_directory(path, 0o755), 0);
    }
}

/// Writes a sysfs attribute's contents, making it if need be.
fn put_attribute(path: &[u8], contents: &[u8]) {
    match linux_overlay::lookup(path) {
        Some(metadata) => {
            if linux_overlay::truncate(metadata.handle, 0) {
                let _ = linux_overlay::write(metadata.handle, 0, contents);
            }
        }
        None => root_owned(linux_overlay::create_file(path, 0o444, contents), 0),
    }
}

fn remove_tree(path: &[u8]) {
    if linux_overlay::lookup(path).is_some() {
        linux_overlay::unlink_below(path);
        let _ = linux_overlay::unlink_path(path);
    }
}

fn make_nodes(fresh: bool, changed: &[Attributes], removed: &[u32]) {
    for directory in [&b"sys"[..], b"sys/block", b"sys/dev", b"sys/dev/block"] {
        make_directory(directory);
    }
    if fresh && linux_overlay::lookup(CONTROL_PATH).is_none() {
        root_owned(
            linux_overlay::create_device(
                CONTROL_PATH,
                NodeKind::CharacterDevice,
                0o660,
                cpu::linux_device_number(CONTROL_MAJOR, CONTROL_MINOR),
            ),
            DISK_GROUP,
        );
    }
    for &minor in removed {
        let _ = linux_overlay::unlink_path(format!("dev/loop{minor}").as_bytes());
        let _ = linux_overlay::unlink_path(format!("sys/dev/block/{MAJOR}:{minor}").as_bytes());
        remove_tree(format!("sys/block/loop{minor}").as_bytes());
    }
    for attributes in changed {
        make_device(attributes);
    }
}

fn make_device(attributes: &Attributes) {
    let minor = attributes.minor;
    let node = format!("dev/loop{minor}");
    if linux_overlay::lookup(node.as_bytes()).is_none() {
        root_owned(
            linux_overlay::create_device(
                node.as_bytes(),
                NodeKind::BlockDevice,
                0o660,
                cpu::linux_device_number(MAJOR, minor),
            ),
            DISK_GROUP,
        );
    }
    let directory = format!("sys/block/loop{minor}");
    make_directory(directory.as_bytes());
    make_directory(format!("{directory}/queue").as_bytes());
    let link = format!("sys/dev/block/{MAJOR}:{minor}");
    if linux_overlay::lookup(link.as_bytes()).is_none() {
        let target = format!("../../block/loop{minor}");
        let _ = linux_overlay::create_symlink(link.as_bytes(), target.as_bytes());
    }
    let block_size = format!("{}\n", attributes.block_size);
    for (name, contents) in [
        ("dev", format!("{MAJOR}:{minor}\n")),
        (
            "uevent",
            format!("MAJOR={MAJOR}\nMINOR={minor}\nDEVNAME=loop{minor}\nDEVTYPE=disk\n"),
        ),
        ("size", format!("{}\n", attributes.sectors)),
        ("ro", format!("{}\n", u8::from(attributes.read_only))),
        ("removable", "0\n".into()),
        ("queue/logical_block_size", block_size.clone()),
        ("queue/physical_block_size", block_size),
    ] {
        put_attribute(
            format!("{directory}/{name}").as_bytes(),
            contents.as_bytes(),
        );
    }
    let settings = format!("{directory}/loop");
    let Some((backing, offset, size_limit, flags)) = &attributes.bound else {
        remove_tree(settings.as_bytes());
        return;
    };
    make_directory(settings.as_bytes());
    let mut backing = backing.clone();
    backing.push(b'\n');
    put_attribute(format!("{settings}/backing_file").as_bytes(), &backing);
    let flag = |bit: u32| format!("{}\n", u8::from(flags & bit != 0));
    for (name, contents) in [
        ("offset", format!("{offset}\n")),
        ("sizelimit", format!("{size_limit}\n")),
        ("autoclear", flag(FLAG_AUTOCLEAR)),
        ("partscan", flag(FLAG_PARTSCAN)),
        ("dio", flag(FLAG_DIRECT_IO)),
    ] {
        put_attribute(format!("{settings}/{name}").as_bytes(), contents.as_bytes());
    }
}
