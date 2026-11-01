#![forbid(unsafe_code)]
//! The DRM render node of a virtio-gpu, as Linux's `virtio_gpu` driver
//! offers it (`include/uapi/drm/drm.h` and `virtgpu_drm.h`) to libdrm and
//! Mesa's Venus Vulkan driver.
//!
//! A [`File`] is one open file description of the render node. It decodes
//! the ioctls and keeps what Linux keeps per open file: the 3D context
//! (made once by `DRM_IOCTL_VIRTGPU_CONTEXT_INIT` with a capset and a ring
//! count), the GEM handles naming the context's blob resources, and the
//! fake `mmap` offsets that map them. The device is behind [`Gpu`]: the
//! kernel turns its calls into virtio-gpu commands. User memory, which the
//! ioctls point into, is behind [`UserMemory`]. What only the kernel can
//! finish (making a fence or dma-buf descriptor) comes back as an
//! [`Outcome`].
//!
//! Implemented: host-memory blobs (`VIRTGPU_BLOB_MEM_HOST3D`, all that
//! Venus allocates) mapped from the device's host-visible region, command
//! submission on a context's rings with an out-fence descriptor, PRIME
//! export and import of blobs. Not yet: guest-memory blobs, classic virgl
//! 3D resources and transfers, and DRM sync objects (Venus simulates
//! these with fence descriptors).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// DRM's character device major number.
pub const MAJOR: u32 = 226;
/// The minor number of the first render node, `/dev/dri/renderD128`.
pub const RENDER_MINOR: u32 = 128;
/// The name `DRM_IOCTL_VERSION` reports, which Venus checks.
pub const DRIVER_NAME: &[u8] = b"virtio_gpu";

const PAGE_SIZE: u64 = 4096;
/// Fake mmap offsets start here, past any real file offset, as in Linux
/// (`DRM_FILE_PAGE_OFFSET_START`); a handle's object is at `handle << 32`.
const OFFSET_SHIFT: u32 = 32;

/// The errno values an ioctl fails with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Errno {
    Inval,
    Fault,
    NoEnt,
    NoMem,
    NoSys,
    Exist,
    Busy,
    Again,
    Io,
    NoTty,
    Perm,
}

impl Errno {
    /// The Linux errno.
    pub const fn number(self) -> i32 {
        match self {
            Self::Perm => 1,
            Self::NoEnt => 2,
            Self::Io => 5,
            Self::Again => 11,
            Self::NoMem => 12,
            Self::Fault => 14,
            Self::Busy => 16,
            Self::Exist => 17,
            Self::Inval => 22,
            Self::NoTty => 25,
            Self::NoSys => 38,
        }
    }
}

/// The calling process's memory, which ioctl structures point into.
pub trait UserMemory {
    /// Copies `output.len()` bytes from `address`; false on a fault.
    fn read(&self, address: u64, output: &mut [u8]) -> bool;
    /// Copies `input` to `address`; false on a fault.
    fn write(&mut self, address: u64, input: &[u8]) -> bool;
}

/// What the device offers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Features {
    /// 3D contexts (`VIRTIO_GPU_F_VIRGL`).
    pub three_d: bool,
    /// Blob resources (`VIRTIO_GPU_F_RESOURCE_BLOB`).
    pub blob: bool,
    /// A host-visible shared memory region to map host blobs from.
    pub host_visible: bool,
    /// Contexts created with a capset (`VIRTIO_GPU_F_CONTEXT_INIT`).
    pub context_init: bool,
    /// The capset ids the device has, one bit each.
    pub capsets: u64,
}

/// How a mapping of device memory may be cached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cache {
    Cached,
    Uncached,
    WriteCombined,
}

/// Where a mapped blob is: its physical address and caching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapping {
    pub physical: u64,
    pub cache: Cache,
}

/// A blob to create: memory kind, flags, the host's id for it and its size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blob {
    pub context: u32,
    pub memory: u32,
    pub flags: u32,
    pub id: u64,
    pub size: u64,
}

/// The device. Resources are reference counted by the implementation: a
/// new blob has one reference, held by its GEM handle.
pub trait Gpu {
    fn features(&self) -> Features;
    /// Copies capset `id` at `version` into `output`; returns its length.
    fn capset(&mut self, id: u32, version: u32, output: &mut [u8]) -> Result<usize, Errno>;
    /// Creates a 3D context of `capset`; returns its id.
    fn create_context(&mut self, capset: u32) -> Result<u32, Errno>;
    fn destroy_context(&mut self, context: u32);
    /// Creates a blob, attached to its context; returns the resource id.
    fn create_blob(&mut self, blob: Blob) -> Result<u32, Errno>;
    /// Maps blob `resource` of `size` bytes into the host-visible region.
    fn map(&mut self, resource: u32, size: u64) -> Result<Mapping, Errno>;
    /// Runs `commands` on `context`'s `ring`; with `fenced`, returns the
    /// fence that signals once they are done.
    fn submit(
        &mut self,
        context: u32,
        ring: Option<u8>,
        commands: &[u8],
        fenced: bool,
    ) -> Result<Option<u64>, Errno>;
    /// Waits until the work submitted so far that uses `resource` is done,
    /// or fails with EBUSY at once if `nowait` and it is not.
    fn wait(&mut self, resource: u32, nowait: bool) -> Result<(), Errno>;
    fn retain(&mut self, resource: u32);
    /// Drops a reference; the last unmaps and destroys the resource.
    fn release(&mut self, resource: u32);
}

/// What the kernel must finish after [`File::ioctl`] returns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Done,
    /// `EXECBUFFER` asked for an out-fence: make a fence descriptor for
    /// `fence`, store it as a little-endian `i32` at `argument[offset..]`
    /// and copy the argument back.
    FenceDescriptor {
        fence: u64,
        offset: usize,
    },
    /// `PRIME_HANDLE_TO_FD`: make a dma-buf descriptor for `resource` of
    /// `size` bytes (taking a reference with [`Gpu::retain`]) with
    /// `flags` (O_CLOEXEC, O_RDWR), store it at `argument[offset..]`.
    Export {
        resource: u32,
        size: u64,
        flags: u32,
        offset: usize,
    },
    /// `PRIME_FD_TO_HANDLE`: find the dma-buf descriptor `descriptor` and
    /// finish with [`File::import`].
    Import {
        descriptor: i32,
    },
}

/// The ioctls this crate knows, by their DRM number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    Version,
    GetCap,
    SetClientCap,
    GemClose,
    PrimeHandleToFd,
    PrimeFdToHandle,
    Map,
    Execbuffer,
    GetParam,
    ResourceInfo,
    Wait,
    GetCaps,
    ResourceCreateBlob,
    ContextInit,
}

impl Request {
    /// Decodes an ioctl request word: DRM's type `'d'` and its number.
    /// The size it encodes is the caller's, which Linux accepts when it
    /// differs from the kernel's (copying the smaller and zero-filling).
    pub fn decode(command: u32) -> Result<(Self, usize), Errno> {
        if (command >> 8) & 0xff != u32::from(b'd') {
            return Err(Errno::NoTty);
        }
        let size = ((command >> 16) & 0x3fff) as usize;
        let request = match command & 0xff {
            0x00 => Self::Version,
            0x09 => Self::GemClose,
            0x0c => Self::GetCap,
            0x0d => Self::SetClientCap,
            0x2d => Self::PrimeHandleToFd,
            0x2e => Self::PrimeFdToHandle,
            0x41 => Self::Map,
            0x42 => Self::Execbuffer,
            0x43 => Self::GetParam,
            0x45 => Self::ResourceInfo,
            0x48 => Self::Wait,
            0x49 => Self::GetCaps,
            0x4a => Self::ResourceCreateBlob,
            0x4b => Self::ContextInit,
            _ => return Err(Errno::Inval),
        };
        Ok((request, size))
    }

    /// The size of the kernel's structure for the request.
    pub const fn size(self) -> usize {
        match self {
            Self::Version | Self::Execbuffer => 64,
            Self::GetCap
            | Self::SetClientCap
            | Self::Map
            | Self::GetParam
            | Self::ResourceInfo
            | Self::ContextInit => 16,
            Self::GemClose | Self::Wait => 8,
            Self::PrimeHandleToFd | Self::PrimeFdToHandle => 12,
            Self::GetCaps => 24,
            Self::ResourceCreateBlob => 48,
        }
    }
}

const PARAM_3D_FEATURES: u64 = 1;
const PARAM_CAPSET_QUERY_FIX: u64 = 2;
const PARAM_RESOURCE_BLOB: u64 = 3;
const PARAM_HOST_VISIBLE: u64 = 4;
const PARAM_CROSS_DEVICE: u64 = 5;
const PARAM_CONTEXT_INIT: u64 = 6;
const PARAM_SUPPORTED_CAPSET_IDS: u64 = 7;
const PARAM_EXPLICIT_DEBUG_NAME: u64 = 8;

const CONTEXT_PARAM_CAPSET_ID: u64 = 1;
const CONTEXT_PARAM_NUM_RINGS: u64 = 2;
const CONTEXT_PARAM_POLL_RINGS_MASK: u64 = 3;
const CONTEXT_PARAM_DEBUG_NAME: u64 = 4;
/// The most rings a context may have (Linux's limit).
const MAX_RINGS: u64 = 64;

const EXECBUF_FENCE_FD_IN: u32 = 1;
const EXECBUF_FENCE_FD_OUT: u32 = 2;
const EXECBUF_RING_IDX: u32 = 4;
/// The largest command stream one EXECBUFFER may carry.
pub const MAX_COMMAND_BYTES: usize = 1 << 20;

const BLOB_MEM_GUEST: u32 = 1;
const BLOB_MEM_HOST3D: u32 = 2;
const BLOB_MEM_HOST3D_GUEST: u32 = 3;
const BLOB_FLAGS: u32 = 1 | 2 | 4;

const CAP_TIMESTAMP_MONOTONIC: u64 = 6;
const CAP_PRIME: u64 = 5;
const PRIME_CAP_IMPORT: u64 = 1;
const PRIME_CAP_EXPORT: u64 = 2;

const WAIT_NOWAIT: u32 = 1;

/// O_CLOEXEC and O_RDWR, the flags PRIME_HANDLE_TO_FD accepts.
const PRIME_FLAGS: u32 = 0o2_000_000 | 2;

#[derive(Clone, Copy, Debug)]
struct Context {
    id: u32,
    rings: u32,
}

#[derive(Clone, Copy, Debug)]
struct Object {
    resource: u32,
    size: u64,
    memory: u32,
    mapping: Option<Mapping>,
}

/// One open file description of the render node.
#[derive(Debug, Default)]
pub struct File {
    context: Option<Context>,
    /// Handle `n` is `objects[n - 1]`; closed handles are `None` and reused.
    objects: Vec<Option<Object>>,
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(word)
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(word)
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

impl File {
    pub const fn new() -> Self {
        Self {
            context: None,
            objects: Vec::new(),
        }
    }

    /// Runs `request` on `argument`, the caller's structure copied in (and
    /// zero-extended to [`Request::size`]); the kernel copies it back for
    /// requests that return data.
    pub fn ioctl(
        &mut self,
        gpu: &mut impl Gpu,
        user: &mut impl UserMemory,
        request: Request,
        argument: &mut [u8],
    ) -> Result<Outcome, Errno> {
        if argument.len() < request.size() {
            return Err(Errno::Inval);
        }
        match request {
            Request::Version => version(user, argument).map(|()| Outcome::Done),
            Request::GetCap => {
                let value = match get_u64(argument, 0) {
                    CAP_PRIME => PRIME_CAP_IMPORT | PRIME_CAP_EXPORT,
                    CAP_TIMESTAMP_MONOTONIC => 1,
                    _ => return Err(Errno::Inval),
                };
                put_u64(argument, 8, value);
                Ok(Outcome::Done)
            }
            // A render node has no client capabilities to set.
            Request::SetClientCap => Err(Errno::Inval),
            Request::GemClose => {
                let object = self.take(get_u32(argument, 0))?;
                gpu.release(object.resource);
                Ok(Outcome::Done)
            }
            Request::PrimeHandleToFd => {
                let flags = get_u32(argument, 4);
                if flags & !PRIME_FLAGS != 0 {
                    return Err(Errno::Inval);
                }
                let object = self.object(get_u32(argument, 0))?;
                Ok(Outcome::Export {
                    resource: object.resource,
                    size: object.size,
                    flags,
                    offset: 8,
                })
            }
            Request::PrimeFdToHandle => Ok(Outcome::Import {
                descriptor: get_u32(argument, 8) as i32,
            }),
            Request::Map => {
                let handle = get_u32(argument, 8);
                let offset = self.map(gpu, handle)?;
                put_u64(argument, 0, offset);
                Ok(Outcome::Done)
            }
            Request::Execbuffer => self.execbuffer(gpu, user, argument),
            Request::GetParam => {
                let features = gpu.features();
                let value = match get_u64(argument, 0) {
                    PARAM_3D_FEATURES => u64::from(features.three_d),
                    PARAM_CAPSET_QUERY_FIX => 1,
                    PARAM_RESOURCE_BLOB => u64::from(features.blob),
                    PARAM_HOST_VISIBLE => u64::from(features.host_visible),
                    PARAM_CROSS_DEVICE | PARAM_EXPLICIT_DEBUG_NAME => 0,
                    PARAM_CONTEXT_INIT => u64::from(features.context_init),
                    PARAM_SUPPORTED_CAPSET_IDS => features.capsets,
                    _ => return Err(Errno::Inval),
                };
                // Linux writes an int to the address in `value`.
                if !user.write(get_u64(argument, 8), &(value as u32).to_le_bytes()) {
                    return Err(Errno::Fault);
                }
                Ok(Outcome::Done)
            }
            Request::ResourceInfo => {
                let object = self.object(get_u32(argument, 0))?;
                put_u32(argument, 4, object.resource);
                put_u32(argument, 8, object.size.min(u64::from(u32::MAX)) as u32);
                put_u32(argument, 12, object.memory);
                Ok(Outcome::Done)
            }
            Request::Wait => {
                let object = self.object(get_u32(argument, 0))?;
                gpu.wait(object.resource, get_u32(argument, 4) & WAIT_NOWAIT != 0)?;
                Ok(Outcome::Done)
            }
            Request::GetCaps => {
                if !gpu.features().three_d {
                    return Err(Errno::NoSys);
                }
                let (id, version) = (get_u32(argument, 0), get_u32(argument, 4));
                let size = get_u32(argument, 16) as usize;
                let mut data = Vec::new();
                data.try_reserve_exact(size).map_err(|_| Errno::NoMem)?;
                data.resize(size, 0);
                let length = gpu.capset(id, version, &mut data)?;
                if !user.write(get_u64(argument, 8), &data[..length.min(size)]) {
                    return Err(Errno::Fault);
                }
                Ok(Outcome::Done)
            }
            Request::ResourceCreateBlob => self.create_blob(gpu, user, argument),
            Request::ContextInit => self.context_init(gpu, user, argument),
        }
    }

    /// Finishes `PRIME_FD_TO_HANDLE` for the dma-buf of `resource` (of
    /// `size` bytes, `memory` kind): a handle naming it in this file, the
    /// existing one if there is one. Takes a reference for a new handle.
    pub fn import(
        &mut self,
        gpu: &mut impl Gpu,
        resource: u32,
        size: u64,
        memory: u32,
        argument: &mut [u8],
    ) -> Result<(), Errno> {
        let existing = self
            .objects
            .iter()
            .position(|object| object.is_some_and(|object| object.resource == resource));
        let handle = match existing {
            Some(index) => index as u32 + 1,
            None => {
                gpu.retain(resource);
                self.insert(Object {
                    resource,
                    size,
                    memory,
                    mapping: None,
                })
                .inspect_err(|_| gpu.release(resource))?
            }
        };
        put_u32(argument, 4, handle);
        Ok(())
    }

    /// The mapping of the object at fake offset `offset`, for an mmap of
    /// `length` bytes: it must start at the object and fit in it, and the
    /// object must have been mapped (`DRM_IOCTL_VIRTGPU_MAP`).
    pub fn mmap(&self, offset: u64, length: u64) -> Result<Mapping, Errno> {
        if offset & ((1 << OFFSET_SHIFT) - 1) != 0 {
            return Err(Errno::Inval);
        }
        let object = self.object((offset >> OFFSET_SHIFT) as u32)?;
        let mapping = object.mapping.ok_or(Errno::Inval)?;
        if length == 0 || length > object.size.next_multiple_of(PAGE_SIZE) {
            return Err(Errno::Inval);
        }
        Ok(mapping)
    }

    /// Releases everything the file holds, when it is closed.
    pub fn close(&mut self, gpu: &mut impl Gpu) {
        for object in self.objects.drain(..).flatten() {
            gpu.release(object.resource);
        }
        if let Some(context) = self.context.take() {
            gpu.destroy_context(context.id);
        }
    }

    fn object(&self, handle: u32) -> Result<Object, Errno> {
        handle
            .checked_sub(1)
            .and_then(|index| self.objects.get(index as usize).copied().flatten())
            .ok_or(Errno::NoEnt)
    }

    fn take(&mut self, handle: u32) -> Result<Object, Errno> {
        handle
            .checked_sub(1)
            .and_then(|index| self.objects.get_mut(index as usize))
            .and_then(Option::take)
            .ok_or(Errno::NoEnt)
    }

    fn insert(&mut self, object: Object) -> Result<u32, Errno> {
        let index = match self.objects.iter().position(Option::is_none) {
            Some(index) => {
                self.objects[index] = Some(object);
                index
            }
            None => {
                self.objects.try_reserve(1).map_err(|_| Errno::NoMem)?;
                self.objects.push(Some(object));
                self.objects.len() - 1
            }
        };
        u32::try_from(index + 1).map_err(|_| Errno::NoMem)
    }

    fn map(&mut self, gpu: &mut impl Gpu, handle: u32) -> Result<u64, Errno> {
        let index = handle.checked_sub(1).ok_or(Errno::NoEnt)? as usize;
        let object = self
            .objects
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Errno::NoEnt)?;
        if object.mapping.is_none() {
            object.mapping = Some(gpu.map(object.resource, object.size)?);
        }
        Ok(u64::from(handle) << OFFSET_SHIFT)
    }

    fn context_init(
        &mut self,
        gpu: &mut impl Gpu,
        user: &mut impl UserMemory,
        argument: &[u8],
    ) -> Result<Outcome, Errno> {
        let features = gpu.features();
        if !features.context_init {
            return Err(Errno::Inval);
        }
        if self.context.is_some() {
            return Err(Errno::Exist);
        }
        let count = get_u32(argument, 0);
        let address = get_u64(argument, 8);
        if count == 0 || count > 4 {
            return Err(Errno::Inval);
        }
        let mut capset = None;
        let mut rings = None;
        let mut seen = 0_u32;
        for index in 0..u64::from(count) {
            let mut parameter = [0_u8; 16];
            let at = address.checked_add(index * 16).ok_or(Errno::Fault)?;
            if !user.read(at, &mut parameter) {
                return Err(Errno::Fault);
            }
            let (name, value) = (get_u64(&parameter, 0), get_u64(&parameter, 8));
            let bit = 1_u32 << name.min(31);
            if seen & bit != 0 {
                return Err(Errno::Inval);
            }
            seen |= bit;
            match name {
                CONTEXT_PARAM_CAPSET_ID => {
                    if value >= 64 || features.capsets & (1 << value) == 0 {
                        return Err(Errno::Inval);
                    }
                    capset = Some(value as u32);
                }
                CONTEXT_PARAM_NUM_RINGS => {
                    if value > MAX_RINGS {
                        return Err(Errno::Inval);
                    }
                    rings = Some(value as u32);
                }
                // No ring raises DRM events (Venus asks for none).
                CONTEXT_PARAM_POLL_RINGS_MASK => {
                    if value != 0 {
                        return Err(Errno::Inval);
                    }
                }
                CONTEXT_PARAM_DEBUG_NAME => {}
                _ => return Err(Errno::Inval),
            }
        }
        let capset = capset.ok_or(Errno::Inval)?;
        let id = gpu.create_context(capset)?;
        self.context = Some(Context {
            id,
            rings: rings.unwrap_or(0),
        });
        Ok(Outcome::Done)
    }

    fn create_blob(
        &mut self,
        gpu: &mut impl Gpu,
        user: &mut impl UserMemory,
        argument: &mut [u8],
    ) -> Result<Outcome, Errno> {
        let features = gpu.features();
        if !features.blob {
            return Err(Errno::Inval);
        }
        let memory = get_u32(argument, 0);
        let flags = get_u32(argument, 4);
        let size = get_u64(argument, 16);
        let command_size = get_u32(argument, 28) as usize;
        let command = get_u64(argument, 32);
        let id = get_u64(argument, 40);
        if flags & !BLOB_FLAGS != 0 || size == 0 {
            return Err(Errno::Inval);
        }
        match memory {
            BLOB_MEM_HOST3D if features.host_visible || flags & 1 == 0 => {}
            // Guest-memory blobs (and host blobs with guest backing) need
            // guest pages the device can reach; not yet.
            BLOB_MEM_GUEST | BLOB_MEM_HOST3D_GUEST => return Err(Errno::Inval),
            _ => return Err(Errno::Inval),
        }
        let context = self.context.ok_or(Errno::Inval)?;
        // Commands that make the host object the blob exports run first.
        if command_size != 0 {
            let commands = read_commands(user, command, command_size)?;
            gpu.submit(context.id, None, &commands, false)?;
        }
        let size = size.next_multiple_of(PAGE_SIZE);
        let resource = gpu.create_blob(Blob {
            context: context.id,
            memory,
            flags,
            id,
            size,
        })?;
        let handle = self
            .insert(Object {
                resource,
                size,
                memory,
                mapping: None,
            })
            .inspect_err(|_| gpu.release(resource))?;
        put_u32(argument, 8, handle);
        put_u32(argument, 12, resource);
        Ok(Outcome::Done)
    }

    fn execbuffer(
        &mut self,
        gpu: &mut impl Gpu,
        user: &mut impl UserMemory,
        argument: &mut [u8],
    ) -> Result<Outcome, Errno> {
        let flags = get_u32(argument, 0);
        let size = get_u32(argument, 4) as usize;
        let command = get_u64(argument, 8);
        let handles = get_u64(argument, 16);
        let handle_count = get_u32(argument, 24) as usize;
        let ring = get_u32(argument, 32);
        let (in_syncobjs, out_syncobjs) = (get_u32(argument, 40), get_u32(argument, 44));
        if flags & !(EXECBUF_FENCE_FD_IN | EXECBUF_FENCE_FD_OUT | EXECBUF_RING_IDX) != 0
            || in_syncobjs != 0
            || out_syncobjs != 0
        {
            return Err(Errno::Inval);
        }
        let context = self.context.ok_or(Errno::Inval)?;
        let ring = if flags & EXECBUF_RING_IDX != 0 {
            if ring >= context.rings {
                return Err(Errno::Inval);
            }
            Some(ring as u8)
        } else {
            None
        };
        // Every handle the submission names must exist.
        for index in 0..handle_count {
            let mut handle = [0_u8; 4];
            let at = handles.checked_add(index as u64 * 4).ok_or(Errno::Fault)?;
            if !user.read(at, &mut handle) {
                return Err(Errno::Fault);
            }
            self.object(u32::from_le_bytes(handle))?;
        }
        let commands = read_commands(user, command, size)?;
        let fenced = flags & EXECBUF_FENCE_FD_OUT != 0;
        let fence = gpu.submit(context.id, ring, &commands, fenced)?;
        match fence {
            Some(fence) if fenced => Ok(Outcome::FenceDescriptor { fence, offset: 28 }),
            _ => Ok(Outcome::Done),
        }
    }
}

/// The input fence descriptor an EXECBUFFER waits on first, if it names
/// one (`VIRTGPU_EXECBUF_FENCE_FD_IN`); the kernel waits before
/// [`File::ioctl`].
pub fn execbuffer_in_fence(argument: &[u8]) -> Option<i32> {
    (argument.len() >= 32 && get_u32(argument, 0) & EXECBUF_FENCE_FD_IN != 0)
        .then(|| get_u32(argument, 28) as i32)
}

fn read_commands(user: &impl UserMemory, address: u64, size: usize) -> Result<Vec<u8>, Errno> {
    if size > MAX_COMMAND_BYTES {
        return Err(Errno::Inval);
    }
    let mut commands = Vec::new();
    commands.try_reserve_exact(size).map_err(|_| Errno::NoMem)?;
    commands.resize(size, 0);
    if size != 0 && !user.read(address, &mut commands) {
        return Err(Errno::Fault);
    }
    Ok(commands)
}

/// `DRM_IOCTL_VERSION`: copies the name, date and description into the
/// caller's buffers, as much as fits, and reports their full lengths.
fn version(user: &mut impl UserMemory, argument: &mut [u8]) -> Result<(), Errno> {
    put_u32(argument, 0, 0);
    put_u32(argument, 4, 1);
    put_u32(argument, 8, 0);
    for (offset, text) in [(16, DRIVER_NAME), (32, &b"0"[..]), (48, &b"virtio GPU"[..])] {
        let capacity = get_u64(argument, offset) as usize;
        let address = get_u64(argument, offset + 8);
        let copied = capacity.min(text.len());
        if address != 0 && copied != 0 && !user.write(address, &text[..copied]) {
            return Err(Errno::Fault);
        }
        put_u64(argument, offset, text.len() as u64);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
