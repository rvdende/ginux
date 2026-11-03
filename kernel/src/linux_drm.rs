//! The DRM render node `/dev/dri/renderD128` of a virtio-gpu with 3D
//! (Venus) support, as Linux's `virtio_gpu` driver offers it.
//!
//! `ginux_drm` holds what an open render node keeps and decodes the
//! ioctls; `drivers::virtio_gpu` runs the device. This module keeps the
//! open files and the dma-bufs exported from them, which descriptors share
//! as object slots of the socket table (so `dup`, `fork`, SCM_RIGHTS and
//! `close` treat them as Linux treats any open file), and releases them
//! once their last descriptor closes. It also makes the device node and
//! the sysfs attributes libdrm finds the device by.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use ginux_drm::{File, Gpu};

use crate::drivers::virtio_gpu::{self, VirtioGpu};
use crate::sync::{LockRank, SpinLock};

/// Object classes in the socket table.
pub(crate) const CLASS_FILE: u8 = 1;
pub(crate) const CLASS_FENCE: u8 = 2;
pub(crate) const CLASS_DMABUF: u8 = 3;

/// The render node's path and device number (226:128).
pub(crate) const NODE_PATH: &[u8] = b"dev/dri/renderD128";
pub(crate) const NODE_DEVICE: u32 = (ginux_drm::MAJOR << 8) | ginux_drm::RENDER_MINOR;
const SYSFS_DEVICE: &[u8] = b"sys/dev/char/226:128/device";

/// A dma-buf exported from a render node: its resource, size and memory.
#[derive(Clone, Copy)]
pub(crate) struct DmaBuf {
    pub(crate) resource: u32,
    pub(crate) size: u64,
    pub(crate) memory: u32,
}

struct Drm {
    /// Open render node files, by object id; `None` marks a free id or a
    /// file taken out while one of its ioctls runs.
    files: Vec<Option<File>>,
    dmabufs: Vec<Option<DmaBuf>>,
}

static DRM: SpinLock<Drm> = SpinLock::new(
    LockRank::DRM,
    Drm {
        files: Vec::new(),
        dmabufs: Vec::new(),
    },
);

fn insert<T>(table: &mut Vec<Option<T>>, value: T) -> Option<u64> {
    let index = match table.iter().position(Option::is_none) {
        Some(index) => {
            table[index] = Some(value);
            index
        }
        None => {
            table.try_reserve(1).ok()?;
            table.push(Some(value));
            table.len() - 1
        }
    };
    Some(index as u64)
}

/// Whether the render node exists: the GPU offers Venus contexts.
pub(crate) fn available() -> bool {
    virtio_gpu::has_three_d()
}

/// Opens a render node file; returns its object slot.
pub(crate) fn open() -> Option<crate::linux_socket::SlotId> {
    crate::arch::x86_64::cpu::linux_release_objects();
    let id = insert(&mut DRM.lock().files, File::new())?;
    match crate::linux_socket::open_object(CLASS_FILE, id) {
        Ok(slot) => Some(slot),
        Err(_) => {
            DRM.lock().files[id as usize] = None;
            None
        }
    }
}

/// Runs `operation` on open file `id`, taken out of the table meanwhile
/// (system calls run one at a time, and the device may be slow).
pub(crate) fn with_file<R>(id: u64, operation: impl FnOnce(&mut File) -> R) -> Option<R> {
    let mut file = DRM.lock().files.get_mut(id as usize)?.take()?;
    let result = operation(&mut file);
    if let Some(slot) = DRM.lock().files.get_mut(id as usize) {
        *slot = Some(file);
    }
    Some(result)
}

/// Records an exported dma-buf; returns its object id.
pub(crate) fn export(dmabuf: DmaBuf) -> Option<u64> {
    insert(&mut DRM.lock().dmabufs, dmabuf)
}

pub(crate) fn dmabuf(id: u64) -> Option<DmaBuf> {
    DRM.lock().dmabufs.get(id as usize).copied().flatten()
}

/// Releases object `class`/`id` after its last descriptor closed: a render
/// node file or a dma-buf. Objects of other classes are not this module's.
pub(crate) fn release(class: u8, id: u64) {
    match class {
        CLASS_FILE => {
            let file = DRM.lock().files.get_mut(id as usize).and_then(Option::take);
            if let Some(mut file) = file {
                file.close(&mut VirtioGpu);
            }
        }
        CLASS_DMABUF => {
            let dmabuf = DRM
                .lock()
                .dmabufs
                .get_mut(id as usize)
                .and_then(Option::take);
            if let Some(dmabuf) = dmabuf {
                VirtioGpu.release(dmabuf.resource);
            }
        }
        _ => {}
    }
}

/// Makes `/dev/dri/renderD128` and the sysfs attributes libdrm reads to
/// find the device (`/sys/dev/char/226:128/device`: its `drm` directory,
/// `subsystem` link and PCI identity), in the domain's overlay, the first
/// time a path under them is walked. Nothing is made without the device.
pub(crate) fn ensure_nodes() {
    if !available() || crate::linux_overlay::lookup(NODE_PATH).is_some() {
        return;
    }
    // Making the files walks their paths, which comes back here.
    if MAKING_NODES.swap(true, Ordering::Acquire) {
        return;
    }
    make_nodes();
    MAKING_NODES.store(false, Ordering::Release);
}

/// Logs the first [`FAILURE_LOG_LIMIT`] DRM ioctls that fail, by command
/// and errno, so a stalled Vulkan driver shows what the kernel refused.
pub(crate) fn log_failure(command: u32, errno: u64) {
    if FAILURES_LOGGED.fetch_add(1, Ordering::Relaxed) < FAILURE_LOG_LIMIT {
        crate::serial_write("ginux: drm ioctl ");
        crate::serial_write_hex(u64::from(command));
        crate::serial_write(" failed: errno ");
        crate::serial_write_u64(errno);
        crate::serial_write("\r\n");
    }
}

const FAILURE_LOG_LIMIT: u32 = 32;
static FAILURES_LOGGED: AtomicU32 = AtomicU32::new(0);

/// Per ioctl number (the request word's low byte): calls, the calls that
/// found the GPU busy and are issued again, and timestamp-counter cycles
/// spent in the kernel, for a SysRq `l` profile.
static IOCTL_CALLS: [AtomicU32; 256] = [const { AtomicU32::new(0) }; 256];
static IOCTL_RETRIES: [AtomicU32; 256] = [const { AtomicU32::new(0) }; 256];
static IOCTL_CYCLES: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];

pub(crate) fn record_ioctl(command: u32, retried: bool, cycles: u64) {
    let number = (command & 0xff) as usize;
    IOCTL_CALLS[number].fetch_add(1, Ordering::Relaxed);
    if retried {
        IOCTL_RETRIES[number].fetch_add(1, Ordering::Relaxed);
    }
    IOCTL_CYCLES[number].fetch_add(cycles, Ordering::Relaxed);
}

pub(crate) fn reset_ioctl_stats() {
    for number in 0..256 {
        IOCTL_CALLS[number].store(0, Ordering::Relaxed);
        IOCTL_RETRIES[number].store(0, Ordering::Relaxed);
        IOCTL_CYCLES[number].store(0, Ordering::Relaxed);
    }
}

/// Prints `number:calls/retries/microseconds` for each ioctl called.
pub(crate) fn report_ioctl_stats() {
    let hz = crate::arch::x86_64::timer::monotonic_frequency()
        .unwrap_or(1)
        .max(1);
    crate::serial_write("ginux: profile: drm ioctls (number:calls/retries/us):");
    for number in 0..256 {
        let calls = IOCTL_CALLS[number].load(Ordering::Relaxed);
        if calls == 0 {
            continue;
        }
        crate::serial_write(" ");
        crate::serial_write_hex(number as u64);
        crate::serial_write(":");
        crate::serial_write_u64(u64::from(calls));
        crate::serial_write("/");
        crate::serial_write_u64(u64::from(IOCTL_RETRIES[number].load(Ordering::Relaxed)));
        crate::serial_write("/");
        crate::serial_write_u64(IOCTL_CYCLES[number].load(Ordering::Relaxed) * 1_000_000 / hz);
    }
    crate::serial_write("\r\n");
}

/// Set while [`ensure_nodes`] makes the files.
static MAKING_NODES: AtomicBool = AtomicBool::new(false);

fn make_nodes() {
    let (bus, device, function) = virtio_gpu::pci_address();
    let uevent = alloc::format!(
        "DRIVER=virtio-pci\nPCI_CLASS=38000\nPCI_ID=1AF4:1050\nPCI_SUBSYS_ID=1AF4:1100\n\
         PCI_SLOT_NAME=0000:{bus:02x}:{device:02x}.{}\n",
        function & 7
    );
    let uevent = uevent.as_bytes();
    for directory in [
        &b"dev/dri"[..],
        b"sys/dev",
        b"sys/dev/char",
        b"sys/dev/char/226:128",
        SYSFS_DEVICE,
        b"sys/dev/char/226:128/device/drm",
        b"sys/dev/char/226:128/device/drm/renderD128",
    ] {
        if crate::linux_overlay::lookup(directory).is_none()
            && crate::linux_overlay::create_directory(directory, 0o755).is_none()
        {
            return;
        }
    }
    for (name, contents) in [
        (&b"sys/dev/char/226:128/device/uevent"[..], uevent),
        (b"sys/dev/char/226:128/device/vendor", b"0x1af4\n"),
        (b"sys/dev/char/226:128/device/device", b"0x1050\n"),
        (b"sys/dev/char/226:128/device/subsystem_vendor", b"0x1af4\n"),
        (b"sys/dev/char/226:128/device/subsystem_device", b"0x1100\n"),
        (b"sys/dev/char/226:128/device/revision", b"0x01\n"),
        (b"sys/dev/char/226:128/dev", b"226:128\n"),
    ] {
        if crate::linux_overlay::lookup(name).is_none() {
            let _ = crate::linux_overlay::create_file(name, 0o444, contents);
        }
    }
    let subsystem = b"sys/dev/char/226:128/device/subsystem";
    if crate::linux_overlay::lookup(subsystem).is_none() {
        let _ = crate::linux_overlay::create_symlink(subsystem, b"../../../../bus/pci");
    }
    let _ = crate::linux_overlay::create_device(
        NODE_PATH,
        crate::linux_overlay::NodeKind::CharacterDevice,
        0o666,
        NODE_DEVICE,
    );
}
