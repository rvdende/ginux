//! swapon(2) and swapoff(2) for Linux processes (`crate::linux_swap`
//! keeps the areas). The checks and their order are Linux's
//! (mm/swapfile.c): the flags, CAP_SYS_ADMIN, the number of areas, the
//! path, what it is (a block device or a regular file of a volume, not
//! one already on), then the swap header and, for a file, that it has no
//! holes.

use super::*;

use crate::linux_swap::{Target, MAX_SWAPFILES, SWAP_FLAGS_VALID};

/// swapon(path, flags).
pub(super) fn linux_swapon(path_address: u64, flags: u64) -> u64 {
    let flags = flags as u32;
    if flags & !SWAP_FLAGS_VALID != 0 {
        return LINUX_EINVAL;
    }
    if !linux_has_capability(ginux_credentials::capability::SYS_ADMIN) {
        return LINUX_EPERM;
    }
    let instance = linux_execution_instance();
    if crate::linux_swap::count(instance) >= MAX_SWAPFILES {
        return LINUX_EPERM;
    }
    let (target, shown, size) = match linux_swap_target(path_address) {
        Ok(found) => found,
        Err(error) => return error,
    };
    if crate::linux_swap::active(target) {
        return LINUX_EBUSY;
    }
    let mut header = [0_u8; PAGE_SIZE];
    let read = match target {
        Target::File(handle) => {
            // Only a volume's file can be swapped to: tmpfs has no swap
            // file support (EINVAL), as Linux's shmem has none.
            if !crate::linux_blockfs::owns(handle) {
                return LINUX_EINVAL;
            }
            crate::linux_overlay::read(handle, 0, &mut header).unwrap_or(0)
        }
        Target::Device(device) => linux_swap_device_read(device, &mut header),
    };
    if read < PAGE_SIZE {
        return LINUX_EINVAL;
    }
    let pages = size / PAGE_SIZE as u64;
    let Some(usable) = crate::linux_swap::usable_pages(&header, pages) else {
        return LINUX_EINVAL;
    };
    // The pages the header spans, itself included.
    let header_pages = u64::from(u32::from_le_bytes([
        header[1028],
        header[1029],
        header[1030],
        header[1031],
    ])) + 1;
    // A swap file must have a block under every page (no holes).
    if let Target::File(handle) = target {
        if !crate::linux_blockfs::range_backed(handle, 0, (usable + 1) * PAGE_SIZE as u64) {
            return LINUX_EINVAL;
        }
    }
    if let Err(error) = crate::linux_swap::activate(instance, target, &shown, usable, flags) {
        return error.wrapping_neg();
    }
    // SWAP_FLAG_DISCARD discards the whole area but its header now, unless
    // only freed pages are to be discarded (DISCARD_PAGES without
    // DISCARD_ONCE); a loop device discards by punching its backing file.
    const DISCARD: u32 = 0x1_0000;
    const DISCARD_ONCE: u32 = 0x2_0000;
    const DISCARD_PAGES: u32 = 0x4_0000;
    let area_discard =
        flags & DISCARD != 0 && (flags & DISCARD_ONCE != 0 || flags & DISCARD_PAGES == 0);
    if let (true, Target::Device(device)) = (area_discard, target) {
        let (major, minor) = linux_device_numbers(device);
        if major == crate::linux_loop::MAJOR {
            let length = (header_pages - 1) * PAGE_SIZE as u64;
            let _ = crate::linux_loop::discard(minor, PAGE_SIZE as u64, length);
        }
    }
    0
}

/// swapoff(path).
pub(super) fn linux_swapoff(path_address: u64) -> u64 {
    if !linux_has_capability(ginux_credentials::capability::SYS_ADMIN) {
        return LINUX_EPERM;
    }
    let (target, _, _) = match linux_swap_target(path_address) {
        Ok(found) => found,
        Err(error) => return error,
    };
    match crate::linux_swap::deactivate(linux_execution_instance(), target) {
        Ok(()) => 0,
        Err(error) => error.wrapping_neg(),
    }
}

/// The area `path_address` names: a block device or a regular file, the
/// path /proc/swaps shows for it, and its size. A directory or any other
/// kind of file is EINVAL.
fn linux_swap_target(path_address: u64) -> Result<(Target, Vec<u8>, u64), u64> {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(path_address, &mut path)?;
    if length == 0 {
        return Err(LINUX_ENOENT);
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length =
        linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), &path[..length], &mut canonical)?;
    let (length, _, metadata) = linux_overlay_lookup_following(&mut canonical, length, true)?;
    let Some(metadata) = metadata else {
        return Err(linux_missing_path_error(&canonical[..length]));
    };
    let mut shown = Vec::new();
    shown
        .try_reserve_exact(length + 1)
        .map_err(|_| LINUX_ENOMEM)?;
    shown.push(b'/');
    shown.extend_from_slice(&canonical[..length]);
    match metadata.kind {
        crate::linux_overlay::NodeKind::BlockDevice => {
            let size = linux_swap_device_size(metadata.device).ok_or(LINUX_EINVAL)?;
            Ok((Target::Device(metadata.device), shown, size))
        }
        crate::linux_overlay::NodeKind::File => {
            Ok((Target::File(metadata.handle), shown, metadata.size as u64))
        }
        _ => Err(LINUX_EINVAL),
    }
}

/// The size of block device `device` (a loop device or a RAM disk).
fn linux_swap_device_size(device: u32) -> Option<u64> {
    let (major, minor) = linux_device_numbers(device);
    match major {
        crate::linux_loop::MAJOR => crate::linux_loop::peek(minor).map(|(_, _, size)| size),
        crate::linux_ramdisk::MAJOR => Some(crate::linux_ramdisk::DISK_SIZE),
        _ => None,
    }
}

/// Reads the first page of block device `device`; how much it read.
fn linux_swap_device_read(device: u32, page: &mut [u8; PAGE_SIZE]) -> usize {
    let (major, minor) = linux_device_numbers(device);
    match major {
        crate::linux_loop::MAJOR => {
            let Some((backing, offset, size)) = crate::linux_loop::peek(minor) else {
                return 0;
            };
            if size < PAGE_SIZE as u64 {
                return 0;
            }
            crate::linux_overlay::read(backing, offset as usize, page).unwrap_or(0)
        }
        crate::linux_ramdisk::MAJOR => {
            let Ok(open) = crate::linux_ramdisk::open(minor, true, false) else {
                return 0;
            };
            let read = crate::linux_ramdisk::read_at(open, 0, page).unwrap_or(0);
            crate::linux_ramdisk::release(crate::linux_ramdisk::CLASS_DISK, open);
            read
        }
        _ => 0,
    }
}
