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
    if let Err(error) =
        crate::linux_swap::activate(instance, target, &shown, &header, usable, flags)
    {
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
    let kind = match crate::linux_swap::begin_drain(linux_execution_instance(), target) {
        Ok(kind) => kind,
        Err(error) => return error.wrapping_neg(),
    };
    // Every page out in the area comes back first; without memory for
    // them all, the area stays on (ENOMEM), as Linux's try_to_unuse fails.
    if linux_swap_in_kind(kind) && crate::linux_swap::finish_drain(kind) {
        0
    } else {
        crate::linux_swap::abort_drain(kind);
        LINUX_ENOMEM
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

/// Pages written out per pass of reclaim that pages out (Linux's
/// SWAP_CLUSTER_MAX), so each pass's scan of the page tables pays for more
/// than the one page a fault wanted.
const SWAP_CLUSTER: u64 = 32;

/// Reads or writes page `page` at swap entry `entry`'s place in its area.
fn linux_swap_page_io(entry: u64, page: &mut [u8; PAGE_SIZE], write: bool) -> bool {
    let Some((target, offset)) = crate::linux_swap::location(entry) else {
        return false;
    };
    match target {
        Target::File(handle) => crate::linux_blockfs::swap_page_io(handle, offset, page, write),
        Target::Device(device) => {
            let (major, minor) = linux_device_numbers(device);
            match major {
                crate::linux_loop::MAJOR => {
                    let Some((backing, start, size)) = crate::linux_loop::peek(minor) else {
                        return false;
                    };
                    if offset + PAGE_SIZE as u64 > size {
                        return false;
                    }
                    let position = (start + offset) as usize;
                    let done = if write {
                        crate::linux_overlay::write(backing, position, page)
                    } else {
                        crate::linux_overlay::read(backing, position, page)
                    };
                    done == Some(PAGE_SIZE)
                }
                crate::linux_ramdisk::MAJOR => {
                    let Ok(open) = crate::linux_ramdisk::open(minor, true, write) else {
                        return false;
                    };
                    let done = if write {
                        crate::linux_ramdisk::write_at(open, offset, page)
                    } else {
                        crate::linux_ramdisk::read_at(open, offset, page)
                    };
                    crate::linux_ramdisk::release(crate::linux_ramdisk::CLASS_DISK, open);
                    done.is_ok_and(|done| done == PAGE_SIZE)
                }
                _ => false,
            }
        }
    }
}

/// Reads the page swap entry `entry` holds into `frame` (a fault, or
/// swapoff, bringing a page back). The caller drops the entry's reference
/// once the frame maps in its place.
pub(crate) fn linux_swap_read_page(entry: u64, frame: memory::FrameLease) -> bool {
    // A page read ahead into the swap cache needs no I/O.
    if let Some(cached) = crate::linux_swap::cached(entry) {
        return address_space::copy_linux_frame(cached, frame);
    }
    let mut page = [0_u8; PAGE_SIZE];
    linux_swap_page_io(entry, &mut page, false)
        && address_space::prepare_linux_frame(frame.address(), &page)
}

/// Where the last pass that paged out stopped.
struct LinuxSwapCursor {
    /// The process and the address the last pass stopped at, so the next
    /// one goes on from there rather than paging out the same first pages
    /// again.
    cursor_pid: AtomicU32,
    cursor_address: AtomicU64,
}

static LINUX_SWAP_CURSOR: LinuxSwapCursor = LinuxSwapCursor {
    cursor_pid: AtomicU32::new(0),
    cursor_address: AtomicU64::new(0),
};

/// When reclaim may page out the current process's own pages: while one
/// of its user page faults is resolved, or the kernel brings in a range of
/// its memory it is about to use (`materialize_linux_runtime_user_range`),
/// which is then kept: no system call is midway through using any other
/// of its pages. Elsewhere a page the kernel just faulted in for the call
/// could go before the call used it.
struct LinuxOwnReclaim {
    /// The CPU (plus one, above bit 32) and the process, or 0.
    tag: AtomicU64,
    /// The range that must stay, [start, end).
    pinned_start: AtomicU64,
    pinned_end: AtomicU64,
}

static LINUX_USER_FAULT_RECLAIM: LinuxOwnReclaim = LinuxOwnReclaim {
    tag: AtomicU64::new(0),
    pinned_start: AtomicU64::new(0),
    pinned_end: AtomicU64::new(0),
};

fn linux_user_fault_tag() -> u64 {
    (current_cpu_index_checked().unwrap_or(0) as u64 + 1) << 32
        | u64::from(current_linux_process_pid())
}

/// Lets reclaim take the current process's own pages but [start, end),
/// until dropped.
pub(super) struct LinuxUserFaultReclaim([u64; 3]);

impl LinuxUserFaultReclaim {
    /// For a user page fault (whose page is not in memory to take).
    pub(super) fn enter() -> Self {
        Self::enter_pinning(0, 0)
    }

    /// For the kernel bringing in [start, end) to use it.
    pub(super) fn enter_pinning(start: u64, end: u64) -> Self {
        let state = &LINUX_USER_FAULT_RECLAIM;
        Self([
            state.tag.swap(linux_user_fault_tag(), Ordering::AcqRel),
            state.pinned_start.swap(start, Ordering::AcqRel),
            state.pinned_end.swap(end, Ordering::AcqRel),
        ])
    }
}

impl Drop for LinuxUserFaultReclaim {
    fn drop(&mut self) {
        let state = &LINUX_USER_FAULT_RECLAIM;
        state.pinned_start.store(self.0[1], Ordering::Release);
        state.pinned_end.store(self.0[2], Ordering::Release);
        state.tag.store(self.0[0], Ordering::Release);
    }
}

/// Whether reclaim may take the current process's own pages
/// (`LinuxOwnReclaim`).
pub(super) fn linux_own_pages_reclaimable() -> bool {
    LINUX_USER_FAULT_RECLAIM.tag.load(Ordering::Acquire) == linux_user_fault_tag()
}

/// Whether page `address` of process `pid` must stay in memory: the
/// current process's range the kernel is using.
fn linux_page_pinned(pid: u32, address: u64) -> bool {
    let state = &LINUX_USER_FAULT_RECLAIM;
    pid == current_linux_process_pid()
        && linux_own_pages_reclaimable()
        && (state.pinned_start.load(Ordering::Acquire)..state.pinned_end.load(Ordering::Acquire))
            .contains(&address)
}

/// Whether paging out may happen here: the domain has swap with room, and
/// this CPU holds no lock but the kernel-entry lock (the page I/O takes
/// the volume's, the loop device's and the overlay's, ranked above it).
fn linux_swap_possible(instance: usize) -> bool {
    crate::sync::rank_available(crate::sync::LockRank::MOUNTS)
        && crate::linux_swap::available(instance)
}

/// Pages out the active address space's page at `address` to the domain's
/// swap: true if it went.
fn linux_swap_out_page(instance: usize, address: u64) -> bool {
    let Some(frame) = address_space::current_linux_runtime_page(address).frame else {
        return false;
    };
    let owner = memory::frame_charge(frame);
    let Some(entry) = crate::linux_swap::allocate(instance, owner) else {
        return false;
    };
    let Some((frame, old)) = address_space::swap_out_current_linux_page(address, entry) else {
        crate::linux_swap::free(entry);
        return false;
    };
    let mut page = [0_u8; PAGE_SIZE];
    if !address_space::read_linux_frame(frame, &mut page)
        || !linux_swap_page_io(entry, &mut page, true)
    {
        let _ = address_space::restore_current_linux_swapped_page(address, old);
        crate::linux_swap::free(entry);
        return false;
    }
    // The frame's release gives its charge back to its memory cgroup,
    // whose swap the entry is now charged to.
    address_space::release_linux_private_page(frame)
}

/// Pages out up to `budget` (at least a cluster) of the private anonymous
/// pages of process `pid`, whose address space is the active one: its
/// anonymous mappings and heap, but not locked or huge ones, nor pages
/// shared with others (a shared anonymous mapping's, which its page-table
/// entries mark). Pages used since the last pass get a second round
/// first. How many went.
pub(super) fn linux_swap_out_current(pid: u32, budget: u64) -> u64 {
    let instance = linux_execution_instance();
    if budget == 0 || !linux_swap_possible(instance) {
        return 0;
    }
    let budget = budget.max(SWAP_CLUSTER);
    let Some(areas) = crate::linux_areas::snapshot(instance, pid) else {
        return 0;
    };
    let mut ranges = Vec::new();
    for area in areas.iter().filter(|area| {
        matches!(
            area.backing,
            crate::linux_areas::Backing::Anonymous | crate::linux_areas::Backing::Heap
        ) && !area.locked
            && !area.huge
    }) {
        if ranges.try_reserve(1).is_err() {
            break;
        }
        ranges.push((area.start, area.end));
    }
    if ranges.is_empty() {
        return 0;
    }
    // Go on from where the last pass over this process stopped.
    let resume = if LINUX_SWAP_CURSOR.cursor_pid.load(Ordering::Relaxed) == pid {
        LINUX_SWAP_CURSOR.cursor_address.load(Ordering::Relaxed)
    } else {
        0
    };
    let first = ranges
        .iter()
        .position(|(_, end)| *end > resume)
        .unwrap_or(0);
    let mut swapped = 0;
    let mut candidates = [0_u64; SWAP_CLUSTER as usize];
    let mut last = resume;
    'passes: for second_chance in [true, false] {
        for index in (first..ranges.len()).chain(0..first) {
            let (start, end) = ranges[index];
            let mut position = if index == first {
                start.max(resume)
            } else {
                start
            };
            while position < end {
                let want = ((budget - swapped) as usize).min(candidates.len());
                let (found, next) = address_space::current_linux_swap_candidates(
                    position,
                    end,
                    second_chance,
                    &mut candidates[..want],
                );
                for address in &candidates[..found] {
                    if linux_page_pinned(pid, *address) {
                        continue;
                    }
                    if linux_swap_out_page(instance, *address) {
                        swapped += 1;
                        last = *address + PAGE_SIZE as u64;
                    } else if !crate::linux_swap::available(instance) {
                        break 'passes;
                    }
                }
                if swapped >= budget {
                    break 'passes;
                }
                position = next;
            }
        }
    }
    LINUX_SWAP_CURSOR.cursor_pid.store(pid, Ordering::Relaxed);
    LINUX_SWAP_CURSOR
        .cursor_address
        .store(last, Ordering::Relaxed);
    if swapped != 0 {
        // The registry's list of the process's pages is out of date; fork
        // and release read its page tables instead.
        let _ = linux_process::mark_live_process_address_space_stale(pid);
    }
    swapped
}

/// MADV_PAGEOUT over `pages` pages at `address` of process `pid`, whose
/// address space is the active one: its private anonymous pages there go
/// out to swap now, and so do its pages of shared memory (an unnamed shmem
/// or memfd node) that no other process maps, unmapped from it first.
pub(super) fn linux_swap_pageout(pid: u32, address: u64, pages: usize) {
    let instance = linux_execution_instance();
    if !linux_swap_possible(instance) {
        return;
    }
    let Some(areas) = crate::linux_areas::snapshot(instance, pid) else {
        return;
    };
    let end = address.saturating_add((pages * PAGE_SIZE) as u64);
    let mut changed = false;
    for area in areas
        .iter()
        .filter(|area| area.start < end && area.end > address && !area.locked && !area.huge)
    {
        let private = matches!(
            area.backing,
            crate::linux_areas::Backing::Anonymous | crate::linux_areas::Backing::Heap
        );
        let shared_file = area.shared
            && matches!(
                area.backing,
                crate::linux_areas::Backing::File { .. } | crate::linux_areas::Backing::Anonymous
            );
        if !private && !shared_file {
            continue;
        }
        for page in (area.start.max(address)..area.end.min(end)).step_by(PAGE_SIZE) {
            let state = address_space::current_linux_runtime_page(page);
            if state.frame.is_none() {
                continue;
            }
            changed |= if state.shared {
                shared_file && linux_swap_out_shared_page(instance, pid, page, area)
            } else {
                private && linux_swap_out_page(instance, page)
            };
        }
    }
    if changed {
        let _ = linux_process::mark_live_process_address_space_stale(pid);
    }
}

/// Pages out page `address` of shared mapping `area` of process `pid` (the
/// active address space): the page of an unnamed shmem or memfd node that
/// only this mapping maps is unmapped (its next touch maps it again, as a
/// file page past a mapping's old end does), written to swap and its frame
/// freed, the node noting the swap entry in its place. True if the page
/// left the process.
fn linux_swap_out_shared_page(
    instance: usize,
    pid: u32,
    address: u64,
    area: &crate::linux_areas::Area,
) -> bool {
    let Some((handle, offset)) = linux_shared_page_of(pid, area, address) else {
        return false;
    };
    let index = offset / PAGE_SIZE;
    let state = address_space::current_linux_runtime_page(address);
    let Some(frame) = crate::linux_overlay::paged_frame_for_swap(handle, index) else {
        return false;
    };
    if state.frame != Some(frame)
        || state.protection == 0
        || state.sealed
        || !crate::linux_overlay::sole_shared_mapping(handle, offset, pid, address)
    {
        return false;
    }
    let removed = address_space::remove_current_linux_runtime_page(address);
    if removed.frame != Some(frame) {
        return false;
    }
    if address_space::reserve_current_linux_past_eof_page(address, state.protection, false)
        .is_none()
    {
        return false;
    }
    let Some(entry) = crate::linux_swap::allocate(instance, crate::linux_cgroup::NO_SLOT) else {
        return true;
    };
    let mut page = [0_u8; PAGE_SIZE];
    if address_space::read_linux_frame(frame, &mut page)
        && linux_swap_page_io(entry, &mut page, true)
        && crate::linux_overlay::mark_paged_page_swapped(handle, index, frame, entry)
    {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
    } else {
        crate::linux_swap::free(entry);
    }
    true
}

/// The page of its file (or, for anonymous shared memory, of its shmem
/// node, as the overlay's registry has it) that page `address` of shared
/// mapping `area` of process `pid` maps, and the byte offset in it.
fn linux_shared_page_of(
    pid: u32,
    area: &crate::linux_areas::Area,
    address: u64,
) -> Option<(crate::linux_overlay::Handle, usize)> {
    match &area.backing {
        crate::linux_areas::Backing::File {
            device,
            inode,
            offset,
            ..
        } => {
            let handle = crate::linux_overlay::paged_file(*device, *inode)?;
            let offset = usize::try_from(offset.checked_add(address - area.start)?).ok()?;
            Some((handle, offset))
        }
        crate::linux_areas::Backing::Anonymous => {
            crate::linux_overlay::shared_mapping(pid, address)
        }
        _ => None,
    }
}

/// The pages of shared mapping `area` of the current process within
/// [start, end) whose page of its file or shmem node is out in swap.
pub(super) fn linux_shared_swapped_pages(
    area: &crate::linux_areas::Area,
    start: u64,
    end: u64,
) -> u64 {
    // Nothing out in swap, nothing to look up page by page.
    let (total, free) = crate::linux_swap::totals(linux_execution_instance());
    if total == free {
        return 0;
    }
    let pid = current_linux_process_pid();
    (start.max(area.start)..end.min(area.end))
        .step_by(PAGE_SIZE)
        .filter(|page| {
            linux_shared_page_of(pid, area, *page).is_some_and(|(handle, offset)| {
                crate::linux_overlay::paged_page_swapped(handle, offset / PAGE_SIZE)
            })
        })
        .count() as u64
}

/// MADV_WILLNEED over `pages` pages at `address`: those of them out in
/// swap are read into the swap cache, so touching them needs no I/O. The
/// frames are charged to the caller's cgroup, whose other pages may go
/// out to make room for them.
pub(super) fn linux_swap_willneed(address: u64, pages: usize) {
    let _reclaim = LinuxUserFaultReclaim::enter();
    for page in 0..pages as u64 {
        let state = address_space::current_linux_runtime_page(address + page * PAGE_SIZE as u64);
        let Some(entry) = state.swap else {
            continue;
        };
        if crate::linux_swap::cached(entry).is_some() {
            continue;
        }
        let Some([frame]) = memory::allocate_user_frames::<1>() else {
            return;
        };
        let mut bytes = [0_u8; PAGE_SIZE];
        if !linux_swap_page_io(entry, &mut bytes, false)
            || !address_space::prepare_linux_frame(frame.address(), &bytes)
            || !crate::linux_swap::insert_cached(entry, frame)
        {
            let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        }
    }
}

/// Brings back every page the domain's processes have paged out to the
/// area of type `kind` (swapoff): true once none is left. A process
/// running on another CPU, whose page tables cannot be changed from here,
/// or a page with no memory to come back to, leaves pages out.
fn linux_swap_in_kind(kind: u8) -> bool {
    let instance = linux_execution_instance();
    let current = current_linux_process_pid();
    let mut members = Vec::new();
    for (pid, _) in linux_process::live_memcg_members(|_| true) {
        if members.try_reserve(1).is_err() {
            return false;
        }
        members.push(pid);
    }
    for pid in members {
        if pid != current && linux_live_process_bank(pid, instance).is_some() {
            continue;
        }
        let bring_back = || {
            let mut pages = [0_u64; 64];
            loop {
                let found = address_space::current_linux_swapped_pages_in(kind, &mut pages);
                if found == 0 {
                    return true;
                }
                for address in &pages[..found] {
                    if !linux_swap_in_page(*address) {
                        return false;
                    }
                }
            }
        };
        let done = if pid == current {
            bring_back()
        } else {
            let Some(root) = linux_process::live_process_root(pid) else {
                continue;
            };
            address_space::with_live_linux_process_root(root, bring_back).unwrap_or(false)
        };
        if !done {
            return false;
        }
        let _ = linux_process::mark_live_process_address_space_stale(pid);
    }
    crate::linux_swap::used_in(kind) == 0
}

/// Reads the active address space's page at `address` back from swap,
/// into a frame charged to the cgroup whose swap it was charged to.
fn linux_swap_in_page(address: u64) -> bool {
    let page = address_space::current_linux_runtime_page(address);
    let Some(entry) = page.swap else {
        return true;
    };
    let owner = crate::linux_swap::owner(entry);
    let Some(frame) = memory::allocate_user_frame_charged_to(owner) else {
        return false;
    };
    // An inaccessible page keeps a frame as a reservation: it comes back
    // readable, then loses its access again.
    let protection = page.protection.max(LINUX_PROT_READ as u8);
    let back = (page.protection != 0
        || address_space::protect_current_linux_runtime_page(address, protection))
        && address_space::materialize_current_linux_runtime_page(address, frame, protection, false)
        && (page.protection != 0 || address_space::protect_current_linux_runtime_page(address, 0));
    if !back && address_space::current_linux_runtime_page(address).frame != Some(frame) {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
    }
    back
}
