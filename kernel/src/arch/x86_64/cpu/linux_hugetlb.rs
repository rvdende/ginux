//! Huge pages, as Linux's hugetlbfs and mm/hugetlb.c give them: a pool of
//! 2 MiB pages a domain sizes through `/proc/sys/vm/nr_hugepages` (and
//! `/sys/kernel/mm/hugepages/hugepages-2048kB`), mapped by MAP_HUGETLB,
//! files on a hugetlbfs mount, MFD_HUGETLB memfds and SHM_HUGETLB
//! segments. A huge mapping is 2 MiB aligned and a multiple of 2 MiB long,
//! and is only split at a huge page boundary.
//!
//! The pool's size is what its sysfs files hold (`/proc/sys/vm/nr_hugepages`
//! is the same file). The pool is an account: what a mapping reserves comes out of it when it
//! is made (ENOMEM once it is used up, unless MAP_NORESERVE), and is
//! backed by 512 ordinary pages each, mapped as small pages. What is in use
//! is counted from the things that hold pages (`linux_huge_pages_in_use`),
//! so a mapping's pages go back when it does, by munmap, exec or exit.

use super::*;

/// The huge page size, 2 MiB, the only one Ginux has.
pub(super) const LINUX_HUGE_PAGE_SIZE: u64 = crate::linux_areas::HUGE_PAGE_SIZE;
/// log2 of the huge page size, as MAP_HUGE_*, MFD_HUGE_* and SHM_HUGE_*
/// name a size.
const LINUX_HUGE_PAGE_SHIFT: u64 = 21;
/// Where the size of a huge page is encoded in mmap, memfd_create and
/// shmget flags, and its mask.
const LINUX_HUGE_SIZE_SHIFT: u64 = 26;
const LINUX_HUGE_SIZE_MASK: u64 = 0x3f;
pub(super) const LINUX_MAP_HUGETLB: u64 = 0x4_0000;
pub(super) const LINUX_SHM_HUGETLB: u64 = 0o4000;
const LINUX_SHM_NORESERVE: u64 = 0o10000;
pub(super) const LINUX_MFD_HUGETLB: u64 = 4;

/// The pool's sysfs directory, which LTP takes as "huge pages exist".
const LINUX_HUGEPAGES_SYSFS: &[u8] = b"sys/kernel/mm/hugepages/hugepages-2048kB";

/// The huge pages a mapping of `length` bytes takes.
fn linux_huge_pages_for(length: u64) -> u64 {
    length.div_ceil(LINUX_HUGE_PAGE_SIZE)
}

/// Whether a huge page size encoded in `flags` (MAP_HUGE_*, MFD_HUGE_*,
/// SHM_HUGE_*) is one Ginux has: the default, or 2 MiB.
fn linux_huge_size_supported(flags: u64) -> bool {
    matches!(
        (flags >> LINUX_HUGE_SIZE_SHIFT) & LINUX_HUGE_SIZE_MASK,
        0 | LINUX_HUGE_PAGE_SHIFT
    )
}

/// The number one of the pool's sysfs files holds, 0 without one.
fn linux_hugepages_sysfs_value(name: &[u8]) -> u64 {
    let mut path = [0_u8; 96];
    let Some(length) = linux_hugepages_sysfs_path(name, &mut path) else {
        return 0;
    };
    let Some(metadata) = crate::linux_overlay::lookup(&path[..length]) else {
        return 0;
    };
    let mut text = [0_u8; 24];
    let read = crate::linux_overlay::read(metadata.handle, 0, &mut text).unwrap_or(0);
    linux_parse_kernel_integer(text[..read].trim_ascii())
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0)
}

/// The persistent huge pages of the pool (nr_hugepages): the number its
/// sysfs file holds, which /proc/sys/vm/nr_hugepages also is.
fn linux_huge_pool_size() -> u64 {
    linux_hugepages_sysfs_value(b"nr_hugepages")
}

/// The surplus pages the pool may lend beyond its own
/// (nr_overcommit_hugepages).
fn linux_huge_pool_overcommit() -> u64 {
    linux_hugepages_sysfs_value(b"nr_overcommit_hugepages")
}

/// The group whose members may make SHM_HUGETLB segments
/// (vm.hugetlb_shm_group): root's, as Linux boots.
const LINUX_HUGETLB_SHM_GROUP: u32 = 0;

/// The huge pages in use in the current domain: those its processes'
/// private huge mappings reserve, those files of huge pages hold for their
/// shared mappings, and those SHM_HUGETLB segments hold.
fn linux_huge_pages_in_use() -> u64 {
    let segments = crate::linux_sysv_ipc::segments()
        .iter()
        .filter(|(_, segment)| segment.huge)
        .map(|(_, segment)| linux_huge_pages_for(segment.size))
        .sum::<u64>();
    crate::linux_areas::huge_reserved_pages(linux_execution_instance())
        + crate::linux_overlay::huge_pages_in_use()
        + segments
}

/// The pool as /proc/meminfo counts it.
#[derive(Clone, Copy)]
pub(super) struct LinuxHugePageCounts {
    pub(super) total: u64,
    pub(super) free: u64,
    pub(super) reserved: u64,
    pub(super) surplus: u64,
    /// The persistent pages (nr_hugepages).
    pub(super) persistent: u64,
    pub(super) overcommit: u64,
}

pub(super) fn linux_huge_page_counts() -> LinuxHugePageCounts {
    let persistent = linux_huge_pool_size();
    let used = linux_huge_pages_in_use();
    let surplus = used.saturating_sub(persistent);
    LinuxHugePageCounts {
        total: persistent + surplus,
        free: persistent.saturating_sub(used),
        // Pages are taken when a mapping is made, not when first touched,
        // so none is reserved but not yet in use.
        reserved: 0,
        surplus,
        persistent,
        overcommit: linux_huge_pool_overcommit(),
    }
}

/// Whether `pages` more huge pages can be had: the pool's free ones, then
/// surplus ones up to nr_overcommit_hugepages (Linux's
/// hugetlb_acct_memory).
fn linux_huge_pages_available(pages: u64) -> bool {
    let counts = linux_huge_page_counts();
    pages <= counts.free + counts.overcommit.saturating_sub(counts.surplus)
}

/// The pool size a write of `requested` to nr_hugepages gets: no more than
/// free memory can back beyond the pages in use, as Linux's allocation of
/// the pages may fall short.
fn linux_huge_pool_size_for(requested: u64) -> u64 {
    let (_, free_frames) = linux_domain_frame_counts();
    let backed =
        free_frames / (LINUX_HUGE_PAGE_SIZE / PAGE_SIZE as u64) + linux_huge_pages_in_use();
    requested.min(backed)
}

/// Whether overlay file `handle` is made of huge pages: an MFD_HUGETLB
/// memfd, or a file on a hugetlbfs mount (which is remembered).
pub(super) fn linux_overlay_huge(handle: crate::linux_overlay::Handle) -> bool {
    if crate::linux_overlay::is_huge(handle) {
        return true;
    }
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let Some(length) = crate::linux_overlay::copy_path(handle, &mut path) else {
        return false;
    };
    let huge =
        crate::linux_mounts::on_filesystem(linux_mount_space(), &path[..length], b"hugetlbfs");
    if huge {
        let _ = crate::linux_overlay::set_huge(handle);
    }
    huge
}

/// A huge mapping mmap is making: what to mark once it is mapped.
#[derive(Clone, Copy)]
pub(super) struct LinuxHugeMapping {
    length: u64,
    shared: bool,
    reserved: bool,
}

/// mmap of huge pages (MAP_HUGETLB, or a file of huge pages): checks it
/// and rewrites `arguments` (address, length, protection, flags, fd,
/// offset) into the small-page mapping that backs it, 2 MiB aligned and
/// rounded up to whole huge pages; None for any other mapping. As Linux:
/// MAP_HUGETLB of a file that is not of huge pages, a huge page size Ginux
/// lacks, or a fixed address or file offset off a huge page boundary is
/// EINVAL; a mapping the pool cannot reserve is ENOMEM.
pub(super) fn linux_huge_mmap_arguments(
    arguments: &mut [u64; 6],
) -> Result<Option<LinuxHugeMapping>, u64> {
    let [address, length, protection, flags, descriptor, offset] = *arguments;
    let anonymous = flags & LINUX_MAP_ANONYMOUS != 0;
    let file = if anonymous {
        None
    } else {
        linux_overlay_descriptor_handle(u64::from(descriptor as u32))
            .filter(|handle| linux_overlay_huge(*handle))
    };
    // A descriptor that is not open is EBADF before anything else, as the
    // mapping path finds (mmap08).
    if flags & LINUX_MAP_HUGETLB == 0 && file.is_none()
        || !anonymous && !linux_descriptor_open(u64::from(descriptor as u32))
    {
        return Ok(None);
    }
    if !anonymous && file.is_none() || !linux_huge_size_supported(flags) || length == 0 {
        return Err(LINUX_EINVAL);
    }
    let Some(length) = length.checked_next_multiple_of(LINUX_HUGE_PAGE_SIZE) else {
        return Err(LINUX_ENOMEM);
    };
    let fixed = flags & (LINUX_MAP_FIXED | LINUX_MAP_FIXED_NOREPLACE) != 0;
    if fixed && !address.is_multiple_of(LINUX_HUGE_PAGE_SIZE)
        || file.is_some() && !offset.is_multiple_of(LINUX_HUGE_PAGE_SIZE)
    {
        return Err(LINUX_EINVAL);
    }
    let shared = flags & LINUX_MAP_SHARED != 0;
    // A shared mapping of a file takes the pages the file does not hold
    // yet; any other takes all of its own.
    let needed = match file.filter(|_| shared) {
        Some(handle) => linux_huge_pages_for(offset.saturating_add(length))
            .saturating_sub(u64::from(crate::linux_overlay::huge_pages(handle))),
        None => linux_huge_pages_for(length),
    };
    if flags & LINUX_MAP_NORESERVE == 0 && !linux_huge_pages_available(needed) {
        return Err(LINUX_ENOMEM);
    }
    // A writable mapping past a file's end extends it (hugetlbfs_file_mmap).
    if let Some(handle) = file {
        let end = usize::try_from(offset.saturating_add(length)).map_err(|_| LINUX_ENOMEM)?;
        if protection & LINUX_PROT_WRITE != 0
            && crate::linux_overlay::metadata(handle).is_some_and(|metadata| metadata.size < end)
            && !crate::linux_overlay::truncate(handle, end)
        {
            return Err(LINUX_ENOMEM);
        }
    }
    // The kernel places a huge mapping on a huge page boundary: past room
    // for one huge page more than it needs, rounded up.
    let address = if fixed {
        address
    } else {
        let Ok(pages) = usize::try_from((length + LINUX_HUGE_PAGE_SIZE) / PAGE_SIZE as u64) else {
            return Err(LINUX_ENOMEM);
        };
        let Some(candidate) = linux_runtime_select_mapping(0, pages, false, false) else {
            return Err(LINUX_ENOMEM);
        };
        candidate.next_multiple_of(LINUX_HUGE_PAGE_SIZE)
    };
    let placed = if fixed { 0 } else { LINUX_MAP_FIXED_NOREPLACE };
    *arguments = [
        address,
        length,
        protection,
        (flags | placed) & !(LINUX_MAP_HUGETLB | (LINUX_HUGE_SIZE_MASK << LINUX_HUGE_SIZE_SHIFT)),
        descriptor,
        offset,
    ];
    Ok(Some(LinuxHugeMapping {
        length,
        shared,
        reserved: !shared && flags & LINUX_MAP_NORESERVE == 0,
    }))
}

/// Records the huge mapping `huge` mmap made at `address`: its areas
/// split only on huge page boundaries, a private one holds its pages, and
/// a shared one's file holds them for every mapping of it.
pub(super) fn linux_huge_mapped(address: u64, huge: LinuxHugeMapping) {
    let pid = current_linux_process_pid();
    crate::linux_areas::mark_huge(
        linux_execution_instance(),
        pid,
        address,
        huge.length,
        huge.reserved,
    );
    if huge.shared {
        if let Some((handle, offset)) = crate::linux_overlay::shared_mapping(pid, address) {
            let end = (offset as u64).saturating_add(huge.length);
            let pages = u32::try_from(linux_huge_pages_for(end)).unwrap_or(u32::MAX);
            let _ = crate::linux_overlay::hold_huge_pages(handle, pages);
        }
    }
}

/// Whether munmap or mprotect of `length` bytes at `address` would split a
/// huge mapping inside a huge page, which Linux refuses (EINVAL).
pub(super) fn linux_huge_split(address: u64, length: u64) -> bool {
    crate::linux_areas::huge_split(
        linux_execution_instance(),
        current_linux_process_pid(),
        address,
        length,
    )
}

/// memfd_create's huge page flags, MFD_HUGETLB with a size: Ok(true) for a
/// memfd of huge pages; EINVAL for unknown flags, ENODEV for a huge page
/// size Ginux lacks (memfd_create04).
pub(super) fn linux_memfd_huge_flags(flags: u64, known: u64) -> Result<bool, u64> {
    if flags & LINUX_MFD_HUGETLB == 0 {
        return if flags & !known == 0 {
            Ok(false)
        } else {
            Err(LINUX_EINVAL)
        };
    }
    if flags & !(known | LINUX_MFD_HUGETLB | (LINUX_HUGE_SIZE_MASK << LINUX_HUGE_SIZE_SHIFT)) != 0 {
        return Err(LINUX_EINVAL);
    }
    if !linux_huge_size_supported(flags) {
        return Err(LINUX_ENODEV);
    }
    Ok(true)
}

/// shmget's SHM_HUGETLB flags: the bits it adds to those shmget knows.
pub(super) const LINUX_SHM_HUGE_FLAGS: u64 =
    LINUX_SHM_HUGETLB | LINUX_SHM_NORESERVE | (LINUX_HUGE_SIZE_MASK << LINUX_HUGE_SIZE_SHIFT);

/// Whether the caller may make a SHM_HUGETLB segment of `size` bytes and
/// the pool can give it its pages, as Linux's hugetlb_file_setup: EINVAL
/// for a huge page size Ginux lacks, EPERM for a caller without
/// CAP_IPC_LOCK outside vm.hugetlb_shm_group whose RLIMIT_MEMLOCK does not
/// cover it, ENOMEM when the pool is short.
pub(super) fn linux_shm_huge_allowed(size: u64, flags: u64) -> Result<(), u64> {
    if !linux_huge_size_supported(flags) {
        return Err(LINUX_EINVAL);
    }
    let huge_size = size
        .checked_next_multiple_of(LINUX_HUGE_PAGE_SIZE)
        .ok_or(LINUX_ENOMEM)?;
    let credentials = current_linux_credentials().ok_or(LINUX_EPERM)?;
    let group = LINUX_HUGETLB_SHM_GROUP;
    let in_group = linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
        credentials.in_group(groups, group) || credentials.group.effective == group
    })
    .unwrap_or(false);
    let memlock = linux_resource_limit_values(LINUX_RLIMIT_MEMLOCK, true)
        .map_or(u64::MAX, |values| values[0]);
    if !credentials.privileged() && !in_group && memlock < huge_size {
        return Err(LINUX_EPERM);
    }
    if flags & LINUX_SHM_NORESERVE == 0 && !linux_huge_pages_available(linux_huge_pages_for(size)) {
        return Err(LINUX_ENOMEM);
    }
    Ok(())
}

/// The pool's sysfs files, with their modes.
const LINUX_HUGEPAGES_SYSFS_FILES: [(&[u8], u32); 6] = [
    (b"nr_hugepages", 0o644),
    (b"nr_hugepages_mempolicy", 0o644),
    (b"free_hugepages", 0o444),
    (b"resv_hugepages", 0o444),
    (b"surplus_hugepages", 0o444),
    (b"nr_overcommit_hugepages", 0o644),
];

/// `LINUX_HUGEPAGES_SYSFS`/`name` in `path`, with its length.
fn linux_hugepages_sysfs_path(name: &[u8], path: &mut [u8; 96]) -> Option<usize> {
    let length = LINUX_HUGEPAGES_SYSFS.len() + 1 + name.len();
    let path = path.get_mut(..length)?;
    path[..LINUX_HUGEPAGES_SYSFS.len()].copy_from_slice(LINUX_HUGEPAGES_SYSFS);
    path[LINUX_HUGEPAGES_SYSFS.len()] = b'/';
    path[LINUX_HUGEPAGES_SYSFS.len() + 1..].copy_from_slice(name);
    Some(length)
}

/// A domain starts: `/sys/kernel/mm/hugepages/hugepages-2048kB` shows its
/// pool, empty, which root may size.
pub(super) fn linux_prepare_hugetlbfs() {
    for directory in [
        &b"sys"[..],
        b"sys/kernel",
        b"sys/kernel/mm",
        b"sys/kernel/mm/hugepages",
        LINUX_HUGEPAGES_SYSFS,
    ] {
        if crate::linux_overlay::lookup(directory).is_none()
            && crate::published_rootfs::exact_entry(directory).is_none()
        {
            if let Some(handle) = crate::linux_overlay::create_directory(directory, 0o755) {
                let _ = crate::linux_overlay::set_owner(handle, 0, 0);
            }
        }
    }
    let mut path = [0_u8; 96];
    for (name, mode) in LINUX_HUGEPAGES_SYSFS_FILES {
        let Some(length) = linux_hugepages_sysfs_path(name, &mut path) else {
            continue;
        };
        if crate::linux_overlay::lookup(&path[..length]).is_none() {
            if let Some(handle) = crate::linux_overlay::create_file(&path[..length], mode, b"0\n") {
                let _ = crate::linux_overlay::set_owner(handle, 0, 0);
            }
        }
    }
    linux_refresh_hugepages_sysfs();
}

/// Rewrites the pool's derived sysfs files (free, reserved, surplus pages,
/// and nr_hugepages_mempolicy, which is nr_hugepages without NUMA) with
/// what it holds now; a walk to a path under `/sys/kernel/mm` does this, so
/// they read as current.
pub(super) fn linux_refresh_hugepages_sysfs() {
    let counts = linux_huge_page_counts();
    let mut path = [0_u8; 96];
    for (name, value) in [
        (&b"nr_hugepages_mempolicy"[..], counts.persistent),
        (b"free_hugepages", counts.free),
        (b"resv_hugepages", counts.reserved),
        (b"surplus_hugepages", counts.surplus),
    ] {
        let Some(length) = linux_hugepages_sysfs_path(name, &mut path) else {
            continue;
        };
        if let Some(metadata) = crate::linux_overlay::lookup(&path[..length]) {
            linux_write_hugepages_value(metadata.handle, value);
        }
    }
}

/// Replaces the text of overlay file `handle` with `value` and a newline.
fn linux_write_hugepages_value(handle: crate::linux_overlay::Handle, value: u64) {
    let mut text = [0_u8; 24];
    let mut used = 0;
    if append_linux_decimal(&mut text, &mut used, value)
        && append_linux_bytes(&mut text, &mut used, b"\n")
    {
        let _ = crate::linux_overlay::truncate(handle, 0)
            && crate::linux_overlay::write(handle, 0, &text[..used]) == Some(used);
    }
}

/// `/proc/sys/vm/nr_hugepages` and `nr_overcommit_hugepages`, canonical in
/// `output[..length]`, are the pool's sysfs files: the path becomes
/// theirs. The new length.
pub(super) fn linux_hugepages_proc_alias(
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
    length: usize,
) -> usize {
    let Some(name) = output[..length].strip_prefix(b"proc/sys/vm/") else {
        return length;
    };
    if !matches!(name, b"nr_hugepages" | b"nr_overcommit_hugepages") {
        return length;
    }
    let mut path = [0_u8; 96];
    let Some(alias) = linux_hugepages_sysfs_path(name, &mut path) else {
        return length;
    };
    output[..alias].copy_from_slice(&path[..alias]);
    alias
}

/// After a write to overlay file `handle`: one of the pool's writable sysfs
/// files sets the pool as the matching /proc/sys/vm value does, and the
/// files then show what it got.
pub(super) fn linux_hugepages_sysfs_written(handle: crate::linux_overlay::Handle) {
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let Some(length) = crate::linux_overlay::copy_path(handle, &mut path) else {
        return;
    };
    let Some(name) = path[..length]
        .strip_prefix(LINUX_HUGEPAGES_SYSFS)
        .and_then(|rest| rest.strip_prefix(b"/"))
    else {
        return;
    };
    if !matches!(
        name,
        b"nr_hugepages" | b"nr_hugepages_mempolicy" | b"nr_overcommit_hugepages"
    ) {
        return;
    }
    let mut text = [0_u8; 24];
    let read = crate::linux_overlay::read(handle, 0, &mut text).unwrap_or(0);
    let value = linux_parse_kernel_integer(text[..read].trim_ascii())
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);
    if name == b"nr_overcommit_hugepages" {
        linux_write_hugepages_value(handle, value);
    } else {
        // The pool gets as many pages as memory can back, which reads back
        // (tst_hugepage compares).
        let mut path = [0_u8; 96];
        if let Some(metadata) = linux_hugepages_sysfs_path(b"nr_hugepages", &mut path)
            .and_then(|length| crate::linux_overlay::lookup(&path[..length]))
        {
            linux_write_hugepages_value(metadata.handle, linux_huge_pool_size_for(value));
        }
    }
    linux_refresh_hugepages_sysfs();
}
