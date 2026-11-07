//! Linux security modules as Ginux has them: the capability module every
//! Linux has, and Landlock (`crate::linux_landlock`, policy in
//! `ginux_landlock`). This holds their system calls (landlock_*, lsm_*),
//! securityfs's `/sys/kernel/security/lsm`, and the checks the file,
//! socket and signal paths ask Landlock.
//!
//! Where Linux ties a check to an inode, Landlock here judges the path
//! (rules cover the hierarchy beneath the path they named), and a process's
//! threads share one domain.

use super::*;
use ginux_landlock::access as landlock;

/// The active modules' ids (LSM_ID_CAPABILITY, LSM_ID_LANDLOCK), in the
/// order `/sys/kernel/security/lsm` names them.
const LINUX_LSM_IDS: [u64; 2] = [100, 110];
const LINUX_LSM_NAMES: &[u8] = b"capability,landlock";

/// sizeof(struct lsm_ctx): id, flags, len and ctx_len.
const LINUX_LSM_CONTEXT_SIZE: usize = 32;

/// A descriptor whose file Landlock did not let its opener truncate (a
/// regular file) or ioctl (a device), as Linux decides both when the file
/// is opened: a file opened before its process was restricted keeps both.
const LINUX_PRIVATE_LANDLOCK_NO_TRUNCATE: u32 = 1 << 27;
const LINUX_PRIVATE_LANDLOCK_NO_IOCTL: u32 = 1 << 26;
pub(super) const LINUX_PRIVATE_LANDLOCK_DESCRIPTOR: u32 =
    LINUX_PRIVATE_LANDLOCK_NO_TRUNCATE | LINUX_PRIVATE_LANDLOCK_NO_IOCTL;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFBLK: u32 = 0o060_000;

/// A domain starts: Landlock forgets its last run, and securityfs's
/// `/sys/kernel/security/lsm` lists the active modules, comma
/// separated with no newline, as Linux's does.
pub(super) fn linux_prepare_securityfs() {
    crate::linux_landlock::start_instance(linux_execution_instance());
    for directory in [&b"sys"[..], b"sys/kernel", b"sys/kernel/security"] {
        if crate::linux_overlay::lookup(directory).is_none()
            && crate::published_rootfs::exact_entry(directory).is_none()
        {
            if let Some(handle) = crate::linux_overlay::create_directory(directory, 0o755) {
                let _ = crate::linux_overlay::set_owner(handle, 0, 0);
            }
        }
    }
    let lsm = b"sys/kernel/security/lsm";
    if crate::linux_overlay::lookup(lsm).is_none() {
        if let Some(handle) = crate::linux_overlay::create_file(lsm, 0o444, LINUX_LSM_NAMES) {
            let _ = crate::linux_overlay::set_owner(handle, 0, 0);
        }
    }
}

/// lsm_get_self_attr: neither active module keeps a process attribute
/// (those are SELinux's, AppArmor's and Smack's), so after Linux's checks
/// `size` gets 0 and the call is EOPNOTSUPP.
pub(super) fn linux_lsm_get_self_attr(attribute: u64, context: u64, size: u64, flags: u64) -> u64 {
    const LSM_FLAG_SINGLE: u64 = 1;
    let flags = u64::from(flags as u32);
    if attribute as u32 == 0 || size == 0 {
        return LINUX_EINVAL;
    }
    let mut available = [0_u8; 4];
    if !copy_from_linux_user(size, &mut available) {
        return LINUX_EFAULT;
    }
    if flags != 0 {
        if flags != LSM_FLAG_SINGLE || context == 0 {
            return LINUX_EINVAL;
        }
        let mut header = [0_u8; LINUX_LSM_CONTEXT_SIZE];
        if !copy_from_linux_user(context, &mut header) {
            return LINUX_EFAULT;
        }
        // The module asked about must be named (not LSM_ID_UNDEF).
        if header[..8] == [0; 8] {
            return LINUX_EINVAL;
        }
    }
    if !copy_to_linux_user(size, &0_u32.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    LINUX_EOPNOTSUPP
}

/// lsm_set_self_attr: Linux's checks of the context, then EOPNOTSUPP, as
/// no active module sets process attributes.
pub(super) fn linux_lsm_set_self_attr(_attribute: u64, context: u64, size: u64, flags: u64) -> u64 {
    let (size, flags) = (size as u32 as usize, flags as u32);
    if flags != 0 || size < LINUX_LSM_CONTEXT_SIZE {
        return LINUX_EINVAL;
    }
    if size > PAGE_SIZE {
        return LINUX_E2BIG;
    }
    let mut header = [0_u8; LINUX_LSM_CONTEXT_SIZE];
    let mut whole = [0_u8; PAGE_SIZE];
    if !copy_from_linux_user(context, &mut whole[..size]) {
        return LINUX_EFAULT;
    }
    header.copy_from_slice(&whole[..LINUX_LSM_CONTEXT_SIZE]);
    let word = |offset: usize| u64::from_ne_bytes(header[offset..offset + 8].try_into().unwrap());
    let (length, context_length) = (word(16), word(24));
    let required = (LINUX_LSM_CONTEXT_SIZE as u64).checked_add(context_length);
    if (size as u64) < length || required.is_none_or(|required| length < required) {
        return LINUX_EINVAL;
    }
    LINUX_EOPNOTSUPP
}

/// lsm_list_modules: the active modules' ids; `size` gets the bytes the
/// list takes, and a smaller buffer is E2BIG.
pub(super) fn linux_lsm_list_modules(identifiers: u64, size: u64, flags: u64) -> u64 {
    if flags as u32 != 0 {
        return LINUX_EINVAL;
    }
    let mut available = [0_u8; 4];
    let total = (LINUX_LSM_IDS.len() * size_of::<u64>()) as u32;
    if !copy_from_linux_user(size, &mut available)
        || !copy_to_linux_user(size, &total.to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    if u32::from_ne_bytes(available) < total {
        return LINUX_E2BIG;
    }
    for (index, identifier) in LINUX_LSM_IDS.iter().enumerate() {
        if !copy_to_linux_user(identifiers + 8 * index as u64, &identifier.to_ne_bytes()) {
            return LINUX_EFAULT;
        }
    }
    LINUX_LSM_IDS.len() as u64
}

fn linux_landlock_error(error: ginux_landlock::Error) -> u64 {
    error.errno().wrapping_neg()
}

/// The current process, as `crate::linux_landlock` names processes.
fn linux_landlock_process() -> (usize, u32) {
    (linux_execution_instance(), current_linux_process_pid())
}

/// The ruleset `descriptor` stands for: EBADF when it is not open, EBADFD
/// when it is no ruleset.
fn linux_landlock_ruleset(descriptor: u64) -> Result<u64, u64> {
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return Err(LINUX_EBADF);
    }
    match linux_object_descriptor(descriptor) {
        Some((crate::linux_landlock::CLASS_RULESET, id)) => Ok(id),
        _ => Err(LINUX_EBADFD),
    }
}

/// Whether `descriptor` is a Landlock ruleset.
pub(super) fn linux_landlock_ruleset_descriptor(descriptor: u64) -> bool {
    linux_object_descriptor(descriptor)
        .is_some_and(|(class, _)| class == crate::linux_landlock::CLASS_RULESET)
}

/// landlock_create_ruleset(2), with Linux's checks in Linux's order; with
/// LANDLOCK_CREATE_RULESET_VERSION alone, the ABI version.
pub(super) fn linux_landlock_create_ruleset(attribute: u64, size: u64, flags: u64) -> u64 {
    const LANDLOCK_CREATE_RULESET_VERSION: u64 = 1;
    /// handled_access_fs, the one field every ABI version has.
    const MINIMUM_SIZE: u64 = 8;
    /// handled_access_fs, handled_access_net, scoped.
    const KNOWN_SIZE: usize = 24;
    let flags = u64::from(flags as u32);
    if flags != 0 {
        return if flags == LANDLOCK_CREATE_RULESET_VERSION && attribute == 0 && size == 0 {
            u64::from(ginux_landlock::ABI_VERSION)
        } else {
            LINUX_EINVAL
        };
    }
    if attribute == 0 {
        return LINUX_EFAULT;
    }
    if size < MINIMUM_SIZE {
        return LINUX_EINVAL;
    }
    if size > PAGE_SIZE as u64 {
        return LINUX_E2BIG;
    }
    let size = size as usize;
    // A newer program's longer struct is fine while what this kernel does
    // not know of is zero.
    if size > KNOWN_SIZE {
        let mut rest = [0_u8; PAGE_SIZE];
        let rest = &mut rest[..size - KNOWN_SIZE];
        if !copy_from_linux_user(attribute + KNOWN_SIZE as u64, rest) {
            return LINUX_EFAULT;
        }
        if rest.iter().any(|byte| *byte != 0) {
            return LINUX_E2BIG;
        }
    }
    let mut bytes = [0_u8; KNOWN_SIZE];
    if !copy_from_linux_user(attribute, &mut bytes[..size.min(KNOWN_SIZE)]) {
        return LINUX_EFAULT;
    }
    let field = |offset: usize| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let id = match crate::linux_landlock::create(field(0), field(8), field(16)) {
        Ok(id) => id,
        Err(error) => return linux_landlock_error(error),
    };
    match crate::linux_socket::open_object(crate::linux_landlock::CLASS_RULESET, id) {
        Ok(slot) => linux_install_object_descriptor(slot, LINUX_O_CLOEXEC),
        Err(_) => {
            crate::linux_landlock::release(crate::linux_landlock::CLASS_RULESET, id);
            LINUX_ENOMEM
        }
    }
}

/// landlock_add_rule(2): a path-beneath rule (LANDLOCK_RULE_PATH_BENEATH)
/// or a TCP port rule (LANDLOCK_RULE_NET_PORT), checked as Linux does.
pub(super) fn linux_landlock_add_rule(
    descriptor: u64,
    rule_type: u64,
    attribute: u64,
    flags: u64,
) -> u64 {
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const LANDLOCK_RULE_NET_PORT: u32 = 2;
    if flags as u32 != 0 {
        return LINUX_EINVAL;
    }
    let id = match linux_landlock_ruleset(descriptor) {
        Ok(id) => id,
        Err(error) => return error,
    };
    let result = match rule_type as u32 {
        LANDLOCK_RULE_PATH_BENEATH => {
            // struct landlock_path_beneath_attr is packed: allowed_access,
            // then parent_fd.
            let mut rule = [0_u8; 12];
            if !copy_from_linux_user(attribute, &mut rule) {
                return LINUX_EFAULT;
            }
            let allowed = u64::from_ne_bytes(rule[..8].try_into().unwrap());
            let parent = i32::from_ne_bytes(rule[8..].try_into().unwrap());
            if let Err(error) = crate::linux_landlock::check_path_rule(id, allowed) {
                return linux_landlock_error(error);
            }
            let (path, length, directory) = match linux_landlock_rule_file(parent) {
                Ok(file) => file,
                Err(error) => return error,
            };
            crate::linux_landlock::add_path(id, &path[..length], directory, allowed)
        }
        LANDLOCK_RULE_NET_PORT => {
            let mut rule = [0_u8; 16];
            if !copy_from_linux_user(attribute, &mut rule) {
                return LINUX_EFAULT;
            }
            let allowed = u64::from_ne_bytes(rule[..8].try_into().unwrap());
            let port = u64::from_ne_bytes(rule[8..].try_into().unwrap());
            crate::linux_landlock::add_port(id, port, allowed)
        }
        _ => return LINUX_EINVAL,
    };
    result.map_or_else(linux_landlock_error, |()| 0)
}

/// The file a path-beneath rule names by descriptor `parent` (O_PATH ones
/// too): its canonical path and whether it is a directory. Not open is
/// EBADF; a ruleset, pipe, socket or other file of no filesystem EBADFD.
fn linux_landlock_rule_file(
    parent: i32,
) -> Result<([u8; crate::linux_overlay::PATH_CAPACITY], usize, bool), u64> {
    let descriptor = u64::try_from(parent).map_err(|_| LINUX_EBADF)?;
    if !linux_descriptor_open(descriptor) {
        return Err(LINUX_EBADF);
    }
    if linux_landlock_ruleset_descriptor(descriptor) {
        return Err(LINUX_EBADFD);
    }
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_descriptor_path(descriptor, &mut path)
        .or_else(|| linux_descriptor_link_target(descriptor, &mut path))
        .filter(|length| path[..*length].starts_with(b"/"))
        .ok_or(LINUX_EBADFD)?;
    path.copy_within(1..length, 0);
    let length = length - 1;
    let directory = linux_descriptor_stat(descriptor).map_or_else(
        || linux_inotify_is_directory(&path[..length]),
        |stat| u32::from_ne_bytes(stat[24..28].try_into().unwrap()) & S_IFMT == S_IFDIR,
    );
    Ok((path, length, directory))
}

/// landlock_restrict_self(2): stacks ruleset `descriptor` on the calling
/// process's domain. It takes no_new_privs or CAP_SYS_ADMIN, so that a
/// sandbox cannot confuse a privileged program it starts.
pub(super) fn linux_landlock_restrict_self(descriptor: u64, flags: u64) -> u64 {
    if !X86_RUNTIME.ELF_PROBE_NO_NEW_PRIVS.load(Ordering::SeqCst)
        && !linux_has_capability(ginux_credentials::capability::SYS_ADMIN)
    {
        return LINUX_EPERM;
    }
    if flags as u32 != 0 {
        return LINUX_EINVAL;
    }
    let id = match linux_landlock_ruleset(descriptor) {
        Ok(id) => id,
        Err(error) => return error,
    };
    let (instance, pid) = linux_landlock_process();
    crate::linux_landlock::restrict(instance, pid, id).map_or_else(linux_landlock_error, |()| 0)
}

/// EACCES unless Landlock lets the current process have `access` (the
/// filesystem rights) on canonical `path`.
pub(super) fn linux_landlock_check(path: &[u8], access: u64) -> Result<(), u64> {
    let (instance, pid) = linux_landlock_process();
    if crate::linux_landlock::allows_path(instance, pid, path, access) {
        Ok(())
    } else {
        Err(LINUX_EACCES)
    }
}

/// Whether the current process is restricted by Landlock at all.
fn linux_landlock_restricted() -> bool {
    let (instance, pid) = linux_landlock_process();
    crate::linux_landlock::is_restricted(instance, pid)
}

/// The file type (S_IFMT bits) of canonical `path` as the overlay or the
/// image has it; None for the kernel's virtual files.
fn linux_landlock_file_type(path: &[u8]) -> Option<u32> {
    use crate::linux_overlay::NodeKind;
    if path.is_empty() {
        return Some(S_IFDIR);
    }
    if let Some(metadata) = crate::linux_overlay::lookup(path) {
        return Some(match metadata.kind {
            NodeKind::File => S_IFREG,
            NodeKind::Directory => S_IFDIR,
            NodeKind::Symlink => 0o120_000,
            NodeKind::Fifo => 0o010_000,
            NodeKind::Socket => 0o140_000,
            NodeKind::CharacterDevice => S_IFCHR,
            NodeKind::BlockDevice => S_IFBLK,
        });
    }
    let image = crate::linux_overlay::image_path(path)?;
    let (_, entry) =
        crate::published_rootfs::lookup_metadata_at(crate::published_rootfs::ROOT_HANDLE, &image)?;
    Some(match entry.map(|entry| entry.kind) {
        None | Some(crate::published_rootfs::EntryKind::Directory) => S_IFDIR,
        Some(crate::published_rootfs::EntryKind::Symlink) => 0o120_000,
        Some(_) => S_IFREG,
    })
}

/// The rights a file of type `file_type` has as a rename or link moves it
/// (Landlock's file rights for anything but a directory).
fn linux_landlock_moved_rights(file_type: u32) -> u64 {
    if file_type == S_IFDIR {
        landlock::FS_ALL
    } else {
        landlock::FS_FILE
    }
}

/// Landlock's check of an open of canonical `path` (after any symlinks)
/// with `flags`: making it (LANDLOCK_ACCESS_FS_MAKE_REG on its directory)
/// when it does not `exist` and O_CREAT asks, then reading (READ_FILE, or
/// READ_DIR for a directory) and writing (WRITE_FILE) it, and truncating
/// an existing regular file with O_TRUNC (TRUNCATE). `truncating` is
/// truncate(2)'s open, which needs TRUNCATE rather than WRITE_FILE. O_PATH
/// opens nothing, so is not checked.
pub(super) fn linux_landlock_check_open(
    path: &[u8],
    flags: u64,
    exists: bool,
    truncating: bool,
) -> Result<(), u64> {
    if flags & LINUX_O_PATH != 0 || !linux_landlock_restricted() {
        return Ok(());
    }
    if !exists && flags & LINUX_O_CREAT != 0 {
        linux_landlock_check(linux_parent_path(path), landlock::FS_MAKE_REG)?;
    }
    let file_type = linux_landlock_file_type(path);
    let directory = flags & LINUX_O_DIRECTORY != 0 || file_type == Some(S_IFDIR);
    let read = if directory {
        landlock::FS_READ_DIR
    } else {
        landlock::FS_READ_FILE
    };
    let mut access = match flags & LINUX_O_ACCMODE {
        0 => read,
        1 => landlock::FS_WRITE_FILE,
        _ => read | landlock::FS_WRITE_FILE,
    };
    if truncating {
        access = (access & !landlock::FS_WRITE_FILE) | landlock::FS_TRUNCATE;
    } else if exists && flags & LINUX_O_TRUNC != 0 && file_type == Some(S_IFREG) {
        access |= landlock::FS_TRUNCATE;
    }
    linux_landlock_check(path, access)
}

/// After an open of descriptor `opened` (or its error) by a restricted
/// process: marks what Landlock let it do with the file then, as Linux
/// decides at open, truncate a regular file and ioctl a device.
pub(super) fn linux_landlock_opened(opened: u64, flags: u64) -> u64 {
    if opened >= LINUX_RETURN_TO_KERNEL || flags & LINUX_O_PATH != 0 || !linux_landlock_restricted()
    {
        return opened;
    }
    let Some(mode) = linux_descriptor_stat(opened)
        .map(|stat| u32::from_ne_bytes(stat[24..28].try_into().unwrap()) & S_IFMT)
    else {
        return opened;
    };
    let (right, mark) = match mode {
        S_IFREG => (landlock::FS_TRUNCATE, LINUX_PRIVATE_LANDLOCK_NO_TRUNCATE),
        S_IFCHR | S_IFBLK => (landlock::FS_IOCTL_DEV, LINUX_PRIVATE_LANDLOCK_NO_IOCTL),
        _ => return opened,
    };
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let Some(length) = linux_descriptor_path(opened, &mut path)
        .or_else(|| linux_descriptor_link_target(opened, &mut path))
        .filter(|length| path[..*length].starts_with(b"/"))
    else {
        return opened;
    };
    if linux_landlock_check(&path[1..length], right).is_err() {
        linux_landlock_mark_descriptor(opened, mark);
    }
    opened
}

fn linux_landlock_mark_descriptor(descriptor: u64, mark: u32) {
    let flags = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS.get(index))
        .or_else(|| {
            X86_RUNTIME
                .ELF_PROBE_SOCKET_FLAGS
                .get(linux_socket_descriptor_index(descriptor)?)
        });
    if let Some(flags) = flags {
        flags.fetch_or(mark, Ordering::SeqCst);
    }
}

fn linux_landlock_marked(descriptor: u64, mark: u32) -> bool {
    linux_socket_flags(descriptor).is_some_and(|flags| flags & mark != 0)
}

/// ftruncate(2) of `descriptor`: EACCES when Landlock did not let its
/// opener truncate the file.
pub(super) fn linux_landlock_check_ftruncate(descriptor: u64) -> Result<(), u64> {
    if linux_landlock_marked(descriptor, LINUX_PRIVATE_LANDLOCK_NO_TRUNCATE) {
        Err(LINUX_EACCES)
    } else {
        Ok(())
    }
}

/// ioctl(2) `request` on `descriptor`: EACCES on a device Landlock did not
/// let its opener ioctl (LANDLOCK_ACCESS_FS_IOCTL_DEV), but for the
/// commands Linux leaves to every file: close-on-exec, non-blocking and
/// async mode, the queue size, and those about the filesystem rather than
/// the device.
pub(super) fn linux_landlock_check_ioctl(descriptor: u64, request: u64) -> Result<(), u64> {
    const ANY_FILE: [u32; 14] = [
        0x5451,      // FIOCLEX
        0x5450,      // FIONCLEX
        0x5421,      // FIONBIO
        0x5452,      // FIOASYNC
        0x5460,      // FIOQSIZE
        0xc004_5877, // FIFREEZE
        0xc004_5878, // FITHAW
        0xc020_660b, // FS_IOC_FIEMAP
        0x0002,      // FIGETBSZ
        0x4004_9409, // FICLONE
        0x4020_940d, // FICLONERANGE
        0xc018_9436, // FIDEDUPERANGE
        0x8011_1500, // FS_IOC_GETFSUUID
        0x8081_1501, // FS_IOC_GETFSSYSFSPATH
    ];
    if linux_landlock_marked(descriptor, LINUX_PRIVATE_LANDLOCK_NO_IOCTL)
        && !ANY_FILE.contains(&(request as u32))
    {
        Err(LINUX_EACCES)
    } else {
        Ok(())
    }
}

/// Landlock's check of making a node of type `mode` (S_IFMT bits; 0 is a
/// regular file) at canonical `path`.
pub(super) fn linux_landlock_check_make(path: &[u8], mode: u32) -> Result<(), u64> {
    linux_landlock_check(linux_parent_path(path), ginux_landlock::make_right(mode))
}

/// Landlock's check of unlink (`directory` false) or rmdir of canonical
/// `path`, an existing name.
pub(super) fn linux_landlock_check_remove(path: &[u8], directory: bool) -> Result<(), u64> {
    linux_landlock_check(
        linux_parent_path(path),
        ginux_landlock::remove_right(directory),
    )
}

/// Landlock's check of a hard link to canonical `old` named `new`.
pub(super) fn linux_landlock_check_link(old: &[u8], new: &[u8]) -> Result<(), u64> {
    let file_type = linux_landlock_file_type(old).unwrap_or(S_IFREG);
    linux_landlock_check_move(
        old,
        new,
        0,
        ginux_landlock::make_right(file_type),
        linux_landlock_moved_rights(file_type),
    )
}

/// Landlock's check of renaming canonical `old` to `new` (swapping them
/// with RENAME_EXCHANGE): removing each name from its directory and making
/// it in the other (EACCES), then, between directories, the move itself
/// (LANDLOCK_ACCESS_FS_REFER, and no right gained: EXDEV).
pub(super) fn linux_landlock_check_rename(
    old: &[u8],
    new: &[u8],
    exchange: bool,
) -> Result<(), u64> {
    if !linux_landlock_restricted() {
        return Ok(());
    }
    let old_type = linux_landlock_file_type(old).unwrap_or(S_IFREG);
    let new_type = linux_landlock_file_type(new);
    let removal = |file_type: u32| ginux_landlock::remove_right(file_type == S_IFDIR);
    let mut from_access = removal(old_type);
    let mut to_access = ginux_landlock::make_right(old_type);
    if let Some(new_type) = new_type {
        to_access |= removal(new_type);
        if exchange {
            from_access |= ginux_landlock::make_right(new_type);
        }
    }
    linux_landlock_check_move(
        old,
        new,
        from_access,
        to_access,
        linux_landlock_moved_rights(old_type),
    )?;
    match new_type {
        Some(new_type) if exchange && linux_parent_path(old) != linux_parent_path(new) => {
            linux_landlock_check_move(new, old, 0, 0, linux_landlock_moved_rights(new_type))
        }
        _ => Ok(()),
    }
}

fn linux_landlock_check_move(
    old: &[u8],
    new: &[u8],
    removal: u64,
    making: u64,
    file_rights: u64,
) -> Result<(), u64> {
    let (instance, pid) = linux_landlock_process();
    crate::linux_landlock::check_move(
        instance,
        pid,
        linux_parent_path(old),
        linux_parent_path(new),
        removal,
        making,
        file_rights,
    )
    .map_err(|denial| match denial {
        ginux_landlock::Denial::Access => LINUX_EACCES,
        ginux_landlock::Denial::Reparent => LINUX_EXDEV,
    })
}

/// Executing canonical `path` takes LANDLOCK_ACCESS_FS_EXECUTE and, as
/// the file is opened for reading to load it, READ_FILE.
pub(super) fn linux_landlock_check_execute(path: &[u8]) -> Result<(), u64> {
    linux_landlock_check(path, landlock::FS_EXECUTE | landlock::FS_READ_FILE)
}

/// mount, umount and pivot_root: EPERM for a process whose domain handles
/// any filesystem right, which a changed mount would let it escape.
pub(super) fn linux_landlock_check_mount() -> Result<(), u64> {
    let (instance, pid) = linux_landlock_process();
    if crate::linux_landlock::restricts_filesystem(instance, pid) {
        Err(LINUX_EPERM)
    } else {
        Ok(())
    }
}

/// Binding (`connect` false) or connecting a TCP socket to `port`:
/// EACCES unless the domain's port rules allow it.
pub(super) fn linux_landlock_check_port(port: u16, connect: bool) -> Result<(), u64> {
    let access = if connect {
        landlock::NET_CONNECT_TCP
    } else {
        landlock::NET_BIND_TCP
    };
    let (instance, pid) = linux_landlock_process();
    if crate::linux_landlock::allows_port(instance, pid, port, access) {
        Ok(())
    } else {
        Err(LINUX_EACCES)
    }
}

/// Unix socket `slot` was bound to the abstract name `path` (a leading
/// NUL): connects to it are judged by the binder's domain.
pub(super) fn linux_landlock_bound_unix(slot: crate::linux_socket::SlotId, path: &[u8]) {
    if path.first() == Some(&0) {
        let (instance, pid) = linux_landlock_process();
        crate::linux_landlock::bound_abstract(instance, pid, slot);
    }
}

/// Connecting or sending to `target`, bound to the abstract name `path`:
/// EPERM when the caller's domain scopes abstract Unix sockets and the
/// binder is outside it (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET).
pub(super) fn linux_landlock_check_unix_peer(
    target: crate::linux_socket::SlotId,
    path: &[u8],
) -> Result<(), u64> {
    if path.first() != Some(&0) {
        return Ok(());
    }
    let (instance, pid) = linux_landlock_process();
    if crate::linux_landlock::may_reach_socket(instance, pid, target) {
        Ok(())
    } else {
        Err(LINUX_EPERM)
    }
}

/// Whether the current process may signal process `target`
/// (LANDLOCK_SCOPE_SIGNAL).
pub(super) fn linux_landlock_may_signal(target: u32) -> bool {
    let (instance, pid) = linux_landlock_process();
    crate::linux_landlock::may_signal(instance, pid, target)
}

/// A forked `child` gets its parent's domain.
pub(super) fn linux_landlock_fork(parent: u32, child: u32) -> bool {
    crate::linux_landlock::fork(linux_execution_instance(), parent, child)
}

/// Process `pid` was reaped (or killed with its domain): its domain goes.
/// A zombie keeps it, as Linux's keeps its credentials, so a signal to it
/// is judged as before. Skipped (left to the next fork that reuses the id)
/// when a lock ranked above Landlock's is held.
pub(super) fn linux_landlock_exit(pid: u32) {
    if crate::sync::rank_available(crate::sync::LockRank::LANDLOCK) {
        crate::linux_landlock::exit(linux_execution_instance(), pid);
    }
}

/// The boot check of the calls that have no effect: the ABI version, and
/// Linux's first errors.
pub(super) fn verify_linux_landlock_syscalls() -> bool {
    linux_landlock_create_ruleset(0, 0, 1) == u64::from(ginux_landlock::ABI_VERSION)
        && linux_landlock_create_ruleset(0, 0, 3) == LINUX_EINVAL
        && linux_landlock_create_ruleset(0, 8, 0) == LINUX_EFAULT
        && linux_landlock_add_rule(0, 1, 0, 1) == LINUX_EINVAL
        && linux_landlock_restrict_self(u64::MAX, 1) != 0
}
