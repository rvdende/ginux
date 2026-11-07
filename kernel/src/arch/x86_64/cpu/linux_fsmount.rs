//! The new mount API for Linux processes (`crate::linux_fscontext` keeps
//! its objects): fsopen(2), fsconfig(2) and fspick(2) on filesystem
//! contexts, fsmount(2) and open_tree(2) making detached mounts, and
//! move_mount(2) attaching or moving them. The checks and their order are
//! Linux's (fs/fsopen.c, fs/namespace.c); what is mounted goes through the
//! same paths as mount(2).

use super::*;

use crate::linux_fscontext::{self as fscontext, Phase, Tree, Value};

const FSCONFIG_SET_FLAG: u32 = 0;
const FSCONFIG_SET_STRING: u32 = 1;
const FSCONFIG_SET_BINARY: u32 = 2;
const FSCONFIG_SET_PATH: u32 = 3;
const FSCONFIG_SET_PATH_EMPTY: u32 = 4;
const FSCONFIG_SET_FD: u32 = 5;
const FSCONFIG_CMD_CREATE: u32 = 6;
const FSCONFIG_CMD_RECONFIGURE: u32 = 7;
const FSCONFIG_CMD_CREATE_EXCL: u32 = 8;

const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const MOUNT_ATTR_ATIME: u64 = 0x70;
const MOUNT_ATTR_RELATIME: u64 = 0x0;
const MOUNT_ATTR_NOATIME: u64 = 0x10;
const MOUNT_ATTR_STRICTATIME: u64 = 0x20;
const MOUNT_ATTR_NODIRATIME: u64 = 0x80;
const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x20_0000;

const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_NO_AUTOMOUNT: u64 = 0x800;
const AT_EMPTY_PATH: u64 = 0x1000;
const AT_RECURSIVE: u64 = 0x8000;

/// The longest key and string value fsconfig takes, with its NUL.
const PARAMETER_CAPACITY: usize = 256;

/// May the caller mount: CAP_SYS_ADMIN in a domain that lets it manage
/// mounts (Linux's may_mount).
fn linux_may_mount() -> bool {
    current_container_slot().is_some()
        && linux_privileged_operation_allowed(linux_user::PrivilegedOperation::ManageMounts)
        && linux_has_capability(ginux_credentials::capability::SYS_ADMIN)
}

/// The filesystem context a descriptor is open on.
pub(super) fn linux_fs_context_descriptor(descriptor: u64) -> Option<u64> {
    match linux_object_descriptor(descriptor)? {
        (fscontext::CLASS_CONTEXT, id) => Some(id),
        _ => None,
    }
}

/// The detached mount a descriptor (of fsmount or open_tree) is open on.
pub(super) fn linux_detached_mount_descriptor(descriptor: u64) -> Option<u64> {
    match linux_object_descriptor(descriptor)? {
        (fscontext::CLASS_MOUNT, id) => Some(id),
        _ => None,
    }
}

/// The canonical path (no leading slash) of the file `descriptor` is open
/// on, into `output`.
pub(super) fn linux_descriptor_canonical(
    descriptor: u64,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Option<usize> {
    let mut absolute = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = linux_descriptor_path(descriptor, &mut absolute)?;
    let relative = absolute[..length]
        .strip_prefix(b"/")
        .unwrap_or(&absolute[..length]);
    output.get_mut(..relative.len())?.copy_from_slice(relative);
    Some(relative.len())
}

/// A descriptor for object `class`/`id` of this module, or the error with
/// the object dropped.
fn linux_install_mount_object(class: u8, id: u64, close_on_exec: bool) -> u64 {
    let flags = if close_on_exec { LINUX_O_CLOEXEC } else { 0 };
    match crate::linux_socket::open_object(class, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags),
        Err(_) => {
            fscontext::release(class, id);
            LINUX_ENOMEM
        }
    }
}

/// What a path argument of these calls names.
enum LinuxMountPath {
    /// A canonical path, of this length in the caller's buffer.
    Path(usize),
    /// A detached mount, by its descriptor.
    Detached(u64),
}

/// Resolves the path at `address` relative to `directory` as these calls
/// look paths up: an empty one names `directory` itself when `empty`
/// (AT_EMPTY_PATH and its kin), the last symlink is followed when
/// `follow`, and the path must exist.
fn linux_mount_api_path(
    directory: u64,
    address: u64,
    empty: bool,
    follow: bool,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Result<LinuxMountPath, u64> {
    let directory = u64::from(directory as u32);
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(address, &mut path)?;
    let path = &path[..length];
    if path.is_empty() {
        if !empty {
            return Err(LINUX_ENOENT);
        }
        if directory as u32 == LINUX_AT_FDCWD {
            return linux_walk_start(directory, output).map(LinuxMountPath::Path);
        }
        if !linux_descriptor_open(directory) {
            return Err(LINUX_EBADF);
        }
        if let Some(id) = linux_detached_mount_descriptor(directory) {
            return Ok(LinuxMountPath::Detached(id));
        }
        return linux_descriptor_canonical(directory, output)
            .map(LinuxMountPath::Path)
            .ok_or(LINUX_EBADF);
    }
    // Nothing lies below a detached mount's root here.
    if !path.starts_with(b"/") && directory as u32 != LINUX_AT_FDCWD {
        if let Some(id) = linux_detached_mount_descriptor(directory) {
            return if path == b"." {
                Ok(LinuxMountPath::Detached(id))
            } else {
                Err(LINUX_ENOENT)
            };
        }
    }
    let mut length = match linux_canonical_path_at(directory, path, output) {
        Ok(length) => length,
        Err(LINUX_EISDIR) => 0,
        Err(error) => return Err(error),
    };
    if follow && length != 0 {
        length = linux_overlay_lookup_following(output, length, true)?.0;
    }
    let canonical = &output[..length];
    if linux_path_access(canonical).is_none()
        && !linux_kernel_mount_point(canonical)
        && !linux_api_directory(canonical)
    {
        return Err(linux_missing_path_error(canonical));
    }
    Ok(LinuxMountPath::Path(length))
}

/// The domain mount options (`crate::linux_mounts`) of mount attributes
/// (MOUNT_ATTR_*), whose atime part is one of relatime, noatime and
/// strictatime.
fn linux_mount_attribute_flags(attributes: u64) -> u32 {
    let mut flags = [
        (MOUNT_ATTR_RDONLY, crate::linux_mounts::READ_ONLY),
        (MOUNT_ATTR_NOSUID, crate::linux_mounts::NO_SUID),
        (MOUNT_ATTR_NODEV, crate::linux_mounts::NO_DEVICES),
        (MOUNT_ATTR_NOEXEC, crate::linux_mounts::NO_EXEC),
        (MOUNT_ATTR_NODIRATIME, crate::linux_mounts::NO_DIRATIME),
        (MOUNT_ATTR_NOSYMFOLLOW, crate::linux_mounts::NO_SYMFOLLOW),
    ]
    .into_iter()
    .filter(|(attribute, _)| attributes & attribute != 0)
    .fold(0, |flags, (_, flag)| flags | flag);
    match attributes & MOUNT_ATTR_ATIME {
        MOUNT_ATTR_NOATIME => flags |= crate::linux_mounts::NO_ATIME,
        MOUNT_ATTR_STRICTATIME => flags |= crate::linux_mounts::STRICT_ATIME,
        _ => {}
    }
    flags
}

/// fsopen(2): a context for a new filesystem of the type named at
/// `name_address`.
pub(super) fn linux_fsopen(name_address: u64, flags: u64) -> u64 {
    const FSOPEN_CLOEXEC: u64 = 1;
    if !linux_may_mount() {
        return LINUX_EPERM;
    }
    let flags = u64::from(flags as u32);
    if flags & !FSOPEN_CLOEXEC != 0 {
        return LINUX_EINVAL;
    }
    let mut name = [0_u8; PAGE_SIZE];
    let length = match copy_linux_c_string(name_address, &mut name) {
        Ok(length) => length,
        Err(LINUX_ENAMETOOLONG) => return LINUX_EINVAL,
        Err(error) => return error,
    };
    let name = &name[..length];
    if !linux_mountable_filesystem(name) {
        return LINUX_ENODEV;
    }
    match fscontext::open(linux_execution_instance(), name) {
        Ok(id) => {
            linux_install_mount_object(fscontext::CLASS_CONTEXT, id, flags & FSOPEN_CLOEXEC != 0)
        }
        Err(_) => LINUX_ENOMEM,
    }
}

/// fspick(2): a context to reconfigure the filesystem mounted at a path,
/// which must be a mount's root.
pub(super) fn linux_fspick(directory: u64, path_address: u64, flags: u64) -> u64 {
    const FSPICK_CLOEXEC: u64 = 1;
    const FSPICK_SYMLINK_NOFOLLOW: u64 = 2;
    const FSPICK_NO_AUTOMOUNT: u64 = 4;
    const FSPICK_EMPTY_PATH: u64 = 8;
    if !linux_may_mount() {
        return LINUX_EPERM;
    }
    let flags = u64::from(flags as u32);
    if flags & !(FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH)
        != 0
    {
        return LINUX_EINVAL;
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_mount_api_path(
        directory,
        path_address,
        flags & FSPICK_EMPTY_PATH != 0,
        flags & FSPICK_SYMLINK_NOFOLLOW == 0,
        &mut canonical,
    ) {
        Ok(LinuxMountPath::Path(length)) => length,
        // The root of a detached mount: nothing here to reconfigure.
        Ok(LinuxMountPath::Detached(_)) => return LINUX_EINVAL,
        Err(error) => return error,
    };
    let path = &canonical[..length];
    let space = linux_mount_space();
    let filesystem = match crate::linux_mounts::topmost_id(space, path) {
        Some(id) => crate::linux_mounts::with_mount(space, id, |mount| {
            let mut name = [0_u8; 32];
            let length = mount.filesystem.len().min(name.len());
            name[..length].copy_from_slice(&mount.filesystem[..length]);
            (name, length)
        }),
        None if linux_kernel_mount_point(path) => {
            let kernel = linux_kernel_filesystem(path).filesystem;
            let mut name = [0_u8; 32];
            name[..kernel.len()].copy_from_slice(kernel);
            Some((name, kernel.len()))
        }
        None => return LINUX_EINVAL,
    };
    let Some((name, name_length)) = filesystem else {
        return LINUX_EINVAL;
    };
    match fscontext::pick(linux_execution_instance(), &name[..name_length], path) {
        Ok(id) => {
            linux_install_mount_object(fscontext::CLASS_CONTEXT, id, flags & FSPICK_CLOEXEC != 0)
        }
        Err(_) => LINUX_ENOMEM,
    }
}

/// fsconfig(2): sets a parameter of a context, or makes or reconfigures
/// its filesystem.
pub(super) fn linux_fsconfig(
    descriptor: u64,
    command: u64,
    key_address: u64,
    value_address: u64,
    auxiliary: u64,
) -> u64 {
    let descriptor = descriptor as u32 as i32;
    let command = command as u32;
    let auxiliary = auxiliary as u32 as i32;
    if descriptor < 0 {
        return LINUX_EINVAL;
    }
    let (key, value) = (key_address != 0, value_address != 0);
    let valid = match command {
        FSCONFIG_SET_FLAG => key && !value && auxiliary == 0,
        FSCONFIG_SET_STRING => key && value && auxiliary == 0,
        FSCONFIG_SET_BINARY => key && value && auxiliary > 0 && auxiliary <= 1024 * 1024,
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            key && value && (auxiliary == LINUX_AT_FDCWD as i32 || auxiliary >= 0)
        }
        FSCONFIG_SET_FD => key && !value && auxiliary >= 0,
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL | FSCONFIG_CMD_RECONFIGURE => {
            !key && !value && auxiliary == 0
        }
        _ => return LINUX_EOPNOTSUPP,
    };
    if !valid {
        return LINUX_EINVAL;
    }
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let Some(id) = linux_fs_context_descriptor(descriptor) else {
        return LINUX_EINVAL;
    };
    let Some(legacy) =
        fscontext::with_context(id, |context| fscontext::legacy(&context.filesystem))
    else {
        return LINUX_EBADF;
    };
    // The legacy interface takes flags and strings only, and no exclusive
    // create.
    if legacy
        && matches!(
            command,
            FSCONFIG_SET_BINARY
                | FSCONFIG_SET_PATH
                | FSCONFIG_SET_PATH_EMPTY
                | FSCONFIG_SET_FD
                | FSCONFIG_CMD_CREATE_EXCL
        )
    {
        return LINUX_EOPNOTSUPP;
    }
    let mut key = [0_u8; PARAMETER_CAPACITY];
    let key_length = if key_address != 0 {
        match copy_linux_c_string(key_address, &mut key) {
            Ok(length) => length,
            Err(LINUX_ENAMETOOLONG) => return LINUX_EINVAL,
            Err(error) => return error,
        }
    } else {
        0
    };
    let key = &key[..key_length];
    let mut string = [0_u8; PARAMETER_CAPACITY];
    let value = match command {
        FSCONFIG_SET_FLAG => Value::Flag,
        FSCONFIG_SET_STRING => match copy_linux_c_string(value_address, &mut string) {
            Ok(length) => Value::String(&string[..length]),
            Err(LINUX_ENAMETOOLONG) => return LINUX_EINVAL,
            Err(error) => return error,
        },
        FSCONFIG_SET_BINARY => {
            // The blob must be readable; no parameter here takes one.
            let mut chunk = [0_u8; 256];
            let size = auxiliary as u64;
            let mut offset = 0;
            while offset < size {
                let length = (size - offset).min(chunk.len() as u64) as usize;
                if !copy_from_linux_user(value_address + offset, &mut chunk[..length]) {
                    return LINUX_EFAULT;
                }
                offset += length as u64;
            }
            Value::Other
        }
        FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            let mut path = [0_u8; LINUX_PATH_MAX];
            match copy_linux_c_string(value_address, &mut path) {
                Ok(0) if command == FSCONFIG_SET_PATH => return LINUX_ENOENT,
                Ok(_) => Value::Other,
                Err(error) => return error,
            }
        }
        FSCONFIG_SET_FD => {
            if !linux_descriptor_open(u64::from(auxiliary as u32)) {
                return LINUX_EBADF;
            }
            Value::Other
        }
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => return linux_fs_context_create(id),
        _ => return linux_fs_context_reconfigure(id),
    };
    match fscontext::set(id, key, value) {
        Ok(()) => 0,
        Err(fscontext::Error::Invalid) => LINUX_EINVAL,
        Err(fscontext::Error::Busy) => LINUX_EBUSY,
        Err(fscontext::Error::NoMemory) => LINUX_ENOMEM,
        Err(fscontext::Error::Gone) => LINUX_EBADF,
    }
}

/// FSCONFIG_CMD_CREATE: makes the context's filesystem, which here means
/// checking that it can be: a volume's device must be a free block device,
/// an overlay's layers must be there. The mount itself is made when
/// move_mount attaches what fsmount makes of it.
fn linux_fs_context_create(id: u64) -> u64 {
    let Some((phase, filesystem, source, data)) = fscontext::with_context(id, |context| {
        (
            context.phase,
            context.filesystem.clone(),
            context.source.clone(),
            context.data.clone(),
        )
    }) else {
        return LINUX_EBADF;
    };
    if phase != Phase::Create {
        return LINUX_EBUSY;
    }
    let checked = match filesystem.as_slice() {
        b"ext2" | b"ext3" | b"ext4" => match source {
            None => Err(LINUX_EINVAL),
            Some(source) => {
                let mut name = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
                linux_volume_device(&source, &mut name).and_then(|(device, _)| {
                    if crate::linux_blockfs::device_mounted(device) {
                        Err(LINUX_EBUSY)
                    } else {
                        Ok(())
                    }
                })
            }
        },
        b"overlay" => linux_overlayfs_check(&data),
        _ => Ok(()),
    };
    match checked {
        Ok(()) => {
            fscontext::set_phase(id, Phase::AwaitingMount);
            0
        }
        Err(error) => {
            fscontext::set_phase(id, Phase::Failed);
            error
        }
    }
}

/// FSCONFIG_CMD_RECONFIGURE: applies the context's "ro" or "rw" to the
/// filesystem fspick chose.
fn linux_fs_context_reconfigure(id: u64) -> u64 {
    let Some((phase, picked, read_only)) = fscontext::with_context(id, |context| {
        (context.phase, context.picked.clone(), context.read_only)
    }) else {
        return LINUX_EBADF;
    };
    if phase != Phase::Reconfigure {
        return LINUX_EBUSY;
    }
    if !linux_has_capability(ginux_credentials::capability::SYS_ADMIN) {
        fscontext::set_phase(id, Phase::Failed);
        return LINUX_EPERM;
    }
    if let (Some(path), Some(read_only)) = (picked, read_only) {
        let result = linux_remount_read_only(&path, read_only);
        if result != 0 {
            fscontext::set_phase(id, Phase::Failed);
            return result;
        }
    }
    fscontext::clean(id);
    0
}

/// Makes the filesystem mounted at canonical `path` read-only or
/// writable, as a remount does: a volume with a file open for writing
/// cannot become read-only (EBUSY).
fn linux_remount_read_only(path: &[u8], read_only: bool) -> u64 {
    let space = linux_mount_space();
    let storage = crate::linux_mounts::superblock_at(space, path).map(|(_, storage)| storage);
    let storage = storage.as_deref().unwrap_or(b"\0");
    if read_only
        && crate::linux_blockfs::generations_at(storage).is_some_and(|generations| {
            generations
                .into_iter()
                .any(linux_overlay_file_open_for_write)
        })
    {
        return LINUX_EBUSY;
    }
    if let Some(Err(error)) = crate::linux_blockfs::remount(storage, read_only) {
        return error.wrapping_neg();
    }
    if let Some(id) = crate::linux_mounts::topmost_id(space, path) {
        if let Some(flags) = crate::linux_mounts::with_mount(space, id, |mount| mount.flags) {
            let flags = if read_only {
                flags | crate::linux_mounts::READ_ONLY
            } else {
                flags & !crate::linux_mounts::READ_ONLY
            };
            crate::linux_mounts::set_flags(space, id, flags);
        }
    }
    0
}

/// fsmount(2): a detached mount of the filesystem a context made, with
/// mount attributes `attributes`.
pub(super) fn linux_fsmount(descriptor: u64, flags: u64, attributes: u64) -> u64 {
    const FSMOUNT_CLOEXEC: u64 = 1;
    const VALID_ATTRIBUTES: u64 = MOUNT_ATTR_RDONLY
        | MOUNT_ATTR_NOSUID
        | MOUNT_ATTR_NODEV
        | MOUNT_ATTR_NOEXEC
        | MOUNT_ATTR_ATIME
        | MOUNT_ATTR_NODIRATIME
        | MOUNT_ATTR_NOSYMFOLLOW;
    if !linux_may_mount() {
        return LINUX_EPERM;
    }
    let (flags, attributes) = (u64::from(flags as u32), u64::from(attributes as u32));
    if flags & !FSMOUNT_CLOEXEC != 0 || attributes & !VALID_ATTRIBUTES != 0 {
        return LINUX_EINVAL;
    }
    if !matches!(
        attributes & MOUNT_ATTR_ATIME,
        MOUNT_ATTR_RELATIME | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME
    ) {
        return LINUX_EINVAL;
    }
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let Some(id) = linux_fs_context_descriptor(descriptor) else {
        return LINUX_EINVAL;
    };
    match fscontext::mount_context(id, linux_mount_attribute_flags(attributes)) {
        Ok(mount) => {
            linux_install_mount_object(fscontext::CLASS_MOUNT, mount, flags & FSMOUNT_CLOEXEC != 0)
        }
        Err(fscontext::Error::Busy) => LINUX_EBUSY,
        Err(fscontext::Error::NoMemory) => LINUX_ENOMEM,
        Err(fscontext::Error::Gone) => LINUX_EBADF,
        Err(fscontext::Error::Invalid) => LINUX_EINVAL,
    }
}

/// open_tree(2): an O_PATH descriptor of a path, or with OPEN_TREE_CLONE
/// a detached copy of the mount there (with the mounts below it, with
/// AT_RECURSIVE).
pub(super) fn linux_open_tree(directory: u64, path_address: u64, flags: u64) -> u64 {
    const OPEN_TREE_CLONE: u64 = 1;
    const OPEN_TREE_CLOEXEC: u64 = LINUX_O_CLOEXEC;
    let flags = u64::from(flags as u32);
    if flags
        & !(AT_EMPTY_PATH
            | AT_NO_AUTOMOUNT
            | AT_RECURSIVE
            | AT_SYMLINK_NOFOLLOW
            | OPEN_TREE_CLONE
            | OPEN_TREE_CLOEXEC)
        != 0
    {
        return LINUX_EINVAL;
    }
    let clone = flags & OPEN_TREE_CLONE != 0;
    if flags & AT_RECURSIVE != 0 && !clone {
        return LINUX_EINVAL;
    }
    if clone && !linux_may_mount() {
        return LINUX_EPERM;
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let length = match linux_mount_api_path(
        directory,
        path_address,
        flags & AT_EMPTY_PATH != 0,
        follow,
        &mut canonical,
    ) {
        Ok(LinuxMountPath::Path(length)) => length,
        Ok(LinuxMountPath::Detached(_)) => return LINUX_EINVAL,
        Err(error) => return error,
    };
    let path = &canonical[..length];
    if !clone {
        // As an O_PATH open of the path found.
        let mut absolute = [0_u8; LINUX_PATH_MAX];
        let Some(destination) = absolute.get_mut(1..=length) else {
            return LINUX_ENAMETOOLONG;
        };
        destination.copy_from_slice(path);
        absolute[0] = b'/';
        let open_flags =
            LINUX_O_PATH | if follow { 0 } else { LINUX_O_NOFOLLOW } | flags & OPEN_TREE_CLOEXEC;
        return linux_openat_path(
            u64::from(LINUX_AT_FDCWD),
            absolute,
            length + 1,
            open_flags,
            0,
        );
    }
    let space = linux_mount_space();
    let options = crate::linux_mounts::flags_at(space, path);
    match fscontext::clone_tree(
        linux_execution_instance(),
        path,
        flags & AT_RECURSIVE != 0,
        options,
    ) {
        Ok(id) => {
            linux_install_mount_object(fscontext::CLASS_MOUNT, id, flags & OPEN_TREE_CLOEXEC != 0)
        }
        Err(_) => LINUX_ENOMEM,
    }
}

/// open_tree_attr(2): open_tree, then mount_setattr's attributes on the
/// detached copy it made.
pub(super) fn linux_open_tree_attr(
    directory: u64,
    path_address: u64,
    flags: u64,
    attributes_address: u64,
    size: u64,
) -> u64 {
    const OPEN_TREE_CLONE: u64 = 1;
    let descriptor = linux_open_tree(directory, path_address, flags);
    if descriptor >= LINUX_RETURN_TO_KERNEL || attributes_address == 0 {
        return descriptor;
    }
    let result = if u64::from(flags as u32) & OPEN_TREE_CLONE == 0 {
        LINUX_EINVAL
    } else {
        linux_mount_setattr_at(
            descriptor,
            None,
            flags & AT_RECURSIVE,
            attributes_address,
            size,
        )
    };
    if result != 0 {
        let _ = linux_descriptor_close(descriptor);
        return result;
    }
    descriptor
}

/// move_mount(2): attaches a detached mount to a path, or moves a mounted
/// tree from one path to another.
pub(super) fn linux_move_mount(
    from_directory: u64,
    from_address: u64,
    to_directory: u64,
    to_address: u64,
    flags: u64,
) -> u64 {
    const MOVE_MOUNT_F_SYMLINKS: u64 = 0x1;
    const MOVE_MOUNT_F_AUTOMOUNTS: u64 = 0x2;
    const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x4;
    const MOVE_MOUNT_T_SYMLINKS: u64 = 0x10;
    const MOVE_MOUNT_T_AUTOMOUNTS: u64 = 0x20;
    const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x40;
    const MOVE_MOUNT_SET_GROUP: u64 = 0x100;
    const MOVE_MOUNT_BENEATH: u64 = 0x200;
    const VALID: u64 = MOVE_MOUNT_F_SYMLINKS
        | MOVE_MOUNT_F_AUTOMOUNTS
        | MOVE_MOUNT_F_EMPTY_PATH
        | MOVE_MOUNT_T_SYMLINKS
        | MOVE_MOUNT_T_AUTOMOUNTS
        | MOVE_MOUNT_T_EMPTY_PATH
        | MOVE_MOUNT_SET_GROUP
        | MOVE_MOUNT_BENEATH;
    if !linux_may_mount() {
        return LINUX_EPERM;
    }
    let flags = u64::from(flags as u32);
    if flags & !VALID != 0
        || flags & (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)
            == MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP
    {
        return LINUX_EINVAL;
    }
    let mut from = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let from_target = match linux_mount_api_path(
        from_directory,
        from_address,
        flags & MOVE_MOUNT_F_EMPTY_PATH != 0,
        flags & MOVE_MOUNT_F_SYMLINKS != 0,
        &mut from,
    ) {
        Ok(target) => target,
        Err(error) => return error,
    };
    let mut to = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let to_length = match linux_mount_api_path(
        to_directory,
        to_address,
        flags & MOVE_MOUNT_T_EMPTY_PATH != 0,
        flags & MOVE_MOUNT_T_SYMLINKS != 0,
        &mut to,
    ) {
        Ok(LinuxMountPath::Path(length)) => length,
        Ok(LinuxMountPath::Detached(_)) => return LINUX_EINVAL,
        Err(error) => return error,
    };
    let to = &to[..to_length];
    let beneath = flags & MOVE_MOUNT_BENEATH != 0;
    match from_target {
        LinuxMountPath::Detached(id) => linux_attach_detached(id, to, beneath),
        LinuxMountPath::Path(length) if flags & MOVE_MOUNT_SET_GROUP != 0 => {
            linux_mount_set_group(&from[..length], to)
        }
        LinuxMountPath::Path(length) => linux_move_mounted_tree(&from[..length], to),
    }
}

/// MOVE_MOUNT_SET_GROUP: `to` joins the peer group of `from`; both must be
/// mounts' roots.
fn linux_mount_set_group(from: &[u8], to: &[u8]) -> u64 {
    let space = linux_mount_space();
    let (Some(from), Some(to)) = (
        crate::linux_mounts::topmost_id(space, from),
        crate::linux_mounts::topmost_id(space, to),
    ) else {
        return LINUX_EINVAL;
    };
    match crate::linux_mounts::share_group(space, from, to) {
        Ok(()) => 0,
        Err(_) => LINUX_EINVAL,
    }
}

/// Attaches detached mount `id` at canonical `target` (beneath the mount
/// there when `beneath`). A detached mount that is attached already is
/// moved instead.
fn linux_attach_detached(id: u64, target: &[u8], beneath: bool) -> u64 {
    let Some((tree, flags, attached)) = fscontext::with_mount(id, |mount| {
        (mount.tree.clone(), mount.flags, mount.attached.clone())
    }) else {
        return LINUX_EBADF;
    };
    if let Some(path) = attached {
        return linux_move_mounted_tree(&path, target);
    }
    let directory = linux_api_directory(target)
        || linux_kernel_mount_point(target)
        || linux_path_access(target).is_some_and(|access| access.directory);
    if !directory {
        return LINUX_ENOTDIR;
    }
    let space = linux_mount_space();
    if beneath
        && (target.is_empty()
            || !linux_kernel_mount_point(target)
                && !crate::linux_mounts::is_mount_point(space, target))
    {
        return LINUX_EINVAL;
    }
    let result = match tree {
        Tree::New {
            filesystem,
            source,
            data,
        } => linux_mount_new(target, source.as_deref(), &filesystem, flags, &data),
        Tree::Clone { path, recursive } => match crate::linux_mounts::bind(
            space,
            &path,
            target,
            recursive,
            &linux_kernel_filesystem(&path),
        ) {
            Ok(mount) => {
                crate::linux_mounts::set_flags(space, mount, flags);
                0
            }
            Err(crate::linux_mounts::Error::NotMounted) => LINUX_EINVAL,
            Err(crate::linux_mounts::Error::NoMemory) => LINUX_ENOMEM,
        },
    };
    if result != 0 {
        return result;
    }
    if beneath {
        if let Some(mount) = crate::linux_mounts::topmost_id(space, target) {
            crate::linux_mounts::put_beneath(space, mount);
        }
    }
    match fscontext::attached(id, target) {
        Ok(()) => 0,
        Err(_) => LINUX_ENOMEM,
    }
}

/// Moves the mount whose root is canonical `from`, with the mounts below
/// it, to canonical `to` (move_mount, mount(2)'s MS_MOVE).
pub(super) fn linux_move_mounted_tree(from: &[u8], to: &[u8]) -> u64 {
    let space = linux_mount_space();
    if !crate::linux_mounts::is_mount_point(space, from) {
        return LINUX_EINVAL;
    }
    // A mount cannot move below itself.
    if to
        .strip_prefix(from)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/") || from.is_empty())
    {
        return LINUX_ELOOP;
    }
    if !linux_path_access(to).is_some_and(|access| access.directory) {
        return LINUX_ENOTDIR;
    }
    match crate::linux_mounts::move_tree(space, from, to) {
        Ok(()) => 0,
        Err(crate::linux_mounts::Error::NotMounted) => LINUX_EINVAL,
        Err(crate::linux_mounts::Error::NoMemory) => LINUX_ENOMEM,
    }
}

/// An overlay's layers, as canonical paths, from its options.
struct LinuxOverlayLayers {
    lowers: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    upper: Option<alloc::vec::Vec<u8>>,
    work: Option<alloc::vec::Vec<u8>>,
}

/// The pieces of `text` between unescaped `separator`s, with the escaping
/// backslashes taken out (overlayfs's options and its lowerdir list).
fn linux_split_escaped(text: &[u8], separator: u8) -> Option<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    let mut pieces = alloc::vec::Vec::new();
    let mut piece = alloc::vec::Vec::new();
    let mut bytes = text.iter();
    while let Some(byte) = bytes.next() {
        match *byte {
            b'\\' => {
                piece.try_reserve(1).ok()?;
                piece.push(*bytes.next().unwrap_or(&b'\\'));
            }
            byte if byte == separator => {
                pieces.try_reserve(1).ok()?;
                pieces.push(core::mem::take(&mut piece));
            }
            byte => {
                piece.try_reserve(1).ok()?;
                piece.push(byte);
            }
        }
    }
    pieces.try_reserve(1).ok()?;
    pieces.push(piece);
    Some(pieces)
}

/// The canonical path of the directory a layer option names, relative to
/// the mounter's working directory, symlinks followed.
fn linux_overlay_layer_path(path: &[u8]) -> Result<alloc::vec::Vec<u8>, u64> {
    if path.is_empty() {
        return Err(LINUX_ENOENT);
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = match linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), path, &mut canonical) {
        Ok(length) => length,
        Err(LINUX_EISDIR) => 0,
        Err(error) => return Err(error),
    };
    let length = if length == 0 {
        0
    } else {
        linux_overlay_lookup_following(&mut canonical, length, true)?.0
    };
    let canonical = &canonical[..length];
    match linux_path_access(canonical) {
        Some(access) if access.directory => {}
        Some(_) => return Err(LINUX_ENOTDIR),
        None if canonical.is_empty() => {}
        None => return Err(linux_missing_path_error(canonical)),
    }
    let mut stored = alloc::vec::Vec::new();
    stored
        .try_reserve_exact(canonical.len())
        .map_err(|_| LINUX_ENOMEM)?;
    stored.extend_from_slice(canonical);
    Ok(stored)
}

/// Reads an overlay's layers from its options (`lowerdir=A:B,upperdir=U,
/// workdir=W`), with Linux's checks: a lower layer is required, an upper
/// one needs a work directory on the same mount and outside it, and every
/// layer must be a directory.
fn linux_overlayfs_layers(data: &[u8]) -> Result<LinuxOverlayLayers, u64> {
    let mut layers = LinuxOverlayLayers {
        lowers: alloc::vec::Vec::new(),
        upper: None,
        work: None,
    };
    for option in linux_split_escaped(data, b',').ok_or(LINUX_ENOMEM)? {
        if option.is_empty() {
            continue;
        }
        let (key, value) = match option.iter().position(|byte| *byte == b'=') {
            Some(at) => (&option[..at], &option[at + 1..]),
            None => (&option[..], &b""[..]),
        };
        match key {
            b"lowerdir" => {
                layers.lowers.clear();
                for lower in linux_split_escaped(value, b':').ok_or(LINUX_ENOMEM)? {
                    let lower = linux_overlay_layer_path(&lower)?;
                    layers.lowers.try_reserve(1).map_err(|_| LINUX_ENOMEM)?;
                    layers.lowers.push(lower);
                }
            }
            b"lowerdir+" => {
                let lower = linux_overlay_layer_path(value)?;
                layers.lowers.try_reserve(1).map_err(|_| LINUX_ENOMEM)?;
                layers.lowers.push(lower);
            }
            b"upperdir" => layers.upper = Some(linux_overlay_layer_path(value)?),
            b"workdir" => layers.work = Some(linux_overlay_layer_path(value)?),
            // The superblock flags and the options of features that change
            // nothing here.
            _ => {}
        }
    }
    if layers.lowers.is_empty() {
        return Err(LINUX_EINVAL);
    }
    let space = linux_mount_space();
    let inside = |outer: &[u8], inner: &[u8]| {
        outer.is_empty()
            || inner
                .strip_prefix(outer)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
    };
    match (&layers.upper, &layers.work) {
        (Some(_), None) => return Err(LINUX_EINVAL),
        (Some(upper), Some(work)) => {
            if crate::linux_mounts::mount_id_at(space, upper)
                != crate::linux_mounts::mount_id_at(space, work)
                || inside(upper, work)
                || inside(work, upper)
            {
                return Err(LINUX_EINVAL);
            }
            if linux_read_only_path(upper) {
                return Err(LINUX_EROFS);
            }
        }
        // A work directory without an upper layer is ignored.
        (None, _) => layers.work = None,
    }
    Ok(layers)
}

/// Whether overlay options `data` name layers that can be mounted
/// (fsconfig's FSCONFIG_CMD_CREATE).
fn linux_overlayfs_check(data: &[u8]) -> Result<(), u64> {
    linux_overlayfs_layers(data).map(|_| ())
}

/// mount(2) of an overlay at canonical `target`, a directory, from the
/// layers its options `data` name; one without an upper layer is
/// read-only.
pub(super) fn linux_mount_overlayfs(
    target: &[u8],
    source: &[u8],
    options: u32,
    data: &[u8],
) -> u64 {
    let layers = match linux_overlayfs_layers(data) {
        Ok(layers) => layers,
        Err(error) => return error,
    };
    // Linux keeps its staging directory in the work directory.
    if let Some(work) = &layers.work {
        let mut staging = alloc::vec::Vec::new();
        if staging.try_reserve_exact(work.len() + 5).is_err() {
            return LINUX_ENOMEM;
        }
        staging.extend_from_slice(work);
        if !work.is_empty() {
            staging.push(b'/');
        }
        staging.extend_from_slice(b"work");
        if crate::linux_overlay::lookup(&staging).is_none()
            && crate::linux_overlay::create_directory(&staging, 0).is_none()
        {
            return LINUX_EIO;
        }
    }
    let options = if layers.upper.is_none() {
        options | crate::linux_mounts::READ_ONLY
    } else {
        options
    };
    // The layers are where their paths lead now, the mounts below the
    // mount point too (lowerdir may be the mount point itself).
    let stored = |layer: &[u8]| crate::linux_mount_paths::storage(layer).into_owned();
    let lowers: alloc::vec::Vec<alloc::vec::Vec<u8>> =
        layers.lowers.iter().map(|lower| stored(lower)).collect();
    let lowers: alloc::vec::Vec<&[u8]> = lowers.iter().map(|lower| &lower[..]).collect();
    let upper = layers.upper.as_deref().map(stored);
    let superblock = crate::linux_mounts::new_superblock();
    let storage = crate::linux_mount_paths::storage_root(superblock);
    let space = linux_mount_space();
    if let Err(error) = crate::linux_overlayfs::mount(&storage, upper.as_deref(), &lowers) {
        return error.wrapping_neg();
    }
    match crate::linux_mounts::mount(space, target, source, b"overlay", options, superblock) {
        Ok(_) => {
            crate::linux_overlayfs::set_device(
                &storage,
                crate::linux_mount_paths::storage_device(superblock),
            );
            0
        }
        Err(_) => {
            crate::linux_overlayfs::unmount(&storage);
            LINUX_ENOMEM
        }
    }
}
