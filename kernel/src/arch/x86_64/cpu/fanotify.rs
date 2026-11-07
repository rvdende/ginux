//! fanotify(7)'s system calls and the events the kernel reports to it
//! (the groups, marks and queues are `crate::linux_fanotify`'s).
//!
//! An event names its objects by canonical path, with the identifiers a
//! group reporting them gives: the file handle name_to_handle_at encodes
//! and the fsid statfs reports, computed the same way here.

use super::*;
use crate::linux_fanotify::{self as fanotify, Kind, Node, Notice};

pub(super) fn linux_fanotify_descriptor(descriptor: u64) -> bool {
    linux_device_descriptor(descriptor) & !3 == LINUX_DEVICE_FANOTIFY
}

/// The group a descriptor stands for: its domain and its open file
/// description's id.
fn linux_fanotify_key(descriptor: u64) -> Option<(usize, u64)> {
    if !linux_fanotify_descriptor(descriptor) {
        return None;
    }
    linux_descriptor_open_file_id(descriptor).map(|id| (linux_execution_instance(), id))
}

/// Whether the caller has CAP_SYS_ADMIN in the domain's initial user
/// namespace, as Linux's capable() asks (the kernel outside a process is
/// root): root of a namespace made in the domain does not.
fn linux_fanotify_admin() -> bool {
    current_linux_credentials()
        .is_none_or(|credentials| credentials.has(ginux_credentials::capability::SYS_ADMIN))
        && current_linux_user_namespace()
            .is_none_or(|namespace| linux_user::parent(namespace).is_none())
}

/// Who the caller's groups count against: its user in its user namespace
/// and those above it.
fn linux_fanotify_owner() -> Option<fanotify::Owner> {
    let uid = current_linux_credentials().map_or(0, |credentials| credentials.user.effective);
    let mut namespaces = Vec::new();
    let mut namespace = current_linux_user_namespace();
    while let Some(handle) = namespace {
        namespaces.try_reserve(1).ok()?;
        namespaces.push(handle.to_word());
        namespace = linux_user::parent(handle);
    }
    if namespaces.is_empty() {
        namespaces.try_reserve(1).ok()?;
        namespaces.push(0);
    }
    Some(fanotify::Owner { uid, namespaces })
}

/// The /proc/sys values of fanotify's per-user limits: the caller's user
/// namespace's (user/max_fanotify_groups and max_fanotify_marks), or the
/// domain's initial namespace's (fs/fanotify/max_user_groups and
/// max_user_marks); None for other paths.
fn linux_fanotify_limit_at(path: &[u8]) -> Option<(fanotify::Limit, Option<u64>)> {
    let (limit, own) = match path {
        b"sys/user/max_fanotify_groups" => (fanotify::Limit::Groups, true),
        b"sys/user/max_fanotify_marks" => (fanotify::Limit::Marks, true),
        b"sys/fs/fanotify/max_user_groups" => (fanotify::Limit::Groups, false),
        b"sys/fs/fanotify/max_user_marks" => (fanotify::Limit::Marks, false),
        _ => return None,
    };
    let namespace = current_linux_user_namespace();
    let namespace = if own { namespace } else { None };
    Some((
        limit,
        namespace
            .filter(|namespace| linux_user::parent(*namespace).is_some())
            .map(linux_user::UserNamespaceHandle::to_word),
    ))
}

/// The number a fanotify limit's /proc/sys file shows.
pub(super) fn linux_fanotify_limit_value(path: &[u8]) -> Option<i64> {
    let (limit, namespace) = linux_fanotify_limit_at(path)?;
    let initial = linux_fanotify_initial_namespace();
    Some(i64::from(fanotify::user_limit(
        linux_execution_instance(),
        namespace.unwrap_or(initial),
        namespace.is_none(),
        limit,
    )))
}

/// Writes a fanotify limit's /proc/sys file: Some(false) for a value out
/// of range.
pub(super) fn linux_fanotify_set_limit(path: &[u8], value: i64) -> Option<bool> {
    let (limit, namespace) = linux_fanotify_limit_at(path)?;
    let Ok(value) = u32::try_from(value).map(|value| value.min(i32::MAX as u32)) else {
        return Some(false);
    };
    let namespace = namespace.unwrap_or_else(linux_fanotify_initial_namespace);
    Some(fanotify::set_user_limit(linux_execution_instance(), namespace, limit, value).is_ok())
}

/// The domain's initial user namespace, as fanotify's limits name it.
fn linux_fanotify_initial_namespace() -> u64 {
    let mut namespace = current_linux_user_namespace();
    while let Some(parent) = namespace.and_then(linux_user::parent) {
        namespace = Some(parent);
    }
    namespace.map_or(0, linux_user::UserNamespaceHandle::to_word)
}

/// fanotify_init(2), with Linux's checks in Linux's order.
pub(super) fn linux_fanotify_init(flags: u64, event_flags: u64) -> u64 {
    use crate::linux_fanotify::{
        FAN_REPORT_DIR_FID, FAN_REPORT_FID, FAN_REPORT_NAME, FAN_REPORT_PIDFD,
        FAN_REPORT_TARGET_FID, FAN_REPORT_TID, FAN_UNLIMITED_QUEUE, FID_BITS, UNPRIVILEGED,
    };
    const FAN_CLOEXEC: u32 = 0x1;
    const FAN_NONBLOCK: u32 = 0x2;
    const CLASS_BITS: u32 = 0xc;
    const FAN_UNLIMITED_MARKS: u32 = 0x20;
    const INIT_FLAGS: u32 = FAN_CLOEXEC
        | FAN_NONBLOCK
        | CLASS_BITS
        | FID_BITS
        | FAN_REPORT_TID
        | FAN_REPORT_PIDFD
        | FAN_UNLIMITED_QUEUE
        | FAN_UNLIMITED_MARKS;
    // What only CAP_SYS_ADMIN may ask for: permission events, other
    // processes' threads and pidfds, unlimited resources.
    const ADMIN_FLAGS: u32 =
        CLASS_BITS | FAN_REPORT_TID | FAN_REPORT_PIDFD | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS;
    const O_DSYNC: u32 = 0x1000;
    const O_SYNC: u32 = 0x10_1000;
    const EVENT_FLAGS: u32 = 3
        | LINUX_O_APPEND as u32
        | LINUX_O_NONBLOCK as u32
        | O_SYNC
        | O_DSYNC
        | LINUX_O_CLOEXEC as u32
        | LINUX_O_LARGEFILE as u32
        | LINUX_O_NOATIME as u32;
    let flags = flags as u32;
    let event_flags = event_flags as u32;
    let fid_mode = flags & FID_BITS;
    // Without CAP_SYS_ADMIN only a notification group reporting file
    // handles may be made, as in Linux; it gets no mount or filesystem
    // marks and sees only its own process's pid.
    let mut internal = 0;
    if !linux_fanotify_admin() {
        if flags & ADMIN_FLAGS != 0 || fid_mode == 0 {
            return LINUX_EPERM;
        }
        internal |= UNPRIVILEGED;
    }
    if flags & !INIT_FLAGS != 0
        || flags & FAN_REPORT_PIDFD != 0 && flags & FAN_REPORT_TID != 0
        || event_flags & !EVENT_FLAGS != 0
        || event_flags & 3 == 3
        || fid_mode != 0 && flags & CLASS_BITS != 0
        || fid_mode & FAN_REPORT_NAME != 0 && fid_mode & FAN_REPORT_DIR_FID == 0
        || fid_mode & FAN_REPORT_TARGET_FID != 0
            && fid_mode & (FAN_REPORT_NAME | FAN_REPORT_FID) != FAN_REPORT_NAME | FAN_REPORT_FID
        || flags & CLASS_BITS == CLASS_BITS
    {
        return LINUX_EINVAL;
    }
    let Some(descriptor) = (LINUX_AUX_DESCRIPTOR_FIRST..LINUX_AUX_DESCRIPTOR_LIMIT)
        .find(|descriptor| linux_aux_descriptor_free(*descriptor))
    else {
        return LINUX_EMFILE;
    };
    let index = (descriptor - LINUX_AUX_DESCRIPTOR_FIRST) as usize;
    X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[index]
        .store(LINUX_DEVICE_FANOTIFY | 3, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index].store(
        if flags & FAN_NONBLOCK != 0 {
            LINUX_O_NONBLOCK as u32
        } else {
            0
        },
        Ordering::SeqCst,
    );
    let queue_limit = linux_proc_sysctl_value(b"sys/fs/fanotify/max_queued_events")
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(fanotify::DEFAULT_QUEUE_LIMIT);
    let created = match linux_descriptor_open_file_id(descriptor).zip(linux_fanotify_owner()) {
        Some((id, owner)) => fanotify::create(
            linux_execution_instance(),
            id,
            (current_linux_process_pid(), owner),
            (flags | internal, event_flags | LINUX_O_LARGEFILE as u32),
            queue_limit,
        ),
        None => Err(fanotify::Error::NoMemory),
    };
    if let Err(error) = created {
        X86_RUNTIME.ELF_PROBE_DEVICE_DESCRIPTORS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SOCKET_FLAGS[index].store(0, Ordering::SeqCst);
        return match error {
            fanotify::Error::TooMany => LINUX_EMFILE,
            _ => LINUX_ENOMEM,
        };
    }
    set_linux_descriptor_close_on_exec(descriptor, flags & FAN_CLOEXEC != 0);
    descriptor
}

/// statfs's f_fsid of the filesystem canonical `path` lies on: a tmpfs
/// mount's id, a volume's id, /proc's and cgroup2's numbers, or the
/// root's, as `linux_statfs` reports them.
fn linux_fanotify_fsid(path: &[u8]) -> [u8; 8] {
    linux_fanotify_fsid_of(
        path,
        crate::linux_overlay::lookup(path).map(|metadata| metadata.handle),
    )
}

/// `linux_fanotify_fsid` for the object at `path` whose overlay node, if
/// it has one, is `handle` (so a caller that looked it up already does not
/// walk the path again).
fn linux_fanotify_fsid_of(path: &[u8], handle: Option<crate::linux_overlay::Handle>) -> [u8; 8] {
    if let Some(fsid) = linux_tmpfs_fsid(path) {
        return fsid;
    }
    if let Some(statfs) = handle.and_then(crate::linux_blockfs::statfs_of) {
        let mut fsid = [0_u8; 8];
        fsid[..4].copy_from_slice(&statfs.id[0].to_ne_bytes());
        fsid[4..].copy_from_slice(&statfs.id[1].to_ne_bytes());
        return fsid;
    }
    let below =
        |root: &[u8]| path == root || path.starts_with(root) && path.get(root.len()) == Some(&b'/');
    let filesystem: u64 = if below(b"proc") {
        2
    } else if below(b"sys/fs/cgroup") {
        3
    } else {
        1
    };
    filesystem.to_ne_bytes()
}

/// A file or directory an event names, with its identifiers.
pub(super) struct LinuxFanotifyNode {
    path: LinuxInotifyPath,
    directory: bool,
    openable: bool,
    fsid: [u8; 8],
    handle: Option<[u8; 8]>,
    /// Its hard links, for whether removing a name deletes it.
    links: u32,
    /// Its overlay node, when it has one.
    overlay: Option<crate::linux_overlay::Handle>,
}

impl LinuxFanotifyNode {
    fn node(&self) -> Node<'_> {
        Node {
            path: &self.path,
            directory: self.directory,
            openable: self.openable,
            fsid: self.fsid,
            handle: self.handle,
        }
    }

    /// The same object at another path (a renamed file at its new name).
    fn at(&self, path: &[u8]) -> Option<Self> {
        Some(Self {
            path: linux_heap_path(path)?,
            ..*self
        })
    }
}

/// The file or directory at canonical `path`, as fanotify names it; None
/// when nothing is there (or only the kernel's virtual files, which have
/// no handle).
pub(super) fn linux_fanotify_node(path: &[u8]) -> Option<LinuxFanotifyNode> {
    use crate::linux_overlay::NodeKind;
    use crate::published_rootfs::EntryKind;
    // As name_to_handle_at encodes it: the overlay's node by generation,
    // else the image's entry by handle.
    let overlay = crate::linux_overlay::lookup(path);
    let (directory, openable, handle, links) = if let Some(metadata) = overlay {
        let handle =
            u64::from(1_u32) << 32 | u64::from(crate::linux_overlay::generation(metadata.handle));
        (
            metadata.kind == NodeKind::Directory,
            matches!(metadata.kind, NodeKind::File | NodeKind::Directory),
            handle,
            metadata.links,
        )
    } else {
        if crate::linux_overlay::hidden(path) {
            return None;
        }
        let (rootfs, entry) =
            crate::published_rootfs::lookup_at(crate::published_rootfs::ROOT_HANDLE, path)
                .filter(|(handle, _)| !linux_rootfs_handle_hidden(*handle))?;
        let kind = entry.map(|entry| entry.kind);
        let directory = matches!(kind, None | Some(EntryKind::Directory));
        let handle = u64::from(2_u32) << 32 | u64::from(rootfs);
        (
            directory,
            !matches!(kind, Some(EntryKind::Symlink)),
            handle,
            1,
        )
    };
    Some(LinuxFanotifyNode {
        path: linux_heap_path(path)?,
        directory,
        openable,
        fsid: linux_fanotify_fsid_of(path, overlay.map(|metadata| metadata.handle)),
        handle: Some(handle.to_ne_bytes()),
        links,
        overlay: overlay.map(|metadata| metadata.handle),
    })
}

/// A directory as only its path matters to an event (no group reports
/// identifiers): its marks are found by path.
fn linux_fanotify_directory_by_path(path: &[u8]) -> Option<LinuxFanotifyNode> {
    Some(LinuxFanotifyNode {
        path: linux_heap_path(path)?,
        directory: true,
        openable: true,
        fsid: [0; 8],
        handle: None,
        links: 1,
        overlay: None,
    })
}

/// The process and thread making the current call.
fn linux_fanotify_cause() -> fanotify::Cause {
    let pid = current_linux_process_pid();
    fanotify::Cause {
        pid,
        tid: current_linux_tid().unwrap_or(pid),
    }
}

fn linux_fanotify_notify(notice: &Notice) {
    if fanotify::notify(linux_execution_instance(), notice, linux_fanotify_cause()) {
        wake_linux_descriptor_waits();
    }
}

/// Events `mask` happened to the file or directory at canonical `path`:
/// through an open file (`opened`: a path, which mount marks and groups
/// reporting descriptors hear), or to it by name (an attribute change, a
/// truncate).
fn linux_fanotify_file_event(path: &[u8], mask: u32, opened: bool) {
    linux_fanotify_file_event_of(path, mask, opened, || linux_fanotify_node(path));
}

/// `linux_fanotify_file_event` with the object from `object`, asked only
/// when some mark may hear the event.
fn linux_fanotify_file_event_of(
    path: &[u8],
    mask: u32,
    opened: bool,
    object: impl FnOnce() -> Option<LinuxFanotifyNode>,
) {
    if !fanotify::active()
        || !opened && !fanotify::identifier_groups()
        || !fanotify::may_hear(linux_execution_instance(), mask)
    {
        return;
    }
    let Some(object) = object() else {
        return;
    };
    let (parent_path, name) = fanotify::split(path);
    // The directory's identifiers matter only to groups reporting them.
    let parent = (!path.is_empty())
        .then(|| {
            if fanotify::identifier_groups() {
                linux_fanotify_node(parent_path)
            } else {
                linux_fanotify_directory_by_path(parent_path)
            }
        })
        .flatten();
    let mount = opened.then(|| {
        if fanotify::mount_marks() {
            crate::linux_mounts::mount_id_at(linux_mount_space(), path)
        } else {
            0
        }
    });
    linux_fanotify_notify(&Notice {
        kind: Kind::File,
        mask,
        object: object.node(),
        directory: parent.as_ref().map(LinuxFanotifyNode::node),
        name,
        moved: None,
        mount,
    });
    // A file of an overlayfs is a layer's file underneath: that file hears
    // the event too, by its own identifiers, as Linux reports it on the
    // real inode (since 6.5). Its directory and mount are the layer's,
    // which marks do not name here.
    if let Some(real) = object
        .overlay
        .filter(|handle| crate::linux_overlayfs::owns(*handle))
        .and_then(crate::linux_overlayfs::real)
        .and_then(linux_fanotify_handle_node)
    {
        linux_fanotify_notify(&Notice {
            kind: Kind::File,
            mask,
            object: real.node(),
            directory: None,
            name,
            moved: None,
            mount: None,
        });
    }
}

/// The object overlay node `handle` is, by its own path (a layer's file).
fn linux_fanotify_handle_node(handle: crate::linux_overlay::Handle) -> Option<LinuxFanotifyNode> {
    use crate::linux_overlay::NodeKind;
    let metadata = crate::linux_overlay::metadata(handle)?;
    let mut path = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = crate::linux_overlay::copy_path(handle, &mut path)?;
    let path = &path[..length];
    let identifier =
        u64::from(1_u32) << 32 | u64::from(crate::linux_overlay::generation(metadata.handle));
    Some(LinuxFanotifyNode {
        path: linux_heap_path(path)?,
        directory: metadata.kind == NodeKind::Directory,
        openable: matches!(metadata.kind, NodeKind::File | NodeKind::Directory),
        fsid: linux_fanotify_fsid_of(path, Some(metadata.handle)),
        handle: Some(identifier.to_ne_bytes()),
        links: metadata.links,
        overlay: Some(metadata.handle),
    })
}

/// Events `mask` happened through an open file of canonical `path`.
pub(super) fn linux_fanotify_event(path: &[u8], mask: u32) {
    linux_fanotify_file_event(path, mask, true);
}

/// The object open file `descriptor` (of canonical `path`) has open, by
/// its overlay node, without walking the path again (a large directory's
/// entries cost a scan each).
pub(super) fn linux_fanotify_descriptor_node(
    descriptor: u64,
    path: &[u8],
) -> Option<LinuxFanotifyNode> {
    use crate::linux_overlay::NodeKind;
    let Some(handle) = linux_overlay_descriptor_handle(descriptor) else {
        return linux_fanotify_node(path);
    };
    let Some(metadata) = crate::linux_overlay::metadata(handle) else {
        return linux_fanotify_node(path);
    };
    let identifier =
        u64::from(1_u32) << 32 | u64::from(crate::linux_overlay::generation(metadata.handle));
    Some(LinuxFanotifyNode {
        path: linux_heap_path(path)?,
        directory: metadata.kind == NodeKind::Directory,
        openable: matches!(metadata.kind, NodeKind::File | NodeKind::Directory),
        fsid: linux_fanotify_fsid_of(path, Some(metadata.handle)),
        handle: Some(identifier.to_ne_bytes()),
        links: metadata.links,
        overlay: Some(handle),
    })
}

/// Events `mask` happened through open file `descriptor` of canonical
/// `path`.
pub(super) fn linux_fanotify_descriptor_event(descriptor: u64, path: &[u8], mask: u32) {
    linux_fanotify_file_event_of(path, mask, true, || {
        linux_fanotify_descriptor_node(descriptor, path)
    });
}

/// Events `mask` happened through an open file whose object was `object`
/// (a closed descriptor's, described before it closed).
pub(super) fn linux_fanotify_node_event(object: LinuxFanotifyNode, mask: u32) {
    let path = object.path.clone();
    linux_fanotify_file_event_of(&path, mask, true, || Some(object));
}

/// Events `mask` happened to canonical `path` by name (FAN_ATTRIB, a
/// truncate's FAN_MODIFY), as Linux's fsnotify_change reports them.
pub(super) fn linux_fanotify_change(path: &[u8], mask: u32) {
    linux_fanotify_file_event(path, mask, false);
}

/// The directory entry of `entry` changed (`mask`: created, deleted,
/// moved from or to); `entry` names the object at the entry's path.
fn linux_fanotify_entry(entry: &LinuxFanotifyNode, mask: u32) {
    let (directory_path, name) = fanotify::split(&entry.path);
    let Some(directory) = linux_fanotify_node(directory_path) else {
        return;
    };
    linux_fanotify_notify(&Notice {
        kind: Kind::Entry,
        mask,
        object: entry.node(),
        directory: Some(directory.node()),
        name,
        moved: None,
        mount: None,
    });
}

/// Events `mask` happened to `object` itself (deleted, moved, its link
/// count changed).
fn linux_fanotify_inode(object: &LinuxFanotifyNode, mask: u32) {
    linux_fanotify_notify(&Notice {
        kind: Kind::Inode,
        mask,
        object: object.node(),
        directory: None,
        name: b"",
        moved: None,
        mount: None,
    });
}

/// Whether directory entry and inode events are worth describing: some
/// group reporting identifiers has a mark.
fn linux_fanotify_entries_watched() -> bool {
    fanotify::active() && fanotify::identifier_groups()
}

/// The object at canonical `path` before a call that removes or renames
/// it, when some group may hear of it.
pub(super) fn linux_fanotify_before(path: Option<&[u8]>) -> Option<LinuxFanotifyNode> {
    linux_fanotify_entries_watched()
        .then(|| path.and_then(linux_fanotify_node))
        .flatten()
}

/// `path` was made (open with O_CREAT, mkdir, mknod, symlink; a link
/// changes the file's link count first).
pub(super) fn linux_fanotify_created(path: &[u8], link: bool) {
    if !linux_fanotify_entries_watched() {
        return;
    }
    let Some(entry) = linux_fanotify_node(path) else {
        return;
    };
    if link {
        linux_fanotify_inode(&entry, fanotify::FAN_ATTRIB);
    }
    linux_fanotify_entry(&entry, fanotify::FAN_CREATE);
}

/// `victim`, as it was, lost its name: a file's link count changes, it is
/// deleted with its last name (FAN_DELETE_SELF), and its directory loses
/// the entry (FAN_DELETE), in Linux's order.
pub(super) fn linux_fanotify_removed(victim: &LinuxFanotifyNode) {
    if !linux_fanotify_entries_watched() {
        return;
    }
    if !victim.directory {
        linux_fanotify_inode(victim, fanotify::FAN_ATTRIB);
    }
    if victim.directory || victim.links <= 1 {
        linux_fanotify_inode(victim, fanotify::FAN_DELETE_SELF);
    }
    linux_fanotify_entry(victim, fanotify::FAN_DELETE);
}

/// `source` (as it was at its old name) moved to canonical `to`, over
/// `target` when one was there (swapped with it for RENAME_EXCHANGE), as
/// Linux's fsnotify_move reports it: FAN_RENAME with both names, the old
/// directory's FAN_MOVED_FROM, the new one's FAN_MOVED_TO, the replaced
/// file's link count, the moved file's FAN_MOVE_SELF, and the replaced
/// file's deletion.
pub(super) fn linux_fanotify_renamed(
    source: &LinuxFanotifyNode,
    to: &[u8],
    target: Option<&LinuxFanotifyNode>,
    exchange: bool,
) {
    if !linux_fanotify_entries_watched() {
        return;
    }
    let Some(moved) = source.at(to) else {
        return;
    };
    linux_fanotify_move(source, &moved);
    match target {
        Some(target) if exchange => {
            if let Some(swapped) = target.at(&source.path) {
                linux_fanotify_move(target, &swapped);
            }
        }
        Some(target) => {
            linux_fanotify_inode(target, fanotify::FAN_ATTRIB);
            if target.directory || target.links <= 1 {
                linux_fanotify_inode(target, fanotify::FAN_DELETE_SELF);
            }
        }
        None => {}
    }
}

/// One file's move from `from` (its old entry) to `to` (the same file at
/// its new entry).
fn linux_fanotify_move(from: &LinuxFanotifyNode, to: &LinuxFanotifyNode) {
    let (old_path, old_name) = fanotify::split(&from.path);
    let (new_path, new_name) = fanotify::split(&to.path);
    let (Some(old_directory), Some(new_directory)) =
        (linux_fanotify_node(old_path), linux_fanotify_node(new_path))
    else {
        return;
    };
    linux_fanotify_notify(&Notice {
        kind: Kind::Entry,
        mask: fanotify::FAN_RENAME,
        object: to.node(),
        directory: Some(old_directory.node()),
        name: old_name,
        moved: Some((new_directory.node(), new_name)),
        mount: None,
    });
    linux_fanotify_notify(&Notice {
        kind: Kind::Entry,
        mask: fanotify::FAN_MOVED_FROM,
        object: to.node(),
        directory: Some(old_directory.node()),
        name: old_name,
        moved: None,
        mount: None,
    });
    linux_fanotify_notify(&Notice {
        kind: Kind::Entry,
        mask: fanotify::FAN_MOVED_TO,
        object: to.node(),
        directory: Some(new_directory.node()),
        name: new_name,
        moved: None,
        mount: None,
    });
    linux_fanotify_inode(to, fanotify::FAN_MOVE_SELF);
}

/// The object at canonical `path` as a permission check sees it, when it
/// is one fanotify reports.
fn linux_fanotify_object(path: &[u8]) -> Option<fanotify::Object<'_>> {
    let node = linux_fanotify_node(path).filter(|node| node.openable)?;
    let (mount, fsid) = if fanotify::mount_marks() {
        (
            crate::linux_mounts::mount_id_at(linux_mount_space(), path),
            node.fsid,
        )
    } else {
        (0, [0; 8])
    };
    Some(fanotify::Object {
        path,
        directory: node.directory,
        mount,
        fsid,
    })
}

/// Before system call `number` with `arguments`: an open (FAN_OPEN_PERM)
/// or a read (FAN_ACCESS_PERM) of a file that a permission mark covers
/// waits until the groups that heard of it answer. Returns the call's
/// result when it does not go on: EPERM when a group denied it, or a
/// restart while one has not answered.
pub(super) fn linux_fanotify_permission_check(
    number: u64,
    arguments: [u64; 3],
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
) -> Option<u64> {
    use crate::linux_fanotify::{Permission, FAN_ACCESS_PERM, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM};
    let at = u64::from(LINUX_AT_FDCWD);
    let (path, mask) = match number {
        LINUX_READ_SYSCALL
        | LINUX_PREAD64_SYSCALL
        | LINUX_READV_SYSCALL
        | LINUX_PREADV_SYSCALL
        | LINUX_PREADV2_SYSCALL => {
            if linux_device_descriptor(u64::from(arguments[0] as u32)) & LINUX_DESCRIPTOR_INPUT == 0
            {
                return None;
            }
            (
                linux_inotify_descriptor_path(arguments[0])?,
                FAN_ACCESS_PERM,
            )
        }
        // Only a file already there is asked about: one the call creates
        // is not there to check yet.
        LINUX_OPEN_SYSCALL | LINUX_CREAT_SYSCALL | LINUX_OPENAT_SYSCALL => {
            let (directory, address, flags) = match number {
                LINUX_OPEN_SYSCALL => (at, arguments[0], arguments[1]),
                LINUX_CREAT_SYSCALL => (at, arguments[0], 0),
                _ => (arguments[0], arguments[1], arguments[2]),
            };
            let path = linux_inotify_path_at(directory, address)?;
            if flags & LINUX_O_NOFOLLOW != 0 {
                (path, FAN_OPEN_PERM)
            } else {
                let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
                canonical.get_mut(..path.len())?.copy_from_slice(&path);
                let length = linux_overlay_lookup_following(&mut canonical, path.len(), true)
                    .ok()?
                    .0;
                (linux_heap_path(&canonical[..length])?, FAN_OPEN_PERM)
            }
        }
        // An exec opens its file to run it: FAN_OPEN_EXEC_PERM, then
        // FAN_OPEN_PERM, as Linux's open_exec asks.
        LINUX_EXECVE_SYSCALL => {
            let path = linux_inotify_path_at(at, arguments[0])?;
            let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
            canonical.get_mut(..path.len())?.copy_from_slice(&path);
            let length = linux_overlay_lookup_following(&mut canonical, path.len(), true)
                .ok()?
                .0;
            (
                linux_heap_path(&canonical[..length])?,
                FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM,
            )
        }
        _ => return None,
    };
    let object = linux_fanotify_object(&path)
        .filter(|object| mask & FAN_ACCESS_PERM == 0 || !object.directory)?;
    let steps: &[u32] = if mask == FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM {
        &[FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM]
    } else {
        core::slice::from_ref(&mask)
    };
    match fanotify::permission_steps(
        linux_execution_instance(),
        object,
        steps,
        linux_fanotify_cause(),
    ) {
        Permission::Allowed => None,
        Permission::Denied => Some(LINUX_EPERM),
        Permission::Asked => {
            wake_linux_descriptor_waits();
            Some(linux_retry_later_live_return(output, caller, number))
        }
        Permission::Waiting => Some(linux_retry_later_live_return(output, caller, number)),
    }
}

/// fanotify_mark(2), with Linux's checks in Linux's order.
pub(super) fn linux_fanotify_mark(
    descriptor: u64,
    flags: u64,
    mask: u64,
    directory: u64,
    path_address: u64,
) -> u64 {
    use crate::linux_fanotify::{
        Change, Command, MarkKind, DIRENT_EVENTS, EVENT_FLAGS, FAN_EVENT_ON_CHILD, FAN_FS_ERROR,
        FAN_RENAME, FAN_REPORT_DIR_FID, FAN_REPORT_NAME, FAN_REPORT_TARGET_FID, FID_BITS,
        PATH_EVENTS, PERMISSION_EVENTS, UNPRIVILEGED, VALID_MASK,
    };
    const FAN_MARK_ADD: u32 = 0x1;
    const FAN_MARK_REMOVE: u32 = 0x2;
    const FAN_MARK_DONT_FOLLOW: u32 = 0x4;
    const FAN_MARK_ONLYDIR: u32 = 0x8;
    const FAN_MARK_MOUNT: u32 = 0x10;
    const FAN_MARK_IGNORED_MASK: u32 = 0x20;
    const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x40;
    const FAN_MARK_FLUSH: u32 = 0x80;
    const FAN_MARK_FILESYSTEM: u32 = 0x100;
    const FAN_MARK_EVICTABLE: u32 = 0x200;
    const FAN_MARK_IGNORE: u32 = 0x400;
    const TYPE_BITS: u32 = FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM;
    const COMMAND_BITS: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH;
    const IGNORE_BITS: u32 = FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE;
    const VALID_FLAGS: u32 = TYPE_BITS
        | COMMAND_BITS
        | IGNORE_BITS
        | FAN_MARK_DONT_FOLLOW
        | FAN_MARK_ONLYDIR
        | FAN_MARK_IGNORED_SURV_MODIFY
        | FAN_MARK_EVICTABLE;
    const CLASS_BITS: u32 = 0xc;
    let descriptor = u64::from(descriptor as u32);
    let flags = flags as u32;
    // Only the lower 32 bits of the mask mean anything yet.
    let Ok(mut mask) = u32::try_from(mask) else {
        return LINUX_EINVAL;
    };
    let mark_type = flags & TYPE_BITS;
    let command = flags & COMMAND_BITS;
    let ignore = flags & IGNORE_BITS;
    if flags & !VALID_FLAGS != 0
        || mark_type == TYPE_BITS
        || match command {
            FAN_MARK_ADD | FAN_MARK_REMOVE => mask == 0,
            FAN_MARK_FLUSH => flags & !(TYPE_BITS | FAN_MARK_FLUSH) != 0,
            _ => true,
        }
        || mask & !VALID_MASK != 0
        || ignore == IGNORE_BITS
    {
        return LINUX_EINVAL;
    }
    // A legacy ignore mask has no event flags.
    let mut unset = 0;
    if ignore == FAN_MARK_IGNORED_MASK {
        mask &= !EVENT_FLAGS;
        unset = EVENT_FLAGS;
    }
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let Some((domain, group)) = linux_fanotify_key(descriptor) else {
        return LINUX_EINVAL;
    };
    let Some((group_flags, _)) = fanotify::flags(domain, group) else {
        return LINUX_EINVAL;
    };
    // Mount and filesystem marks take CAP_SYS_ADMIN, in the group's maker
    // and in the caller.
    if (!linux_fanotify_admin() || group_flags & UNPRIVILEGED != 0) && mark_type != 0 {
        return LINUX_EPERM;
    }
    // Permission events need a content class; an error event a filesystem
    // mark; an evictable mark an inode; the events with no file to open a
    // group reporting identifiers and no mount mark (they have no path to
    // tell the mount by); FAN_RENAME the names.
    let fid_mode = group_flags & FID_BITS;
    if mask & PERMISSION_EVENTS != 0 && group_flags & CLASS_BITS == 0
        || mask & FAN_FS_ERROR != 0 && mark_type != FAN_MARK_FILESYSTEM
        || flags & FAN_MARK_EVICTABLE != 0 && mark_type != 0
        || mask & !(PATH_EVENTS | PERMISSION_EVENTS | EVENT_FLAGS) != 0
            && (fid_mode == 0 || mark_type == FAN_MARK_MOUNT)
        || mask & FAN_RENAME != 0 && fid_mode & FAN_REPORT_NAME == 0
    {
        return LINUX_EINVAL;
    }
    if command == FAN_MARK_FLUSH {
        return match fanotify::flush(
            domain,
            group,
            mark_type == FAN_MARK_MOUNT,
            mark_type == FAN_MARK_FILESYSTEM,
        ) {
            Ok(()) => 0,
            Err(_) => LINUX_EINVAL,
        };
    }
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length = if path_address == 0 {
        // No path: the mark goes on what `directory` refers to. A pipe's
        // or socket's filesystem is the kernel's own, which no mount or
        // filesystem mark may watch.
        let directory = u64::from(directory as u32);
        if directory != u64::from(LINUX_AT_FDCWD)
            && mark_type != 0
            && (linux_pipe_descriptor(directory) || linux_socket_slot(directory).is_some())
        {
            return LINUX_EINVAL;
        }
        if let Some(path) = (directory != u64::from(LINUX_AT_FDCWD))
            .then(|| linux_descriptor_canonical_path(directory))
            .flatten()
        {
            canonical[..path.len()].copy_from_slice(&path);
            path.len()
        } else {
            match linux_walk_start(directory, &mut canonical) {
                Ok(length) => length,
                Err(error) => return error,
            }
        }
    } else {
        let mut path = [0_u8; LINUX_PATH_MAX];
        let path_length = match copy_linux_c_string(path_address, &mut path) {
            Ok(length) => length,
            Err(error) => return error,
        };
        let length = match linux_canonical_path_at(directory, &path[..path_length], &mut canonical)
        {
            Ok(length) => length,
            // The root has an empty canonical path.
            Err(LINUX_EISDIR) => 0,
            Err(error) => return error,
        };
        if flags & FAN_MARK_DONT_FOLLOW == 0 {
            match linux_overlay_lookup_following(&mut canonical, length, true) {
                Ok((length, ..)) => length,
                Err(error) => return error,
            }
        } else {
            length
        }
    };
    let path = &canonical[..length];
    let exists = linux_inotify_exists(path)
        || LinuxCharacterDevice::from_canonical(path).is_some()
        || linux_api_directory(path);
    if !exists {
        return LINUX_ENOENT;
    }
    let is_directory = linux_inotify_is_directory(path) || linux_api_directory(path);
    if flags & FAN_MARK_ONLYDIR != 0 && !is_directory {
        return LINUX_ENOTDIR;
    }
    let inode = mark_type == 0;
    // With the v5.17 interfaces, events and flags only a directory has are
    // refused on an inode mark of anything else.
    let strict = group_flags & FAN_REPORT_TARGET_FID != 0
        || mask & FAN_RENAME != 0
        || ignore == FAN_MARK_IGNORE;
    if command == FAN_MARK_ADD
        && strict
        && inode
        && !is_directory
        && mask & (DIRENT_EVENTS | EVENT_FLAGS) != 0
    {
        return LINUX_ENOTDIR;
    }
    // A group reporting identifiers needs objects that have them.
    let node = linux_fanotify_node(path);
    if fid_mode != 0 && node.as_ref().is_none_or(|node| node.handle.is_none()) {
        return LINUX_EOPNOTSUPP;
    }
    if command == FAN_MARK_ADD
        && ignore != 0
        && flags & FAN_MARK_IGNORED_SURV_MODIFY == 0
        && ignore == FAN_MARK_IGNORE
        && (!inode || is_directory)
    {
        return if inode { LINUX_EISDIR } else { LINUX_EINVAL };
    }
    // Only a directory's inode mark hears its entries; a group reporting
    // directories asks every other mark for its file's directory and name.
    if !inode || !is_directory {
        mask &= !FAN_EVENT_ON_CHILD;
        unset |= FAN_EVENT_ON_CHILD;
        if fid_mode & FAN_REPORT_DIR_FID != 0 && command == FAN_MARK_ADD && ignore == 0 {
            mask |= FAN_EVENT_ON_CHILD;
        }
    }
    let kind = match mark_type {
        FAN_MARK_MOUNT => {
            MarkKind::Mount(crate::linux_mounts::mount_id_at(linux_mount_space(), path))
        }
        FAN_MARK_FILESYSTEM => MarkKind::Filesystem(linux_fanotify_fsid(path)),
        _ => MarkKind::Inode,
    };
    let change = Change {
        mask,
        ignore: ignore != 0,
        ignore_flags: ignore == FAN_MARK_IGNORE,
        survive_modify: flags & FAN_MARK_IGNORED_SURV_MODIFY != 0,
        unset,
    };
    let command = if command == FAN_MARK_ADD {
        Command::Add
    } else {
        Command::Remove
    };
    let handle = node.as_ref().and_then(|node| node.handle);
    match fanotify::mark(domain, group, command, (kind, path, handle), change) {
        Ok(()) => 0,
        Err(fanotify::Error::NotFound) => LINUX_ENOENT,
        Err(fanotify::Error::NoMemory) => LINUX_ENOMEM,
        Err(fanotify::Error::TooMany | fanotify::Error::NoSpace) => LINUX_ENOSPC,
        Err(fanotify::Error::Invalid) => LINUX_EINVAL,
    }
}

/// Opens canonical `path` for a listener, with its group's event_f_flags;
/// what the listener does with it raises no events. A file that is gone
/// is reported without a descriptor; an open Linux would fail too (a
/// read-only mount for O_RDWR, no descriptor free) is the read's error.
fn linux_fanotify_open(path: &[u8], flags: u32) -> Result<Option<i32>, u64> {
    let mut absolute = [0_u8; LINUX_PATH_MAX];
    let length = path.len() + 1;
    let Some(target) = absolute.get_mut(1..length) else {
        return Ok(None);
    };
    target.copy_from_slice(path);
    absolute[0] = b'/';
    let descriptor = linux_openat_path(
        u64::from(LINUX_AT_FDCWD),
        absolute,
        length,
        u64::from(flags),
        0,
    );
    if descriptor >= LINUX_RETURN_TO_KERNEL {
        return match descriptor {
            LINUX_EROFS | LINUX_EMFILE | LINUX_ENFILE | LINUX_ETXTBSY => Err(descriptor),
            _ => Ok(None),
        };
    }
    let Ok(event_descriptor) = i32::try_from(descriptor) else {
        return Ok(None);
    };
    let flags = usize::try_from(descriptor)
        .ok()
        .and_then(|index| X86_RUNTIME.ELF_PROBE_STDIO_SOCKET_FLAGS.get(index))
        .or_else(|| {
            X86_RUNTIME
                .ELF_PROBE_SOCKET_FLAGS
                .get(linux_socket_descriptor_index(descriptor)?)
        });
    if let Some(flags) = flags {
        flags.fetch_or(LINUX_PRIVATE_NONOTIFY_DESCRIPTOR, Ordering::SeqCst);
    }
    Ok(Some(event_descriptor))
}

/// read(2) on a group: as many queued events as fit, each with a
/// descriptor of its object opened for the reader (a group reporting
/// descriptors), its identifier records (a group reporting identifiers)
/// and a pidfd of its process (FAN_REPORT_PIDFD).
pub(super) fn linux_fanotify_read(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    use crate::linux_fanotify::{
        EVENT_METADATA_SIZE, FAN_REPORT_PIDFD, PIDFD_INFO_SIZE, UNPRIVILEGED,
    };
    const METADATA_VERSION: u8 = 3;
    /// The pidfd record's type (FAN_EVENT_INFO_TYPE_PIDFD).
    const INFO_PIDFD: u8 = 4;
    const FAN_NOPIDFD: i32 = -1;
    const FAN_EPIDFD: i32 = -2;
    let (domain, group) = linux_fanotify_key(descriptor)?;
    let (group_flags, event_flags) = fanotify::flags(domain, group)?;
    let room = usize::try_from(count).unwrap_or(usize::MAX);
    let events = match fanotify::take(domain, group, room) {
        Ok(events) => events,
        Err(fanotify::Error::Invalid) => return Some(LINUX_EINVAL),
        Err(_) => return Some(LINUX_ENOMEM),
    };
    if events.is_empty() {
        return Some(LINUX_EAGAIN);
    }
    let reader = current_linux_process_pid();
    let pidfd_mode = group_flags & FAN_REPORT_PIDFD != 0;
    let mut written = 0_u64;
    for event in events {
        // An unprivileged group gets no descriptors and sees only its own
        // process's pid.
        let opened = match event.path.as_deref() {
            Some(path) if group_flags & UNPRIVILEGED == 0 => linux_fanotify_open(path, event_flags),
            _ => Ok(None),
        };
        let event_descriptor = match opened {
            Ok(event_descriptor) => event_descriptor,
            Err(error) => {
                if let Some(request) = event.request {
                    fanotify::delivered(domain, group, request, None);
                }
                return Some(if written == 0 { error } else { written });
            }
        };
        let pid = if event.pid == 0 || group_flags & UNPRIVILEGED != 0 && event.pid != reader {
            0
        } else {
            linux_pid_seen_by(reader, event.pid)
        };
        let pidfd = if !pidfd_mode {
            None
        } else if pid == 0 {
            Some(FAN_NOPIDFD)
        } else {
            match linux_pidfd_open(u64::from(event.pid), 0) {
                LINUX_ESRCH => Some(FAN_NOPIDFD),
                opened if opened >= LINUX_RETURN_TO_KERNEL => Some(FAN_EPIDFD),
                opened => Some(opened as i32),
            }
        };
        let size = EVENT_METADATA_SIZE
            + event.records.len()
            + if pidfd_mode { PIDFD_INFO_SIZE } else { 0 };
        let mut metadata = [0_u8; EVENT_METADATA_SIZE];
        metadata[..4].copy_from_slice(&(size as u32).to_ne_bytes());
        metadata[4] = METADATA_VERSION;
        metadata[6..8].copy_from_slice(&(EVENT_METADATA_SIZE as u16).to_ne_bytes());
        metadata[8..16].copy_from_slice(&u64::from(event.mask).to_ne_bytes());
        metadata[16..20].copy_from_slice(&event_descriptor.unwrap_or(-1).to_ne_bytes());
        metadata[20..24].copy_from_slice(&pid.to_ne_bytes());
        let at = address + written;
        let mut copied = copy_to_linux_user(at, &metadata)
            && (event.records.is_empty()
                || copy_to_linux_user(at + EVENT_METADATA_SIZE as u64, &event.records));
        if let Some(pidfd) = pidfd {
            let mut record = [0_u8; PIDFD_INFO_SIZE];
            record[0] = INFO_PIDFD;
            record[2..4].copy_from_slice(&(PIDFD_INFO_SIZE as u16).to_ne_bytes());
            record[4..].copy_from_slice(&pidfd.to_ne_bytes());
            copied = copied
                && copy_to_linux_user(
                    at + (EVENT_METADATA_SIZE + event.records.len()) as u64,
                    &record,
                );
        }
        if !copied {
            if let Some(event_descriptor) = event_descriptor {
                let _ = linux_descriptor_close(event_descriptor as u64);
            }
            if let Some(pidfd) = pidfd.filter(|pidfd| *pidfd >= 0) {
                let _ = linux_descriptor_close(pidfd as u64);
            }
        }
        if let Some(request) = event.request {
            fanotify::delivered(domain, group, request, event_descriptor.filter(|_| copied));
        }
        if !copied {
            return Some(if written == 0 { LINUX_EFAULT } else { written });
        }
        written += size as u64;
    }
    Some(written)
}

/// write(2) on a group: a struct fanotify_response answering a
/// permission event.
pub(super) fn linux_fanotify_write(descriptor: u64, address: u64, count: u64) -> Option<u64> {
    const RESPONSE_SIZE: u64 = 8;
    let (domain, group) = linux_fanotify_key(descriptor)?;
    if count < RESPONSE_SIZE {
        return Some(LINUX_EINVAL);
    }
    let mut response = [0_u8; RESPONSE_SIZE as usize];
    if !copy_from_linux_user(address, &mut response) {
        return Some(LINUX_EFAULT);
    }
    let event_descriptor = i32::from_ne_bytes(response[..4].try_into().unwrap());
    let answer = u32::from_ne_bytes(response[4..].try_into().unwrap());
    Some(
        match fanotify::respond(domain, group, event_descriptor, answer) {
            Ok(()) => RESPONSE_SIZE,
            Err(fanotify::Error::NotFound) => LINUX_ENOENT,
            Err(_) => LINUX_EINVAL,
        },
    )
}

/// /proc/PID/fdinfo/N of a group: its flags and a line for each mark,
/// in Linux's format.
pub(super) fn linux_fanotify_fdinfo(descriptor: u64) -> Option<Vec<u8>> {
    use core::fmt::Write;
    struct Text(Vec<u8>);
    impl core::fmt::Write for Text {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            self.0
                .try_reserve(text.len())
                .map_err(|_| core::fmt::Error)?;
            self.0.extend_from_slice(text.as_bytes());
            Ok(())
        }
    }
    let (domain, group) = linux_fanotify_key(descriptor)?;
    let (flags, event_flags, marks) = fanotify::view(domain, group)?;
    let status = linux_socket_flags(descriptor).unwrap_or(0) & LINUX_O_NONBLOCK as u32;
    let close_on_exec = if linux_descriptor_close_on_exec(descriptor) {
        0o2_000_000
    } else {
        0
    };
    let mut text = Text(Vec::new());
    write!(
        text,
        "pos:\t0\nflags:\t0{:o}\nmnt_id:\t1\nino:\t1\nfanotify flags:{:x} event-flags:{:x}\n",
        2 | status | close_on_exec,
        flags,
        event_flags
    )
    .ok()?;
    for mark in marks {
        match mark.kind {
            fanotify::MarkKind::Inode => {
                let handle = linux_fanotify_node(&mark.path).and_then(|node| node.handle);
                let inode = handle.map_or(1, |handle| {
                    u32::from_ne_bytes([handle[0], handle[1], handle[2], handle[3]])
                });
                write!(
                    text,
                    "fanotify ino:{:x} sdev:0 mflags:{:x} mask:{:x} ignored_mask:{:x} ",
                    inode, mark.flags, mark.mask, mark.ignore
                )
                .ok()?;
                if let Some(handle) = handle {
                    write!(
                        text,
                        "fhandle-bytes:8 fhandle-type:{:x} f_handle:",
                        fanotify::HANDLE_TYPE
                    )
                    .ok()?;
                    for byte in handle {
                        write!(text, "{byte:02x}").ok()?;
                    }
                }
                text.write_str("\n").ok()?;
            }
            fanotify::MarkKind::Mount(id) => writeln!(
                text,
                "fanotify mnt_id:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x}",
                id, mark.flags, mark.mask, mark.ignore
            )
            .ok()?,
            fanotify::MarkKind::Filesystem(fsid) => writeln!(
                text,
                "fanotify sdev:{:x} mflags:{:x} mask:{:x} ignored_mask:{:x}",
                u32::from_ne_bytes([fsid[0], fsid[1], fsid[2], fsid[3]]),
                mark.flags,
                mark.mask,
                mark.ignore
            )
            .ok()?,
        }
    }
    Some(text.0)
}

pub(super) fn linux_fanotify_ready(descriptor: u64) -> bool {
    linux_fanotify_key(descriptor).is_some_and(|(domain, group)| fanotify::ready(domain, group))
}

/// Process `pid` ended: the groups it made go with it, as with its last
/// descriptors of them. Skipped (left to the domain's end) when a lock
/// ranked above fanotify's is held.
pub(super) fn linux_fanotify_exit(pid: u32) {
    if crate::sync::rank_available(crate::sync::LockRank::FANOTIFY) {
        fanotify::exit_process(linux_execution_instance(), pid);
    }
}

/// Closing a group's descriptor: the group goes when its creator closes
/// its last descriptor of it.
pub(super) fn linux_fanotify_release(descriptor: u64) {
    let Some((domain, group)) = linux_fanotify_key(descriptor) else {
        return;
    };
    if (0..LINUX_DESCRIPTOR_TABLE_LIMIT).any(|candidate| {
        candidate != descriptor
            && linux_fanotify_descriptor(candidate)
            && linux_descriptor_open_file_id(candidate) == Some(group)
    }) {
        return;
    }
    fanotify::release(domain, Some(group), current_linux_process_pid());
}
