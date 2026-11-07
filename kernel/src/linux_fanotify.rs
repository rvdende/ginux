//! fanotify(7): groups, their marks on files, directories, mounts and
//! filesystems, and the events they queue, permission events among them.
//!
//! A mark names a file or directory by its canonical path (under the
//! domain's root), as inotify watches do, a mount by its id, or a
//! filesystem by its fsid (statfs's f_fsid). The kernel reports what
//! happened as a [`Notice`], shaped as Linux's fsnotify calls are: an event
//! on a file or directory (open, read, write, close, attribute changes),
//! which its parent hears when it watches its children or a mark wants
//! the parent and name; a change of a directory's entries (create, delete,
//! move, rename), which the directory hears; or an event on an inode itself
//! (deleted, moved). Each group that hears it queues one event, which
//! merges with a queued one of the same object, process and kind, as in
//! Linux.
//!
//! A group made with FAN_REPORT_FID, FAN_REPORT_DIR_FID, FAN_REPORT_NAME
//! or FAN_REPORT_TARGET_FID reports its events with file identifiers
//! (fsid and file handle, as statfs and name_to_handle_at give them) and
//! names instead of descriptors, and chooses which of the object, its
//! directory, the entry's name and the rename's new directory and name to
//! report as Linux's does; such groups also hear the directory entry
//! events.
//!
//! A permission event (FAN_ACCESS_PERM, ...) holds the thread that caused
//! it until every group it reached answers by writing a response for the
//! event's descriptor, or closes; the thread asks again each time its
//! system call restarts (`permission`).
#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

pub(crate) const FAN_ACCESS: u32 = 0x0000_0001;
pub(crate) const FAN_MODIFY: u32 = 0x0000_0002;
pub(crate) const FAN_ATTRIB: u32 = 0x0000_0004;
pub(crate) const FAN_CLOSE_WRITE: u32 = 0x0000_0008;
pub(crate) const FAN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub(crate) const FAN_OPEN: u32 = 0x0000_0020;
pub(crate) const FAN_MOVED_FROM: u32 = 0x0000_0040;
pub(crate) const FAN_MOVED_TO: u32 = 0x0000_0080;
pub(crate) const FAN_CREATE: u32 = 0x0000_0100;
pub(crate) const FAN_DELETE: u32 = 0x0000_0200;
pub(crate) const FAN_DELETE_SELF: u32 = 0x0000_0400;
pub(crate) const FAN_MOVE_SELF: u32 = 0x0000_0800;
pub(crate) const FAN_OPEN_EXEC: u32 = 0x0000_1000;
pub(crate) const FAN_Q_OVERFLOW: u32 = 0x0000_4000;
pub(crate) const FAN_FS_ERROR: u32 = 0x0000_8000;
pub(crate) const FAN_OPEN_PERM: u32 = 0x0001_0000;
pub(crate) const FAN_ACCESS_PERM: u32 = 0x0002_0000;
pub(crate) const FAN_OPEN_EXEC_PERM: u32 = 0x0004_0000;
pub(crate) const FAN_EVENT_ON_CHILD: u32 = 0x0800_0000;
pub(crate) const FAN_RENAME: u32 = 0x1000_0000;
pub(crate) const FAN_ONDIR: u32 = 0x4000_0000;

/// fanotify_init's flags for what events report.
pub(crate) const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
pub(crate) const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
pub(crate) const FAN_REPORT_TID: u32 = 0x0000_0100;
pub(crate) const FAN_REPORT_FID: u32 = 0x0000_0200;
pub(crate) const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
pub(crate) const FAN_REPORT_NAME: u32 = 0x0000_0800;
pub(crate) const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;
/// The flags that make a group report file identifiers.
pub(crate) const FID_BITS: u32 =
    FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID;
/// A group made without CAP_SYS_ADMIN (Linux's FANOTIFY_UNPRIV): no mount
/// or filesystem marks, and the pids of other processes are not reported.
pub(crate) const UNPRIVILEGED: u32 = 0x8000_0000;

/// Events that carry an open file (and so a descriptor for the listener).
pub(crate) const PATH_EVENTS: u32 =
    FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN | FAN_OPEN_EXEC;
pub(crate) const PERMISSION_EVENTS: u32 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;
/// Changes of a directory's entries, which the directory hears.
pub(crate) const DIRENT_EVENTS: u32 =
    FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CREATE | FAN_DELETE | FAN_RENAME;
/// Events about directory entries and inodes, which only groups reporting
/// file handles may ask for.
pub(crate) const INODE_EVENTS: u32 = DIRENT_EVENTS | FAN_ATTRIB | FAN_DELETE_SELF | FAN_MOVE_SELF;
/// Flags that steer which objects a mark hears rather than events.
pub(crate) const EVENT_FLAGS: u32 = FAN_ONDIR | FAN_EVENT_ON_CHILD;
/// Everything a mark's mask may hold.
pub(crate) const VALID_MASK: u32 =
    PATH_EVENTS | PERMISSION_EVENTS | INODE_EVENTS | FAN_FS_ERROR | EVENT_FLAGS;
/// The events (Linux's ALL_FSNOTIFY_EVENTS as fanotify knows them).
const ALL_EVENTS: u32 = PATH_EVENTS | PERMISSION_EVENTS | INODE_EVENTS | FAN_FS_ERROR;
/// What an event's mask may show its reader.
const OUTGOING: u32 = ALL_EVENTS | FAN_Q_OVERFLOW | FAN_ONDIR;
/// Events that happen to a file, which its parent may hear.
const CHILD_EVENTS: u32 = FAN_ACCESS
    | FAN_MODIFY
    | FAN_ATTRIB
    | FAN_CLOSE_WRITE
    | FAN_CLOSE_NOWRITE
    | FAN_OPEN
    | FAN_OPEN_EXEC
    | PERMISSION_EVENTS;
/// What one event reports, by the fanotify_event_metadata it is read as.
pub(crate) const EVENT_METADATA_SIZE: usize = 24;
/// The default queue limit (/proc/sys/fs/fanotify/max_queued_events).
pub(crate) const DEFAULT_QUEUE_LIMIT: usize = 16_384;
/// The most groups a domain may have (max_user_groups).
pub(crate) const GROUP_LIMIT: usize = 128;
/// The most marks a domain may have (max_user_marks).
pub(crate) const MARK_LIMIT: usize = 8_192;
/// How many queued events a new one may merge with (Linux's limit).
const MERGE_DEPTH: usize = 128;

/// The file handle type of Ginux's handles (name_to_handle_at).
pub(crate) const HANDLE_TYPE: i32 = 0x474e;
/// The handle type reported for an object with no handle.
const FILEID_INVALID: i32 = 0xff;
/// Info record types (FAN_EVENT_INFO_TYPE_*).
const INFO_FID: u8 = 1;
const INFO_DFID_NAME: u8 = 2;
const INFO_DFID: u8 = 3;
const INFO_OLD_DFID_NAME: u8 = 10;
const INFO_NEW_DFID_NAME: u8 = 12;
/// The size of struct fanotify_event_info_pidfd.
pub(crate) const PIDFD_INFO_SIZE: usize = 8;

/// The answers a listener writes for a permission event (struct
/// fanotify_response's response).
pub(crate) const FAN_ALLOW: u32 = 0x01;
pub(crate) const FAN_DENY: u32 = 0x02;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// No such group, an answer that is not one, or a buffer too small
    /// for the first event.
    Invalid,
    /// No such mark, or no permission event awaits that descriptor.
    NotFound,
    /// Too many groups.
    TooMany,
    /// Too many marks.
    NoSpace,
    NoMemory,
}

/// What a mark is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarkKind {
    /// A file or directory, by its path.
    Inode,
    /// Every object on a mount (FAN_MARK_MOUNT), by its id.
    Mount(u32),
    /// Every object on a filesystem (FAN_MARK_FILESYSTEM), by its fsid.
    Filesystem([u8; 8]),
}

/// The mark commands of fanotify_mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Command {
    Add,
    Remove,
}

/// How a mark changes: the events and flags, into its mask or its ignore
/// mask, and the ignore mask's kind.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Change {
    pub(crate) mask: u32,
    /// FAN_MARK_IGNORED_MASK or FAN_MARK_IGNORE: the ignore mask changes.
    pub(crate) ignore: bool,
    /// FAN_MARK_IGNORE: the ignore mask's FAN_ONDIR and FAN_EVENT_ON_CHILD
    /// count, as they do in a mark's mask.
    pub(crate) ignore_flags: bool,
    /// FAN_MARK_IGNORED_SURV_MODIFY: a modification leaves the ignore mask.
    pub(crate) survive_modify: bool,
    /// Flags a removal takes off too (Linux's umask: the event flags a
    /// legacy ignore mask or a mark that cannot hear children never keeps).
    pub(crate) unset: u32,
}

struct Mark {
    kind: MarkKind,
    path: Vec<u8>,
    mask: u32,
    ignore: u32,
    ignore_flags: bool,
    survive_modify: bool,
}

/// Where a mark stands to the object of an event (Linux's iteration
/// types).
#[derive(Clone, Copy, Eq, PartialEq)]
enum Place {
    /// On the object (for a directory entry event, the directory).
    Own,
    /// On the object's directory, which watches its children.
    Parent,
    /// On a rename's new directory.
    Second,
    Mount,
    Filesystem,
}

impl Mark {
    /// Whether `mask` (a mark's mask or ignore mask with its flags) speaks
    /// for an object that is a directory or not, from `place`.
    fn applicable(mask: u32, directory: bool, place: Place) -> bool {
        (!directory || mask & FAN_ONDIR != 0)
            && (place != Place::Parent || mask & FAN_EVENT_ON_CHILD != 0)
    }

    /// The events this mark ignores for the object.
    fn ignored(&self, directory: bool, place: Place) -> u32 {
        let events = self.ignore & !EVENT_FLAGS;
        // A legacy ignore mask (FAN_MARK_IGNORED_MASK) ignores its events
        // everywhere; FAN_MARK_IGNORE's heeds its flags.
        if events == 0
            || !self.ignore_flags
            || !directory && place != Place::Parent
            || Self::applicable(self.ignore, directory, place)
        {
            events
        } else {
            0
        }
    }

    /// The events this mark asks for on the object.
    fn heard(&self, directory: bool, place: Place) -> u32 {
        if Self::applicable(self.mask, directory, place) {
            self.mask & !EVENT_FLAGS
        } else {
            0
        }
    }

    /// The mask the object's inode shows for this mark (Linux's
    /// fsnotify_calc_mask): its mask, with its ignore mask's events and
    /// flags (so that a directory ignoring its children's events still
    /// hears of them), and FAN_MODIFY when a modification clears the
    /// ignore mask.
    fn watching(&self) -> u32 {
        if self.ignore == 0 {
            return self.mask;
        }
        let ignore = if self.ignore_flags {
            self.ignore
        } else {
            self.ignore & !EVENT_FLAGS
        };
        self.mask | ignore | if self.survive_modify { 0 } else { FAN_MODIFY }
    }
}

/// A file or directory as an event names it.
#[derive(Clone, Copy)]
pub(crate) struct Node<'a> {
    /// Its canonical path.
    pub(crate) path: &'a [u8],
    pub(crate) directory: bool,
    /// Whether it is a regular file or a directory: the objects an event
    /// with a descriptor may name.
    pub(crate) openable: bool,
    /// statfs's f_fsid of its filesystem.
    pub(crate) fsid: [u8; 8],
    /// Its file handle as name_to_handle_at encodes it; None when it has
    /// none.
    pub(crate) handle: Option<[u8; 8]>,
}

impl Node<'_> {
    fn same(&self, other: &Node) -> bool {
        match (self.handle, other.handle) {
            (Some(first), Some(second)) => first == second,
            _ => self.path == other.path,
        }
    }
}

/// How an event happened, as Linux's fsnotify hooks tell it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Kind {
    /// To a file or directory (fsnotify_parent): its directory hears it if
    /// it watches its children, or a mark wants the directory and name.
    File,
    /// To a directory's entry `name` (fsnotify_name): the directory hears
    /// it.
    Entry,
    /// To an inode itself (fsnotify_inode): deleted, moved, its link count.
    Inode,
}

/// Something that happened, for the groups of a domain to hear.
#[derive(Clone, Copy)]
pub(crate) struct Notice<'a> {
    pub(crate) kind: Kind,
    /// The events, without FAN_ONDIR (which `object.directory` gives).
    pub(crate) mask: u32,
    /// The file or directory it happened to (the entry, for an entry
    /// event; the renamed file, at its new name, for FAN_RENAME).
    pub(crate) object: Node<'a>,
    /// Its directory (none for the root), or the directory whose entry
    /// changed.
    pub(crate) directory: Option<Node<'a>>,
    /// The object's name in `directory`.
    pub(crate) name: &'a [u8],
    /// FAN_RENAME's new directory and name.
    pub(crate) moved: Option<(Node<'a>, &'a [u8])>,
    /// The mount, when the event is about an open file (a path): only then
    /// do mount marks hear it, and groups reporting descriptors.
    pub(crate) mount: Option<u32>,
}

/// The object a permission event happens to.
#[derive(Clone, Copy)]
pub(crate) struct Object<'a> {
    /// Its canonical path.
    pub(crate) path: &'a [u8],
    pub(crate) directory: bool,
    /// The id of the mount it lies on (0 for the root's own files).
    pub(crate) mount: u32,
    /// statfs's f_fsid of its filesystem.
    pub(crate) fsid: [u8; 8],
}

impl Object<'_> {
    fn place(&self, mark: &Mark) -> Option<Place> {
        match mark.kind {
            MarkKind::Inode if mark.path == self.path => Some(Place::Own),
            MarkKind::Inode if !self.path.is_empty() && mark.path == split(self.path).0 => {
                Some(Place::Parent)
            }
            MarkKind::Mount(id) if id == self.mount => Some(Place::Mount),
            MarkKind::Filesystem(fsid) if fsid == self.fsid => Some(Place::Filesystem),
            _ => None,
        }
    }
}

/// Who caused an event: its process and thread.
#[derive(Clone, Copy)]
pub(crate) struct Cause {
    pub(crate) pid: u32,
    pub(crate) tid: u32,
}

/// What an event identifies its object by.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Info {
    Overflow,
    /// A group reporting descriptors: the object to open.
    Path(Vec<u8>),
    /// One file identifier: the object, or (FAN_REPORT_DIR_FID) its
    /// directory.
    Fid {
        fsid: [u8; 8],
        object: Option<[u8; 8]>,
    },
    /// A directory and the entry's name, a rename's new directory and
    /// name, and the entry's own identifier, as the group asks.
    Name {
        fsid: [u8; 8],
        directory: Option<[u8; 8]>,
        second: Option<[u8; 8]>,
        child: Option<[u8; 8]>,
        name: Vec<u8>,
        second_name: Vec<u8>,
    },
}

struct Event {
    /// The events and, for a group reporting identifiers, FAN_ONDIR.
    mask: u32,
    info: Info,
    /// Whether the object is a directory (events on directories and on
    /// other files do not merge).
    ondir: bool,
    /// The process or thread reported (FAN_REPORT_TID), 0 for an overflow.
    pid: u32,
    /// The permission request this event asks the group about.
    request: Option<u64>,
}

impl Event {
    /// Linux's fanotify_should_merge.
    fn merges_with(&self, new: &Event) -> bool {
        if self.request.is_some()
            || self.pid != new.pid
            || self.ondir != new.ondir
            || (self.mask ^ new.mask) & FAN_RENAME != 0
        {
            return false;
        }
        match (&self.info, &new.info) {
            (Info::Path(old), Info::Path(new)) => old == new,
            (
                Info::Fid {
                    fsid,
                    object: Some(object),
                },
                Info::Fid {
                    fsid: new_fsid,
                    object: new_object,
                },
            ) => fsid == new_fsid && Some(*object) == *new_object,
            (old @ Info::Name { directory, .. }, new @ Info::Name { .. }) => {
                directory.is_some() && old == new
            }
            _ => false,
        }
    }
}

/// An event as read: what read(2) reports and the descriptor it opens.
pub(crate) struct Delivery {
    pub(crate) mask: u32,
    /// The object to open for the listener; none for an overflow and for
    /// a group reporting identifiers.
    pub(crate) path: Option<Vec<u8>>,
    pub(crate) pid: u32,
    pub(crate) request: Option<u64>,
    /// The info records that follow the metadata (the identifier records;
    /// the pidfd record, FAN_REPORT_PIDFD, is the reader's to add).
    pub(crate) records: Vec<u8>,
}

struct Group {
    domain: usize,
    id: u64,
    /// The process that made it: a child closing an inherited descriptor
    /// leaves the group to it, as with inotify instances.
    creator: u32,
    /// fanotify_init's flags, with UNPRIVILEGED.
    flags: u32,
    /// fanotify_init's event_f_flags: how event descriptors are opened.
    event_flags: u32,
    marks: Vec<Mark>,
    queue: VecDeque<Event>,
    limit: usize,
    /// Permission events read and not yet answered: the listener's
    /// descriptor for each and its request.
    awaiting: Vec<(i32, u64)>,
}

impl Group {
    /// The events of `mask` this group hears on `object` (permission
    /// events).
    fn interest(&self, object: &Object, mask: u32) -> u32 {
        let mut heard = 0;
        let mut ignored = 0;
        for mark in &self.marks {
            let Some(place) = object.place(mark) else {
                continue;
            };
            ignored |= mark.ignored(object.directory, place);
            heard |= mark.heard(object.directory, place);
        }
        mask & heard & !ignored
    }

    fn report_tid(&self) -> bool {
        self.flags & FAN_REPORT_TID != 0
    }

    fn fid_mode(&self) -> u32 {
        self.flags & FID_BITS
    }

    /// Queues an event, merged into a queued one as Linux merges them
    /// (never a permission event); past the queue's limit, an overflow
    /// event stands for what is lost.
    fn queue(&mut self, event: Event) {
        if event.request.is_none() {
            if self.queue.len() >= self.limit {
                if self
                    .queue
                    .back()
                    .is_none_or(|last| last.info != Info::Overflow)
                    && self.queue.try_reserve(1).is_ok()
                {
                    self.queue.push_back(Event {
                        mask: FAN_Q_OVERFLOW,
                        info: Info::Overflow,
                        ondir: false,
                        pid: 0,
                        request: None,
                    });
                }
                return;
            }
            if let Some(queued) = self
                .queue
                .iter_mut()
                .rev()
                .take(MERGE_DEPTH)
                .find(|queued| queued.merges_with(&event))
            {
                queued.mask |= event.mask;
                return;
            }
        }
        if self.queue.try_reserve(1).is_ok() {
            self.queue.push_back(event);
        }
    }

    /// The marks of this group the event reaches, with where each stands
    /// (a mark may stand twice: a rename within its directory).
    fn reached(&self, slots: &Slots) -> Vec<(usize, Place)> {
        let mut reached = Vec::new();
        for (index, mark) in self.marks.iter().enumerate() {
            let mut places = [None; 2];
            match mark.kind {
                MarkKind::Inode => {
                    if mark.path == slots.own {
                        places[0] = Some(Place::Own);
                    }
                    if let Some((path, place)) = slots.second {
                        // A directory that does not watch its children is
                        // no parent to the event.
                        let watches = place != Place::Parent
                            || (mark.mask | mark.ignore) & FAN_EVENT_ON_CHILD != 0;
                        if mark.path == path && watches {
                            places[1] = Some(place);
                        }
                    }
                }
                MarkKind::Mount(id) if slots.mount == Some(id) => places[0] = Some(Place::Mount),
                MarkKind::Filesystem(fsid) if fsid == slots.fsid => {
                    places[0] = Some(Place::Filesystem)
                }
                _ => {}
            }
            for place in places.into_iter().flatten() {
                if reached.try_reserve(1).is_ok() {
                    reached.push((index, place));
                }
            }
        }
        reached
    }
}

/// The objects whose marks an event reaches (Linux's iteration types).
struct Slots<'a> {
    own: &'a [u8],
    second: Option<(&'a [u8], Place)>,
    mount: Option<u32>,
    fsid: [u8; 8],
}

/// A permission request: a thread waiting for the groups its event
/// reached to answer.
struct Request {
    id: u64,
    domain: usize,
    tid: u32,
    path: Vec<u8>,
    mask: u32,
    /// Groups yet to answer.
    pending: usize,
    denied: bool,
}

struct State {
    groups: Vec<Group>,
    requests: Vec<Request>,
    next_request: u64,
}

impl State {
    /// A group's answer to request `id`.
    fn answer(&mut self, id: u64, allow: bool) {
        if let Some(request) = self.requests.iter_mut().find(|request| request.id == id) {
            request.pending = request.pending.saturating_sub(1);
            request.denied |= !allow;
        }
    }

    fn group(&mut self, domain: usize, id: u64) -> Option<&mut Group> {
        self.groups
            .iter_mut()
            .find(|group| group.domain == domain && group.id == id)
    }

    /// The union of the masks of every group's inode marks on `path`
    /// (Linux's i_fsnotify_mask).
    fn inode_mask(&self, domain: usize, path: &[u8]) -> u32 {
        self.groups
            .iter()
            .filter(|group| group.domain == domain)
            .flat_map(|group| group.marks.iter())
            .filter(|mark| mark.kind == MarkKind::Inode && mark.path == path)
            .fold(0, |mask, mark| mask | mark.watching())
    }

    /// The union of the masks of the marks of `kind` (a mount or a
    /// filesystem).
    fn kind_mask(&self, domain: usize, kind: MarkKind) -> u32 {
        self.groups
            .iter()
            .filter(|group| group.domain == domain)
            .flat_map(|group| group.marks.iter())
            .filter(|mark| mark.kind == kind)
            .fold(0, |mask, mark| mask | mark.watching())
    }

    fn marks(&self, domain: usize) -> usize {
        self.groups
            .iter()
            .filter(|group| group.domain == domain)
            .map(|group| group.marks.len())
            .sum()
    }
}

static STATE: SpinLock<State> = SpinLock::new(
    LockRank::FANOTIFY,
    State {
        groups: Vec::new(),
        requests: Vec::new(),
        next_request: 1,
    },
);
/// Marks in all domains, so file operations skip the table when none.
static MARKS: AtomicUsize = AtomicUsize::new(0);
/// Marks that ask for permission events, so reads skip the check when none.
static PERMISSION_MARKS: AtomicUsize = AtomicUsize::new(0);
/// Mount and filesystem marks, so events look up their mount only then.
static MOUNT_MARKS: AtomicUsize = AtomicUsize::new(0);
/// Groups reporting file identifiers, so the kernel describes directory
/// entry and inode events only when one exists.
static FID_GROUPS: AtomicUsize = AtomicUsize::new(0);

/// The directory part of a canonical path and its last component.
pub(crate) fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => (&path[..slash], &path[slash + 1..]),
        None => (&[], path),
    }
}

fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

/// Keeps the mark counters in step with a mark appearing (`added`) or
/// going.
fn count_mark(mark: &Mark, added: bool) {
    let counters = [
        (true, &MARKS),
        (mark.mask & PERMISSION_EVENTS != 0, &PERMISSION_MARKS),
        (mark.kind != MarkKind::Inode, &MOUNT_MARKS),
    ];
    for (counted, counter) in counters {
        if counted {
            if added {
                counter.fetch_add(1, Ordering::Relaxed);
            } else {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// Whether any domain has a mark: file operations call in only then.
pub(crate) fn active() -> bool {
    MARKS.load(Ordering::Relaxed) != 0
}

/// Whether any mark asks for permission events.
pub(crate) fn permission_active() -> bool {
    PERMISSION_MARKS.load(Ordering::Relaxed) != 0
}

/// Whether any mark is on a mount or filesystem, so events need their
/// object's mount and filesystem.
pub(crate) fn mount_marks() -> bool {
    MOUNT_MARKS.load(Ordering::Relaxed) != 0
}

/// Whether some group reports file identifiers: only such groups hear
/// directory entry and inode events.
pub(crate) fn identifier_groups() -> bool {
    FID_GROUPS.load(Ordering::Relaxed) != 0
}

/// A new group `id` of `domain` with fanotify_init's `flags` (with
/// UNPRIVILEGED) and `event_flags`.
pub(crate) fn create(
    domain: usize,
    id: u64,
    creator: u32,
    (flags, event_flags): (u32, u32),
) -> Result<(), Error> {
    let mut state = STATE.lock();
    if state
        .groups
        .iter()
        .filter(|group| group.domain == domain)
        .count()
        >= GROUP_LIMIT
    {
        return Err(Error::TooMany);
    }
    state.groups.try_reserve(1).map_err(|_| Error::NoMemory)?;
    state.groups.push(Group {
        domain,
        id,
        creator,
        flags,
        event_flags,
        marks: Vec::new(),
        queue: VecDeque::new(),
        limit: if flags & FAN_UNLIMITED_QUEUE != 0 {
            usize::MAX
        } else {
            DEFAULT_QUEUE_LIMIT
        },
        awaiting: Vec::new(),
    });
    if flags & FID_BITS != 0 {
        FID_GROUPS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

/// Group `id` goes when its creator closes its last descriptor of it
/// (`closer`), and every group of a domain with the domain (`id` None).
/// The permission events it holds are allowed, as Linux allows them.
pub(crate) fn release(domain: usize, id: Option<u64>, closer: u32) {
    let mut state = STATE.lock();
    let mut index = 0;
    while index < state.groups.len() {
        let group = &state.groups[index];
        let gone =
            group.domain == domain && id.is_none_or(|id| group.id == id && group.creator == closer);
        if !gone {
            index += 1;
            continue;
        }
        let group = state.groups.swap_remove(index);
        for mark in &group.marks {
            count_mark(mark, false);
        }
        if group.flags & FID_BITS != 0 {
            FID_GROUPS.fetch_sub(1, Ordering::Relaxed);
        }
        let requests = group
            .queue
            .iter()
            .filter_map(|event| event.request)
            .chain(group.awaiting.iter().map(|(_, request)| *request));
        for request in requests {
            state.answer(request, true);
        }
    }
    if id.is_none() {
        state.requests.retain(|request| request.domain != domain);
    }
}

/// Process `pid` of `domain` ended: the groups it made go, their
/// permission events allowed.
pub(crate) fn exit_process(domain: usize, pid: u32) {
    let ids: Vec<u64> = STATE
        .lock()
        .groups
        .iter()
        .filter(|group| group.domain == domain && group.creator == pid)
        .map(|group| group.id)
        .collect();
    for id in ids {
        release(domain, Some(id), pid);
    }
}

/// fanotify_init's flags (with UNPRIVILEGED) and event_f_flags of group
/// `id`.
pub(crate) fn flags(domain: usize, id: u64) -> Option<(u32, u32)> {
    STATE
        .lock()
        .group(domain, id)
        .map(|group| (group.flags, group.event_flags))
}

/// FAN_MARK_FLUSH: group `id`'s marks of one kind go (inode marks, or
/// mount or filesystem marks by `mounts` and `filesystems`).
pub(crate) fn flush(domain: usize, id: u64, mounts: bool, filesystems: bool) -> Result<(), Error> {
    let mut state = STATE.lock();
    let group = state.group(domain, id).ok_or(Error::Invalid)?;
    group.marks.retain(|mark| {
        let flushed = match mark.kind {
            MarkKind::Inode => !mounts && !filesystems,
            MarkKind::Mount(_) => mounts,
            MarkKind::Filesystem(_) => filesystems,
        };
        if flushed {
            count_mark(mark, false);
        }
        !flushed
    });
    Ok(())
}

/// FAN_MARK_ADD and FAN_MARK_REMOVE on group `id`'s mark of `kind` (at
/// canonical `path` for an inode mark).
pub(crate) fn mark(
    domain: usize,
    id: u64,
    command: Command,
    kind: MarkKind,
    path: &[u8],
    change: Change,
) -> Result<(), Error> {
    let mut state = STATE.lock();
    let full = state.marks(domain) >= MARK_LIMIT;
    let group = state.group(domain, id).ok_or(Error::Invalid)?;
    let path: &[u8] = if kind == MarkKind::Inode { path } else { &[] };
    let index = group
        .marks
        .iter()
        .position(|mark| mark.kind == kind && mark.path == path);
    match (command, index) {
        (Command::Add, Some(index)) => {
            let mark = &mut group.marks[index];
            count_mark(mark, false);
            if change.ignore {
                mark.ignore |= change.mask;
                mark.ignore_flags |= change.ignore_flags;
                mark.survive_modify |= change.survive_modify;
            } else {
                mark.mask |= change.mask;
            }
            count_mark(mark, true);
        }
        (Command::Add, None) => {
            if full {
                return Err(Error::NoSpace);
            }
            group.marks.try_reserve(1).map_err(|_| Error::NoMemory)?;
            let (mask, ignore) = if change.ignore {
                (0, change.mask)
            } else {
                (change.mask, 0)
            };
            let mark = Mark {
                kind,
                path: copy(path)?,
                mask,
                ignore,
                ignore_flags: change.ignore && change.ignore_flags,
                survive_modify: change.ignore && change.survive_modify,
            };
            count_mark(&mark, true);
            group.marks.push(mark);
        }
        (Command::Remove, Some(index)) => {
            let mark = &mut group.marks[index];
            count_mark(mark, false);
            if change.ignore {
                mark.ignore &= !(change.mask | change.unset);
            } else {
                mark.mask &= !(change.mask | change.unset);
            }
            if (mark.mask | mark.ignore) & !EVENT_FLAGS == 0 {
                group.marks.remove(index);
            } else {
                count_mark(&group.marks[index], true);
            }
        }
        (Command::Remove, None) => return Err(Error::NotFound),
    }
    Ok(())
}

/// Where canonical `path` is after `from` moved to `to`: itself, or `to`
/// with what follows `from`, for `from` and what lies beneath it.
fn moved_path(path: &[u8], from: &[u8], to: &[u8]) -> Option<Result<Vec<u8>, Error>> {
    let rest = path.strip_prefix(from)?;
    if !rest.is_empty() && !rest.starts_with(b"/") {
        return None;
    }
    let mut moved = Vec::new();
    Some(
        moved
            .try_reserve_exact(to.len() + rest.len())
            .map_err(|_| Error::NoMemory)
            .map(|()| {
                moved.extend_from_slice(to);
                moved.extend_from_slice(rest);
                moved
            }),
    )
}

/// `from` (and what lies beneath it) was renamed to `to`, over what was
/// there, or swapped with it (`exchange`): the inode marks follow their
/// objects, as Linux's marks are on inodes; a replaced object's go.
pub(crate) fn renamed(domain: usize, from: &[u8], to: &[u8], exchange: bool) {
    if !active() || from == to {
        return;
    }
    let mut state = STATE.lock();
    for group in state
        .groups
        .iter_mut()
        .filter(|group| group.domain == domain)
    {
        group.marks.retain(|mark| {
            let replaced = !exchange
                && mark.kind == MarkKind::Inode
                && moved_path(&mark.path, to, to).is_some();
            if replaced {
                count_mark(mark, false);
            }
            !replaced
        });
        for mark in group
            .marks
            .iter_mut()
            .filter(|mark| mark.kind == MarkKind::Inode)
        {
            let followed = moved_path(&mark.path, from, to)
                .or_else(|| exchange.then(|| moved_path(&mark.path, to, from)).flatten());
            if let Some(Ok(path)) = followed {
                mark.path = path;
            }
        }
    }
}

/// The object at canonical `path` is gone (its last name removed): its
/// inode marks go, as Linux's go with the inode.
pub(crate) fn removed(domain: usize, path: &[u8]) {
    if !active() {
        return;
    }
    let mut state = STATE.lock();
    for group in state
        .groups
        .iter_mut()
        .filter(|group| group.domain == domain)
    {
        group.marks.retain(|mark| {
            let gone = mark.kind == MarkKind::Inode && moved_path(&mark.path, path, path).is_some();
            if gone {
                count_mark(mark, false);
            }
            !gone
        });
    }
}

/// How a notice reaches the groups once the parent's part is settled
/// (Linux's fsnotify arguments).
struct Prepared<'a> {
    mask: u32,
    /// The directory handed to the groups, and the entry's name when it
    /// goes with it.
    directory: Option<Node<'a>>,
    name: Option<&'a [u8]>,
    slots: Slots<'a>,
}

/// Linux's __fsnotify_parent: whether an event on a file goes to its
/// directory too (it watches its children), and whether the directory and
/// name go with it (some mark on the file, its mount or filesystem wants
/// them, or the directory hears it).
fn prepare<'a>(state: &State, domain: usize, notice: &Notice<'a>) -> Prepared<'a> {
    let ondir = notice.object.directory;
    let mut mask = notice.mask | if ondir { FAN_ONDIR } else { 0 };
    let mut directory = None;
    let mut name = None;
    let mut second = None;
    let own = notice.object.path;
    match notice.kind {
        Kind::File => {
            if let Some(parent) = notice.directory {
                let parent_mask = state.inode_mask(domain, parent.path);
                let watched = parent_mask & FAN_EVENT_ON_CHILD != 0;
                // A mark asks for the directory and name with
                // FAN_EVENT_ON_CHILD in its mask (Linux's
                // fsnotify_parent_needed_mask, per object).
                let needed_mask = |marks: u32| {
                    if marks & FAN_EVENT_ON_CHILD != 0 {
                        marks & CHILD_EVENTS
                    } else {
                        0
                    }
                };
                let needed = !ondir && {
                    let mount = notice.mount.map_or(0, |id| {
                        needed_mask(state.kind_mask(domain, MarkKind::Mount(id)))
                    });
                    let marks = needed_mask(state.inode_mask(domain, own))
                        | needed_mask(
                            state.kind_mask(domain, MarkKind::Filesystem(notice.object.fsid)),
                        )
                        | mount;
                    mask & marks != 0
                };
                if (watched || needed) && (!ondir || watched) {
                    let interested = watched && mask & parent_mask & CHILD_EVENTS != 0;
                    if needed || interested {
                        name = Some(notice.name);
                        if interested {
                            mask |= FAN_EVENT_ON_CHILD;
                            second = Some((parent.path, Place::Parent));
                        }
                    }
                    directory = Some(parent);
                }
            }
        }
        Kind::Entry => {
            directory = notice.directory;
            name = Some(notice.name);
            if let Some((moved, _)) = notice.moved.filter(|_| mask & FAN_RENAME != 0) {
                second = Some((moved.path, Place::Second));
            }
        }
        Kind::Inode => {}
    }
    Prepared {
        mask,
        directory,
        name,
        slots: Slots {
            own: if notice.kind == Kind::Entry {
                notice.directory.map_or(own, |directory| directory.path)
            } else {
                own
            },
            second,
            mount: notice.mount,
            fsid: notice.object.fsid,
        },
    }
}

/// Linux's send_to_group and fanotify_group_event_mask: the events (with
/// FAN_ONDIR for a group reporting identifiers) group `group` reports of
/// the notice, and where its marks that heard it stand.
fn group_mask(
    group: &mut Group,
    notice: &Notice,
    prepared: &Prepared,
    reached: &[(usize, Place)],
) -> (u32, u32) {
    let mask = prepared.mask;
    let ondir = mask & FAN_ONDIR != 0;
    if mask & FAN_MODIFY != 0 {
        for (index, _) in reached {
            let mark = &mut group.marks[*index];
            if !mark.survive_modify {
                mark.ignore = 0;
            }
        }
    }
    let mut marks_mask = 0;
    let mut ignored = 0;
    for (index, place) in reached {
        let mark = &group.marks[*index];
        marks_mask |= mark.mask;
        ignored |= mark.ignored(ondir, *place);
    }
    if mask & ALL_EVENTS & marks_mask & !ignored == 0 {
        return (0, 0);
    }
    let fid_mode = group.fid_mode();
    if fid_mode == 0 {
        // Events reported with a descriptor need an open file of a
        // regular file or directory.
        if notice.mount.is_none() || !notice.object.openable {
            return (0, 0);
        }
    } else if fid_mode & FAN_REPORT_FID == 0 && prepared.directory.is_none() && !ondir {
        // Nothing to report but a directory.
        return (0, 0);
    }
    let mut marks_mask = 0;
    let mut ignored = 0;
    let mut places = 0_u32;
    for (index, place) in reached {
        let mark = &group.marks[*index];
        ignored |= mark.ignored(ondir, *place);
        if !Mark::applicable(mark.mask, ondir, *place) {
            continue;
        }
        marks_mask |= mark.mask;
        places |= 1 << (*place as u32);
    }
    let test = mask & marks_mask & !ignored;
    if fid_mode != 0 {
        if test & !EVENT_FLAGS == 0 {
            return (0, 0);
        }
        (test & (OUTGOING | EVENT_FLAGS), places)
    } else {
        (test & OUTGOING & !EVENT_FLAGS, places)
    }
}

/// Linux's fanotify_alloc_event: what an event of group `group` with
/// `mask` identifies.
fn event_info(
    group: &Group,
    mask: u32,
    notice: &Notice,
    prepared: &Prepared,
    places: u32,
) -> Result<Info, Error> {
    let fid_mode = group.fid_mode();
    if fid_mode == 0 {
        return copy(notice.object.path).map(Info::Path);
    }
    let dirent = mask & DIRENT_EVENTS != 0;
    let ondir = mask & FAN_ONDIR != 0;
    let object = &notice.object;
    let directory = prepared.directory.as_ref();
    let mut id = if dirent && fid_mode & FAN_REPORT_TARGET_FID == 0 {
        directory
    } else {
        Some(object)
    };
    let mut dirid = if dirent {
        directory
    } else if object.directory {
        Some(object)
    } else {
        directory
    };
    let mut child = None;
    let mut name = prepared.name;
    let mut moved = None;
    let mut name_event = false;
    if fid_mode & FAN_REPORT_DIR_FID != 0 && dirid.is_some() {
        let report_child = if dirent {
            fid_mode & FAN_REPORT_TARGET_FID != 0
        } else {
            fid_mode & FAN_REPORT_FID != 0 && !ondir
        };
        if report_child && !id.zip(dirid).is_some_and(|(id, dirid)| id.same(dirid)) {
            child = id;
        }
        id = dirid;
        if fid_mode & FAN_REPORT_NAME == 0 {
            name_event = child.is_some();
            name = None;
        } else if dirent || !ondir {
            name_event = true;
        }
        if mask & FAN_RENAME != 0 {
            let place = |place: Place| places & (1 << (place as u32)) != 0;
            let filesystem = place(Place::Filesystem);
            if !(filesystem || place(Place::Own)) {
                dirid = None;
                name = None;
            }
            if filesystem || place(Place::Second) {
                moved = notice.moved;
            }
        }
    }
    let fsid = object.fsid;
    if name_event && (name.is_some() || moved.is_some() || child.is_some()) {
        let (second, second_name) = match moved {
            Some((directory, name)) => (directory.handle, copy(name)?),
            None => (None, Vec::new()),
        };
        Ok(Info::Name {
            fsid,
            directory: dirid.and_then(|directory| directory.handle),
            second,
            child: child.and_then(|child| child.handle),
            name: copy(name.unwrap_or(&[]))?,
            second_name,
        })
    } else {
        Ok(Info::Fid {
            fsid,
            object: id.and_then(|id| id.handle),
        })
    }
}

/// `notice` happened (no permission event): each group of `domain` that
/// hears it queues one event. Returns whether any did, for the caller to
/// wake readers.
pub(crate) fn notify(domain: usize, notice: &Notice, cause: Cause) -> bool {
    if !active() {
        return false;
    }
    let mut state = STATE.lock();
    let prepared = prepare(&state, domain, notice);
    let mut queued = false;
    for group in state
        .groups
        .iter_mut()
        .filter(|group| group.domain == domain)
    {
        let reached = group.reached(&prepared.slots);
        if reached.is_empty() {
            continue;
        }
        let (mask, places) = group_mask(group, notice, &prepared, &reached);
        if mask == 0 {
            continue;
        }
        let Ok(info) = event_info(group, mask, notice, &prepared, places) else {
            continue;
        };
        let pid = if group.report_tid() {
            cause.tid
        } else {
            cause.pid
        };
        group.queue(Event {
            mask,
            info,
            ondir: notice.object.directory,
            pid,
            request: None,
        });
        queued = true;
    }
    queued
}

/// What a permission check decides.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Permission {
    Allowed,
    Denied,
    /// A group has not answered yet: the thread asks again later.
    Waiting,
    /// The check queued events: the thread asks again later, and readers
    /// should be woken.
    Asked,
}

/// Whether the thread of `cause` may go on with permission event `mask`
/// on `object`. The first time, the groups of `domain` that hear the event
/// queue it and the thread waits; once they all answered, the thread's
/// next check gets their verdict.
pub(crate) fn permission(domain: usize, object: Object, mask: u32, cause: Cause) -> Permission {
    if !permission_active() {
        return Permission::Allowed;
    }
    let mut state = STATE.lock();
    if let Some(index) = state
        .requests
        .iter()
        .position(|request| request.domain == domain && request.tid == cause.tid)
    {
        let request = &state.requests[index];
        if request.path == object.path && request.mask == mask {
            if request.pending != 0 {
                return Permission::Waiting;
            }
            let denied = request.denied;
            state.requests.swap_remove(index);
            return if denied {
                Permission::Denied
            } else {
                Permission::Allowed
            };
        }
        // The thread left an earlier check (a signal ended its call).
        state.requests.swap_remove(index);
    }
    let id = state.next_request;
    let mut reached = 0;
    let Ok(path) = copy(object.path) else {
        return Permission::Allowed;
    };
    if state.requests.try_reserve(1).is_err() {
        return Permission::Allowed;
    }
    for group in state
        .groups
        .iter_mut()
        .filter(|group| group.domain == domain)
    {
        if group.interest(&object, mask) == 0 {
            continue;
        }
        let Ok(event_path) = copy(object.path) else {
            continue;
        };
        let pid = if group.report_tid() {
            cause.tid
        } else {
            cause.pid
        };
        let before = group.queue.len();
        group.queue(Event {
            mask,
            info: Info::Path(event_path),
            ondir: object.directory,
            pid,
            request: Some(id),
        });
        reached += usize::from(group.queue.len() != before);
    }
    if reached == 0 {
        return Permission::Allowed;
    }
    state.next_request = id + 1;
    state.requests.push(Request {
        id,
        domain,
        tid: cause.tid,
        path,
        mask,
        pending: reached,
        denied: false,
    });
    Permission::Asked
}

/// One identifier record (struct fanotify_event_info_fid with its file
/// handle, and a name for the DFID_NAME types), padded to 4 bytes.
fn push_record(
    records: &mut Vec<u8>,
    info_type: u8,
    fsid: [u8; 8],
    handle: Option<[u8; 8]>,
    name: &[u8],
) -> Result<(), Error> {
    let handle_bytes = handle.map_or(0, |handle| handle.len());
    let name_bytes = if name.is_empty() { 0 } else { name.len() + 1 };
    let length = (4 + 8 + 8 + handle_bytes + name_bytes).next_multiple_of(4);
    records.try_reserve(length).map_err(|_| Error::NoMemory)?;
    let start = records.len();
    records.extend_from_slice(&[info_type, 0]);
    records.extend_from_slice(&(length as u16).to_ne_bytes());
    records.extend_from_slice(&fsid);
    records.extend_from_slice(&(handle_bytes as u32).to_ne_bytes());
    let handle_type = if handle.is_some() {
        HANDLE_TYPE
    } else {
        FILEID_INVALID
    };
    records.extend_from_slice(&handle_type.to_ne_bytes());
    if let Some(handle) = handle {
        records.extend_from_slice(&handle);
    }
    if !name.is_empty() {
        records.extend_from_slice(name);
        records.push(0);
    }
    records.resize(start + length, 0);
    Ok(())
}

/// Linux's copy_info_records_to_user: the identifier records of an event
/// of a group with `fid_mode`.
fn records(info: &Info, mask: u32, fid_mode: u32) -> Result<Vec<u8>, Error> {
    let mut records = Vec::new();
    let ondir = mask & FAN_ONDIR != 0;
    // The record of the object itself, after any directory records.
    let object_type = |after_directory: bool| -> (u8, &'static [u8]) {
        if fid_mode == FAN_REPORT_FID || after_directory {
            (INFO_FID, b"")
        } else if fid_mode & FAN_REPORT_NAME != 0 && ondir {
            // A directory's own event names it ".".
            (INFO_DFID_NAME, b".")
        } else if mask & DIRENT_EVENTS != 0 || ondir {
            (INFO_DFID, b"")
        } else {
            (INFO_FID, b"")
        }
    };
    match info {
        Info::Overflow | Info::Path(_) => {}
        Info::Fid { fsid, object } => {
            if object.is_some() {
                let (info_type, name) = object_type(false);
                push_record(&mut records, info_type, *fsid, *object, name)?;
            }
        }
        Info::Name {
            fsid,
            directory,
            second,
            child,
            name,
            second_name,
        } => {
            let mut wrote = false;
            if directory.is_some() {
                let info_type = if mask & FAN_RENAME != 0 {
                    INFO_OLD_DFID_NAME
                } else if name.is_empty() {
                    INFO_DFID
                } else {
                    INFO_DFID_NAME
                };
                push_record(&mut records, info_type, *fsid, *directory, name)?;
                wrote = true;
            }
            if second.is_some() {
                push_record(
                    &mut records,
                    INFO_NEW_DFID_NAME,
                    *fsid,
                    *second,
                    second_name,
                )?;
                wrote = true;
            }
            if child.is_some() {
                let (info_type, name) = object_type(wrote);
                push_record(&mut records, info_type, *fsid, *child, name)?;
            }
        }
    }
    Ok(records)
}

/// read(2) on group `id` with room for `room` bytes: the queued events
/// that fit, oldest first (each with a pidfd record more when the group
/// reports pidfds). A first event that does not fit is EINVAL and stays
/// queued.
pub(crate) fn take(domain: usize, id: u64, room: usize) -> Result<Vec<Delivery>, Error> {
    let mut state = STATE.lock();
    let group = state.group(domain, id).ok_or(Error::Invalid)?;
    let fid_mode = group.fid_mode();
    let pidfd = if group.flags & FAN_REPORT_PIDFD != 0 {
        PIDFD_INFO_SIZE
    } else {
        0
    };
    let mut taken = Vec::new();
    let mut used = 0;
    while let Some(event) = group.queue.front() {
        let records = records(&event.info, event.mask, fid_mode)?;
        let size = EVENT_METADATA_SIZE + records.len() + pidfd;
        if used + size > room {
            if taken.is_empty() {
                return Err(Error::Invalid);
            }
            break;
        }
        taken.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let Some(event) = group.queue.pop_front() else {
            break;
        };
        used += size;
        taken.push(Delivery {
            mask: event.mask & OUTGOING,
            path: match event.info {
                Info::Path(path) => Some(path),
                _ => None,
            },
            pid: event.pid,
            request: event.request,
            records,
        });
    }
    Ok(taken)
}

/// The listener got descriptor `descriptor` for permission request
/// `request` of group `id` (or none, `None`: the request is denied); it
/// waits for the listener's answer, unless the group went meanwhile.
pub(crate) fn delivered(domain: usize, id: u64, request: u64, descriptor: Option<i32>) {
    let mut state = STATE.lock();
    let kept = descriptor.is_some_and(|descriptor| {
        state.group(domain, id).is_some_and(|group| {
            group.awaiting.try_reserve(1).is_ok() && {
                group.awaiting.push((descriptor, request));
                true
            }
        })
    });
    if !kept {
        state.answer(request, descriptor.is_some());
    }
}

/// write(2) of a struct fanotify_response to group `id`: the answer for
/// the permission event read with `descriptor`.
pub(crate) fn respond(domain: usize, id: u64, descriptor: i32, response: u32) -> Result<(), Error> {
    const FAN_AUDIT: u32 = 0x10;
    const FAN_INFO: u32 = 0x20;
    let verdict = response & !(FAN_AUDIT | FAN_INFO);
    if !matches!(verdict, FAN_ALLOW | FAN_DENY)
        || response & (FAN_AUDIT | FAN_INFO) != 0
        || descriptor < 0
    {
        return Err(Error::Invalid);
    }
    let mut state = STATE.lock();
    let group = state.group(domain, id).ok_or(Error::Invalid)?;
    let index = group
        .awaiting
        .iter()
        .position(|(awaiting, _)| *awaiting == descriptor)
        .ok_or(Error::NotFound)?;
    let (_, request) = group.awaiting.remove(index);
    state.answer(request, verdict == FAN_ALLOW);
    Ok(())
}

/// A mark as /proc/PID/fdinfo shows it.
pub(crate) struct MarkView {
    pub(crate) kind: MarkKind,
    pub(crate) path: Vec<u8>,
    pub(crate) mask: u32,
    pub(crate) ignore: u32,
    /// The mark's FAN_MARK_* flags: FAN_MARK_IGNORED_SURV_MODIFY and
    /// FAN_MARK_IGNORE.
    pub(crate) flags: u32,
}

/// Group `id`'s fanotify_init flags and event_f_flags, and its marks, as
/// fdinfo lists them.
pub(crate) fn view(domain: usize, id: u64) -> Option<(u32, u32, Vec<MarkView>)> {
    const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x40;
    const FAN_MARK_IGNORE: u32 = 0x400;
    let mut state = STATE.lock();
    let group = state.group(domain, id)?;
    let mut marks = Vec::new();
    marks.try_reserve_exact(group.marks.len()).ok()?;
    for mark in &group.marks {
        marks.push(MarkView {
            kind: mark.kind,
            path: copy(&mark.path).ok()?,
            mask: mark.mask,
            ignore: mark.ignore,
            flags: if mark.survive_modify {
                FAN_MARK_IGNORED_SURV_MODIFY
            } else {
                0
            } | if mark.ignore_flags {
                FAN_MARK_IGNORE
            } else {
                0
            },
        });
    }
    Some((group.flags & !UNPRIVILEGED, group.event_flags, marks))
}

/// Whether group `id` has events queued (poll, a blocking read).
pub(crate) fn ready(domain: usize, id: u64) -> bool {
    STATE
        .lock()
        .group(domain, id)
        .is_some_and(|group| !group.queue.is_empty())
}
