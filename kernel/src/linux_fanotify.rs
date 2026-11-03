//! fanotify(7): groups, their marks on files, directories and mounts, and
//! the events they queue, permission events among them.
//!
//! A mark names a file or directory by its canonical path (under the
//! domain's root), as inotify watches do, or a mount by its id. An event on
//! an object reaches each group once, with the events of every mark of the
//! group that hears it: the object's own, its directory's (with
//! FAN_EVENT_ON_CHILD) and its mount's, less the marks' ignore masks.
//! Events of one object and process merge while queued, as in Linux.
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
/// fanotify_init's flag for events to report the thread, not the process.
pub(crate) const FAN_REPORT_TID: u32 = 0x0000_0100;

/// Events that carry an open file (and so a descriptor for the listener).
pub(crate) const PATH_EVENTS: u32 =
    FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN | FAN_OPEN_EXEC;
pub(crate) const PERMISSION_EVENTS: u32 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;
/// Events about directory entries and inodes, which only groups reporting
/// file handles may ask for.
pub(crate) const INODE_EVENTS: u32 = FAN_ATTRIB
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF
    | FAN_RENAME;
/// Flags that steer which objects a mark hears rather than events.
pub(crate) const EVENT_FLAGS: u32 = FAN_ONDIR | FAN_EVENT_ON_CHILD;
/// Everything a mark's mask may hold.
pub(crate) const VALID_MASK: u32 =
    PATH_EVENTS | PERMISSION_EVENTS | INODE_EVENTS | FAN_FS_ERROR | EVENT_FLAGS;
/// What one event reports, by the fanotify_event_metadata it is read as.
pub(crate) const EVENT_METADATA_SIZE: usize = 24;
/// The default queue limit (/proc/sys/fs/fanotify/max_queued_events).
pub(crate) const DEFAULT_QUEUE_LIMIT: usize = 16_384;
/// The most groups a domain may have (max_user_groups).
pub(crate) const GROUP_LIMIT: usize = 128;
/// How many queued events a new one may merge with (Linux's limit).
const MERGE_DEPTH: usize = 128;

/// The answers a listener writes for a permission event (struct
/// fanotify_response's response).
pub(crate) const FAN_ALLOW: u32 = 0x01;
pub(crate) const FAN_DENY: u32 = 0x02;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// No such group, or an answer that is not one.
    Invalid,
    /// No such mark, or no permission event awaits that descriptor.
    NotFound,
    /// Too many groups.
    TooMany,
    NoMemory,
}

/// What a mark is on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarkKind {
    /// A file or directory, by its path.
    Inode,
    /// Every object on a mount (FAN_MARK_MOUNT), by its id.
    Mount(u32),
    /// Every object on a filesystem (FAN_MARK_FILESYSTEM); each mount here
    /// has a filesystem of its own, so by the mount's id too.
    Filesystem(u32),
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
}

struct Mark {
    kind: MarkKind,
    path: Vec<u8>,
    mask: u32,
    ignore: u32,
    ignore_flags: bool,
    survive_modify: bool,
}

/// Where a mark stands to the object of an event.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Place {
    Own,
    Parent,
    Mount,
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
}

/// The object an event happened to.
#[derive(Clone, Copy)]
pub(crate) struct Object<'a> {
    /// Its canonical path.
    pub(crate) path: &'a [u8],
    pub(crate) directory: bool,
    /// The id of the mount it lies on (0 for the root's own files).
    pub(crate) mount: u32,
}

impl Object<'_> {
    fn place(&self, mark: &Mark) -> Option<Place> {
        match mark.kind {
            MarkKind::Inode if mark.path == self.path => Some(Place::Own),
            MarkKind::Inode if !self.path.is_empty() && mark.path == split(self.path).0 => {
                Some(Place::Parent)
            }
            MarkKind::Mount(id) | MarkKind::Filesystem(id) if id == self.mount => {
                Some(Place::Mount)
            }
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

struct Event {
    /// The events, without flags.
    mask: u32,
    path: Vec<u8>,
    /// The process or thread reported (FAN_REPORT_TID), 0 for an overflow.
    pid: u32,
    directory: bool,
    /// The permission request this event asks the group about.
    request: Option<u64>,
}

/// An event as read: what read(2) reports and the descriptor it opens.
pub(crate) struct Delivery {
    pub(crate) mask: u32,
    /// The object to open for the listener; none for an overflow.
    pub(crate) path: Option<Vec<u8>>,
    pub(crate) pid: u32,
    pub(crate) request: Option<u64>,
}

struct Group {
    domain: usize,
    id: u64,
    /// The process that made it: a child closing an inherited descriptor
    /// leaves the group to it, as with inotify instances.
    creator: u32,
    /// fanotify_init's flags.
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
    /// The events of `mask` this group hears on `object`.
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

    /// Queues an event, merged into a queued one of the same object and
    /// process when it is no permission event, as Linux merges them.
    fn queue(&mut self, event: Event) {
        if event.request.is_none() {
            if let Some(queued) = self
                .queue
                .iter_mut()
                .rev()
                .take(MERGE_DEPTH)
                .find(|queued| {
                    queued.request.is_none()
                        && queued.mask != FAN_Q_OVERFLOW
                        && queued.pid == event.pid
                        && queued.directory == event.directory
                        && queued.path == event.path
                })
            {
                queued.mask |= event.mask;
                return;
            }
            if self.queue.len() >= self.limit {
                if self
                    .queue
                    .back()
                    .is_none_or(|last| last.mask != FAN_Q_OVERFLOW)
                    && self.queue.try_reserve(1).is_ok()
                {
                    self.queue.push_back(Event {
                        mask: FAN_Q_OVERFLOW,
                        path: Vec::new(),
                        pid: 0,
                        directory: false,
                        request: None,
                    });
                }
                return;
            }
        }
        if self.queue.try_reserve(1).is_ok() {
            self.queue.push_back(event);
        }
    }
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

/// The directory part of a canonical path and its last component.
fn split(path: &[u8]) -> (&[u8], &[u8]) {
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
/// object's mount.
pub(crate) fn mount_marks() -> bool {
    MOUNT_MARKS.load(Ordering::Relaxed) != 0
}

/// A new group `id` of `domain` with fanotify_init's `flags` and
/// `event_flags`.
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
        limit: DEFAULT_QUEUE_LIMIT,
        awaiting: Vec::new(),
    });
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

/// fanotify_init's flags and event_f_flags of group `id`.
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
                mark.ignore &= !change.mask;
            } else {
                mark.mask &= !change.mask;
            }
            if mark.mask | mark.ignore == 0 {
                group.marks.remove(index);
            } else {
                count_mark(&group.marks[index], true);
            }
        }
        (Command::Remove, None) => return Err(Error::NotFound),
    }
    Ok(())
}

/// Events `mask` (without permission events) happened to `object`: each
/// group of `domain` that hears some of them queues one event. Returns
/// whether any did, for the caller to wake readers.
pub(crate) fn notify(domain: usize, object: Object, mask: u32, cause: Cause) -> bool {
    if !active() {
        return false;
    }
    let mut state = STATE.lock();
    let mut queued = false;
    for group in state
        .groups
        .iter_mut()
        .filter(|group| group.domain == domain)
    {
        // A modification clears the ignore masks that do not survive it.
        if mask & FAN_MODIFY != 0 {
            for mark in &mut group.marks {
                if mark.ignore != 0 && !mark.survive_modify && object.place(mark).is_some() {
                    mark.ignore = 0;
                }
            }
        }
        let events = group.interest(&object, mask & !PERMISSION_EVENTS);
        if events == 0 {
            continue;
        }
        let Ok(path) = copy(object.path) else {
            continue;
        };
        let pid = if group.report_tid() {
            cause.tid
        } else {
            cause.pid
        };
        group.queue(Event {
            mask: events,
            path,
            pid,
            directory: object.directory,
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
            path: event_path,
            pid,
            directory: object.directory,
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

/// read(2) on group `id`: up to `count` queued events, oldest first.
pub(crate) fn take(domain: usize, id: u64, count: usize) -> Result<Vec<Delivery>, Error> {
    let mut state = STATE.lock();
    let group = state.group(domain, id).ok_or(Error::Invalid)?;
    let count = count.min(group.queue.len());
    let mut taken = Vec::new();
    taken
        .try_reserve_exact(count)
        .map_err(|_| Error::NoMemory)?;
    for event in group.queue.drain(..count) {
        taken.push(Delivery {
            mask: event.mask,
            path: (event.mask != FAN_Q_OVERFLOW).then_some(event.path),
            pid: event.pid,
            request: event.request,
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

/// Whether group `id` has events queued (poll, a blocking read).
pub(crate) fn ready(domain: usize, id: u64) -> bool {
    STATE
        .lock()
        .group(domain, id)
        .is_some_and(|group| !group.queue.is_empty())
}
