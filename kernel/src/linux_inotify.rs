//! inotify(7): instances, their watches and their event queues.
//!
//! A watch names a path (canonical, under the domain's root) as the
//! instance's process saw it when it added the watch; a rename moves the
//! watches under the renamed path. Events reach a watch on the object itself
//! (no name) and a watch on the object's directory (with the object's name),
//! as Linux reports them. Each instance queues its events in order, merges
//! an event identical to the last one queued, and past its queue limit
//! (`/proc/sys/fs/inotify/max_queued_events`) queues one IN_Q_OVERFLOW.
#![forbid(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

pub(crate) const IN_ACCESS: u32 = 0x0000_0001;
pub(crate) const IN_MODIFY: u32 = 0x0000_0002;
pub(crate) const IN_ATTRIB: u32 = 0x0000_0004;
pub(crate) const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub(crate) const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub(crate) const IN_OPEN: u32 = 0x0000_0020;
pub(crate) const IN_MOVED_FROM: u32 = 0x0000_0040;
pub(crate) const IN_MOVED_TO: u32 = 0x0000_0080;
pub(crate) const IN_CREATE: u32 = 0x0000_0100;
pub(crate) const IN_DELETE: u32 = 0x0000_0200;
pub(crate) const IN_DELETE_SELF: u32 = 0x0000_0400;
pub(crate) const IN_MOVE_SELF: u32 = 0x0000_0800;
pub(crate) const IN_ALL_EVENTS: u32 = 0x0000_0fff;
pub(crate) const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub(crate) const IN_IGNORED: u32 = 0x0000_8000;
pub(crate) const IN_ONLYDIR: u32 = 0x0100_0000;
pub(crate) const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub(crate) const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub(crate) const IN_MASK_CREATE: u32 = 0x1000_0000;
pub(crate) const IN_MASK_ADD: u32 = 0x2000_0000;
pub(crate) const IN_ISDIR: u32 = 0x4000_0000;
pub(crate) const IN_ONESHOT: u32 = 0x8000_0000;

/// What add_watch accepts besides the events.
const WATCH_FLAGS: u32 =
    IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD | IN_ONESHOT;
/// Events reported to a watch on the object's directory, with its name.
const CHILD_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE;
/// Events reported to a watch on the object itself, without a name.
const OWN_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_DELETE_SELF
    | IN_MOVE_SELF;
/// The size of `struct inotify_event` before its name.
const EVENT_HEADER: usize = 16;
/// The default `max_queued_events`.
pub(crate) const DEFAULT_QUEUE_LIMIT: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// No such instance or watch, or a mask with no events.
    Invalid,
    /// IN_MASK_CREATE on a path already watched.
    Exists,
    NoMemory,
}

struct Watch {
    wd: i32,
    path: Vec<u8>,
    /// Events and the IN_ONESHOT / IN_EXCL_UNLINK flags.
    mask: u32,
}

#[derive(Clone, PartialEq, Eq)]
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Vec<u8>,
}

impl Event {
    /// Its size as read(2) returns it: the header and the name padded with
    /// NULs to a multiple of the header's size.
    fn size(&self) -> usize {
        EVENT_HEADER + Self::name_length(&self.name)
    }

    fn name_length(name: &[u8]) -> usize {
        if name.is_empty() {
            0
        } else {
            (name.len() + 1).div_ceil(EVENT_HEADER) * EVENT_HEADER
        }
    }
}

struct Instance {
    domain: usize,
    id: u64,
    /// The process that made it: a child closing an inherited descriptor
    /// leaves the instance to it (inotify11).
    creator: u32,
    watches: Vec<Watch>,
    next_wd: i32,
    queue: VecDeque<Event>,
    limit: usize,
}

impl Instance {
    fn queue(&mut self, event: Event) {
        if self.queue.back() == Some(&event) {
            return;
        }
        if self.queue.len() >= self.limit {
            let overflow = Event {
                wd: -1,
                mask: IN_Q_OVERFLOW,
                cookie: 0,
                name: Vec::new(),
            };
            if self.queue.back() != Some(&overflow) && self.queue.try_reserve(1).is_ok() {
                self.queue.push_back(overflow);
            }
            return;
        }
        if self.queue.try_reserve(1).is_ok() {
            self.queue.push_back(event);
        }
    }

    /// Queues `mask` for watch `index`, which ends after a one-shot event.
    fn report(&mut self, index: usize, mask: u32, cookie: u32, name: &[u8]) -> bool {
        let watch = &self.watches[index];
        let wd = watch.wd;
        let oneshot = watch.mask & IN_ONESHOT != 0;
        let Ok(name) = copy(name) else {
            return false;
        };
        self.queue(Event {
            wd,
            mask,
            cookie,
            name,
        });
        if oneshot {
            self.watches.remove(index);
            WATCHES.fetch_sub(1, Ordering::Relaxed);
            self.queue(Event {
                wd,
                mask: IN_IGNORED,
                cookie: 0,
                name: Vec::new(),
            });
            return true;
        }
        false
    }
}

static INSTANCES: SpinLock<Vec<Instance>> = SpinLock::new(LockRank::INOTIFY, Vec::new());

/// dnotify (fcntl F_NOTIFY): a process asks to be signalled, through a
/// directory's descriptor, when the directory or its entries change.
struct Dnotify {
    domain: usize,
    pid: u32,
    descriptor: u32,
    path: Vec<u8>,
    /// DN_* events.
    events: u32,
    multishot: bool,
}

/// dnotify's registrations, the signals F_SETSIG chose (domain, pid,
/// descriptor, signal), and the notices due (domain, pid, descriptor) for
/// the kernel to send once the system call that caused them is done.
struct DnotifyState {
    registrations: Vec<Dnotify>,
    signals: Vec<(usize, u32, u32, u8)>,
    fired: Vec<(usize, u32, u32)>,
}

static DNOTIFY: SpinLock<DnotifyState> = SpinLock::new(
    LockRank::INOTIFY,
    DnotifyState {
        registrations: Vec::new(),
        signals: Vec::new(),
        fired: Vec::new(),
    },
);

pub(crate) const DN_ACCESS: u32 = 0x1;
pub(crate) const DN_MODIFY: u32 = 0x2;
pub(crate) const DN_CREATE: u32 = 0x4;
pub(crate) const DN_DELETE: u32 = 0x8;
pub(crate) const DN_RENAME: u32 = 0x10;
pub(crate) const DN_ATTRIB: u32 = 0x20;
pub(crate) const DN_MULTISHOT: u32 = 0x8000_0000;

/// F_NOTIFY on the descriptor `descriptor` of `pid`, for directory
/// `path`: `events` (DN_*, with DN_MULTISHOT to stay after the first
/// notice) replace the descriptor's registration; none removes it.
pub(crate) fn dnotify_register(
    domain: usize,
    pid: u32,
    descriptor: u32,
    path: &[u8],
    events: u32,
) -> Result<(), Error> {
    let mut state = DNOTIFY.lock();
    let before = state.registrations.len();
    state.registrations.retain(|registration| {
        !(registration.domain == domain
            && registration.pid == pid
            && registration.descriptor == descriptor)
    });
    let removed = before - state.registrations.len();
    let multishot = events & DN_MULTISHOT != 0;
    let events = events & !DN_MULTISHOT;
    let added = if events != 0 {
        let mut copy = Vec::new();
        copy.try_reserve_exact(path.len())
            .map_err(|_| Error::NoMemory)?;
        copy.extend_from_slice(path);
        state
            .registrations
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        state.registrations.push(Dnotify {
            domain,
            pid,
            descriptor,
            path: copy,
            events,
            multishot,
        });
        1
    } else {
        0
    };
    // The watch count turns the system call hooks on and off.
    WATCHES.fetch_add(added, Ordering::Relaxed);
    WATCHES.fetch_sub(removed, Ordering::Relaxed);
    Ok(())
}

/// F_SETSIG: the signal (0 for SIGIO) `pid`'s descriptor's notices use.
pub(crate) fn set_notice_signal(domain: usize, pid: u32, descriptor: u32, signal: u8) -> bool {
    let mut state = DNOTIFY.lock();
    state
        .signals
        .retain(|entry| !(entry.0 == domain && entry.1 == pid && entry.2 == descriptor));
    if signal == 0 {
        return true;
    }
    if state.signals.try_reserve(1).is_err() {
        return false;
    }
    state.signals.push((domain, pid, descriptor, signal));
    true
}

/// F_GETSIG: the signal F_SETSIG set, else 0.
pub(crate) fn notice_signal(domain: usize, pid: u32, descriptor: u32) -> u8 {
    DNOTIFY
        .lock()
        .signals
        .iter()
        .find(|entry| entry.0 == domain && entry.1 == pid && entry.2 == descriptor)
        .map_or(0, |entry| entry.3)
}

/// `pid` closed `descriptor`: its registration and signal choice go.
pub(crate) fn dnotify_closed(domain: usize, pid: u32, descriptor: u32) {
    let mut state = DNOTIFY.lock();
    let before = state.registrations.len();
    state.registrations.retain(|registration| {
        !(registration.domain == domain
            && registration.pid == pid
            && registration.descriptor == descriptor)
    });
    WATCHES.fetch_sub(before - state.registrations.len(), Ordering::Relaxed);
    state
        .signals
        .retain(|entry| !(entry.0 == domain && entry.1 == pid && entry.2 == descriptor));
}

/// The notices due since the last call: (pid, descriptor, signal), the
/// signal 0 meaning SIGIO.
pub(crate) fn take_dnotify_notices(domain: usize, output: &mut Vec<(u32, u32, u8)>) {
    let mut state = DNOTIFY.lock();
    let mut index = 0;
    while index < state.fired.len() {
        let (fired_domain, pid, descriptor) = state.fired[index];
        if fired_domain != domain {
            index += 1;
            continue;
        }
        state.fired.swap_remove(index);
        let signal = state
            .signals
            .iter()
            .find(|entry| entry.0 == domain && entry.1 == pid && entry.2 == descriptor)
            .map_or(0, |entry| entry.3);
        if output.try_reserve(1).is_ok() {
            output.push((pid, descriptor, signal));
        }
    }
}

/// Dnotify's DN_* events that inotify event `mask` stands for.
fn dnotify_events(mask: u32) -> u32 {
    let mut events = 0;
    if mask & IN_ACCESS != 0 {
        events |= DN_ACCESS;
    }
    if mask & IN_MODIFY != 0 {
        events |= DN_MODIFY;
    }
    if mask & (IN_CREATE | IN_MOVED_TO) != 0 {
        events |= DN_CREATE;
    }
    if mask & (IN_DELETE | IN_MOVED_FROM) != 0 {
        events |= DN_DELETE;
    }
    if mask & IN_ATTRIB != 0 {
        events |= DN_ATTRIB;
    }
    events
}

/// Notes the dnotify registrations `events` (DN_*) on `path` reach: the
/// directory's own (`own`) and, with `to_parent`, its parent's. A
/// registration without DN_MULTISHOT ends with its first notice.
fn dnotify_hear(domain: usize, path: &[u8], events: u32, own: bool, to_parent: bool) {
    if events == 0 {
        return;
    }
    let (parent, _) = split(path);
    let mut state = DNOTIFY.lock();
    let DnotifyState {
        registrations,
        fired,
        ..
    } = &mut *state;
    let mut index = 0;
    let mut ended = 0;
    while index < registrations.len() {
        let registration = &registrations[index];
        let reached = registration.domain == domain
            && registration.events & events != 0
            && (own && registration.path == path
                || to_parent && !path.is_empty() && registration.path == parent);
        if !reached {
            index += 1;
            continue;
        }
        if fired.try_reserve(1).is_ok() {
            fired.push((domain, registration.pid, registration.descriptor));
        }
        if registration.multishot {
            index += 1;
        } else {
            registrations.swap_remove(index);
            ended += 1;
        }
    }
    WATCHES.fetch_sub(ended, Ordering::Relaxed);
}
/// Watches in all domains, so file operations skip the table when none.
static WATCHES: AtomicUsize = AtomicUsize::new(0);
/// Cookies pairing IN_MOVED_FROM with IN_MOVED_TO.
static NEXT_COOKIE: AtomicU32 = AtomicU32::new(1);

fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

/// The directory part of a canonical path and its last component.
fn split(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|byte| *byte == b'/') {
        Some(slash) => (&path[..slash], &path[slash + 1..]),
        None => (&[], path),
    }
}

/// Whether any domain has a watch: file operations call in only then.
pub(crate) fn active() -> bool {
    WATCHES.load(Ordering::Relaxed) != 0
}

/// A new instance `id` of `domain` with `limit` queued events at most.
pub(crate) fn create(domain: usize, id: u64, creator: u32, limit: usize) -> bool {
    let mut instances = INSTANCES.lock();
    if instances.try_reserve(1).is_err() {
        return false;
    }
    instances.retain(|instance| instance.domain != domain || instance.id != id);
    instances.push(Instance {
        domain,
        id,
        creator,
        watches: Vec::new(),
        next_wd: 1,
        queue: VecDeque::new(),
        limit: limit.max(1),
    });
    true
}

/// Instance `id` goes when its creator closes its last descriptor of it
/// (`closer`), and every instance of a domain with the domain (`id` None).
pub(crate) fn release(domain: usize, id: Option<u64>, closer: u32) {
    let mut instances = INSTANCES.lock();
    instances.retain(|instance| {
        let gone = instance.domain == domain
            && id.is_none_or(|id| instance.id == id && instance.creator == closer);
        if gone {
            WATCHES.fetch_sub(instance.watches.len(), Ordering::Relaxed);
        }
        !gone
    });
}

/// inotify_add_watch: the watch on `path` (a new one, or the existing one
/// with its mask replaced, or extended with IN_MASK_ADD).
pub(crate) fn add_watch(domain: usize, id: u64, path: &[u8], mask: u32) -> Result<i32, Error> {
    if mask & IN_ALL_EVENTS == 0 || mask & !(IN_ALL_EVENTS | WATCH_FLAGS) != 0 {
        return Err(Error::Invalid);
    }
    let kept = mask & (IN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK);
    let mut instances = INSTANCES.lock();
    let instance = instances
        .iter_mut()
        .find(|instance| instance.domain == domain && instance.id == id)
        .ok_or(Error::Invalid)?;
    if let Some(watch) = instance.watches.iter_mut().find(|watch| watch.path == path) {
        if mask & IN_MASK_CREATE != 0 {
            return Err(Error::Exists);
        }
        watch.mask = if mask & IN_MASK_ADD != 0 {
            watch.mask | kept
        } else {
            kept
        };
        return Ok(watch.wd);
    }
    instance
        .watches
        .try_reserve(1)
        .map_err(|_| Error::NoMemory)?;
    let wd = instance.next_wd;
    instance.next_wd = wd.checked_add(1).ok_or(Error::NoMemory)?;
    instance.watches.push(Watch {
        wd,
        path: copy(path)?,
        mask: kept,
    });
    WATCHES.fetch_add(1, Ordering::Relaxed);
    Ok(wd)
}

/// inotify_rm_watch: the watch ends with IN_IGNORED.
pub(crate) fn rm_watch(domain: usize, id: u64, wd: i32) -> Result<(), Error> {
    let mut instances = INSTANCES.lock();
    let instance = instances
        .iter_mut()
        .find(|instance| instance.domain == domain && instance.id == id)
        .ok_or(Error::Invalid)?;
    let index = instance
        .watches
        .iter()
        .position(|watch| watch.wd == wd)
        .ok_or(Error::Invalid)?;
    instance.watches.remove(index);
    WATCHES.fetch_sub(1, Ordering::Relaxed);
    instance.queue(Event {
        wd,
        mask: IN_IGNORED,
        cookie: 0,
        name: Vec::new(),
    });
    Ok(())
}

/// The watches of `path`, and of the directory holding it for events
/// reported with a name, in every instance of `domain`, hear `mask`.
fn deliver(domain: usize, path: &[u8], mask: u32, directory: bool, cookie: u32) {
    deliver_to(domain, path, mask, directory, cookie, true);
}

/// `deliver`, to the directory's watches too only with `to_parent`.
fn deliver_to(
    domain: usize,
    path: &[u8],
    mask: u32,
    directory: bool,
    cookie: u32,
    to_parent: bool,
) {
    // Linux leaves IN_ISDIR off the events of the watched object's own
    // removal and move.
    let isdir = if directory && mask & (IN_DELETE_SELF | IN_MOVE_SELF) == 0 {
        IN_ISDIR
    } else {
        0
    };
    let (parent, name) = split(path);
    let mut instances = INSTANCES.lock();
    for instance in instances
        .iter_mut()
        .filter(|instance| instance.domain == domain)
    {
        let mut index = 0;
        while index < instance.watches.len() {
            let watch = &instance.watches[index];
            let own = watch.path == path && mask & OWN_EVENTS != 0;
            let child =
                to_parent && !path.is_empty() && watch.path == parent && mask & CHILD_EVENTS != 0;
            let heard = watch.mask & mask & IN_ALL_EVENTS;
            let excluded = mask & IN_EXCL_UNLINK != 0 && watch.mask & IN_EXCL_UNLINK != 0;
            if heard == 0 || !(own || child) || excluded {
                index += 1;
                continue;
            }
            let name: &[u8] = if own { &[] } else { name };
            let ended = instance.report(index, heard | isdir, cookie, name);
            if !ended {
                index += 1;
            }
        }
    }
    drop(instances);
    // Dnotify hears its own and its entries' events, but not a move of
    // the watched directory itself.
    let events = dnotify_events(mask & !(IN_MOVE_SELF | IN_DELETE_SELF));
    dnotify_hear(domain, path, events, mask & OWN_EVENTS != 0, to_parent);
}

/// An event on the object at canonical `path`: IN_ACCESS, IN_MODIFY,
/// IN_ATTRIB, IN_OPEN or a close. `unlinked`: the object has no name any
/// more (an open file unlinked), and IN_EXCL_UNLINK watches hear nothing of
/// it (inotify12).
pub(crate) fn notify(domain: usize, path: &[u8], mask: u32, directory: bool, unlinked: bool) {
    if !active() {
        return;
    }
    deliver(
        domain,
        path,
        mask | if unlinked { IN_EXCL_UNLINK } else { 0 },
        directory,
        0,
    );
}

/// `path` was created (open with O_CREAT, mkdir, mknod, link, symlink).
pub(crate) fn created(domain: usize, path: &[u8], directory: bool) {
    if active() {
        deliver(domain, path, IN_CREATE, directory, 0);
    }
}

/// `path` was unlinked or removed: IN_DELETE to its directory's watches,
/// IN_DELETE_SELF and IN_IGNORED to its own (after IN_ATTRIB, the link
/// count's change, for a file), which end; an IN_EXCL_UNLINK watch of a
/// file hears nothing more of it.
pub(crate) fn deleted(domain: usize, path: &[u8], directory: bool) {
    if !active() {
        return;
    }
    // The link count's change: the file's own watches only.
    if !directory {
        deliver_to(domain, path, IN_ATTRIB, false, 0, false);
    }
    deliver(domain, path, IN_DELETE, directory, 0);
    let mut instances = INSTANCES.lock();
    for instance in instances
        .iter_mut()
        .filter(|instance| instance.domain == domain)
    {
        let mut index = 0;
        while index < instance.watches.len() {
            if instance.watches[index].path != path {
                index += 1;
                continue;
            }
            let watch = &instance.watches[index];
            let wd = watch.wd;
            if watch.mask & IN_DELETE_SELF != 0 {
                instance.queue(Event {
                    wd,
                    mask: IN_DELETE_SELF,
                    cookie: 0,
                    name: Vec::new(),
                });
            }
            instance.watches.remove(index);
            WATCHES.fetch_sub(1, Ordering::Relaxed);
            instance.queue(Event {
                wd,
                mask: IN_IGNORED,
                cookie: 0,
                name: Vec::new(),
            });
        }
    }
}

/// `from` was renamed to `to`: IN_MOVED_FROM and IN_MOVED_TO with one
/// cookie to their directories' watches, IN_MOVE_SELF to its own, and the
/// watches on it or under it follow it.
pub(crate) fn renamed(domain: usize, from: &[u8], to: &[u8], directory: bool) {
    if !active() {
        return;
    }
    let cookie = NEXT_COOKIE.fetch_add(1, Ordering::Relaxed).max(1);
    // A rename within one directory is dnotify's DN_RENAME there; one out
    // of or into it is not (fcntl39).
    let same_directory = split(from).0 == split(to).0;
    if same_directory {
        dnotify_hear(domain, from, DN_RENAME, false, true);
    }
    deliver(domain, from, IN_MOVED_FROM, directory, cookie);
    deliver(domain, to, IN_MOVED_TO, directory, cookie);
    deliver(domain, from, IN_MOVE_SELF, directory, 0);
    let mut instances = INSTANCES.lock();
    for watch in instances
        .iter_mut()
        .filter(|instance| instance.domain == domain)
        .flat_map(|instance| instance.watches.iter_mut())
    {
        let under = watch.path.len() > from.len()
            && watch.path.starts_with(from)
            && watch.path[from.len()] == b'/';
        if watch.path != from && !under {
            continue;
        }
        let mut moved = Vec::new();
        if moved
            .try_reserve(to.len() + watch.path.len() - from.len())
            .is_err()
        {
            continue;
        }
        moved.extend_from_slice(to);
        moved.extend_from_slice(&watch.path[from.len()..]);
        watch.path = moved;
    }
}

/// read(2) on instance `id`: the queued events that fit in `capacity`
/// bytes, written by `write` one after another (offset, bytes); EINVAL
/// when even the first does not fit, 0 bytes when none is queued.
pub(crate) fn read(
    domain: usize,
    id: u64,
    capacity: usize,
    mut write: impl FnMut(usize, &[u8]) -> bool,
) -> Result<usize, Error> {
    let mut instances = INSTANCES.lock();
    let instance = instances
        .iter_mut()
        .find(|instance| instance.domain == domain && instance.id == id)
        .ok_or(Error::Invalid)?;
    let mut written = 0;
    while let Some(event) = instance.queue.front() {
        let size = event.size();
        if written + size > capacity {
            if written == 0 {
                return Err(Error::Invalid);
            }
            break;
        }
        let mut header = [0_u8; EVENT_HEADER];
        header[..4].copy_from_slice(&event.wd.to_ne_bytes());
        header[4..8].copy_from_slice(&event.mask.to_ne_bytes());
        header[8..12].copy_from_slice(&event.cookie.to_ne_bytes());
        let name_length = Event::name_length(&event.name) as u32;
        header[12..16].copy_from_slice(&name_length.to_ne_bytes());
        let mut name = [0_u8; 256 + EVENT_HEADER];
        let padded = name_length as usize;
        if padded > name.len() {
            instance.queue.pop_front();
            continue;
        }
        name[..event.name.len()].copy_from_slice(&event.name);
        if !write(written, &header)
            || padded != 0 && !write(written + EVENT_HEADER, &name[..padded])
        {
            return if written == 0 {
                Err(Error::NoMemory)
            } else {
                Ok(written)
            };
        }
        written += size;
        instance.queue.pop_front();
    }
    Ok(written)
}

/// Whether instance `id` has events queued (poll, epoll, a blocking read).
pub(crate) fn ready(domain: usize, id: u64) -> bool {
    INSTANCES.lock().iter().any(|instance| {
        instance.domain == domain && instance.id == id && !instance.queue.is_empty()
    })
}

/// The watches of instance `id` for /proc/PID/fdinfo: wd and mask each.
pub(crate) fn watches(domain: usize, id: u64, mut each: impl FnMut(i32, u32)) {
    for instance in INSTANCES
        .lock()
        .iter()
        .filter(|instance| instance.domain == domain && instance.id == id)
    {
        for watch in &instance.watches {
            each(watch.wd, watch.mask);
        }
    }
}
