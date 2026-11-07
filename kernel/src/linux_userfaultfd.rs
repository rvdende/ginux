//! userfaultfd(2) contexts: the ranges of a process's memory registered
//! with each, the page faults reported to it and not yet resolved, and the
//! pages it write-protected.
//!
//! A context belongs to the process (its memory) that made it, as Linux's
//! `userfaultfd_ctx` holds its mm: a forked child's memory is not
//! registered, and unmapping a range or replacing the process's image
//! drops its registrations. A descriptor names its context by id as an
//! object slot of the socket table ([`CLASS_CONTEXT`]), so dup, fork,
//! SCM_RIGHTS and close count it; the last close drops the context.
//!
//! The kernel's fault path asks [`fault`] whether a fault is a context's to
//! resolve: a missing page (MISSING), a write to a write-protected page
//! (WP), or a shared file page whose contents exist but are not mapped
//! (MINOR). If so, a message is queued for the context's reader (once per
//! page until it is resolved) and the faulting thread waits by trying the
//! access again later; the ioctls that fill, protect or wake a range clear
//! its pages' reports. Faults of the kernel's own accesses are not
//! reported: those resolve as if nothing were registered.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

/// The object class of userfaultfd descriptors in the socket table.
pub(crate) const CLASS_CONTEXT: u8 = 11;

/// Registration modes (UFFDIO_REGISTER_MODE_*).
pub(crate) const MODE_MISSING: u8 = 1;
pub(crate) const MODE_WP: u8 = 2;
pub(crate) const MODE_MINOR: u8 = 4;

/// Page fault message flags (UFFD_PAGEFAULT_FLAG_*).
pub(crate) const FLAG_WRITE: u64 = 1;
pub(crate) const FLAG_WP: u64 = 2;
pub(crate) const FLAG_MINOR: u64 = 4;

/// Features (UFFD_FEATURE_*) this kernel offers.
pub(crate) const FEATURE_PAGEFAULT_FLAG_WP: u64 = 1 << 0;
pub(crate) const FEATURE_EVENT_FORK: u64 = 1 << 1;
pub(crate) const FEATURE_THREAD_ID: u64 = 1 << 8;
pub(crate) const FEATURE_MINOR_SHMEM: u64 = 1 << 10;
pub(crate) const FEATURE_EXACT_ADDRESS: u64 = 1 << 11;
pub(crate) const FEATURE_POISON: u64 = 1 << 14;
pub(crate) const FEATURE_MOVE: u64 = 1 << 16;
pub(crate) const FEATURES: u64 = FEATURE_PAGEFAULT_FLAG_WP
    | FEATURE_THREAD_ID
    | FEATURE_MINOR_SHMEM
    | FEATURE_EXACT_ADDRESS
    | FEATURE_POISON
    | FEATURE_MOVE;

const PAGE_SIZE: u64 = 4096;

/// A fault reported to a context's reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Message {
    /// The faulting address, page-aligned unless the context asked for
    /// UFFD_FEATURE_EXACT_ADDRESS.
    pub(crate) address: u64,
    pub(crate) flags: u64,
    /// The faulting thread, with UFFD_FEATURE_THREAD_ID.
    pub(crate) thread: u32,
}

impl Message {
    /// `struct uffd_msg` of a UFFD_EVENT_PAGEFAULT.
    pub(crate) fn to_bytes(self) -> [u8; MESSAGE_SIZE] {
        const UFFD_EVENT_PAGEFAULT: u8 = 0x12;
        let mut bytes = [0; MESSAGE_SIZE];
        bytes[0] = UFFD_EVENT_PAGEFAULT;
        bytes[8..16].copy_from_slice(&self.flags.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.address.to_ne_bytes());
        bytes[24..28].copy_from_slice(&self.thread.to_ne_bytes());
        bytes
    }
}

/// Bytes of `struct uffd_msg`.
pub(crate) const MESSAGE_SIZE: usize = 32;

/// Why a context call failed, as the ioctls report it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// No such context, or it is not the caller's (EINVAL).
    Invalid,
    /// Part of the range belongs to another context (EBUSY).
    Busy,
    /// No memory for the bookkeeping (ENOMEM).
    NoMemory,
}

#[derive(Clone, Copy)]
struct Range {
    start: u64,
    end: u64,
    modes: u8,
}

struct Context {
    /// The domain instance and process whose memory this is.
    instance: usize,
    pid: u32,
    /// The features UFFDIO_API enabled; None before it.
    features: Option<u64>,
    ranges: Vec<Range>,
    /// Faults not read yet.
    unread: VecDeque<Message>,
    /// Pages with a reported fault not yet resolved.
    reported: Vec<u64>,
    /// Write-protected pages, with the protection each had.
    protected: Vec<(u64, u8)>,
}

impl Context {
    fn range_modes(&self, page: u64) -> u8 {
        self.ranges
            .iter()
            .find(|range| (range.start..range.end).contains(&page))
            .map_or(0, |range| range.modes)
    }

    fn of(&self, instance: usize, pid: u32) -> bool {
        self.instance == instance && self.pid == pid
    }

    /// Takes `start..end` out of the registered ranges.
    fn cut(&mut self, start: u64, end: u64) -> Result<(), Error> {
        let mut kept = Vec::new();
        kept.try_reserve(self.ranges.len() + 1)
            .map_err(|_| Error::NoMemory)?;
        for range in &self.ranges {
            if range.end <= start || range.start >= end {
                kept.push(*range);
                continue;
            }
            if range.start < start {
                kept.push(Range {
                    end: start,
                    ..*range
                });
            }
            if range.end > end {
                kept.push(Range {
                    start: end,
                    ..*range
                });
            }
        }
        self.ranges = kept;
        Ok(())
    }

    fn resolve(&mut self, start: u64, end: u64) {
        self.reported.retain(|page| !(start..end).contains(page));
        self.unread
            .retain(|message| !(start..end).contains(&(message.address & !(PAGE_SIZE - 1))));
    }
}

struct Contexts {
    contexts: Vec<Option<Context>>,
}

static CONTEXTS: SpinLock<Contexts> = SpinLock::new(
    LockRank::USERFAULTFD,
    Contexts {
        contexts: Vec::new(),
    },
);

/// Live contexts, so the fault path skips the table while there are none.
static LIVE: AtomicUsize = AtomicUsize::new(0);

impl Contexts {
    fn get(&mut self, id: u64) -> Option<&mut Context> {
        self.contexts.get_mut(usize::try_from(id).ok()?)?.as_mut()
    }
}

/// Whether any context exists.
pub(crate) fn active() -> bool {
    LIVE.load(Ordering::Acquire) != 0
}

/// Makes a context for process `pid` of `instance`; returns its id.
pub(crate) fn create(instance: usize, pid: u32) -> Option<u64> {
    let mut table = CONTEXTS.lock();
    let context = Context {
        instance,
        pid,
        features: None,
        ranges: Vec::new(),
        unread: VecDeque::new(),
        reported: Vec::new(),
        protected: Vec::new(),
    };
    let index = match table.contexts.iter().position(Option::is_none) {
        Some(index) => {
            table.contexts[index] = Some(context);
            index
        }
        None => {
            table.contexts.try_reserve(1).ok()?;
            table.contexts.push(Some(context));
            table.contexts.len() - 1
        }
    };
    LIVE.fetch_add(1, Ordering::AcqRel);
    Some(index as u64)
}

/// Drops context `id` after its last descriptor closed; returns the pages
/// it write-protected, with their protection, for the kernel to give back
/// when they are the current process's. Objects of other classes are not
/// this module's.
pub(crate) fn release(class: u8, id: u64) -> Option<Released> {
    if class != CLASS_CONTEXT {
        return None;
    }
    let context = CONTEXTS
        .lock()
        .contexts
        .get_mut(usize::try_from(id).ok()?)?
        .take()?;
    LIVE.fetch_sub(1, Ordering::AcqRel);
    Some(Released {
        instance: context.instance,
        pid: context.pid,
        protected: context.protected,
    })
}

/// What a released context leaves for the kernel to undo.
pub(crate) struct Released {
    pub(crate) instance: usize,
    pub(crate) pid: u32,
    /// The pages it write-protected, with their protection.
    pub(crate) protected: Vec<(u64, u8)>,
}

/// The process context `id` belongs to.
pub(crate) fn process(id: u64) -> Option<(usize, u32)> {
    CONTEXTS
        .lock()
        .get(id)
        .map(|context| (context.instance, context.pid))
}

/// The features UFFDIO_API enabled, None before it.
pub(crate) fn features(id: u64) -> Option<u64> {
    CONTEXTS.lock().get(id).and_then(|context| context.features)
}

/// UFFDIO_API: enables `features`, once.
pub(crate) fn negotiate(id: u64, features: u64) -> Result<(), Error> {
    let mut table = CONTEXTS.lock();
    let context = table.get(id).ok_or(Error::Invalid)?;
    if context.features.is_some() {
        return Err(Error::Invalid);
    }
    context.features = Some(features);
    Ok(())
}

/// The modes `start..end` (whole pages) are registered with by context
/// `id`, if every page is; 0 otherwise.
pub(crate) fn modes(id: u64, start: u64, end: u64) -> u8 {
    let mut table = CONTEXTS.lock();
    let Some(context) = table.get(id) else {
        return 0;
    };
    (start..end)
        .step_by(PAGE_SIZE as usize)
        .map(|page| context.range_modes(page))
        .fold(u8::MAX, |all, modes| all & modes)
        & (MODE_MISSING | MODE_WP | MODE_MINOR)
}

/// The modes page `page` of process `pid` is registered with, by any
/// context.
pub(crate) fn page_modes(instance: usize, pid: u32, page: u64) -> u8 {
    CONTEXTS
        .lock()
        .contexts
        .iter()
        .flatten()
        .filter(|context| context.of(instance, pid))
        .map(|context| context.range_modes(page))
        .fold(0, |all, modes| all | modes)
}

/// UFFDIO_REGISTER: registers `start..end` with `modes`. A range another
/// context of the same process holds is EBUSY.
pub(crate) fn register(id: u64, start: u64, end: u64, modes: u8) -> Result<(), Error> {
    let mut table = CONTEXTS.lock();
    let (instance, pid) = table
        .get(id)
        .map(|context| (context.instance, context.pid))
        .ok_or(Error::Invalid)?;
    let taken = table.contexts.iter().enumerate().any(|(other, context)| {
        other as u64 != id
            && context.as_ref().is_some_and(|context| {
                context.of(instance, pid)
                    && context
                        .ranges
                        .iter()
                        .any(|range| range.start < end && start < range.end)
            })
    });
    if taken {
        return Err(Error::Busy);
    }
    let context = table.get(id).ok_or(Error::Invalid)?;
    context.cut(start, end)?;
    context.ranges.try_reserve(1).map_err(|_| Error::NoMemory)?;
    context.ranges.push(Range { start, end, modes });
    Ok(())
}

/// UFFDIO_UNREGISTER: drops `start..end` from context `id` and returns
/// the pages there it write-protected, for the kernel to give back.
pub(crate) fn unregister(id: u64, start: u64, end: u64) -> Result<Vec<(u64, u8)>, Error> {
    let mut table = CONTEXTS.lock();
    let context = table.get(id).ok_or(Error::Invalid)?;
    context.cut(start, end)?;
    context.resolve(start, end);
    Ok(take_protected(context, start, end))
}

fn take_protected(context: &mut Context, start: u64, end: u64) -> Vec<(u64, u8)> {
    let (taken, kept) = core::mem::take(&mut context.protected)
        .into_iter()
        .partition(|(page, _)| (start..end).contains(page));
    context.protected = kept;
    taken
}

/// Process `pid` unmapped `start..end` (or, with all of it, replaced its
/// image or ended): its contexts lose those registrations, reports and
/// protections, as Linux's do with the areas.
pub(crate) fn forget(instance: usize, pid: u32, start: u64, end: u64) {
    if !active() {
        return;
    }
    let mut table = CONTEXTS.lock();
    for context in table
        .contexts
        .iter_mut()
        .flatten()
        .filter(|context| context.of(instance, pid))
    {
        let _ = context.cut(start, end);
        context.resolve(start, end);
        let _ = take_protected(context, start, end);
    }
}

/// What a fault is to the contexts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    /// No context resolves it: the kernel does.
    Unregistered,
    /// A context's reader has it (now or before): the thread waits.
    Reported,
}

/// The kinds of fault a context resolves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Missing,
    WriteProtect,
    Minor,
}

/// A fault of thread `thread` of process `pid` at `address`, of `kind`
/// (`write` for a write access): reported to the context that registered
/// the page for it, once until it is resolved.
pub(crate) fn fault(
    instance: usize,
    pid: u32,
    thread: u32,
    address: u64,
    kind: Kind,
    write: bool,
) -> Fault {
    let page = address & !(PAGE_SIZE - 1);
    let (mode, mut flags) = match kind {
        Kind::Missing => (MODE_MISSING, 0),
        Kind::WriteProtect => (MODE_WP, FLAG_WP),
        Kind::Minor => (MODE_MINOR, FLAG_MINOR),
    };
    if write {
        flags |= FLAG_WRITE;
    }
    let mut table = CONTEXTS.lock();
    let Some(context) = table.contexts.iter_mut().flatten().find(|context| {
        context.of(instance, pid)
            && context.features.is_some()
            && context.range_modes(page) & mode != 0
            && (kind != Kind::WriteProtect
                || context
                    .protected
                    .iter()
                    .any(|(protected, _)| *protected == page))
    }) else {
        return Fault::Unregistered;
    };
    if context.reported.contains(&page) {
        return Fault::Reported;
    }
    let features = context.features.unwrap_or(0);
    let message = Message {
        address: if features & FEATURE_EXACT_ADDRESS != 0 {
            address
        } else {
            page
        },
        flags,
        thread: if features & FEATURE_THREAD_ID != 0 {
            thread
        } else {
            0
        },
    };
    if context.reported.try_reserve(1).is_err() || context.unread.try_reserve(1).is_err() {
        return Fault::Reported;
    }
    context.reported.push(page);
    context.unread.push_back(message);
    Fault::Reported
}

/// The unread faults of context `id`, at most `limit`, oldest first.
/// Invalid before UFFDIO_API.
pub(crate) fn read(id: u64, limit: usize) -> Result<Vec<Message>, Error> {
    let mut table = CONTEXTS.lock();
    let context = table.get(id).ok_or(Error::Invalid)?;
    if context.features.is_none() {
        return Err(Error::Invalid);
    }
    let count = limit.min(context.unread.len());
    Ok(context.unread.drain(..count).collect())
}

/// Whether context `id` has faults to read; None before UFFDIO_API.
pub(crate) fn readable(id: u64) -> Option<bool> {
    let mut table = CONTEXTS.lock();
    let context = table.get(id)?;
    context.features?;
    Some(!context.unread.is_empty())
}

/// The faults on `start..end` are resolved: their threads go on (WAKE,
/// and the ioctls that fill or unprotect a range).
pub(crate) fn resolve(id: u64, start: u64, end: u64) {
    if let Some(context) = CONTEXTS.lock().get(id) {
        context.resolve(start, end);
    }
}

/// Whether context `id` write-protected `page`.
pub(crate) fn protected(id: u64, page: u64) -> bool {
    CONTEXTS.lock().get(id).is_some_and(|context| {
        context
            .protected
            .iter()
            .any(|(protected, _)| *protected == page)
    })
}

/// Records that context `id` write-protected `page`, which had
/// `protection`.
pub(crate) fn protect(id: u64, page: u64, protection: u8) -> Result<(), Error> {
    let mut table = CONTEXTS.lock();
    let context = table.get(id).ok_or(Error::Invalid)?;
    if context
        .protected
        .iter()
        .any(|(protected, _)| *protected == page)
    {
        return Ok(());
    }
    context
        .protected
        .try_reserve(1)
        .map_err(|_| Error::NoMemory)?;
    context.protected.push((page, protection));
    Ok(())
}

/// Ends context `id`'s write protection of `page`; returns the protection
/// the page had.
pub(crate) fn unprotect(id: u64, page: u64) -> Option<u8> {
    let mut table = CONTEXTS.lock();
    let context = table.get(id)?;
    let index = context
        .protected
        .iter()
        .position(|(protected, _)| *protected == page)?;
    Some(context.protected.swap_remove(index).1)
}
