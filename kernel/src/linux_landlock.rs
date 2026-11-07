//! Landlock state: the rulesets descriptors name, the domain each process
//! is restricted by, and the domains of the processes that bound abstract
//! Unix socket names. The policy itself is `ginux_landlock`'s.
//!
//! A ruleset descriptor is an object slot of the socket table
//! ([`CLASS_RULESET`]), so dup, fork, SCM_RIGHTS and close count it; the
//! last close drops the ruleset. A process's domain is copied to the
//! children it forks, kept across exec and dropped at exit. Linux keeps a
//! domain per thread (in its credentials); here every thread of a process
//! shares one, which is what a process restricting itself before it starts
//! threads (the documented use) sees.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use ginux_landlock::{Denial, Domain, Error, Ruleset};

use crate::linux_socket::SlotId;
use crate::sync::{LockRank, SpinLock};

/// The object class of ruleset descriptors in the socket table.
pub(crate) const CLASS_RULESET: u8 = 12;

struct Process {
    instance: usize,
    pid: u32,
    domain: Domain,
}

/// An abstract Unix socket name's binder, with the domain it had then.
struct BoundSocket {
    instance: usize,
    slot: SlotId,
    domain: Domain,
}

struct State {
    rulesets: Vec<Option<Ruleset>>,
    processes: Vec<Process>,
    sockets: Vec<BoundSocket>,
    /// The id the next enforced ruleset gets as a layer.
    next_layer: u64,
}

static STATE: SpinLock<State> = SpinLock::new(
    LockRank::LANDLOCK,
    State {
        rulesets: Vec::new(),
        processes: Vec::new(),
        sockets: Vec::new(),
        next_layer: 1,
    },
);

/// Restricted processes, so checks skip the table while there are none.
static RESTRICTED: AtomicUsize = AtomicUsize::new(0);

impl State {
    fn ruleset(&mut self, id: u64) -> Option<&mut Ruleset> {
        self.rulesets.get_mut(usize::try_from(id).ok()?)?.as_mut()
    }

    fn domain(&self, instance: usize, pid: u32) -> Option<&Domain> {
        self.processes
            .iter()
            .find(|process| process.instance == instance && process.pid == pid)
            .map(|process| &process.domain)
    }

    fn forget(&mut self, instance: usize, pid: u32) {
        let before = self.processes.len();
        self.processes
            .retain(|process| process.instance != instance || process.pid != pid);
        RESTRICTED.fetch_sub(before - self.processes.len(), Ordering::AcqRel);
    }

    fn set(&mut self, instance: usize, pid: u32, domain: Domain) -> Result<(), Error> {
        if let Some(process) = self
            .processes
            .iter_mut()
            .find(|process| process.instance == instance && process.pid == pid)
        {
            process.domain = domain;
            return Ok(());
        }
        self.processes.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.processes.push(Process {
            instance,
            pid,
            domain,
        });
        RESTRICTED.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

fn restricted() -> bool {
    RESTRICTED.load(Ordering::Acquire) != 0
}

/// Asks `question` of the domain of process `pid` of `instance`; an
/// unrestricted process gets `free`.
fn with_domain<T>(instance: usize, pid: u32, free: T, question: impl FnOnce(&Domain) -> T) -> T {
    if !restricted() {
        return free;
    }
    STATE.lock().domain(instance, pid).map_or(free, question)
}

/// A new ruleset handling these rights and scopes; returns its id.
pub(crate) fn create(handled_fs: u64, handled_net: u64, scoped: u64) -> Result<u64, Error> {
    let ruleset = Ruleset::new(handled_fs, handled_net, scoped)?;
    let mut state = STATE.lock();
    let index = match state.rulesets.iter().position(Option::is_none) {
        Some(index) => {
            state.rulesets[index] = Some(ruleset);
            index
        }
        None => {
            state.rulesets.try_reserve(1).map_err(|_| Error::NoMemory)?;
            state.rulesets.push(Some(ruleset));
            state.rulesets.len() - 1
        }
    };
    Ok(index as u64)
}

/// Drops ruleset `id` after its last descriptor closed. Objects of other
/// classes are not this module's.
pub(crate) fn release(class: u8, id: u64) {
    if class != CLASS_RULESET {
        return;
    }
    if let Ok(index) = usize::try_from(id) {
        if let Some(ruleset) = STATE.lock().rulesets.get_mut(index) {
            *ruleset = None;
        }
    }
}

/// The checks of a path-beneath rule for ruleset `id` that come before its
/// file descriptor is looked at.
pub(crate) fn check_path_rule(id: u64, allowed: u64) -> Result<(), Error> {
    STATE
        .lock()
        .ruleset(id)
        .ok_or(Error::Invalid)?
        .check_path_rule(allowed)
}

/// Adds a path-beneath rule to ruleset `id`.
pub(crate) fn add_path(id: u64, path: &[u8], directory: bool, allowed: u64) -> Result<(), Error> {
    STATE
        .lock()
        .ruleset(id)
        .ok_or(Error::Invalid)?
        .add_path(path, directory, allowed)
}

/// Adds a TCP port rule to ruleset `id`.
pub(crate) fn add_port(id: u64, port: u64, allowed: u64) -> Result<(), Error> {
    STATE
        .lock()
        .ruleset(id)
        .ok_or(Error::Invalid)?
        .add_port(port, allowed)
}

/// Restricts process `pid` of `instance` by ruleset `id` as a new layer.
pub(crate) fn restrict(instance: usize, pid: u32, id: u64) -> Result<(), Error> {
    let mut state = STATE.lock();
    let layer = state.next_layer;
    let ruleset = state.ruleset(id).ok_or(Error::Invalid)?.clone();
    let domain = state
        .domain(instance, pid)
        .cloned()
        .unwrap_or_default()
        .restricted_by(&ruleset, layer)?;
    state.set(instance, pid, domain)?;
    state.next_layer += 1;
    Ok(())
}

/// Gives a forked `child` its parent's domain; what an exited process left
/// under a reused id goes first. False when there is no memory for it: the
/// fork fails rather than let the child go unrestricted.
pub(crate) fn fork(instance: usize, parent: u32, child: u32) -> bool {
    if !restricted() {
        return true;
    }
    let mut state = STATE.lock();
    state.forget(instance, child);
    match state.domain(instance, parent).cloned() {
        Some(domain) => state.set(instance, child, domain).is_ok(),
        None => true,
    }
}

/// A domain starts on `instance`: what its last run left (processes it
/// killed without reaping, sockets) goes.
pub(crate) fn start_instance(instance: usize) {
    let mut state = STATE.lock();
    let before = state.processes.len();
    state
        .processes
        .retain(|process| process.instance != instance);
    RESTRICTED.fetch_sub(before - state.processes.len(), Ordering::AcqRel);
    state.sockets.retain(|socket| socket.instance != instance);
}

/// Process `pid` was reaped.
pub(crate) fn exit(instance: usize, pid: u32) {
    if restricted() {
        STATE.lock().forget(instance, pid);
    }
}

/// Whether process `pid` is restricted by any ruleset.
pub(crate) fn is_restricted(instance: usize, pid: u32) -> bool {
    with_domain(instance, pid, false, Domain::is_restricted)
}

/// Whether some layer of `pid`'s domain handles a filesystem right (which
/// forbids mounting and unmounting).
pub(crate) fn restricts_filesystem(instance: usize, pid: u32) -> bool {
    with_domain(instance, pid, false, Domain::restricts_filesystem)
}

/// Whether process `pid` may have `access` on `path`.
pub(crate) fn allows_path(instance: usize, pid: u32, path: &[u8], access: u64) -> bool {
    access == 0
        || with_domain(instance, pid, true, |domain| {
            domain.allows_path(path, access)
        })
}

/// Whether process `pid` may move or link a file from directory `from` to
/// directory `to` (see `Domain::check_move`).
pub(crate) fn check_move(
    instance: usize,
    pid: u32,
    from: &[u8],
    to: &[u8],
    removal: u64,
    making: u64,
    file_rights: u64,
) -> Result<(), Denial> {
    with_domain(instance, pid, Ok(()), |domain| {
        domain.check_move(from, to, removal, making, file_rights)
    })
}

/// Whether process `pid` may bind or connect (`access`) TCP port `port`.
pub(crate) fn allows_port(instance: usize, pid: u32, port: u16, access: u64) -> bool {
    with_domain(instance, pid, true, |domain| {
        domain.allows_port(port, access)
    })
}

/// Whether process `pid` may signal process `target`.
pub(crate) fn may_signal(instance: usize, pid: u32, target: u32) -> bool {
    if !restricted() {
        return true;
    }
    let state = STATE.lock();
    let Some(domain) = state.domain(instance, pid) else {
        return true;
    };
    let free = Domain::default();
    let target = state.domain(instance, target).unwrap_or(&free);
    domain.reaches(ginux_landlock::access::SCOPE_SIGNAL, target)
}

/// Socket `slot` was bound to an abstract name by process `pid`: connects
/// and sends to it are judged by the domain `pid` has now.
pub(crate) fn bound_abstract(instance: usize, pid: u32, slot: SlotId) {
    let mut state = STATE.lock();
    state
        .sockets
        .retain(|socket| socket.instance != instance || socket.slot != slot);
    if let Some(domain) = state.domain(instance, pid).cloned() {
        if state.sockets.try_reserve(1).is_ok() {
            state.sockets.push(BoundSocket {
                instance,
                slot,
                domain,
            });
        }
    }
}

/// Whether process `pid` may connect or send to the socket `slot` bound to
/// an abstract name.
pub(crate) fn may_reach_socket(instance: usize, pid: u32, slot: SlotId) -> bool {
    if !restricted() {
        return true;
    }
    let state = STATE.lock();
    let Some(domain) = state.domain(instance, pid) else {
        return true;
    };
    let free = Domain::default();
    let target = state
        .sockets
        .iter()
        .find(|socket| socket.instance == instance && socket.slot == slot)
        .map_or(&free, |socket| &socket.domain);
    domain.reaches(ginux_landlock::access::SCOPE_ABSTRACT_UNIX_SOCKET, target)
}
