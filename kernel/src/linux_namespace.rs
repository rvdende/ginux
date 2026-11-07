//! The namespaces a process has besides its user and mount ones (which
//! `linux_user` and `linux_mount` keep): UTS (its host and domain name),
//! IPC (its System V objects), PID (the process ids it sees), time (the
//! offsets of its monotonic and boot-time clocks) and network (its
//! interfaces and /proc/sys/net values).
//!
//! A domain's processes start in its initial namespace of each kind,
//! number 0, which holds no entry here: the domain-wide host name, System V
//! instance, process ids, clocks and network (the domain's network service
//! with its loopback and eth0). A network namespace made inside the domain
//! has only a loopback interface of its own, down until a process brings
//! it up, and its own /proc/sys/net values. clone and unshare make new ones,
//! setns joins one through a /proc/PID/ns descriptor, and a namespace goes
//! once no process is in it, none will be born into it, and no PID
//! namespace below it is left. Namespaces never reach past their domain:
//! every table entry belongs to one domain instance.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    control_abi, linux_user,
    sync::{LockRank, SpinLock},
};

/// How deep PID namespaces may nest (Linux's MAX_PID_NS_LEVEL).
pub(crate) const PID_LEVEL_LIMIT: usize = 32;
/// System V instances for IPC namespaces made inside domains, after the
/// domains' own (`linux_sysv_ipc` has one per domain and the host's).
pub(crate) const IPC_INSTANCE_LIMIT: usize = 16;
/// The first System V instance an IPC namespace gets.
pub(crate) const IPC_INSTANCE_FIRST: usize = control_abi::DOMAIN_LIMIT + 1;
/// The /proc/sys/net values a network namespace keeps (the caller numbers
/// them).
pub(crate) const NET_SYSCTL_LIMIT: usize = 8;
/// The most UTS name bytes (Linux's __NEW_UTS_LEN).
pub(crate) const UTS_NAME_CAPACITY: usize = 64;

/// The kinds of namespace /proc/PID/ns shows, with Linux's CLONE_NEW* flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    User,
    Mount,
    Uts,
    Ipc,
    Pid,
    Time,
    Net,
    Cgroup,
}

impl Kind {
    pub(crate) const ALL: [Self; 8] = [
        Self::User,
        Self::Mount,
        Self::Uts,
        Self::Ipc,
        Self::Pid,
        Self::Time,
        Self::Net,
        Self::Cgroup,
    ];

    /// The CLONE_NEW* flag setns and NS_GET_NSTYPE name the kind by.
    pub(crate) const fn clone_flag(self) -> u64 {
        match self {
            Self::User => 0x1000_0000,
            Self::Mount => 0x2_0000,
            Self::Uts => 0x0400_0000,
            Self::Ipc => 0x0800_0000,
            Self::Pid => 0x2000_0000,
            Self::Time => 0x80,
            Self::Net => 0x4000_0000,
            Self::Cgroup => 0x0200_0000,
        }
    }

    /// The name readlink shows before the inode number (`uts:[...]`).
    pub(crate) const fn name(self) -> &'static [u8] {
        match self {
            Self::User => b"user",
            Self::Mount => b"mnt",
            Self::Uts => b"uts",
            Self::Ipc => b"ipc",
            Self::Pid => b"pid",
            Self::Time => b"time",
            Self::Net => b"net",
            Self::Cgroup => b"cgroup",
        }
    }

    const fn index(self) -> u64 {
        self as u64
    }

    fn from_index(index: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.index() == index)
    }

    /// The inode of namespace `id` of this kind: Linux's fixed numbers for
    /// the initial ones (PROC_*_INIT_INO), and numbers above 0xf0000000,
    /// where Linux hands out the rest, for the others.
    pub(crate) const fn inode(self, id: u32) -> u64 {
        if id == 0 {
            return match self {
                Self::Ipc => 0xefff_ffff,
                Self::Uts => 0xefff_fffe,
                Self::User => 0xefff_fffd,
                Self::Pid => 0xefff_fffc,
                Self::Cgroup => 0xefff_fffb,
                Self::Time => 0xefff_fffa,
                Self::Net => 0xefff_fff9,
                Self::Mount => 0xefff_fff8,
            };
        }
        0xf000_0000 + (self.index() << 24) + id as u64
    }
}

/// A namespace as a /proc/PID/ns descriptor holds it: its kind, its number
/// (0 for the domain's initial one of kinds kept here) and, for user and
/// mount namespaces, the word their own module finds the handle by.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Reference {
    pub(crate) kind: Kind,
    pub(crate) id: u32,
    pub(crate) handle: u64,
}

impl Reference {
    /// The reference packed into one descriptor word: the kind in the top
    /// four bits, the number in the next 24, the handle word in the rest.
    pub(crate) fn to_word(self) -> u64 {
        self.kind.index() << 60 | u64::from(self.id & 0xff_ffff) << 36 | self.handle & 0xf_ffff_ffff
    }

    pub(crate) fn from_word(word: u64) -> Option<Self> {
        Some(Self {
            kind: Kind::from_index(word >> 60)?,
            id: ((word >> 36) & 0xff_ffff) as u32,
            handle: word & 0xf_ffff_ffff,
        })
    }

    pub(crate) fn inode(self) -> u64 {
        self.kind.inode(self.id)
    }
}

/// The namespaces of the kinds kept here a process is in, by number.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Set {
    pub(crate) uts: u32,
    pub(crate) ipc: u32,
    /// The PID namespace the process lives in (fixed for its life).
    pub(crate) pid: u32,
    /// Where its children are born: unshare(CLONE_NEWPID) and setns move it.
    pub(crate) pid_for_children: u32,
    pub(crate) time: u32,
    /// Where its children are born; unshare(CLONE_NEWTIME) moves it.
    pub(crate) time_for_children: u32,
    pub(crate) net: u32,
}

impl Set {
    /// The set a child forked from a process with this one starts with: it
    /// lives in its parent's namespaces for children.
    pub(crate) fn for_child(self) -> Self {
        Self {
            pid: self.pid_for_children,
            time: self.time_for_children,
            ..self
        }
    }

    fn uses(&self, kind: Kind, id: u32) -> bool {
        match kind {
            Kind::Uts => self.uts == id,
            Kind::Ipc => self.ipc == id,
            Kind::Pid => self.pid == id || self.pid_for_children == id,
            Kind::Time => self.time == id || self.time_for_children == id,
            Kind::Net => self.net == id,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The table could not grow (ENOMEM).
    NoMemory,
    /// The domain holds as many as it may (ENOSPC), or PID namespaces nest
    /// too deep (EUSERS from the caller).
    NoSpace,
    /// The namespace is gone or is not of that kind (EINVAL).
    Invalid,
    /// A process already entered the time namespace: its offsets are fixed
    /// (EACCES).
    Frozen,
}

#[derive(Clone, Copy)]
enum Data {
    Uts {
        names: [[u8; UTS_NAME_CAPACITY]; 2],
        lengths: [u8; 2],
    },
    /// The System V instance holding the namespace's objects.
    Ipc { instance: usize },
    Pid {
        /// The namespace it was made in (0: the domain's initial one).
        parent: u32,
        /// 1 for a child of the initial namespace, and so on down.
        level: u8,
        next_pid: u32,
    },
    Time {
        /// CLOCK_MONOTONIC's and CLOCK_BOOTTIME's offsets in nanoseconds.
        offsets: [i64; 2],
        /// A process entered it: the offsets no longer change.
        frozen: bool,
    },
    Net {
        loopback: Loopback,
        /// The /proc/sys/net values written in it, by the caller's number
        /// (`None`: the built-in one).
        sysctls: [Option<i64>; NET_SYSCTL_LIMIT],
    },
}

/// A network namespace's loopback interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Loopback {
    /// IFF_UP: it carries 127.0.0.0/8.
    pub(crate) up: bool,
    pub(crate) mtu: i32,
}

#[derive(Clone, Copy)]
struct Namespace {
    instance: usize,
    id: u32,
    /// The user namespace that owns it (NS_GET_USERNS).
    owner: linux_user::UserNamespaceHandle,
    data: Data,
}

impl Namespace {
    fn kind(&self) -> Kind {
        match self.data {
            Data::Uts { .. } => Kind::Uts,
            Data::Ipc { .. } => Kind::Ipc,
            Data::Pid { .. } => Kind::Pid,
            Data::Time { .. } => Kind::Time,
            Data::Net { .. } => Kind::Net,
        }
    }
}

/// A process born into a PID namespace below the initial one: the
/// namespaces from level 1 down to its own, and its number in each.
struct LocalPids {
    instance: usize,
    global: u32,
    chain: Vec<u32>,
    pids: Vec<u32>,
    /// Its parent reaped it: kept until the next reap, so the wait that
    /// reaped it can still tell the parent its number.
    reaped: bool,
}

impl LocalPids {
    /// Its number in PID namespace `namespace`, if it lies within it.
    fn seen_from(&self, namespace: u32) -> Option<u32> {
        let index = self.chain.iter().position(|id| *id == namespace)?;
        self.pids.get(index).copied()
    }
}

struct Namespaces {
    namespaces: Vec<Namespace>,
    pids: Vec<LocalPids>,
    /// System V instances of namespaces that went while a process still
    /// had a segment attached; they are released once none is.
    draining_ipc: Vec<usize>,
    next_id: u32,
}

static NAMESPACES: SpinLock<Namespaces> = SpinLock::new(
    LockRank::NAMESPACES,
    Namespaces {
        namespaces: Vec::new(),
        pids: Vec::new(),
        draining_ipc: Vec::new(),
        next_id: 1,
    },
);

/// How many PID, IPC, time and network namespaces exist beyond the
/// initial ones: while none does, the calls that translate need not look.
static LIVE_COUNTS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

fn count_slot(kind: Kind) -> Option<usize> {
    match kind {
        Kind::Pid => Some(0),
        Kind::Ipc => Some(1),
        Kind::Time => Some(2),
        Kind::Net => Some(3),
        _ => None,
    }
}

/// Whether any namespace of `kind` exists beyond the initial ones.
pub(crate) fn any(kind: Kind) -> bool {
    count_slot(kind).is_some_and(|slot| LIVE_COUNTS[slot].load(Ordering::Acquire) != 0)
}

impl Namespaces {
    fn find(&self, instance: usize, id: u32) -> Option<&Namespace> {
        self.namespaces
            .iter()
            .find(|namespace| namespace.instance == instance && namespace.id == id)
    }

    fn find_mut(&mut self, instance: usize, id: u32) -> Option<&mut Namespace> {
        self.namespaces
            .iter_mut()
            .find(|namespace| namespace.instance == instance && namespace.id == id)
    }

    fn insert(
        &mut self,
        instance: usize,
        owner: linux_user::UserNamespaceHandle,
        data: Data,
    ) -> Result<u32, Error> {
        self.namespaces
            .try_reserve(1)
            .map_err(|_| Error::NoMemory)?;
        let id = self.next_id;
        // Numbers fit the 24 bits a descriptor keeps; wrapping skips the
        // ones still in use.
        let mut candidate = id;
        while self
            .namespaces
            .iter()
            .any(|namespace| namespace.id == candidate)
            || candidate == 0
        {
            candidate = (candidate % 0xff_ffff) + 1;
        }
        self.next_id = (candidate % 0xff_ffff) + 1;
        let namespace = Namespace {
            instance,
            id: candidate,
            owner,
            data,
        };
        if let Some(slot) = count_slot(namespace.kind()) {
            LIVE_COUNTS[slot].fetch_add(1, Ordering::AcqRel);
        }
        self.namespaces.push(namespace);
        Ok(candidate)
    }

    /// The PID namespace `id`'s parent and level (the initial one: none, 0).
    fn pid_position(&self, instance: usize, id: u32) -> Option<(u32, u8)> {
        if id == 0 {
            return Some((0, 0));
        }
        match self.find(instance, id)?.data {
            Data::Pid { parent, level, .. } => Some((parent, level)),
            _ => None,
        }
    }

    /// The PID namespaces from level 1 down to `id`, in order.
    fn pid_chain(&self, instance: usize, id: u32) -> Option<Vec<u32>> {
        let (_, level) = self.pid_position(instance, id)?;
        let mut chain = Vec::new();
        chain.try_reserve_exact(usize::from(level)).ok()?;
        chain.resize(usize::from(level), 0);
        let mut current = id;
        for slot in (0..usize::from(level)).rev() {
            chain[slot] = current;
            current = self.pid_position(instance, current)?.0;
        }
        Some(chain)
    }
}

/// A new UTS namespace owned by `owner`, holding `host` and `domain`.
pub(crate) fn create_uts(
    instance: usize,
    owner: linux_user::UserNamespaceHandle,
    host: &[u8],
    domain: &[u8],
) -> Result<u32, Error> {
    let mut names = [[0; UTS_NAME_CAPACITY]; 2];
    let mut lengths = [0; 2];
    for (index, name) in [host, domain].into_iter().enumerate() {
        let name = &name[..name.len().min(UTS_NAME_CAPACITY)];
        names[index][..name.len()].copy_from_slice(name);
        lengths[index] = name.len() as u8;
    }
    NAMESPACES
        .lock()
        .insert(instance, owner, Data::Uts { names, lengths })
}

/// UTS namespace `id`'s host (`which` 0) or domain (1) name into `output`.
pub(crate) fn uts_name(
    instance: usize,
    id: u32,
    which: usize,
    output: &mut [u8; UTS_NAME_CAPACITY],
) -> Option<usize> {
    let table = NAMESPACES.lock();
    let Data::Uts { names, lengths } = table.find(instance, id)?.data else {
        return None;
    };
    let length = usize::from(*lengths.get(which)?);
    output[..length].copy_from_slice(&names[which][..length]);
    Some(length)
}

/// Sets UTS namespace `id`'s host (`which` 0) or domain (1) name.
pub(crate) fn set_uts_name(instance: usize, id: u32, which: usize, name: &[u8]) -> bool {
    if which > 1 || name.len() > UTS_NAME_CAPACITY {
        return false;
    }
    let mut table = NAMESPACES.lock();
    let Some(Namespace {
        data: Data::Uts { names, lengths },
        ..
    }) = table.find_mut(instance, id)
    else {
        return false;
    };
    names[which][..name.len()].copy_from_slice(name);
    lengths[which] = name.len() as u8;
    true
}

/// A new IPC namespace owned by `owner`, with a System V instance of its own.
pub(crate) fn create_ipc(
    instance: usize,
    owner: linux_user::UserNamespaceHandle,
) -> Result<u32, Error> {
    let mut table = NAMESPACES.lock();
    let taken = |candidate: usize, table: &Namespaces| {
        table.draining_ipc.contains(&candidate)
            || table
                .namespaces
                .iter()
                .any(|namespace| matches!(namespace.data, Data::Ipc { instance } if instance == candidate))
    };
    let ipc_instance = (IPC_INSTANCE_FIRST..IPC_INSTANCE_FIRST + IPC_INSTANCE_LIMIT)
        .find(|candidate| !taken(*candidate, &table))
        .ok_or(Error::NoSpace)?;
    table.insert(
        instance,
        owner,
        Data::Ipc {
            instance: ipc_instance,
        },
    )
}

/// The System V instance of IPC namespace `id`.
pub(crate) fn ipc_instance(instance: usize, id: u32) -> Option<usize> {
    match NAMESPACES.lock().find(instance, id)?.data {
        Data::Ipc { instance } => Some(instance),
        _ => None,
    }
}

/// A new PID namespace below `parent`, owned by `owner`.
pub(crate) fn create_pid(
    instance: usize,
    owner: linux_user::UserNamespaceHandle,
    parent: u32,
) -> Result<u32, Error> {
    let mut table = NAMESPACES.lock();
    let (_, parent_level) = table.pid_position(instance, parent).ok_or(Error::Invalid)?;
    if usize::from(parent_level) + 1 >= PID_LEVEL_LIMIT {
        return Err(Error::NoSpace);
    }
    table.insert(
        instance,
        owner,
        Data::Pid {
            parent,
            level: parent_level + 1,
            next_pid: 1,
        },
    )
}

/// PID namespace `id`'s parent: `None` for the initial one.
pub(crate) fn pid_parent(instance: usize, id: u32) -> Option<u32> {
    if id == 0 {
        return None;
    }
    NAMESPACES
        .lock()
        .pid_position(instance, id)
        .map(|(parent, _)| parent)
}

/// Whether PID namespace `inner` is `outer` or lies below it.
pub(crate) fn pid_within(instance: usize, outer: u32, inner: u32) -> bool {
    if outer == 0 {
        return true;
    }
    let table = NAMESPACES.lock();
    table
        .pid_chain(instance, inner)
        .is_some_and(|chain| chain.contains(&outer))
}

/// Gives process `global`, born into PID namespace `namespace`, its number
/// there and in every namespace between it and the initial one.
pub(crate) fn enter_pid(instance: usize, namespace: u32, global: u32) -> Result<(), Error> {
    if namespace == 0 {
        return Ok(());
    }
    let mut table = NAMESPACES.lock();
    let chain = table.pid_chain(instance, namespace).ok_or(Error::Invalid)?;
    table.pids.try_reserve(1).map_err(|_| Error::NoMemory)?;
    let mut pids: Vec<u32> = Vec::new();
    pids.try_reserve_exact(chain.len())
        .map_err(|_| Error::NoMemory)?;
    for id in &chain {
        let Some(Namespace {
            data: Data::Pid { next_pid, .. },
            ..
        }) = table.find_mut(instance, *id)
        else {
            return Err(Error::Invalid);
        };
        pids.push(*next_pid);
        *next_pid = next_pid.checked_add(1).ok_or(Error::NoSpace)?;
    }
    table
        .pids
        .retain(|entry| !(entry.instance == instance && entry.global == global));
    table.pids.push(LocalPids {
        instance,
        global,
        chain,
        pids,
        reaped: false,
    });
    Ok(())
}

/// Process `global` was reaped: its numbers go at the next reap (or
/// failed fork), once the wait that reaped it has reported it.
pub(crate) fn forget_pid(instance: usize, global: u32) {
    if !any(Kind::Pid) {
        return;
    }
    let mut table = NAMESPACES.lock();
    table
        .pids
        .retain(|entry| !(entry.instance == instance && entry.reaped));
    if let Some(entry) = table
        .pids
        .iter_mut()
        .find(|entry| entry.instance == instance && entry.global == global)
    {
        entry.reaped = true;
    }
}

/// Process `global`'s number as PID namespace `observer` sees it: `None`
/// when it lies outside that namespace.
pub(crate) fn pid_seen_from(instance: usize, observer: u32, global: u32) -> Option<u32> {
    if observer == 0 {
        return Some(global);
    }
    NAMESPACES
        .lock()
        .pids
        .iter()
        .find(|entry| entry.instance == instance && entry.global == global)?
        .seen_from(observer)
}

/// The live process PID namespace `observer` calls `local`, by its global
/// number.
pub(crate) fn pid_global(instance: usize, observer: u32, local: u32) -> Option<u32> {
    if observer == 0 {
        return Some(local);
    }
    NAMESPACES
        .lock()
        .pids
        .iter()
        .find(|entry| {
            entry.instance == instance && !entry.reaped && entry.seen_from(observer) == Some(local)
        })
        .map(|entry| entry.global)
}

/// The global numbers of the live processes born into PID namespace
/// `namespace` or one below it.
pub(crate) fn pid_members(instance: usize, namespace: u32) -> Vec<u32> {
    let table = NAMESPACES.lock();
    let mut members = Vec::new();
    for entry in table.pids.iter().filter(|entry| {
        entry.instance == instance && !entry.reaped && entry.chain.contains(&namespace)
    }) {
        if members.try_reserve(1).is_ok() {
            members.push(entry.global);
        }
    }
    members
}

/// A new time namespace owned by `owner`, starting with `source`'s offsets.
pub(crate) fn create_time(
    instance: usize,
    owner: linux_user::UserNamespaceHandle,
    source: u32,
) -> Result<u32, Error> {
    let mut table = NAMESPACES.lock();
    let offsets = if source == 0 {
        [0; 2]
    } else {
        match table.find(instance, source).ok_or(Error::Invalid)?.data {
            Data::Time { offsets, .. } => offsets,
            _ => return Err(Error::Invalid),
        }
    };
    table.insert(
        instance,
        owner,
        Data::Time {
            offsets,
            frozen: false,
        },
    )
}

/// Time namespace `id`'s CLOCK_MONOTONIC and CLOCK_BOOTTIME offsets.
pub(crate) fn time_offsets(instance: usize, id: u32) -> [i64; 2] {
    if id == 0 || !any(Kind::Time) {
        return [0; 2];
    }
    match NAMESPACES
        .lock()
        .find(instance, id)
        .map(|namespace| namespace.data)
    {
        Some(Data::Time { offsets, .. }) => offsets,
        _ => [0; 2],
    }
}

/// Sets time namespace `id`'s offsets (`None` keeps one): only before a
/// process entered it.
pub(crate) fn set_time_offsets(
    instance: usize,
    id: u32,
    monotonic: Option<i64>,
    boottime: Option<i64>,
) -> Result<(), Error> {
    if id == 0 {
        // The initial namespace is in use from the start.
        return Err(Error::Frozen);
    }
    let mut table = NAMESPACES.lock();
    let Some(Namespace {
        data: Data::Time { offsets, frozen },
        ..
    }) = table.find_mut(instance, id)
    else {
        return Err(Error::Invalid);
    };
    if *frozen {
        return Err(Error::Frozen);
    }
    if let Some(value) = monotonic {
        offsets[0] = value;
    }
    if let Some(value) = boottime {
        offsets[1] = value;
    }
    Ok(())
}

/// A process entered time namespace `id`: its offsets are fixed from now.
pub(crate) fn freeze_time(instance: usize, id: u32) {
    if let Some(Namespace {
        data: Data::Time { frozen, .. },
        ..
    }) = NAMESPACES.lock().find_mut(instance, id)
    {
        *frozen = true;
    }
}

/// A new network namespace owned by `owner`: a loopback interface, down,
/// and the built-in /proc/sys/net values.
pub(crate) fn create_net(
    instance: usize,
    owner: linux_user::UserNamespaceHandle,
) -> Result<u32, Error> {
    NAMESPACES.lock().insert(
        instance,
        owner,
        Data::Net {
            loopback: Loopback {
                up: false,
                mtu: 65_536,
            },
            sysctls: [None; NET_SYSCTL_LIMIT],
        },
    )
}

/// Network namespace `id`'s loopback interface.
pub(crate) fn loopback(instance: usize, id: u32) -> Option<Loopback> {
    match NAMESPACES.lock().find(instance, id)?.data {
        Data::Net { loopback, .. } => Some(loopback),
        _ => None,
    }
}

/// Changes network namespace `id`'s loopback interface.
pub(crate) fn set_loopback(instance: usize, id: u32, change: impl FnOnce(&mut Loopback)) -> bool {
    match NAMESPACES.lock().find_mut(instance, id) {
        Some(Namespace {
            data: Data::Net { loopback, .. },
            ..
        }) => {
            change(loopback);
            true
        }
        _ => false,
    }
}

/// The /proc/sys/net value number `index` written in network namespace
/// `id`, if one was.
pub(crate) fn net_sysctl(instance: usize, id: u32, index: usize) -> Option<i64> {
    match NAMESPACES.lock().find(instance, id)?.data {
        Data::Net { sysctls, .. } => *sysctls.get(index)?,
        _ => None,
    }
}

/// Writes the /proc/sys/net value number `index` of network namespace `id`.
pub(crate) fn set_net_sysctl(instance: usize, id: u32, index: usize, value: i64) -> bool {
    match NAMESPACES.lock().find_mut(instance, id) {
        Some(Namespace {
            data: Data::Net { sysctls, .. },
            ..
        }) => sysctls
            .get_mut(index)
            .map(|slot| *slot = Some(value))
            .is_some(),
        _ => false,
    }
}

/// Whether namespace `id` of `kind` exists in the domain (the initial one
/// always does).
pub(crate) fn exists(instance: usize, kind: Kind, id: u32) -> bool {
    id == 0
        || NAMESPACES
            .lock()
            .find(instance, id)
            .is_some_and(|namespace| namespace.kind() == kind)
}

/// The user namespace owning namespace `id` (`None` for an initial one,
/// which the domain's initial user namespace owns).
pub(crate) fn owner(instance: usize, id: u32) -> Option<linux_user::UserNamespaceHandle> {
    (id != 0)
        .then(|| {
            NAMESPACES
                .lock()
                .find(instance, id)
                .map(|namespace| namespace.owner)
        })
        .flatten()
}

/// Drops the domain's namespaces that nothing uses any more: no process in
/// `sets` is in one or would have children born into it, no process born
/// into a PID namespace is left unreaped, and no PID namespace below it
/// remains. A gone IPC namespace's System V instance is handed to
/// `release_ipc`; one it cannot release yet (a segment is still attached)
/// is offered again on a later pass.
pub(crate) fn collect(instance: usize, sets: &[Set], release_ipc: impl Fn(usize) -> bool) {
    let mut released = Vec::new();
    {
        let mut table = NAMESPACES.lock();
        loop {
            let unused = table.namespaces.iter().position(|namespace| {
                let kind = namespace.kind();
                let id = namespace.id;
                namespace.instance == instance
                    && !sets.iter().any(|set| set.uses(kind, id))
                    && !(kind == Kind::Pid
                        && (table.pids.iter().any(|entry| {
                            entry.instance == instance && !entry.reaped && entry.chain.contains(&id)
                        }) || table.namespaces.iter().any(|other| {
                            other.instance == instance
                                && matches!(other.data, Data::Pid { parent, .. } if parent == id)
                        })))
            });
            let Some(index) = unused else { break };
            let namespace = table.namespaces.swap_remove(index);
            if let Some(slot) = count_slot(namespace.kind()) {
                LIVE_COUNTS[slot].fetch_sub(1, Ordering::AcqRel);
            }
            if let Data::Ipc { instance } = namespace.data {
                if table.draining_ipc.try_reserve(1).is_ok() {
                    table.draining_ipc.push(instance);
                }
            }
        }
        if released.try_reserve(table.draining_ipc.len()).is_ok() {
            released.extend_from_slice(&table.draining_ipc);
        }
    }
    let gone: Vec<usize> = released
        .into_iter()
        .filter(|ipc_instance| release_ipc(*ipc_instance))
        .collect();
    if !gone.is_empty() {
        NAMESPACES
            .lock()
            .draining_ipc
            .retain(|ipc_instance| !gone.contains(ipc_instance));
    }
}

/// Drops `instance`'s namespaces when its domain stops; its processes are
/// gone, so `collect` with no sets takes every one.
pub(crate) fn forget_instance(instance: usize, release_ipc: impl Fn(usize) -> bool) {
    NAMESPACES
        .lock()
        .pids
        .retain(|entry| entry.instance != instance);
    collect(instance, &[], release_ipc);
}
