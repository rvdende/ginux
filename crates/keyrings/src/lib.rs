#![forbid(unsafe_code)]
//! The kernel's key retention service as Linux defines it for add_key(2),
//! request_key(2) and keyctl(2): keys with a type, description, payload,
//! owner and permission mask; keyrings that link them; the thread, process,
//! session, user and user-session keyrings a caller reaches through the
//! special key ids; possession; and the per-user quotas.
//!
//! One [`Keyrings`] holds every key of a domain. The kernel copies the
//! arguments in from user memory, describes the calling thread with a
//! [`Caller`], passes its clock where expiry matters, maps an [`Error`] to
//! its errno and copies an [`Output`] back by that output's rule. It also
//! reports fork, thread creation, exec and exit, because the special
//! keyrings belong to threads, processes and users.
//!
//! Every keyring link and every anchor (a thread's thread and session
//! keyring, a process's process keyring, a user's user and user-session
//! keyring) holds a reference to a key, and a key is dropped as soon as
//! nothing refers to it, with the links it held. Revoked and expired keys
//! therefore stay until they are unlinked; there is no delayed collector.
//!
//! Only the "user", "logon" and "keyring" types exist. There are no
//! upcalls: when request_key(2) is given callout data and finds nothing, it
//! leaves a negatively instantiated key behind and fails with ENOKEY, as
//! Linux does when /sbin/request-key cannot instantiate the key. Without
//! upcalls there are no authorization keys, so KEYCTL_INSTANTIATE,
//! KEYCTL_INSTANTIATE_IOV, KEYCTL_NEGATE and KEYCTL_REJECT are EPERM for
//! the kernel to return, and KEYCTL_ASSUME_AUTHORITY has nothing to assume.
//! Persistent keyrings, security labels (KEYCTL_GET_SECURITY reports an
//! empty one), Diffie-Hellman and public-key operations and notifications
//! are not modelled; their keyctl operations are EOPNOTSUPP.
//!
//! This is pure bookkeeping, so it can be tested on the host.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod keys;
mod proc;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use keys::{
    copy, Anchor, Key, Lookup, Match, Need, NewKey, Process, Quota, Search, Searched, State,
    Thread, User, LINK_BYTES,
};
use permission::{LINK, READ, SEARCH, SET_ATTRIBUTE, VIEW, WRITE};
use proc::Text;

/// The caller's thread keyring (`KEY_SPEC_THREAD_KEYRING`).
pub const THREAD_KEYRING: i32 = -1;
/// The caller's process keyring (`KEY_SPEC_PROCESS_KEYRING`).
pub const PROCESS_KEYRING: i32 = -2;
/// The caller's session keyring (`KEY_SPEC_SESSION_KEYRING`).
pub const SESSION_KEYRING: i32 = -3;
/// The keyring of the caller's real user id (`KEY_SPEC_USER_KEYRING`).
pub const USER_KEYRING: i32 = -4;
/// The session keyring of the caller's real user id
/// (`KEY_SPEC_USER_SESSION_KEYRING`).
pub const USER_SESSION_KEYRING: i32 = -5;
/// Group keyrings were never implemented by Linux; naming one is EINVAL.
pub const GROUP_KEYRING: i32 = -6;
/// The authorization key of a request_key(2) upcall, which never exists
/// here (`KEY_SPEC_REQKEY_AUTH_KEY`).
pub const REQUEST_KEY_AUTH_KEY: i32 = -7;
/// The destination keyring of a request_key(2) upcall, which never exists
/// here (`KEY_SPEC_REQUESTOR_KEYRING`).
pub const REQUESTOR_KEYRING: i32 = -8;

/// KEYCTL_MOVE's flag that refuses to displace a key of the same type and
/// description from the destination (`KEYCTL_MOVE_EXCL`).
pub const MOVE_EXCLUSIVE: u32 = 1;

/// The longest key type name, counting the terminating NUL; the kernel
/// copies at most this much.
pub const TYPE_LIMIT: usize = 32;
/// The longest description, keyring name or restriction, counting the
/// terminating NUL (`KEY_MAX_DESC_SIZE`).
pub const DESCRIPTION_LIMIT: usize = 4096;
/// The longest request_key(2) callout string, counting the terminating
/// NUL: one page.
pub const CALLOUT_LIMIT: usize = 4096;
/// The largest payload add_key(2) accepts before it looks at the type.
pub const PAYLOAD_LIMIT: usize = 1024 * 1024 - 1;
/// The largest payload KEYCTL_UPDATE accepts: one page.
pub const UPDATE_LIMIT: usize = 4096;
/// The largest payload of a "user" or "logon" key.
pub const USER_PAYLOAD_LIMIT: usize = 32_767;
/// How long the negative key request_key(2) leaves behind lasts.
pub const NEGATIVE_TIMEOUT_SECONDS: u64 = 60;

/// The id describe and /proc show for a key without a group, as Linux
/// shows its overflow group.
const OVERFLOW_ID: u32 = 65_534;
const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Where request_key(2) links a key it creates when the call names no
/// keyring (`KEY_REQKEY_DEFL_*`), as KEYCTL_SET_REQKEY_KEYRING sets it.
pub mod request_default {
    /// Only report the current setting.
    pub const NO_CHANGE: i32 = -1;
    /// The thread keyring if there is one, else the process keyring, else
    /// the session keyring, else the user-session keyring.
    pub const DEFAULT: i32 = 0;
    /// As DEFAULT, but the thread keyring is created when this is set.
    pub const THREAD: i32 = 1;
    /// From the process keyring on, which is created when this is set.
    pub const PROCESS: i32 = 2;
    /// From the session keyring on.
    pub const SESSION: i32 = 3;
    pub const USER: i32 = 4;
    pub const USER_SESSION: i32 = 5;
    /// Not supported by Linux either: EINVAL.
    pub const GROUP: i32 = 6;
    /// The upcall's requestor keyring, which never exists here, so this
    /// behaves as DEFAULT.
    pub const REQUESTOR: i32 = 7;
}

/// KEYCTL_CAPABILITIES bits (`KEYCTL_CAPS0_*`).
pub mod capability {
    pub const CAPABILITIES: u8 = 0x01;
    pub const PERSISTENT_KEYRINGS: u8 = 0x02;
    pub const DIFFIE_HELLMAN: u8 = 0x04;
    pub const PUBLIC_KEY: u8 = 0x08;
    pub const BIG_KEY: u8 = 0x10;
    pub const INVALIDATE: u8 = 0x20;
    pub const RESTRICT_KEYRING: u8 = 0x40;
    pub const MOVE: u8 = 0x80;
}

/// A key's permission mask: four bytes granting rights to the possessor,
/// the owning user, the group and everyone else, from the most significant
/// byte down. Each byte holds the rights below.
pub mod permission {
    /// Read the type, description and permissions.
    pub const VIEW: u32 = 0x01;
    /// Read a key's payload or a keyring's list of links.
    pub const READ: u32 = 0x02;
    /// Update or revoke a key; add links to or remove them from a keyring.
    pub const WRITE: u32 = 0x04;
    /// Find a key by a search; search a keyring's links.
    pub const SEARCH: u32 = 0x08;
    /// Link a key into a keyring.
    pub const LINK: u32 = 0x10;
    /// Change the owner, permissions or timeout, or revoke.
    pub const SET_ATTRIBUTE: u32 = 0x20;
    pub const ALL: u32 = 0x3f;
    /// Every bit a mask may have.
    pub const VALID: u32 = 0x3f3f_3f3f;

    pub const fn possessor(rights: u32) -> u32 {
        rights << 24
    }

    pub const fn user(rights: u32) -> u32 {
        rights << 16
    }

    pub const fn group(rights: u32) -> u32 {
        rights << 8
    }

    pub const fn other(rights: u32) -> u32 {
        rights
    }
}

use permission::{possessor, user, ALL};

/// The thread and process keyrings: everything for the possessor, view for
/// the owner.
const PRIVATE_KEYRING_PERMISSIONS: u32 = possessor(ALL) | user(VIEW);
/// An anonymous session keyring additionally lets its owner read it.
const ANONYMOUS_SESSION_PERMISSIONS: u32 = possessor(ALL) | user(VIEW | READ);
/// A named session keyring additionally lets its owner link it into other
/// keyrings.
const NAMED_SESSION_PERMISSIONS: u32 = possessor(ALL) | user(VIEW | READ | LINK);
/// The user and user-session keyrings: everything for the owner, and
/// everything but changing attributes for the possessor.
const USER_KEYRING_PERMISSIONS: u32 = possessor(ALL & !SET_ATTRIBUTE) | user(ALL);

/// Why an operation failed. Each variant stands for the errno Linux
/// returns, which [`Error::errno`] gives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// ENOKEY: no such key or special keyring, a key that was invalidated,
    /// a negatively instantiated key, or nothing matched a search.
    NoKey,
    /// EKEYREVOKED
    KeyRevoked,
    /// EKEYEXPIRED
    KeyExpired,
    /// EACCES: the permission mask does not grant what the operation needs.
    AccessDenied,
    /// EPERM: a type or keyring name reserved to the kernel, or a keyring
    /// restricted against new links.
    NotPermitted,
    /// EINVAL
    Invalid,
    /// ENODEV: add_key(2) named a key type that does not exist.
    NoDevice,
    /// EOPNOTSUPP: the key's type cannot do this (read a "logon" key,
    /// update a keyring).
    NotSupported,
    /// EDQUOT: the owner's key count or byte quota would be exceeded.
    QuotaExceeded,
    /// ENOMEM
    NoMemory,
    /// EEXIST: KEYCTL_MOVE_EXCL found a matching key in the destination,
    /// or the keyring is already restricted.
    Exists,
    /// ENOTDIR: a keyring was expected.
    NotDirectory,
    /// ENOENT: the key is not linked from that keyring, or the key type has
    /// no restriction schemes.
    NotFound,
    /// EDEADLK: the link would make a keyring contain itself.
    Deadlock,
    /// ELOOP: the linked keyring nests too deep to check for a cycle.
    TooDeep,
}

impl Error {
    /// The Linux errno this error stands for.
    pub const fn errno(self) -> i32 {
        match self {
            Self::NoKey => 126,
            Self::KeyRevoked => 128,
            Self::KeyExpired => 127,
            Self::AccessDenied => 13,
            Self::NotPermitted => 1,
            Self::Invalid => 22,
            Self::NoDevice => 19,
            Self::NotSupported => 95,
            Self::QuotaExceeded => 122,
            Self::NoMemory => 12,
            Self::Exists => 17,
            Self::NotDirectory => 20,
            Self::NotFound => 2,
            Self::Deadlock => 35,
            Self::TooDeep => 40,
        }
    }
}

fn no_memory<T>(_: T) -> Error {
    Error::NoMemory
}

/// The thread making a call, as the key service sees it.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    /// The filesystem user id: it owns the keys the thread creates and
    /// selects the user rights of a mask.
    pub uid: u32,
    /// The filesystem group id: it is the group of new keys.
    pub gid: u32,
    /// The supplementary groups, sorted as setgroups(2) leaves them.
    pub groups: &'a [u32],
    /// The real user id: it selects the user and user-session keyrings and
    /// owns the thread, process and session keyrings the thread gets.
    pub real_uid: u32,
    pub real_gid: u32,
    /// The thread group id, which names the process keyring.
    pub pid: u32,
    /// The thread id, which names the thread and session keyrings.
    pub tid: u32,
    /// The thread holds CAP_SYS_ADMIN: it may give a key to another user or
    /// group and set the permissions of keys it does not own.
    pub privileged: bool,
}

impl Caller<'_> {
    fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.binary_search(&gid).is_ok()
    }
}

/// The quotas of /proc/sys/kernel/keys: how many keys a user may own and
/// how many bytes of descriptions, payloads and keyring links they may
/// take. Root (uid 0) has limits of its own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub root_max_keys: u32,
    pub root_max_bytes: u32,
    pub max_keys: u32,
    pub max_bytes: u32,
}

impl Limits {
    /// Linux's defaults.
    pub const LINUX: Self = Self {
        root_max_keys: 1_000_000,
        root_max_bytes: 25_000_000,
        max_keys: 200,
        max_bytes: 20_000,
    };

    /// The key and byte limits of `uid`.
    pub const fn of(&self, uid: u32) -> (u32, u32) {
        if uid == 0 {
            (self.root_max_keys, self.root_max_bytes)
        } else {
            (self.max_keys, self.max_bytes)
        }
    }

    /// Whether Linux's sysctls would accept every value: 1 to `i32::MAX`.
    fn valid(&self) -> bool {
        [
            self.root_max_keys,
            self.root_max_bytes,
            self.max_keys,
            self.max_bytes,
        ]
        .iter()
        .all(|&limit| (1..=i32::MAX as u32).contains(&limit))
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::LINUX
    }
}

/// The key types that exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    /// A blob of 1 to 32767 bytes that user space may read and update.
    User,
    /// A "user" key that user space may not read; its description must
    /// start with a "service:" prefix.
    Logon,
    /// A set of links to other keys.
    Keyring,
}

impl KeyType {
    pub fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"user" => Some(Self::User),
            b"logon" => Some(Self::Logon),
            b"keyring" => Some(Self::Keyring),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Logon => "logon",
            Self::Keyring => "keyring",
        }
    }

    const fn readable(self) -> bool {
        !matches!(self, Self::Logon)
    }

    /// A keyring has no update: add_key(2) replaces a keyring of the same
    /// name with a new one instead.
    const fn updatable(self) -> bool {
        !matches!(self, Self::Keyring)
    }

    fn check_payload(self, payload: &[u8]) -> Result<(), Error> {
        let valid = match self {
            Self::User | Self::Logon => (1..=USER_PAYLOAD_LIMIT).contains(&payload.len()),
            Self::Keyring => payload.is_empty(),
        };
        valid.then_some(()).ok_or(Error::Invalid)
    }

    /// A "logon" description needs a ':' with something before it.
    fn check_description(self, description: &[u8]) -> Result<(), Error> {
        match self {
            Self::Logon
                if !matches!(description.iter().position(|&byte| byte == b':'), Some(1..)) =>
            {
                Err(Error::Invalid)
            }
            _ => Ok(()),
        }
    }

    /// What a key gets when add_key(2) or request_key(2) creates it:
    /// everything the type supports for the possessor, view for the owner.
    const fn default_permissions(self) -> u32 {
        let rights = match self {
            Self::User | Self::Keyring => ALL,
            Self::Logon => ALL & !READ,
        };
        possessor(rights) | user(VIEW)
    }
}

/// Checks a key type name as Linux does while copying it in: empty or too
/// long is EINVAL, and a name starting with '.' is reserved (EPERM). The
/// kernel may call this right after copying the type so that EPERM comes
/// before a fault in a later argument, as in Linux.
pub fn check_type_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name.len() >= TYPE_LIMIT {
        Err(Error::Invalid)
    } else if name.first() == Some(&b'.') {
        Err(Error::NotPermitted)
    } else {
        Ok(())
    }
}

/// A string that does not fit in `limit` bytes with its NUL is EINVAL.
fn check_length(string: &[u8], limit: usize) -> Result<(), Error> {
    if string.len() < limit {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

/// Bytes an operation returns for user memory. The system call returns
/// [`Output::len`] whatever the size of the caller's buffer; how much of
/// the output a smaller buffer receives depends on the operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    bytes: Vec<u8>,
    /// A buffer too small for the whole output receives the start of it
    /// (KEYCTL_GET_SECURITY, KEYCTL_CAPABILITIES) instead of nothing
    /// (KEYCTL_DESCRIBE, KEYCTL_READ).
    truncates: bool,
}

impl Output {
    fn whole(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            truncates: false,
        }
    }

    fn truncating(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            bytes: copy(bytes)?,
            truncates: true,
        })
    }

    /// The full length, which the system call returns.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// What to copy into a buffer of `capacity` bytes: everything if it
    /// fits, else a prefix or nothing as the operation does. The kernel
    /// copies nothing when the buffer pointer is null.
    pub fn for_buffer(&self, capacity: usize) -> &[u8] {
        if self.bytes.len() <= capacity {
            &self.bytes
        } else if self.truncates {
            self.bytes.get(..capacity).unwrap_or_default()
        } else {
            &[]
        }
    }
}

/// Every key, keyring and anchor of one domain. Operations that take `now`
/// read the kernel's clock in nanoseconds: any clock that does not go
/// backwards, as long as every call uses the same one.
#[derive(Debug)]
pub struct Keyrings {
    /// Sorted by serial number.
    keys: Vec<Key>,
    /// Quota records and per-user keyrings, sorted by uid.
    users: Vec<User>,
    /// Threads with a thread or session keyring or a request-key default,
    /// sorted by thread id.
    threads: Vec<Thread>,
    /// Processes with a process keyring, sorted by process id.
    processes: Vec<Process>,
    next_serial: i32,
    limits: Limits,
}

impl Default for Keyrings {
    fn default() -> Self {
        Self::new()
    }
}

impl Keyrings {
    pub const fn new() -> Self {
        Self {
            keys: Vec::new(),
            users: Vec::new(),
            threads: Vec::new(),
            processes: Vec::new(),
            next_serial: 1,
            limits: Limits::LINUX,
        }
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Sets the quotas, as writes to /proc/sys/kernel/keys do. Keys over a
    /// lowered limit stay; only new charges are refused.
    pub fn set_limits(&mut self, limits: Limits) -> Result<(), Error> {
        if !limits.valid() {
            return Err(Error::Invalid);
        }
        self.limits = limits;
        Ok(())
    }

    /// add_key(2): creates a key of `key_type` and links it into `keyring`,
    /// or, if the keyring already links a "user" or "logon" key of that
    /// type and description that is not revoked, updates that key in place
    /// and returns its serial. A new key displaces a key of the same type
    /// and description from the keyring, which is how a keyring is
    /// replaced.
    pub fn add_key(
        &mut self,
        caller: &Caller,
        key_type: &[u8],
        description: &[u8],
        payload: &[u8],
        keyring: i32,
        now: u64,
    ) -> Result<i32, Error> {
        if payload.len() > PAYLOAD_LIMIT {
            return Err(Error::Invalid);
        }
        check_type_name(key_type)?;
        check_length(description, DESCRIPTION_LIMIT)?;
        if key_type == b"keyring" && description.first() == Some(&b'.') {
            return Err(Error::NotPermitted);
        }
        let target = self.lookup(caller, keyring, Lookup::CREATE, Need::Rights(WRITE), now)?;
        let kind = KeyType::from_name(key_type).ok_or(Error::NoDevice)?;
        let ring = self.get(target.serial)?;
        if !ring.is_keyring() {
            return Err(Error::NotDirectory);
        }
        kind.check_payload(payload)?;
        if description.is_empty() {
            return Err(Error::Invalid);
        }
        let existing = self.find_link(ring, kind, description);
        if existing.is_none() && !self.fits(ring.uid, 0, LINK_BYTES) {
            return Err(Error::QuotaExceeded);
        }
        if ring.restricted {
            return Err(Error::NotPermitted);
        }
        if let Some(serial) = existing.filter(|_| kind.updatable()) {
            let key = self.get(serial)?;
            if !matches!(key.state, State::Revoked | State::Invalidated) {
                if !key.permits(caller, target.possessed, WRITE) {
                    return Err(Error::AccessDenied);
                }
                self.replace_payload(serial, payload)?;
                return Ok(serial);
            }
        }
        kind.check_description(description)?;
        let key = Key::new(NewKey {
            kind,
            description,
            payload,
            uid: caller.uid,
            gid: Some(caller.gid),
            permissions: kind.default_permissions(),
            state: State::Positive,
            expiry: None,
            per_user: false,
        })?;
        self.add_new(target.serial, existing, key)
    }

    /// request_key(2): searches the caller's thread, process and session
    /// keyrings (or the user-session keyring when it has no session) for a
    /// valid key of that type and description, links what it finds into
    /// `destination` unless that is 0, and returns its serial. A matching
    /// key that is revoked, expired, negative or not searchable gives its
    /// error if nothing valid is found. With `callout` and nothing found,
    /// a negative key that expires after [`NEGATIVE_TIMEOUT_SECONDS`] is
    /// linked into `destination`, or the request-key default keyring, and
    /// the call fails with ENOKEY; the callout data itself is ignored.
    pub fn request_key(
        &mut self,
        caller: &Caller,
        key_type: &[u8],
        description: &[u8],
        callout: Option<&[u8]>,
        destination: i32,
        now: u64,
    ) -> Result<i32, Error> {
        check_type_name(key_type)?;
        check_length(description, DESCRIPTION_LIMIT)?;
        if let Some(callout) = callout {
            check_length(callout, CALLOUT_LIMIT)?;
        }
        let destination = match destination {
            0 => None,
            id => Some(self.lookup(caller, id, Lookup::CREATE, Need::Rights(WRITE), now)?),
        };
        let kind = KeyType::from_name(key_type).ok_or(Error::NoKey)?;
        match self.search_caller(caller, Match::Index(kind, description), now) {
            Searched::Found(serial) => {
                if let Some(destination) = destination {
                    // Keys found from the caller's own keyrings are possessed.
                    if !self.get(serial)?.permits(caller, true, LINK) {
                        return Err(Error::AccessDenied);
                    }
                    self.link_checked(destination.serial, serial)?;
                }
                Ok(serial)
            }
            Searched::Skipped(error) => Err(error),
            Searched::Nothing if callout.is_none() => Err(Error::NoKey),
            Searched::Nothing => {
                let ring = match destination {
                    Some(destination) => destination.serial,
                    None => {
                        let ring = self.request_destination(caller)?;
                        if !self.get(ring)?.permits(caller, true, WRITE) {
                            return Err(Error::AccessDenied);
                        }
                        ring
                    }
                };
                self.add_negative(caller, kind, description, ring, now)?;
                Err(Error::NoKey)
            }
        }
    }

    /// KEYCTL_GET_KEYRING_ID: the serial of `id`, which may be a special
    /// id; `create` makes a missing thread, process or session keyring.
    /// The user keyrings are made whether or not `create` is set.
    pub fn get_keyring_id(
        &mut self,
        caller: &Caller,
        id: i32,
        create: bool,
        now: u64,
    ) -> Result<i32, Error> {
        let flags = if create {
            Lookup::CREATE
        } else {
            Lookup::PLAIN
        };
        Ok(self
            .lookup(caller, id, flags, Need::Rights(SEARCH), now)?
            .serial)
    }

    /// KEYCTL_JOIN_SESSION_KEYRING: with no name, gives the calling thread a
    /// new anonymous session keyring. With a name, joins the first keyring
    /// of that name, by serial, that grants the caller search permission
    /// without possession, creating one if there is none; joining the
    /// session keyring the thread already has returns 0, as Linux does.
    /// A named session keyring does not grant its owner search permission
    /// by default, so joining it again makes a new one until that is
    /// granted. Other threads keep their session keyrings.
    pub fn join_session_keyring(
        &mut self,
        caller: &Caller,
        name: Option<&[u8]>,
    ) -> Result<i32, Error> {
        let Some(name) = name else {
            return self.new_session(caller);
        };
        check_length(name, DESCRIPTION_LIMIT)?;
        if name.is_empty() {
            return Err(Error::Invalid);
        }
        if name.first() == Some(&b'.') {
            return Err(Error::NotPermitted);
        }
        let current = self.thread(caller.tid).and_then(|thread| thread.session);
        match self.find_named_keyring(caller, name) {
            Some(serial) if current == Some(serial) => Ok(0),
            Some(serial) => {
                self.ensure_thread(caller.tid)?;
                self.set_anchor(Anchor::Session(caller.tid), Some(serial));
                Ok(serial)
            }
            None => self.new_anchored_keyring(
                caller,
                Anchor::Session(caller.tid),
                name,
                NAMED_SESSION_PERMISSIONS,
                Quota::Checked,
            ),
        }
    }

    /// KEYCTL_UPDATE: replaces a "user" or "logon" key's payload, which
    /// clears its timeout.
    pub fn update(
        &mut self,
        caller: &Caller,
        id: i32,
        payload: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        if payload.len() > UPDATE_LIMIT {
            return Err(Error::Invalid);
        }
        let handle = self.lookup(caller, id, Lookup::PLAIN, Need::Rights(WRITE), now)?;
        let kind = self.get(handle.serial)?.kind;
        if !kind.updatable() {
            return Err(Error::NotSupported);
        }
        kind.check_payload(payload)?;
        self.replace_payload(handle.serial, payload)
    }

    /// KEYCTL_REVOKE: with write or set-attribute permission, makes every
    /// later use of the key fail with EKEYREVOKED and drops its payload; a
    /// revoked keyring loses its links. The key stays linked until it is
    /// unlinked or displaced.
    pub fn revoke(&mut self, caller: &Caller, id: i32, now: u64) -> Result<(), Error> {
        let handle = match self.lookup(caller, id, Lookup::PLAIN, Need::Rights(WRITE), now) {
            Err(Error::AccessDenied) => {
                self.lookup(caller, id, Lookup::PLAIN, Need::Rights(SET_ATTRIBUTE), now)?
            }
            result => result?,
        };
        self.get_mut(handle.serial)?.state = State::Revoked;
        self.discard_contents(handle.serial);
        Ok(())
    }

    /// KEYCTL_CHOWN: gives the key to `uid` and/or `gid` (`None` leaves one
    /// unchanged). Changing the owner needs privilege and moves the key's
    /// quota charge to the new owner; changing the group needs privilege
    /// unless the caller belongs to the new group.
    pub fn chown(
        &mut self,
        caller: &Caller,
        id: i32,
        uid: Option<u32>,
        gid: Option<u32>,
        now: u64,
    ) -> Result<(), Error> {
        if uid.is_none() && gid.is_none() {
            return Ok(());
        }
        let handle = self.lookup(
            caller,
            id,
            Lookup::CREATE_PARTIAL,
            Need::Rights(SET_ATTRIBUTE),
            now,
        )?;
        let key = self.get(handle.serial)?;
        let (old_uid, charged) = (key.uid, key.charged);
        let new_uid = uid.filter(|&uid| uid != old_uid);
        let new_gid = gid.filter(|&gid| Some(gid) != key.gid);
        if !caller.privileged
            && (new_uid.is_some() || new_gid.is_some_and(|gid| !caller.in_group(gid)))
        {
            return Err(Error::AccessDenied);
        }
        if let Some(new_uid) = new_uid {
            if !self.fits(new_uid, 1, charged) {
                return Err(Error::QuotaExceeded);
            }
            self.ensure_user(new_uid)?;
            self.charge(new_uid, charged);
            self.uncharge(old_uid, charged);
            self.get_mut(handle.serial)?.uid = new_uid;
        }
        if gid.is_some() {
            self.get_mut(handle.serial)?.gid = gid;
        }
        Ok(())
    }

    /// KEYCTL_SETPERM: sets the permission mask of a key the caller owns,
    /// or of any key if it is privileged.
    pub fn set_permissions(
        &mut self,
        caller: &Caller,
        id: i32,
        permissions: u32,
        now: u64,
    ) -> Result<(), Error> {
        if permissions & !permission::VALID != 0 {
            return Err(Error::Invalid);
        }
        let handle = self.lookup(
            caller,
            id,
            Lookup::CREATE_PARTIAL,
            Need::Rights(SET_ATTRIBUTE),
            now,
        )?;
        let key = self.get_mut(handle.serial)?;
        if !caller.privileged && key.uid != caller.uid {
            return Err(Error::AccessDenied);
        }
        key.permissions = permissions;
        Ok(())
    }

    /// KEYCTL_DESCRIBE: "type;uid;gid;perm;description" with the mask as
    /// eight hex digits and a terminating NUL. A buffer too small for all
    /// of it receives nothing.
    pub fn describe(&mut self, caller: &Caller, id: i32, now: u64) -> Result<Output, Error> {
        let handle = self.lookup(caller, id, Lookup::PARTIAL, Need::Rights(VIEW), now)?;
        let key = self.get(handle.serial)?;
        let mut text = Text::new();
        text.format(format_args!(
            "{};{};{};{:08x};",
            key.kind.name(),
            key.uid,
            key.gid.unwrap_or(OVERFLOW_ID),
            key.permissions
        ))?;
        text.push(&key.description)?;
        text.push(&[0])?;
        Ok(Output::whole(text.into_bytes()))
    }

    /// KEYCTL_CLEAR: removes every link from a keyring.
    pub fn clear(&mut self, caller: &Caller, keyring: i32, now: u64) -> Result<(), Error> {
        let handle = self.lookup(caller, keyring, Lookup::CREATE, Need::Rights(WRITE), now)?;
        if !self.get(handle.serial)?.is_keyring() {
            return Err(Error::NotDirectory);
        }
        self.discard_contents(handle.serial);
        Ok(())
    }

    /// KEYCTL_LINK: links `key` into `keyring`, displacing a key of the same
    /// type and description.
    pub fn link(&mut self, caller: &Caller, key: i32, keyring: i32, now: u64) -> Result<(), Error> {
        let ring = self.lookup(caller, keyring, Lookup::CREATE, Need::Rights(WRITE), now)?;
        let key = self.lookup(caller, key, Lookup::CREATE, Need::Rights(LINK), now)?;
        self.link_checked(ring.serial, key.serial)
    }

    /// KEYCTL_UNLINK: removes the link to `key` from `keyring`. The key
    /// itself needs no permission and may be revoked or expired.
    pub fn unlink(
        &mut self,
        caller: &Caller,
        key: i32,
        keyring: i32,
        now: u64,
    ) -> Result<(), Error> {
        let ring = self.lookup(caller, keyring, Lookup::PLAIN, Need::Rights(WRITE), now)?;
        let key = self.lookup(caller, key, Lookup::PARTIAL, Need::Unlink, now)?;
        if !self.get(ring.serial)?.is_keyring() {
            return Err(Error::NotDirectory);
        }
        if self.detach(ring.serial, key.serial) {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// KEYCTL_SEARCH: searches the tree under `keyring` (the keyring itself,
    /// then its links, then the keyrings it links, through those the caller
    /// may search) for a valid key of that type and description, links it
    /// into `destination` unless that is 0, and returns its serial.
    pub fn search(
        &mut self,
        caller: &Caller,
        keyring: i32,
        key_type: &[u8],
        description: &[u8],
        destination: i32,
        now: u64,
    ) -> Result<i32, Error> {
        check_type_name(key_type)?;
        check_length(description, DESCRIPTION_LIMIT)?;
        let start = self.lookup(caller, keyring, Lookup::PLAIN, Need::Rights(SEARCH), now)?;
        let destination = match destination {
            0 => None,
            id => Some(self.lookup(caller, id, Lookup::CREATE, Need::Rights(WRITE), now)?),
        };
        let kind = KeyType::from_name(key_type).ok_or(Error::NoKey)?;
        if !self.get(start.serial)?.is_keyring() {
            return Err(Error::NotDirectory);
        }
        let search = Search {
            caller,
            matcher: Match::Index(kind, description),
            possessed: start.possessed,
            check_state: true,
            now,
        };
        let found = match self.search_tree(&search, start.serial) {
            Searched::Found(serial) => serial,
            Searched::Skipped(error) => return Err(error),
            Searched::Nothing => return Err(Error::NoKey),
        };
        if let Some(destination) = destination {
            // What a search finds is possessed if the keyring it started in is.
            if !self.get(found)?.permits(caller, start.possessed, LINK) {
                return Err(Error::AccessDenied);
            }
            self.link_checked(destination.serial, found)?;
        }
        Ok(found)
    }

    /// KEYCTL_READ: a "user" key's payload, or a keyring's links as
    /// native-endian 32-bit serial numbers. A key the caller possesses may
    /// be read without read permission. A buffer too small for all of it
    /// receives nothing.
    pub fn read(&mut self, caller: &Caller, id: i32, now: u64) -> Result<Output, Error> {
        let handle = self.lookup(caller, id, Lookup::PLAIN, Need::Deferred, now)?;
        let key = self.get(handle.serial)?;
        key.instantiated()?;
        if !handle.possessed && !key.permits(caller, false, READ) {
            return Err(Error::AccessDenied);
        }
        if !key.kind.readable() {
            return Err(Error::NotSupported);
        }
        key.validate(now)?;
        let bytes = if key.is_keyring() {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(key.links.len() * 4)
                .map_err(no_memory)?;
            for serial in &key.links {
                bytes.extend_from_slice(&serial.to_ne_bytes());
            }
            bytes
        } else {
            copy(&key.payload)?
        };
        Ok(Output::whole(bytes))
    }

    /// KEYCTL_SET_REQKEY_KEYRING: sets the calling thread's request-key
    /// default (a [`request_default`] value) and returns the previous one;
    /// [`request_default::NO_CHANGE`] only returns it. Choosing the thread
    /// or process keyring creates it if missing, never replaces it.
    pub fn set_request_default(&mut self, caller: &Caller, value: i32) -> Result<i32, Error> {
        let old = self
            .thread(caller.tid)
            .map_or(request_default::DEFAULT, |thread| thread.request_default);
        match value {
            request_default::NO_CHANGE => return Ok(old),
            request_default::THREAD => {
                self.special(caller, THREAD_KEYRING, true)?;
            }
            request_default::PROCESS => {
                self.special(caller, PROCESS_KEYRING, true)?;
            }
            request_default::DEFAULT
            | request_default::SESSION
            | request_default::USER
            | request_default::USER_SESSION
            | request_default::REQUESTOR => {}
            _ => return Err(Error::Invalid),
        }
        self.ensure_thread(caller.tid)?;
        if let Some(thread) = self.thread_mut(caller.tid) {
            thread.request_default = value;
        }
        Ok(old)
    }

    /// KEYCTL_SET_TIMEOUT: the key expires `seconds` after `now`; 0 removes
    /// the timeout. An expired key fails with EKEYEXPIRED until it is
    /// unlinked, or updated in place by add_key(2).
    pub fn set_timeout(
        &mut self,
        caller: &Caller,
        id: i32,
        seconds: u32,
        now: u64,
    ) -> Result<(), Error> {
        let handle = self.lookup(
            caller,
            id,
            Lookup::CREATE_PARTIAL,
            Need::Rights(SET_ATTRIBUTE),
            now,
        )?;
        self.get_mut(handle.serial)?.expiry =
            (seconds != 0).then(|| now.saturating_add(u64::from(seconds) * NANOSECONDS_PER_SECOND));
        Ok(())
    }

    /// KEYCTL_GET_SECURITY: the key's security label, which is always empty
    /// (a lone NUL). A buffer too small receives what fits. Without view
    /// permission this is ENOKEY: Linux then looks for an authorization key
    /// for the key, and there are none.
    pub fn get_security(&mut self, caller: &Caller, id: i32, now: u64) -> Result<Output, Error> {
        match self.lookup(caller, id, Lookup::PARTIAL, Need::Rights(VIEW), now) {
            Ok(_) => Output::truncating(&[0]),
            Err(Error::AccessDenied) => Err(Error::NoKey),
            Err(error) => Err(error),
        }
    }

    /// KEYCTL_SESSION_TO_PARENT: gives the thread `parent_tid` the caller's
    /// session keyring, which the caller must be allowed to link. The
    /// kernel first checks what Linux requires of the parent: the same
    /// user and group ids as the caller and a single thread (EPERM).
    pub fn session_to_parent(
        &mut self,
        caller: &Caller,
        parent_tid: u32,
        now: u64,
    ) -> Result<(), Error> {
        let session = self.lookup(
            caller,
            SESSION_KEYRING,
            Lookup::PLAIN,
            Need::Rights(LINK),
            now,
        )?;
        self.ensure_thread(parent_tid)?;
        self.set_anchor(Anchor::Session(parent_tid), Some(session.serial));
        Ok(())
    }

    /// KEYCTL_INVALIDATE: removes the key from every keyring at once; later
    /// lookups fail with ENOKEY. A key that is some thread's, process's or
    /// user's special keyring stays until that anchor lets it go.
    pub fn invalidate(&mut self, caller: &Caller, id: i32, now: u64) -> Result<(), Error> {
        let handle = self.lookup(caller, id, Lookup::PLAIN, Need::Rights(SEARCH), now)?;
        self.get_mut(handle.serial)?.state = State::Invalidated;
        self.discard_contents(handle.serial);
        self.unlink_everywhere(handle.serial);
        Ok(())
    }

    /// KEYCTL_RESTRICT_KEYRING: with neither a type nor a restriction,
    /// refuses every later link into the keyring (EPERM). No key type here
    /// has restriction schemes: a known type is ENOENT, an unknown one
    /// ENOKEY. A keyring can be restricted once (EEXIST).
    pub fn restrict_keyring(
        &mut self,
        caller: &Caller,
        id: i32,
        key_type: Option<&[u8]>,
        restriction: Option<&[u8]>,
        now: u64,
    ) -> Result<(), Error> {
        let handle = self.lookup(caller, id, Lookup::PLAIN, Need::Rights(SET_ATTRIBUTE), now)?;
        let restricting = match (key_type, restriction) {
            (None, None) => None,
            (Some(key_type), Some(restriction)) => {
                check_type_name(key_type)?;
                check_length(restriction, DESCRIPTION_LIMIT)?;
                Some(key_type)
            }
            _ => return Err(Error::Invalid),
        };
        let key = self.get_mut(handle.serial)?;
        if !key.is_keyring() {
            return Err(Error::NotDirectory);
        }
        if let Some(key_type) = restricting {
            return Err(match KeyType::from_name(key_type) {
                Some(_) => Error::NotFound,
                None => Error::NoKey,
            });
        }
        if key.restricted {
            return Err(Error::Exists);
        }
        key.restricted = true;
        Ok(())
    }

    /// KEYCTL_MOVE: links `key` into `to` and removes its link from `from`
    /// in one step. With [`MOVE_EXCLUSIVE`] a key of the same type and
    /// description in `to` is EEXIST instead of being displaced. Moving
    /// within one keyring does nothing.
    pub fn move_key(
        &mut self,
        caller: &Caller,
        key: i32,
        from: i32,
        to: i32,
        flags: u32,
        now: u64,
    ) -> Result<(), Error> {
        if flags & !MOVE_EXCLUSIVE != 0 {
            return Err(Error::Invalid);
        }
        let key = self
            .lookup(caller, key, Lookup::CREATE, Need::Rights(LINK), now)?
            .serial;
        let from = self
            .lookup(caller, from, Lookup::PLAIN, Need::Rights(WRITE), now)?
            .serial;
        let to = self
            .lookup(caller, to, Lookup::CREATE, Need::Rights(WRITE), now)?
            .serial;
        if from == to {
            return Ok(());
        }
        let (source, destination, moved) = (self.get(from)?, self.get(to)?, self.get(key)?);
        if !source.is_keyring() || !destination.is_keyring() {
            return Err(Error::NotDirectory);
        }
        if !source.links.contains(&key) {
            return Err(Error::NotFound);
        }
        let existing = self.find_link(destination, moved.kind, &moved.description);
        if existing.is_none() && !self.fits(destination.uid, 0, LINK_BYTES) {
            return Err(Error::QuotaExceeded);
        }
        if flags & MOVE_EXCLUSIVE != 0 && existing.is_some() {
            return Err(Error::Exists);
        }
        if destination.restricted {
            return Err(Error::NotPermitted);
        }
        if moved.is_keyring() {
            self.check_cycle(to, moved, 0)?;
        }
        self.reserve_link(to, existing)?;
        self.attach(to, key);
        self.detach(from, key);
        Ok(())
    }

    /// KEYCTL_CAPABILITIES: what this service supports, as two bytes of
    /// [`capability`] bits. A buffer too small receives what fits.
    pub fn capabilities() -> Result<Output, Error> {
        use capability::{CAPABILITIES, INVALIDATE, MOVE, RESTRICT_KEYRING};
        Output::truncating(&[CAPABILITIES | INVALIDATE | RESTRICT_KEYRING | MOVE, 0])
    }

    /// A new process `child_tid` forked from `parent`: it shares the
    /// parent's session keyring and request-key default, and starts with no
    /// thread or process keyring.
    pub fn fork(&mut self, parent: &Caller, child_tid: u32) -> Result<(), Error> {
        // Forget what a missed exit left under a reused thread id.
        self.exit_thread(child_tid);
        let Some(record) = self.thread(parent.tid) else {
            return Ok(());
        };
        let (session, request_default) = (record.session, record.request_default);
        if session.is_none() && request_default == request_default::DEFAULT {
            return Ok(());
        }
        self.ensure_thread(child_tid)?;
        if let Some(child) = self.thread_mut(child_tid) {
            child.request_default = request_default;
        }
        self.set_anchor(Anchor::Session(child_tid), session);
        Ok(())
    }

    /// A new thread `child_tid` in `parent`'s process: as for fork, and it
    /// gets a new thread keyring of its own if `parent` has one (Linux does
    /// not fail the clone when that keyring cannot be made, and neither
    /// does this). The process keyring is already shared.
    pub fn spawn_thread(&mut self, parent: &Caller, child_tid: u32) -> Result<(), Error> {
        self.fork(parent, child_tid)?;
        if self
            .thread(parent.tid)
            .is_some_and(|thread| thread.keyring.is_some())
        {
            let _ = self.new_anchored_keyring(
                parent,
                Anchor::ThreadKeyring(child_tid),
                b"_tid",
                PRIVATE_KEYRING_PERMISSIONS,
                Quota::Overrun,
            );
        }
        Ok(())
    }

    /// execve(2) by thread `tid` of process `pid`: the new program starts
    /// without a thread or process keyring and keeps the session keyring.
    pub fn exec(&mut self, pid: u32, tid: u32) {
        self.set_anchor(Anchor::ThreadKeyring(tid), None);
        self.set_anchor(Anchor::ProcessKeyring(pid), None);
    }

    /// Thread `tid` exited: its thread keyring and its hold on the session
    /// keyring go.
    pub fn exit_thread(&mut self, tid: u32) {
        let Ok(index) = self.threads.binary_search_by_key(&tid, |thread| thread.tid) else {
            return;
        };
        let thread = self.threads.remove(index);
        for serial in [thread.keyring, thread.session].into_iter().flatten() {
            self.release(serial);
        }
    }

    /// The last thread of process `pid` exited: its process keyring goes.
    pub fn exit_process(&mut self, pid: u32) {
        let Ok(index) = self
            .processes
            .binary_search_by_key(&pid, |process| process.pid)
        else {
            return;
        };
        if let Some(serial) = self.processes.remove(index).keyring {
            self.release(serial);
        }
    }

    /// The keyring a negative key from request_key(2) goes to when the call
    /// names none: from the thread's request-key default down the chain of
    /// keyrings that exist, ending at the user-session keyring.
    fn request_destination(&mut self, caller: &Caller) -> Result<i32, Error> {
        let thread = self.thread(caller.tid);
        let default = thread.map_or(request_default::DEFAULT, |thread| thread.request_default);
        let thread_keyring = thread.and_then(|thread| thread.keyring);
        let session = thread.and_then(|thread| thread.session);
        let process_keyring = self.process(caller.pid).and_then(|process| process.keyring);
        let found = match default {
            request_default::USER => return Ok(self.user_keyrings(caller)?.0),
            request_default::USER_SESSION => None,
            request_default::SESSION => session,
            request_default::PROCESS => process_keyring.or(session),
            _ => thread_keyring.or(process_keyring).or(session),
        };
        match found {
            Some(serial) => Ok(serial),
            None => Ok(self.user_keyrings(caller)?.1),
        }
    }

    /// Creates the negative key request_key(2) leaves in `ring`.
    fn add_negative(
        &mut self,
        caller: &Caller,
        kind: KeyType,
        description: &[u8],
        ring: i32,
        now: u64,
    ) -> Result<(), Error> {
        let keyring = self.get(ring)?;
        if !keyring.is_keyring() {
            return Err(Error::NotDirectory);
        }
        let existing = self.find_link(keyring, kind, description);
        if existing.is_none() && !self.fits(keyring.uid, 0, LINK_BYTES) {
            return Err(Error::QuotaExceeded);
        }
        if keyring.restricted {
            return Err(Error::NotPermitted);
        }
        kind.check_description(description)?;
        let key = Key::new(NewKey {
            kind,
            description,
            payload: &[],
            uid: caller.uid,
            gid: Some(caller.gid),
            permissions: kind.default_permissions(),
            state: State::Negative(Error::NoKey),
            expiry: Some(now.saturating_add(NEGATIVE_TIMEOUT_SECONDS * NANOSECONDS_PER_SECOND)),
            per_user: false,
        })?;
        self.add_new(ring, existing, key).map(|_| ())
    }

    /// The first live keyring by serial named `name` that the caller may
    /// search without possessing it, which is what joining a session by
    /// name finds.
    fn find_named_keyring(&self, caller: &Caller, name: &[u8]) -> Option<i32> {
        self.keys
            .iter()
            .find(|key| {
                key.is_keyring()
                    && key.state == State::Positive
                    && key.description == name
                    && key.permits(caller, false, SEARCH)
            })
            .map(|key| key.serial)
    }

    fn new_session(&mut self, caller: &Caller) -> Result<i32, Error> {
        self.new_anchored_keyring(
            caller,
            Anchor::Session(caller.tid),
            b"_ses",
            ANONYMOUS_SESSION_PERMISSIONS,
            Quota::Overrun,
        )
    }
}
