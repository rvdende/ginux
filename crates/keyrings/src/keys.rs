//! The key table and the rules every operation shares: resolving an id to
//! a key with the checks Linux's key lookup makes, possession, searching
//! keyring trees, links and the references that keep keys alive, and quota
//! accounting.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::{fmt, mem};

use crate::asymmetric::{self, Asymmetric};
use crate::encrypted::Encrypted;
use crate::restrict::Restriction;

use crate::permission::SEARCH;
use crate::proc::Text;
use crate::{
    no_memory, Caller, Error, KeyType, Keyrings, PRIVATE_KEYRING_PERMISSIONS, PROCESS_KEYRING,
    REQUESTOR_KEYRING, REQUEST_KEY_AUTH_KEY, SESSION_KEYRING, THREAD_KEYRING, USER_KEYRING,
    USER_KEYRING_PERMISSIONS, USER_SESSION_KEYRING,
};

/// The bytes of its owner's quota each link takes from a keyring.
pub(crate) const LINK_BYTES: usize = 4;
/// How many keyrings deep a search descends below the keyring it starts
/// in, and how deep a linked keyring may nest (Linux's
/// KEYRING_SEARCH_MAX_DEPTH).
pub(crate) const SEARCH_DEPTH: usize = 6;

/// How a key was instantiated, or what has happened to it since.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    /// Instantiated with a payload (or, for a keyring, its links).
    Positive,
    /// Left by request_key(2) when nothing could be found: using it fails
    /// with this error until it expires or add_key(2) updates it.
    Negative(Error),
    Revoked,
    /// Unlinked from every keyring; it lingers only while a thread,
    /// process or user still anchors it.
    Invalidated,
}

pub(crate) struct Key {
    pub(crate) serial: i32,
    pub(crate) kind: KeyType,
    pub(crate) description: Vec<u8>,
    /// What the key's type keeps.
    pub(crate) payload: Payload,
    /// A keyring's links, in the order they were made.
    pub(crate) links: Vec<i32>,
    pub(crate) uid: u32,
    /// `None` for the user keyrings, which Linux creates without a group.
    pub(crate) gid: Option<u32>,
    pub(crate) permissions: u32,
    pub(crate) state: State,
    /// When the key expires, on the kernel's clock in nanoseconds.
    pub(crate) expiry: Option<u64>,
    /// The keyring links and anchors that keep the key.
    pub(crate) references: u32,
    /// The bytes charged to the owner's quota.
    pub(crate) charged: usize,
    /// What the keyring accepts new links to, once restricted.
    pub(crate) restriction: Option<Restriction>,
    /// A user or user-session keyring: asking for a new session keyring
    /// replaces it as a thread's session keyring.
    pub(crate) per_user: bool,
}

/// Shows the payload's length only: a key's data ("logon" keys above all)
/// must not reach a kernel log through a debug print.
impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Key")
            .field("serial", &self.serial)
            .field("kind", &self.kind)
            .field("description", &self.description)
            .field("payload_length", &self.payload.quota_bytes())
            .field("links", &self.links)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("permissions", &self.permissions)
            .field("state", &self.state)
            .field("expiry", &self.expiry)
            .field("references", &self.references)
            .finish_non_exhaustive()
    }
}

/// What a key's type keeps for it.
pub(crate) enum Payload {
    /// A "user", "logon" or "dns_resolver" key's data; nothing for a
    /// keyring, a negative key or one whose contents were discarded.
    Data(Vec<u8>),
    /// A "dns_resolver" key recording a failed lookup: reading it fails
    /// with this errno.
    DnsError(u16),
    Asymmetric(Box<Asymmetric>),
    Encrypted(Box<Encrypted>),
}

impl Payload {
    pub(crate) const fn empty() -> Self {
        Self::Data(Vec::new())
    }

    /// The data of a "user"-like key; empty for the other kinds.
    pub(crate) fn data(&self) -> &[u8] {
        match self {
            Self::Data(data) => data,
            _ => &[],
        }
    }

    /// The bytes it takes from the owner's quota.
    pub(crate) fn quota_bytes(&self) -> usize {
        match self {
            Self::Data(data) => data.len(),
            Self::DnsError(_) => 0,
            Self::Asymmetric(_) => asymmetric::QUOTA_BYTES,
            Self::Encrypted(key) => key.quota_bytes(),
        }
    }
}

/// What a new key starts as.
pub(crate) struct NewKey<'a> {
    pub(crate) kind: KeyType,
    pub(crate) description: &'a [u8],
    pub(crate) payload: Payload,
    pub(crate) uid: u32,
    pub(crate) gid: Option<u32>,
    pub(crate) permissions: u32,
    pub(crate) state: State,
    pub(crate) expiry: Option<u64>,
    pub(crate) per_user: bool,
}

pub(crate) fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len()).map_err(no_memory)?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

impl Key {
    /// A key that is not yet in the table: its serial is given when it is
    /// inserted.
    pub(crate) fn new(new: NewKey<'_>) -> Result<Self, Error> {
        Ok(Self {
            serial: 0,
            kind: new.kind,
            description: copy(new.description)?,
            payload: new.payload,
            links: Vec::new(),
            uid: new.uid,
            gid: new.gid,
            permissions: new.permissions,
            state: new.state,
            expiry: new.expiry,
            references: 0,
            charged: 0,
            restriction: None,
            per_user: new.per_user,
        })
    }

    /// What the key takes from its owner's quota: the description with its
    /// NUL, and what the payload takes or four bytes per link.
    pub(crate) fn quota_bytes(&self) -> usize {
        let data = match self.kind {
            KeyType::Keyring => self.links.len() * LINK_BYTES,
            _ => self.payload.quota_bytes(),
        };
        self.description.len() + 1 + data
    }

    pub(crate) fn is_keyring(&self) -> bool {
        self.kind == KeyType::Keyring
    }

    pub(crate) fn expired(&self, now: u64) -> bool {
        self.expiry.is_some_and(|expiry| now >= expiry)
    }

    /// Whether the key may still be used, a negative instantiation aside.
    pub(crate) fn validate(&self, now: u64) -> Result<(), Error> {
        match self.state {
            State::Invalidated => Err(Error::NoKey),
            State::Revoked => Err(Error::KeyRevoked),
            _ if self.expired(now) => Err(Error::KeyExpired),
            _ => Ok(()),
        }
    }

    /// A negatively instantiated key fails with its error.
    pub(crate) fn instantiated(&self) -> Result<(), Error> {
        match self.state {
            State::Negative(error) => Err(error),
            _ => Ok(()),
        }
    }

    pub(crate) fn has_index(&self, kind: KeyType, description: &[u8]) -> bool {
        self.kind == kind && self.description == description
    }

    /// Whether the mask grants `caller` all of `rights`: the owner's byte
    /// if it owns the key, else the group's byte if that grants anything
    /// and the caller is in the group, else the other byte; plus the
    /// possessor's byte when the caller possesses the key.
    pub(crate) fn permits(&self, caller: &Caller, possessed: bool, rights: u32) -> bool {
        let mask = self.permissions;
        let group_rights = mask & crate::permission::group(crate::permission::ALL) != 0;
        let mut granted = if self.uid == caller.uid {
            mask >> 16
        } else if group_rights && self.gid.is_some_and(|gid| caller.in_group(gid)) {
            mask >> 8
        } else {
            mask
        };
        if possessed {
            granted |= mask >> 24;
        }
        granted & rights == rights
    }
}

/// A user's quota usage and per-user keyrings.
#[derive(Debug)]
pub(crate) struct User {
    pub(crate) uid: u32,
    pub(crate) keys: u32,
    pub(crate) bytes: usize,
    pub(crate) keyring: Option<i32>,
    pub(crate) session_keyring: Option<i32>,
}

#[derive(Debug)]
pub(crate) struct Thread {
    pub(crate) tid: u32,
    pub(crate) keyring: Option<i32>,
    pub(crate) session: Option<i32>,
    pub(crate) request_default: i32,
}

#[derive(Debug)]
pub(crate) struct Process {
    pub(crate) pid: u32,
    pub(crate) keyring: Option<i32>,
}

/// A place outside the keyrings that holds a reference to a key.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Anchor {
    ThreadKeyring(u32),
    Session(u32),
    ProcessKeyring(u32),
    UserKeyring(u32),
    UserSessionKeyring(u32),
}

/// Whether a new key's charge is held to the owner's limits. Linux lets
/// the thread, process and anonymous session keyrings overrun them, so a
/// thread at its quota still gets the keyrings it needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Quota {
    Checked,
    Overrun,
}

/// How a lookup treats the key it finds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Lookup {
    /// Create a missing thread, process or session keyring.
    pub(crate) create: bool,
    /// Accept a negatively instantiated key.
    pub(crate) partial: bool,
}

impl Lookup {
    pub(crate) const PLAIN: Self = Self {
        create: false,
        partial: false,
    };
    pub(crate) const CREATE: Self = Self {
        create: true,
        partial: false,
    };
    pub(crate) const PARTIAL: Self = Self {
        create: false,
        partial: true,
    };
    pub(crate) const CREATE_PARTIAL: Self = Self {
        create: true,
        partial: true,
    };
}

/// What a lookup checks before it returns a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Need {
    /// The key must be usable and grant these rights.
    Rights(u32),
    /// Nothing about the key itself: unlinking concerns only the keyring.
    Unlink,
    /// Nothing yet: KEYCTL_READ checks state and rights in its own order.
    Deferred,
}

/// A key a lookup resolved, and whether the caller possesses it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Handle {
    pub(crate) serial: i32,
    pub(crate) possessed: bool,
}

/// Which keys a search looks for.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Match<'a> {
    /// One key, to decide whether the caller possesses it.
    Serial(i32),
    /// Keys of a type and exact description.
    Index(KeyType, &'a [u8]),
    /// Asymmetric keys with this id: the issuer name id if the flag is
    /// set, else the issuer-and-serial or subject key id.
    AsymmetricId(&'a [u8], bool),
}

impl Match<'_> {
    fn matches(self, key: &Key) -> bool {
        match self {
            Self::Serial(serial) => key.serial == serial,
            Self::Index(kind, description) => key.has_index(kind, description),
            Self::AsymmetricId(id, name) => {
                let Payload::Asymmetric(asymmetric) = &key.payload else {
                    return false;
                };
                let same = |slot: &Option<Vec<u8>>| slot.as_deref() == Some(id);
                if name {
                    same(&asymmetric.ids[2])
                } else {
                    same(&asymmetric.ids[0]) || same(&asymmetric.ids[1])
                }
            }
        }
    }
}

pub(crate) struct Search<'a> {
    pub(crate) caller: &'a Caller<'a>,
    pub(crate) matcher: Match<'a>,
    /// Whether the keyring the search starts in is possessed; everything
    /// found under it inherits that.
    pub(crate) possessed: bool,
    /// Skip revoked, expired and negative keys, noting why, as request_key
    /// and KEYCTL_SEARCH do; possession ignores the state.
    pub(crate) check_state: bool,
    pub(crate) now: u64,
}

/// What a search came to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Searched {
    Found(i32),
    /// Nothing valid matched; this is why the first matching key was
    /// passed over.
    Skipped(Error),
    Nothing,
}

impl Keyrings {
    pub(crate) fn key(&self, serial: i32) -> Option<&Key> {
        let index = self
            .keys
            .binary_search_by_key(&serial, |key| key.serial)
            .ok()?;
        self.keys.get(index)
    }

    pub(crate) fn key_mut(&mut self, serial: i32) -> Option<&mut Key> {
        let index = self
            .keys
            .binary_search_by_key(&serial, |key| key.serial)
            .ok()?;
        self.keys.get_mut(index)
    }

    pub(crate) fn get(&self, serial: i32) -> Result<&Key, Error> {
        self.key(serial).ok_or(Error::NoKey)
    }

    pub(crate) fn get_mut(&mut self, serial: i32) -> Result<&mut Key, Error> {
        self.key_mut(serial).ok_or(Error::NoKey)
    }

    pub(crate) fn user(&self, uid: u32) -> Option<&User> {
        let index = self
            .users
            .binary_search_by_key(&uid, |user| user.uid)
            .ok()?;
        self.users.get(index)
    }

    fn user_mut(&mut self, uid: u32) -> Option<&mut User> {
        let index = self
            .users
            .binary_search_by_key(&uid, |user| user.uid)
            .ok()?;
        self.users.get_mut(index)
    }

    pub(crate) fn thread(&self, tid: u32) -> Option<&Thread> {
        let index = self
            .threads
            .binary_search_by_key(&tid, |thread| thread.tid)
            .ok()?;
        self.threads.get(index)
    }

    pub(crate) fn thread_mut(&mut self, tid: u32) -> Option<&mut Thread> {
        let index = self
            .threads
            .binary_search_by_key(&tid, |thread| thread.tid)
            .ok()?;
        self.threads.get_mut(index)
    }

    pub(crate) fn process(&self, pid: u32) -> Option<&Process> {
        let index = self
            .processes
            .binary_search_by_key(&pid, |process| process.pid)
            .ok()?;
        self.processes.get(index)
    }

    fn process_mut(&mut self, pid: u32) -> Option<&mut Process> {
        let index = self
            .processes
            .binary_search_by_key(&pid, |process| process.pid)
            .ok()?;
        self.processes.get_mut(index)
    }

    pub(crate) fn ensure_user(&mut self, uid: u32) -> Result<(), Error> {
        if let Err(index) = self.users.binary_search_by_key(&uid, |user| user.uid) {
            self.users.try_reserve(1).map_err(no_memory)?;
            self.users.insert(
                index,
                User {
                    uid,
                    keys: 0,
                    bytes: 0,
                    keyring: None,
                    session_keyring: None,
                },
            );
        }
        Ok(())
    }

    pub(crate) fn ensure_thread(&mut self, tid: u32) -> Result<(), Error> {
        if let Err(index) = self.threads.binary_search_by_key(&tid, |thread| thread.tid) {
            self.threads.try_reserve(1).map_err(no_memory)?;
            self.threads.insert(
                index,
                Thread {
                    tid,
                    keyring: None,
                    session: None,
                    request_default: crate::request_default::DEFAULT,
                },
            );
        }
        Ok(())
    }

    fn ensure_process(&mut self, pid: u32) -> Result<(), Error> {
        if let Err(index) = self
            .processes
            .binary_search_by_key(&pid, |process| process.pid)
        {
            self.processes.try_reserve(1).map_err(no_memory)?;
            self.processes.insert(index, Process { pid, keyring: None });
        }
        Ok(())
    }

    /// Whether `uid` may take `keys` more keys and `bytes` more bytes;
    /// reaching a limit exactly is allowed.
    pub(crate) fn fits(&self, uid: u32, keys: u32, bytes: usize) -> bool {
        let (max_keys, max_bytes) = self.limits.of(uid);
        let (used_keys, used_bytes) = self
            .user(uid)
            .map_or((0, 0), |user| (user.keys, user.bytes));
        used_keys.saturating_add(keys) <= max_keys
            && used_bytes.saturating_add(bytes) <= max_bytes as usize
    }

    /// Charges a key of `bytes` to `uid`, whose record must exist.
    pub(crate) fn charge(&mut self, uid: u32, bytes: usize) {
        if let Some(user) = self.user_mut(uid) {
            user.keys = user.keys.saturating_add(1);
            user.bytes = user.bytes.saturating_add(bytes);
        }
    }

    /// Returns a key of `bytes` from `uid`'s quota, forgetting a user with
    /// no keys left.
    pub(crate) fn uncharge(&mut self, uid: u32, bytes: usize) {
        let Ok(index) = self.users.binary_search_by_key(&uid, |user| user.uid) else {
            return;
        };
        let Some(user) = self.users.get_mut(index) else {
            return;
        };
        user.keys = user.keys.saturating_sub(1);
        user.bytes = user.bytes.saturating_sub(bytes);
        // A user keyring given away by KEYCTL_CHOWN is still anchored here.
        if user.keys == 0 && user.keyring.is_none() && user.session_keyring.is_none() {
            self.users.remove(index);
        }
    }

    /// Brings the owner's quota in line with what the key now holds.
    pub(crate) fn recharge(&mut self, serial: i32) {
        let Some(key) = self.key_mut(serial) else {
            return;
        };
        let bytes = key.quota_bytes();
        let old = mem::replace(&mut key.charged, bytes);
        let uid = key.uid;
        if let Some(user) = self.user_mut(uid) {
            user.bytes = user.bytes.saturating_sub(old).saturating_add(bytes);
        }
    }

    /// Puts a new key in the table with no references and charges its
    /// owner. Room in the table and the owner's record must be ready, and
    /// the caller links or anchors the key before anything is released.
    pub(crate) fn insert(&mut self, mut key: Key) -> i32 {
        let serial = self.allocate_serial();
        key.serial = serial;
        key.charged = key.quota_bytes();
        self.charge(key.uid, key.charged);
        let index = self
            .keys
            .partition_point(|existing| existing.serial < serial);
        self.keys.insert(index, key);
        serial
    }

    /// The next unused serial: they increase from 1 and wrap past
    /// `i32::MAX`.
    fn allocate_serial(&mut self) -> i32 {
        loop {
            let serial = self.next_serial;
            self.next_serial = serial.checked_add(1).unwrap_or(1);
            if self.key(serial).is_none() {
                return serial;
            }
        }
    }

    pub(crate) fn retain(&mut self, serial: i32) {
        if let Some(key) = self.key_mut(serial) {
            key.references = key.references.saturating_add(1);
        }
    }

    /// Drops a reference, and the key with whatever only it held once
    /// nothing refers to it.
    pub(crate) fn release(&mut self, serial: i32) {
        let Some(key) = self.key_mut(serial) else {
            return;
        };
        key.references = key.references.saturating_sub(1);
        if key.references == 0 {
            self.sweep();
        }
    }

    /// Removes every key nothing refers to. A removed keyring lets go of
    /// its links, which may leave more keys unreferenced; looping instead
    /// of recursing keeps a long chain of keyrings off the stack.
    fn sweep(&mut self) {
        while let Some(index) = self.keys.iter().position(|key| key.references == 0) {
            let key = self.keys.remove(index);
            self.uncharge(key.uid, key.charged);
            let trusted = key.restriction.and_then(Restriction::trusted);
            for serial in key.links.into_iter().chain(trusted) {
                if let Some(linked) = self.key_mut(serial) {
                    linked.references = linked.references.saturating_sub(1);
                }
            }
        }
    }

    /// Points `anchor` at `serial`, releasing what it held before.
    pub(crate) fn set_anchor(&mut self, anchor: Anchor, serial: Option<i32>) {
        let slot = match anchor {
            Anchor::ThreadKeyring(tid) => self.thread_mut(tid).map(|thread| &mut thread.keyring),
            Anchor::Session(tid) => self.thread_mut(tid).map(|thread| &mut thread.session),
            Anchor::ProcessKeyring(pid) => {
                self.process_mut(pid).map(|process| &mut process.keyring)
            }
            Anchor::UserKeyring(uid) => self.user_mut(uid).map(|user| &mut user.keyring),
            Anchor::UserSessionKeyring(uid) => {
                self.user_mut(uid).map(|user| &mut user.session_keyring)
            }
        };
        let Some(slot) = slot else {
            return;
        };
        let old = mem::replace(slot, serial);
        if old == serial {
            return;
        }
        if let Some(serial) = serial {
            self.retain(serial);
        }
        if let Some(old) = old {
            self.release(old);
        }
    }

    /// Creates a keyring owned by `owner`'s real ids and makes it `anchor`.
    pub(crate) fn new_anchored_keyring(
        &mut self,
        owner: &Caller,
        anchor: Anchor,
        name: &[u8],
        permissions: u32,
        quota: Quota,
    ) -> Result<i32, Error> {
        let uid = owner.real_uid;
        if quota == Quota::Checked && !self.fits(uid, 1, name.len() + 1) {
            return Err(Error::QuotaExceeded);
        }
        let key = Key::new(NewKey {
            kind: KeyType::Keyring,
            description: name,
            payload: Payload::empty(),
            uid,
            gid: Some(owner.real_gid),
            permissions,
            state: State::Positive,
            expiry: None,
            per_user: false,
        })?;
        self.keys.try_reserve(1).map_err(no_memory)?;
        self.ensure_user(uid)?;
        match anchor {
            Anchor::ThreadKeyring(tid) | Anchor::Session(tid) => self.ensure_thread(tid)?,
            Anchor::ProcessKeyring(pid) => self.ensure_process(pid)?,
            Anchor::UserKeyring(uid) | Anchor::UserSessionKeyring(uid) => self.ensure_user(uid)?,
        }
        let serial = self.insert(key);
        self.set_anchor(anchor, Some(serial));
        Ok(serial)
    }

    /// The user keyring "_uid.UID" and user-session keyring "_uid_ses.UID"
    /// of the caller's real user id, created together on first use with the
    /// user keyring linked from the user-session keyring. They are found by
    /// uid, never by name, so a keyring someone else named "_uid.UID"
    /// cannot stand in for them.
    pub(crate) fn user_keyrings(&mut self, caller: &Caller) -> Result<(i32, i32), Error> {
        let uid = caller.real_uid;
        if let Some(User {
            keyring: Some(keyring),
            session_keyring: Some(session),
            ..
        }) = self.user(uid)
        {
            return Ok((*keyring, *session));
        }
        let mut user_name = Text::new();
        user_name.format(format_args!("_uid.{uid}"))?;
        let mut session_name = Text::new();
        session_name.format(format_args!("_uid_ses.{uid}"))?;
        let bytes = user_name.len() + 1 + session_name.len() + 1 + LINK_BYTES;
        if !self.fits(uid, 2, bytes) {
            return Err(Error::QuotaExceeded);
        }
        let new = |description| NewKey {
            kind: KeyType::Keyring,
            description,
            payload: Payload::empty(),
            uid,
            gid: None,
            permissions: USER_KEYRING_PERMISSIONS,
            state: State::Positive,
            expiry: None,
            per_user: true,
        };
        let keyring = Key::new(new(user_name.as_bytes()))?;
        let mut session = Key::new(new(session_name.as_bytes()))?;
        session.links.try_reserve(1).map_err(no_memory)?;
        self.keys.try_reserve(2).map_err(no_memory)?;
        self.ensure_user(uid)?;
        let keyring = self.insert(keyring);
        let session = self.insert(session);
        // Each new keyring is referenced before an anchor can release
        // anything, so a sweep cannot take it.
        self.attach(session, keyring);
        self.set_anchor(Anchor::UserSessionKeyring(uid), Some(session));
        self.set_anchor(Anchor::UserKeyring(uid), Some(keyring));
        Ok((keyring, session))
    }

    /// Resolves `id` to a key as Linux's lookup does: a special id names
    /// one of the caller's keyrings, which `flags.create` may create, and is
    /// always possessed; a serial must exist and is possessed if a search
    /// of the caller's keyrings reaches it. Unless `need` defers or skips
    /// the checks, the key must not be negative (unless `flags.partial`),
    /// invalidated, revoked or expired, and must grant the rights.
    pub(crate) fn lookup(
        &mut self,
        caller: &Caller,
        id: i32,
        flags: Lookup,
        need: Need,
        now: u64,
    ) -> Result<Handle, Error> {
        let (serial, special) = if id > 0 {
            (id, false)
        } else {
            (self.special(caller, id, flags.create)?, true)
        };
        let key = self.get(serial)?;
        let possessed = special || self.possesses(caller, serial);
        if let Need::Rights(rights) = need {
            if !flags.partial {
                key.instantiated()?;
            }
            key.validate(now)?;
            if !key.permits(caller, possessed, rights) {
                return Err(Error::AccessDenied);
            }
        }
        Ok(Handle { serial, possessed })
    }

    /// The keyring a special id names for `caller`.
    pub(crate) fn special(&mut self, caller: &Caller, id: i32, create: bool) -> Result<i32, Error> {
        match id {
            THREAD_KEYRING => match self.thread(caller.tid).and_then(|thread| thread.keyring) {
                Some(serial) => Ok(serial),
                None if create => self.new_anchored_keyring(
                    caller,
                    Anchor::ThreadKeyring(caller.tid),
                    b"_tid",
                    PRIVATE_KEYRING_PERMISSIONS,
                    Quota::Overrun,
                ),
                None => Err(Error::NoKey),
            },
            PROCESS_KEYRING => match self.process(caller.pid).and_then(|process| process.keyring) {
                Some(serial) => Ok(serial),
                None if create => self.new_anchored_keyring(
                    caller,
                    Anchor::ProcessKeyring(caller.pid),
                    b"_pid",
                    PRIVATE_KEYRING_PERMISSIONS,
                    Quota::Overrun,
                ),
                None => Err(Error::NoKey),
            },
            SESSION_KEYRING => self.session_keyring(caller, create),
            USER_KEYRING => Ok(self.user_keyrings(caller)?.0),
            USER_SESSION_KEYRING => Ok(self.user_keyrings(caller)?.1),
            REQUEST_KEY_AUTH_KEY | REQUESTOR_KEYRING => Err(Error::NoKey),
            // Group keyrings, 0 and ids below the special range.
            _ => Err(Error::Invalid),
        }
    }

    /// A thread without a session keyring is given the user-session keyring
    /// as one when it asks, or a new session keyring when it is about to
    /// change it; so is a thread whose session keyring is the user-session
    /// keyring.
    fn session_keyring(&mut self, caller: &Caller, create: bool) -> Result<i32, Error> {
        match self.thread(caller.tid).and_then(|thread| thread.session) {
            Some(serial) if !create || !self.key(serial).is_some_and(|key| key.per_user) => {
                Ok(serial)
            }
            Some(_) => self.new_session(caller),
            None => {
                let (_, user_session) = self.user_keyrings(caller)?;
                if create {
                    return self.new_session(caller);
                }
                self.ensure_thread(caller.tid)?;
                self.set_anchor(Anchor::Session(caller.tid), Some(user_session));
                Ok(user_session)
            }
        }
    }

    /// The keyrings that make keys possessed and that request_key(2)
    /// searches, in its order: the thread keyring, the process keyring,
    /// and the session keyring or, without one, the user-session keyring.
    pub(crate) fn caller_keyrings(&self, caller: &Caller) -> [Option<i32>; 3] {
        let thread = self.thread(caller.tid);
        let session = thread.and_then(|thread| thread.session).or_else(|| {
            self.user(caller.real_uid)
                .and_then(|user| user.session_keyring)
        });
        [
            thread.and_then(|thread| thread.keyring),
            self.process(caller.pid).and_then(|process| process.keyring),
            session,
        ]
    }

    /// Whether `caller` possesses the key: it is one of the caller's
    /// keyrings, or linked from one through keyrings the caller may search,
    /// and it grants the caller search permission itself.
    pub(crate) fn possesses(&self, caller: &Caller, serial: i32) -> bool {
        let search = Search {
            caller,
            matcher: Match::Serial(serial),
            possessed: true,
            check_state: false,
            now: 0,
        };
        self.caller_keyrings(caller)
            .into_iter()
            .flatten()
            .any(|top| self.search_tree(&search, top) == Searched::Found(serial))
    }

    /// request_key(2)'s search of the caller's keyrings, which it possesses.
    pub(crate) fn search_caller(&self, caller: &Caller, matcher: Match<'_>, now: u64) -> Searched {
        let search = Search {
            caller,
            matcher,
            possessed: true,
            check_state: true,
            now,
        };
        let mut noted = None;
        for top in self.caller_keyrings(caller).into_iter().flatten() {
            match self.search_tree(&search, top) {
                Searched::Found(serial) => return Searched::Found(serial),
                Searched::Skipped(error) => {
                    noted.get_or_insert(error);
                }
                Searched::Nothing => {}
            }
        }
        noted.map_or(Searched::Nothing, Searched::Skipped)
    }

    /// Searches the tree under the keyring `top`, which must grant search
    /// permission. If `top` itself matches, it decides the result.
    pub(crate) fn search_tree(&self, search: &Search<'_>, top: i32) -> Searched {
        let Some(keyring) = self.key(top) else {
            return Searched::Nothing;
        };
        if !keyring.permits(search.caller, search.possessed, SEARCH) {
            return Searched::Skipped(Error::AccessDenied);
        }
        if search.matcher.matches(keyring) {
            return match self.consider(search, keyring) {
                Ok(()) => Searched::Found(top),
                Err(error) => Searched::Skipped(error),
            };
        }
        let mut noted = None;
        match self.walk(search, keyring, 0, &mut noted) {
            Some(serial) => Searched::Found(serial),
            None => noted.map_or(Searched::Nothing, Searched::Skipped),
        }
    }

    /// Checks a keyring's own links before descending into the keyrings it
    /// links, one at a time, as far as [`SEARCH_DEPTH`].
    fn walk(
        &self,
        search: &Search<'_>,
        keyring: &Key,
        depth: usize,
        noted: &mut Option<Error>,
    ) -> Option<i32> {
        let linked = || keyring.links.iter().filter_map(|&serial| self.key(serial));
        for key in linked().filter(|key| search.matcher.matches(key)) {
            match self.consider(search, key) {
                Ok(()) => return Some(key.serial),
                Err(error) => {
                    noted.get_or_insert(error);
                }
            }
        }
        if depth >= SEARCH_DEPTH {
            return None;
        }
        linked()
            .filter(|key| key.is_keyring() && key.permits(search.caller, search.possessed, SEARCH))
            .find_map(|child| self.walk(search, child, depth + 1, noted))
    }

    /// Whether a matching key is the result, or why it is passed over.
    fn consider(&self, search: &Search<'_>, key: &Key) -> Result<(), Error> {
        if search.check_state {
            if matches!(key.state, State::Revoked | State::Invalidated) {
                return Err(Error::KeyRevoked);
            }
            if key.expired(search.now) {
                return Err(Error::KeyExpired);
            }
        }
        if !key.permits(search.caller, search.possessed, SEARCH) {
            return Err(Error::AccessDenied);
        }
        if search.check_state {
            key.instantiated()?;
        }
        Ok(())
    }

    /// The link in `keyring` to a key of that type and description.
    pub(crate) fn find_link(
        &self,
        keyring: &Key,
        kind: KeyType,
        description: &[u8],
    ) -> Option<i32> {
        keyring.links.iter().copied().find(|&serial| {
            self.key(serial)
                .is_some_and(|key| key.has_index(kind, description))
        })
    }

    /// Linking keyring `key` into `ring` must not let `ring` contain
    /// itself (EDEADLK), and `key` must not nest deeper than a search can
    /// follow to check that (ELOOP).
    pub(crate) fn check_cycle(&self, ring: i32, key: &Key, depth: usize) -> Result<(), Error> {
        if key.serial == ring || key.links.contains(&ring) {
            return Err(Error::Deadlock);
        }
        let children = key.links.iter().filter_map(|&serial| self.key(serial));
        for child in children.filter(|child| child.is_keyring()) {
            if depth >= SEARCH_DEPTH {
                return Err(Error::TooDeep);
            }
            self.check_cycle(ring, child, depth + 1)?;
        }
        Ok(())
    }

    /// Makes room for one more link unless an existing link is replaced.
    pub(crate) fn reserve_link(&mut self, ring: i32, existing: Option<i32>) -> Result<(), Error> {
        if existing.is_none() {
            self.get_mut(ring)?
                .links
                .try_reserve(1)
                .map_err(no_memory)?;
        }
        Ok(())
    }

    /// key_link: checks and makes a link, displacing a key of the same type
    /// and description. Linking a key that is already there changes
    /// nothing.
    pub(crate) fn link_checked(
        &mut self,
        caller: &Caller,
        ring: i32,
        serial: i32,
        now: u64,
    ) -> Result<(), Error> {
        let keyring = self.get(ring)?;
        if !keyring.is_keyring() {
            return Err(Error::NotDirectory);
        }
        let key = self.get(serial)?;
        let existing = self.find_link(keyring, key.kind, &key.description);
        if existing.is_none() && !self.fits(keyring.uid, 0, LINK_BYTES) {
            return Err(Error::QuotaExceeded);
        }
        self.check_restriction(caller, ring, key.kind, &key.payload, now)?;
        if key.is_keyring() {
            self.check_cycle(ring, key, 0)?;
        }
        self.reserve_link(ring, existing)?;
        self.attach(ring, serial);
        Ok(())
    }

    /// Puts a new key in the table linked from `ring`, charging the key and
    /// the link (together when one user owns both). `existing` is the link
    /// the key displaces.
    pub(crate) fn add_new(
        &mut self,
        ring: i32,
        existing: Option<i32>,
        key: Key,
    ) -> Result<i32, Error> {
        let ring_owner = self.get(ring)?.uid;
        let link_bytes = if existing.is_none() { LINK_BYTES } else { 0 };
        let bytes = key.quota_bytes();
        let fits = if ring_owner == key.uid {
            self.fits(key.uid, 1, bytes + link_bytes)
        } else {
            self.fits(key.uid, 1, bytes)
        };
        if !fits {
            return Err(Error::QuotaExceeded);
        }
        self.reserve_link(ring, existing)?;
        self.keys.try_reserve(1).map_err(no_memory)?;
        self.ensure_user(key.uid)?;
        let serial = self.insert(key);
        self.attach(ring, serial);
        Ok(serial)
    }

    /// Links `serial` into `ring`, replacing the link to a key of the same
    /// type and description. Room for a new link must be reserved.
    pub(crate) fn attach(&mut self, ring: i32, serial: i32) {
        let (Some(keyring), Some(key)) = (self.key(ring), self.key(serial)) else {
            return;
        };
        let replaced = self.find_link(keyring, key.kind, &key.description);
        if replaced == Some(serial) {
            return;
        }
        self.retain(serial);
        if let Some(keyring) = self.key_mut(ring) {
            let slot = replaced.and_then(|old| keyring.links.iter_mut().find(|link| **link == old));
            match slot {
                Some(link) => *link = serial,
                None => keyring.links.push(serial),
            }
        }
        self.recharge(ring);
        if let Some(old) = replaced {
            self.release(old);
        }
    }

    /// Removes the link to `serial` from `ring`; false if there is none.
    pub(crate) fn detach(&mut self, ring: i32, serial: i32) -> bool {
        let Some(keyring) = self.key_mut(ring) else {
            return false;
        };
        let Some(slot) = keyring.links.iter().position(|&linked| linked == serial) else {
            return false;
        };
        keyring.links.remove(slot);
        self.recharge(ring);
        self.release(serial);
        true
    }

    /// Removes every link to `serial`.
    pub(crate) fn unlink_everywhere(&mut self, serial: i32) {
        let mut removed = 0;
        for index in 0..self.keys.len() {
            let Some(keyring) = self.keys.get_mut(index) else {
                break;
            };
            let before = keyring.links.len();
            keyring.links.retain(|&linked| linked != serial);
            if keyring.links.len() != before {
                removed += 1;
                let ring = keyring.serial;
                self.recharge(ring);
            }
        }
        for _ in 0..removed {
            self.release(serial);
        }
    }

    /// Drops a key's payload and links, as revoking, invalidating and
    /// clearing do.
    pub(crate) fn discard_contents(&mut self, serial: i32) {
        let Some(key) = self.key_mut(serial) else {
            return;
        };
        key.payload = Payload::empty();
        let links = mem::take(&mut key.links);
        self.recharge(serial);
        for linked in links {
            self.release(linked);
        }
    }

    /// Gives a key a new payload, which positively instantiates a negative
    /// key and clears any timeout.
    pub(crate) fn replace_payload(&mut self, serial: i32, payload: Payload) -> Result<(), Error> {
        let key = self.get(serial)?;
        let bytes = key.description.len() + 1 + payload.quota_bytes();
        let growth = bytes.saturating_sub(key.charged);
        if growth != 0 && !self.fits(key.uid, 0, growth) {
            return Err(Error::QuotaExceeded);
        }
        let key = self.get_mut(serial)?;
        key.payload = payload;
        key.state = State::Positive;
        key.expiry = None;
        self.recharge(serial);
        Ok(())
    }
}
