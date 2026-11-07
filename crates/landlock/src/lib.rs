#![forbid(unsafe_code)]
//! Landlock, Linux's unprivileged sandboxing, as Ginux enforces it: the
//! rulesets a process builds (`landlock_create_ruleset`,
//! `landlock_add_rule`), the domain of stacked layers it restricts itself
//! to (`landlock_restrict_self`), and the questions the kernel asks before
//! filesystem, network, signal and abstract Unix socket operations.
//!
//! Filesystem rules name canonical paths (from the domain's root, without
//! a leading slash; "" is the root itself) and cover what lies beneath
//! them, as Linux's path-beneath rules cover a directory's hierarchy. A
//! request is granted when, in every layer that handles its access rights,
//! rules on the path or on a directory above it grant them all. Linux ties
//! rules to inodes; here they follow the path a rule named.
//!
//! This is pure policy, so it is tested on the host; the kernel keeps the
//! rulesets and each process's domain and asks these questions.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::sync::Arc;
use alloc::vec::Vec;

/// The ABI version `landlock_create_ruleset` reports: Linux 6.12's, with
/// truncation, device ioctls, TCP ports and scopes.
pub const ABI_VERSION: u32 = 6;

/// How many rulesets a domain may stack (Linux's LANDLOCK_MAX_NUM_LAYERS).
pub const MAX_LAYERS: usize = 16;

/// Access rights, as `linux/landlock.h` numbers them.
pub mod access {
    pub const FS_EXECUTE: u64 = 1 << 0;
    pub const FS_WRITE_FILE: u64 = 1 << 1;
    pub const FS_READ_FILE: u64 = 1 << 2;
    pub const FS_READ_DIR: u64 = 1 << 3;
    pub const FS_REMOVE_DIR: u64 = 1 << 4;
    pub const FS_REMOVE_FILE: u64 = 1 << 5;
    pub const FS_MAKE_CHAR: u64 = 1 << 6;
    pub const FS_MAKE_DIR: u64 = 1 << 7;
    pub const FS_MAKE_REG: u64 = 1 << 8;
    pub const FS_MAKE_SOCK: u64 = 1 << 9;
    pub const FS_MAKE_FIFO: u64 = 1 << 10;
    pub const FS_MAKE_BLOCK: u64 = 1 << 11;
    pub const FS_MAKE_SYM: u64 = 1 << 12;
    pub const FS_REFER: u64 = 1 << 13;
    pub const FS_TRUNCATE: u64 = 1 << 14;
    pub const FS_IOCTL_DEV: u64 = 1 << 15;
    pub const FS_ALL: u64 = (1 << 16) - 1;
    /// The rights that apply to a file itself, which are all a rule on a
    /// file (rather than a directory) may grant.
    pub const FS_FILE: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;

    pub const NET_BIND_TCP: u64 = 1 << 0;
    pub const NET_CONNECT_TCP: u64 = 1 << 1;
    pub const NET_ALL: u64 = NET_BIND_TCP | NET_CONNECT_TCP;

    pub const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    pub const SCOPE_SIGNAL: u64 = 1 << 1;
    pub const SCOPE_ALL: u64 = SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL;
}

use access::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// EINVAL: an unknown or unhandled access right, a port past 65535, or
    /// directory rights on a file.
    Invalid,
    /// ENOMSG: a ruleset that handles nothing, or a rule that grants
    /// nothing.
    Empty,
    /// E2BIG: the domain already stacks `MAX_LAYERS` rulesets.
    TooManyLayers,
    /// ENOMEM.
    NoMemory,
}

impl Error {
    pub const fn errno(self) -> u64 {
        match self {
            Self::Invalid => 22,
            Self::Empty => 42,
            Self::TooManyLayers => 7,
            Self::NoMemory => 12,
        }
    }
}

/// Why moving or linking a file to another directory is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    /// EACCES: a right to remove from or add to a directory is missing.
    Access,
    /// EXDEV: the move itself is not allowed (no LANDLOCK_ACCESS_FS_REFER,
    /// or the file would gain rights where it goes); the caller may copy.
    Reparent,
}

/// A ruleset being built: what it handles and the rules it grants.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Ruleset {
    pub handled_fs: u64,
    pub handled_net: u64,
    pub scoped: u64,
    paths: Vec<(Vec<u8>, u64)>,
    ports: Vec<(u16, u64)>,
}

impl Ruleset {
    /// A ruleset that handles these rights and scopes: an unknown one is
    /// EINVAL, none at all ENOMSG.
    pub fn new(handled_fs: u64, handled_net: u64, scoped: u64) -> Result<Self, Error> {
        if handled_fs & !FS_ALL != 0 || handled_net & !NET_ALL != 0 || scoped & !SCOPE_ALL != 0 {
            return Err(Error::Invalid);
        }
        if handled_fs == 0 && handled_net == 0 && scoped == 0 {
            return Err(Error::Empty);
        }
        Ok(Self {
            handled_fs,
            handled_net,
            scoped,
            ..Self::default()
        })
    }

    /// The checks of a path-beneath rule granting `allowed` that come
    /// before its file is looked at: it must grant something (ENOMSG), and
    /// only what the ruleset handles (EINVAL).
    pub fn check_path_rule(&self, allowed: u64) -> Result<(), Error> {
        if allowed == 0 {
            return Err(Error::Empty);
        }
        if allowed & !self.handled_fs != 0 {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Adds a rule granting `allowed` beneath `path`, a directory or, when
    /// `directory` is false, a file, which may be granted only file rights
    /// (EINVAL). A second rule on one path adds to the first.
    pub fn add_path(&mut self, path: &[u8], directory: bool, allowed: u64) -> Result<(), Error> {
        self.check_path_rule(allowed)?;
        if !directory && allowed & !FS_FILE != 0 {
            return Err(Error::Invalid);
        }
        if let Some((_, rights)) = self.paths.iter_mut().find(|(rule, _)| rule == path) {
            *rights |= allowed;
            return Ok(());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(path.len())
            .map_err(|_| Error::NoMemory)?;
        owned.extend_from_slice(path);
        self.paths.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.paths.push((owned, allowed));
        Ok(())
    }

    /// Adds a rule granting `allowed` on TCP port `port`: it must grant
    /// something (ENOMSG), only handled network rights (EINVAL), and the
    /// port must fit 16 bits (EINVAL).
    pub fn add_port(&mut self, port: u64, allowed: u64) -> Result<(), Error> {
        if allowed == 0 {
            return Err(Error::Empty);
        }
        if allowed & !self.handled_net != 0 {
            return Err(Error::Invalid);
        }
        let port = u16::try_from(port).map_err(|_| Error::Invalid)?;
        if let Some((_, rights)) = self.ports.iter_mut().find(|(rule, _)| *rule == port) {
            *rights |= allowed;
            return Ok(());
        }
        self.ports.try_reserve(1).map_err(|_| Error::NoMemory)?;
        self.ports.push((port, allowed));
        Ok(())
    }

    /// What the rules grant at `path`: the union of the rules on it and on
    /// every directory above it.
    fn granted_at(&self, path: &[u8]) -> u64 {
        self.paths
            .iter()
            .filter(|(rule, _)| beneath(path, rule))
            .fold(0, |granted, (_, rights)| granted | rights)
    }

    fn granted_on_port(&self, port: u16) -> u64 {
        self.ports
            .iter()
            .filter(|(rule, _)| *rule == port)
            .fold(0, |granted, (_, rights)| granted | rights)
    }
}

/// Whether `path` is `rule` or lies beneath it ("" is the root, above
/// everything).
fn beneath(path: &[u8], rule: &[u8]) -> bool {
    rule.is_empty()
        || path
            .strip_prefix(rule)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
}

/// One enforced ruleset, frozen: `id` tells domains apart for scopes.
#[derive(Debug, Eq, PartialEq)]
struct Layer {
    id: u64,
    rules: Ruleset,
}

/// The layers a process is restricted by, oldest first. A child gets its
/// parent's; restricting oneself again adds a layer on top.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Domain {
    layers: Vec<Arc<Layer>>,
}

impl Domain {
    /// Whether any ruleset restricts this domain.
    pub fn is_restricted(&self) -> bool {
        !self.layers.is_empty()
    }

    /// Whether some layer handles a filesystem right.
    pub fn restricts_filesystem(&self) -> bool {
        self.layers.iter().any(|layer| layer.rules.handled_fs != 0)
    }

    /// This domain with `ruleset` stacked on top as layer `id`: E2BIG past
    /// `MAX_LAYERS`.
    pub fn restricted_by(&self, ruleset: &Ruleset, id: u64) -> Result<Self, Error> {
        if self.layers.len() >= MAX_LAYERS {
            return Err(Error::TooManyLayers);
        }
        let mut layers = Vec::new();
        layers
            .try_reserve_exact(self.layers.len() + 1)
            .map_err(|_| Error::NoMemory)?;
        layers.extend(self.layers.iter().cloned());
        layers.push(Arc::new(Layer {
            id,
            rules: ruleset.clone(),
        }));
        Ok(Self { layers })
    }

    /// Whether `access` on `path` is allowed: every layer that handles a
    /// right asked for grants it at the path or above.
    pub fn allows_path(&self, path: &[u8], access: u64) -> bool {
        self.layers.iter().all(|layer| {
            let needed = access & layer.rules.handled_fs;
            needed == 0 || layer.rules.granted_at(path) & needed == needed
        })
    }

    /// Whether a file of the kind `file_rights` describes (`FS_FILE` for a
    /// file, `FS_ALL` for a directory) may move or get a name from
    /// directory `from` to directory `to`: every layer must grant
    /// LANDLOCK_ACCESS_FS_REFER on both (which every ruleset handles
    /// implicitly), and the file must not gain a handled right there that
    /// it does not have where it is (EXDEV). Same-directory moves are not
    /// asked about, and a domain that handles no filesystem right at all
    /// (only ports or scopes) does not restrict moves.
    pub fn allows_reparent(&self, from: &[u8], to: &[u8], file_rights: u64) -> bool {
        !self.restricts_filesystem()
            || self.layers.iter().all(|layer| {
                let at_source = layer.rules.granted_at(from);
                let at_target = layer.rules.granted_at(to);
                let handled = layer.rules.handled_fs & file_rights & !FS_REFER;
                at_source & FS_REFER != 0
                    && at_target & FS_REFER != 0
                    && at_target & handled & !at_source == 0
            })
    }

    /// The checks of a rename or link between directories: the rights to
    /// remove the file from `from` (`removal`, 0 for a link) and add it to
    /// `to` (`making`) first (EACCES), then, when the directories differ,
    /// the move itself (`allows_reparent`, EXDEV).
    pub fn check_move(
        &self,
        from: &[u8],
        to: &[u8],
        removal: u64,
        making: u64,
        file_rights: u64,
    ) -> Result<(), Denial> {
        if !self.allows_path(from, removal) || !self.allows_path(to, making) {
            return Err(Denial::Access);
        }
        if from != to && !self.allows_reparent(from, to, file_rights) {
            return Err(Denial::Reparent);
        }
        Ok(())
    }

    /// Whether `access` (bind or connect) on TCP port `port` is allowed.
    pub fn allows_port(&self, port: u16, access: u64) -> bool {
        self.layers.iter().all(|layer| {
            let needed = access & layer.rules.handled_net;
            needed == 0 || layer.rules.granted_on_port(port) & needed == needed
        })
    }

    /// Whether a process of this domain may reach one of `target`'s under
    /// `scope` (signals, abstract Unix sockets): each of our layers that
    /// scopes it must also restrict the target, which is then in our
    /// domain or one nested in it.
    pub fn reaches(&self, scope: u64, target: &Domain) -> bool {
        self.layers
            .iter()
            .filter(|layer| layer.rules.scoped & scope != 0)
            .all(|layer| target.layers.iter().any(|other| other.id == layer.id))
    }
}

/// The right to make a node of a mode's file type (`S_IFMT` bits).
pub const fn make_right(mode: u32) -> u64 {
    match mode & 0o170_000 {
        0o040_000 => FS_MAKE_DIR,
        0o020_000 => FS_MAKE_CHAR,
        0o060_000 => FS_MAKE_BLOCK,
        0o010_000 => FS_MAKE_FIFO,
        0o140_000 => FS_MAKE_SOCK,
        0o120_000 => FS_MAKE_SYM,
        _ => FS_MAKE_REG,
    }
}

/// The right to remove a node: a directory's or anything else's.
pub const fn remove_right(directory: bool) -> u64 {
    if directory {
        FS_REMOVE_DIR
    } else {
        FS_REMOVE_FILE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(rulesets: &[Ruleset]) -> Domain {
        rulesets
            .iter()
            .enumerate()
            .fold(Domain::default(), |domain, (index, ruleset)| {
                domain.restricted_by(ruleset, index as u64 + 1).unwrap()
            })
    }

    #[test]
    fn rulesets_check_what_they_handle() {
        assert_eq!(Ruleset::new(u64::MAX, 0, 0), Err(Error::Invalid));
        assert_eq!(Ruleset::new(0, 4, 0), Err(Error::Invalid));
        assert_eq!(Ruleset::new(0, 0, 4), Err(Error::Invalid));
        assert_eq!(Ruleset::new(0, 0, 0), Err(Error::Empty));
        let mut ruleset = Ruleset::new(FS_EXECUTE, NET_BIND_TCP, 0).unwrap();
        assert_eq!(ruleset.add_path(b"bin", true, 0), Err(Error::Empty));
        assert_eq!(
            ruleset.add_path(b"bin", true, FS_READ_FILE),
            Err(Error::Invalid)
        );
        assert_eq!(ruleset.add_port(448, FS_EXECUTE << 4), Err(Error::Invalid));
        assert_eq!(ruleset.add_port(65_536, NET_BIND_TCP), Err(Error::Invalid));
        assert_eq!(ruleset.add_port(80, NET_BIND_TCP), Ok(()));
        // A file takes only file rights.
        let mut files = Ruleset::new(FS_ALL, 0, 0).unwrap();
        assert_eq!(
            files.add_path(b"bin/sh", false, FS_READ_DIR),
            Err(Error::Invalid)
        );
        assert_eq!(files.add_path(b"bin/sh", false, FS_EXECUTE), Ok(()));
    }

    #[test]
    fn rules_cover_what_lies_beneath() {
        let mut ruleset = Ruleset::new(FS_READ_FILE | FS_WRITE_FILE, 0, 0).unwrap();
        ruleset
            .add_path(b"tmp/sandbox", true, FS_READ_FILE)
            .unwrap();
        let domain = domain(&[ruleset]);
        assert!(domain.allows_path(b"tmp/sandbox/file", FS_READ_FILE));
        assert!(domain.allows_path(b"tmp/sandbox", FS_READ_FILE));
        assert!(!domain.allows_path(b"tmp/sandboxed", FS_READ_FILE));
        assert!(!domain.allows_path(b"tmp/sandbox/file", FS_WRITE_FILE));
        // Unhandled rights are never refused.
        assert!(domain.allows_path(b"etc/passwd", FS_EXECUTE));
        assert!(!domain.allows_path(b"etc/passwd", FS_READ_FILE));
    }

    #[test]
    fn every_layer_must_grant() {
        let mut first = Ruleset::new(FS_READ_FILE, 0, 0).unwrap();
        first.add_path(b"", true, FS_READ_FILE).unwrap();
        let mut second = Ruleset::new(FS_READ_FILE, 0, 0).unwrap();
        second.add_path(b"home", true, FS_READ_FILE).unwrap();
        let domain = domain(&[first, second]);
        assert!(domain.allows_path(b"home/user", FS_READ_FILE));
        assert!(!domain.allows_path(b"etc/hosts", FS_READ_FILE));
    }

    #[test]
    fn layers_stack_to_the_limit() {
        let ruleset = Ruleset::new(FS_EXECUTE, 0, 0).unwrap();
        let mut domain = Domain::default();
        for id in 0..MAX_LAYERS as u64 {
            domain = domain.restricted_by(&ruleset, id).unwrap();
        }
        assert_eq!(
            domain.restricted_by(&ruleset, 99),
            Err(Error::TooManyLayers)
        );
    }

    #[test]
    fn moves_need_refer_on_both_directories() {
        let mut ruleset = Ruleset::new(FS_READ_FILE | FS_WRITE_FILE | FS_REFER, 0, 0).unwrap();
        ruleset.add_path(b"m/folder1", true, FS_REFER).unwrap();
        ruleset.add_path(b"m/folder2", true, FS_REFER).unwrap();
        let domain = domain(&[ruleset]);
        assert_eq!(
            domain.check_move(b"m/folder1", b"m/folder2", 0, 0, FS_FILE),
            Ok(())
        );
        assert_eq!(
            domain.check_move(b"m/folder2", b"m/folder3", 0, 0, FS_FILE),
            Err(Denial::Reparent)
        );
        // A ruleset that does not handle REFER still refuses moves...
        let read_only = super::tests::domain(&[Ruleset::new(FS_READ_FILE, 0, 0).unwrap()]);
        assert!(!read_only.allows_reparent(b"a", b"b", FS_FILE));
        assert_eq!(read_only.check_move(b"a", b"a", 0, 0, FS_FILE), Ok(()));
        // ...but one that handles no filesystem right leaves them alone.
        let net_only = super::tests::domain(&[Ruleset::new(0, NET_BIND_TCP, 0).unwrap()]);
        assert!(net_only.allows_reparent(b"a", b"b", FS_FILE));
    }

    #[test]
    fn moves_may_not_gain_rights() {
        let mut ruleset = Ruleset::new(FS_READ_FILE | FS_REFER, 0, 0).unwrap();
        ruleset.add_path(b"a", true, FS_REFER).unwrap();
        ruleset
            .add_path(b"b", true, FS_REFER | FS_READ_FILE)
            .unwrap();
        let domain = domain(&[ruleset]);
        assert!(!domain.allows_reparent(b"a", b"b", FS_FILE));
        assert!(domain.allows_reparent(b"b", b"a", FS_FILE));
    }

    #[test]
    fn moves_check_removal_and_making_first() {
        let mut ruleset = Ruleset::new(FS_REMOVE_FILE | FS_MAKE_REG, 0, 0).unwrap();
        ruleset.add_path(b"a", true, FS_REMOVE_FILE).unwrap();
        let domain = domain(&[ruleset]);
        assert_eq!(
            domain.check_move(b"a", b"a", FS_REMOVE_FILE, FS_MAKE_REG, FS_FILE),
            Err(Denial::Access)
        );
    }

    #[test]
    fn ports_need_a_rule() {
        let mut ruleset = Ruleset::new(0, NET_BIND_TCP, 0).unwrap();
        ruleset.add_port(8080, NET_BIND_TCP).unwrap();
        let domain = domain(&[ruleset]);
        assert!(domain.allows_port(8080, NET_BIND_TCP));
        assert!(!domain.allows_port(8081, NET_BIND_TCP));
        assert!(domain.allows_port(8081, NET_CONNECT_TCP));
    }

    #[test]
    fn scopes_reach_only_nested_domains() {
        let scoped = Ruleset::new(0, 0, SCOPE_SIGNAL).unwrap();
        let outer = Domain::default().restricted_by(&scoped, 1).unwrap();
        let nested = outer.restricted_by(&scoped, 2).unwrap();
        let other = Domain::default().restricted_by(&scoped, 3).unwrap();
        let free = Domain::default();
        assert!(outer.reaches(SCOPE_SIGNAL, &outer));
        assert!(outer.reaches(SCOPE_SIGNAL, &nested));
        assert!(!nested.reaches(SCOPE_SIGNAL, &outer));
        assert!(!outer.reaches(SCOPE_SIGNAL, &other));
        assert!(!outer.reaches(SCOPE_SIGNAL, &free));
        assert!(free.reaches(SCOPE_SIGNAL, &outer));
        // A scope the layers do not set does not limit.
        assert!(outer.reaches(SCOPE_ABSTRACT_UNIX_SOCKET, &free));
    }

    #[test]
    fn node_rights_follow_the_file_type() {
        assert_eq!(make_right(0o100_644), FS_MAKE_REG);
        assert_eq!(make_right(0), FS_MAKE_REG);
        assert_eq!(make_right(0o020_600), FS_MAKE_CHAR);
        assert_eq!(make_right(0o140_000), FS_MAKE_SOCK);
        assert_eq!(remove_right(true), FS_REMOVE_DIR);
    }
}
