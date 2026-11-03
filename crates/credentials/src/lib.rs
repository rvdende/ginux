#![forbid(unsafe_code)]
//! A process's credentials and the rules Linux applies to them: who it is
//! (user and group ids, real, effective, saved and filesystem), which
//! supplementary groups it belongs to, how it may change them (setuid(2),
//! setreuid(2), setresuid(2), setfsuid(2), setgroups(2) and their group
//! counterparts), and what they allow on a file (the owner, group and other
//! permission bits, and root's override).
//!
//! Capabilities follow the effective ids as they do for a Linux process
//! that never calls capset: a process holds CAP_SETUID, CAP_SETGID and
//! CAP_KILL while its effective user id is 0, and the filesystem
//! capabilities (CAP_DAC_OVERRIDE, CAP_CHOWN, CAP_FOWNER) while its
//! filesystem user id is 0. Whether a process may take ids it does not
//! already hold is the caller's [`Authority`]: the kernel grants it only to
//! root in a domain that allows switching users.
//!
//! This is pure bookkeeping, so it can be tested on the host.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

/// The most supplementary groups a process may have (Linux's NGROUPS_MAX).
pub const GROUPS_LIMIT: usize = 65_536;

/// The id a system call passes to leave an id unchanged (`(uid_t) -1`).
pub const UNCHANGED: u32 = u32::MAX;

/// Why an id change was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The process may not take that id (EPERM).
    Permission,
    /// The id does not exist in the process's user namespace (EINVAL).
    Invalid,
}

/// What a process may do when it changes its ids.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authority {
    /// It holds CAP_SETUID (for user ids) or CAP_SETGID (for group ids),
    /// so it may take any id that exists.
    pub privileged: bool,
    /// The ids that exist: its user namespace maps `0..id_count`.
    pub id_count: u32,
}

impl Authority {
    fn exists(self, id: u32) -> bool {
        id < self.id_count
    }

    /// Checks that each id other than [`UNCHANGED`] exists.
    fn check(self, ids: &[u32]) -> Result<(), Error> {
        if ids.iter().all(|&id| id == UNCHANGED || self.exists(id)) {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
}

/// One kind of id, user or group, as Linux keeps it per process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ids {
    /// Who the process is: the id signals and accounting use.
    pub real: u32,
    /// The id permission checks use.
    pub effective: u32,
    /// The id the process may switch its effective id back to.
    pub saved: u32,
    /// The id file access uses; it follows the effective id.
    pub filesystem: u32,
}

impl Ids {
    /// Every id set to `id`.
    pub const fn all(id: u32) -> Self {
        Self {
            real: id,
            effective: id,
            saved: id,
            filesystem: id,
        }
    }

    fn holds(&self, id: u32) -> bool {
        id == self.real || id == self.effective || id == self.saved
    }

    /// setuid(2): a privileged process sets every id; any other may set its
    /// effective id to its real or saved id.
    pub fn set(&mut self, id: u32, authority: Authority) -> Result<(), Error> {
        if !authority.exists(id) {
            return Err(Error::Invalid);
        }
        if authority.privileged {
            self.real = id;
            self.saved = id;
        } else if id != self.real && id != self.saved {
            return Err(Error::Permission);
        }
        self.effective = id;
        self.filesystem = id;
        Ok(())
    }

    /// setreuid(2): the real id may become the real or effective id, the
    /// effective id any of real, effective and saved. Setting the real id,
    /// or the effective id to anything but the old real id, also sets the
    /// saved id to the new effective id.
    pub fn set_real_effective(
        &mut self,
        real: u32,
        effective: u32,
        authority: Authority,
    ) -> Result<(), Error> {
        authority.check(&[real, effective])?;
        if !authority.privileged
            && (real != UNCHANGED && real != self.real && real != self.effective
                || effective != UNCHANGED && !self.holds(effective))
        {
            return Err(Error::Permission);
        }
        let old_real = self.real;
        if real != UNCHANGED {
            self.real = real;
        }
        if effective != UNCHANGED {
            self.effective = effective;
        }
        if real != UNCHANGED || effective != UNCHANGED && effective != old_real {
            self.saved = self.effective;
        }
        self.filesystem = self.effective;
        Ok(())
    }

    /// setresuid(2): each id may become any of the current real, effective
    /// and saved ids.
    pub fn set_real_effective_saved(
        &mut self,
        real: u32,
        effective: u32,
        saved: u32,
        authority: Authority,
    ) -> Result<(), Error> {
        authority.check(&[real, effective, saved])?;
        if !authority.privileged
            && [real, effective, saved]
                .into_iter()
                .any(|id| id != UNCHANGED && !self.holds(id))
        {
            return Err(Error::Permission);
        }
        if real != UNCHANGED {
            self.real = real;
        }
        if effective != UNCHANGED {
            self.effective = effective;
        }
        if saved != UNCHANGED {
            self.saved = saved;
        }
        self.filesystem = self.effective;
        Ok(())
    }

    /// setfsuid(2): sets the filesystem id to an id the process holds (or
    /// any, if privileged) and returns the previous one, also when it
    /// refuses; an id that does not exist only asks for the current one.
    pub fn set_filesystem(&mut self, id: u32, authority: Authority) -> u32 {
        let old = self.filesystem;
        if authority.exists(id) && (authority.privileged || self.holds(id) || id == old) {
            self.filesystem = id;
        }
        old
    }

    /// execve(2): a set-user-ID (or set-group-ID) program makes `id` the
    /// effective id; the saved and filesystem ids follow the effective id.
    pub fn exec(&mut self, set_id: Option<u32>) {
        if let Some(id) = set_id {
            self.effective = id;
        }
        self.saved = self.effective;
        self.filesystem = self.effective;
    }
}

/// Linux capability numbers (capabilities(7)).
pub mod capability {
    pub const CHOWN: u32 = 0;
    pub const DAC_OVERRIDE: u32 = 1;
    pub const DAC_READ_SEARCH: u32 = 2;
    pub const FOWNER: u32 = 3;
    pub const FSETID: u32 = 4;
    pub const KILL: u32 = 5;
    pub const SETGID: u32 = 6;
    pub const SETUID: u32 = 7;
    pub const SETPCAP: u32 = 8;
    pub const LINUX_IMMUTABLE: u32 = 9;
    pub const NET_ADMIN: u32 = 12;
    pub const NET_RAW: u32 = 13;
    pub const IPC_LOCK: u32 = 14;
    pub const SYS_MODULE: u32 = 16;
    pub const SYS_RAWIO: u32 = 17;
    pub const SYS_CHROOT: u32 = 18;
    pub const SYS_PTRACE: u32 = 19;
    pub const SYS_PACCT: u32 = 20;
    pub const SYS_ADMIN: u32 = 21;
    pub const SYS_BOOT: u32 = 22;
    pub const SYS_NICE: u32 = 23;
    pub const SYS_RESOURCE: u32 = 24;
    pub const SYS_TIME: u32 = 25;
    pub const SYS_TTY_CONFIG: u32 = 26;
    pub const MKNOD: u32 = 27;
    pub const MAC_OVERRIDE: u32 = 33;
    pub const SYSLOG: u32 = 34;
    /// The highest capability Linux defines (CAP_CHECKPOINT_RESTORE).
    pub const LAST: u32 = 40;
    /// Every capability.
    pub const ALL: u64 = (1 << (LAST + 1)) - 1;
    /// The capabilities a filesystem id change gives or takes with it.
    pub const FILESYSTEM: u64 = 1 << CHOWN
        | 1 << DAC_OVERRIDE
        | 1 << DAC_READ_SEARCH
        | 1 << FOWNER
        | 1 << FSETID
        | 1 << LINUX_IMMUTABLE
        | 1 << MAC_OVERRIDE
        | 1 << MKNOD;
}

/// A process's capability sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    /// The bounding set: what exec may grant and capset may make
    /// inheritable. Only PR_CAPBSET_DROP shrinks it.
    pub bounding: u64,
}

impl Capabilities {
    /// What root starts with: every capability permitted and effective.
    pub const ROOT: Self = Self {
        effective: capability::ALL,
        permitted: capability::ALL,
        inheritable: 0,
        bounding: capability::ALL,
    };
    /// None held (the bounding set is still full).
    pub const NONE: Self = Self {
        effective: 0,
        permitted: 0,
        inheritable: 0,
        bounding: capability::ALL,
    };
}

/// A process's user and group ids and its capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credentials {
    pub user: Ids,
    pub group: Ids,
    pub capabilities: Capabilities,
}

/// What a file allows: its owner, group and mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileAccess {
    pub owner: u32,
    pub group: u32,
    /// The permission bits (`0o7777`).
    pub mode: u32,
    pub directory: bool,
}

/// The access a process asks of a file: Linux's MAY_READ, MAY_WRITE and
/// MAY_EXEC, which are also the bits of each class in a mode.
pub mod access {
    pub const READ: u32 = 4;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 1;
}

impl Credentials {
    /// Every user and group id 0.
    pub const ROOT: Self = Self {
        user: Ids::all(0),
        group: Ids::all(0),
        capabilities: Capabilities::ROOT,
    };

    /// Credentials of an ordinary user: its ids, no capabilities.
    pub const fn user(uid: u32, gid: u32) -> Self {
        Self {
            user: Ids::all(uid),
            group: Ids::all(gid),
            capabilities: Capabilities::NONE,
        }
    }

    /// Whether the process holds capability `capability` (effective).
    pub fn has(&self, capability: u32) -> bool {
        capability <= capability::LAST && self.capabilities.effective & 1 << capability != 0
    }

    /// The capabilities follow a change of the user ids from `old`, as
    /// capabilities(7) says: losing every id 0 drops the permitted and
    /// effective sets, an effective id leaving 0 drops the effective set
    /// and one becoming 0 restores it from the permitted set; the
    /// filesystem capabilities follow the filesystem id the same way.
    pub fn after_user_change(&mut self, old: Ids) {
        let new = self.user;
        let caps = &mut self.capabilities;
        let old_root = old.real == 0 || old.effective == 0 || old.saved == 0;
        let new_root = new.real == 0 || new.effective == 0 || new.saved == 0;
        if old_root && !new_root {
            caps.permitted = 0;
            caps.effective = 0;
        }
        if old.effective == 0 && new.effective != 0 {
            caps.effective = 0;
        } else if old.effective != 0 && new.effective == 0 {
            caps.effective = caps.permitted;
        }
        if old.filesystem == 0 && new.filesystem != 0 {
            caps.effective &= !capability::FILESYSTEM;
        } else if old.filesystem != 0 && new.filesystem == 0 {
            caps.effective |= caps.permitted & capability::FILESYSTEM;
        }
    }

    /// execve(2) without file capabilities: root (real or effective) gets
    /// every capability of the bounding set permitted, effective when its
    /// effective id is 0; any other process none.
    pub fn after_exec(&mut self) {
        if self.user.real == 0 || self.user.effective == 0 {
            let granted = capability::ALL & self.capabilities.bounding;
            self.capabilities.permitted = granted;
            self.capabilities.effective = if self.user.effective == 0 { granted } else { 0 };
        } else {
            self.capabilities.permitted = 0;
            self.capabilities.effective = 0;
        }
    }

    /// capset(2): the new permitted set within the old, the effective within
    /// the new permitted, the inheritable within the old inheritable and
    /// permitted sets unless CAP_SETPCAP allows any, and always within the
    /// old inheritable and bounding sets (EPERM otherwise). The bounding
    /// set is kept; `new.bounding` is ignored.
    pub fn set_capabilities(&mut self, new: Capabilities) -> Result<(), Error> {
        let old = self.capabilities;
        let new = Capabilities {
            bounding: old.bounding,
            ..new
        };
        let inheritable_allowed = if self.has(capability::SETPCAP) {
            capability::ALL
        } else {
            old.inheritable | old.permitted
        } & (old.inheritable | old.bounding);
        if new.permitted & !old.permitted != 0
            || new.effective & !new.permitted != 0
            || new.inheritable & !inheritable_allowed != 0
        {
            return Err(Error::Permission);
        }
        self.capabilities = new;
        Ok(())
    }

    /// PR_CAPBSET_READ: whether `capability` is in the bounding set
    /// (Invalid for a capability that does not exist).
    pub fn bounding_has(&self, capability: u32) -> Result<bool, Error> {
        if capability > capability::LAST {
            return Err(Error::Invalid);
        }
        Ok(self.capabilities.bounding & 1 << capability != 0)
    }

    /// PR_CAPBSET_DROP: removes `capability` from the bounding set, which
    /// takes CAP_SETPCAP.
    pub fn drop_bounding(&mut self, capability: u32) -> Result<(), Error> {
        if capability > capability::LAST {
            return Err(Error::Invalid);
        }
        if !self.has(capability::SETPCAP) {
            return Err(Error::Permission);
        }
        self.capabilities.bounding &= !(1 << capability);
        Ok(())
    }

    /// The process holds CAP_SETUID, CAP_SETGID and CAP_KILL.
    pub fn privileged(&self) -> bool {
        self.user.effective == 0
    }

    /// The process holds the filesystem capabilities: CAP_DAC_OVERRIDE,
    /// CAP_CHOWN and CAP_FOWNER.
    pub fn filesystem_privileged(&self) -> bool {
        self.user.filesystem == 0
    }

    /// The process's filesystem group is `group`, or it belongs to it.
    pub fn in_group(&self, groups: &[u32], group: u32) -> bool {
        self.group.filesystem == group || groups.binary_search(&group).is_ok()
    }

    /// The process may have `wanted` (bits of [`access`]) on `file`: the
    /// owner's bits apply to its owner, the group's to its group, the
    /// others' to everyone else, and root may read and write anything and
    /// execute anything that some class may execute.
    pub fn may_access(&self, groups: &[u32], file: FileAccess, wanted: u32) -> bool {
        let class = if self.user.filesystem == file.owner {
            file.mode >> 6
        } else if self.in_group(groups, file.group) {
            file.mode >> 3
        } else {
            file.mode
        } & 7;
        if wanted & !class == 0 {
            return true;
        }
        self.filesystem_privileged()
            && (wanted & access::EXECUTE == 0 || file.directory || file.mode & 0o111 != 0)
    }

    /// The process owns `file`, or holds CAP_FOWNER: it may change its mode
    /// and times.
    pub fn owns(&self, file: FileAccess) -> bool {
        self.filesystem_privileged() || self.user.filesystem == file.owner
    }

    /// chown(2): root may give `file` any owner and group; its owner may
    /// only change its group, to one it belongs to.
    pub fn may_chown(&self, groups: &[u32], file: FileAccess, owner: u32, group: u32) -> bool {
        if self.filesystem_privileged() {
            return true;
        }
        let owner_unchanged = owner == UNCHANGED || owner == file.owner;
        let group_allowed =
            group == UNCHANGED || group == file.group || self.in_group(groups, group);
        self.user.filesystem == file.owner && owner_unchanged && group_allowed
    }

    /// kill(2): root may signal anyone; anyone else a process whose real or
    /// saved id is its real or effective id.
    pub fn may_signal(&self, target: &Self) -> bool {
        self.privileged()
            || [self.user.real, self.user.effective]
                .into_iter()
                .any(|id| id == target.user.real || id == target.user.saved)
    }
}

/// Validates and sorts a setgroups(2) list: only a privileged process may
/// set its groups, to at most [`GROUPS_LIMIT`] groups that exist.
pub fn set_groups(list: &mut [u32], authority: Authority) -> Result<(), Error> {
    if !authority.privileged {
        return Err(Error::Permission);
    }
    if list.len() > GROUPS_LIMIT || list.iter().any(|&group| !authority.exists(group)) {
        return Err(Error::Invalid);
    }
    list.sort_unstable();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const NOBODY: u32 = 65_534;
    const ROOT: Authority = Authority {
        privileged: true,
        id_count: 65_536,
    };
    const USER: Authority = Authority {
        privileged: false,
        id_count: 65_536,
    };

    #[test]
    fn root_setuid_drops_every_id() {
        let mut ids = Ids::all(0);
        assert_eq!(ids.set(NOBODY, ROOT), Ok(()));
        assert_eq!(ids, Ids::all(NOBODY));
        assert_eq!(ids.set(0, USER), Err(Error::Permission));
    }

    #[test]
    fn unprivileged_setuid_moves_only_the_effective_id() {
        let mut ids = Ids {
            real: 1000,
            effective: 0,
            saved: 0,
            filesystem: 0,
        };
        assert_eq!(ids.set(1000, USER), Ok(()));
        assert_eq!((ids.real, ids.effective, ids.saved), (1000, 1000, 0));
        assert_eq!(ids.set(0, USER), Ok(()));
        assert_eq!(ids.effective, 0);
        assert_eq!(ids.set(5, USER), Err(Error::Permission));
    }

    #[test]
    fn unmapped_ids_are_invalid() {
        let single = Authority {
            privileged: true,
            id_count: 1,
        };
        let mut ids = Ids::all(0);
        assert_eq!(ids.set(NOBODY, single), Err(Error::Invalid));
        assert_eq!(
            ids.set_real_effective(UNCHANGED, NOBODY, single),
            Err(Error::Invalid)
        );
        assert_eq!(ids.set(0, single), Ok(()));
        assert_eq!(ids.set_filesystem(NOBODY, single), 0);
        assert_eq!(ids.filesystem, 0);
    }

    #[test]
    fn seteuid_keeps_the_saved_id_so_root_can_return() {
        let mut ids = Ids::all(0);
        assert_eq!(
            ids.set_real_effective_saved(UNCHANGED, NOBODY, UNCHANGED, ROOT),
            Ok(())
        );
        assert_eq!((ids.real, ids.effective, ids.saved), (0, NOBODY, 0));
        assert_eq!(
            ids.set_real_effective_saved(UNCHANGED, 0, UNCHANGED, USER),
            Ok(())
        );
        assert_eq!(ids.effective, 0);
    }

    #[test]
    fn setreuid_updates_the_saved_id_as_linux_does() {
        let mut ids = Ids::all(0);
        // Only the effective id, to the real id: the saved id stays.
        assert_eq!(ids.set_real_effective(UNCHANGED, 0, ROOT), Ok(()));
        assert_eq!(ids.saved, 0);
        // The effective id to something else: the saved id follows.
        assert_eq!(ids.set_real_effective(UNCHANGED, NOBODY, ROOT), Ok(()));
        assert_eq!((ids.real, ids.effective, ids.saved), (0, NOBODY, NOBODY));
        // Swapping real and effective is allowed without privilege.
        let mut ids = Ids {
            real: 1,
            effective: 2,
            saved: 2,
            filesystem: 2,
        };
        assert_eq!(ids.set_real_effective(2, 1, USER), Ok(()));
        assert_eq!((ids.real, ids.effective, ids.saved), (2, 1, 1));
        assert_eq!(
            ids.set_real_effective(7, UNCHANGED, USER),
            Err(Error::Permission)
        );
    }

    #[test]
    fn setfsuid_returns_the_old_id_and_refuses_strangers() {
        let mut ids = Ids::all(NOBODY);
        assert_eq!(ids.set_filesystem(0, USER), NOBODY);
        assert_eq!(ids.filesystem, NOBODY);
        assert_eq!(ids.set_filesystem(UNCHANGED, USER), NOBODY);
        let mut ids = Ids::all(0);
        assert_eq!(ids.set_filesystem(NOBODY, ROOT), 0);
        assert_eq!(ids.set_filesystem(UNCHANGED, ROOT), NOBODY);
    }

    #[test]
    fn exec_applies_set_id_and_resets_saved() {
        let mut ids = Ids {
            real: 1000,
            effective: 1000,
            saved: 5,
            filesystem: 1000,
        };
        ids.exec(None);
        assert_eq!(ids, Ids::all(1000));
        ids.exec(Some(0));
        assert_eq!(
            (ids.real, ids.effective, ids.saved, ids.filesystem),
            (1000, 0, 0, 0)
        );
    }

    #[test]
    fn file_access_uses_one_class_and_root_overrides() {
        let file = FileAccess {
            owner: 1000,
            group: 100,
            mode: 0o640,
            directory: false,
        };
        let user = Credentials::user;
        assert!(user(1000, 1000).may_access(&[], file, access::READ | access::WRITE));
        assert!(user(5, 100).may_access(&[], file, access::READ));
        assert!(!user(5, 100).may_access(&[], file, access::WRITE));
        assert!(user(5, 5).may_access(&[100], file, access::READ));
        assert!(!user(5, 5).may_access(&[], file, access::READ));
        // The owner's bits apply even when the group's would allow more.
        let narrow = FileAccess {
            mode: 0o070,
            ..file
        };
        assert!(!user(1000, 100).may_access(&[], narrow, access::READ));
        // Root reads and writes anything, but executes only executables.
        assert!(Credentials::ROOT.may_access(&[], narrow, access::READ | access::WRITE));
        assert!(!Credentials::ROOT.may_access(&[], file, access::EXECUTE));
        let program = FileAccess {
            mode: 0o700,
            ..file
        };
        assert!(Credentials::ROOT.may_access(&[], program, access::EXECUTE));
    }

    #[test]
    fn chown_and_kill_permissions() {
        let file = FileAccess {
            owner: 1000,
            group: 1000,
            mode: 0o644,
            directory: false,
        };
        let owner = Credentials::user(1000, 1000);
        assert!(owner.may_chown(&[50], file, UNCHANGED, 50));
        assert!(!owner.may_chown(&[50], file, UNCHANGED, 60));
        assert!(!owner.may_chown(&[], file, 0, UNCHANGED));
        assert!(Credentials::ROOT.may_chown(&[], file, 0, 0));
        let stranger = Credentials::user(5, 5);
        assert!(!stranger.may_signal(&owner));
        assert!(owner.may_signal(&owner));
        assert!(Credentials::ROOT.may_signal(&owner));
    }

    #[test]
    fn setgroups_needs_privilege_and_sorts() {
        let mut list = vec![30, 10, 20];
        assert_eq!(set_groups(&mut list, USER), Err(Error::Permission));
        assert_eq!(set_groups(&mut list, ROOT), Ok(()));
        assert_eq!(list, [10, 20, 30]);
        let mut unmapped = vec![70_000];
        assert_eq!(set_groups(&mut unmapped, ROOT), Err(Error::Invalid));
    }

    #[test]
    fn capabilities_follow_user_changes_and_capset() {
        let mut root = Credentials::ROOT;
        assert!(root.has(capability::SYS_ADMIN));
        let old = root.user;
        root.user.effective = 1000;
        root.after_user_change(old);
        assert!(!root.has(capability::SYS_ADMIN));
        assert_eq!(root.capabilities.permitted, capability::ALL);
        let old = root.user;
        root.user.effective = 0;
        root.after_user_change(old);
        assert!(root.has(capability::SYS_ADMIN));
        let old = root.user;
        root.user = Ids::all(1000);
        root.after_user_change(old);
        assert_eq!(root.capabilities, Capabilities::NONE);
        let mut caps = Credentials::ROOT;
        let dropped = Capabilities {
            effective: capability::ALL & !(1 << capability::SYS_RESOURCE),
            ..Capabilities::ROOT
        };
        assert_eq!(caps.set_capabilities(dropped), Ok(()));
        assert!(!caps.has(capability::SYS_RESOURCE));
        let raised = Capabilities {
            permitted: 0,
            effective: 1,
            inheritable: 0,
            bounding: capability::ALL,
        };
        assert_eq!(caps.set_capabilities(raised), Err(Error::Permission));
        let mut bounded = Credentials::ROOT;
        assert_eq!(bounded.drop_bounding(capability::KILL), Ok(()));
        assert_eq!(bounded.bounding_has(capability::KILL), Ok(false));
        assert_eq!(
            bounded.bounding_has(capability::LAST + 1),
            Err(Error::Invalid)
        );
        let inherit_kill = Capabilities {
            inheritable: 1 << capability::KILL,
            ..bounded.capabilities
        };
        assert_eq!(
            bounded.set_capabilities(inherit_kill),
            Err(Error::Permission)
        );
        bounded.after_exec();
        assert_eq!(bounded.capabilities.permitted & 1 << capability::KILL, 0);
    }
}
