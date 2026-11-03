//! Unix98 pseudo-terminals, as Linux's devpts offers them: opening
//! `/dev/ptmx` makes a master and slave pair ([`ginux_tty::Pair`]), and the
//! slave appears as `/dev/pts/N` until the master closes.
//!
//! The pairs live in one table by index (the N of `/dev/pts/N`), each
//! owned by the domain that made it: a slave node opens only its own
//! domain's pair. Descriptors refer to an end as an object slot of the
//! socket table (class [`CLASS_MASTER`] or [`CLASS_SLAVE`], id the index),
//! so `dup`, `fork`, SCM_RIGHTS and `close` share and count them as Linux
//! counts open files. Each open of a slave makes one slot; the socket table
//! hands back a slot once its last descriptor closes ([`release`]): the
//! master's makes the slave hang up and removes its node, the last slave's
//! makes the master read EIO, and the pair is freed once both are gone.
//!
//! The slave node is a character device in the domain's overlay (136:N,
//! mode 0620, owned by the opener and group tty), so listing, stat and
//! ttyname see it like any device file.

use alloc::vec::Vec;

use ginux_tty::Pair;

use crate::sync::{LockRank, SpinLock};

/// Object classes in the socket table; DRM, loop devices, RAM disks and
/// /dev/kmsg take 1 to 7.
pub(crate) const CLASS_MASTER: u8 = 8;
pub(crate) const CLASS_SLAVE: u8 = 9;

/// /dev/ptmx: 5:2.
pub(crate) const MASTER_DEVICE: u32 = (5 << 8) | 2;
/// Slaves are numbered from 136:0 over eight majors, as on Linux.
const SLAVE_MAJOR: u32 = 136;
const LIMIT: usize = 8 * 256;
/// The tty group devpts gives slave nodes (its usual `gid=5,mode=620`).
const TTY_GROUP: u32 = 5;
const SLAVE_MODE: u32 = 0o620;

/// One pair and who holds it.
pub(crate) struct Entry {
    pub(crate) pair: Pair,
    /// The domain (container slot) that made the pair.
    owner: usize,
    master_open: bool,
    /// Slave slots open.
    slaves: u32,
    /// The session the slave is the controlling terminal of (0 for none)
    /// and its foreground process group.
    pub(crate) session: u32,
    pub(crate) group: u32,
    /// TIOCEXCL on the slave: further opens need privilege.
    pub(crate) exclusive: bool,
    /// When a waiting read's VTIME runs out, per end (0 when no timer
    /// runs), in the kernel's nanoseconds.
    pub(crate) read_deadline: [u64; 2],
}

struct Ptys {
    entries: Vec<Option<Entry>>,
    /// Sessions whose controlling terminal hung up, for the kernel to send
    /// SIGHUP and SIGCONT.
    hangups: Vec<u32>,
}

static PTYS: SpinLock<Ptys> = SpinLock::new(
    LockRank::PTYS,
    Ptys {
        entries: Vec::new(),
        hangups: Vec::new(),
    },
);

/// Why opening an end failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OpenError {
    /// Every pair is in use (ENOSPC).
    Exhausted,
    /// No memory for the pair or its slot (ENOMEM).
    NoMemory,
    /// No such pair, its master is gone or it is locked (EIO).
    Unavailable,
    /// The slave is exclusive (EBUSY).
    Busy,
}

/// The device number of slave `index`, as overlay nodes keep it.
pub(crate) fn slave_device(index: u64) -> u32 {
    let index = index as u32;
    ((SLAVE_MAJOR + index / 256) << 8) | (index % 256)
}

/// The slave index a device number names.
pub(crate) fn slave_index(device: u32) -> Option<u64> {
    let (major, minor) = (device >> 8, device & 0xff);
    (SLAVE_MAJOR..SLAVE_MAJOR + (LIMIT / 256) as u32)
        .contains(&major)
        .then(|| u64::from((major - SLAVE_MAJOR) * 256 + minor))
}

/// The slave node's path, `dev/pts/N`.
pub(crate) fn node_path(index: u64, output: &mut [u8; 16]) -> &[u8] {
    let mut digits = [0_u8; 8];
    let mut count = 0;
    let mut value = index;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output[..8].copy_from_slice(b"dev/pts/");
    for (slot, digit) in output[8..].iter_mut().zip(digits[..count].iter().rev()) {
        *slot = *digit;
    }
    &output[..8 + count]
}

/// Runs `operation` on pair `index` if domain `owner` holds it.
pub(crate) fn with<R>(
    owner: usize,
    index: u64,
    operation: impl FnOnce(&mut Entry) -> R,
) -> Option<R> {
    let mut ptys = PTYS.lock();
    let entry = ptys
        .entries
        .get_mut(usize::try_from(index).ok()?)?
        .as_mut()
        .filter(|entry| entry.owner == owner)?;
    Some(operation(entry))
}

/// Makes a pair for domain `owner` and opens its master; returns the
/// master's slot and the pair's index. The slave's node belongs to
/// `user`.
pub(crate) fn open_master(
    owner: usize,
    user: u32,
) -> Result<(crate::linux_socket::SlotId, u64), OpenError> {
    let index = {
        let mut ptys = PTYS.lock();
        let entry = Entry {
            pair: Pair::new(),
            owner,
            master_open: true,
            slaves: 0,
            session: 0,
            group: 0,
            exclusive: false,
            read_deadline: [0; 2],
        };
        match ptys.entries.iter().position(Option::is_none) {
            Some(index) => {
                ptys.entries[index] = Some(entry);
                index
            }
            None if ptys.entries.len() < LIMIT => {
                if ptys.entries.try_reserve(1).is_err() {
                    return Err(OpenError::NoMemory);
                }
                ptys.entries.push(Some(entry));
                ptys.entries.len() - 1
            }
            None => return Err(OpenError::Exhausted),
        }
    } as u64;
    let slot = match crate::linux_socket::open_object(CLASS_MASTER, index) {
        Ok(slot) => slot,
        Err(_) => {
            PTYS.lock().entries[index as usize] = None;
            return Err(OpenError::NoMemory);
        }
    };
    if crate::linux_overlay::lookup(b"dev/pts").is_none() {
        let _ = crate::linux_overlay::create_directory(b"dev/pts", 0o755);
    }
    let mut path = [0; 16];
    let path = node_path(index, &mut path);
    let _ = crate::linux_overlay::unlink_path(path);
    if let Some(node) = crate::linux_overlay::create_device(
        path,
        crate::linux_overlay::NodeKind::CharacterDevice,
        SLAVE_MODE,
        slave_device(index),
    ) {
        let _ = crate::linux_overlay::set_owner(node, user, TTY_GROUP);
    }
    Ok((slot, index))
}

/// Opens slave `index` of domain `owner`'s pair; `privileged` passes an
/// exclusive slave.
pub(crate) fn open_slave(
    owner: usize,
    index: u64,
    privileged: bool,
) -> Result<crate::linux_socket::SlotId, OpenError> {
    with(owner, index, |entry| {
        if !entry.master_open {
            return Err(OpenError::Unavailable);
        }
        if entry.exclusive && entry.slaves > 0 && !privileged {
            return Err(OpenError::Busy);
        }
        entry
            .pair
            .open_slave()
            .map_err(|_| OpenError::Unavailable)?;
        entry.slaves += 1;
        Ok(())
    })
    .ok_or(OpenError::Unavailable)??;
    crate::linux_socket::open_object(CLASS_SLAVE, index).map_err(|_| {
        release(CLASS_SLAVE, index);
        OpenError::NoMemory
    })
}

/// Whether a pair is the controlling terminal of `session`.
pub(crate) fn controls_session(session: u32) -> bool {
    session != 0
        && PTYS
            .lock()
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.session == session)
}

/// The sessions whose controlling terminal hung up since the last call.
pub(crate) fn take_hangups() -> Vec<u32> {
    core::mem::take(&mut PTYS.lock().hangups)
}

/// Releases end `class`/`index` after its last descriptor closed: a
/// master hangs up its slave and removes the slave's node, the last slave
/// lets the master read EIO, and a pair with neither is freed. Objects of
/// other classes are not this module's.
pub(crate) fn release(class: u8, index: u64) {
    if !matches!(class, CLASS_MASTER | CLASS_SLAVE) {
        return;
    }
    let mut ptys = PTYS.lock();
    let Ptys { entries, hangups } = &mut *ptys;
    let Some(slot) = entries.get_mut(index as usize) else {
        return;
    };
    let Some(entry) = slot.as_mut() else {
        return;
    };
    if class == CLASS_MASTER {
        entry.master_open = false;
        entry.pair.close_master();
        if entry.session != 0 && hangups.try_reserve(1).is_ok() {
            hangups.push(entry.session);
        }
        entry.session = 0;
        entry.group = 0;
        // Removed while the index is still held, so a pair that reuses it
        // keeps its own node.
        let mut path = [0; 16];
        let _ = crate::linux_overlay::unlink_path(node_path(index, &mut path));
    } else {
        entry.slaves = entry.slaves.saturating_sub(1);
        if entry.slaves == 0 {
            entry.pair.close_slave();
            entry.exclusive = false;
        }
    }
    if !entry.master_open && entry.slaves == 0 {
        *slot = None;
    }
}
