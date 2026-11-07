//! The descriptors a process holds above the fixed part of its descriptor
//! table, which raising RLIMIT_NOFILE (up to /proc/sys/fs/nr_open) lets it
//! open: each table holds only the descriptors in use, so a process that
//! never goes past the fixed part has none.
//!
//! A process's descriptor state names its table by id (0: none). Processes
//! that share a descriptor table (CLONE_FILES) name the same one. A copy of
//! a process's descriptors (a fork, an unshare, an exec) takes a reference
//! to the table ([`retain`]) instead of copying it: the first change through
//! a table with more than one reference copies it first ([`copy`], copy on
//! write), and dropping the last reference frees it ([`release`]). What an
//! entry refers to (a socket, a queue) is held once per table: the caller
//! holds it again for a copy and lets go of it when a table is freed.
#![forbid(unsafe_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

/// One descriptor, as the fixed part keeps one in its parallel arrays.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Entry {
    /// The descriptor's kind and access bits (cpu.rs's device states).
    pub(crate) state: u16,
    /// The image entry it has open (0: none).
    pub(crate) rootfs: u16,
    /// Its socket slot + 1 (0: none): pipes and sockets.
    pub(crate) socket: u16,
    pub(crate) socket_flags: u32,
    /// The overlay node (or tmpfs file) generation it has open.
    pub(crate) generation: u32,
    /// Its file offset, or the identity of what it refers to.
    pub(crate) offset: u64,
    /// Its open file description's id (0: none yet).
    pub(crate) open_file_id: u64,
    pub(crate) close_on_exec: bool,
    /// Its open created the file (F_CREATED_QUERY).
    pub(crate) created: bool,
}

struct Table {
    /// The domain whose processes hold it.
    domain: usize,
    /// The descriptor states naming it as copies of their own (sharers
    /// under CLONE_FILES count once).
    references: u32,
    entries: BTreeMap<u64, Entry>,
}

struct Tables {
    /// Tables by id - 1 (`None`: free).
    tables: Vec<Option<Table>>,
}

static TABLES: SpinLock<Tables> =
    SpinLock::new(LockRank::DESCRIPTOR_TABLES, Tables { tables: Vec::new() });
/// How many tables exist, across domains: none spares the descriptor
/// paths that would look in one (an offset change, a scan of a process's
/// descriptors).
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Whether any table exists.
pub(crate) fn active() -> bool {
    LIVE.load(Ordering::Relaxed) != 0
}

impl Tables {
    fn table(&mut self, id: u32) -> Option<&mut Table> {
        self.tables.get_mut(id.checked_sub(1)? as usize)?.as_mut()
    }

    fn insert(&mut self, table: Table) -> Option<u32> {
        let index = match self.tables.iter().position(Option::is_none) {
            Some(index) => index,
            None => {
                self.tables.try_reserve(1).ok()?;
                self.tables.push(None);
                self.tables.len() - 1
            }
        };
        self.tables[index] = Some(table);
        LIVE.fetch_add(1, Ordering::Relaxed);
        u32::try_from(index + 1).ok()
    }
}

/// A new, empty table's id, for a process of domain `domain`.
pub(crate) fn create(domain: usize) -> Option<u32> {
    TABLES.lock().insert(Table {
        domain,
        references: 1,
        entries: BTreeMap::new(),
    })
}

/// Descriptor `descriptor` of table `id`.
pub(crate) fn get(id: u32, descriptor: u64) -> Option<Entry> {
    if id == 0 {
        return None;
    }
    TABLES.lock().table(id)?.entries.get(&descriptor).copied()
}

/// Sets descriptor `descriptor` of table `id`; false without memory or
/// without the table.
pub(crate) fn set(id: u32, descriptor: u64, entry: Entry) -> bool {
    let mut tables = TABLES.lock();
    let Some(table) = tables.table(id) else {
        return false;
    };
    table.entries.insert(descriptor, entry);
    true
}

/// Changes descriptor `descriptor` of table `id`, if it is open there.
pub(crate) fn update(id: u32, descriptor: u64, change: impl FnOnce(&mut Entry)) -> bool {
    let mut tables = TABLES.lock();
    let Some(entry) = tables
        .table(id)
        .and_then(|table| table.entries.get_mut(&descriptor))
    else {
        return false;
    };
    change(entry);
    true
}

/// Takes descriptor `descriptor` out of table `id`.
pub(crate) fn remove(id: u32, descriptor: u64) -> Option<Entry> {
    TABLES.lock().table(id)?.entries.remove(&descriptor)
}

/// The lowest descriptor from `first` below `limit` that table `id` (if
/// any) does not hold.
pub(crate) fn first_free(id: u32, first: u64, limit: u64) -> Option<u64> {
    let mut tables = TABLES.lock();
    let Some(table) = tables.table(id) else {
        return (first < limit).then_some(first);
    };
    let mut candidate = first;
    for descriptor in table
        .entries
        .range(first..)
        .map(|(descriptor, _)| *descriptor)
    {
        if descriptor != candidate {
            break;
        }
        candidate += 1;
    }
    (candidate < limit).then_some(candidate)
}

/// The descriptors of table `id`, in order.
pub(crate) fn entries(id: u32) -> Vec<(u64, Entry)> {
    let mut tables = TABLES.lock();
    let Some(table) = tables.table(id) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    if entries.try_reserve_exact(table.entries.len()).is_ok() {
        entries.extend(
            table
                .entries
                .iter()
                .map(|(descriptor, entry)| (*descriptor, *entry)),
        );
    }
    entries
}

/// A copy of table `id` under a new id (0 for no table), for a process
/// that stops sharing it; None without memory.
pub(crate) fn copy(id: u32) -> Option<u32> {
    if id == 0 {
        return Some(0);
    }
    let mut tables = TABLES.lock();
    let table = tables.table(id)?;
    let (domain, entries) = (table.domain, table.entries.clone());
    tables.insert(Table {
        domain,
        references: 1,
        entries,
    })
}

/// Another descriptor state names table `id` as a copy of its own.
pub(crate) fn retain(id: u32) -> bool {
    let mut tables = TABLES.lock();
    let Some(table) = tables.table(id) else {
        return false;
    };
    table.references += 1;
    true
}

/// A descriptor state that named table `id` as its own no longer does:
/// the last one frees it, giving back its descriptors for the caller to
/// let go of what they refer to (none while other references remain).
pub(crate) fn release(id: u32) -> Vec<(u64, Entry)> {
    {
        let mut tables = TABLES.lock();
        let Some(table) = tables.table(id) else {
            return Vec::new();
        };
        if table.references > 1 {
            table.references -= 1;
            return Vec::new();
        }
    }
    free(id)
}

/// Whether table `id` has more than one reference, so a change through
/// one of them copies it first.
pub(crate) fn shared(id: u32) -> bool {
    TABLES
        .lock()
        .table(id)
        .is_some_and(|table| table.references > 1)
}

/// Frees table `id`, giving back its descriptors for the caller to let go
/// of what they refer to.
pub(crate) fn free(id: u32) -> Vec<(u64, Entry)> {
    let mut tables = TABLES.lock();
    let Some(slot) = id
        .checked_sub(1)
        .and_then(|index| tables.tables.get_mut(index as usize))
    else {
        return Vec::new();
    };
    let Some(table) = slot.take() else {
        return Vec::new();
    };
    LIVE.fetch_sub(1, Ordering::Relaxed);
    table.entries.into_iter().collect()
}

/// Every table's descriptors of open file `open_file_id` get `offset`: the
/// file offset is the open file description's, which descriptors in
/// several tables (after a fork) share.
pub(crate) fn sync_offset(open_file_id: u64, offset: u64) {
    if open_file_id == 0 || !active() {
        return;
    }
    let mut tables = TABLES.lock();
    for table in tables.tables.iter_mut().flatten() {
        for entry in table.entries.values_mut() {
            if entry.open_file_id == open_file_id {
                entry.offset = offset;
            }
        }
    }
}

/// Domain `domain` stopped: its processes' tables go (what they referred
/// to went with the domain).
pub(crate) fn forget_domain(domain: usize) {
    let mut tables = TABLES.lock();
    for slot in &mut tables.tables {
        if slot.as_ref().is_some_and(|table| table.domain == domain) {
            *slot = None;
            LIVE.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
