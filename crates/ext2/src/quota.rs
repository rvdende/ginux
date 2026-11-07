//! Disk quotas: per user, group and project usage (bytes and inodes) and
//! limits, kept in quota files of the VFS v2 format (`vfsv0` and `vfsv1`),
//! as Linux and the quota tools keep them.
//!
//! A quota file is a regular file on the filesystem: either one quotaon(2)
//! names (`aquota.user`, made by quotacheck) or, with ext4's `quota`
//! feature, a hidden system inode the superblock names. The file is made
//! of 1 KiB blocks: block 0 holds a header (magic, version) and the file
//! information (grace times, flags, block count and the heads of two free
//! lists); block 1 roots a four-level radix tree indexed by the id's bytes,
//! whose leaves point at data blocks; a data block (a 16-byte header with
//! free-list links and its entry count) holds fixed-size entries, one per
//! id (48 bytes in vfsv0, 72 in vfsv1).
//!
//! While quotas are on, every change to a counted inode's blocks, owner
//! or existence adjusts the usage of its ids in memory; the changed entries
//! go to the file at sync and when quotas go off. With limits enforced, an
//! allocation past a hard limit, or past a soft limit whose grace time has
//! run out, is EDQUOT, unless the caller is exempt (CAP_SYS_RESOURCE).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::bytes::{set_u16, set_u32, u16_at, u32_at};
use crate::inode::Inode;
use crate::{BlockDevice, Error, Filesystem, Result, Timestamp, ROOT_INODE};

/// The quota file's block size, whatever the filesystem's.
const BLOCK: usize = 1024;
/// The tree's root block and depth.
const TREE_ROOT: u32 = 1;
const TREE_DEPTH: u32 = 4;
/// A data block's header.
const DATA_HEADER: usize = 16;
/// The file information, after the 8-byte header in block 0.
const INFO_OFFSET: usize = 8;
/// Limits are kept in 1 KiB quota blocks on the disk.
const QUOTA_BLOCK_BITS: u32 = 10;

/// Whose usage a quota counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum QuotaKind {
    User,
    Group,
    Project,
}

impl QuotaKind {
    pub const ALL: [Self; 3] = [Self::User, Self::Group, Self::Project];

    /// quotactl(2)'s type number (USRQUOTA, GRPQUOTA, PRJQUOTA).
    pub const fn from_type(kind: u32) -> Option<Self> {
        match kind {
            0 => Some(Self::User),
            1 => Some(Self::Group),
            2 => Some(Self::Project),
            _ => None,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }

    /// The quota file magic for this kind.
    const fn magic(self) -> u32 {
        match self {
            Self::User => 0xd9c0_1f11,
            Self::Group => 0xd9c0_1927,
            Self::Project => 0xd9c0_3f14,
        }
    }
}

/// A quota file format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaFormat {
    /// QFMT_VFS_V0: 32-bit limits and counts.
    V0,
    /// QFMT_VFS_V1: 64-bit limits and counts.
    V1,
}

impl QuotaFormat {
    /// The format of quotactl(2)'s format id (QFMT_VFS_V0 2, QFMT_VFS_V1 4).
    pub const fn from_id(id: u32) -> Option<Self> {
        match id {
            2 => Some(Self::V0),
            4 => Some(Self::V1),
            _ => None,
        }
    }

    pub const fn id(self) -> u32 {
        match self {
            Self::V0 => 2,
            Self::V1 => 4,
        }
    }

    const fn version(self) -> u32 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
        }
    }

    const fn entry_size(self) -> usize {
        match self {
            Self::V0 => 48,
            Self::V1 => 72,
        }
    }

    const fn entries_per_block(self) -> usize {
        (BLOCK - DATA_HEADER) / self.entry_size()
    }

    /// The largest space limit, in bytes, and inode limit the format holds.
    pub const fn max_space(self) -> u64 {
        match self {
            Self::V0 => 0xffff_ffff << QUOTA_BLOCK_BITS,
            Self::V1 => i64::MAX as u64,
        }
    }

    pub const fn max_inodes(self) -> u64 {
        match self {
            Self::V0 => 0xffff_ffff,
            Self::V1 => i64::MAX as u64,
        }
    }
}

/// One id's usage and limits; space in bytes, times in seconds since the
/// epoch (0: no grace period running).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dquot {
    pub space_hard: u64,
    pub space_soft: u64,
    pub space: u64,
    pub inode_hard: u64,
    pub inode_soft: u64,
    pub inodes: u64,
    pub space_timer: u64,
    pub inode_timer: u64,
}

/// Which fields Q_SETQUOTA sets.
#[derive(Clone, Copy, Debug, Default)]
pub struct DquotChange {
    pub space_hard: Option<u64>,
    pub space_soft: Option<u64>,
    pub space: Option<u64>,
    pub inode_hard: Option<u64>,
    pub inode_soft: Option<u64>,
    pub inodes: Option<u64>,
    pub space_timer: Option<u64>,
    pub inode_timer: Option<u64>,
}

/// A quota kind's state (Q_GETINFO, Q_GETFMT).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaInfo {
    pub format: QuotaFormat,
    pub space_grace: u64,
    pub inode_grace: u64,
    /// The file's flags (DQF_*).
    pub flags: u32,
    /// A hidden system file (ext4's quota feature).
    pub system_file: bool,
    /// Limits are enforced, not only usage counted.
    pub enforced: bool,
}

/// Which quotas a mount asks for (usrquota, grpquota, prjquota; quota is
/// usrquota).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaOptions {
    pub user: bool,
    pub group: bool,
    pub project: bool,
}

impl QuotaOptions {
    pub fn any(&self) -> bool {
        self.user || self.group || self.project
    }

    fn get(&self, kind: QuotaKind) -> bool {
        match kind {
            QuotaKind::User => self.user,
            QuotaKind::Group => self.group,
            QuotaKind::Project => self.project,
        }
    }
}

/// The file information block.
#[derive(Clone, Copy, Debug)]
struct FileInfo {
    space_grace: u32,
    inode_grace: u32,
    flags: u32,
    blocks: u32,
    free_block: u32,
    free_entry: u32,
}

struct Entry {
    dquot: Dquot,
    /// Where the entry lies in the file, once it has one.
    offset: Option<u64>,
    dirty: bool,
}

/// A loaded quota file.
struct Loaded {
    format: QuotaFormat,
    inode: u32,
    system: bool,
    enforced: bool,
    info: FileInfo,
    info_dirty: bool,
    entries: BTreeMap<u32, Entry>,
}

/// The filesystem's quota state.
#[derive(Default)]
pub(crate) struct Quotas {
    loaded: [Option<Loaded>; 3],
    pub(crate) options: QuotaOptions,
    /// Inodes allocated since they were last written: the first write
    /// counts them, not a difference from what the table held.
    fresh: BTreeSet<u32>,
    /// What the current allocation may still use, in bytes.
    pub(crate) budget: Option<u64>,
    exempt: bool,
    pub(crate) now: u64,
}

impl Quotas {
    pub(crate) fn new(options: QuotaOptions) -> Self {
        Self {
            options,
            ..Self::default()
        }
    }

    pub(crate) fn any_loaded(&self) -> bool {
        self.loaded.iter().any(Option::is_some)
    }

    pub(crate) fn is_quota_file(&self, number: u32) -> bool {
        self.loaded
            .iter()
            .flatten()
            .any(|loaded| loaded.inode == number)
    }

    pub(crate) fn note_fresh(&mut self, number: u32) {
        if self.any_loaded() {
            self.fresh.insert(number);
        }
    }
}

/// An entry's on-disk bytes, and back.
fn encode(format: QuotaFormat, id: u32, dquot: &Dquot) -> [u8; 72] {
    let mut bytes = [0_u8; 72];
    let blocks = |space: u64| space.div_ceil(1 << QUOTA_BLOCK_BITS);
    let put64 = |bytes: &mut [u8], at: usize, value: u64| {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes())
    };
    set_u32(&mut bytes, 0, id);
    match format {
        QuotaFormat::V0 => {
            set_u32(&mut bytes, 4, dquot.inode_hard as u32);
            set_u32(&mut bytes, 8, dquot.inode_soft as u32);
            set_u32(&mut bytes, 12, dquot.inodes as u32);
            set_u32(&mut bytes, 16, blocks(dquot.space_hard) as u32);
            set_u32(&mut bytes, 20, blocks(dquot.space_soft) as u32);
            put64(&mut bytes, 24, dquot.space);
            put64(&mut bytes, 32, dquot.space_timer);
            put64(&mut bytes, 40, dquot.inode_timer);
        }
        QuotaFormat::V1 => {
            put64(&mut bytes, 8, dquot.inode_hard);
            put64(&mut bytes, 16, dquot.inode_soft);
            put64(&mut bytes, 24, dquot.inodes);
            put64(&mut bytes, 32, blocks(dquot.space_hard));
            put64(&mut bytes, 40, blocks(dquot.space_soft));
            put64(&mut bytes, 48, dquot.space);
            put64(&mut bytes, 56, dquot.space_timer);
            put64(&mut bytes, 64, dquot.inode_timer);
        }
    }
    // An all-zero entry is a free one: id 0 with nothing marks itself.
    let size = format.entry_size();
    if bytes[..size].iter().all(|byte| *byte == 0) {
        let at = size - 8;
        put64(&mut bytes, at, 1);
    }
    bytes
}

fn decode(format: QuotaFormat, bytes: &[u8]) -> (u32, Dquot) {
    let get64 = |at: usize| {
        let mut word = [0_u8; 8];
        word.copy_from_slice(&bytes[at..at + 8]);
        u64::from_le_bytes(word)
    };
    let space = |blocks: u64| blocks.saturating_mul(1 << QUOTA_BLOCK_BITS);
    let id = u32_at(bytes, 0);
    let mut dquot = match format {
        QuotaFormat::V0 => Dquot {
            inode_hard: u64::from(u32_at(bytes, 4)),
            inode_soft: u64::from(u32_at(bytes, 8)),
            inodes: u64::from(u32_at(bytes, 12)),
            space_hard: space(u64::from(u32_at(bytes, 16))),
            space_soft: space(u64::from(u32_at(bytes, 20))),
            space: get64(24),
            space_timer: get64(32),
            inode_timer: get64(40),
        },
        QuotaFormat::V1 => Dquot {
            inode_hard: get64(8),
            inode_soft: get64(16),
            inodes: get64(24),
            space_hard: space(get64(32)),
            space_soft: space(get64(40)),
            space: get64(48),
            space_timer: get64(56),
            inode_timer: get64(64),
        },
    };
    // The marker of an otherwise empty entry.
    let rest = Dquot {
        inode_timer: 0,
        ..dquot
    };
    if dquot.inode_timer == 1 && rest == Dquot::default() {
        dquot.inode_timer = 0;
    }
    (id, dquot)
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// The quota id of each kind an inode is charged to.
pub(crate) fn owners(inode: &Inode) -> [u32; 3] {
    [inode.owner(), inode.group(), inode.project()]
}

impl<D: BlockDevice> Filesystem<D> {
    /// Tells the filesystem the time and whether the caller may exceed
    /// quota limits (CAP_SYS_RESOURCE), for the operations that follow.
    pub fn set_caller(&mut self, now: Timestamp, quota_exempt: bool) {
        self.quotas.now = now.seconds.max(0) as u64;
        self.quotas.exempt = quota_exempt;
    }

    /// The quota options the filesystem was mounted with.
    pub fn quota_options(&self) -> QuotaOptions {
        self.quotas.options
    }

    /// Whether quotas live in hidden system inodes (ext4's quota feature):
    /// they count from the mount, and quotaon(2) only enforces them.
    pub fn quota_system_files(&self) -> bool {
        self.superblock.quota()
    }

    /// The kinds of quota the filesystem can keep.
    pub fn quota_kinds(&self) -> &'static [QuotaKind] {
        if self.superblock.project() || self.superblock.extents() {
            &QuotaKind::ALL
        } else {
            &QuotaKind::ALL[..2]
        }
    }

    /// Whether inode `number` counts toward quotas: the root and every
    /// inode past the reserved ones, but no quota file.
    pub(crate) fn quota_counted(&self, number: u32) -> bool {
        (number == ROOT_INODE || number >= self.superblock.first_inode())
            && !self.quotas.is_quota_file(number)
            && !self.superblock.quota_inodes().contains(&number)
    }

    /// Loads the system quota files at mount (the quota feature).
    pub(crate) fn load_system_quotas(&mut self) -> Result<()> {
        if !self.superblock.quota() {
            return Ok(());
        }
        for kind in QuotaKind::ALL {
            let number = self.superblock.quota_inodes()[kind.index()];
            if number == 0 {
                continue;
            }
            let enforced = self.quotas.options.get(kind);
            self.load_quota(kind, number, QuotaFormat::V1, true, enforced)?;
        }
        Ok(())
    }

    fn load_quota(
        &mut self,
        kind: QuotaKind,
        number: u32,
        format: QuotaFormat,
        system: bool,
        enforced: bool,
    ) -> Result<()> {
        let header = self.read_quota_block(number, 0)?;
        if u32_at(&header, 0) != kind.magic() || u32_at(&header, 4) != format.version() {
            return Err(Error::Invalid);
        }
        let at = INFO_OFFSET;
        let info = FileInfo {
            space_grace: u32_at(&header, at),
            inode_grace: u32_at(&header, at + 4),
            flags: u32_at(&header, at + 8),
            blocks: u32_at(&header, at + 12),
            free_block: u32_at(&header, at + 16),
            free_entry: u32_at(&header, at + 20),
        };
        let mut data_blocks = BTreeSet::new();
        let mut pending: Vec<(u32, u32)> = Vec::new();
        pending.push((TREE_ROOT, 0));
        let mut seen = BTreeSet::new();
        while let Some((block, depth)) = pending.pop() {
            if block >= info.blocks.max(TREE_ROOT + 1) || !seen.insert((block, depth)) {
                return Err(Error::Corrupt);
            }
            let bytes = self.read_quota_block(number, block)?;
            for index in 0..BLOCK / 4 {
                let reference = u32_at(&bytes, index * 4);
                if reference == 0 {
                    continue;
                }
                if depth + 1 < TREE_DEPTH {
                    pending.try_reserve(1).map_err(|_| Error::NoMemory)?;
                    pending.push((reference, depth + 1));
                } else {
                    data_blocks.insert(reference);
                }
            }
        }
        let mut entries = BTreeMap::new();
        let size = format.entry_size();
        for block in data_blocks {
            if block >= info.blocks {
                return Err(Error::Corrupt);
            }
            let bytes = self.read_quota_block(number, block)?;
            for slot in 0..format.entries_per_block() {
                let at = DATA_HEADER + slot * size;
                let raw = &bytes[at..at + size];
                if all_zero(raw) {
                    continue;
                }
                let (id, dquot) = decode(format, raw);
                entries.insert(
                    id,
                    Entry {
                        dquot,
                        offset: Some(u64::from(block) * BLOCK as u64 + at as u64),
                        dirty: false,
                    },
                );
            }
        }
        self.quotas.loaded[kind.index()] = Some(Loaded {
            format,
            inode: number,
            system,
            enforced,
            info,
            info_dirty: false,
            entries,
        });
        Ok(())
    }

    fn read_quota_block(&mut self, number: u32, block: u32) -> Result<[u8; BLOCK]> {
        let mut bytes = [0_u8; BLOCK];
        let read = self.read(number, u64::from(block) * BLOCK as u64, &mut bytes)?;
        bytes[read..].fill(0);
        Ok(bytes)
    }

    fn write_quota_bytes(&mut self, number: u32, offset: u64, data: &[u8]) -> Result<()> {
        let mut done = 0;
        while done < data.len() {
            let written = self.write(number, offset + done as u64, &data[done..])?;
            if written == 0 {
                return Err(Error::NoSpace);
            }
            done += written;
        }
        Ok(())
    }

    fn loaded(&self, kind: QuotaKind) -> Result<&Loaded> {
        self.quotas.loaded[kind.index()]
            .as_ref()
            .ok_or(Error::NoQuota)
    }

    fn loaded_mut(&mut self, kind: QuotaKind) -> Result<&mut Loaded> {
        self.quotas.loaded[kind.index()]
            .as_mut()
            .ok_or(Error::NoQuota)
    }

    /// Q_QUOTAON with a quota file (no quota feature): quota inode
    /// `number`, in `format`, counts and enforces quotas of `kind`. The
    /// file becomes immutable and is not counted itself.
    pub fn quota_on(&mut self, kind: QuotaKind, number: u32, format_id: u32) -> Result<()> {
        if !self.quotas.options.any() {
            return Err(Error::Invalid);
        }
        if self.quotas.is_quota_file(number) {
            return Err(Error::Busy);
        }
        let inode = self.live_inode(number)?;
        if inode.kind() != Some(crate::Kind::File) {
            return Err(Error::Access);
        }
        if self.read_only() {
            return Err(Error::ReadOnly);
        }
        if self.quotas.loaded[kind.index()].is_some() {
            return Err(Error::Busy);
        }
        let format = QuotaFormat::from_id(format_id).ok_or(Error::NoQuota)?;
        self.load_quota(kind, number, format, false, true)?;
        let mut inode = self.live_inode(number)?;
        inode.set_flags(inode.flags() | crate::inode::IMMUTABLE_FL | crate::inode::NOATIME_FL);
        self.write_inode(number, &inode)
    }

    /// Q_QUOTAOFF: writes `kind`'s quotas back and stops keeping them (a
    /// quota file is an ordinary file again). Nothing to do when off.
    pub fn quota_off(&mut self, kind: QuotaKind, now: Timestamp) -> Result<()> {
        let Some(number) = self.quotas.loaded[kind.index()]
            .as_ref()
            .map(|loaded| loaded.inode)
        else {
            return Ok(());
        };
        self.sync_quota(kind)?;
        self.quotas.loaded[kind.index()] = None;
        if !self.read_only() {
            let mut inode = self.live_inode(number)?;
            inode.set_flags(
                inode.flags() & !(crate::inode::IMMUTABLE_FL | crate::inode::NOATIME_FL),
            );
            inode.set_time(crate::inode::Time::Modify, now);
            inode.set_time(crate::inode::Time::Change, now);
            self.write_inode(number, &inode)?;
        }
        if !self.quotas.any_loaded() {
            self.quotas.fresh.clear();
        }
        Ok(())
    }

    /// Q_QUOTAON on system quota files: enforces `kind`'s limits (EEXIST
    /// if they are already; EINVAL when the kind is not counted).
    pub fn quota_enable(&mut self, kind: QuotaKind) -> Result<()> {
        if !self.superblock.quota() {
            return Err(Error::NoSys);
        }
        let loaded = self.quotas.loaded[kind.index()]
            .as_mut()
            .ok_or(Error::Invalid)?;
        if loaded.enforced {
            return Err(Error::Exists);
        }
        loaded.enforced = true;
        Ok(())
    }

    /// Q_QUOTAOFF on system quota files: stops enforcing `kind`'s limits
    /// (counting goes on; EEXIST if they were not enforced).
    pub fn quota_disable(&mut self, kind: QuotaKind) -> Result<()> {
        if !self.superblock.quota() {
            return Err(Error::NoSys);
        }
        match self.quotas.loaded[kind.index()].as_mut() {
            Some(loaded) if loaded.enforced => {
                loaded.enforced = false;
                self.sync_quota(kind)
            }
            _ => Err(Error::Exists),
        }
    }

    /// Q_GETINFO and Q_GETFMT (ESRCH while off).
    pub fn quota_info(&self, kind: QuotaKind) -> Result<QuotaInfo> {
        let loaded = self.loaded(kind)?;
        Ok(QuotaInfo {
            format: loaded.format,
            space_grace: u64::from(loaded.info.space_grace),
            inode_grace: u64::from(loaded.info.inode_grace),
            flags: loaded.info.flags,
            system_file: loaded.system,
            enforced: loaded.enforced,
        })
    }

    /// Q_SETINFO: the grace times (written at once).
    pub fn set_quota_info(
        &mut self,
        kind: QuotaKind,
        space_grace: Option<u64>,
        inode_grace: Option<u64>,
    ) -> Result<()> {
        let loaded = self.loaded_mut(kind)?;
        if let Some(grace) = space_grace {
            loaded.info.space_grace = grace.min(u64::from(u32::MAX)) as u32;
        }
        if let Some(grace) = inode_grace {
            loaded.info.inode_grace = grace.min(u64::from(u32::MAX)) as u32;
        }
        loaded.info_dirty = true;
        self.write_quota_info(kind)
    }

    /// Q_GETQUOTA: `id`'s usage and limits (zeros for an id with none).
    pub fn get_quota(&self, kind: QuotaKind, id: u32) -> Result<Dquot> {
        Ok(self
            .loaded(kind)?
            .entries
            .get(&id)
            .map(|entry| entry.dquot)
            .unwrap_or_default())
    }

    /// Q_GETNEXTQUOTA: the first id from `id` on that has an entry (ESRCH
    /// if none).
    pub fn next_quota_id(&self, kind: QuotaKind, id: u32) -> Result<u32> {
        self.loaded(kind)?
            .entries
            .range(id..)
            .find(|(_, entry)| entry.dquot != Dquot::default() || entry.offset.is_some())
            .map(|(id, _)| *id)
            .ok_or(Error::NoQuota)
    }

    /// Q_SETQUOTA: sets `change`'s fields of `id` (ERANGE past what the
    /// format holds), and restarts or clears the grace timers as limits
    /// and usage now stand. Written at once.
    pub fn set_quota(&mut self, kind: QuotaKind, id: u32, change: &DquotChange) -> Result<()> {
        let now = self.quotas.now;
        let loaded = self.loaded_mut(kind)?;
        let (max_space, max_inodes) = (loaded.format.max_space(), loaded.format.max_inodes());
        if change.space_soft.is_some_and(|limit| limit > max_space)
            || change.space_hard.is_some_and(|limit| limit > max_space)
            || change.inode_soft.is_some_and(|limit| limit > max_inodes)
            || change.inode_hard.is_some_and(|limit| limit > max_inodes)
        {
            return Err(Error::Range);
        }
        let (space_grace, inode_grace) = (
            u64::from(loaded.info.space_grace),
            u64::from(loaded.info.inode_grace),
        );
        let entry = loaded.entries.entry(id).or_insert(Entry {
            dquot: Dquot::default(),
            offset: None,
            dirty: false,
        });
        let dquot = &mut entry.dquot;
        let space_checked = change.space.is_some()
            || change.space_soft.is_some()
            || change.space_hard.is_some()
            || change.space_timer.is_some();
        let inodes_checked = change.inodes.is_some()
            || change.inode_soft.is_some()
            || change.inode_hard.is_some()
            || change.inode_timer.is_some();
        for (field, value) in [
            (&mut dquot.space, change.space),
            (&mut dquot.space_soft, change.space_soft),
            (&mut dquot.space_hard, change.space_hard),
            (&mut dquot.inodes, change.inodes),
            (&mut dquot.inode_soft, change.inode_soft),
            (&mut dquot.inode_hard, change.inode_hard),
            (&mut dquot.space_timer, change.space_timer),
            (&mut dquot.inode_timer, change.inode_timer),
        ] {
            if let Some(value) = value {
                *field = value;
            }
        }
        if space_checked {
            if dquot.space_soft == 0 || dquot.space <= dquot.space_soft {
                dquot.space_timer = 0;
            } else if change.space_timer.is_none() {
                dquot.space_timer = now + space_grace;
            }
        }
        if inodes_checked {
            if dquot.inode_soft == 0 || dquot.inodes <= dquot.inode_soft {
                dquot.inode_timer = 0;
            } else if change.inode_timer.is_none() {
                dquot.inode_timer = now + inode_grace;
            }
        }
        entry.dirty = true;
        self.write_dquot(kind, id)
    }

    /// Q_SYNC: every quota's changed entries and information to the files.
    pub fn quota_sync(&mut self) -> Result<()> {
        for kind in QuotaKind::ALL {
            if self.quotas.loaded[kind.index()].is_some() {
                self.sync_quota(kind)?;
            }
        }
        Ok(())
    }

    fn sync_quota(&mut self, kind: QuotaKind) -> Result<()> {
        if self.read_only() || self.is_shut_down() {
            return Ok(());
        }
        let dirty: Vec<u32> = self
            .loaded(kind)?
            .entries
            .iter()
            .filter(|(_, entry)| entry.dirty)
            .map(|(id, _)| *id)
            .collect();
        for id in dirty {
            self.write_dquot(kind, id)?;
        }
        if self.loaded(kind)?.info_dirty {
            self.write_quota_info(kind)?;
        }
        Ok(())
    }

    fn write_quota_info(&mut self, kind: QuotaKind) -> Result<()> {
        if self.read_only() || self.is_shut_down() {
            return Ok(());
        }
        let loaded = self.loaded(kind)?;
        let info = loaded.info;
        let number = loaded.inode;
        let mut bytes = [0_u8; 24];
        for (index, value) in [
            info.space_grace,
            info.inode_grace,
            info.flags,
            info.blocks,
            info.free_block,
            info.free_entry,
        ]
        .into_iter()
        .enumerate()
        {
            set_u32(&mut bytes, index * 4, value);
        }
        self.write_quota_bytes(number, INFO_OFFSET as u64, &bytes)?;
        self.loaded_mut(kind)?.info_dirty = false;
        Ok(())
    }

    /// Writes `id`'s entry of `kind`, giving it a place in the file first
    /// if it has none (an entry that is all zeros and has none stays out).
    fn write_dquot(&mut self, kind: QuotaKind, id: u32) -> Result<()> {
        if self.read_only() || self.is_shut_down() {
            return Ok(());
        }
        let loaded = self.loaded(kind)?;
        let Some(entry) = loaded.entries.get(&id) else {
            return Ok(());
        };
        let (format, number, dquot, offset) =
            (loaded.format, loaded.inode, entry.dquot, entry.offset);
        let offset = match offset {
            Some(offset) => offset,
            None if dquot == Dquot::default() => {
                if let Some(entry) = self.loaded_mut(kind)?.entries.get_mut(&id) {
                    entry.dirty = false;
                }
                return Ok(());
            }
            None => self.insert_dquot(kind, id)?,
        };
        let bytes = encode(format, id, &dquot);
        self.write_quota_bytes(number, offset, &bytes[..format.entry_size()])?;
        if let Some(entry) = self.loaded_mut(kind)?.entries.get_mut(&id) {
            entry.offset = Some(offset);
            entry.dirty = false;
        }
        if self.loaded(kind)?.info_dirty {
            self.write_quota_info(kind)?;
        }
        Ok(())
    }

    /// A block of the quota file for the tree or data: from the free
    /// list, else past the end.
    fn new_quota_block(&mut self, kind: QuotaKind) -> Result<u32> {
        let (number, free) = {
            let loaded = self.loaded(kind)?;
            (loaded.inode, loaded.info.free_block)
        };
        let block = if free != 0 {
            let bytes = self.read_quota_block(number, free)?;
            self.loaded_mut(kind)?.info.free_block = u32_at(&bytes, 0);
            free
        } else {
            let loaded = self.loaded_mut(kind)?;
            let block = loaded.info.blocks;
            loaded.info.blocks += 1;
            block
        };
        self.loaded_mut(kind)?.info_dirty = true;
        self.write_quota_bytes(number, u64::from(block) * BLOCK as u64, &[0; BLOCK])?;
        Ok(block)
    }

    /// Makes room in the tree for `id`'s entry; returns its offset.
    fn insert_dquot(&mut self, kind: QuotaKind, id: u32) -> Result<u64> {
        let number = self.loaded(kind)?.inode;
        let mut block = TREE_ROOT;
        for depth in 0..TREE_DEPTH {
            let mut bytes = self.read_quota_block(number, block)?;
            let index = ((id >> ((TREE_DEPTH - 1 - depth) * 8)) & 0xff) as usize;
            let reference = u32_at(&bytes, index * 4);
            if depth + 1 < TREE_DEPTH {
                block = if reference != 0 {
                    reference
                } else {
                    let new = self.new_quota_block(kind)?;
                    set_u32(&mut bytes, index * 4, new);
                    self.write_quota_bytes(number, u64::from(block) * BLOCK as u64, &bytes)?;
                    new
                };
                continue;
            }
            if reference != 0 {
                return Err(Error::Corrupt);
            }
            let (data, offset) = self.free_dquot_slot(kind)?;
            set_u32(&mut bytes, index * 4, data);
            self.write_quota_bytes(number, u64::from(block) * BLOCK as u64, &bytes)?;
            return Ok(offset);
        }
        Err(Error::Corrupt)
    }

    /// An entry slot in a data block with room (the free-entry list's
    /// first, or a new block): its block and offset in the file.
    fn free_dquot_slot(&mut self, kind: QuotaKind) -> Result<(u32, u64)> {
        let (number, format, head) = {
            let loaded = self.loaded(kind)?;
            (loaded.inode, loaded.format, loaded.info.free_entry)
        };
        let size = format.entry_size();
        let per_block = format.entries_per_block();
        if head == 0 {
            let block = self.new_quota_block(kind)?;
            let mut bytes = [0_u8; BLOCK];
            set_u16(&mut bytes, 8, 1);
            if per_block > 1 {
                let loaded = self.loaded_mut(kind)?;
                loaded.info.free_entry = block;
                loaded.info_dirty = true;
            }
            self.write_quota_bytes(number, u64::from(block) * BLOCK as u64, &bytes)?;
            return Ok((block, u64::from(block) * BLOCK as u64 + DATA_HEADER as u64));
        }
        let mut bytes = self.read_quota_block(number, head)?;
        let slot = (0..per_block)
            .find(|slot| {
                let at = DATA_HEADER + slot * size;
                all_zero(&bytes[at..at + size])
            })
            .ok_or(Error::Corrupt)?;
        let entries = u16_at(&bytes, 8) + 1;
        set_u16(&mut bytes, 8, entries);
        if usize::from(entries) >= per_block {
            // Full: off the free-entry list.
            let next = u32_at(&bytes, 0);
            set_u32(&mut bytes, 0, 0);
            set_u32(&mut bytes, 4, 0);
            if next != 0 {
                let mut following = self.read_quota_block(number, next)?;
                set_u32(&mut following, 4, 0);
                self.write_quota_bytes(number, u64::from(next) * BLOCK as u64, &following)?;
            }
            let loaded = self.loaded_mut(kind)?;
            loaded.info.free_entry = next;
            loaded.info_dirty = true;
        }
        self.write_quota_bytes(number, u64::from(head) * BLOCK as u64, &bytes)?;
        Ok((
            head,
            u64::from(head) * BLOCK as u64 + (DATA_HEADER + slot * size) as u64,
        ))
    }

    /// Adds `space` bytes and `inodes` inodes (either may be negative) to
    /// `ids`' usage, in each kind kept, restarting or clearing the soft
    /// limit timers.
    pub(crate) fn charge_quota(&mut self, ids: [u32; 3], space: i64, inodes: i64) {
        let now = self.quotas.now;
        for kind in QuotaKind::ALL {
            let Some(loaded) = self.quotas.loaded[kind.index()].as_mut() else {
                continue;
            };
            let (space_grace, inode_grace) = (
                u64::from(loaded.info.space_grace),
                u64::from(loaded.info.inode_grace),
            );
            let entry = loaded.entries.entry(ids[kind.index()]).or_insert(Entry {
                dquot: Dquot::default(),
                offset: None,
                dirty: false,
            });
            let dquot = &mut entry.dquot;
            dquot.space = dquot.space.saturating_add_signed(space);
            dquot.inodes = dquot.inodes.saturating_add_signed(inodes);
            if dquot.space_soft == 0 || dquot.space <= dquot.space_soft {
                dquot.space_timer = 0;
            } else if dquot.space_timer == 0 {
                dquot.space_timer = now + space_grace;
            }
            if dquot.inode_soft == 0 || dquot.inodes <= dquot.inode_soft {
                dquot.inode_timer = 0;
            } else if dquot.inode_timer == 0 {
                dquot.inode_timer = now + inode_grace;
            }
            entry.dirty = true;
        }
    }

    /// The bytes `ids` may still allocate under the enforced limits (None:
    /// no limit applies).
    pub(crate) fn quota_room(&self, ids: [u32; 3]) -> Option<u64> {
        if self.quotas.exempt {
            return None;
        }
        let now = self.quotas.now;
        let mut room: Option<u64> = None;
        for kind in QuotaKind::ALL {
            let Some(loaded) = self.quotas.loaded[kind.index()].as_ref() else {
                continue;
            };
            if !loaded.enforced {
                continue;
            }
            let Some(entry) = loaded.entries.get(&ids[kind.index()]) else {
                continue;
            };
            let dquot = &entry.dquot;
            let mut left = u64::MAX;
            if dquot.space_hard != 0 {
                left = left.min(dquot.space_hard.saturating_sub(dquot.space));
            }
            if dquot.space_soft != 0
                && dquot.space >= dquot.space_soft
                && dquot.space_timer != 0
                && now >= dquot.space_timer
            {
                left = 0;
            }
            if left != u64::MAX {
                room = Some(room.map_or(left, |room| room.min(left)));
            }
        }
        room
    }

    /// Whether `ids` may have `inodes` more inodes under the enforced
    /// limits (EDQUOT if not).
    pub(crate) fn quota_inode_room(&self, ids: [u32; 3], inodes: u64) -> Result<()> {
        if self.quotas.exempt {
            return Ok(());
        }
        let now = self.quotas.now;
        for kind in QuotaKind::ALL {
            let Some(loaded) = self.quotas.loaded[kind.index()].as_ref() else {
                continue;
            };
            if !loaded.enforced {
                continue;
            }
            let Some(entry) = loaded.entries.get(&ids[kind.index()]) else {
                continue;
            };
            let dquot = &entry.dquot;
            let total = dquot.inodes.saturating_add(inodes);
            if dquot.inode_hard != 0 && total > dquot.inode_hard {
                return Err(Error::QuotaExceeded);
            }
            if dquot.inode_soft != 0
                && total > dquot.inode_soft
                && dquot.inode_timer != 0
                && now >= dquot.inode_timer
            {
                return Err(Error::QuotaExceeded);
            }
        }
        Ok(())
    }

    /// Accounts a write of inode `number` as `inode`: the change from what
    /// the table holds (or, for a new inode, all of it).
    pub(crate) fn account_inode_write(&mut self, number: u32, inode: &Inode) -> Result<()> {
        if !self.quotas.any_loaded() || !self.quota_counted(number) {
            return Ok(());
        }
        let ids = owners(inode);
        let space = (inode.sectors() * 512) as i64;
        if self.quotas.fresh.remove(&number) {
            self.charge_quota(ids, space, 1);
            return Ok(());
        }
        let old = self.read_inode(number)?;
        let (old_ids, old_space) = (owners(&old), (old.sectors() * 512) as i64);
        if old_ids == ids {
            if space != old_space {
                self.charge_quota(ids, space - old_space, 0);
            }
        } else {
            self.charge_quota(old_ids, -old_space, -1);
            self.charge_quota(ids, space, 1);
        }
        Ok(())
    }

    /// Accounts inode `number`'s freeing.
    pub(crate) fn account_inode_free(&mut self, number: u32) -> Result<()> {
        if !self.quotas.any_loaded() || !self.quota_counted(number) {
            return Ok(());
        }
        if self.quotas.fresh.remove(&number) {
            return Ok(());
        }
        let inode = self.read_inode(number)?;
        self.charge_quota(owners(&inode), -((inode.sectors() * 512) as i64), -1);
        Ok(())
    }

    /// Runs `operation` with the room `inode`'s ids have under quota as
    /// the budget of its allocations.
    pub(crate) fn with_quota_budget<T>(
        &mut self,
        number: u32,
        inode: &Inode,
        operation: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let previous = self.quotas.budget;
        if self.quota_counted(number) {
            self.quotas.budget = self.quota_room(owners(inode));
        }
        let result = operation(self);
        self.quotas.budget = previous;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_round_trip_and_mark_empty_ones() {
        for format in [QuotaFormat::V0, QuotaFormat::V1] {
            let dquot = Dquot {
                space_hard: 4096,
                space_soft: 2048,
                space: 12345,
                inode_hard: 10,
                inode_soft: 5,
                inodes: 3,
                space_timer: 99,
                inode_timer: 7,
            };
            let bytes = encode(format, 1000, &dquot);
            assert_eq!(decode(format, &bytes[..format.entry_size()]), (1000, dquot));
            let empty = encode(format, 0, &Dquot::default());
            assert!(!all_zero(&empty[..format.entry_size()]));
            assert_eq!(
                decode(format, &empty[..format.entry_size()]),
                (0, Dquot::default())
            );
        }
        assert_eq!(QuotaFormat::V0.entries_per_block(), 21);
        assert_eq!(QuotaFormat::V1.entries_per_block(), 14);
    }
}
