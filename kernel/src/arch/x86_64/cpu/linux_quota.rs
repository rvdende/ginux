//! quotactl(2) and quotactl_fd(2) for Linux processes: disk quotas of the
//! ext2/ext3/ext4 volumes (`ginux_ext2` keeps them; `linux_blockfs`
//! reaches the volume). The checks and their order are Linux's
//! (fs/quota/quota.c, fs/quota/dquot.c, fs/ext4/super.c): the type, the
//! device (or descriptor), the filesystem's quota types, the caller's
//! privilege, then the command.

use super::*;

use crate::linux_blockfs::QuotaVolume;
use ginux_ext2::{Dquot, DquotChange, QuotaKind};

const Q_SYNC: u32 = 0x80_0001;
const Q_QUOTAON: u32 = 0x80_0002;
const Q_QUOTAOFF: u32 = 0x80_0003;
const Q_GETFMT: u32 = 0x80_0004;
const Q_GETINFO: u32 = 0x80_0005;
const Q_SETINFO: u32 = 0x80_0006;
const Q_GETQUOTA: u32 = 0x80_0007;
const Q_SETQUOTA: u32 = 0x80_0008;
const Q_GETNEXTQUOTA: u32 = 0x80_0009;
/// XFS-style commands needing no privilege, as Linux lists them.
const Q_XGETQSTAT: u32 = 0x5805;
const Q_XGETQSTATV: u32 = 0x5808;
const Q_XQUOTASYNC: u32 = 0x5807;
const Q_XGETQUOTA: u32 = 0x5803;

/// `struct if_dqblk`'s validity bits and `struct if_dqinfo`'s.
const QIF_BLIMITS: u32 = 1;
const QIF_SPACE: u32 = 2;
const QIF_ILIMITS: u32 = 4;
const QIF_INODES: u32 = 8;
const QIF_BTIME: u32 = 16;
const QIF_ITIME: u32 = 32;
const QIF_ALL: u32 = 63;
const IIF_BGRACE: u32 = 1;
const IIF_IGRACE: u32 = 2;
const IIF_FLAGS: u32 = 4;
const IIF_ALL: u32 = 7;
/// Q_GETINFO's flags: quotas in system files, root squash.
const DQF_ROOT_SQUASH: u32 = 1;
const DQF_SYS_FILE: u32 = 1 << 16;
/// Sizes of `struct if_dqblk`, `struct if_nextdqblk` and `struct
/// if_dqinfo` on x86-64.
const DQBLK_SIZE: usize = 72;
const DQINFO_SIZE: usize = 24;

/// quotactl(cmd, special, id, addr).
pub(super) fn linux_quotactl(command: u64, special: u64, id: u64, address: u64) -> u64 {
    let command = command as u32;
    let (command, kind) = (command >> 8, command & 0xff);
    let Some(kind) = QuotaKind::from_type(kind) else {
        return LINUX_EINVAL;
    };
    if special == 0 {
        if command == Q_SYNC {
            crate::linux_blockfs::quota_sync_all();
            return 0;
        }
        return LINUX_ENODEV;
    }
    // Q_QUOTAON's file is looked up before the device; an error in it is
    // only reported where it matters.
    let file = (command == Q_QUOTAON).then(|| linux_quota_file(address));
    let mut device_path = [0_u8; LINUX_PATH_MAX];
    let length = match copy_linux_c_string(special, &mut device_path) {
        Ok(length) => length,
        Err(error) => return error,
    };
    let mut name = [0_u8; crate::linux_overlay::PATH_CAPACITY + 1];
    let device = match linux_volume_device(&device_path[..length], &mut name) {
        Ok((device, _)) => device,
        Err(error) => return error,
    };
    if !crate::linux_blockfs::device_mounted(device) {
        return LINUX_ENODEV;
    }
    linux_quota_command(
        QuotaVolume::Device(device),
        kind,
        command,
        id as u32,
        address,
        file.unwrap_or(Err(LINUX_EINVAL)),
    )
}

/// quotactl_fd(fd, cmd, id, addr): the volume the descriptor's file is
/// on; a file of no volume (a socket, a pipe, the overlay) has no quota
/// operations (ENOSYS).
pub(super) fn linux_quotactl_fd(descriptor: u64, command: u64, id: u64, address: u64) -> u64 {
    let descriptor = u64::from(descriptor as u32);
    if !linux_descriptor_open(descriptor) {
        return LINUX_EBADF;
    }
    let command = command as u32;
    let (command, kind) = (command >> 8, command & 0xff);
    let Some(kind) = QuotaKind::from_type(kind) else {
        return LINUX_EINVAL;
    };
    let Some(handle) = linux_overlay_descriptor_handle(descriptor)
        .filter(|handle| crate::linux_blockfs::owns(*handle))
    else {
        return LINUX_ENOSYS;
    };
    linux_quota_command(
        QuotaVolume::File(handle),
        kind,
        command,
        id as u32,
        address,
        Err(LINUX_EINVAL),
    )
}

/// The file Q_QUOTAON names, followed.
fn linux_quota_file(address: u64) -> Result<crate::linux_overlay::Handle, u64> {
    let mut path = [0_u8; LINUX_PATH_MAX];
    let length = copy_linux_c_string(address, &mut path)?;
    let mut canonical = [0_u8; crate::linux_overlay::PATH_CAPACITY];
    let length =
        linux_canonical_path_at(u64::from(LINUX_AT_FDCWD), &path[..length], &mut canonical)?;
    match linux_overlay_lookup_following(&mut canonical, length, true)? {
        (_, _, Some(metadata)) => Ok(metadata.handle),
        (length, _, None) => Err(linux_missing_path_error(&canonical[..length])),
    }
}

/// Whether the caller may run `command` for `id` of `kind`: some need no
/// privilege, Q_GETQUOTA is the caller's own for its user or a group it
/// is in, the rest need CAP_SYS_ADMIN.
fn linux_quota_permitted(command: u32, kind: QuotaKind, id: u32) -> bool {
    match command {
        Q_GETFMT | Q_SYNC | Q_GETINFO | Q_XGETQSTAT | Q_XGETQSTATV | Q_XQUOTASYNC => return true,
        Q_GETQUOTA | Q_XGETQUOTA => {
            if let Some(credentials) = current_linux_credentials() {
                let own = match kind {
                    QuotaKind::User => credentials.user.effective == id,
                    QuotaKind::Group => linux_process::with_live_process_groups(
                        current_linux_process_pid(),
                        |groups| credentials.in_group(groups, id),
                    )
                    .unwrap_or(false),
                    QuotaKind::Project => false,
                };
                if own {
                    return true;
                }
            }
        }
        _ => {}
    }
    linux_has_capability(ginux_credentials::capability::SYS_ADMIN)
}

/// The command `command` (`Q_*`, without the type) of `kind` on `volume`.
fn linux_quota_command(
    volume: QuotaVolume,
    kind: QuotaKind,
    command: u32,
    id: u32,
    address: u64,
    file: Result<crate::linux_overlay::Handle, u64>,
) -> u64 {
    let Some(kinds) = crate::linux_blockfs::quota_kinds(volume) else {
        return LINUX_ENODEV;
    };
    if !kinds.contains(&kind) {
        return LINUX_EINVAL;
    }
    if !linux_quota_permitted(command, kind, id) {
        return LINUX_EPERM;
    }
    let errno = |error: crate::linux_blockfs::Errno| error.wrapping_neg();
    let system = crate::linux_blockfs::quota_system_files(volume).unwrap_or(false);
    let result: Result<(), u64> = match command {
        Q_QUOTAON => {
            if system {
                crate::linux_blockfs::quota_enable(volume, kind)
                    .unwrap_or(Err(19))
                    .map_err(errno)
            } else {
                file.and_then(|file| {
                    crate::linux_blockfs::quota_on(volume, kind, file, id)
                        .unwrap_or(Err(19))
                        .map_err(errno)
                })
            }
        }
        Q_QUOTAOFF => crate::linux_blockfs::quota_off(volume, kind)
            .unwrap_or(Err(19))
            .map_err(errno),
        Q_GETFMT => crate::linux_blockfs::quota_info(volume, kind)
            .unwrap_or(Err(19))
            .map_err(errno)
            .and_then(|info| linux_quota_copy_out(address, &info.format.id().to_ne_bytes())),
        Q_GETINFO => crate::linux_blockfs::quota_info(volume, kind)
            .unwrap_or(Err(19))
            .map_err(errno)
            .and_then(|info| {
                let mut bytes = [0_u8; DQINFO_SIZE];
                bytes[0..8].copy_from_slice(&info.space_grace.to_ne_bytes());
                bytes[8..16].copy_from_slice(&info.inode_grace.to_ne_bytes());
                let mut flags = 0;
                if info.system_file {
                    flags |= DQF_SYS_FILE;
                }
                bytes[16..20].copy_from_slice(&flags.to_ne_bytes());
                bytes[20..24].copy_from_slice(&IIF_ALL.to_ne_bytes());
                linux_quota_copy_out(address, &bytes)
            }),
        Q_SETINFO => linux_quota_set_info(volume, kind, address),
        Q_GETQUOTA => crate::linux_blockfs::get_quota(volume, kind, id)
            .unwrap_or(Err(19))
            .map_err(errno)
            .and_then(|dquot| linux_quota_copy_out(address, &linux_dqblk(&dquot, None))),
        Q_GETNEXTQUOTA => crate::linux_blockfs::next_quota(volume, kind, id)
            .unwrap_or(Err(19))
            .map_err(errno)
            .and_then(|(next, dquot)| {
                linux_quota_copy_out(address, &linux_dqblk(&dquot, Some(next)))
            }),
        Q_SETQUOTA => linux_quota_set_quota(volume, kind, id, address),
        Q_SYNC => crate::linux_blockfs::quota_sync(volume)
            .unwrap_or(Err(19))
            .map_err(errno),
        _ => Err(LINUX_EINVAL),
    };
    result.map_or_else(|error| error, |()| 0)
}

fn linux_quota_copy_out(address: u64, bytes: &[u8]) -> Result<(), u64> {
    if copy_to_linux_user(address, bytes) {
        Ok(())
    } else {
        Err(LINUX_EFAULT)
    }
}

/// `struct if_dqblk` (or, with the id, `struct if_nextdqblk`) of `dquot`:
/// space limits in 1 KiB blocks, rounded up, the space itself in bytes.
fn linux_dqblk(dquot: &Dquot, id: Option<u32>) -> [u8; DQBLK_SIZE] {
    let blocks = |space: u64| space.div_ceil(1024);
    let mut bytes = [0_u8; DQBLK_SIZE];
    for (index, value) in [
        blocks(dquot.space_hard),
        blocks(dquot.space_soft),
        dquot.space,
        dquot.inode_hard,
        dquot.inode_soft,
        dquot.inodes,
        dquot.space_timer,
        dquot.inode_timer,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_ne_bytes());
    }
    bytes[64..68].copy_from_slice(&QIF_ALL.to_ne_bytes());
    if let Some(id) = id {
        bytes[68..72].copy_from_slice(&id.to_ne_bytes());
    }
    bytes
}

/// Q_SETINFO: `struct if_dqinfo`'s grace times; root squash is for the
/// old quota format only (EINVAL here).
fn linux_quota_set_info(volume: QuotaVolume, kind: QuotaKind, address: u64) -> Result<(), u64> {
    let mut bytes = [0_u8; DQINFO_SIZE];
    if !copy_from_linux_user(address, &mut bytes) {
        return Err(LINUX_EFAULT);
    }
    let word = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap_or_default());
    let half = |at: usize| u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap_or_default());
    let (space_grace, inode_grace, flags, valid) = (word(0), word(8), half(16), half(20));
    if valid & !(IIF_FLAGS | IIF_BGRACE | IIF_IGRACE) != 0 {
        return Err(LINUX_EINVAL);
    }
    if valid & IIF_FLAGS != 0 && flags & !DQF_ROOT_SQUASH != 0 {
        return Err(LINUX_EINVAL);
    }
    if valid & IIF_FLAGS != 0 && flags & DQF_ROOT_SQUASH != 0 {
        // Root squash is the old format's: EINVAL once the quota is found
        // on.
        crate::linux_blockfs::quota_info(volume, kind)
            .unwrap_or(Err(19))
            .map_err(|error| error.wrapping_neg())?;
        return Err(LINUX_EINVAL);
    }
    crate::linux_blockfs::set_quota_info(
        volume,
        kind,
        (valid & IIF_BGRACE != 0).then_some(space_grace),
        (valid & IIF_IGRACE != 0).then_some(inode_grace),
    )
    .unwrap_or(Err(19))
    .map_err(|error| error.wrapping_neg())
}

/// Q_SETQUOTA: the fields `struct if_dqblk`'s validity bits name (limits
/// in 1 KiB blocks become bytes, wrapping as Linux's shift does, so a
/// limit too large for the format is ERANGE).
fn linux_quota_set_quota(
    volume: QuotaVolume,
    kind: QuotaKind,
    id: u32,
    address: u64,
) -> Result<(), u64> {
    let mut bytes = [0_u8; DQBLK_SIZE];
    if !copy_from_linux_user(address, &mut bytes) {
        return Err(LINUX_EFAULT);
    }
    let word = |index: usize| {
        u64::from_ne_bytes(
            bytes[index * 8..index * 8 + 8]
                .try_into()
                .unwrap_or_default(),
        )
    };
    let valid = u32::from_ne_bytes(bytes[64..68].try_into().unwrap_or_default());
    let space = |blocks: u64| blocks.wrapping_shl(10);
    let when = |bit: u32, value: u64| (valid & bit != 0).then_some(value);
    let change = DquotChange {
        space_hard: when(QIF_BLIMITS, space(word(0))),
        space_soft: when(QIF_BLIMITS, space(word(1))),
        space: when(QIF_SPACE, word(2)),
        inode_hard: when(QIF_ILIMITS, word(3)),
        inode_soft: when(QIF_ILIMITS, word(4)),
        inodes: when(QIF_INODES, word(5)),
        space_timer: when(QIF_BTIME, word(6)),
        inode_timer: when(QIF_ITIME, word(7)),
    };
    crate::linux_blockfs::set_quota(volume, kind, id, &change)
        .unwrap_or(Err(19))
        .map_err(|error| error.wrapping_neg())
}
