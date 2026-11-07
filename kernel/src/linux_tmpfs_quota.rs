//! The size limits of tmpfs mounts (mount options `size=`, `nr_blocks=`
//! and `nr_inodes=`) and what their files use of them.
//!
//! A tmpfs's files are the overlay's below its mount point. The overlay
//! charges each data page it allocates for a file there, and each file it
//! creates, to the deepest limited tmpfs covering the file's path, and
//! gives them back when the file's data goes; a charge past the limit
//! fails, so the write that needs it fails with ENOSPC, as on Linux. A
//! tmpfs mounted without a limit is not tracked.
#![forbid(unsafe_code)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::sync::{LockRank, SpinLock};

/// The page a block of a tmpfs is.
pub(crate) const BLOCK_SIZE: u64 = 4096;

/// One limited tmpfs.
struct Limit {
    instance: usize,
    /// The canonical mount point, without a leading slash.
    path: Vec<u8>,
    blocks: Option<u64>,
    inodes: Option<u64>,
    used_blocks: u64,
    used_inodes: u64,
}

static LIMITS: SpinLock<Vec<Limit>> = SpinLock::new(LockRank::TMPFS_LIMITS, Vec::new());
/// How many limits there are: none spares every charge the lock.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// What a tmpfs mount's options ask for, `None` where they leave it
/// unlimited.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Options {
    pub(crate) blocks: Option<u64>,
    pub(crate) inodes: Option<u64>,
}

/// A number with an optional k, m, g, t, p or e suffix (memparse).
fn parse_size(text: &[u8]) -> Option<u64> {
    let digits = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    let value: u64 = core::str::from_utf8(&text[..digits]).ok()?.parse().ok()?;
    let shift = match &text[digits..] {
        [] => 0,
        [b'k' | b'K'] => 10,
        [b'm' | b'M'] => 20,
        [b'g' | b'G'] => 30,
        [b't' | b'T'] => 40,
        [b'p' | b'P'] => 50,
        [b'e' | b'E'] => 60,
        _ => return None,
    };
    value.checked_mul(1 << shift)
}

/// The limits in tmpfs mount data `data` ("size=32M,mode=0755,..."):
/// `size` in bytes (or a percentage of `memory` bytes), rounded up to
/// blocks, `nr_blocks` and `nr_inodes`; options that say nothing about
/// size are left to others. EINVAL (`None`) for a malformed size.
pub(crate) fn parse(data: &[u8], memory: u64) -> Option<Options> {
    let mut options = Options::default();
    for option in data.split(|byte| *byte == b',') {
        let Some(split) = option.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let (name, value) = (&option[..split], &option[split + 1..]);
        match name {
            b"size" => {
                let bytes = match value.strip_suffix(b"%") {
                    Some(percent) => {
                        let percent: u64 = core::str::from_utf8(percent).ok()?.parse().ok()?;
                        memory / 100 * percent
                    }
                    None => parse_size(value)?,
                };
                options.blocks = Some(bytes.div_ceil(BLOCK_SIZE));
            }
            b"nr_blocks" => options.blocks = Some(parse_size(value)?),
            b"nr_inodes" => options.inodes = Some(parse_size(value)?),
            _ => {}
        }
    }
    Some(options)
}

fn covers(point: &[u8], path: &[u8]) -> bool {
    point.is_empty()
        || path
            .strip_prefix(point)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
}

/// The deepest limit of `instance` covering canonical `path`.
fn limit_at<'a>(limits: &'a mut [Limit], instance: usize, path: &[u8]) -> Option<&'a mut Limit> {
    limits
        .iter_mut()
        .filter(|limit| limit.instance == instance && covers(&limit.path, path))
        .max_by_key(|limit| limit.path.len())
}

/// Limits the tmpfs just mounted at canonical `path` as `options` say
/// (nothing if they set no limit).
pub(crate) fn mounted(instance: usize, path: &[u8], options: Options) -> bool {
    if options == Options::default() {
        return true;
    }
    let mut stored = Vec::new();
    if stored.try_reserve_exact(path.len()).is_err() {
        return false;
    }
    stored.extend_from_slice(path);
    let mut limits = LIMITS.lock();
    if limits.try_reserve(1).is_err() {
        return false;
    }
    limits.push(Limit {
        instance,
        path: stored,
        blocks: options.blocks,
        inodes: options.inodes,
        used_blocks: 0,
        used_inodes: 0,
    });
    COUNT.store(limits.len(), Ordering::Release);
    true
}

/// A remount's new limits for the tmpfs at canonical `path`; false (EINVAL)
/// below what its files already use.
pub(crate) fn remounted(instance: usize, path: &[u8], options: Options) -> bool {
    let mut limits = LIMITS.lock();
    let Some(limit) = limits
        .iter_mut()
        .rfind(|limit| limit.instance == instance && limit.path == path)
    else {
        drop(limits);
        return mounted(instance, path, options);
    };
    if options
        .blocks
        .is_some_and(|blocks| blocks < limit.used_blocks)
        || options
            .inodes
            .is_some_and(|inodes| inodes < limit.used_inodes)
    {
        return false;
    }
    limit.blocks = options.blocks.or(limit.blocks);
    limit.inodes = options.inodes.or(limit.inodes);
    true
}

/// Forgets the limit of the tmpfs unmounted from canonical `path`.
pub(crate) fn unmounted(instance: usize, path: &[u8]) {
    let mut limits = LIMITS.lock();
    if let Some(index) = limits
        .iter()
        .rposition(|limit| limit.instance == instance && limit.path == path)
    {
        limits.remove(index);
    }
    COUNT.store(limits.len(), Ordering::Release);
}

/// Forgets `instance`'s limits when its domain stops.
pub(crate) fn forget_instance(instance: usize) {
    let mut limits = LIMITS.lock();
    limits.retain(|limit| limit.instance != instance);
    COUNT.store(limits.len(), Ordering::Release);
}

/// Charges `blocks` data blocks and `inodes` files of canonical `path` to
/// its tmpfs; false, charging nothing, past the tmpfs's limit.
pub(crate) fn charge(instance: usize, path: &[u8], blocks: u64, inodes: u64) -> bool {
    if COUNT.load(Ordering::Acquire) == 0 {
        return true;
    }
    let mut limits = LIMITS.lock();
    let Some(limit) = limit_at(&mut limits, instance, path) else {
        return true;
    };
    let used_blocks = limit.used_blocks.saturating_add(blocks);
    let used_inodes = limit.used_inodes.saturating_add(inodes);
    if limit.blocks.is_some_and(|most| used_blocks > most)
        || limit.inodes.is_some_and(|most| used_inodes > most)
    {
        return false;
    }
    limit.used_blocks = used_blocks;
    limit.used_inodes = used_inodes;
    true
}

/// Gives back `blocks` data blocks and `inodes` files of canonical `path`.
pub(crate) fn release(instance: usize, path: &[u8], blocks: u64, inodes: u64) {
    if COUNT.load(Ordering::Acquire) == 0 {
        return;
    }
    let mut limits = LIMITS.lock();
    if let Some(limit) = limit_at(&mut limits, instance, path) {
        limit.used_blocks = limit.used_blocks.saturating_sub(blocks);
        limit.used_inodes = limit.used_inodes.saturating_sub(inodes);
    }
}

/// What statfs(2) shows of the limited tmpfs canonical `path` lies on:
/// total and used blocks, total and used files (`None` totals are
/// unlimited).
pub(crate) fn usage(instance: usize, path: &[u8]) -> Option<(Option<u64>, u64, Option<u64>, u64)> {
    let mut limits = LIMITS.lock();
    let limit = limit_at(&mut limits, instance, path)?;
    Some((
        limit.blocks,
        limit.used_blocks,
        limit.inodes,
        limit.used_inodes,
    ))
}
