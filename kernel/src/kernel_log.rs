//! The machine's kernel log: the last [`CAPACITY`] bytes of what the
//! kernel wrote to its console, kept for syslog(2) and `/dev/kmsg` in a
//! domain set `privileged=true` (dmesg). Writers never block: each takes
//! its span of the ring with one atomic add, so the log may be written
//! from any context, with any lock held.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// Bytes the ring holds.
pub(crate) const CAPACITY: usize = 1 << 16;

static RING: [AtomicU8; CAPACITY] = [const { AtomicU8::new(0) }; CAPACITY];
/// Bytes ever written; the ring holds the last `CAPACITY` of them.
static WRITTEN: AtomicU64 = AtomicU64::new(0);
/// Where the log starts after the last clear (syslog's CLEAR actions).
static CLEARED: AtomicU64 = AtomicU64::new(0);
/// How far syslog's destructive READ has consumed the log.
static CONSUMED: AtomicU64 = AtomicU64::new(0);

/// Appends console output, dropping carriage returns so lines end in "\n".
pub(crate) fn record(bytes: &[u8]) {
    let count = bytes.iter().filter(|byte| **byte != b'\r').count() as u64;
    if count == 0 {
        return;
    }
    let start = WRITTEN.fetch_add(count, Ordering::AcqRel);
    for (offset, byte) in bytes.iter().filter(|byte| **byte != b'\r').enumerate() {
        RING[((start + offset as u64) % CAPACITY as u64) as usize].store(*byte, Ordering::Relaxed);
    }
}

/// The oldest position still in the ring at or after `from`.
fn oldest(from: u64) -> u64 {
    from.max(
        WRITTEN
            .load(Ordering::Acquire)
            .saturating_sub(CAPACITY as u64),
    )
}

/// Copies the newest bytes since the last clear into `output` (at most
/// its length, the last ones), as syslog's READ_ALL does; the count.
pub(crate) fn read_recent(output: &mut [u8]) -> usize {
    let end = WRITTEN.load(Ordering::Acquire);
    let start =
        oldest(CLEARED.load(Ordering::Acquire)).max(end.saturating_sub(output.len() as u64));
    copy(start, end, output)
}

/// Copies unread bytes into `output` and marks them read (syslog's READ).
pub(crate) fn read_unread(output: &mut [u8]) -> usize {
    let end = WRITTEN.load(Ordering::Acquire);
    let start = oldest(CONSUMED.load(Ordering::Acquire));
    let end = end.min(start + output.len() as u64);
    let copied = copy(start, end, output);
    CONSUMED.store(start + copied as u64, Ordering::Release);
    copied
}

/// The bytes syslog's READ would return now (SIZE_UNREAD).
pub(crate) fn unread() -> u64 {
    let end = WRITTEN.load(Ordering::Acquire);
    end - oldest(CONSUMED.load(Ordering::Acquire)).min(end)
}

/// Forgets what was logged so far (syslog's CLEAR and READ_CLEAR).
pub(crate) fn clear() {
    CLEARED.store(WRITTEN.load(Ordering::Acquire), Ordering::Release);
}

fn copy(start: u64, end: u64, output: &mut [u8]) -> usize {
    let mut count = 0;
    for (position, slot) in (start..end).zip(output.iter_mut()) {
        *slot = RING[(position % CAPACITY as u64) as usize].load(Ordering::Relaxed);
        count += 1;
    }
    count
}
