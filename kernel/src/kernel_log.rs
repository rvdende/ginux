//! The machine's kernel log: the last [`CAPACITY`] bytes of what the
//! kernel wrote to its console, kept for syslog(2) and `/dev/kmsg` in a
//! domain set `privileged=true` (dmesg). Writers never block: each takes
//! its span of the ring with one atomic add, so the log may be written
//! from any context, with any lock held.
//!
//! `/dev/kmsg` reads the log as records, one per line: a record's sequence
//! number counts the lines written before it ([`Cursor`]).

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

/// Bytes the ring holds: Linux's default log buffer (CONFIG_LOG_BUF_SHIFT
/// 17).
pub(crate) const CAPACITY: usize = 1 << 17;

static RING: [AtomicU8; CAPACITY] = [const { AtomicU8::new(0) }; CAPACITY];
/// Bytes ever written; the ring holds the last `CAPACITY` of them.
static WRITTEN: AtomicU64 = AtomicU64::new(0);
/// Where the log starts after the last clear (syslog's CLEAR actions).
static CLEARED: AtomicU64 = AtomicU64::new(0);
/// How far syslog's destructive READ has consumed the log.
static CONSUMED: AtomicU64 = AtomicU64::new(0);
/// Lines ever completed (newlines written), counted once their bytes are
/// in the ring.
static LINES: AtomicU64 = AtomicU64::new(0);

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
    let lines = bytes.iter().filter(|byte| **byte == b'\n').count() as u64;
    LINES.fetch_add(lines, Ordering::AcqRel);
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

/// A reader's place in the log as records: the byte position where its
/// next record starts and that record's sequence number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Cursor {
    position: u64,
    pub(crate) sequence: u64,
}

/// What [`next_record`] found at a cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Record {
    /// The record's text was copied (cut to the output's length, `length`
    /// in full); the cursor now names the record after it.
    Read { copied: usize, length: usize },
    /// No whole record yet: nothing follows, or the last line is still
    /// being written.
    Pending,
    /// The record was overwritten; the cursor now names the oldest one.
    Lost,
}

/// The byte at `position`, which must still be in the ring.
fn byte_at(position: u64) -> u8 {
    RING[(position % CAPACITY as u64) as usize].load(Ordering::Relaxed)
}

/// The cursor of the record starting at `position`, where `end` is where
/// the log ended when the record was found.
fn cursor_at(position: u64, end: u64) -> Cursor {
    let following = (position..end).filter(|at| byte_at(*at) == b'\n').count() as u64;
    Cursor {
        position,
        sequence: LINES.load(Ordering::Acquire).saturating_sub(following),
    }
}

/// The first record at or after `from`: `from` itself if a line starts
/// there, else the line after it.
fn record_from(from: u64) -> Cursor {
    let end = WRITTEN.load(Ordering::Acquire);
    let from = oldest(from).min(end);
    let position = if from == 0 || byte_at(from - 1) == b'\n' {
        from
    } else {
        (from..end)
            .find(|at| byte_at(*at) == b'\n')
            .map_or(end, |newline| newline + 1)
    };
    cursor_at(position, end)
}

/// The oldest whole record still in the ring, where a `/dev/kmsg` reader
/// starts (and SEEK_SET puts it).
pub(crate) fn first_record() -> Cursor {
    // The oldest byte kept starts a line only if the byte before it, which
    // is gone, was a newline: start at the next line.
    match WRITTEN.load(Ordering::Acquire).checked_sub(CAPACITY as u64) {
        Some(gone) if gone > 0 => record_from(gone + 1),
        _ => record_from(0),
    }
}

/// The first record after the last syslog CLEAR (SEEK_DATA).
pub(crate) fn record_after_clear() -> Cursor {
    let first = first_record();
    let cleared = CLEARED.load(Ordering::Acquire);
    if cleared <= first.position {
        first
    } else {
        record_from(cleared)
    }
}

/// The cursor past the last whole record, naming the one written next
/// (SEEK_END).
pub(crate) fn end_record() -> Cursor {
    let end = WRITTEN.load(Ordering::Acquire);
    let start = oldest(0);
    let position = (start..end)
        .rev()
        .find(|at| byte_at(*at) == b'\n')
        .map_or(start, |newline| newline + 1);
    cursor_at(position, end)
}

/// Copies the text of the record at `cursor` (its line without the
/// newline) into `output`, as far as it fits, and moves past it.
pub(crate) fn next_record(cursor: &mut Cursor, output: &mut [u8]) -> Record {
    let end = WRITTEN.load(Ordering::Acquire);
    if cursor.position < oldest(0) {
        *cursor = first_record();
        return Record::Lost;
    }
    let Some(newline) = (cursor.position..end).find(|at| byte_at(*at) == b'\n') else {
        return Record::Pending;
    };
    let copied = copy(cursor.position, newline, output);
    // A writer may have wrapped around over the line while it was copied.
    if cursor.position < oldest(0) {
        *cursor = first_record();
        return Record::Lost;
    }
    let length = (newline - cursor.position) as usize;
    cursor.position = newline + 1;
    cursor.sequence += 1;
    Record::Read { copied, length }
}
