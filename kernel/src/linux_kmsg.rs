//! `/dev/kmsg` (1:11), the kernel log as Linux's printk offers it to user
//! space: each read returns one record, each write adds one. Records are
//! the lines of the machine's kernel log (`kernel_log`), so only a domain
//! set `privileged=true` may open the device (the caller checks).
//!
//! A read gives `PRIORITY,SEQUENCE,TIMESTAMP,-;TEXT\n` with the text's
//! control bytes escaped as `\xNN`, as Linux does. The log keeps neither a
//! line's priority nor its time: every record reads as the kernel's
//! informational level (6) at time 0, and a written record's `<N>` prefix
//! is dropped. Open devices are object slots of the socket table
//! ([`CLASS_READER`]); each has its own place in the log, shared by its
//! duplicates as Linux shares a file's.

use alloc::vec::Vec;

use crate::kernel_log::{self, Cursor, Record};
use crate::sync::{LockRank, SpinLock};

/// The object class of an open `/dev/kmsg` in the socket table.
pub(crate) const CLASS_READER: u8 = 7;
/// The character device number of `/dev/kmsg`, a memory device.
pub(crate) const MAJOR: u32 = 1;
pub(crate) const MINOR: u32 = 11;

/// The longest record Linux takes or gives (PRINTKRB_RECORD_MAX).
pub(crate) const RECORD_MAX: usize = 1024;
/// Linux's informational level, `<6>`, for the kernel's own lines.
const KERNEL_PRIORITY: &[u8] = b"6";

const SEEK_SET: u32 = 0;
const SEEK_END: u32 = 2;
const SEEK_DATA: u32 = 3;

/// What a `/dev/kmsg` read, write or seek can fail with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// EAGAIN: no new record (the caller waits unless O_NONBLOCK).
    WouldBlock,
    /// EPIPE: the reader's next record was overwritten; it now reads from
    /// the oldest one.
    Overwritten,
    /// EINVAL: a buffer too small for the record, a record too long, or an
    /// unknown seek.
    Invalid,
    /// ESPIPE: a seek to an offset other than 0.
    IllegalSeek,
    /// EBADF: no such open.
    BadDescriptor,
}

impl Error {
    pub(crate) fn number(self) -> u64 {
        match self {
            Self::BadDescriptor => 9,
            Self::WouldBlock => 11,
            Self::Invalid => 22,
            Self::IllegalSeek => 29,
            Self::Overwritten => 32,
        }
    }
}

#[derive(Clone, Copy)]
struct Open {
    /// Where the next read starts.
    cursor: Cursor,
    readable: bool,
    writable: bool,
}

/// Open devices, by object id.
static OPENS: SpinLock<Vec<Option<Open>>> = SpinLock::new(LockRank::KMSG, Vec::new());

/// Opens the device for reading, writing or both; returns the open's
/// object id. A reader starts at the oldest record still in the log.
pub(crate) fn open(readable: bool, writable: bool) -> u64 {
    let open = Some(Open {
        cursor: kernel_log::first_record(),
        readable,
        writable,
    });
    let mut opens = OPENS.lock();
    let id = match opens.iter().position(Option::is_none) {
        Some(index) => {
            opens[index] = open;
            index
        }
        None => {
            opens.push(open);
            opens.len() - 1
        }
    };
    id as u64
}

/// Forgets open `class`/`id` after its last descriptor closed. Objects of
/// other classes are not this module's.
pub(crate) fn release(class: u8, id: u64) {
    if class == CLASS_READER {
        if let Some(open) = OPENS.lock().get_mut(id as usize) {
            *open = None;
        }
    }
}

fn opened(id: u64) -> Result<Open, Error> {
    OPENS
        .lock()
        .get(id as usize)
        .copied()
        .flatten()
        .ok_or(Error::BadDescriptor)
}

fn set_cursor(id: u64, cursor: Cursor) {
    if let Some(Some(open)) = OPENS.lock().get_mut(id as usize) {
        open.cursor = cursor;
    }
}

/// Reads the next record of open `id` into a buffer of `capacity` bytes:
/// the record as Linux formats it. EINVAL if it does not fit (the record
/// is skipped, as Linux skips it).
pub(crate) fn read(id: u64, capacity: usize) -> Result<Vec<u8>, Error> {
    let open = opened(id)?;
    if !open.readable {
        return Err(Error::BadDescriptor);
    }
    let mut cursor = open.cursor;
    let sequence = cursor.sequence;
    let mut text = [0_u8; RECORD_MAX];
    let copied = match kernel_log::next_record(&mut cursor, &mut text) {
        Record::Read { copied, .. } => copied,
        Record::Pending => return Err(Error::WouldBlock),
        Record::Lost => {
            set_cursor(id, cursor);
            return Err(Error::Overwritten);
        }
    };
    set_cursor(id, cursor);
    let record = format_record(sequence, &text[..copied]);
    if record.len() > capacity {
        return Err(Error::Invalid);
    }
    Ok(record)
}

/// The record with sequence number `sequence` and `text` as a read shows
/// it.
fn format_record(sequence: u64, text: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut record = Vec::with_capacity(32 + text.len());
    record.extend_from_slice(KERNEL_PRIORITY);
    record.push(b',');
    record.extend_from_slice(alloc::format!("{sequence}").as_bytes());
    record.extend_from_slice(b",0,-;");
    for &byte in text {
        if !(b' '..0x7f).contains(&byte) || byte == b'\\' {
            record.extend_from_slice(&[b'\\', b'x', HEX[usize::from(byte >> 4)]]);
            record.push(HEX[usize::from(byte & 0xf)]);
        } else {
            record.push(byte);
        }
    }
    record.push(b'\n');
    record
}

/// Writes one record, `input` without its `<N>` priority prefix, to the
/// kernel log and console; the count taken (all of it). EINVAL for more
/// than a record holds.
pub(crate) fn write(id: u64, input: &[u8]) -> Result<usize, Error> {
    if !opened(id)?.writable {
        return Err(Error::BadDescriptor);
    }
    if input.len() > RECORD_MAX {
        return Err(Error::Invalid);
    }
    let mut text = input;
    if let Some(rest) = text.strip_prefix(b"<") {
        let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        if let Some(after) = rest[digits..].strip_prefix(b">") {
            text = after;
        }
    }
    // A record ends at the first NUL, as printk's "%s" reads it.
    if let Some(end) = text.iter().position(|byte| *byte == 0) {
        text = &text[..end];
    }
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let mut line = Vec::with_capacity(text.len() + 1);
    line.extend_from_slice(text);
    line.push(b'\n');
    crate::serial_write_bytes(&line);
    Ok(input.len())
}

/// Moves open `id` in the log: to the first record (SEEK_SET), the first
/// after the last syslog clear (SEEK_DATA) or past the last (SEEK_END).
/// Only offset 0 is valid; the result is 0, as on Linux.
pub(crate) fn seek(id: u64, offset: i64, whence: u32) -> Result<u64, Error> {
    if offset != 0 {
        return Err(Error::IllegalSeek);
    }
    opened(id)?;
    let cursor = match whence {
        SEEK_SET => kernel_log::first_record(),
        SEEK_DATA => kernel_log::record_after_clear(),
        SEEK_END => kernel_log::end_record(),
        _ => return Err(Error::Invalid),
    };
    set_cursor(id, cursor);
    Ok(0)
}
