//! Core dumps' names: each domain's `/proc/sys/kernel/core_pattern`, and
//! the file name it gives a dumping process (Linux's format_corename).
#![forbid(unsafe_code)]

use alloc::vec::Vec;

use crate::sync::{LockRank, SpinLock};

/// The longest pattern Linux takes (CORENAME_MAX_SIZE less its NUL).
pub(crate) const PATTERN_MAX: usize = 127;
/// The pattern a domain starts with: "core" in the working directory.
const DEFAULT_PATTERN: &[u8] = b"core";

/// The domains' patterns, where set.
static PATTERNS: SpinLock<Vec<(usize, Vec<u8>)>> =
    SpinLock::new(LockRank::CORE_PATTERNS, Vec::new());

/// Domain `domain`'s core_pattern.
pub(crate) fn pattern(domain: usize) -> Vec<u8> {
    let patterns = PATTERNS.lock();
    let pattern = patterns
        .iter()
        .find(|(owner, _)| *owner == domain)
        .map_or(DEFAULT_PATTERN, |(_, pattern)| &pattern[..]);
    let mut copy = Vec::new();
    if copy.try_reserve_exact(pattern.len()).is_ok() {
        copy.extend_from_slice(pattern);
    }
    copy
}

/// Sets domain `domain`'s core_pattern; false if it is too long or there
/// is no memory for it.
pub(crate) fn set_pattern(domain: usize, pattern: &[u8]) -> bool {
    if pattern.len() > PATTERN_MAX {
        return false;
    }
    let mut stored = Vec::new();
    if stored.try_reserve_exact(pattern.len()).is_err() {
        return false;
    }
    stored.extend_from_slice(pattern);
    let mut patterns = PATTERNS.lock();
    if let Some((_, existing)) = patterns.iter_mut().find(|(owner, _)| *owner == domain) {
        *existing = stored;
        return true;
    }
    if patterns.try_reserve(1).is_err() {
        return false;
    }
    patterns.push((domain, stored));
    true
}

/// What a dumping process's core file is called.
pub(crate) struct Process<'a> {
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) signal: u32,
    pub(crate) seconds: u64,
    /// Its command name (comm).
    pub(crate) name: &'a [u8],
    pub(crate) hostname: &'a [u8],
}

/// The core file name `pattern` gives `process`, with `.PID` added when
/// `uses_pid` (core_uses_pid) and the pattern names no pid; None for a
/// pattern that pipes the core to a program ("|..."), which Ginux does
/// not run.
pub(crate) fn file_name(pattern: &[u8], uses_pid: bool, process: &Process) -> Option<Vec<u8>> {
    if pattern.first() == Some(&b'|') {
        return None;
    }
    let mut name = Vec::new();
    let mut has_pid = false;
    let decimal = |name: &mut Vec<u8>, mut value: u64| {
        let mut digits = [0_u8; 20];
        let mut count = 0;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        name.extend(digits[..count].iter().rev());
    };
    let mut bytes = pattern.iter();
    while let Some(&byte) = bytes.next() {
        if byte != b'%' {
            name.push(byte);
            continue;
        }
        match bytes.next() {
            Some(b'%') => name.push(b'%'),
            Some(b'p' | b'P' | b'i' | b'I') => {
                has_pid = true;
                decimal(&mut name, u64::from(process.pid));
            }
            Some(b'u') => decimal(&mut name, u64::from(process.uid)),
            Some(b'g') => decimal(&mut name, u64::from(process.gid)),
            Some(b's') => decimal(&mut name, u64::from(process.signal)),
            Some(b't') => decimal(&mut name, process.seconds),
            Some(b'e') => name.extend_from_slice(process.name),
            Some(b'h') => name.extend_from_slice(process.hostname),
            // Other specifiers (and a lone '%' at the end) give nothing.
            _ => {}
        }
    }
    if uses_pid && !has_pid {
        name.push(b'.');
        decimal(&mut name, u64::from(process.pid));
    }
    Some(name)
}

/// Domain `domain` stopped: its pattern goes.
pub(crate) fn forget_domain(domain: usize) {
    PATTERNS.lock().retain(|(owner, _)| *owner != domain);
}
