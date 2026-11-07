#![forbid(unsafe_code)]
//! The rules of Linux's cgroup v2 hierarchy and its memory controller, as
//! the kernel applies them to a domain's `/sys/fs/cgroup`: what a control
//! file accepts, what it reads back, which changes the hierarchy refuses
//! and which process an out-of-memory cgroup gives up.
//!
//! Linux's `kernel/cgroup/cgroup.c`, `mm/memcontrol.c` and
//! `Documentation/admin-guide/cgroup-v2.rst` are the specification. This
//! is pure logic over plain numbers, so it is tested on the host; the
//! kernel keeps the counters (atomics updated from page faults on any CPU)
//! and asks this crate what they mean.

#![no_std]

/// The page size every memory count is kept in.
pub const PAGE_SIZE: u64 = 4096;

/// A page counter without a limit: Linux's `PAGE_COUNTER_MAX` on 64-bit
/// (`LONG_MAX / PAGE_SIZE`), which reads back as `max`.
pub const UNLIMITED: u64 = i64::MAX as u64 / PAGE_SIZE;

/// Why a control-file write or a hierarchy change is refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// EINVAL: the text does not parse, or names no controller.
    Invalid,
    /// ENOENT: the controller is not available to this cgroup (its parent
    /// does not delegate it).
    NotAvailable,
    /// EBUSY: the change would leave processes in a cgroup that delegates
    /// a controller to its children, or take away a controller a child
    /// still delegates.
    Busy,
}

/// A set of controllers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Controllers(u8);

impl Controllers {
    pub const NONE: Self = Self(0);
    pub const MEMORY: Self = Self(1);
    /// Every controller Ginux implements, as the root offers them.
    pub const ALL: Self = Self::MEMORY;

    const NAMES: [(Self, &'static [u8]); 1] = [(Self::MEMORY, b"memory")];

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// The controller called `name`.
    pub fn by_name(name: &[u8]) -> Option<Self> {
        Self::NAMES
            .iter()
            .find(|(_, known)| *known == name)
            .map(|(controller, _)| *controller)
    }

    /// The set as `cgroup.controllers` and `cgroup.subtree_control` read:
    /// names separated by spaces, then a newline.
    pub fn write_names(self, output: &mut Output<'_>) -> bool {
        let mut first = true;
        for (controller, name) in Self::NAMES {
            if self.contains(controller) {
                if !first && !output.push(b" ") {
                    return false;
                }
                if !output.push(name) {
                    return false;
                }
                first = false;
            }
        }
        output.push(b"\n")
    }
}

/// A `cgroup.subtree_control` write: the controllers to start and stop
/// delegating.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubtreeChange {
    pub enable: Controllers,
    pub disable: Controllers,
}

/// Parses a `cgroup.subtree_control` write: `+name` and `-name` tokens
/// separated by white space. Anything else, an unknown name, or one
/// controller both added and removed, is EINVAL.
pub fn parse_subtree_control(input: &[u8]) -> Result<SubtreeChange, Error> {
    let mut change = SubtreeChange::default();
    for token in input
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|token| !token.is_empty())
    {
        let (sign, name) = token.split_first().ok_or(Error::Invalid)?;
        let controller = Controllers::by_name(name).ok_or(Error::Invalid)?;
        match sign {
            b'+' => change.enable = change.enable.union(controller),
            b'-' => change.disable = change.disable.union(controller),
            _ => return Err(Error::Invalid),
        }
    }
    if !change.enable.intersection(change.disable).is_empty() {
        return Err(Error::Invalid);
    }
    Ok(change)
}

/// What a cgroup's position allows a `cgroup.subtree_control` change.
#[derive(Clone, Copy, Debug)]
pub struct SubtreeState {
    /// Its `cgroup.subtree_control` now.
    pub current: Controllers,
    /// Its `cgroup.controllers`: what its parent delegates (all for the
    /// root).
    pub available: Controllers,
    pub root: bool,
    /// Whether processes are in the cgroup itself.
    pub has_processes: bool,
    /// What its children delegate further, together.
    pub children_delegate: Controllers,
}

/// The `cgroup.subtree_control` a change leaves, or why it is refused, as
/// Linux's `cgroup_subtree_control_write` decides: a controller must be
/// available to be delegated (ENOENT); a non-root cgroup with processes
/// may not start delegating (EBUSY, "no internal processes"); and a
/// controller a child delegates further may not be withdrawn (EBUSY).
pub fn apply_subtree_change(
    state: SubtreeState,
    change: SubtreeChange,
) -> Result<Controllers, Error> {
    if !state.available.contains(change.enable) {
        return Err(Error::NotAvailable);
    }
    let enable = change.enable.without(state.current);
    let disable = change.disable.intersection(state.current);
    if !disable.intersection(state.children_delegate).is_empty() {
        return Err(Error::Busy);
    }
    if !enable.is_empty() && !state.root && state.has_processes {
        return Err(Error::Busy);
    }
    Ok(state.current.union(enable).without(disable))
}

/// Whether processes may move into a cgroup: not into a non-root one that
/// delegates controllers to its children (EBUSY).
pub fn may_hold_processes(root: bool, subtree_control: Controllers) -> Result<(), Error> {
    if root || subtree_control.is_empty() {
        Ok(())
    } else {
        Err(Error::Busy)
    }
}

/// Parses a `cgroup.procs` write: one process ID in decimal, optionally
/// followed by white space; 0 names the writer.
pub fn parse_pid(input: &[u8]) -> Result<u32, Error> {
    let text = trim(input);
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return Err(Error::Invalid);
    }
    let mut value = 0_u32;
    for digit in text {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
            .ok_or(Error::Invalid)?;
    }
    Ok(value)
}

/// Parses a memory limit (`memory.max`, `high`, `low`, `min`,
/// `swap.max`) as Linux's `page_counter_memparse` does: `max`, or a byte
/// count (decimal, `0x` hexadecimal or `0` octal) with an optional K, M,
/// G, T, P or E suffix, rounded down to whole pages. Surrounding white
/// space is ignored; anything else is EINVAL.
pub fn parse_memory_limit(input: &[u8]) -> Result<u64, Error> {
    let text = trim(input);
    if text == b"max" {
        return Ok(UNLIMITED);
    }
    let (bytes, rest) = parse_unsigned(text).ok_or(Error::Invalid)?;
    let (shift, rest) = match rest.split_first() {
        Some((suffix, rest)) => match suffix.to_ascii_uppercase() {
            b'K' => (10, rest),
            b'M' => (20, rest),
            b'G' => (30, rest),
            b'T' => (40, rest),
            b'P' => (50, rest),
            b'E' => (60, rest),
            _ => return Err(Error::Invalid),
        },
        None => (0, rest),
    };
    if !rest.is_empty() {
        return Err(Error::Invalid);
    }
    // memparse shifts without checking for overflow, as Linux does.
    let bytes = bytes.wrapping_shl(shift);
    Ok((bytes / PAGE_SIZE).min(UNLIMITED))
}

/// A page count as a memory file reads: bytes, or `max` when unlimited.
pub fn write_memory_limit(pages: u64, output: &mut Output<'_>) -> bool {
    if pages >= UNLIMITED {
        output.push(b"max\n")
    } else {
        output.decimal(pages * PAGE_SIZE) && output.push(b"\n")
    }
}

/// A page count as bytes and a newline (`memory.current`, `memory.peak`).
pub fn write_bytes(pages: u64, output: &mut Output<'_>) -> bool {
    output.decimal(pages.saturating_mul(PAGE_SIZE)) && output.push(b"\n")
}

/// What a memory cgroup holds, in pages (`memory.stat`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryStat {
    /// Anonymous memory: private pages and the program break and stack.
    pub anon: u64,
    /// Page cache.
    pub file: u64,
    /// Shared memory and tmpfs.
    pub shmem: u64,
    /// Page cache mapped into a process.
    pub file_mapped: u64,
    /// Pages swapped out.
    pub swapped: u64,
    /// Lazily freed anonymous pages (MADV_FREE) not yet reclaimed.
    pub lazyfree: u64,
    /// Pages reclaimed from the cgroup.
    pub reclaimed: u64,
}

/// `memory.stat` as Linux words it (in bytes, in its order). Ginux keeps
/// no LRU lists, so all anonymous memory is active and all page cache
/// inactive, and the kernel-side counts are zero.
pub fn write_memory_stat(stat: &MemoryStat, output: &mut Output<'_>) -> bool {
    let bytes = |pages: u64| pages.saturating_mul(PAGE_SIZE);
    let lines: [(&[u8], u64); 22] = [
        (b"anon", bytes(stat.anon)),
        (b"file", bytes(stat.file + stat.shmem)),
        (b"kernel", 0),
        (b"kernel_stack", 0),
        (b"pagetables", 0),
        (b"sec_pagetables", 0),
        (b"percpu", 0),
        (b"sock", 0),
        (b"vmalloc", 0),
        (b"shmem", bytes(stat.shmem)),
        (b"file_mapped", bytes(stat.file_mapped)),
        (b"file_dirty", 0),
        (b"file_writeback", 0),
        (b"swapcached", 0),
        (b"anon_thp", 0),
        (b"inactive_anon", bytes(stat.lazyfree)),
        (
            b"active_anon",
            bytes(stat.anon.saturating_sub(stat.lazyfree) + stat.shmem),
        ),
        (b"inactive_file", bytes(stat.file)),
        (b"active_file", 0),
        (b"unevictable", 0),
        (b"pgscan", stat.reclaimed),
        (b"pgsteal", stat.reclaimed),
    ];
    lines.iter().all(|(name, value)| {
        output.push(name) && output.push(b" ") && output.decimal(*value) && output.push(b"\n")
    }) && output.push(b"pglazyfree ")
        && output.decimal(stat.lazyfree)
        && output.push(b"\npglazyfreed ")
        && output.decimal(stat.reclaimed)
        && output.push(b"\n")
}

/// How often a memory cgroup met its limits (`memory.events`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryEvents {
    /// Reclaimed below `memory.low` under pressure.
    pub low: u64,
    /// Went over `memory.high`.
    pub high: u64,
    /// A charge met `memory.max`.
    pub max: u64,
    /// Reclaim failed and the cgroup was out of memory.
    pub oom: u64,
    /// Processes killed for it.
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

pub fn write_memory_events(events: &MemoryEvents, output: &mut Output<'_>) -> bool {
    let lines: [(&[u8], u64); 6] = [
        (b"low", events.low),
        (b"high", events.high),
        (b"max", events.max),
        (b"oom", events.oom),
        (b"oom_kill", events.oom_kill),
        (b"oom_group_kill", events.oom_group_kill),
    ];
    lines.iter().all(|(name, value)| {
        output.push(name) && output.push(b" ") && output.decimal(*value) && output.push(b"\n")
    })
}

/// `memory.swap.events`: when swap use met `memory.swap.high` and
/// `memory.swap.max`, and when a swap-out failed.
pub fn write_swap_events(high: u64, max: u64, fail: u64, output: &mut Output<'_>) -> bool {
    output.push(b"high ")
        && output.decimal(high)
        && output.push(b"\nmax ")
        && output.decimal(max)
        && output.push(b"\nfail ")
        && output.decimal(fail)
        && output.push(b"\n")
}

/// `cgroup.events`: whether processes are in the cgroup or below it.
pub fn write_cgroup_events(populated: bool, output: &mut Output<'_>) -> bool {
    output.push(if populated {
        b"populated 1\nfrozen 0\n"
    } else {
        b"populated 0\nfrozen 0\n"
    })
}

/// Whether charging `pages` more on `usage` goes past `limit`.
pub const fn exceeds(usage: u64, pages: u64, limit: u64) -> bool {
    limit < UNLIMITED && usage.saturating_add(pages) > limit
}

/// The OOM killer's score for a process, as Linux's `oom_badness`: its
/// resident and swapped pages and page tables, plus `oom_score_adj`
/// thousandths of `total_pages`. A process set to -1000 is never chosen
/// (None).
pub fn oom_badness(
    resident: u64,
    swapped: u64,
    page_tables: u64,
    oom_score_adj: i32,
    total_pages: u64,
) -> Option<i64> {
    if oom_score_adj <= -1000 {
        return None;
    }
    let points = (resident + swapped + page_tables).min(i64::MAX as u64) as i64;
    let adjustment = i64::from(oom_score_adj) * (total_pages / 1000).min(i64::MAX as u64) as i64;
    Some(points.saturating_add(adjustment))
}

/// The process to kill, of `(pid, badness)` candidates: the highest score,
/// the earliest listed on a tie.
pub fn choose_oom_victim(candidates: impl IntoIterator<Item = (u32, Option<i64>)>) -> Option<u32> {
    let mut chosen: Option<(u32, i64)> = None;
    for (pid, badness) in candidates {
        let Some(badness) = badness else {
            continue;
        };
        if chosen.is_none_or(|(_, best)| badness > best) {
            chosen = Some((pid, badness));
        }
    }
    chosen.map(|(pid, _)| pid)
}

fn trim(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |end| end + 1);
    &input[start..end.max(start)]
}

/// An unsigned number as `simple_strtoull` with base 0 reads it, and what
/// follows it; None without a digit or past 64 bits.
fn parse_unsigned(text: &[u8]) -> Option<(u64, &[u8])> {
    let (radix, digits) = if let Some(rest) = text
        .strip_prefix(b"0x")
        .or_else(|| text.strip_prefix(b"0X"))
        .filter(|rest| rest.first().is_some_and(u8::is_ascii_hexdigit))
    {
        (16, rest)
    } else if text.len() > 1 && text[0] == b'0' {
        (8, &text[1..])
    } else {
        (10, text)
    };
    let length = digits
        .iter()
        .position(|byte| !(*byte as char).is_digit(radix))
        .unwrap_or(digits.len());
    if length == 0 && radix != 8 {
        return None;
    }
    let mut value = 0_u64;
    for digit in &digits[..length] {
        let digit = (*digit as char).to_digit(radix)?;
        value = value
            .checked_mul(u64::from(radix))?
            .checked_add(u64::from(digit))?;
    }
    Some((value, &digits[length..]))
}

/// A bounded text buffer for a control file's contents.
pub struct Output<'a> {
    bytes: &'a mut [u8],
    length: usize,
}

impl<'a> Output<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, length: 0 }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Appends `text`; false (and nothing appended) when it does not fit.
    pub fn push(&mut self, text: &[u8]) -> bool {
        let Some(end) = self.length.checked_add(text.len()) else {
            return false;
        };
        let Some(target) = self.bytes.get_mut(self.length..end) else {
            return false;
        };
        target.copy_from_slice(text);
        self.length = end;
        true
    }

    pub fn decimal(&mut self, value: u64) -> bool {
        let mut digits = [0_u8; 20];
        let mut index = digits.len();
        let mut rest = value;
        loop {
            index -= 1;
            digits[index] = b'0' + (rest % 10) as u8;
            rest /= 10;
            if rest == 0 {
                break;
            }
        }
        self.push(&digits[index..])
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    fn written(write: impl FnOnce(&mut Output<'_>) -> bool) -> std::vec::Vec<u8> {
        let mut bytes = [0_u8; 512];
        let mut output = Output::new(&mut bytes);
        assert!(write(&mut output));
        output.as_bytes().to_vec()
    }

    #[test]
    fn limits_parse_as_page_counter_memparse() {
        assert_eq!(parse_memory_limit(b"max\n"), Ok(UNLIMITED));
        assert_eq!(parse_memory_limit(b"  max  "), Ok(UNLIMITED));
        assert_eq!(parse_memory_limit(b"268435456"), Ok(65536));
        assert_eq!(parse_memory_limit(b"4095"), Ok(0));
        assert_eq!(parse_memory_limit(b"8191\n"), Ok(1));
        assert_eq!(parse_memory_limit(b"256M"), Ok(65536));
        assert_eq!(parse_memory_limit(b"1g"), Ok(262_144));
        assert_eq!(parse_memory_limit(b"4k"), Ok(1));
        assert_eq!(parse_memory_limit(b"0x1000"), Ok(1));
        assert_eq!(parse_memory_limit(b"010000"), Ok(1));
        assert_eq!(parse_memory_limit(b"0"), Ok(0));
        assert_eq!(parse_memory_limit(b""), Err(Error::Invalid));
        assert_eq!(parse_memory_limit(b"-1"), Err(Error::Invalid));
        assert_eq!(parse_memory_limit(b"12x"), Err(Error::Invalid));
        assert_eq!(parse_memory_limit(b"1M2"), Err(Error::Invalid));
        assert_eq!(parse_memory_limit(b"maximum"), Err(Error::Invalid));
        assert_eq!(parse_memory_limit(b"9223372036854775807"), Ok(UNLIMITED));
    }

    #[test]
    fn limits_read_back_in_bytes_or_max() {
        assert_eq!(written(|o| write_memory_limit(UNLIMITED, o)), b"max\n");
        assert_eq!(written(|o| write_memory_limit(65536, o)), b"268435456\n");
        assert_eq!(written(|o| write_memory_limit(0, o)), b"0\n");
        assert_eq!(written(|o| write_bytes(3, o)), b"12288\n");
    }

    #[test]
    fn subtree_control_tokens() {
        assert_eq!(
            parse_subtree_control(b"+memory\n"),
            Ok(SubtreeChange {
                enable: Controllers::MEMORY,
                disable: Controllers::NONE
            })
        );
        assert_eq!(
            parse_subtree_control(b"  -memory  "),
            Ok(SubtreeChange {
                enable: Controllers::NONE,
                disable: Controllers::MEMORY
            })
        );
        assert_eq!(parse_subtree_control(b""), Ok(SubtreeChange::default()));
        assert_eq!(parse_subtree_control(b"memory"), Err(Error::Invalid));
        assert_eq!(parse_subtree_control(b"+cpu"), Err(Error::Invalid));
        assert_eq!(
            parse_subtree_control(b"+memory -memory"),
            Err(Error::Invalid)
        );
    }

    #[test]
    fn subtree_changes_follow_the_hierarchy_rules() {
        let root = SubtreeState {
            current: Controllers::NONE,
            available: Controllers::ALL,
            root: true,
            has_processes: true,
            children_delegate: Controllers::NONE,
        };
        let enable = SubtreeChange {
            enable: Controllers::MEMORY,
            disable: Controllers::NONE,
        };
        let disable = SubtreeChange {
            enable: Controllers::NONE,
            disable: Controllers::MEMORY,
        };
        // The root may hold processes and delegate.
        assert_eq!(apply_subtree_change(root, enable), Ok(Controllers::MEMORY));
        // A child with processes may not start delegating.
        let child = SubtreeState {
            root: false,
            available: Controllers::MEMORY,
            ..root
        };
        assert_eq!(apply_subtree_change(child, enable), Err(Error::Busy));
        let empty = SubtreeState {
            has_processes: false,
            ..child
        };
        assert_eq!(apply_subtree_change(empty, enable), Ok(Controllers::MEMORY));
        // A controller the parent does not delegate is not available.
        let bare = SubtreeState {
            available: Controllers::NONE,
            ..empty
        };
        assert_eq!(apply_subtree_change(bare, enable), Err(Error::NotAvailable));
        // Withdrawing what a child still delegates is refused; withdrawing
        // what is not enabled does nothing.
        let delegating = SubtreeState {
            current: Controllers::MEMORY,
            children_delegate: Controllers::MEMORY,
            ..empty
        };
        assert_eq!(apply_subtree_change(delegating, disable), Err(Error::Busy));
        assert_eq!(apply_subtree_change(empty, disable), Ok(Controllers::NONE));
        // Enabling what is enabled changes nothing, even with processes.
        let enabled = SubtreeState {
            current: Controllers::MEMORY,
            has_processes: true,
            ..child
        };
        assert_eq!(
            apply_subtree_change(enabled, enable),
            Ok(Controllers::MEMORY)
        );
        assert_eq!(
            may_hold_processes(false, Controllers::MEMORY),
            Err(Error::Busy)
        );
        assert_eq!(may_hold_processes(true, Controllers::MEMORY), Ok(()));
        assert_eq!(may_hold_processes(false, Controllers::NONE), Ok(()));
    }

    #[test]
    fn controller_names() {
        assert_eq!(written(|o| Controllers::ALL.write_names(o)), b"memory\n");
        assert_eq!(written(|o| Controllers::NONE.write_names(o)), b"\n");
    }

    #[test]
    fn pids() {
        assert_eq!(parse_pid(b"42\n"), Ok(42));
        assert_eq!(parse_pid(b"0"), Ok(0));
        assert_eq!(parse_pid(b""), Err(Error::Invalid));
        assert_eq!(parse_pid(b"-1"), Err(Error::Invalid));
        assert_eq!(parse_pid(b"4294967296"), Err(Error::Invalid));
        assert_eq!(parse_pid(b"12 13"), Err(Error::Invalid));
    }

    #[test]
    fn stat_and_events_read_as_linux() {
        let stat = MemoryStat {
            anon: 2,
            shmem: 1,
            ..MemoryStat::default()
        };
        let text = written(|o| write_memory_stat(&stat, o));
        assert!(text.starts_with(b"anon 8192\nfile 4096\nkernel 0\n"));
        assert!(text.windows(12).any(|window| window == b"shmem 4096\nf"));
        let events = MemoryEvents {
            max: 3,
            oom: 1,
            oom_kill: 1,
            ..MemoryEvents::default()
        };
        assert_eq!(
            written(|o| write_memory_events(&events, o)),
            b"low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n"
        );
        assert_eq!(
            written(|o| write_cgroup_events(true, o)),
            b"populated 1\nfrozen 0\n"
        );
        assert_eq!(
            written(|o| write_swap_events(0, 2, 1, o)),
            b"high 0\nmax 2\nfail 1\n"
        );
    }

    #[test]
    fn charges_against_limits() {
        assert!(!exceeds(10, 5, UNLIMITED));
        assert!(!exceeds(10, 5, 15));
        assert!(exceeds(10, 6, 15));
        assert!(exceeds(0, 1, 0));
    }

    #[test]
    fn oom_victims() {
        assert_eq!(oom_badness(100, 0, 1, 0, 1000), Some(101));
        assert_eq!(oom_badness(100, 0, 0, -1000, 1000), None);
        assert_eq!(oom_badness(100, 0, 0, 500, 100_000), Some(50_100));
        assert_eq!(
            choose_oom_victim([(1, Some(5)), (2, Some(9)), (3, None), (4, Some(9))]),
            Some(2)
        );
        assert_eq!(choose_oom_victim([(1, None)]), None);
    }

    #[test]
    fn output_refuses_overflow() {
        let mut bytes = [0_u8; 4];
        let mut output = Output::new(&mut bytes);
        assert!(output.push(b"abc"));
        assert!(!output.push(b"de"));
        assert_eq!(output.as_bytes(), b"abc");
        assert!(output.decimal(7));
        assert!(!output.decimal(1));
    }
}
