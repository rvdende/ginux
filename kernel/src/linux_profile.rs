//! A sampling profile of the Linux runtime, Linux's SysRq `l` in spirit:
//! writing `l` to `/proc/sysrq-trigger` samples where the runtime CPU is on
//! each of its next [`SAMPLES`] timer interrupts (the process, user or kernel
//! mode, and the instruction) and prints the counts once the samples are in.
//! A process that stalls everyone else shows up as the samples it takes:
//! its user code spinning, or a kernel loop to symbolize with
//! `tools/debug/symbolize.sh`. It also counts system calls by number, on
//! every CPU, while the samples are taken.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Timer interrupts to sample: a few seconds' worth.
const SAMPLES: u32 = 1000;
/// Distinct (process, mode, instruction) entries kept; samples beyond go
/// to an overflow count.
const ENTRIES: usize = 256;
/// Entries printed: the most frequent.
const PRINTED: usize = 32;

/// Samples still to take.
static REMAINING: AtomicU32 = AtomicU32::new(0);
/// Timer interrupts since boot, to tell a stopped tick from a busy one.
static TICKS: AtomicU64 = AtomicU64::new(0);
/// System calls numbered below this are counted.
const SYSCALLS: usize = 512;
static SYSCALL_COUNTS: [AtomicU32; SYSCALLS] = [const { AtomicU32::new(0) }; SYSCALLS];
/// Ticks when the profile started, to report its length.
static STARTED_AT: AtomicU64 = AtomicU64::new(0);
/// Cycles spent in each system call's handler.
static SYSCALL_CYCLES: [AtomicU64; SYSCALLS] = [const { AtomicU64::new(0) }; SYSCALLS];
/// Lock acquisitions by lock rank (ranks are below 256).
static LOCKS: [AtomicU32; 256] = [const { AtomicU32::new(0) }; 256];

/// Named spans of kernel code timed while a profile runs: how often each
/// ran and the timestamp-counter cycles it took.
#[derive(Clone, Copy)]
pub(crate) enum Span {
    GpuClaimWait,
    GpuSubmit,
    DrmFileIoctl,
    DrmFenceDescriptor,
    ContainerDomainId,
    Snapshot,
    Munmap,
    UserFault,
    SaveProcess,
    RestoreProcess,
    /// A fork system call's request (`linux_request_process_fork`).
    ForkRequest,
    /// The fork transaction's making of the child (`begin_live_fork`).
    ForkBegin,
    /// Its setup of the child's runtime state, until the child first runs.
    ForkPrepare,
    /// A fork transaction's end, the child's run excepted.
    ForkFinish,
}
const SPANS: [&str; 14] = [
    "gpu-claim-wait",
    "gpu-submit",
    "drm-file-ioctl",
    "drm-fence-fd",
    "container-domain-id",
    "snapshot",
    "munmap",
    "user-fault",
    "save-process",
    "restore-process",
    "fork-request",
    "fork-begin",
    "fork-prepare",
    "fork-finish",
];
static SPAN_COUNTS: [AtomicU32; SPANS.len()] = [const { AtomicU32::new(0) }; SPANS.len()];
static SPAN_CYCLES: [AtomicU64; SPANS.len()] = [const { AtomicU64::new(0) }; SPANS.len()];

/// Times `operation` as `span` while a profile runs.
pub(crate) fn span<R>(span: Span, operation: impl FnOnce() -> R) -> R {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return operation();
    }
    let started = crate::arch::x86_64::timer::timestamp_counter();
    let result = operation();
    let cycles = crate::arch::x86_64::timer::timestamp_counter().wrapping_sub(started);
    SPAN_COUNTS[span as usize].fetch_add(1, Ordering::Relaxed);
    SPAN_CYCLES[span as usize].fetch_add(cycles, Ordering::Relaxed);
    result
}

/// Where a span timed by hand starts (`span_since`): a timestamp while a
/// profile runs, else 0.
pub(crate) fn span_start() -> u64 {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    crate::arch::x86_64::timer::timestamp_counter()
}

/// Ends a span `span_start` began, for code with several ways out.
pub(crate) fn span_since(span: Span, started: u64) {
    if started == 0 {
        return;
    }
    let cycles = crate::arch::x86_64::timer::timestamp_counter().wrapping_sub(started);
    SPAN_COUNTS[span as usize].fetch_add(1, Ordering::Relaxed);
    SPAN_CYCLES[span as usize].fetch_add(cycles, Ordering::Relaxed);
}

static OVERFLOW: AtomicU32 = AtomicU32::new(0);
/// Each entry's key, `pid << 1 | kernel` (0 when free), its instruction
/// and its count.
static KEYS: [AtomicU64; ENTRIES] = [const { AtomicU64::new(0) }; ENTRIES];
static INSTRUCTIONS: [AtomicU64; ENTRIES] = [const { AtomicU64::new(0) }; ENTRIES];
static COUNTS: [AtomicU32; ENTRIES] = [const { AtomicU32::new(0) }; ENTRIES];

/// Starts a profile, unless one is under way.
pub(crate) fn start() {
    if REMAINING.load(Ordering::Acquire) != 0 {
        return;
    }
    for index in 0..ENTRIES {
        KEYS[index].store(0, Ordering::Relaxed);
        INSTRUCTIONS[index].store(0, Ordering::Relaxed);
        COUNTS[index].store(0, Ordering::Relaxed);
    }
    OVERFLOW.store(0, Ordering::Relaxed);
    for count in &SYSCALL_COUNTS {
        count.store(0, Ordering::Relaxed);
    }
    for total in &SYSCALL_CYCLES {
        total.store(0, Ordering::Relaxed);
    }
    for count in &LOCKS {
        count.store(0, Ordering::Relaxed);
    }
    for count in &MEMORY_COUNTS {
        count.store(0, Ordering::Relaxed);
    }
    STARTED_AT.store(TICKS.load(Ordering::Relaxed), Ordering::Relaxed);
    crate::linux_drm::reset_ioctl_stats();
    for index in 0..SPANS.len() {
        SPAN_COUNTS[index].store(0, Ordering::Relaxed);
        SPAN_CYCLES[index].store(0, Ordering::Relaxed);
    }
    crate::serial_write("ginux: sysrq: sampling the runtime CPU; timer ticks so far ");
    crate::serial_write_u64(TICKS.load(Ordering::Relaxed));
    crate::serial_write("\r\n");
    REMAINING.store(SAMPLES, Ordering::Release);
}

/// Counts a timer interrupt.
pub(crate) fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Counts an acquisition of a lock of `rank` while a profile runs.
pub(crate) fn count_lock(rank: u16) {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return;
    }
    if let Some(count) = LOCKS.get(usize::from(rank)) {
        count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Adds `cycles` spent handling system call `number` while a profile runs.
pub(crate) fn time_syscall(number: u64, cycles: u64) {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return;
    }
    if let Some(total) = usize::try_from(number)
        .ok()
        .and_then(|n| SYSCALL_CYCLES.get(n))
    {
        total.fetch_add(cycles, Ordering::Relaxed);
    }
}

/// Frame-allocator calls that take its lock, by function, while a profile
/// runs (see `memory`).
const MEMORY_CALLS: [&str; 8] = [
    "allocate_frames",
    "scrub_and_release_frames",
    "share_frames",
    "frame_is_shared",
    "frames_owned_by",
    "any_frame_lease_live",
    "frame_addresses_owned_by",
    "live_frame_lease",
];
static MEMORY_COUNTS: [AtomicU32; MEMORY_CALLS.len()] =
    [const { AtomicU32::new(0) }; MEMORY_CALLS.len()];

pub(crate) fn count_memory(call: usize) {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return;
    }
    if let Some(count) = MEMORY_COUNTS.get(call) {
        count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts system call `number` while a profile runs.
pub(crate) fn count_syscall(number: u64) {
    if REMAINING.load(Ordering::Relaxed) == 0 {
        return;
    }
    if let Some(count) = usize::try_from(number)
        .ok()
        .and_then(|n| SYSCALL_COUNTS.get(n))
    {
        count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Records one timer interrupt of the runtime CPU: process `pid` was at
/// `instruction`, in the kernel or not.
pub(crate) fn sample(pid: u32, kernel: bool, instruction: u64) {
    let Ok(left) = REMAINING.try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
        left.checked_sub(1)
    }) else {
        return;
    };
    let key = u64::from(pid) << 1 | u64::from(kernel) | 1 << 63;
    let start = (instruction ^ key).wrapping_mul(0x9e37_79b9_7f4a_7c15) as usize % ENTRIES;
    let slot = (0..ENTRIES)
        .map(|step| (start + step) % ENTRIES)
        .find(|index| {
            let stored = KEYS[*index].load(Ordering::Relaxed);
            stored == 0
                || stored == key && INSTRUCTIONS[*index].load(Ordering::Relaxed) == instruction
        });
    match slot {
        Some(index) => {
            KEYS[index].store(key, Ordering::Relaxed);
            INSTRUCTIONS[index].store(instruction, Ordering::Relaxed);
            COUNTS[index].fetch_add(1, Ordering::Relaxed);
        }
        None => {
            OVERFLOW.fetch_add(1, Ordering::Relaxed);
        }
    }
    if left == 1 {
        report();
    }
}

fn report() {
    crate::serial_write("ginux: profile: count pid mode instruction\r\n");
    let mut printed = [usize::MAX; PRINTED];
    for rank in 0..PRINTED {
        let best = (0..ENTRIES)
            .filter(|index| !printed[..rank].contains(index))
            .filter(|index| KEYS[*index].load(Ordering::Relaxed) != 0)
            .max_by_key(|index| COUNTS[*index].load(Ordering::Relaxed));
        let Some(index) = best else {
            break;
        };
        printed[rank] = index;
        let key = KEYS[index].load(Ordering::Relaxed);
        crate::serial_write("ginux: profile: ");
        crate::serial_write_u64(u64::from(COUNTS[index].load(Ordering::Relaxed)));
        crate::serial_write(" ");
        crate::serial_write_u64((key & !(1 << 63)) >> 1);
        crate::serial_write(if key & 1 != 0 { " kernel " } else { " user " });
        crate::serial_write_hex(INSTRUCTIONS[index].load(Ordering::Relaxed));
        crate::serial_write("\r\n");
    }
    crate::serial_write("ginux: profile: unrecorded ");
    crate::serial_write_u64(u64::from(OVERFLOW.load(Ordering::Relaxed)));
    crate::serial_write(" over ");
    crate::serial_write_u64(TICKS.load(Ordering::Relaxed) - STARTED_AT.load(Ordering::Relaxed));
    crate::serial_write(" ticks; system calls (number count):");
    let mut shown = [usize::MAX; 16];
    for rank in 0..shown.len() {
        let Some(number) = (0..SYSCALLS)
            .filter(|number| !shown[..rank].contains(number))
            .filter(|number| SYSCALL_COUNTS[*number].load(Ordering::Relaxed) != 0)
            .max_by_key(|number| SYSCALL_COUNTS[*number].load(Ordering::Relaxed))
        else {
            break;
        };
        shown[rank] = number;
        crate::serial_write(" ");
        crate::serial_write_u64(number as u64);
        crate::serial_write(":");
        crate::serial_write_u64(u64::from(SYSCALL_COUNTS[number].load(Ordering::Relaxed)));
    }
    crate::serial_write("\r\n");
    let hz = crate::arch::x86_64::timer::monotonic_frequency()
        .unwrap_or(1)
        .max(1);
    crate::serial_write("ginux: profile: system call time (number us):");
    let mut shown = [usize::MAX; 12];
    for rank in 0..shown.len() {
        let Some(number) = (0..SYSCALLS)
            .filter(|number| !shown[..rank].contains(number))
            .filter(|number| SYSCALL_CYCLES[*number].load(Ordering::Relaxed) != 0)
            .max_by_key(|number| SYSCALL_CYCLES[*number].load(Ordering::Relaxed))
        else {
            break;
        };
        shown[rank] = number;
        crate::serial_write(" ");
        crate::serial_write_u64(number as u64);
        crate::serial_write(":");
        crate::serial_write_u64(SYSCALL_CYCLES[number].load(Ordering::Relaxed) * 1_000_000 / hz);
    }
    crate::serial_write("\r\nginux: profile: locks (rank count):");
    let mut shown = [usize::MAX; 12];
    for rank in 0..shown.len() {
        let Some(lock) = (0..LOCKS.len())
            .filter(|lock| !shown[..rank].contains(lock))
            .filter(|lock| LOCKS[*lock].load(Ordering::Relaxed) != 0)
            .max_by_key(|lock| LOCKS[*lock].load(Ordering::Relaxed))
        else {
            break;
        };
        shown[rank] = lock;
        crate::serial_write(" ");
        crate::serial_write_u64(lock as u64);
        crate::serial_write(":");
        crate::serial_write_u64(u64::from(LOCKS[lock].load(Ordering::Relaxed)));
    }
    crate::serial_write("\r\n");
    crate::linux_drm::report_ioctl_stats();
    let hz = crate::arch::x86_64::timer::monotonic_frequency()
        .unwrap_or(1)
        .max(1);
    crate::serial_write("ginux: profile: frame allocator calls:");
    for (index, name) in MEMORY_CALLS.iter().enumerate() {
        crate::serial_write(" ");
        crate::serial_write(name);
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(MEMORY_COUNTS[index].load(Ordering::Relaxed)));
    }
    crate::serial_write("\r\n");
    crate::serial_write("ginux: profile: spans (name count us):");
    for (index, name) in SPANS.iter().enumerate() {
        crate::serial_write(" ");
        crate::serial_write(name);
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(SPAN_COUNTS[index].load(Ordering::Relaxed)));
        crate::serial_write(" ");
        crate::serial_write_u64(SPAN_CYCLES[index].load(Ordering::Relaxed) * 1_000_000 / hz);
    }
    crate::serial_write("\r\n");
}
