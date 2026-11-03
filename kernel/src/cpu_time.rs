//! Where each CPU's time goes: user code, the kernel, idle, and (part of
//! the kernel's share) waiting for the kernel-entry lock, measured with the
//! timestamp counter. `/proc/stat` reports the first three per CPU, as
//! Linux does; SysRq `u` writes all four to the kernel log, which shows how
//! much the CPUs of a multi-CPU domain hold each other up.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::arch::x86_64::{cpu, timer};

/// CPUs accounted for; others are not.
const CPU_LIMIT: usize = 16;

static USER: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
static IDLE: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
static LOCK_WAIT: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
/// Processes each CPU's scheduling loop took to run.
static RUNS: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
/// When each CPU last left for user mode (0 while it is in the kernel).
static USER_SINCE: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
/// When accounting began for each CPU.
static STARTED: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
/// The interval of CPU time of the process each CPU runs: whose it is (0:
/// none open), when it began and the CPU's user time then, so it splits
/// into user and kernel time (`process_interval`).
static PROCESS_PID: [AtomicU32; CPU_LIMIT] = [const { AtomicU32::new(0) }; CPU_LIMIT];
static PROCESS_SINCE: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];
static PROCESS_USER_SINCE: [AtomicU64; CPU_LIMIT] = [const { AtomicU64::new(0) }; CPU_LIMIT];

fn slot() -> Option<usize> {
    cpu::current_cpu_index_checked().filter(|cpu| *cpu < CPU_LIMIT)
}

fn start(cpu: usize, now: u64) {
    let _ = STARTED[cpu].compare_exchange(0, now, Ordering::AcqRel, Ordering::Acquire);
}

/// This CPU is about to run user code.
pub(crate) fn leave_for_user() {
    if let Some(cpu) = slot() {
        let now = timer::timestamp_counter();
        start(cpu, now);
        USER_SINCE[cpu].store(now, Ordering::Release);
    }
}

/// This CPU came back to the kernel from user code.
pub(crate) fn back_from_user() {
    if let Some(cpu) = slot() {
        let now = timer::timestamp_counter();
        let since = USER_SINCE[cpu].swap(0, Ordering::AcqRel);
        if since != 0 {
            USER[cpu].fetch_add(now.saturating_sub(since), Ordering::Relaxed);
        }
    }
}

/// CPU `cpu`'s user time so far, the current stretch in user mode included.
fn user_cycles(cpu: usize, now: u64) -> u64 {
    let since = USER_SINCE[cpu].load(Ordering::Acquire);
    let running = if since == 0 {
        0
    } else {
        now.saturating_sub(since)
    };
    USER[cpu].load(Ordering::Relaxed) + running
}

/// A process's interval of CPU time on one CPU, in timestamp-counter
/// ticks.
#[derive(Clone, Copy)]
pub(crate) struct ProcessInterval {
    pub(crate) pid: u32,
    pub(crate) total: u64,
    pub(crate) user: u64,
}

/// This CPU starts running process `pid` at timestamp `now`: its interval
/// of CPU time begins. The interval open until now, if any, is closed and
/// returned for its process to be charged (a process run nested inside
/// another's call starts without the other's being charged first).
pub(crate) fn start_process_interval(pid: u32, now: u64) -> Option<ProcessInterval> {
    let cpu = slot()?;
    let open = process_interval(now, true);
    PROCESS_PID[cpu].store(pid, Ordering::Relaxed);
    open
}

/// This CPU's process interval up to `now`; None while none is open.
/// `close` ends it, for a charge: the CPU's time is no process's until
/// the next starts (`start_process_interval`).
pub(crate) fn process_interval(now: u64, close: bool) -> Option<ProcessInterval> {
    let cpu = slot()?;
    let user = user_cycles(cpu, now);
    let (pid, since, user_since) = if close {
        (
            PROCESS_PID[cpu].swap(0, Ordering::Relaxed),
            PROCESS_SINCE[cpu].swap(now, Ordering::Relaxed),
            PROCESS_USER_SINCE[cpu].swap(user, Ordering::Relaxed),
        )
    } else {
        (
            PROCESS_PID[cpu].load(Ordering::Relaxed),
            PROCESS_SINCE[cpu].load(Ordering::Relaxed),
            PROCESS_USER_SINCE[cpu].load(Ordering::Relaxed),
        )
    };
    if since == 0 || pid == 0 {
        return None;
    }
    let total = now.saturating_sub(since);
    Some(ProcessInterval {
        pid,
        total,
        user: user.saturating_sub(user_since).min(total),
    })
}

/// This CPU idled for `ticks` timestamp-counter ticks.
pub(crate) fn add_idle(ticks: u64) {
    if let Some(cpu) = slot() {
        start(cpu, timer::timestamp_counter());
        IDLE[cpu].fetch_add(ticks, Ordering::Relaxed);
    }
}

/// This CPU waited `ticks` timestamp-counter ticks for the kernel-entry lock.
pub(crate) fn add_lock_wait(ticks: u64) {
    if let Some(cpu) = slot() {
        LOCK_WAIT[cpu].fetch_add(ticks, Ordering::Relaxed);
    }
}

/// This CPU's scheduling loop took a process to run.
pub(crate) fn add_run() {
    if let Some(cpu) = slot() {
        RUNS[cpu].fetch_add(1, Ordering::Relaxed);
    }
}

/// CPU `cpu`'s time since accounting began, in timestamp-counter ticks:
/// total, user, idle and kernel-entry lock waits; None for a CPU that never
/// ran Linux code.
pub(crate) fn times(cpu: usize) -> Option<[u64; 4]> {
    let started = STARTED.get(cpu)?.load(Ordering::Acquire);
    if started == 0 {
        return None;
    }
    let now = timer::timestamp_counter();
    let since = USER_SINCE[cpu].load(Ordering::Acquire);
    let running = if since == 0 {
        0
    } else {
        now.saturating_sub(since)
    };
    Some([
        now.saturating_sub(started),
        USER[cpu].load(Ordering::Relaxed) + running,
        IDLE[cpu].load(Ordering::Relaxed),
        LOCK_WAIT[cpu].load(Ordering::Relaxed),
    ])
}

/// SysRq `u`: each CPU's user, kernel, idle and lock-wait time so far, in
/// milliseconds.
pub(crate) fn report() {
    let frequency = timer::monotonic_frequency().unwrap_or(1).max(1);
    crate::serial_write("ginux: sysrq: cpu time (ms) cpu/user/kernel/idle/lock-wait, runs:\r\n");
    for (cpu, runs) in RUNS.iter().enumerate() {
        let Some([total, user, idle, lock]) = times(cpu) else {
            continue;
        };
        let kernel = total.saturating_sub(user).saturating_sub(idle);
        crate::serial_write("ginux: cpu ");
        crate::serial_write_u64(cpu as u64);
        for value in [user, kernel, idle, lock] {
            crate::serial_write(" ");
            crate::serial_write_u64(value.saturating_mul(1000) / frequency);
        }
        crate::serial_write(" ");
        crate::serial_write_u64(runs.load(Ordering::Relaxed));
        crate::serial_write("\r\n");
    }
}
