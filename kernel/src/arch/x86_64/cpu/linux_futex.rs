#![forbid(unsafe_code)]
use super::*;

static LINUX_PROFILE_FIRST_FUTEX_OPERATION: AtomicU64 = AtomicU64::new(u64::MAX);
static LINUX_PROFILE_FUTEX_OPERATION_COUNTS: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];

/// A process waiting on a futex word while other processes run. A process
/// other than init waits by restarting the call, so the record outlives the
/// restarts: a wake from another process finds and marks it, and a timeout
/// counts from the first attempt.
#[derive(Clone, Copy)]
pub(super) struct LinuxProcessFutexWait {
    pid: u32,
    /// The waiting thread: other threads of the process make futex calls
    /// of their own meanwhile, on other CPUs.
    tid: u32,
    /// The futex word's address in the waiting process, which its call
    /// passes again when it restarts.
    address: u64,
    /// The word waited on, as `linux_futex_key` names it: the address's
    /// unless a requeue moved the wait to another word.
    key: u64,
    mask: u32,
    /// Elapsed nanoseconds when the wait times out, or 0.
    deadline: u64,
    woken: bool,
    /// One word of a futex_waitv wait, which has a record per word: the
    /// call returns the index of the first one woken.
    vector: bool,
    index: u8,
    /// The waiting thread's slot when a vector wait blocked it as a thread
    /// wait of its process (`LINUX_FUTEX_VECTOR_KEY`): wakes from that
    /// process find it by address and make the thread ready. None for a
    /// wait at the process level, which wakes from any process find by key.
    thread_slot: Option<u8>,
}

/// The wait key of a thread blocked in a futex_waitv wait: its tid under a
/// tag no futex address has, so a classic wake never matches it and a
/// vector record names its thread's current wait.
const LINUX_FUTEX_VECTOR_KEY: u64 = 1 << 62;

/// Identifies a futex word across processes by the page it is on, so
/// processes sharing the page (MAP_SHARED, or not yet copied after fork)
/// meet on it.
pub(super) fn linux_futex_key(address: u64) -> u64 {
    let page = address & !(PAGE_SIZE as u64 - 1);
    address_space::current_linux_runtime_page(page)
        .frame
        .map_or(address | 1 << 63, |frame| {
            frame.address() + (address - page)
        })
}

/// Ends `pid`'s process futex wait, returning it.
fn take_linux_process_futex_wait(
    waits: &mut Vec<LinuxProcessFutexWait>,
    pid: u32,
    tid: u32,
) -> Option<LinuxProcessFutexWait> {
    let index = waits
        .iter()
        .position(|wait| !wait.vector && wait.pid == pid && wait.tid == tid)?;
    Some(waits.swap_remove(index))
}

/// Whether thread-level vector record `wait` still names its thread's
/// wait: the thread is blocked in it, not since woken, timed out or
/// interrupted (which leave the records for its next wait to drop).
fn linux_futex_vector_thread_waiting(wait: &LinuxProcessFutexWait) -> bool {
    let Some(slot) = wait.thread_slot.map(usize::from) else {
        return false;
    };
    wait.pid == current_linux_process_pid()
        && slot < LINUX_THREAD_LIMIT
        && X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::SeqCst) == wait.tid
        && X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_BLOCKED
        && X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            == LINUX_THREAD_WAIT_FUTEX
        && X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst)
            == LINUX_FUTEX_VECTOR_KEY | u64::from(wait.tid)
}

/// Wakes up to `limit` threads of this process blocked in futex_waitv
/// waits on the word at `address`: each returns the index of the word
/// that woke it, and its records go.
pub(super) fn wake_linux_futex_vector_threads(
    waits: &mut Vec<LinuxProcessFutexWait>,
    address: u64,
    mask: u32,
    limit: u32,
) -> u32 {
    // Records of this process's threads that left their vector waits
    // another way (timed out, interrupted, exited) go here; a thread puts
    // its records and blocks under the same lock, so none is half made.
    let pid = current_linux_process_pid();
    waits.retain(|wait| {
        wait.thread_slot.is_none() || wait.pid != pid || linux_futex_vector_thread_waiting(wait)
    });
    let mut woken = 0;
    while woken < limit {
        let Some(wait) = waits
            .iter()
            .find(|wait| {
                wait.thread_slot.is_some()
                    && wait.address == address
                    && wait.mask & mask != 0
                    && linux_futex_vector_thread_waiting(wait)
            })
            .copied()
        else {
            break;
        };
        let slot = usize::from(wait.thread_slot.unwrap_or(0));
        X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(u64::from(wait.index), Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
        waits.retain(|other| !(other.vector && other.pid == wait.pid && other.tid == wait.tid));
        linux_trace_futex(8, address, slot as u64);
        woken += 1;
    }
    woken
}

/// Marks up to `limit` processes waiting on `key` woken, dropping records of
/// processes that are gone.
pub(super) fn wake_linux_process_futex_waits(key: u64, mask: u32, limit: u32) -> u32 {
    let mut waits = LINUX_FUTEX_COORDINATION.lock();
    waits.retain(|wait| {
        linux_process::live_process_status(wait.pid).is_some_and(|status| status.state.is_running())
    });
    let mut woken = 0;
    for wait in waits.iter_mut().filter(|wait| {
        !wait.woken && wait.thread_slot.is_none() && wait.key == key && wait.mask & mask != 0
    }) {
        if woken == limit {
            break;
        }
        wait.woken = true;
        linux_process::set_live_process_waiting(wait.pid, false);
        linux_trace_futex(2, key, u64::from(wait.pid) << 32 | u64::from(wait.tid));
        woken += 1;
    }
    woken
}

fn profile_linux_futex_operation(operation: u64) {
    if !cfg!(feature = "linux-boot-profile") {
        return;
    }
    if LINUX_PROFILE_FIRST_FUTEX_OPERATION
        .compare_exchange(u64::MAX, operation, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        serial_write("ginux: profile futex operation: ");
        serial_write_u64(operation);
        serial_write("\r\n");
    }
    if let Some(count) = usize::try_from(operation)
        .ok()
        .and_then(|operation| LINUX_PROFILE_FUTEX_OPERATION_COUNTS.get(operation))
    {
        count.fetch_add(1, Ordering::Relaxed);
    }
}

pub(super) fn write_linux_futex_profile() {
    if !cfg!(feature = "linux-boot-profile") {
        return;
    }
    for (operation, count) in LINUX_PROFILE_FUTEX_OPERATION_COUNTS.iter().enumerate() {
        let count = count.swap(0, Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        serial_write("ginux: profile futex operation/count: ");
        serial_write_u64(operation as u64);
        serial_write("/");
        serial_write_u64(count);
        serial_write("\r\n");
    }
}

/// Wakes up to `wake` waiters on the futex word at `source` and moves up
/// to `requeue` more to the word at `target`, threads of this process and
/// other processes alike; returns how many it woke or moved, as Linux's
/// requeue does.
fn requeue_linux_futex_waits(source: u64, target: u64, wake: u32, requeue: u32) -> u32 {
    let mut woken = wake_linux_futex_masked(source, u32::MAX, wake);
    let (source_key, target_key) = (linux_futex_key(source), linux_futex_key(target));
    let mut waits = LINUX_FUTEX_COORDINATION.lock();
    waits.retain(|wait| {
        linux_process::live_process_status(wait.pid).is_some_and(|status| status.state.is_running())
    });
    let mut moved = 0;
    // A thread blocked in a vector wait was woken above if it was due; one
    // left waits on the target word from here. Linux requeues a waitv
    // waiter's word the same way.
    let current_pid = current_linux_process_pid();
    for wait in waits.iter_mut().filter(|wait| {
        wait.thread_slot.is_some() && wait.pid == current_pid && wait.address == source
    }) {
        if moved == requeue {
            break;
        }
        wait.address = target;
        wait.key = target_key;
        moved += 1;
    }
    for wait in waits
        .iter_mut()
        .filter(|wait| !wait.woken && wait.thread_slot.is_none() && wait.key == source_key)
    {
        if woken < wake {
            wait.woken = true;
            linux_process::set_live_process_waiting(wait.pid, false);
            woken += 1;
        } else if moved < requeue {
            wait.key = target_key;
            moved += 1;
        } else {
            break;
        }
    }
    for slot in 0..LINUX_THREAD_LIMIT {
        if moved == requeue {
            break;
        }
        if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_BLOCKED
            && X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
                == LINUX_THREAD_WAIT_FUTEX
            && X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst) == source
        {
            X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(target, Ordering::SeqCst);
            moved += 1;
        }
    }
    woken + moved
}

#[allow(clippy::too_many_arguments)]
pub(super) fn linux_futex_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    address: u64,
    operation: u64,
    value: u64,
    timeout: u64,
    target: u64,
    bitset: u64,
) -> u64 {
    const FUTEX_COMMAND_MASK: u64 = 0x7f;
    const FUTEX_WAIT: u64 = 0;
    const FUTEX_WAKE: u64 = 1;
    const FUTEX_REQUEUE: u64 = 3;
    const FUTEX_CMP_REQUEUE: u64 = 4;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_WAKE_BITSET: u64 = 10;
    const FUTEX_PRIVATE_FLAG: u64 = 128;
    const FUTEX_CLOCK_REALTIME: u64 = 256;

    profile_linux_futex_operation(operation);
    // The classic futex call takes a 32-bit bitset; callers such as Rust's
    // standard library pass it through a variadic argument whose upper half
    // is unspecified, so truncate as Linux does.
    let bitset = bitset & u64::from(u32::MAX);
    let command = operation & FUTEX_COMMAND_MASK;
    let flags = operation & !FUTEX_COMMAND_MASK;
    if !address.is_multiple_of(size_of::<u32>() as u64)
        || flags & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME) != 0
        || flags & FUTEX_CLOCK_REALTIME != 0 && command != FUTEX_WAIT_BITSET
    {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; size_of::<u32>()];
    if !copy_from_linux_user(address, &mut bytes) {
        // A word on a page not mapped in yet (a SysV segment just attached)
        // is mapped by the owner's path; the light path cannot change page
        // tables (futex_waitv03's waker thread).
        if linux_light_thread_here().is_some() {
            return migrate_current_linux_thread_to_owner(caller, LINUX_FUTEX_SYSCALL);
        }
        return LINUX_EFAULT;
    }
    if matches!(command, FUTEX_REQUEUE | FUTEX_CMP_REQUEUE) {
        // Both counts are C ints; the timeout argument carries how many
        // waiters to requeue.
        let (wake, requeue) = (value as u32 as i32, timeout as u32 as i32);
        if wake < 0 || requeue < 0 || !target.is_multiple_of(size_of::<u32>() as u64) {
            return LINUX_EINVAL;
        }
        let mut target_bytes = [0_u8; size_of::<u32>()];
        if !copy_from_linux_user(target, &mut target_bytes) {
            return LINUX_EFAULT;
        }
        if command == FUTEX_CMP_REQUEUE && u32::from_ne_bytes(bytes) != bitset as u32 {
            return LINUX_EAGAIN;
        }
        return u64::from(requeue_linux_futex_waits(
            address,
            target,
            wake as u32,
            requeue as u32,
        ));
    }
    if matches!(command, FUTEX_WAKE | FUTEX_WAKE_BITSET) {
        let mask = if command == FUTEX_WAKE_BITSET {
            let Ok(mask) = u32::try_from(bitset) else {
                return LINUX_EINVAL;
            };
            if mask == 0 {
                return LINUX_EINVAL;
            }
            mask
        } else {
            u32::MAX
        };
        let limit = u32::try_from(value).unwrap_or(u32::MAX);
        let threads = wake_linux_futex_masked(address, mask, limit);
        let woken = threads
            + wake_linux_process_futex_waits(linux_futex_key(address), mask, limit - threads);
        linux_trace_futex(
            3,
            address,
            u64::from(threads) << 32 | u64::from(woken - threads),
        );
        if woken != 0 {
            X86_RUNTIME
                .LINUX_FUTEX_EXPLICIT_WAKE_COUNT
                .fetch_add(1, Ordering::SeqCst);
        }
        return u64::from(woken);
    }
    if !matches!(command, FUTEX_WAIT | FUTEX_WAIT_BITSET)
        || command == FUTEX_WAIT_BITSET && bitset == 0
    {
        return LINUX_EINVAL;
    }
    // A wait this call began before it restarted ends here: woken by
    // another process, or kept for its deadline if it waits again.
    let pid = current_linux_process_pid();
    let tid = current_linux_tid().unwrap_or(0);
    let earlier = take_linux_process_futex_wait(&mut LINUX_FUTEX_COORDINATION.lock(), pid, tid)
        .filter(|wait| wait.address == address);
    linux_trace_futex(
        5,
        address,
        earlier.map_or(2, |wait| u64::from(wait.woken)) | u64::from(u32::from_ne_bytes(bytes)) << 8,
    );
    if earlier.is_some_and(|wait| wait.woken) {
        return 0;
    }
    // musl passes the expected value as a sign-extended int; Linux compares
    // only the 32-bit futex word. A wait resumed after a restart compared
    // it when it began, and may since have been requeued to another word.
    if earlier.is_none() && u32::from_ne_bytes(bytes) != value as u32 {
        linux_trace_futex(9, address, value);
        return LINUX_EAGAIN;
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let mut target = ready_linux_thread_handle();
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let deadline = if timeout == 0 {
        0
    } else {
        let mut timeout_bytes = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut timeout_bytes) {
            return LINUX_EFAULT;
        }
        let Some(requested) = linux_timespec_nanoseconds(&timeout_bytes) else {
            return LINUX_EINVAL;
        };
        if command == FUTEX_WAIT {
            if requested == 0 {
                return LINUX_ETIMEDOUT;
            }
            let Some(deadline) =
                linux_elapsed_nanoseconds().and_then(|now| now.checked_add(requested))
            else {
                return LINUX_EINVAL;
            };
            deadline
        } else {
            let Some(monotonic_now) = linux_elapsed_nanoseconds() else {
                return LINUX_ENOSYS;
            };
            if flags & FUTEX_CLOCK_REALTIME == 0 {
                if monotonic_now >= requested {
                    return LINUX_ETIMEDOUT;
                }
                requested
            } else {
                let Some((seconds, nanoseconds)) = linux_realtime_time() else {
                    return LINUX_ENOSYS;
                };
                let Some(realtime_now) = seconds
                    .checked_mul(NANOSECONDS_PER_SECOND)
                    .and_then(|seconds| seconds.checked_add(nanoseconds))
                else {
                    return LINUX_EINVAL;
                };
                if realtime_now >= requested {
                    return LINUX_ETIMEDOUT;
                }
                monotonic_now.saturating_add(requested - realtime_now)
            }
        }
    };
    let wait_mask = if command == FUTEX_WAIT_BITSET {
        bitset
    } else {
        u64::from(u32::MAX)
    };
    let mut deadline = deadline;
    // Set once this call has waited at the process level and goes on as a
    // thread wait: the futex word was compared when the wait began.
    let mut compared = false;
    if target.is_none() && current_linux_runtime_cpu_index() == 0 {
        // Another process may be the one to change the futex word, or to
        // wake it.
        let key;
        (key, deadline) = earlier.map_or((linux_futex_key(address), deadline), |wait| {
            (wait.key, wait.deadline)
        });
        if deadline != 0 && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline) {
            return LINUX_ETIMEDOUT;
        }
        {
            let mut waits = LINUX_FUTEX_COORDINATION.lock();
            if waits.try_reserve(1).is_err() {
                return LINUX_ENOMEM;
            }
            waits.push(LinuxProcessFutexWait {
                pid,
                tid,
                address,
                key,
                mask: wait_mask as u32,
                deadline,
                woken: false,
                vector: false,
                index: 0,
                thread_slot: None,
            });
        }
        linux_trace_futex(1, address, key);
        // A process with no other thread sleeps until a wake, a signal or
        // its deadline: until then nothing need resume it to look again.
        let single_threaded = (0..LINUX_THREAD_LIMIT).all(|slot| {
            Some(slot) == current_linux_thread_slot()
                || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_FREE
        });
        // It sleeps until the wait's deadline or a timer of its own, which
        // only its call notices, whichever is due first.
        let wake_deadline = [
            deadline,
            X86_RUNTIME
                .ELF_PROBE_REAL_TIMER_DEADLINE
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_POSIX_TIMER_DEADLINE
                .load(Ordering::SeqCst),
        ]
        .into_iter()
        .filter(|deadline| *deadline != 0)
        .min()
        .unwrap_or(0);
        let result = loop {
            // Each dispatch clears it: set again for every sleep.
            if single_threaded {
                linux_process::set_live_process_futex_sleep(pid, Some(wake_deadline));
            }
            match run_other_linux_processes(output, caller, LINUX_FUTEX_SYSCALL) {
                // Yielded: the call starts again and finds its wait.
                Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                    return LINUX_RETURN_TO_KERNEL;
                }
                Some(LinuxBlockedWait::Return(result)) => break Some(result),
                // Nothing else could run, or a sibling thread was made ready
                // (its sleep ended while this process waited).
                None => break None,
                // Waited in the call (parked): done when FUTEX_WAKE marked the
                // wait or its deadline passed, else wait again.
                Some(LinuxBlockedWait::Recheck) => {
                    let woken = LINUX_FUTEX_COORDINATION
                        .lock()
                        .iter()
                        .any(|wait| wait.pid == pid && wait.tid == tid && wait.woken);
                    if woken {
                        break Some(0);
                    }
                    if deadline != 0
                        && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
                    {
                        break Some(LINUX_ETIMEDOUT);
                    }
                }
            }
        };
        linux_process::set_live_process_futex_sleep(pid, None);
        let wait = take_linux_process_futex_wait(&mut LINUX_FUTEX_COORDINATION.lock(), pid, tid);
        linux_trace_futex(
            6,
            address,
            result.unwrap_or(u64::MAX - 1) | u64::from(wait.is_some_and(|wait| wait.woken)) << 62,
        );
        if let Some(result) = result {
            return result;
        }
        // A sibling thread is ready: this thread goes on waiting as a
        // thread wait while it runs, unless the wait already ended. With
        // nothing to run, it wakes spuriously, which callers allow for.
        target = ready_linux_thread_handle();
        if wait.is_some_and(|wait| wait.woken) || target.is_none() {
            return 0;
        }
        compared = true;
    }
    let coordination = LINUX_FUTEX_COORDINATION.lock();
    if !compared {
        if !copy_from_linux_user(address, &mut bytes) {
            return LINUX_EFAULT;
        }
        if u32::from_ne_bytes(bytes) != value as u32 {
            return LINUX_EAGAIN;
        }
    }
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(LINUX_THREAD_WAIT_FUTEX, address, wait_mask, deadline)
    {
        return LINUX_EINVAL;
    }
    drop(coordination);
    linux_trace_futex(
        4,
        address,
        target.map_or(255, |target| u64::from(target.slot)),
    );
    let Some(target) = target else {
        X86_RUNTIME
            .LINUX_FUTEX_WAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    };
    switch_from_blocked_linux_futex_waiter(output, current, tls, target)
}

pub(super) fn linux_futex2_flags_valid(flags: u64) -> bool {
    const FUTEX2_SIZE_U32: u64 = 2;
    const FUTEX2_PRIVATE: u64 = 128;
    flags & !(FUTEX2_SIZE_U32 | FUTEX2_PRIVATE) == 0 && flags & 3 == FUTEX2_SIZE_U32
}

pub(super) fn linux_futex_wake(address: u64, mask: u64, count: u64, flags: u64) -> u64 {
    if !linux_futex2_flags_valid(flags)
        || !address.is_multiple_of(size_of::<u32>() as u64)
        || mask == 0
        || mask > u64::from(u32::MAX)
        || count > i32::MAX as u64
    {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; size_of::<u32>()];
    if !copy_from_linux_user(address, &mut bytes) {
        return LINUX_EFAULT;
    }
    let limit = count as u32;
    let threads = wake_linux_futex_masked(address, mask as u32, limit);
    u64::from(
        threads
            + wake_linux_process_futex_waits(
                linux_futex_key(address),
                mask as u32,
                limit - threads,
            ),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn linux_futex_wait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    address: u64,
    value: u64,
    mask: u64,
    flags: u64,
    timeout: u64,
    clock: u64,
) -> u64 {
    if !linux_futex2_flags_valid(flags)
        || !address.is_multiple_of(size_of::<u32>() as u64)
        || value > u64::from(u32::MAX)
        || mask == 0
        || mask > u64::from(u32::MAX)
        || !matches!(clock, 0 | 1)
    {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; size_of::<u32>()];
    if !copy_from_linux_user(address, &mut bytes) {
        return LINUX_EFAULT;
    }
    if u32::from_ne_bytes(bytes) != value as u32 {
        return LINUX_EAGAIN;
    }
    let deadline = if timeout == 0 {
        0
    } else {
        let mut timeout_bytes = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut timeout_bytes) {
            return LINUX_EFAULT;
        }
        let Some(deadline) = linux_timespec_nanoseconds(&timeout_bytes) else {
            return LINUX_EINVAL;
        };
        let Some(monotonic_now) = linux_elapsed_nanoseconds() else {
            return LINUX_ENOSYS;
        };
        let deadline = if clock == LINUX_CLOCK_REALTIME {
            let Some((seconds, nanoseconds)) = linux_realtime_time() else {
                return LINUX_ENOSYS;
            };
            let Some(realtime_now) = seconds
                .checked_mul(NANOSECONDS_PER_SECOND)
                .and_then(|seconds| seconds.checked_add(nanoseconds))
            else {
                return LINUX_EINVAL;
            };
            monotonic_now.saturating_add(deadline.saturating_sub(realtime_now))
        } else {
            deadline
        };
        if monotonic_now >= deadline {
            return LINUX_ETIMEDOUT;
        }
        deadline
    };
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let Some(target) = ready_linux_thread_handle() else {
        // Another process may be the one to change the futex word.
        if deadline == 0 {
            return match run_other_linux_processes(output, caller, number) {
                Some(LinuxBlockedWait::Return(result)) => result,
                // Callers recheck their condition after any wakeup, spurious
                // ones included.
                Some(LinuxBlockedWait::Recheck) | None => 0,
            };
        }
        // A timed wait goes on until its deadline (ETIMEDOUT, which
        // futex_waitv01 waits for), a signal, or the word changing.
        loop {
            let now = linux_elapsed_nanoseconds().unwrap_or(deadline);
            if now >= deadline {
                return LINUX_ETIMEDOUT;
            }
            if !copy_from_linux_user(address, &mut bytes)
                || u32::from_ne_bytes(bytes) != value as u32
            {
                return 0;
            }
            let turn = linux_timed_wait_run_others(output, caller, number, Some(deadline));
            if let LinuxWaitTurn::Done(result) = turn {
                return result;
            }
            if ready_linux_thread_handle().is_some() {
                return 0;
            }
            if let LinuxWaitTurn::Idle = turn {
                timer::request_linux_tick_within(deadline.saturating_sub(now));
                linux_wait_for_interrupt();
            }
        }
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    let coordination = LINUX_FUTEX_COORDINATION.lock();
    if !copy_from_linux_user(address, &mut bytes) {
        return LINUX_EFAULT;
    }
    if u32::from_ne_bytes(bytes) != value as u32 {
        return LINUX_EAGAIN;
    }
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(LINUX_THREAD_WAIT_FUTEX, address, mask, deadline)
    {
        return LINUX_EINVAL;
    }
    drop(coordination);
    switch_from_blocked_linux_futex_waiter(output, current, tls, target)
}

/// futex_waitv's absolute `timeout` on `clock` (0 realtime, 1 monotonic)
/// as an elapsed-nanoseconds deadline, 0 without one; Err(errno) as
/// Linux's futex2_setup_timeout. A deadline already past is returned as
/// is: the words are compared first, as in Linux.
fn linux_futex_waitv_deadline(timeout: u64, clock: u64) -> Result<u64, u64> {
    if timeout == 0 {
        return Ok(0);
    }
    if !matches!(clock, LINUX_CLOCK_REALTIME | LINUX_CLOCK_MONOTONIC) {
        return Err(LINUX_EINVAL);
    }
    let mut timeout_bytes = [0_u8; 16];
    if !copy_from_linux_user(timeout, &mut timeout_bytes) {
        return Err(LINUX_EFAULT);
    }
    let requested = linux_timespec_nanoseconds(&timeout_bytes).ok_or(LINUX_EINVAL)?;
    let monotonic_now = linux_elapsed_nanoseconds().ok_or(LINUX_ENOSYS)?;
    if clock == LINUX_CLOCK_MONOTONIC {
        return Ok(requested.max(1));
    }
    let (seconds, nanoseconds) = linux_realtime_time().ok_or(LINUX_ENOSYS)?;
    let realtime_now = seconds
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(nanoseconds))
        .ok_or(LINUX_EINVAL)?;
    Ok(if requested <= realtime_now {
        monotonic_now.max(1)
    } else {
        monotonic_now.saturating_add(requested - realtime_now)
    })
}

/// One futex_waitv waiter: the word's address and the value it must hold.
#[derive(Clone, Copy)]
struct LinuxFutexVectorWord {
    address: u64,
    value: u32,
}

/// futex_waitv(2): waits on up to 128 futex words at once until one is
/// woken (the call returns its index), the absolute timeout passes or a
/// signal arrives, as Linux's futex_wait_multiple. Every word is checked
/// first: the first whose value differs ends the call with EAGAIN.
#[allow(clippy::too_many_arguments)]
pub(super) fn linux_futex_waitv_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    waiters: u64,
    count: u64,
    flags: u64,
    timeout: u64,
    clock: u64,
) -> u64 {
    const FUTEX2_VALID_MASK: u32 = 0x3 | 0x80 | 0x4 | 0x8;
    // No waiter array is EINVAL before anything is read, as in Linux.
    if flags != 0 || count == 0 || count > 128 || waiters == 0 {
        return LINUX_EINVAL;
    }
    let deadline = match linux_futex_waitv_deadline(timeout, clock) {
        Ok(deadline) => deadline,
        Err(error) => return error,
    };
    // futex_parse_waitv: each entry's flags, reserved word and value.
    let mut words = [LinuxFutexVectorWord {
        address: 0,
        value: 0,
    }; 128];
    let words = &mut words[..count as usize];
    for (index, word) in words.iter_mut().enumerate() {
        let mut entry = [0_u8; 24];
        if !copy_from_linux_user(waiters + index as u64 * 24, &mut entry) {
            return LINUX_EFAULT;
        }
        let value = u64::from_ne_bytes(entry[..8].try_into().unwrap());
        let address = u64::from_ne_bytes(entry[8..16].try_into().unwrap());
        let entry_flags = u32::from_ne_bytes(entry[16..20].try_into().unwrap());
        let reserved = u32::from_ne_bytes(entry[20..24].try_into().unwrap());
        if entry_flags & !FUTEX2_VALID_MASK != 0
            || reserved != 0
            || !linux_futex2_flags_valid(u64::from(entry_flags))
            || value > u64::from(u32::MAX)
        {
            return LINUX_EINVAL;
        }
        *word = LinuxFutexVectorWord {
            address,
            value: value as u32,
        };
    }
    // get_futex_key for each, then each word's value in order.
    if words
        .iter()
        .any(|word| !word.address.is_multiple_of(size_of::<u32>() as u64))
    {
        return LINUX_EINVAL;
    }
    let compare = |words: &[LinuxFutexVectorWord], locked: bool| {
        for word in words {
            let mut bytes = [0_u8; size_of::<u32>()];
            if !copy_from_linux_user(word.address, &mut bytes) {
                // A word on a page not mapped in yet (a SysV segment just
                // attached) is mapped by the owner's path.
                if !locked && linux_light_thread_here().is_some() {
                    return Some(migrate_current_linux_thread_to_owner(
                        caller,
                        LINUX_FUTEX_WAITV_SYSCALL,
                    ));
                }
                return Some(LINUX_EFAULT);
            }
            if u32::from_ne_bytes(bytes) != word.value {
                return Some(LINUX_EAGAIN);
            }
        }
        None
    };
    let pid = current_linux_process_pid();
    let tid = current_linux_tid().unwrap_or(0);
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    // A wait this call began before it restarted (it yielded to another
    // process) is still recorded: it ends if a word was woken, else goes on
    // to its deadline without comparing the words again.
    // Only this call can have left process-level records of this thread's
    // (any other wait removes them as it ends); a requeue may have moved
    // their words since.
    let restarted: Option<(Option<u8>, u64)> = {
        let mut waits = LINUX_FUTEX_COORDINATION.lock();
        let ours = |wait: &LinuxProcessFutexWait| {
            wait.vector && wait.thread_slot.is_none() && wait.pid == pid && wait.tid == tid
        };
        let recorded = waits.iter().filter(|wait| ours(wait)).count();
        if recorded == words.len() {
            let woken = waits
                .iter()
                .filter(|wait| ours(wait) && wait.woken)
                .map(|wait| wait.index)
                .min();
            let deadline = waits
                .iter()
                .find(|wait| ours(wait))
                .map_or(0, |wait| wait.deadline);
            Some((woken, deadline))
        } else {
            waits.retain(|wait| !(wait.vector && wait.pid == pid && wait.tid == tid));
            None
        }
    };
    if let Some((Some(index), _)) = restarted {
        LINUX_FUTEX_COORDINATION
            .lock()
            .retain(|wait| !(wait.vector && wait.pid == pid && wait.tid == tid));
        return u64::from(index);
    }
    let deadline = restarted.map_or(deadline, |(_, deadline)| deadline);
    if restarted.is_none() {
        if let Some(result) = compare(words, false) {
            return result;
        }
    }
    if deadline != 0 && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline) {
        LINUX_FUTEX_COORDINATION
            .lock()
            .retain(|wait| !(wait.vector && wait.pid == pid && wait.tid == tid));
        return LINUX_ETIMEDOUT;
    }
    let record = |index: usize, word: &LinuxFutexVectorWord, thread_slot: Option<u8>| {
        LinuxProcessFutexWait {
            pid,
            tid,
            address: word.address,
            key: linux_futex_key(word.address),
            mask: u32::MAX,
            deadline,
            woken: false,
            vector: true,
            index: index as u8,
            thread_slot,
        }
    };
    let process_woken_index = || {
        LINUX_FUTEX_COORDINATION
            .lock()
            .iter()
            .filter(|wait| {
                wait.vector
                    && wait.thread_slot.is_none()
                    && wait.pid == pid
                    && wait.tid == tid
                    && wait.woken
            })
            .map(|wait| wait.index)
            .min()
    };
    let forget = || {
        LINUX_FUTEX_COORDINATION
            .lock()
            .retain(|wait| !(wait.vector && wait.pid == pid && wait.tid == tid));
    };
    if ready_linux_thread_handle().is_none() && current_linux_runtime_cpu_index() == 0 {
        // At the process level: a wake from any process sharing a word
        // marks its record, and the call looks again each time it runs.
        if restarted.is_none() {
            let mut waits = LINUX_FUTEX_COORDINATION.lock();
            if waits.try_reserve(words.len()).is_err() {
                return LINUX_ENOMEM;
            }
            waits.extend(
                words
                    .iter()
                    .enumerate()
                    .map(|(index, word)| record(index, word, None)),
            );
        }
        let result = loop {
            if let Some(index) = process_woken_index() {
                break Some(u64::from(index));
            }
            if deadline != 0 && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline) {
                break Some(LINUX_ETIMEDOUT);
            }
            let turn = linux_timed_wait_run_others(
                output,
                caller,
                LINUX_FUTEX_WAITV_SYSCALL,
                (deadline != 0).then_some(deadline),
            );
            match turn {
                // Yielded: the call starts again and finds its records.
                LinuxWaitTurn::Done(LINUX_RETURN_TO_KERNEL) => return LINUX_RETURN_TO_KERNEL,
                LinuxWaitTurn::Done(result) => break Some(result),
                LinuxWaitTurn::Resumed => {}
                LinuxWaitTurn::Idle => {
                    // A sibling thread is ready: the wait goes on as a
                    // thread wait while it runs.
                    if ready_linux_thread_handle().is_some() {
                        break None;
                    }
                    if let Some(now) = linux_elapsed_nanoseconds().filter(|_| deadline != 0) {
                        timer::request_linux_tick_within(deadline.saturating_sub(now));
                    }
                    linux_wait_for_interrupt();
                }
            }
        };
        if let Some(result) = result {
            forget();
            return result;
        }
    }
    // As a thread wait while a sibling runs (or on a CPU other than the
    // boot CPU): a wake from this process finds the thread by its records.
    // The words were compared when the wait began if it began at the
    // process level, whose records a wake may have marked meanwhile.
    let compared = restarted.is_some()
        || LINUX_FUTEX_COORDINATION
            .lock()
            .iter()
            .any(|wait| wait.vector && wait.pid == pid && wait.tid == tid);
    let target = ready_linux_thread_handle();
    let Some(tls) = linux_thread_context(current) else {
        forget();
        return LINUX_ESRCH;
    };
    let slot = current.slot;
    let mut waits = LINUX_FUTEX_COORDINATION.lock();
    let ours = |wait: &LinuxProcessFutexWait| wait.vector && wait.pid == pid && wait.tid == tid;
    if let Some(index) = waits
        .iter()
        .filter(|wait| ours(wait) && wait.woken)
        .map(|wait| wait.index)
        .min()
    {
        waits.retain(|wait| !ours(wait));
        return u64::from(index);
    }
    if !compared {
        if let Some(result) = compare(words, true) {
            return result;
        }
    }
    if waits.try_reserve(words.len()).is_err() {
        waits.retain(|wait| !ours(wait));
        return LINUX_ENOMEM;
    }
    waits.retain(|wait| !ours(wait));
    waits.extend(
        words
            .iter()
            .enumerate()
            .map(|(index, word)| record(index, word, Some(slot))),
    );
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(
            LINUX_THREAD_WAIT_FUTEX,
            LINUX_FUTEX_VECTOR_KEY | u64::from(tid),
            u64::from(u32::MAX),
            deadline,
        )
    {
        waits.retain(|wait| !ours(wait));
        return LINUX_EINVAL;
    }
    drop(waits);
    let Some(target) = target else {
        X86_RUNTIME
            .LINUX_FUTEX_WAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    };
    switch_from_blocked_linux_futex_waiter(output, current, tls, target)
}

pub(super) fn linux_futex_requeue(
    waiters: u64,
    flags: u64,
    wake_count: u64,
    requeue_count: u64,
) -> u64 {
    if flags != 0 || waiters == 0 || wake_count > i32::MAX as u64 || requeue_count > i32::MAX as u64
    {
        return LINUX_EINVAL;
    }
    let mut entries = [0_u8; 48];
    if !copy_from_linux_user(waiters, &mut entries) {
        return LINUX_EFAULT;
    }
    let parse = |offset: usize| {
        (
            u64::from_ne_bytes(entries[offset..offset + 8].try_into().unwrap()),
            u64::from_ne_bytes(entries[offset + 8..offset + 16].try_into().unwrap()),
            u32::from_ne_bytes(entries[offset + 16..offset + 20].try_into().unwrap()),
            u32::from_ne_bytes(entries[offset + 20..offset + 24].try_into().unwrap()),
        )
    };
    let (expected, source, source_flags, source_reserved) = parse(0);
    let (_, target, target_flags, target_reserved) = parse(24);
    if source_reserved != 0
        || target_reserved != 0
        || source_flags != target_flags
        || !linux_futex2_flags_valid(u64::from(source_flags))
        || !source.is_multiple_of(size_of::<u32>() as u64)
        || !target.is_multiple_of(size_of::<u32>() as u64)
        || expected > u64::from(u32::MAX)
    {
        return LINUX_EINVAL;
    }
    let mut source_bytes = [0_u8; 4];
    let mut target_bytes = [0_u8; 4];
    if !copy_from_linux_user(source, &mut source_bytes)
        || !copy_from_linux_user(target, &mut target_bytes)
    {
        return LINUX_EFAULT;
    }
    if u64::from(u32::from_ne_bytes(source_bytes)) != expected {
        return LINUX_EAGAIN;
    }
    u64::from(requeue_linux_futex_waits(
        source,
        target,
        wake_count as u32,
        requeue_count as u32,
    ))
}

/// Leaves `current`, just blocked in a futex wait, for its ready sibling
/// `target`, whose context the call returns into.
fn switch_from_blocked_linux_futex_waiter(
    output: *mut LinuxSyscallFrame,
    current: LinuxThreadHandle,
    tls: LinuxTlsContext,
    target: LinuxThreadHandle,
) -> u64 {
    let mut target_registers = LinuxSyscallFrame::ZERO;
    let mut target_rip = 0;
    let mut target_rsp = 0;
    let mut target_rflags = 0;
    let mut target_rax = 0;
    if !install_linux_thread_return(
        target,
        &mut target_registers,
        &mut target_rip,
        &mut target_rsp,
        &mut target_rflags,
        &mut target_rax,
    ) {
        let slot = usize::from(current.slot);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(current.slot, Ordering::SeqCst);
        let _ = install_linux_tls_context(tls);
        return LINUX_EINVAL;
    }
    let selected = LinuxUserContext {
        registers: target_registers,
        rip: target_rip,
        rsp: target_rsp,
        rflags: target_rflags,
        rax: target_rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, target, selected) {
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_FUTEX_WAIT_BLOCK_COUNT
        .fetch_add(1, Ordering::SeqCst);
    LINUX_RETURN_FROM_IRET
}
