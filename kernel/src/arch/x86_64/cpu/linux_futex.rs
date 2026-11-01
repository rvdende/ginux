#![forbid(unsafe_code)]
use super::*;

static LINUX_PROFILE_FIRST_FUTEX_OPERATION: AtomicU64 = AtomicU64::new(u64::MAX);
static LINUX_PROFILE_FUTEX_FAST_MISS_CPUS: AtomicU64 = AtomicU64::new(0);
static LINUX_PROFILE_FUTEX_OPERATION_COUNTS: [AtomicU64; 512] = [const { AtomicU64::new(0) }; 512];

/// A process waiting on a futex word while other processes run. A process
/// other than init waits by restarting the call, so the record outlives the
/// restarts: a wake from another process finds and marks it, and a timeout
/// counts from the first attempt.
#[derive(Clone, Copy)]
pub(super) struct LinuxProcessFutexWait {
    pid: u32,
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
}

/// Identifies a futex word across processes by the page it is on, so
/// processes sharing the page (MAP_SHARED, or not yet copied after fork)
/// meet on it.
fn linux_futex_key(address: u64) -> u64 {
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
) -> Option<LinuxProcessFutexWait> {
    let index = waits.iter().position(|wait| wait.pid == pid)?;
    Some(waits.swap_remove(index))
}

/// Marks up to `limit` processes waiting on `key` woken, dropping records of
/// processes that are gone.
fn wake_linux_process_futex_waits(key: u64, mask: u32, limit: u32) -> u32 {
    let mut waits = LINUX_FUTEX_COORDINATION.lock();
    waits.retain(|wait| {
        linux_process::live_process_status(wait.pid).is_some_and(|status| status.state.is_running())
    });
    let mut woken = 0;
    for wait in waits
        .iter_mut()
        .filter(|wait| !wait.woken && wait.key == key && wait.mask & mask != 0)
    {
        if woken == limit {
            break;
        }
        wait.woken = true;
        linux_process::set_live_process_waiting(wait.pid, false);
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

pub(super) fn linux_remote_futex_wait_fast(
    address: u64,
    operation: u64,
    value: u64,
    timeout: u64,
    bitset: u64,
) -> Option<u64> {
    const FUTEX_COMMAND_MASK: u64 = 0x7f;
    const FUTEX_WAIT_BITSET: u64 = 9;
    const FUTEX_PRIVATE_FLAG: u64 = 128;
    const FUTEX_CLOCK_REALTIME: u64 = 256;

    profile_linux_futex_operation(operation);
    // As in linux_futex_live_return, the bitset is a 32-bit value.
    let bitset = bitset & u64::from(u32::MAX);
    if !address.is_multiple_of(size_of::<u32>() as u64) {
        return None;
    }
    if matches!(operation, 1 | 129) {
        let limit = u32::try_from(value).unwrap_or(u32::MAX);
        if limit == 0 {
            return Some(0);
        }
        let coordination = LINUX_FUTEX_COORDINATION.lock();
        // A process waiting on a futex is woken by the full FUTEX_WAKE, under
        // the kernel-entry lock; this path sees only this process's threads.
        if !coordination.is_empty() {
            return None;
        }
        let mut woken = 0_u32;
        for slot in 0..LINUX_THREAD_LIMIT {
            if woken == limit {
                break;
            }
            if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::Acquire) != LINUX_THREAD_BLOCKED
                && X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::Acquire) == address
                && X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot]
                    .compare_exchange(
                        LINUX_THREAD_WAIT_FUTEX,
                        LINUX_THREAD_WAIT_NONE,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
            {
                X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::Release);
                X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::Release);
                woken += 1;
            }
        }
        if woken < limit {
            woken = woken.saturating_add(wake_linux_futex_masked_locked(
                address,
                u32::MAX,
                limit - woken,
            ));
        }
        return Some(u64::from(woken));
    }
    let command = operation & FUTEX_COMMAND_MASK;
    let flags = operation & !FUTEX_COMMAND_MASK;
    if command == FUTEX_WAIT_BITSET {
        if flags & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME) != 0 || bitset == 0 {
            return Some(LINUX_EINVAL);
        }
        let mut bytes = [0_u8; size_of::<u32>()];
        if !address_space::copy_from_current_linux_user_fast(address, &mut bytes) {
            return None;
        }
        if u32::from_ne_bytes(bytes) != value as u32 {
            return Some(LINUX_EAGAIN);
        }
        crate::arch::x86_64::smp::linux_runtime_thread_slot()?;
        if timeout != 0 {
            let mut timeout_bytes = [0_u8; 16];
            if !address_space::copy_from_current_linux_user_fast(timeout, &mut timeout_bytes) {
                return None;
            }
            let Some(requested) = linux_timespec_nanoseconds(&timeout_bytes) else {
                return Some(LINUX_EINVAL);
            };
            let expired = if flags & FUTEX_CLOCK_REALTIME == 0 {
                linux_elapsed_nanoseconds()? >= requested
            } else {
                let (seconds, nanoseconds) = linux_realtime_time()?;
                let Some(realtime_now) = seconds
                    .checked_mul(NANOSECONDS_PER_SECOND)
                    .and_then(|seconds| seconds.checked_add(nanoseconds))
                else {
                    return Some(LINUX_EINVAL);
                };
                realtime_now >= requested
            };
            if expired {
                return Some(LINUX_ETIMEDOUT);
            }
        }
        // A remote application CPU can satisfy the predicate concurrently.
        // Linux permits this wait to return spuriously, and returning directly
        // preserves the coordinator's exact live syscall frame.
        return Some(0);
    }
    if !matches!(operation, 0 | 128) || timeout != 0 {
        return None;
    }
    let mut bytes = [0_u8; size_of::<u32>()];
    if !address_space::copy_from_current_linux_user_fast(address, &mut bytes) {
        // The ordinary path can materialize a valid lazy Linux mapping before
        // deciding whether the address is actually invalid.
        return None;
    }
    if u32::from_ne_bytes(bytes) != value as u32 {
        return Some(LINUX_EAGAIN);
    }
    let remote = crate::arch::x86_64::smp::linux_runtime_thread_slot();
    if remote.is_none() {
        let cpu = current_linux_runtime_cpu_index();
        if cfg!(feature = "linux-boot-profile")
            && cpu < 64
            && LINUX_PROFILE_FUTEX_FAST_MISS_CPUS.fetch_or(1 << cpu, Ordering::Relaxed) & (1 << cpu)
                == 0
        {
            serial_write("ginux: profile futex fast miss cpu/remote: ");
            serial_write_u64(cpu as u64);
            serial_write("/0\r\n");
        }
        return None;
    }
    if current_linux_runtime_cpu_index() == 0
        && (0..LINUX_THREAD_LIMIT).any(|slot| {
            X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::Acquire) == LINUX_THREAD_READY
                && !crate::arch::x86_64::smp::linux_runtime_thread_is_remote(slot)
        })
    {
        if cfg!(feature = "linux-boot-profile")
            && LINUX_PROFILE_FUTEX_FAST_MISS_CPUS.fetch_or(1 << 32, Ordering::Relaxed) & (1 << 32)
                == 0
        {
            serial_write("ginux: profile futex fast miss cpu/remote/local-ready: 0/1/1\r\n");
        }
        // Let the ordinary futex path save the coordinator and run the local
        // worker instead of consuming CPU 0 in a polling wait.
        return None;
    }
    let coordination = LINUX_FUTEX_COORDINATION.lock();
    if !address_space::copy_from_current_linux_user_fast(address, &mut bytes) {
        return Some(LINUX_EFAULT);
    }
    if u32::from_ne_bytes(bytes) != value as u32 {
        return Some(LINUX_EAGAIN);
    }
    let slot = current_linux_thread_slot()?;
    if X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::Acquire) != LINUX_THREAD_WAIT_NONE {
        return None;
    }
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(address, Ordering::Relaxed);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(u64::from(u32::MAX), Ordering::Relaxed);
    if X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot]
        .compare_exchange(
            LINUX_THREAD_WAIT_NONE,
            LINUX_THREAD_WAIT_FUTEX,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::Release);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::Release);
        return None;
    }
    drop(coordination);

    let finish = |result| {
        let _coordination = LINUX_FUTEX_COORDINATION.lock();
        let _ = X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].compare_exchange(
            LINUX_THREAD_WAIT_FUTEX,
            LINUX_THREAD_WAIT_NONE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::Release);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::Release);
        Some(result)
    };

    // Keep the coordinating thread outside the coarse kernel-entry lock while
    // application CPUs run. The userspace futex word is authoritative; a
    // changed value completes the wait. Bound the polling interval so unusual
    // pthread handshakes retain Linux-permitted spurious-wakeup progress.
    for _ in 0..4096 {
        if X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::Acquire)
            != LINUX_THREAD_WAIT_FUTEX
        {
            return finish(0);
        }
        if !address_space::copy_from_current_linux_user_fast(address, &mut bytes) {
            return finish(LINUX_EFAULT);
        }
        if u32::from_ne_bytes(bytes) != value as u32 {
            return finish(0);
        }
        core::hint::spin_loop();
    }
    finish(0)
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
    for wait in waits
        .iter_mut()
        .filter(|wait| !wait.woken && wait.key == source_key)
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
    let earlier = take_linux_process_futex_wait(&mut LINUX_FUTEX_COORDINATION.lock(), pid)
        .filter(|wait| wait.address == address);
    if earlier.is_some_and(|wait| wait.woken) {
        return 0;
    }
    // musl passes the expected value as a sign-extended int; Linux compares
    // only the 32-bit futex word. A wait resumed after a restart compared
    // it when it began, and may since have been requeued to another word.
    if earlier.is_none() && u32::from_ne_bytes(bytes) != value as u32 {
        return LINUX_EAGAIN;
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let target = ready_linux_thread_handle();
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
    if target.is_none() && current_linux_runtime_cpu_index() == 0 {
        if crate::arch::x86_64::smp::linux_runtime_thread_slot().is_some() {
            return 0;
        }
        // Another process may be the one to change the futex word, or to
        // wake it.
        let (key, deadline) = earlier.map_or((linux_futex_key(address), deadline), |wait| {
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
                address,
                key,
                mask: wait_mask as u32,
                deadline,
                woken: false,
            });
        }
        let result = loop {
            match run_other_linux_processes(output, caller, LINUX_FUTEX_SYSCALL) {
                // Yielded: the call starts again and finds its wait.
                Some(LinuxBlockedWait::Return(LINUX_RETURN_TO_KERNEL)) => {
                    return LINUX_RETURN_TO_KERNEL;
                }
                Some(LinuxBlockedWait::Return(result)) => break result,
                // Nothing else could run, or a sibling thread was made ready,
                // which the next wait switches to: a spurious wakeup, which
                // callers allow for by checking their condition again.
                None => break 0,
                // Waited in the call (parked): done when FUTEX_WAKE marked the
                // wait or its deadline passed, else wait again.
                Some(LinuxBlockedWait::Recheck) => {
                    let woken = LINUX_FUTEX_COORDINATION
                        .lock()
                        .iter()
                        .any(|wait| wait.pid == pid && wait.woken);
                    if woken {
                        break 0;
                    }
                    if deadline != 0
                        && linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
                    {
                        break LINUX_ETIMEDOUT;
                    }
                }
            }
        };
        let _ = take_linux_process_futex_wait(&mut LINUX_FUTEX_COORDINATION.lock(), pid);
        return result;
    }
    if command == FUTEX_WAIT_BITSET
        && current_linux_runtime_cpu_index() == 0
        && crate::arch::x86_64::smp::linux_runtime_thread_slot().is_some()
    {
        // A remote application CPU can satisfy this wait concurrently. Linux
        // permits a futex wait to return spuriously, so keep the coordinator's
        // live syscall frame intact and let userspace recheck its predicate.
        // Scheduler-backed switching from this coordinator frame is reserved
        // for waits whose owner can be suspended and restored exactly.
        return 0;
    }
    let coordination = LINUX_FUTEX_COORDINATION.lock();
    if !copy_from_linux_user(address, &mut bytes) {
        return LINUX_EFAULT;
    }
    if u32::from_ne_bytes(bytes) != value as u32 {
        return LINUX_EAGAIN;
    }
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(LINUX_THREAD_WAIT_FUTEX, address, wait_mask, deadline)
    {
        return LINUX_EINVAL;
    }
    drop(coordination);
    let Some(target) = target else {
        X86_RUNTIME
            .LINUX_FUTEX_WAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    };
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
        return match run_other_linux_processes(output, caller, number) {
            Some(LinuxBlockedWait::Return(result)) => result,
            // Callers recheck their condition after any wakeup, spurious ones
            // included.
            Some(LinuxBlockedWait::Recheck) | None => 0,
        };
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
    if flags != 0 || count == 0 || count > 128 {
        return LINUX_EINVAL;
    }
    if count != 1 {
        return LINUX_ENOSYS;
    }
    let mut waiter = [0_u8; 24];
    if !copy_from_linux_user(waiters, &mut waiter) {
        return LINUX_EFAULT;
    }
    let value = u64::from_ne_bytes(waiter[..8].try_into().unwrap());
    let address = u64::from_ne_bytes(waiter[8..16].try_into().unwrap());
    let waiter_flags = u32::from_ne_bytes(waiter[16..20].try_into().unwrap());
    let reserved = u32::from_ne_bytes(waiter[20..24].try_into().unwrap());
    if reserved != 0 {
        return LINUX_EINVAL;
    }
    linux_futex_wait_live_return(
        output,
        caller,
        LINUX_FUTEX_WAITV_SYSCALL,
        address,
        value,
        u64::from(u32::MAX),
        u64::from(waiter_flags),
        timeout,
        clock,
    )
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
