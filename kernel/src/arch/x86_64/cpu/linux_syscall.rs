use super::*;

/// Every this many system calls of a domain, one line names the process,
/// thread and call that made the last one. A process spinning in a loop of
/// system calls shows within seconds; ordinary work prints little. Written
/// from the system call path, never from an interrupt.
const LINUX_SYSCALL_HEARTBEAT: u64 = 1 << 24;

fn write_linux_syscall_heartbeat(count: u64, number: u64, registers: &LinuxSyscallFrame) {
    serial_write("ginux: syscall heartbeat count/pid/tid/number/arguments/previous-result: ");
    let previous = (count as usize + LINUX_RUNTIME_SYSCALL_TRACE_LIMIT - 2)
        % LINUX_RUNTIME_SYSCALL_TRACE_LIMIT;
    for value in [
        count,
        u64::from(current_linux_process_pid()),
        current_linux_tid().map_or(0, u64::from),
        number,
        registers.rdi,
        registers.rsi,
        registers.rdx,
        registers.r10,
        X86_RUNTIME.LINUX_RUNTIME_SYSCALL_RESULT_TRACE[previous].load(Ordering::SeqCst),
    ] {
        serial_write_u64(value);
        serial_write(" ");
    }
    serial_write("(");
    serial_write(linux_descriptor_kind_name(registers.rdi));
    serial_write(")\r\n");
}

/// System call entries per CPU, fast paths included: a count that moves
/// whenever a process gets past a wait and runs, which the runtime loop
/// watches to tell progress from parked calls rechecking their waits.
pub(super) static LINUX_SYSCALL_ENTRIES: [AtomicU64; CPU_ENTRY_STATE_LIMIT] =
    [const { AtomicU64::new(0) }; CPU_ENTRY_STATE_LIMIT];

/// System call entries on this CPU (see `LINUX_SYSCALL_ENTRIES`): a CPU's
/// scheduling loop measures the progress of the processes it runs, not of
/// those other CPUs run.
pub(super) fn linux_syscall_entries_here() -> &'static AtomicU64 {
    let cpu = current_cpu_index_checked()
        .filter(|cpu| *cpu < CPU_ENTRY_STATE_LIMIT)
        .unwrap_or(0);
    &LINUX_SYSCALL_ENTRIES[cpu]
}

pub(super) extern "sysv64" fn linux_syscall_handler(
    number: u64,
    registers: *mut LinuxSyscallFrame,
    user_stack: u64,
    user_rip: u64,
    user_rflags: u64,
) -> u64 {
    // Back in the kernel at the depth this CPU had when it left for user
    // mode, in case the call returns to the kernel.
    set_user_time_stamp_access(true);
    crate::cpu_time::back_from_user();
    crate::sync::kernel_entry_return_from_user();
    linux_syscall_entries_here().fetch_add(1, Ordering::Relaxed);
    crate::linux_socket::poll_closing();
    let traced = linux_strace_call(number, registers);
    let started = timer::timestamp_counter();
    // File events for inotify watches: what a call removes or closes is
    // looked at before it runs.
    let inotify = if registers.is_null() {
        None
    } else {
        // SAFETY: as in linux_syscall_dispatch, the entry stub passes the
        // aligned base of the saved register frame.
        let saved = unsafe { registers.read() };
        let argument = |index: usize| saved.argument(index).unwrap_or(0);
        linux_inotify_before(
            number,
            [
                argument(5),
                argument(4),
                argument(3),
                argument(0),
                argument(2),
                argument(1),
            ],
        )
    };
    let result = linux_syscall_dispatch(
        number,
        registers,
        (user_stack, user_rip, user_rflags),
        inotify,
    );
    // Damage a volume found during the call is reported as it returns.
    let result = linux_volume_failures(result);
    crate::linux_profile::time_syscall(number, timer::timestamp_counter().wrapping_sub(started));
    if let Some(call) = traced.filter(|call| !crate::linux_strace::logged_before(call.number)) {
        call.log(Some(result));
    }
    if result != LINUX_RETURN_TO_KERNEL {
        crate::sync::kernel_entry_leave_to_user();
        crate::cpu_time::leave_for_user();
        set_user_time_stamp_access(linux_user_time_stamp_allowed());
    }
    result
}

/// The trace line of this system call when its process is traced
/// (`crate::linux_strace`): an exec whose environment asks for it starts a
/// trace, and a traced process's children are traced too.
fn linux_strace_call(
    number: u64,
    registers: *mut LinuxSyscallFrame,
) -> Option<crate::linux_strace::Call> {
    if registers.is_null() || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed) {
        return None;
    }
    // SAFETY: as in linux_syscall_dispatch, the entry stub passes the
    // aligned base of the saved register frame.
    let saved = unsafe { registers.read() };
    let argument = |index: usize| saved.argument(index).unwrap_or(0);
    // Arguments in order: rdi, rsi, rdx, r10.
    let arguments = [argument(5), argument(4), argument(3), argument(0)];
    let instance = linux_execution_instance();
    let pid = current_linux_process_pid();
    let environment = match number {
        LINUX_EXECVE_SYSCALL => Some(arguments[2]),
        LINUX_EXECVEAT_SYSCALL => Some(arguments[3]),
        _ => None,
    };
    if environment.is_some_and(linux_environment_requests_strace) {
        crate::linux_strace::trace(instance, pid);
    }
    if !crate::linux_strace::active() {
        return None;
    }
    if !crate::linux_strace::traced(instance, pid) {
        let parent = linux_process::live_process_parent_pid(pid)?;
        if !crate::linux_strace::traced(instance, parent) {
            return None;
        }
        crate::linux_strace::trace(instance, pid);
    }
    let mut call = crate::linux_strace::Call {
        pid,
        tid: current_linux_tid().unwrap_or(0),
        number,
        arguments,
        path: [0; 512],
        path_length: 0,
    };
    if crate::linux_strace::writes_buffer(number) {
        let length = usize::try_from(arguments[2])
            .unwrap_or(usize::MAX)
            .min(call.path.len());
        if copy_from_linux_user(arguments[1], &mut call.path[..length]) {
            call.path_length = length;
        }
    } else if let Some(index) = crate::linux_strace::path_argument(number) {
        let mut path = [0_u8; LINUX_PATH_MAX];
        if let Ok(length) = copy_linux_c_string(arguments[index], &mut path) {
            call.path_length = length.min(call.path.len());
            call.path[..call.path_length].copy_from_slice(&path[..call.path_length]);
        }
    }
    if crate::linux_strace::logged_before(number) {
        call.log(None);
    }
    Some(call)
}

/// Whether the environment vector at `address` holds `GINUX_STRACE=1`.
fn linux_environment_requests_strace(address: u64) -> bool {
    let wanted = crate::linux_strace::ENVIRONMENT;
    (0..4096_u64)
        .map_while(|index| {
            let mut pointer = [0_u8; 8];
            copy_from_linux_user(address.checked_add(index * 8)?, &mut pointer)
                .then(|| u64::from_ne_bytes(pointer))
                .filter(|pointer| *pointer != 0)
        })
        .any(|pointer| {
            let mut entry = [0_u8; 15];
            copy_from_linux_user(pointer, &mut entry[..wanted.len()])
                && entry[..wanted.len()] == *wanted
        })
}

/// Runs system call `number`. `inotify` is what the call's file events
/// need from before it ran; they are reported, and dnotify's signals
/// queued, before the call's own signal delivery, so a dnotify signal
/// reaches the caller as the call returns (fcntl38).
fn linux_syscall_dispatch(
    number: u64,
    registers: *mut LinuxSyscallFrame,
    (user_stack, user_rip, user_rflags): (u64, u64, u64),
    inotify: Option<LinuxInotifyCall>,
) -> u64 {
    if registers.is_null() {
        let _kernel_entry = crate::sync::kernel_entry_lock();
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    }
    crate::linux_profile::count_syscall(number);
    // SAFETY: the assembly entry stub passes the aligned base of the exact
    // twelve-register frame represented by LinuxSyscallFrame.
    let saved_registers = unsafe { registers.read() };
    let fast_runtime_syscall = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::Acquire)
        && !X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::Acquire)
        && !X86_RUNTIME
            .ELF_PROBE_SECCOMP_FILTERED
            .load(Ordering::Acquire)
        && !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::Acquire)
        && X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .load(Ordering::Acquire)
            == 0
        && current_container_slot().is_some_and(|slot| !crate::linux_signal::any_pending(slot))
        && !X86_RUNTIME
            .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
            .load(Ordering::Acquire);
    // A remotely dispatched runtime thread owns its application CPU until it
    // blocks or exits. With no pending asynchronous work, sched_yield() is only
    // a hint and selecting that same thread again has no observable effect.
    if number == LINUX_SCHED_YIELD_SYSCALL
        && fast_runtime_syscall
        && linux_light_thread_here().is_some()
    {
        return 0;
    }
    // Linux normally satisfies supported wall and monotonic clocks through
    // vDSO. Retain a guarded fast syscall fallback for CPU-time clocks and
    // callers that deliberately issue SYSCALL. The result copy still validates
    // the destination leaf permissions.
    if number == LINUX_CLOCK_GETTIME_SYSCALL && fast_runtime_syscall {
        return linux_clock_gettime(saved_registers.rdi, saved_registers.rsi);
    }
    let _kernel_entry = crate::sync::kernel_entry_lock();
    // Dropped before the lock: what the call changed of state shared with
    // other processes reaches them while it still holds it.
    let _shared_state = LinuxSharedStateCall::enter();
    // Before the usual context checks: the timer, not the program, chose
    // this call and saved the context it stands for.
    if number == LINUX_PREEMPT_SYSCALL {
        if let Some(result) = linux_complete_timer_preemption(registers, user_rip) {
            return result;
        }
    }
    // A vfork parent resumed into its wait for the child, which is not one
    // of the program's own calls (no seccomp filter or trace sees it).
    if number == LINUX_VFORK_WAIT_SYSCALL
        && linux_light_thread_here().is_none()
        && linux_process::live_process_vfork_child(current_linux_process_pid()).is_some()
    {
        let caller = LinuxUserContext {
            registers: saved_registers,
            rip: user_rip,
            rsp: user_stack,
            rflags: user_rflags,
            rax: 0,
            fs_base: active_fs_base(),
        };
        return linux_vfork_wait_live(registers, caller);
    }
    // A thread on the light path: it leaves the CPU when its process ends,
    // and calls the light path does not run go to the process's owner.
    if let Some((bank, slot)) = linux_light_thread_here() {
        if LINUX_BANK_DYING[bank].load(Ordering::Acquire)
            || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_RUNNING
        {
            X86_RUNTIME
                .LINUX_CURRENT_THREAD_SLOT
                .store(LINUX_THREAD_SLOT_NONE, Ordering::SeqCst);
            return LINUX_RETURN_TO_KERNEL;
        }
        // seccomp is checked on the owner path.
        if !linux_light_syscall_allowed(number, saved_registers)
            || X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::SeqCst)
            || X86_RUNTIME
                .ELF_PROBE_SECCOMP_FILTERED
                .load(Ordering::SeqCst)
            || X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
            || X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) != 0
            || linux_current_signals_queued()
        {
            let caller = LinuxUserContext {
                registers: saved_registers,
                rip: user_rip,
                rsp: user_stack,
                rflags: user_rflags,
                rax: 0,
                fs_base: active_fs_base(),
            };
            return migrate_current_linux_thread_to_owner(caller, number);
        }
    }
    if let Some(result) =
        linux_controller_syscall(number, saved_registers, user_stack, user_rip, user_rflags)
    {
        return result;
    }
    let syscall_return = LinuxUserContext {
        registers: saved_registers,
        rip: user_rip,
        rsp: user_stack,
        rflags: user_rflags,
        rax: 0,
        fs_base: active_fs_base(),
    };
    let register = |index: usize| saved_registers.argument(index).unwrap_or(0);
    let count = register(3);
    let buffer = register(4);
    let first_argument = register(5);
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Relaxed) {
        linux_epoll_rearm_for_syscall(number, saved_registers.rdi, saved_registers.rsi);
    }
    let code_start = X86_RUNTIME.ELF_PROBE_CODE_BASE.load(Ordering::SeqCst);
    let code_end =
        code_start.saturating_add(X86_RUNTIME.ELF_PROBE_CODE_SIZE.load(Ordering::SeqCst));
    let loader_start = X86_RUNTIME
        .ELF_PROBE_LOADER_CODE_BASE
        .load(Ordering::SeqCst);
    let loader_end = loader_start.saturating_add(
        X86_RUNTIME
            .ELF_PROBE_LOADER_CODE_SIZE
            .load(Ordering::SeqCst),
    );
    if !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::SeqCst)
        || !linux_user_stack_pointer_valid(user_stack)
        || (!(code_start..code_end).contains(&user_rip)
            && !(loader_start..loader_end).contains(&user_rip)
            && !address_space::current_linux_address_executable(user_rip))
        || user_rflags & ((3 << 12) | (1 << 17)) != 0
    {
        if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
            || cfg!(feature = "verification-boot")
        {
            serial_write("ginux: Linux runtime invalid syscall context:");
            for value in [number, user_stack, user_rip, user_rflags] {
                serial_write(" ");
                serial_write_u64(value);
            }
            let slot = current_linux_thread_slot();
            serial_write(" pid/tid/slot/stack-base/stack-size: ");
            for value in [
                u64::from(current_linux_process_pid()),
                current_linux_tid().map_or(0, u64::from),
                slot.map_or(u64::MAX, |slot| slot as u64),
                slot.map_or(0, |slot| {
                    X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst)
                }),
                slot.map_or(0, |slot| {
                    X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst)
                }),
            ] {
                serial_write_u64(value);
                serial_write(" ");
            }
            serial_write("\r\n");
        }
        X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    }
    let runtime_mode = X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst);
    // A blocking call may return into another thread. Signals raised on the
    // way out belong to the thread that made the call, whose context is
    // `syscall_return`; they wait for its next call in that case.
    let calling_thread = current_linux_thread_handle();
    let _profile = LinuxBootSyscallProfile::start(number, runtime_mode);
    let trace_index = if number != LINUX_CLOCK_GETTIME_SYSCALL
        && (runtime_mode
            || cfg!(feature = "verification-boot")
                && X86_RUNTIME.ELF_PROBE_SYSTEM_INIT.load(Ordering::SeqCst))
    {
        let count = X86_RUNTIME
            .LINUX_RUNTIME_SYSCALL_TRACE_COUNT
            .fetch_add(1, Ordering::SeqCst);
        if runtime_mode && (count + 1).is_multiple_of(LINUX_SYSCALL_HEARTBEAT) {
            write_linux_syscall_heartbeat(count + 1, number, &saved_registers);
        }
        let index = count as usize % LINUX_RUNTIME_SYSCALL_TRACE_LIMIT;
        X86_RUNTIME.LINUX_RUNTIME_SYSCALL_TRACE[index].store(number, Ordering::SeqCst);
        Some(index)
    } else {
        None
    };
    if current_linux_tid() == Some(1)
        && X86_RUNTIME.LINUX_CHILD_EXIT_COUNT.load(Ordering::SeqCst) != 0
    {
        X86_RUNTIME
            .LINUX_PARENT_RESUMED
            .store(true, Ordering::SeqCst);
    }
    expire_linux_waits();
    let real_timer_expired = refresh_linux_real_timer();
    let _ = refresh_linux_posix_timers();
    if X86_RUNTIME.ELF_PROBE_SECCOMP_STRICT.load(Ordering::SeqCst)
        && !linux_seccomp_strict_syscall_allowed(number)
    {
        let result = linux_terminate_by_default_signal(LINUX_SIGKILL);
        if let Some(index) = trace_index {
            X86_RUNTIME.LINUX_RUNTIME_SYSCALL_RESULT_TRACE[index].store(result, Ordering::SeqCst);
        }
        return result;
    }
    if X86_RUNTIME
        .ELF_PROBE_SECCOMP_FILTERED
        .load(Ordering::SeqCst)
    {
        let arguments = [
            saved_registers.rdi,
            saved_registers.rsi,
            saved_registers.rdx,
            saved_registers.r10,
            saved_registers.r8,
            saved_registers.r9,
        ];
        if let Some(result) = linux_seccomp_filter_syscall(
            number,
            arguments,
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ) {
            if let Some(index) = trace_index {
                X86_RUNTIME.LINUX_RUNTIME_SYSCALL_RESULT_TRACE[index]
                    .store(result, Ordering::SeqCst);
            }
            return result;
        }
    }
    X86_RUNTIME
        .LINUX_FSIZE_LIMIT_HIT
        .store(false, Ordering::SeqCst);
    // The memory a process held as it exits or replaces its image counts
    // toward its ru_maxrss, read while the address space is still whole.
    if runtime_mode
        && matches!(
            number,
            LINUX_EXIT_SYSCALL
                | LINUX_EXIT_GROUP_SYSCALL
                | LINUX_EXECVE_SYSCALL
                | LINUX_EXECVEAT_SYSCALL
        )
    {
        linux_process::note_live_process_rss(
            current_linux_process_pid(),
            linux_current_resident_kib(),
        );
        // Process accounting records the exit (acct(2)); a process that
        // only replaces its image goes on.
        if matches!(number, LINUX_EXIT_GROUP_SYSCALL)
            || number == LINUX_EXIT_SYSCALL
                && X86_RUNTIME
                    .LINUX_THREAD_STATES
                    .iter()
                    .filter(|state| state.load(Ordering::SeqCst) != LINUX_THREAD_FREE)
                    .count()
                    <= 1
        {
            linux_account_exit((first_argument as u32 & 0xff) << 8);
        }
    }
    // An O_PATH descriptor names a file without opening it: calls that
    // need an open file are EBADF on it, as in Linux (open13).
    if matches!(
        number,
        LINUX_FCHMOD_SYSCALL
            | LINUX_FCHOWN_SYSCALL
            | LINUX_IOCTL_SYSCALL
            | LINUX_FGETXATTR_SYSCALL
            | LINUX_FSETXATTR_SYSCALL
            | LINUX_FLISTXATTR_SYSCALL
            | LINUX_FREMOVEXATTR_SYSCALL
            | LINUX_FSYNC_SYSCALL
            | LINUX_FDATASYNC_SYSCALL
            | LINUX_FLOCK_SYSCALL
    ) && linux_path_descriptor(u64::from(first_argument as u32))
    {
        return LINUX_EBADF;
    }
    // Landlock decided at open whether a device's ioctls are allowed.
    if number == LINUX_IOCTL_SYSCALL {
        if let Err(error) = linux_landlock_check_ioctl(u64::from(first_argument as u32), buffer) {
            return error;
        }
    }
    // A parent ignoring SIGCHLD has no zombies to see or wait for.
    if runtime_mode
        && matches!(
            number,
            LINUX_KILL_SYSCALL | LINUX_WAIT4_SYSCALL | LINUX_WAITID_SYSCALL
        )
    {
        linux_reap_ignored_children();
    }
    // An open or read a fanotify permission mark covers waits for its
    // listeners.
    if runtime_mode && crate::linux_fanotify::permission_active() {
        if let Some(result) = linux_fanotify_permission_check(
            number,
            [first_argument, buffer, count],
            registers,
            syscall_return,
        ) {
            return result;
        }
    }
    let result = match number {
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL | LINUX_IOCTL_SYSCALL
            if linux_graphics_descriptor(first_argument).is_some() =>
        {
            linux_graphics_syscall(number, first_argument, buffer, count)
        }
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL | LINUX_READV_SYSCALL | LINUX_WRITEV_SYSCALL
        | LINUX_IOCTL_SYSCALL
            if runtime_mode && linux_pty_descriptor(first_argument).is_some() =>
        {
            linux_pty_syscall_live_return(
                registers,
                syscall_return,
                number,
                first_argument,
                buffer,
                count,
            )
        }
        // A terminal has no file position.
        LINUX_PREAD64_SYSCALL
        | LINUX_PWRITE64_SYSCALL
        | LINUX_PREADV_SYSCALL
        | LINUX_PWRITEV_SYSCALL
            if runtime_mode && linux_pty_descriptor(first_argument).is_some() =>
        {
            LINUX_ESPIPE
        }
        LINUX_READ_SYSCALL
        | LINUX_WRITE_SYSCALL
        | LINUX_IOCTL_SYSCALL
        | LINUX_LSEEK_SYSCALL
        | LINUX_PREAD64_SYSCALL
        | LINUX_PWRITE64_SYSCALL
        | LINUX_FSYNC_SYSCALL
        | LINUX_FDATASYNC_SYSCALL
            if runtime_mode && linux_block_descriptor(first_argument).is_some() =>
        {
            match linux_block_syscall(number, first_argument, buffer, count, register(0)) {
                // A blocking read of /dev/kmsg with no new record: let the
                // rest of the domain run, then read again.
                LINUX_EAGAIN if linux_kernel_log_read_waits(number, first_argument) => {
                    linux_retry_later_live_return(registers, syscall_return, number)
                }
                result => result,
            }
        }
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL | LINUX_IOCTL_SYSCALL
            if runtime_mode && linux_object_descriptor(first_argument).is_some() =>
        {
            match linux_object_syscall(number, first_argument, buffer, count) {
                // A userfaultfd's EAGAIN is its own answer, but a blocking
                // read of it waits for a fault to read.
                LINUX_EAGAIN if linux_userfaultfd_descriptor(first_argument) => {
                    if number == LINUX_READ_SYSCALL && !linux_socket_nonblocking(first_argument) {
                        linux_retry_later_live_return(registers, syscall_return, number)
                    } else {
                        LINUX_EAGAIN
                    }
                }
                // A blocking read of /dev/net/tun waits for a packet.
                LINUX_EAGAIN if linux_tun_file(first_argument).is_some() => {
                    if number == LINUX_READ_SYSCALL && !linux_socket_nonblocking(first_argument) {
                        linux_retry_later_live_return(registers, syscall_return, number)
                    } else {
                        LINUX_EAGAIN
                    }
                }
                // An ioctl that waits for the GPU: let the rest of the
                // domain run, then issue it again.
                LINUX_EAGAIN if number == LINUX_IOCTL_SYSCALL => {
                    linux_retry_later_live_return(registers, syscall_return, number)
                }
                result => result,
            }
        }
        LINUX_MMAP_SYSCALL if runtime_mode && linux_object_descriptor(register(2)).is_some() => {
            linux_object_mmap(
                first_argument,
                buffer,
                count,
                register(0),
                register(2),
                register(1),
            )
        }
        LINUX_MMAP_SYSCALL
            if runtime_mode
                && linux_graphics_descriptor(register(2))
                    == Some(LinuxGraphicsDevice::Framebuffer) =>
        {
            linux_framebuffer_mmap(first_argument, buffer, count, register(0), register(1))
        }
        LINUX_READ_SYSCALL => linux_descriptor_read_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
        ),
        LINUX_SENDFILE_SYSCALL => linux_sendfile(first_argument, buffer, count, register(0)),
        LINUX_PREAD64_SYSCALL => {
            linux_regular_file_read_at(first_argument, buffer, count, register(0))
        }
        LINUX_PWRITE64_SYSCALL => linux_regular_file_write_at(
            first_argument,
            buffer,
            count,
            linux_pwrite_offset(first_argument, register(0)),
        ),
        LINUX_WRITE_SYSCALL => linux_descriptor_write_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
        ),
        LINUX_SOCKET_SYSCALL => linux_socket_create(first_argument, buffer, count),
        LINUX_SOCKETPAIR_SYSCALL => linux_socket_pair(first_argument, buffer, count, register(0)),
        LINUX_CONNECT_SYSCALL => linux_socket_connect(first_argument, buffer, count),
        LINUX_ACCEPT_SYSCALL => linux_socket_accept_live_return(
            registers,
            syscall_return,
            LINUX_ACCEPT_SYSCALL,
            first_argument,
            buffer,
            count,
            0,
        ),
        LINUX_BIND_SYSCALL => linux_socket_bind(first_argument, buffer, count),
        LINUX_LISTEN_SYSCALL => linux_socket_listen(first_argument, buffer),
        LINUX_ACCEPT4_SYSCALL => linux_socket_accept_live_return(
            registers,
            syscall_return,
            LINUX_ACCEPT4_SYSCALL,
            first_argument,
            buffer,
            count,
            register(0),
        ),
        LINUX_SENDTO_SYSCALL => {
            let flags = register(0);
            let result = linux_socket_sendto(
                first_argument,
                buffer,
                count,
                flags,
                register(2),
                register(1),
            );
            linux_socket_send_live_return(
                registers,
                syscall_return,
                first_argument,
                result,
                flags,
                false,
            )
        }
        // A blocking receive waits by yielding, as read does; MSG_DONTWAIT
        // never waits, MSG_WAITALL keeps collecting until it is full, and
        // MSG_ERRQUEUE reads the (always empty) error queue without waiting.
        LINUX_RECVFROM_SYSCALL
            if register(0) & (0x140 | LINUX_MSG_ERRQUEUE) == 0
                && linux_blocking_socket_yields(first_argument) =>
        {
            linux_local_socket_io_live_return(
                registers,
                syscall_return,
                number,
                first_argument,
                || {
                    linux_socket_recvfrom(
                        None,
                        first_argument,
                        buffer,
                        count,
                        register(0),
                        register(2),
                        register(1),
                    )
                },
            )
        }
        LINUX_RECVFROM_SYSCALL => linux_socket_recvfrom(
            Some((registers, syscall_return, LINUX_RECVFROM_SYSCALL)),
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_SENDMSG_SYSCALL => {
            let result = linux_socket_sendmsg(first_argument, buffer, count);
            linux_socket_send_live_return(
                registers,
                syscall_return,
                first_argument,
                result,
                count,
                false,
            )
        }
        LINUX_RECVMSG_SYSCALL
            if count & (0x140 | LINUX_MSG_ERRQUEUE) == 0
                && linux_blocking_socket_yields(first_argument) =>
        {
            linux_local_socket_io_live_return(
                registers,
                syscall_return,
                number,
                first_argument,
                || linux_socket_recvmsg(None, first_argument, buffer, count),
            )
        }
        LINUX_RECVMSG_SYSCALL => linux_socket_recvmsg(
            Some((registers, syscall_return, LINUX_RECVMSG_SYSCALL)),
            first_argument,
            buffer,
            count,
        ),
        LINUX_RECVMMSG_SYSCALL => {
            linux_socket_recvmmsg(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_SENDMMSG_SYSCALL => {
            let flags = register(0);
            let (result, broken_pipe) = linux_socket_sendmmsg(first_argument, buffer, count, flags);
            linux_socket_send_live_return(
                registers,
                syscall_return,
                first_argument,
                result,
                flags,
                broken_pipe,
            )
        }
        LINUX_SHUTDOWN_SYSCALL => linux_socket_shutdown(first_argument, buffer),
        LINUX_GETSOCKNAME_SYSCALL => linux_socket_name(first_argument, buffer, count, false),
        LINUX_GETPEERNAME_SYSCALL => linux_socket_name(first_argument, buffer, count, true),
        LINUX_SETSOCKOPT_SYSCALL => {
            linux_socket_setsockopt(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_GETSOCKOPT_SYSCALL => {
            linux_socket_getsockopt(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_SCHED_SETAFFINITY_SYSCALL => linux_sched_setaffinity_live_return(
            first_argument,
            buffer,
            count,
            saved_registers,
            user_stack,
            user_rip,
            user_rflags,
        ),
        LINUX_SCHED_YIELD_SYSCALL => linux_sched_yield_live_return(
            registers,
            saved_registers,
            user_stack,
            user_rip,
            user_rflags,
        ),
        LINUX_CLOSE_SYSCALL => {
            linux_descriptor_close_live_return(registers, syscall_return, first_argument)
        }
        LINUX_POLL_SYSCALL => {
            linux_poll_live_return(registers, syscall_return, first_argument, buffer, count)
        }
        LINUX_SELECT_SYSCALL => linux_select_live_return(
            registers,
            syscall_return,
            LinuxSelectInput {
                descriptor_count: first_argument,
                read_address: buffer,
                write_address: count,
                exception_address: register(0),
                timeout_address: register(2),
                signal_mask_address: register(1),
            },
            false,
        ),
        LINUX_PSELECT6_SYSCALL => linux_select_live_return(
            registers,
            syscall_return,
            LinuxSelectInput {
                descriptor_count: first_argument,
                read_address: buffer,
                write_address: count,
                exception_address: register(0),
                timeout_address: register(2),
                signal_mask_address: register(1),
            },
            true,
        ),
        LINUX_FSTAT_SYSCALL => {
            let Some(stat) = linux_descriptor_stat(first_argument) else {
                return LINUX_EBADF;
            };
            if !copy_to_linux_user(buffer, &stat) {
                return LINUX_EFAULT;
            }
            0
        }
        LINUX_LSEEK_SYSCALL => {
            if linux_eventfd_descriptor(first_argument)
                || linux_timerfd_descriptor(first_argument)
                || linux_pipe_descriptor(first_argument)
            {
                return LINUX_ESPIPE;
            }
            let device = linux_device_descriptor(first_argument);
            if device & LINUX_DEVICE_CONSOLE != 0 {
                LINUX_ESPIPE
            } else if linux_rootfs_entry(first_argument).is_some()
                || linux_regular_file(device).is_some()
                || linux_tmp_file(device)
                || device & !3 == LINUX_FILE_PROC_DYNAMIC_PAGEMAP
                || device & !3 == LINUX_FILE_PROC_DYNAMIC_MEM
            {
                linux_regular_file_seek(first_argument, device, buffer, count)
            } else if device & LINUX_DEVICE_DIRECTORY != 0 {
                if buffer == 0 && count == 0 {
                    linux_descriptor_offset(first_argument).store(0, Ordering::SeqCst);
                    0
                } else {
                    LINUX_EINVAL
                }
            } else if device != 0 {
                0
            } else if linux_console_descriptor_open(first_argument) {
                LINUX_ESPIPE
            } else {
                LINUX_EBADF
            }
        }
        LINUX_MMAP_SYSCALL => {
            let mut arguments = [
                first_argument,
                buffer,
                count,
                register(0),
                register(2),
                register(1),
            ];
            // A huge page mapping becomes the small-page mapping that backs
            // it (`linux_huge_mmap_arguments`).
            let huge = if runtime_mode {
                match linux_huge_mmap_arguments(&mut arguments) {
                    Ok(huge) => huge,
                    Err(error) => return error,
                }
            } else {
                None
            };
            // A process past vm.max_map_count areas maps no more, as
            // Linux refuses (munmap04 maps until this fails).
            if runtime_mode
                && crate::linux_areas::count(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                ) > linux_max_map_count()
            {
                return LINUX_ENOMEM;
            }
            let mapped = linux_mmap(
                arguments[0],
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4],
                arguments[5],
            );
            linux_record_mapping(
                mapped,
                arguments[1],
                arguments[2],
                arguments[3],
                arguments[4],
                arguments[5],
            );
            if let Some(huge) = huge.filter(|_| mapped < LINUX_RETURN_TO_KERNEL) {
                linux_huge_mapped(mapped, huge);
            }
            mapped
        }
        LINUX_MUNMAP_SYSCALL => {
            if runtime_mode {
                crate::linux_userfaultfd::forget(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    first_argument,
                    first_argument.saturating_add(buffer),
                );
            }
            // A huge mapping is only cut on a huge page boundary
            // (memfd_create03).
            if runtime_mode && linux_huge_split(first_argument, buffer) {
                return LINUX_EINVAL;
            }
            // Unmapping the middle of an area makes two of it: at the
            // vm.max_map_count limit that is ENOMEM (munmap04).
            if runtime_mode
                && first_argument.is_multiple_of(PAGE_SIZE as u64)
                && buffer != 0
                && crate::linux_areas::count(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                ) >= linux_max_map_count()
                && crate::linux_areas::unmap_splits(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    first_argument,
                    buffer,
                )
            {
                return LINUX_ENOMEM;
            }
            let result = linux_munmap(first_argument, buffer);
            if result == 0 && runtime_mode {
                crate::linux_areas::unmap(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    first_argument,
                    buffer,
                );
            }
            result
        }
        LINUX_SHMGET_SYSCALL => linux_shmget(first_argument, buffer, count),
        LINUX_SHMAT_SYSCALL => linux_shmat(first_argument, buffer, count),
        LINUX_SHMCTL_SYSCALL => linux_shmctl(first_argument, buffer, count),
        LINUX_SEMGET_SYSCALL => linux_semget(first_argument, buffer, count),
        LINUX_SEMOP_SYSCALL => linux_semop_live(
            registers,
            syscall_return,
            number,
            (first_argument, buffer, count, 0),
        ),
        LINUX_SEMCTL_SYSCALL => linux_semctl(first_argument, buffer, count, register(0)),
        LINUX_SHMDT_SYSCALL => linux_shmdt(first_argument),
        LINUX_MSGGET_SYSCALL => linux_msgget(first_argument, buffer),
        LINUX_MSGSND_SYSCALL => linux_message_wait_live(
            registers,
            syscall_return,
            number,
            (first_argument, register(0)),
            || linux_msgsnd(first_argument, buffer, count, register(0)),
        ),
        LINUX_MSGRCV_SYSCALL => linux_message_wait_live(
            registers,
            syscall_return,
            number,
            (first_argument, register(2)),
            || linux_msgrcv(first_argument, buffer, count, register(0), register(2)),
        ),
        LINUX_MSGCTL_SYSCALL => linux_msgctl(first_argument, buffer, count),
        LINUX_MQ_OPEN_SYSCALL => linux_mq_open(first_argument, buffer, count, register(0)),
        LINUX_MQ_UNLINK_SYSCALL => linux_mq_unlink(first_argument),
        LINUX_MQ_TIMEDSEND_SYSCALL => linux_mq_wait_live(
            registers,
            syscall_return,
            number,
            (first_argument, register(2)),
            || linux_mq_timedsend(first_argument, buffer, count, register(0), register(2)),
        ),
        LINUX_MQ_TIMEDRECEIVE_SYSCALL => linux_mq_wait_live(
            registers,
            syscall_return,
            number,
            (first_argument, register(2)),
            || linux_mq_timedreceive(first_argument, buffer, count, register(0), register(2)),
        ),
        LINUX_MQ_NOTIFY_SYSCALL => linux_mq_notify(first_argument, buffer),
        LINUX_MQ_GETSETATTR_SYSCALL => linux_mq_getsetattr(first_argument, buffer, count),
        LINUX_IO_SETUP_SYSCALL => linux_io_setup(first_argument, buffer),
        LINUX_IO_DESTROY_SYSCALL => linux_io_destroy(first_argument),
        LINUX_IO_SUBMIT_SYSCALL => linux_io_submit(first_argument, buffer, count),
        LINUX_IO_GETEVENTS_SYSCALL => {
            linux_io_getevents(first_argument, buffer, count, register(0), register(2), 0)
        }
        LINUX_IO_PGETEVENTS_SYSCALL => linux_io_getevents(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_IO_CANCEL_SYSCALL => linux_io_cancel(first_argument, buffer, count),
        LINUX_LSM_GET_SELF_ATTR_SYSCALL => {
            linux_lsm_get_self_attr(first_argument, buffer, count, register(0))
        }
        LINUX_LSM_SET_SELF_ATTR_SYSCALL => {
            linux_lsm_set_self_attr(first_argument, buffer, count, register(0))
        }
        LINUX_LSM_LIST_MODULES_SYSCALL => linux_lsm_list_modules(first_argument, buffer, count),
        LINUX_STATMOUNT_SYSCALL => linux_statmount(first_argument, buffer, count, register(0)),
        LINUX_LISTMOUNT_SYSCALL => linux_listmount(first_argument, buffer, count, register(0)),
        LINUX_SEMTIMEDOP_SYSCALL => linux_semop_live(
            registers,
            syscall_return,
            number,
            (first_argument, buffer, count, register(0)),
        ),
        LINUX_MREMAP_SYSCALL => {
            const MREMAP_DONTUNMAP: u64 = 4;
            // MREMAP_DONTUNMAP leaves the old mapping where it was.
            let kept = (runtime_mode && register(0) & MREMAP_DONTUNMAP != 0)
                .then(|| {
                    crate::linux_areas::area_at(
                        linux_execution_instance(),
                        current_linux_process_pid(),
                        first_argument,
                    )
                })
                .flatten();
            let moved = linux_mremap(first_argument, buffer, count, register(0), register(2));
            if runtime_mode && moved < 1 << 47 {
                crate::linux_areas::remap(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    (first_argument, buffer),
                    (moved, count),
                );
                if let Some(area) = kept {
                    let start = first_argument;
                    let end = start + buffer.next_multiple_of(PAGE_SIZE as u64);
                    let offset = start - area.start;
                    let backing = match area.backing {
                        crate::linux_areas::Backing::File {
                            device,
                            inode,
                            offset: file_offset,
                            path,
                        } => crate::linux_areas::Backing::File {
                            device,
                            inode,
                            offset: file_offset + offset,
                            path,
                        },
                        backing => backing,
                    };
                    crate::linux_areas::map(
                        linux_execution_instance(),
                        current_linux_process_pid(),
                        crate::linux_areas::Area {
                            start,
                            end,
                            backing,
                            ..area
                        },
                    );
                }
            }
            moved
        }
        LINUX_REMAP_FILE_PAGES_SYSCALL => {
            linux_remap_file_pages(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_MSYNC_SYSCALL => linux_msync(first_argument, buffer, count),
        // A huge mapping is only changed in whole huge pages.
        LINUX_MPROTECT_SYSCALL | LINUX_PKEY_MPROTECT_SYSCALL
            if runtime_mode && linux_huge_split(first_argument, buffer) =>
        {
            LINUX_EINVAL
        }
        // A shared mapping that may not be written cannot be made writable
        // (EACCES: Linux's VM_MAYWRITE).
        LINUX_MPROTECT_SYSCALL | LINUX_PKEY_MPROTECT_SYSCALL
            if runtime_mode
                && count & LINUX_PROT_WRITE != 0
                && crate::linux_areas::write_forbidden(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    first_argument,
                    buffer,
                ) =>
        {
            LINUX_EACCES
        }
        LINUX_MPROTECT_SYSCALL | LINUX_PKEY_MPROTECT_SYSCALL => {
            let result = if number == LINUX_MPROTECT_SYSCALL {
                linux_mprotect(first_argument, buffer, count)
            } else {
                linux_pkey_mprotect(first_argument, buffer, count, register(0))
            };
            if result == 0 && runtime_mode {
                crate::linux_areas::protect(
                    linux_execution_instance(),
                    current_linux_process_pid(),
                    first_argument,
                    buffer,
                    crate::linux_areas::Protection::from_bits(count),
                );
            }
            result
        }
        LINUX_MSEAL_SYSCALL => linux_mseal(first_argument, buffer, count),
        LINUX_PKEY_ALLOC_SYSCALL => linux_pkey_alloc(first_argument, buffer),
        LINUX_PKEY_FREE_SYSCALL => linux_pkey_free(first_argument),
        LINUX_IOCTL_SYSCALL => {
            if let Some(result) = linux_generic_ioctl(first_argument, buffer, count) {
                return result;
            }
            if let Some(result) = linux_file_attributes_ioctl(first_argument, buffer, count) {
                return result;
            }
            if let Some(result) = linux_fiemap_ioctl(first_argument, buffer, count) {
                return result;
            }
            if linux_pidfd_descriptor(first_argument) {
                return linux_pidfd_ioctl(first_argument, buffer, count);
            }
            if linux_namespace_descriptor(first_argument) {
                return linux_namespace_ioctl(first_argument, buffer, count);
            }
            if linux_pipe_descriptor(first_argument) {
                if buffer != LINUX_FIONREAD {
                    return LINUX_ENOTTY;
                }
                let available = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
                    let Some(slot) = linux_socket_slot(first_argument) else {
                        return LINUX_EBADF;
                    };
                    match crate::linux_socket::pipe_queued_bytes(slot) {
                        Ok(available) => available.min(i32::MAX as usize) as u32,
                        Err(error) => return linux_socket_error(error),
                    }
                } else {
                    X86_RUNTIME.ELF_PROBE_PIPE_LENGTH.load(Ordering::SeqCst)
                };
                if !copy_to_linux_user(count, &available.to_ne_bytes()) {
                    return LINUX_EFAULT;
                }
                return 0;
            }
            let device = linux_device_descriptor(first_argument);
            if device != 0 && device & LINUX_DEVICE_CONSOLE == 0 {
                return LINUX_ENOTTY;
            }
            if device == 0 && !linux_console_descriptor_open(first_argument) {
                return if linux_descriptor_open(first_argument) {
                    LINUX_ENOTTY
                } else {
                    LINUX_EBADF
                };
            }
            linux_tty_ioctl(buffer, count)
        }
        LINUX_READV_SYSCALL => linux_descriptor_readv_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
        ),
        LINUX_WRITEV_SYSCALL => linux_descriptor_writev_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
        ),
        LINUX_PREADV_SYSCALL => {
            linux_positioned_iov(first_argument, buffer, count, register(0), 0, false)
        }
        LINUX_PWRITEV_SYSCALL => {
            linux_positioned_iov(first_argument, buffer, count, register(0), 0, true)
        }
        // An offset of -1 reads or writes at the file position.
        LINUX_PREADV2_SYSCALL if register(0) == u64::MAX => linux_descriptor_readv_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
        ),
        LINUX_PREADV2_SYSCALL => linux_positioned_iov(
            first_argument,
            buffer,
            count,
            register(0),
            register(1),
            false,
        ),
        LINUX_PWRITEV2_SYSCALL if register(0) == u64::MAX => linux_descriptor_writev_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
        ),
        LINUX_PWRITEV2_SYSCALL => linux_positioned_iov(
            first_argument,
            buffer,
            count,
            register(0),
            register(1),
            true,
        ),
        LINUX_PIPE_SYSCALL => linux_pipe(first_argument, 0),
        LINUX_MINCORE_SYSCALL => linux_mincore(first_argument, buffer, count),
        LINUX_MADVISE_SYSCALL => linux_madvise(first_argument, buffer, count),
        LINUX_PROCESS_MADVISE_SYSCALL => {
            linux_process_madvise(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_PROCESS_MRELEASE_SYSCALL => linux_process_mrelease(first_argument, buffer),
        LINUX_DUP_SYSCALL => linux_console_dup(first_argument),
        LINUX_DUP2_SYSCALL => linux_console_dup2(first_argument, buffer),
        LINUX_DUP3_SYSCALL => linux_dup3(first_argument, buffer, count),
        LINUX_NANOSLEEP_SYSCALL => {
            linux_nanosleep_live_return(registers, syscall_return, first_argument, buffer)
        }
        LINUX_CLOCK_NANOSLEEP_SYSCALL => linux_clock_nanosleep_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
            register(0),
        ),
        LINUX_GETITIMER_SYSCALL => linux_getitimer(first_argument, buffer),
        LINUX_ALARM_SYSCALL => linux_alarm(first_argument),
        LINUX_SETITIMER_SYSCALL => linux_setitimer(first_argument, buffer, count),
        LINUX_TIMER_CREATE_SYSCALL => linux_timer_create(first_argument, buffer, count),
        LINUX_TIMER_SETTIME_SYSCALL => {
            linux_timer_settime(first_argument, buffer, count, register(0))
        }
        LINUX_TIMER_GETTIME_SYSCALL => linux_timer_gettime(first_argument, buffer),
        LINUX_TIMER_GETOVERRUN_SYSCALL => linux_timer_getoverrun(first_argument),
        LINUX_TIMER_DELETE_SYSCALL => linux_timer_delete(first_argument),
        LINUX_RESTART_SYSCALL => LINUX_EINTR,
        LINUX_EPOLL_WAIT_SYSCALL => linux_epoll_wait_live_return(
            registers,
            syscall_return,
            LinuxEpollWaitInput {
                epoll: first_argument,
                address: buffer,
                maximum: count,
            },
            register(0),
        ),
        LINUX_EPOLL_CTL_SYSCALL => linux_epoll_ctl(first_argument, buffer, count, register(0)),
        LINUX_FCNTL_SYSCALL
            if matches!(
                u64::from(buffer as u32),
                LINUX_F_SETLKW | LINUX_F_OFD_SETLKW
            ) =>
        {
            linux_fcntl_setlkw_live_return(
                registers,
                syscall_return,
                (first_argument, buffer, count),
            )
        }
        LINUX_FCNTL_SYSCALL => linux_descriptor_fcntl(first_argument, buffer, count),
        LINUX_FLOCK_SYSCALL => {
            linux_flock_live_return(registers, syscall_return, first_argument, buffer)
        }
        LINUX_FSYNC_SYSCALL | LINUX_FDATASYNC_SYSCALL => linux_fsync(first_argument),
        LINUX_FADVISE64_SYSCALL => linux_fadvise64(first_argument, buffer, count, register(0)),
        LINUX_TRUNCATE_SYSCALL => linux_lease_live_return(
            registers,
            syscall_return,
            (number, u64::from(LINUX_AT_FDCWD), first_argument, 1),
            || linux_truncate(first_argument, buffer),
        ),
        LINUX_FTRUNCATE_SYSCALL => linux_ftruncate(first_argument, buffer),
        LINUX_FALLOCATE_SYSCALL => linux_fallocate(first_argument, buffer, count, register(0)),
        LINUX_COPY_FILE_RANGE_SYSCALL => linux_copy_file_range(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_BRK_SYSCALL => {
            if runtime_mode {
                let previous = X86_RUNTIME.ELF_PROBE_BRK.load(Ordering::SeqCst);
                let program_break = linux_runtime_brk(first_argument);
                if program_break != previous {
                    linux_record_heap(program_break);
                }
                program_break
            } else {
                let current = X86_RUNTIME.ELF_PROBE_BRK.load(Ordering::SeqCst);
                let limit = X86_RUNTIME.ELF_PROBE_BRK_LIMIT.load(Ordering::SeqCst);
                let base = limit.saturating_sub(PAGE_SIZE as u64);
                if first_argument == 0 {
                    current
                } else if (base..=limit).contains(&first_argument) {
                    X86_RUNTIME
                        .ELF_PROBE_BRK
                        .store(first_argument, Ordering::SeqCst);
                    first_argument
                } else {
                    current
                }
            }
        }
        LINUX_RT_SIGACTION_SYSCALL => {
            linux_rt_sigaction(first_argument, buffer, count, register(0))
        }
        LINUX_RT_SIGPROCMASK_SYSCALL => {
            let result = linux_rt_sigprocmask(first_argument, buffer, count, register(0));
            if result == 0 {
                linux_deliver_pending_signal(registers, syscall_return, (user_rip, user_rflags))
            } else {
                result
            }
        }
        LINUX_RT_SIGRETURN_SYSCALL => linux_rt_sigreturn(registers, user_stack),
        LINUX_RT_SIGPENDING_SYSCALL => linux_rt_sigpending(first_argument, buffer),
        LINUX_RT_SIGQUEUEINFO_SYSCALL => linux_rt_sigqueueinfo(
            first_argument,
            None,
            buffer,
            count,
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ),
        LINUX_RT_TGSIGQUEUEINFO_SYSCALL => linux_rt_sigqueueinfo(
            first_argument,
            Some(buffer),
            count,
            register(0),
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ),
        LINUX_RT_SIGTIMEDWAIT_SYSCALL => linux_rt_sigtimedwait_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
            register(0),
        ),
        LINUX_PAUSE_SYSCALL => linux_signal_suspend_live_return(
            registers,
            syscall_return,
            LINUX_THREAD_WAIT_PAUSE,
            None,
        ),
        LINUX_RT_SIGSUSPEND_SYSCALL => {
            let mask = match linux_temporary_signal_mask(LinuxSignalMaskInput {
                address: first_argument,
                size: buffer,
            }) {
                Ok(mask) => mask,
                Err(error) => return error,
            };
            linux_signal_suspend_live_return(
                registers,
                syscall_return,
                LINUX_THREAD_WAIT_SIGSUSPEND,
                Some(mask),
            )
        }
        // A new namespace other than a user one needs CAP_SYS_ADMIN, checked
        // before anything else of the request (clone11).
        LINUX_CLONE_SYSCALL
            if saved_registers.rdi
                & (0x80
                    | LINUX_CLONE_NEWNS
                    | 0x0200_0000
                    | 0x0400_0000
                    | 0x0800_0000
                    | 0x2000_0000
                    | 0x4000_0000)
                != 0
                && !current_linux_credentials().is_some_and(|credentials| {
                    credentials.has(ginux_credentials::capability::SYS_ADMIN)
                }) =>
        {
            LINUX_EPERM
        }
        LINUX_CLONE_SYSCALL
            if (saved_registers.rdi & !LINUX_CLONE_PROCESS_NAMESPACES == LINUX_SIGCHLD
                || saved_registers.rdi & !LINUX_CLONE_PROCESS_NAMESPACES
                    == LINUX_SIGCHLD | LINUX_CLONE_CHILD_SETTID | LINUX_CLONE_CHILD_CLEARTID)
                && saved_registers.rsi == 0 =>
        {
            let child_tid = if saved_registers.rdi & LINUX_CLONE_CHILD_SETTID != 0 {
                saved_registers.r10
            } else {
                0
            };
            if child_tid != 0 && !linux_writable_user_range_contains(child_tid, size_of::<u32>()) {
                if runtime_mode {
                    serial_write("ginux: Linux process clone child-tid EFAULT flags/address: ");
                    serial_write_u64(saved_registers.rdi);
                    serial_write(" ");
                    serial_write_u64(child_tid);
                    let page_address = child_tid & !(PAGE_SIZE as u64 - 1);
                    let page = address_space::current_linux_runtime_page(page_address);
                    serial_write(" page/occupied/protection/frame/file/secret/cow ");
                    serial_write_u64(page_address);
                    serial_write(" ");
                    serial_write_u64(u64::from(page.occupied));
                    serial_write(" ");
                    serial_write_u64(u64::from(page.protection));
                    serial_write(" ");
                    serial_write_u64(u64::from(page.frame.is_some()));
                    serial_write(" ");
                    serial_write_u64(u64::from(page.file));
                    serial_write(" ");
                    serial_write_u64(u64::from(page.secret));
                    serial_write(" ");
                    serial_write_u64(u64::from(
                        address_space::current_linux_cow_page(page_address).is_some(),
                    ));
                    serial_write("\r\n");
                }
                LINUX_EFAULT
            } else {
                let result = linux_request_process_fork(
                    runtime_mode,
                    syscall_return,
                    saved_registers.rdi & LINUX_CLONE_PROCESS_NAMESPACES,
                    0,
                    saved_registers.rdi & LINUX_CLONE_VM != 0,
                    0,
                    0,
                    false,
                    false,
                );
                if result == LINUX_RETURN_TO_KERNEL {
                    X86_RUNTIME
                        .LINUX_FORK_CHILD_TID_ADDRESS
                        .store(child_tid, Ordering::SeqCst);
                }
                result
            }
        }
        LINUX_CLONE_SYSCALL if runtime_mode && saved_registers.rdi & LINUX_CLONE_THREAD == 0 => {
            // A process: clone(flags | signal, stack, parent_tid, child_tid,
            // tls). musl's posix_spawn makes one with
            // clone(CLONE_VM | CLONE_VFORK | SIGCHLD, stack), LTP's ltp_clone
            // plain forks on a stack and the sharing forms.
            let flags = saved_registers.rdi;
            if flags & LINUX_CLONE_PIDFD != 0 && flags & LINUX_CLONE_PARENT_SETTID != 0 {
                // clone's pidfd goes where the parent's tid would.
                LINUX_EINVAL
            } else {
                linux_clone_process(
                    LinuxProcessClone {
                        flags: flags & !0xff,
                        exit_signal: flags & 0xff,
                        stack: saved_registers.rsi,
                        parent_tid: saved_registers.rdx,
                        child_tid: saved_registers.r10,
                        tls: saved_registers.r8,
                        pidfd: if flags & LINUX_CLONE_PIDFD != 0 {
                            saved_registers.rdx
                        } else {
                            0
                        },
                        cgroup_generation: 0,
                    },
                    syscall_return,
                    true,
                )
            }
        }
        LINUX_CLONE_SYSCALL => {
            let result = linux_clone_thread(saved_registers, user_rip, user_rflags);
            if runtime_mode {
                serial_write("ginux: Linux clone flags/stack/parent-tid/child-tid/tls/result: ");
                for value in [
                    saved_registers.rdi,
                    saved_registers.rsi,
                    saved_registers.rdx,
                    saved_registers.r10,
                    saved_registers.r8,
                    result,
                ] {
                    serial_write_u64(value);
                    serial_write(" ");
                }
                serial_write("\r\n");
            }
            linux_schedule_new_thread(
                registers,
                saved_registers,
                user_stack,
                user_rip,
                user_rflags,
                result,
            )
        }
        LINUX_CLONE3_SYSCALL => {
            let result = linux_clone3(
                first_argument,
                buffer,
                syscall_return,
                saved_registers,
                user_rip,
                user_rflags,
            );
            linux_schedule_new_thread(
                registers,
                saved_registers,
                user_stack,
                user_rip,
                user_rflags,
                result,
            )
        }
        LINUX_FORK_SYSCALL => linux_request_process_fork(
            runtime_mode,
            syscall_return,
            0,
            0,
            false,
            0,
            0,
            false,
            false,
        ),
        LINUX_VFORK_SYSCALL => {
            let result = linux_request_process_fork(
                runtime_mode,
                syscall_return,
                0,
                0,
                true,
                0,
                0,
                false,
                false,
            );
            // The parent is suspended until the child executes or exits.
            if result == LINUX_RETURN_TO_KERNEL {
                X86_RUNTIME.LINUX_FORK_CLONE_FLAGS.store(
                    LINUX_FORK_CLONE_REQUESTED | LINUX_CLONE_VM | LINUX_CLONE_VFORK | LINUX_SIGCHLD,
                    Ordering::SeqCst,
                );
            }
            result
        }
        LINUX_EXECVE_SYSCALL => {
            if runtime_mode && !refresh_live_linux_process_registry(syscall_return) {
                LINUX_EIO
            } else {
                linux_execve(first_argument, buffer, count)
            }
        }
        LINUX_KILL_SYSCALL => {
            let Ok(target) = linux_pid_argument(first_argument) else {
                return LINUX_ESRCH;
            };
            linux_kill(
                target,
                (buffer, LINUX_SI_USER, None),
                registers,
                syscall_return,
                (user_rip, user_rflags),
            )
        }
        LINUX_TGKILL_SYSCALL => linux_tgkill(
            linux_tid_argument(first_argument),
            linux_tid_argument(buffer),
            count,
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ),
        LINUX_TKILL_SYSCALL => linux_tkill(
            linux_tid_argument(first_argument),
            buffer,
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ),
        LINUX_TIME_SYSCALL => linux_time(first_argument),
        LINUX_EXECVEAT_SYSCALL => {
            if runtime_mode && !refresh_live_linux_process_registry(syscall_return) {
                LINUX_EIO
            } else {
                linux_execveat(first_argument, buffer, count, register(0), register(2))
            }
        }
        LINUX_GETPID_SYSCALL => {
            let pid = current_linux_process_pid();
            u64::from(linux_pid_seen_by(pid, pid))
        }
        LINUX_GETTID_SYSCALL => {
            let Some(tid) = current_linux_tid() else {
                return LINUX_ESRCH;
            };
            if tid != 1 {
                X86_RUNTIME
                    .LINUX_CHILD_GETTID_COUNT
                    .fetch_add(1, Ordering::SeqCst);
            }
            u64::from(linux_tid_seen(tid))
        }
        // A parent outside the caller's PID namespace shows as 0.
        LINUX_GETPPID_SYSCALL => {
            let pid = current_linux_process_pid();
            linux_process::live_process_parent_pid(pid).map_or(LINUX_ESRCH, |parent| {
                u64::from(linux_pid_seen_by(pid, parent))
            })
        }
        LINUX_SETPGID_SYSCALL => linux_setpgid(first_argument, buffer),
        LINUX_SETSID_SYSCALL => {
            let pid = current_linux_process_pid();
            match linux_process::create_live_process_session(pid) {
                Ok(session) => u64::from(session),
                Err(linux_process::ProcessGroupError::Access) => LINUX_EACCES,
                Err(linux_process::ProcessGroupError::NoSuchProcess) => LINUX_ESRCH,
                Err(linux_process::ProcessGroupError::Permission) => LINUX_EPERM,
            }
        }
        LINUX_GETPGRP_SYSCALL => linux_process::live_process_group(current_linux_process_pid())
            .map_or(LINUX_ESRCH, u64::from),
        LINUX_GETPGID_SYSCALL | LINUX_GETSID_SYSCALL => {
            let requested = first_argument as i32;
            let pid = if requested == 0 {
                current_linux_process_pid()
            } else if requested > 0 {
                requested as u32
            } else {
                return LINUX_ESRCH;
            };
            let value = if number == LINUX_GETPGID_SYSCALL {
                linux_process::live_process_group(pid)
            } else {
                linux_process::live_process_session(pid)
            };
            value.map_or(LINUX_ESRCH, u64::from)
        }
        LINUX_SIGALTSTACK_SYSCALL => linux_sigaltstack(first_argument, buffer),
        LINUX_SET_TID_ADDRESS_SYSCALL => {
            if !set_current_linux_clear_child_tid(first_argument) {
                return LINUX_ESRCH;
            }
            current_linux_tid().map_or(LINUX_ESRCH, |tid| u64::from(linux_tid_seen(tid)))
        }
        LINUX_SET_ROBUST_LIST_SYSCALL => {
            if buffer != LINUX_ROBUST_LIST_HEAD_SIZE as u64 {
                return LINUX_EINVAL;
            }
            if !set_current_linux_robust_list(first_argument) {
                return LINUX_ESRCH;
            }
            0
        }
        LINUX_GET_ROBUST_LIST_SYSCALL => linux_get_robust_list(first_argument, buffer, count),
        LINUX_GETUID_SYSCALL => {
            current_linux_credentials().map_or(LINUX_ESRCH, |value| u64::from(value.user.real))
        }
        LINUX_GETGID_SYSCALL => {
            current_linux_credentials().map_or(LINUX_ESRCH, |value| u64::from(value.group.real))
        }
        LINUX_GETEUID_SYSCALL => {
            current_linux_credentials().map_or(LINUX_ESRCH, |value| u64::from(value.user.effective))
        }
        LINUX_GETEGID_SYSCALL => current_linux_credentials()
            .map_or(LINUX_ESRCH, |value| u64::from(value.group.effective)),
        LINUX_GETGROUPS_SYSCALL => linux_get_current_groups(first_argument, buffer),
        LINUX_SETGROUPS_SYSCALL => linux_set_current_groups(first_argument, buffer),
        LINUX_SETUID_SYSCALL
        | LINUX_SETGID_SYSCALL
        | LINUX_SETREUID_SYSCALL
        | LINUX_SETREGID_SYSCALL
        | LINUX_SETRESUID_SYSCALL
        | LINUX_SETRESGID_SYSCALL
        | LINUX_SETFSUID_SYSCALL
        | LINUX_SETFSGID_SYSCALL => {
            linux_set_current_identity(number, first_argument, buffer, count)
        }
        LINUX_GETRESUID_SYSCALL | LINUX_GETRESGID_SYSCALL => {
            let Some(credentials) = current_linux_credentials() else {
                return LINUX_ESRCH;
            };
            let ids = if number == LINUX_GETRESUID_SYSCALL {
                credentials.user
            } else {
                credentials.group
            };
            let ids = (ids.real, ids.effective, ids.saved);
            copy_linux_id_triple(first_argument, buffer, count, ids)
        }
        LINUX_PERSONALITY_SYSCALL => linux_personality(first_argument),
        LINUX_CAPGET_SYSCALL => linux_capget(first_argument, buffer),
        LINUX_CAPSET_SYSCALL => linux_capset(first_argument, buffer),
        LINUX_GETPRIORITY_SYSCALL => linux_getpriority(first_argument, buffer),
        LINUX_SETPRIORITY_SYSCALL => linux_setpriority(first_argument, buffer, count),
        LINUX_SCHED_SETPARAM_SYSCALL => linux_sched_setparam(first_argument, buffer),
        LINUX_SCHED_SETSCHEDULER_SYSCALL => linux_set_scheduler(first_argument, buffer, count),
        LINUX_SCHED_GETPARAM_SYSCALL => linux_sched_getparam(first_argument, buffer),
        LINUX_SCHED_GETSCHEDULER_SYSCALL => linux_sched_getscheduler(first_argument),
        LINUX_SCHED_GET_PRIORITY_MAX_SYSCALL | LINUX_SCHED_GET_PRIORITY_MIN_SYSCALL => {
            linux_scheduler_priority_range(
                first_argument,
                number == LINUX_SCHED_GET_PRIORITY_MAX_SYSCALL,
            )
        }
        LINUX_SCHED_RR_GET_INTERVAL_SYSCALL => linux_sched_rr_get_interval(first_argument, buffer),
        LINUX_SCHED_SETATTR_SYSCALL => linux_sched_setattr(first_argument, buffer, count),
        LINUX_SCHED_GETATTR_SYSCALL => {
            linux_sched_getattr(first_argument, buffer, count, register(0))
        }
        LINUX_MLOCK_SYSCALL => linux_memory_lock(first_argument, buffer, 0, true),
        LINUX_MUNLOCK_SYSCALL => linux_memory_lock(first_argument, buffer, 0, false),
        LINUX_MLOCK2_SYSCALL => linux_memory_lock(first_argument, buffer, count, true),
        LINUX_MLOCKALL_SYSCALL => linux_mlockall(first_argument),
        LINUX_MUNLOCKALL_SYSCALL => linux_munlockall(),
        LINUX_PRCTL_SYSCALL => linux_prctl(first_argument, buffer, count, register(0), register(2)),
        LINUX_ARCH_PRCTL_SYSCALL => linux_arch_prctl(first_argument, buffer),
        LINUX_MODIFY_LDT_SYSCALL => linux_modify_ldt(first_argument, buffer, count),
        LINUX_UNAME_SYSCALL => linux_uname_with_copy(first_argument, copy_to_linux_user),
        LINUX_SETHOSTNAME_SYSCALL => linux_set_uts_name(LINUX_UTS_HOST, first_argument, buffer),
        LINUX_SETDOMAINNAME_SYSCALL => linux_set_uts_name(LINUX_UTS_DOMAIN, first_argument, buffer),
        LINUX_STATFS_SYSCALL => linux_statfs(first_argument, buffer),
        LINUX_FSTATFS_SYSCALL => linux_fstatfs(first_argument, buffer),
        LINUX_MOUNT_SYSCALL => linux_landlock_check_mount().map_or_else(
            |error| error,
            |()| linux_mount_filesystem(first_argument, buffer, count, register(0), register(2)),
        ),
        LINUX_UMOUNT2_SYSCALL => linux_landlock_check_mount()
            .map_or_else(|error| error, |()| linux_umount(first_argument, buffer)),
        LINUX_MOUNT_SETATTR_SYSCALL => {
            linux_mount_setattr(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_FSOPEN_SYSCALL => linux_fsopen(first_argument, buffer),
        LINUX_FSCONFIG_SYSCALL => {
            linux_fsconfig(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_FSMOUNT_SYSCALL => linux_fsmount(first_argument, buffer, count),
        LINUX_FSPICK_SYSCALL => linux_fspick(first_argument, buffer, count),
        LINUX_MOVE_MOUNT_SYSCALL => {
            linux_move_mount(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_OPEN_TREE_SYSCALL => linux_open_tree(first_argument, buffer, count),
        LINUX_OPEN_TREE_ATTR_SYSCALL => {
            linux_open_tree_attr(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_SYSFS_SYSCALL => linux_sysfs(first_argument, buffer, count),
        LINUX_USTAT_SYSCALL => linux_ustat(first_argument, buffer),
        LINUX_GETCWD_SYSCALL => linux_getcwd(first_argument, buffer),
        LINUX_CHDIR_SYSCALL => linux_chdir(first_argument),
        LINUX_FCHDIR_SYSCALL => linux_fchdir(first_argument),
        LINUX_READLINK_SYSCALL => {
            linux_readlink_at(u64::from(LINUX_AT_FDCWD), first_argument, buffer, count)
        }
        LINUX_OPEN_SYSCALL => linux_lease_live_return(
            registers,
            syscall_return,
            (number, u64::from(LINUX_AT_FDCWD), first_argument, buffer),
            || linux_openat(u64::from(LINUX_AT_FDCWD), first_argument, buffer, count),
        ),
        LINUX_OPENAT_SYSCALL => linux_lease_live_return(
            registers,
            syscall_return,
            (number, first_argument, buffer, count),
            || linux_openat(first_argument, buffer, count, register(0)),
        ),
        LINUX_OPENAT2_SYSCALL => linux_openat2(first_argument, buffer, count, register(0)),
        LINUX_NAME_TO_HANDLE_AT_SYSCALL => {
            linux_name_to_handle_at(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_OPEN_BY_HANDLE_AT_SYSCALL => linux_open_by_handle_at(first_argument, buffer, count),
        LINUX_MEMFD_CREATE_SYSCALL => linux_memfd_create(first_argument, buffer),
        LINUX_MEMFD_SECRET_SYSCALL => linux_memfd_secret(first_argument),
        LINUX_LANDLOCK_CREATE_RULESET_SYSCALL => {
            linux_landlock_create_ruleset(first_argument, buffer, count)
        }
        LINUX_LANDLOCK_ADD_RULE_SYSCALL => {
            linux_landlock_add_rule(first_argument, buffer, count, register(0))
        }
        LINUX_LANDLOCK_RESTRICT_SELF_SYSCALL => {
            linux_landlock_restrict_self(first_argument, buffer)
        }
        LINUX_IO_URING_SETUP_SYSCALL => linux_io_uring_setup(first_argument, buffer),
        LINUX_IO_URING_ENTER_SYSCALL => linux_io_uring_enter(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_IO_URING_REGISTER_SYSCALL => {
            linux_io_uring_register(first_argument, buffer, count, register(0))
        }
        LINUX_MAP_SHADOW_STACK_SYSCALL => linux_map_shadow_stack(first_argument, buffer, count),
        LINUX_URETPROBE_SYSCALL => linux_kill(
            u64::from(current_linux_process_pid()),
            (LINUX_SIGILL, LINUX_SI_KERNEL, None),
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ),
        LINUX_SECCOMP_SYSCALL => linux_seccomp(first_argument, buffer, count),
        LINUX_RSEQ_SYSCALL => linux_rseq(first_argument, buffer, count, register(0)),
        LINUX_CREAT_SYSCALL => linux_lease_live_return(
            registers,
            syscall_return,
            (
                number,
                u64::from(LINUX_AT_FDCWD),
                first_argument,
                LINUX_O_CREAT | LINUX_O_TRUNC | 1,
            ),
            || {
                linux_openat(
                    u64::from(LINUX_AT_FDCWD),
                    first_argument,
                    LINUX_O_CREAT | LINUX_O_TRUNC | 1,
                    buffer,
                )
            },
        ),
        LINUX_STAT_SYSCALL => {
            linux_newfstatat(u64::from(LINUX_AT_FDCWD), first_argument, buffer, 0)
        }
        LINUX_LSTAT_SYSCALL => linux_newfstatat(
            u64::from(LINUX_AT_FDCWD),
            first_argument,
            buffer,
            LINUX_AT_SYMLINK_NOFOLLOW,
        ),
        LINUX_NEWFSTATAT_SYSCALL => linux_newfstatat(first_argument, buffer, count, register(0)),
        LINUX_MKDIR_SYSCALL => linux_mkdirat(u64::from(LINUX_AT_FDCWD), first_argument, buffer),
        LINUX_MKDIRAT_SYSCALL => linux_mkdirat(first_argument, buffer, count),
        LINUX_MKNOD_SYSCALL => {
            linux_mknodat(u64::from(LINUX_AT_FDCWD), first_argument, buffer, count)
        }
        LINUX_MKNODAT_SYSCALL => linux_mknodat(first_argument, buffer, count, register(0)),
        LINUX_UNLINK_SYSCALL => linux_unlinkat(u64::from(LINUX_AT_FDCWD), first_argument, 0),
        LINUX_LINK_SYSCALL => linux_linkat(
            u64::from(LINUX_AT_FDCWD),
            first_argument,
            u64::from(LINUX_AT_FDCWD),
            buffer,
            0,
        ),
        LINUX_RMDIR_SYSCALL => linux_unlinkat(
            u64::from(LINUX_AT_FDCWD),
            first_argument,
            LINUX_AT_REMOVEDIR,
        ),
        LINUX_UNLINKAT_SYSCALL => linux_unlinkat(first_argument, buffer, count),
        LINUX_LINKAT_SYSCALL => {
            linux_linkat(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_SYMLINK_SYSCALL => linux_symlinkat(first_argument, u64::from(LINUX_AT_FDCWD), buffer),
        LINUX_SYMLINKAT_SYSCALL => linux_symlinkat(first_argument, buffer, count),
        LINUX_RENAME_SYSCALL => linux_renameat(
            u64::from(LINUX_AT_FDCWD),
            first_argument,
            u64::from(LINUX_AT_FDCWD),
            buffer,
            0,
        ),
        LINUX_RENAMEAT_SYSCALL => linux_renameat(first_argument, buffer, count, register(0), 0),
        LINUX_RENAMEAT2_SYSCALL => {
            linux_renameat(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_READLINKAT_SYSCALL => linux_readlink_at(first_argument, buffer, count, register(0)),
        LINUX_CHMOD_SYSCALL => linux_fchmodat(u64::from(LINUX_AT_FDCWD), first_argument, buffer, 0),
        LINUX_FCHMOD_SYSCALL => linux_fchmod(first_argument, buffer),
        LINUX_FCHMODAT_SYSCALL => linux_fchmodat(first_argument, buffer, count, 0),
        LINUX_CHOWN_SYSCALL | LINUX_LCHOWN_SYSCALL => linux_fchownat(
            u64::from(LINUX_AT_FDCWD),
            first_argument,
            buffer,
            count,
            if number == LINUX_LCHOWN_SYSCALL {
                LINUX_AT_SYMLINK_NOFOLLOW
            } else {
                0
            },
        ),
        LINUX_FCHOWN_SYSCALL => linux_fchown(first_argument, buffer, count),
        LINUX_FCHOWNAT_SYSCALL => {
            linux_fchownat(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_SETXATTR_SYSCALL | LINUX_LSETXATTR_SYSCALL => linux_setxattr_path(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            number == LINUX_SETXATTR_SYSCALL,
        ),
        LINUX_FSETXATTR_SYSCALL => {
            linux_fsetxattr(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_GETXATTR_SYSCALL | LINUX_LGETXATTR_SYSCALL => linux_getxattr_path(
            first_argument,
            buffer,
            count,
            register(0),
            number == LINUX_GETXATTR_SYSCALL,
        ),
        LINUX_FGETXATTR_SYSCALL => linux_fgetxattr(first_argument, buffer, count, register(0)),
        LINUX_LISTXATTR_SYSCALL | LINUX_LLISTXATTR_SYSCALL => linux_listxattr_path(
            first_argument,
            buffer,
            count,
            number == LINUX_LISTXATTR_SYSCALL,
        ),
        LINUX_FLISTXATTR_SYSCALL => linux_flistxattr(first_argument, buffer, count),
        LINUX_REMOVEXATTR_SYSCALL | LINUX_LREMOVEXATTR_SYSCALL => {
            linux_removexattr_path(first_argument, buffer, number == LINUX_REMOVEXATTR_SYSCALL)
        }
        LINUX_FREMOVEXATTR_SYSCALL => linux_fremovexattr(first_argument, buffer),
        LINUX_EPOLL_CREATE1_SYSCALL => linux_epoll_create1(first_argument),
        LINUX_PIPE2_SYSCALL => linux_pipe(first_argument, buffer),
        LINUX_SPLICE_SYSCALL => linux_splice(
            registers,
            syscall_return,
            (first_argument, buffer),
            (count, register(0)),
            register(2),
            register(1),
        ),
        LINUX_TEE_SYSCALL => linux_tee(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
            register(0),
        ),
        LINUX_VMSPLICE_SYSCALL => linux_vmsplice_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
            register(0),
        ),
        LINUX_TIMERFD_CREATE_SYSCALL => linux_timerfd_create(first_argument, buffer),
        LINUX_EVENTFD_SYSCALL => linux_eventfd(first_argument, 0),
        LINUX_EVENTFD2_SYSCALL => linux_eventfd(first_argument, buffer),
        LINUX_TIMERFD_SETTIME_SYSCALL => {
            linux_timerfd_settime(first_argument, buffer, count, register(0))
        }
        LINUX_TIMERFD_GETTIME_SYSCALL => linux_timerfd_gettime(first_argument, buffer),
        LINUX_EPOLL_PWAIT_SYSCALL => linux_epoll_pwait_live_return(
            registers,
            syscall_return,
            LinuxEpollWaitInput {
                epoll: first_argument,
                address: buffer,
                maximum: count,
            },
            register(0),
            LinuxSignalMaskInput {
                address: register(2),
                size: register(1),
            },
        ),
        LINUX_EPOLL_PWAIT2_SYSCALL => linux_epoll_pwait2_live_return(
            registers,
            syscall_return,
            LinuxEpollWaitInput {
                epoll: first_argument,
                address: buffer,
                maximum: count,
            },
            register(0),
            LinuxSignalMaskInput {
                address: register(2),
                size: register(1),
            },
        ),
        LINUX_PPOLL_SYSCALL => linux_ppoll_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
        ),
        LINUX_FACCESSAT_SYSCALL => linux_faccessat(first_argument, buffer, count, 0),
        LINUX_FACCESSAT2_SYSCALL => linux_faccessat(first_argument, buffer, count, register(0)),
        LINUX_ACCESS_SYSCALL => {
            linux_faccessat(u64::from(LINUX_AT_FDCWD), first_argument, buffer, 0)
        }
        LINUX_UMASK_SYSCALL => X86_RUNTIME
            .ELF_PROBE_UMASK
            .swap(first_argument & 0o777, Ordering::SeqCst),
        LINUX_GETTIMEOFDAY_SYSCALL => linux_gettimeofday(first_argument, buffer),
        LINUX_SETTIMEOFDAY_SYSCALL => linux_settimeofday(first_argument, buffer),
        LINUX_ADJTIMEX_SYSCALL => linux_adjtimex(first_argument),
        LINUX_CLOCK_ADJTIME_SYSCALL => linux_clock_adjtime(first_argument, buffer),
        LINUX_GETRLIMIT_SYSCALL => linux_getrlimit(
            first_argument,
            buffer,
            X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
            copy_to_linux_user,
        ),
        LINUX_SETRLIMIT_SYSCALL => linux_setrlimit(first_argument, buffer),
        LINUX_SYNC_SYSCALL => {
            crate::linux_blockfs::sync_all();
            0
        }
        LINUX_GETRUSAGE_SYSCALL => linux_getrusage(first_argument, buffer),
        LINUX_SYSINFO_SYSCALL => linux_sysinfo(first_argument),
        LINUX_TIMES_SYSCALL => linux_times(first_argument),
        LINUX_FUTEX_SYSCALL => linux_futex_live_return(
            registers,
            LinuxUserContext {
                registers: saved_registers,
                rip: user_rip,
                rsp: user_stack,
                rflags: user_rflags,
                rax: 0,
                fs_base: active_fs_base(),
            },
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_FUTEX_WAKE_SYSCALL => linux_futex_wake(first_argument, buffer, count, register(0)),
        LINUX_FUTEX_WAIT_SYSCALL => linux_futex_wait_live_return(
            registers,
            syscall_return,
            LINUX_FUTEX_WAIT_SYSCALL,
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_FUTEX_REQUEUE_SYSCALL => {
            linux_futex_requeue(first_argument, buffer, count, register(0))
        }
        LINUX_FUTEX_WAITV_SYSCALL => linux_futex_waitv_live_return(
            registers,
            syscall_return,
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
        ),
        LINUX_PIDFD_OPEN_SYSCALL => linux_pidfd_open(first_argument, buffer),
        LINUX_PIDFD_GETFD_SYSCALL => linux_pidfd_getfd(first_argument, buffer, count),
        LINUX_PIDFD_SEND_SIGNAL_SYSCALL => linux_pidfd_send_signal(
            first_argument,
            buffer,
            count,
            register(0),
            registers,
            syscall_return,
            (user_rip, user_rflags),
        ),
        LINUX_SIGNALFD_SYSCALL => linux_signalfd(first_argument, buffer, count, 0),
        LINUX_SIGNALFD4_SYSCALL => linux_signalfd(first_argument, buffer, count, register(0)),
        LINUX_INOTIFY_INIT_SYSCALL => linux_inotify_init(0),
        LINUX_INOTIFY_INIT1_SYSCALL => linux_inotify_init(first_argument),
        LINUX_INOTIFY_ADD_WATCH_SYSCALL => linux_inotify_add_watch(first_argument, buffer, count),
        LINUX_INOTIFY_RM_WATCH_SYSCALL => linux_inotify_rm_watch(first_argument, buffer),
        LINUX_FANOTIFY_INIT_SYSCALL => linux_fanotify_init(first_argument, buffer),
        LINUX_FANOTIFY_MARK_SYSCALL => {
            linux_fanotify_mark(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_ADD_KEY_SYSCALL => {
            linux_add_key(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_REQUEST_KEY_SYSCALL => linux_request_key(first_argument, buffer, count, register(0)),
        LINUX_KEYCTL_SYSCALL => {
            linux_keyctl(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_USERFAULTFD_SYSCALL => linux_userfaultfd(first_argument),
        LINUX_PRLIMIT64_SYSCALL => linux_prlimit64(first_argument, buffer, count, register(0)),
        LINUX_SCHED_GETAFFINITY_SYSCALL => linux_sched_getaffinity(first_argument, buffer, count),
        LINUX_GETCPU_SYSCALL => {
            if !copy_linux_cpu_location(first_argument, buffer) {
                return LINUX_EFAULT;
            }
            0
        }
        LINUX_GETRANDOM_SYSCALL => linux_getrandom(first_argument, buffer, count),
        LINUX_GETDENTS_SYSCALL => linux_getdents(first_argument, buffer, count, true),
        LINUX_GETDENTS64_SYSCALL => linux_getdents64(first_argument, buffer, count),
        LINUX_READAHEAD_SYSCALL => linux_readahead(first_argument, buffer, count),
        LINUX_EPOLL_CREATE_SYSCALL => {
            if first_argument as i32 <= 0 {
                LINUX_EINVAL
            } else {
                linux_epoll_create1(0)
            }
        }
        LINUX_IOPRIO_GET_SYSCALL => linux_ioprio_get(first_argument, buffer),
        LINUX_IOPRIO_SET_SYSCALL => linux_ioprio_set(first_argument, buffer, count),
        LINUX_CLOCK_GETTIME_SYSCALL => linux_clock_gettime(first_argument, buffer),
        LINUX_CLOCK_SETTIME_SYSCALL => linux_clock_settime(first_argument, buffer),
        LINUX_CLOCK_GETRES_SYSCALL => linux_clock_getres(first_argument, buffer),
        LINUX_UTIMENSAT_SYSCALL => linux_utimensat(first_argument, buffer, count, register(0)),
        LINUX_UTIME_SYSCALL => linux_utime(first_argument, buffer),
        LINUX_UTIMES_SYSCALL => linux_utimes(u64::from(LINUX_AT_FDCWD), first_argument, buffer),
        LINUX_FUTIMESAT_SYSCALL => linux_utimes(first_argument, buffer, count),
        LINUX_FCHMODAT2_SYSCALL => linux_fchmodat(first_argument, buffer, count, register(0)),
        LINUX_STATX_SYSCALL => {
            linux_statx_unique_mount(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_CLOSE_RANGE_SYSCALL => linux_close_range(first_argument, buffer, count),
        LINUX_SYNCFS_SYSCALL => linux_syncfs(first_argument),
        LINUX_SYNC_FILE_RANGE_SYSCALL => {
            linux_sync_file_range(first_argument, buffer, count, register(0))
        }
        LINUX_PROCESS_VM_READV_SYSCALL | LINUX_PROCESS_VM_WRITEV_SYSCALL => linux_process_vm_iov(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
            number == LINUX_PROCESS_VM_WRITEV_SYSCALL,
        ),
        LINUX_SET_MEMPOLICY_SYSCALL => linux_set_mempolicy(first_argument, buffer, count),
        LINUX_GET_MEMPOLICY_SYSCALL => {
            linux_get_mempolicy(first_argument, buffer, count, register(0), register(2))
        }
        LINUX_MBIND_SYSCALL => linux_mbind(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_MIGRATE_PAGES_SYSCALL => {
            linux_migrate_pages(first_argument, buffer, count, register(0))
        }
        LINUX_MOVE_PAGES_SYSCALL => linux_move_pages(
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            register(1),
        ),
        LINUX_SET_MEMPOLICY_HOME_NODE_SYSCALL => {
            linux_set_mempolicy_home_node(first_argument, buffer, count, register(0))
        }
        LINUX_KCMP_SYSCALL => linux_kcmp(first_argument, buffer, count, register(0), register(2)),
        LINUX_CACHESTAT_SYSCALL => linux_cachestat(first_argument, buffer, count, register(0)),
        LINUX_MEMBARRIER_SYSCALL => linux_membarrier(first_argument, buffer, count),
        LINUX_WAIT4_SYSCALL => linux_wait4_live(
            registers,
            first_argument,
            buffer,
            count,
            register(0),
            syscall_return,
        ),
        LINUX_WAITID_SYSCALL => linux_waitid_live(
            registers,
            first_argument,
            buffer,
            count,
            register(0),
            register(2),
            syscall_return,
        ),
        LINUX_USELIB_SYSCALL
        | LINUX_SYSCTL_SYSCALL
        | LINUX_CREATE_MODULE_SYSCALL
        | LINUX_GET_KERNEL_SYMS_SYSCALL
        | LINUX_QUERY_MODULE_SYSCALL
        | LINUX_NFSSERVCTL_SYSCALL
        | LINUX_GETPMSG_SYSCALL
        | LINUX_PUTPMSG_SYSCALL
        | LINUX_AFS_SYSCALL
        | LINUX_TUXCALL_SYSCALL
        | LINUX_SECURITY_SYSCALL
        | LINUX_SET_THREAD_AREA_SYSCALL
        | LINUX_GET_THREAD_AREA_SYSCALL
        | LINUX_LOOKUP_DCOOKIE_SYSCALL
        | LINUX_EPOLL_CTL_OLD_SYSCALL
        | LINUX_EPOLL_WAIT_OLD_SYSCALL
        | LINUX_VSERVER_SYSCALL => LINUX_ENOSYS,
        LINUX_EXIT_SYSCALL
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
                && current_linux_tid() != Some(current_linux_process_pid()) =>
        {
            linux_exit_child_to_parent(registers, syscall_return)
        }
        LINUX_EXIT_SYSCALL
            if current_linux_process_pid() != 1
                && current_linux_tid().is_some_and(|tid| tid != current_linux_process_pid()) =>
        {
            linux_exit_child_to_parent(registers, syscall_return)
        }
        LINUX_EXIT_SYSCALL | LINUX_EXIT_GROUP_SYSCALL if current_linux_process_pid() != 1 => {
            // Memory others still use sees the exit: the tid word
            // (CLONE_CHILD_CLEARTID, set_tid_address) is cleared and woken,
            // as Linux does while the memory has other users.
            let clear_child_tid = current_linux_clear_child_tid().unwrap_or(0);
            if clear_child_tid != 0
                && linux_process::live_process_resource_shared(
                    current_linux_process_pid(),
                    linux_process::SharedResource::Memory,
                )
                && copy_to_linux_user(clear_child_tid, &0_u32.to_ne_bytes())
            {
                let _ = wake_linux_futex(clear_child_tid, 1);
            }
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
                && !refresh_live_linux_process_registry(syscall_return)
            {
                // Linux exit is non-returning. If the final metadata refresh
                // cannot be published, preserve the last validated registry
                // record and let address-space retirement walk the live page
                // tables directly. Returning an errno here would resume a
                // process after libc has committed to termination. The
                // registry's mappings may then name pages the process has
                // already freed, so its release frees only what the page
                // tables show.
                serial_write("ginux: child exit using last validated process snapshot\r\n");
                let _ = linux_process::mark_live_process_address_space_stale(
                    current_linux_process_pid(),
                );
            }
            // The service manager owns reporting ordinary userspace process
            // failures. Keep the raw exit trace available to verification
            // builds without leaking anonymous helper exits onto the domain
            // console during a normal boot.
            if first_argument != 0
                && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
                && cfg!(feature = "verification-boot")
            {
                serial_write("ginux: Linux child exited with status ");
                serial_write_u64(first_argument);
                serial_write("\r\n");
                write_linux_runtime_syscall_trace();
            }
            if !clear_current_linux_process_signal_queues() {
                return LINUX_EIO;
            }
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_STATUS
                .store(first_argument as u8, Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXIT_PID
                .store(current_linux_process_pid(), Ordering::SeqCst);
            X86_RUNTIME
                .LINUX_PROCESS_CHILD_EXITED
                .store(true, Ordering::SeqCst);
            LINUX_RETURN_TO_KERNEL
        }
        LINUX_EXIT_SYSCALL | LINUX_EXIT_GROUP_SYSCALL
            if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) =>
        {
            if let Some(result) =
                linux_init_exit_kill_others_live_return(registers, syscall_return, number)
            {
                return result;
            }
            X86_RUNTIME
                .LINUX_RUNTIME_EXIT_STATUS
                .store(first_argument, Ordering::SeqCst);
            if !linux_close_all_descriptors() {
                return LINUX_EIO;
            }
            if !clear_current_linux_process_signal_queues() {
                return LINUX_EIO;
            }
            retire_all_linux_threads();
            X86_RUNTIME
                .ELF_PROBE_COMPLETED
                .store(true, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
            LINUX_RETURN_TO_KERNEL
        }
        LINUX_EXIT_SYSCALL if current_linux_tid() != Some(1) => {
            linux_exit_child_to_parent(registers, syscall_return)
        }
        LINUX_EXIT_SYSCALL | LINUX_EXIT_GROUP_SYSCALL => {
            X86_RUNTIME
                .ELF_PROBE_EXIT_STATUS
                .store(first_argument, Ordering::SeqCst);
            if !record_live_linux_process_snapshot() {
                return LINUX_ESRCH;
            }
            if X86_RUNTIME.ELF_PROBE_EXEC_REPLACED.load(Ordering::SeqCst) {
                let clear_child_tid = current_linux_clear_child_tid().unwrap_or(0);
                let robust_list = current_linux_robust_list().unwrap_or(0);
                if clear_child_tid != 0 {
                    let _ = copy_to_linux_user(clear_child_tid, &0_u32.to_ne_bytes());
                    let _ = wake_linux_futex(clear_child_tid, 1);
                }
                exit_linux_robust_list(current_linux_tid().unwrap_or(0), robust_list);
                if !set_current_linux_clear_child_tid(0)
                    || !set_current_linux_robust_list(0)
                    || !linux_close_all_descriptors()
                    || !crate::linux_socket::shutdown()
                    || !linux_tmpfs::teardown()
                    || !crate::linux_overlay::teardown()
                    || !clear_current_linux_process_signal_queues()
                    || !retire_current_linux_thread()
                {
                    return LINUX_ESRCH;
                }
                if initramfs::published_file_name_by_node(
                    X86_RUNTIME.ELF_PROBE_EXEC_NODE.load(Ordering::SeqCst),
                ) == Some(b"linux/init")
                {
                    serial_write("DYNEXEC\r\n");
                }
                X86_RUNTIME
                    .ELF_PROBE_COMPLETED
                    .store(true, Ordering::SeqCst);
                X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
                return LINUX_RETURN_TO_KERNEL;
            }
            let clear_child_tid = current_linux_clear_child_tid().unwrap_or(0);
            let robust_list = current_linux_robust_list().unwrap_or(0);
            if clear_child_tid != 0 {
                let _ = copy_to_linux_user(clear_child_tid, &0_u32.to_ne_bytes());
                let _ = wake_linux_futex(clear_child_tid, 1);
            }
            exit_linux_robust_list(current_linux_tid().unwrap_or(0), robust_list);
            if robust_list == 0
                || !set_current_linux_clear_child_tid(0)
                || !set_current_linux_robust_list(0)
                || !linux_close_all_descriptors()
                || !crate::linux_socket::shutdown()
                || !linux_tmpfs::teardown()
                || !crate::linux_overlay::teardown()
                || !clear_current_linux_process_signal_queues()
            {
                return LINUX_ESRCH;
            }
            X86_RUNTIME
                .ELF_PROBE_EXITED_CLEAR_CHILD_TID
                .store(clear_child_tid, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_EXITED_ROBUST_LIST
                .store(robust_list, Ordering::SeqCst);
            if !retire_current_linux_thread() {
                return LINUX_ESRCH;
            }
            X86_RUNTIME
                .ELF_PROBE_COMPLETED
                .store(true, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
            LINUX_RETURN_TO_KERNEL
        }
        LINUX_UNSHARE_SYSCALL => linux_unshare(first_argument),
        LINUX_SETNS_SYSCALL => linux_setns(first_argument, buffer),
        LINUX_REBOOT_SYSCALL => linux_reboot(first_argument, buffer, count, register(0)),
        LINUX_CHROOT_SYSCALL => linux_chroot(first_argument),
        LINUX_PIVOT_ROOT_SYSCALL => linux_landlock_check_mount()
            .map_or_else(|error| error, |()| linux_pivot_root(first_argument, buffer)),
        LINUX_ACCT_SYSCALL => linux_acct(first_argument),
        LINUX_QUOTACTL_SYSCALL => linux_quotactl(first_argument, buffer, count, register(0)),
        LINUX_SWAPON_SYSCALL => linux_swapon(first_argument, buffer),
        LINUX_SWAPOFF_SYSCALL => linux_swapoff(first_argument),
        LINUX_QUOTACTL_FD_SYSCALL => linux_quotactl_fd(first_argument, buffer, count, register(0)),
        LINUX_PTRACE_SYSCALL
            if linux_privileged_operation_allowed(
                linux_user::PrivilegedOperation::TraceProcesses,
            ) =>
        {
            linux_ptrace(first_argument, buffer, count, register(0))
        }
        LINUX_VHANGUP_SYSCALL => linux_vhangup(),
        LINUX_IOPERM_SYSCALL => linux_ioperm(first_argument, buffer, count),
        LINUX_IOPL_SYSCALL => linux_iopl(first_argument),
        LINUX_DELETE_MODULE_SYSCALL => linux_delete_module(first_argument),
        LINUX_SYSLOG_SYSCALL => linux_syslog(first_argument, buffer, count),
        LINUX_PERF_EVENT_OPEN_SYSCALL => {
            linux_perf_event_open(first_argument, buffer, count, register(0), register(2))
        }
        number if linux_privileged_operation(number).is_some() => {
            linux_deny_privileged_operation(number)
        }
        _ => LINUX_ENOSYS,
    };
    let result = if X86_RUNTIME
        .LINUX_FSIZE_LIMIT_HIT
        .swap(false, Ordering::SeqCst)
    {
        linux_file_size_limit_signal(registers, syscall_return, (user_rip, user_rflags), result)
    } else {
        result
    };
    linux_account_call_io(number, result);
    if let Some(call) = inotify {
        linux_inotify_after(call, result);
        linux_send_dnotify_notices();
    }
    let same_thread = current_linux_thread_handle() == calling_thread;
    // A call that went back to the kernel to wait has no result yet to
    // interrupt; its wait sees the signal pending and is interrupted there.
    let returns_to_user = result != LINUX_RETURN_TO_KERNEL && result != LINUX_RETURN_FROM_IRET;
    let result = if real_timer_expired && same_thread && returns_to_user {
        linux_real_timer_signal(registers, syscall_return, (user_rip, user_rflags), result)
    } else {
        if real_timer_expired {
            X86_RUNTIME
                .ELF_PROBE_PENDING_SIGNALS
                .fetch_or(1 << (LINUX_SIGALRM - 1), Ordering::SeqCst);
        }
        result
    };
    let result = if runtime_mode
        && same_thread
        && result != LINUX_RETURN_TO_KERNEL
        && result != LINUX_RETURN_FROM_IRET
        && number != LINUX_RT_SIGRETURN_SYSCALL
        && !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
    {
        let mut interrupted = syscall_return;
        interrupted.rax = result;
        let delivered = linux_deliver_pending_signal_restarting(
            registers,
            interrupted,
            (user_rip, user_rflags),
            Some(number),
        );
        if delivered != 0 {
            delivered
        } else if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
            0
        } else {
            result
        }
    } else {
        result
    };
    if let Some(index) = trace_index {
        X86_RUNTIME.LINUX_RUNTIME_SYSCALL_RESULT_TRACE[index].store(result, Ordering::SeqCst);
    }
    if runtime_mode && result == LINUX_ENOSYS {
        let first = X86_RUNTIME
            .LINUX_RUNTIME_FIRST_UNSUPPORTED_SYSCALL
            .compare_exchange(u64::MAX, number, Ordering::SeqCst, Ordering::SeqCst);
        if let Some(word) = usize::try_from(number / 64)
            .ok()
            .filter(|word| *word < LINUX_RUNTIME_UNSUPPORTED_WORDS)
        {
            let bit = 1_u64 << (number % 64);
            let first_observation = X86_RUNTIME.LINUX_RUNTIME_UNSUPPORTED_SYSCALLS[word]
                .fetch_or(bit, Ordering::SeqCst)
                & bit
                == 0;
            if first_observation {
                serial_write(if first.is_ok() {
                    "ginux: first unsupported syscall number/arguments: "
                } else {
                    "ginux: unsupported syscall number/arguments: "
                });
                serial_write_u64(number);
                for value in [
                    first_argument,
                    buffer,
                    count,
                    register(0),
                    register(1),
                    register(2),
                ] {
                    serial_write(" ");
                    serial_write_u64(value);
                }
                serial_write("\r\n");
            }
        }
    }
    if runtime_mode && result == LINUX_EINVAL {
        if let Some(word) = usize::try_from(number / 64)
            .ok()
            .filter(|word| *word < LINUX_RUNTIME_UNSUPPORTED_WORDS)
        {
            let bit = 1_u64 << (number % 64);
            X86_RUNTIME.LINUX_RUNTIME_EINVAL_SYSCALLS[word].fetch_or(bit, Ordering::SeqCst);
        }
    }
    let switched_thread = runtime_mode && current_linux_thread_handle() != calling_thread;
    // Suspending saves the calling thread's context, so it waits for a
    // return into that thread.
    if runtime_mode
        && !switched_thread
        && result != LINUX_RETURN_TO_KERNEL
        && result != LINUX_RETURN_FROM_IRET
        && !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::Acquire)
        && !linux_bank_shared()
        && X86_RUNTIME
            .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
            .swap(false, Ordering::AcqRel)
    {
        let mut context = syscall_return;
        context.rax = result;
        if save_suspended_linux_runtime(context, 0, 0, true) {
            return LINUX_RETURN_TO_KERNEL;
        }
    }
    // A thread switch returns into another thread's saved context. A timer
    // may have preempted that thread mid-instruction, and SYSRET would
    // replace its RCX and R11 with the return address and flags, so any
    // switch that did not already prepare it returns through the IRETQ
    // epilogue with the values saved for the thread's slot. (A thread saved
    // at a system call holds exactly those values anyway.)
    if switched_thread && result != LINUX_RETURN_TO_KERNEL && result != LINUX_RETURN_FROM_IRET {
        if let Some(slot) = current_linux_thread_slot() {
            // SAFETY: the serialized syscall entry owns this per-CPU state
            // until the assembly epilogue consumes it.
            unsafe {
                let entry_state = &mut *current_entry_state();
                entry_state.signal_rax = result;
                entry_state.signal_rcx = X86_RUNTIME.LINUX_THREAD_RCXS[slot].load(Ordering::SeqCst);
                entry_state.signal_r11 = X86_RUNTIME.LINUX_THREAD_R11S[slot].load(Ordering::SeqCst);
            }
            return LINUX_RETURN_FROM_IRET;
        }
    }
    result
}
