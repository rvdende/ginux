use super::*;

pub(super) fn linux_rt_sigaction(signal: u64, action: u64, old_action: u64, set_size: u64) -> u64 {
    let signal = u64::from(signal as u32);
    if set_size != LINUX_SIGNAL_SET_SIZE || !(1..=LINUX_SIGNAL_COUNT as u64).contains(&signal) {
        return LINUX_EINVAL;
    }
    if action != 0 && matches!(signal, 9 | 19) {
        return LINUX_EINVAL;
    }
    if old_action != 0 && !linux_writable_user_range_contains(old_action, LINUX_SIGNAL_ACTION_SIZE)
    {
        return LINUX_EFAULT;
    }
    let parse_word = |bytes: &[u8; LINUX_SIGNAL_ACTION_SIZE], offset: usize| {
        let mut word = [0_u8; 8];
        word.copy_from_slice(&bytes[offset..offset + 8]);
        u64::from_ne_bytes(word)
    };
    let new_action = if action == 0 {
        None
    } else {
        let mut bytes = [0_u8; LINUX_SIGNAL_ACTION_SIZE];
        if !copy_from_linux_user(action, &mut bytes) {
            return LINUX_EFAULT;
        }
        Some([
            parse_word(&bytes, 0),
            parse_word(&bytes, 8),
            parse_word(&bytes, 16),
            parse_word(&bytes, 24) & !LINUX_UNBLOCKABLE_SIGNALS,
        ])
    };
    let index = signal as usize - 1;
    let current = [
        X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[index].load(Ordering::SeqCst),
        X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[index].load(Ordering::SeqCst),
    ];
    if old_action != 0 {
        let mut bytes = [0_u8; LINUX_SIGNAL_ACTION_SIZE];
        for (offset, word) in current.into_iter().enumerate() {
            let word = if offset == 1 {
                word & LINUX_UAPI_SA_FLAGS
            } else {
                word
            };
            bytes[offset * 8..offset * 8 + 8].copy_from_slice(&word.to_ne_bytes());
        }
        if !copy_to_linux_user(old_action, &bytes) {
            return LINUX_EFAULT;
        }
    }
    if let Some([handler, flags, restorer, mask]) = new_action {
        X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].store(handler, Ordering::SeqCst);
        // Only the flags Linux knows are kept, as it masks them: musl
        // widens an int sa_flags, so SA_RESETHAND arrives sign-extended
        // (0xffffffff80000000), and unknown bits must not make the handler
        // undeliverable (sigaction01, perf_event_open02's SIGALRM).
        X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index]
            .store(flags & LINUX_UAPI_SA_FLAGS, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[index].store(restorer, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[index].store(mask, Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_sigaltstack(new_stack: u64, old_stack: u64) -> u64 {
    if old_stack != 0 && !linux_writable_user_range_contains(old_stack, LINUX_ALT_STACK_SIZE) {
        return LINUX_EFAULT;
    }
    if new_stack != 0
        && X86_RUNTIME.ELF_PROBE_ALT_STACK_FLAGS.load(Ordering::SeqCst) == LINUX_SS_ONSTACK
    {
        return LINUX_EPERM;
    }
    let replacement = if new_stack == 0 {
        None
    } else {
        let mut bytes = [0_u8; LINUX_ALT_STACK_SIZE];
        if !copy_from_linux_user(new_stack, &mut bytes) {
            return LINUX_EFAULT;
        }
        let mut pointer_bytes = [0_u8; 8];
        let mut flags_bytes = [0_u8; 4];
        let mut size_bytes = [0_u8; 8];
        pointer_bytes.copy_from_slice(&bytes[..8]);
        flags_bytes.copy_from_slice(&bytes[8..12]);
        size_bytes.copy_from_slice(&bytes[16..24]);
        let pointer = u64::from_ne_bytes(pointer_bytes);
        let flags = u32::from_ne_bytes(flags_bytes);
        let size = u64::from_ne_bytes(size_bytes);
        match flags {
            LINUX_SS_DISABLE => Some((0, LINUX_SS_DISABLE, 0)),
            0 | LINUX_SS_AUTODISARM if size < LINUX_MIN_ALT_STACK_SIZE => return LINUX_ENOMEM,
            0 | LINUX_SS_AUTODISARM => {
                let Ok(length) = usize::try_from(size) else {
                    return LINUX_EFAULT;
                };
                if !linux_writable_user_range_contains(pointer, length) {
                    return LINUX_EFAULT;
                }
                Some((pointer, flags, size))
            }
            _ => return LINUX_EINVAL,
        }
    };
    if old_stack != 0 {
        let mut bytes = [0_u8; LINUX_ALT_STACK_SIZE];
        bytes[..8].copy_from_slice(
            &X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .load(Ordering::SeqCst)
                .to_ne_bytes(),
        );
        bytes[8..12].copy_from_slice(
            &X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .load(Ordering::SeqCst)
                .to_ne_bytes(),
        );
        bytes[16..24].copy_from_slice(
            &X86_RUNTIME
                .ELF_PROBE_ALT_STACK_SIZE
                .load(Ordering::SeqCst)
                .to_ne_bytes(),
        );
        if !copy_to_linux_user(old_stack, &bytes) {
            return LINUX_EFAULT;
        }
    }
    if let Some((pointer, flags, size)) = replacement {
        X86_RUNTIME
            .ELF_PROBE_ALT_STACK_POINTER
            .store(pointer, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_ALT_STACK_FLAGS
            .store(flags, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_ALT_STACK_SIZE
            .store(size, Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_rt_sigprocmask(how: u64, set: u64, old_set: u64, set_size: u64) -> u64 {
    let how = u64::from(how as u32);
    if set_size != LINUX_SIGNAL_SET_SIZE {
        return LINUX_EINVAL;
    }
    if old_set != 0 && !linux_writable_user_range_contains(old_set, LINUX_SIGNAL_SET_SIZE as usize)
    {
        return LINUX_EFAULT;
    }
    let requested = if set == 0 {
        None
    } else {
        let mut bytes = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
        if !copy_from_linux_user(set, &mut bytes) {
            return LINUX_EFAULT;
        }
        Some(u64::from_ne_bytes(bytes) & !LINUX_UNBLOCKABLE_SIGNALS)
    };
    let current = current_linux_signal_mask();
    let next = match requested {
        None => current,
        Some(mask) if how == LINUX_SIG_BLOCK => current | mask,
        Some(mask) if how == LINUX_SIG_UNBLOCK => current & !mask,
        Some(mask) if how == LINUX_SIG_SETMASK => mask,
        Some(_) => return LINUX_EINVAL,
    };
    if old_set != 0 && !copy_to_linux_user(old_set, &current.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    store_current_linux_signal_mask(next);
    0
}

pub(super) fn linux_rt_sigpending(set: u64, set_size: u64) -> u64 {
    if set_size != LINUX_SIGNAL_SET_SIZE {
        return LINUX_EINVAL;
    }
    let dynamic = linux_dynamic_pending_masks().map_or(0, |(process, thread)| process | thread);
    let pending = (X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) | dynamic)
        & current_linux_signal_mask();
    if copy_to_linux_user(set, &pending.to_ne_bytes()) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_rt_sigqueueinfo(
    process: u64,
    thread: Option<u64>,
    signal: u64,
    information: u64,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    let process = u64::from(process as u32);
    let thread = thread.map(|thread| u64::from(thread as u32));
    let signal = u64::from(signal as u32);
    let current_process = u64::from(current_linux_process_pid());
    // rt_sigqueueinfo's pid may be one of the caller's thread ids, which
    // names the caller's process (rt_sigqueueinfo01).
    let process = if thread.is_none()
        && process != current_process
        && linux_process::live_process_slot(process as u32).is_none()
        && linux_tgkill_target(current_process, process).is_ok()
    {
        current_process
    } else {
        process
    };
    let resolved_thread = if let Some(thread) = thread {
        match linux_tgkill_target(process, thread) {
            Ok(target) => Some(target),
            Err(error) => return error,
        }
    } else {
        None
    };
    let target_thread = resolved_thread.and_then(|target| match target {
        LinuxThreadSignalTarget::Active(target) => Some(target),
        LinuxThreadSignalTarget::Saved { .. } => None,
    });
    if signal == 0 {
        let target_process = resolved_thread.map_or(process as u32, |target| match target {
            LinuxThreadSignalTarget::Active(_) => current_linux_process_pid(),
            LinuxThreadSignalTarget::Saved { pid, .. } => pid,
        });
        if target_process != current_linux_process_pid() {
            if linux_process::live_process_slot(target_process).is_none() {
                return LINUX_ESRCH;
            }
            if !linux_signal_permitted(target_process, signal) {
                return LINUX_EPERM;
            }
        }
        return 0;
    }
    if !(1..=LINUX_SIGNAL_COUNT as u64).contains(&signal) {
        return LINUX_EINVAL;
    }
    let mut bytes = [0_u8; size_of::<LinuxSignalInformation>()];
    if !copy_from_linux_user(information, &mut bytes) {
        return LINUX_EFAULT;
    }
    let code = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    if code >= 0 {
        return LINUX_EPERM;
    }
    let value = u64::from_ne_bytes(bytes[24..32].try_into().unwrap());
    let (sender_pid, sender_uid) = linux_signal_sender();
    if let Some(LinuxThreadSignalTarget::Saved {
        pid,
        process_slot,
        thread_slot,
    }) = resolved_thread
    {
        if !linux_signal_permitted(pid, signal) {
            return LINUX_EPERM;
        }
        return linux_queue_saved_thread_signal(
            pid,
            process_slot,
            thread_slot,
            signal,
            code,
            Some(value),
        );
    }
    if process != current_process {
        let process = process as u32;
        if linux_process::live_process_slot(process).is_none() {
            return LINUX_ESRCH;
        }
        if !linux_signal_permitted(process, signal) {
            return LINUX_EPERM;
        }
        return linux_queue_process_signal(process, signal, code, Some(value));
    }
    if wake_linux_signal_wait_target(
        target_thread,
        signal,
        code,
        Some(value),
        Some((sender_pid, sender_uid)),
    ) {
        return 0;
    }
    let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal as usize - 1].load(Ordering::SeqCst);
    if handler == 1 || handler == 0 && linux_default_signal_ignored(signal) {
        return 0;
    }
    let instance = linux_signal_instance();
    let process_slot = match linux_process::live_process_slot(process as u32) {
        Some(slot) => slot,
        None => return LINUX_ESRCH,
    };
    let (scope, slot, target_is_current, target_mask) = if let Some(target) = target_thread {
        let thread_slot = usize::from(target.slot);
        (
            crate::linux_signal::Scope::Thread,
            linux_thread_signal_queue_slot(process_slot, thread_slot),
            current_linux_thread_handle() == Some(target),
            X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[thread_slot].load(Ordering::SeqCst),
        )
    } else {
        (
            crate::linux_signal::Scope::Process,
            process_slot,
            true,
            X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
        )
    };
    if target_is_current && target_mask & (1 << (signal - 1)) == 0 {
        return linux_kill(
            u64::from(current_linux_process_pid()),
            (signal, code, Some(value)),
            output,
            interrupted,
            return_registers,
        );
    }
    match linux_enqueue_signal(
        instance,
        scope,
        slot,
        crate::linux_signal::Pending {
            signal: signal as u8,
            code,
            value,
            sender_pid,
            sender_uid,
        },
        signal >= 32,
    ) {
        Ok(_) => 0,
        Err(crate::linux_signal::Error::NoMemory) => LINUX_EAGAIN,
        Err(crate::linux_signal::Error::Invalid) => LINUX_EINVAL,
    }
}

pub(super) fn linux_signal_instance() -> usize {
    current_container_slot().unwrap_or(control_abi::DOMAIN_LIMIT)
}

pub(super) fn linux_signal_sender() -> (u32, u32) {
    (
        current_linux_process_pid(),
        current_linux_credentials().map_or(0, |credentials| credentials.user.real),
    )
}

pub(super) fn linux_thread_signal_queue_slot(process: usize, thread: usize) -> usize {
    process * crate::linux_signal::THREAD_LIMIT + thread
}

pub(super) fn clear_linux_signal_queues_for_process(instance: usize, process: usize) -> bool {
    crate::linux_signal::clear(instance, crate::linux_signal::Scope::Process, process).is_ok()
        && (0..crate::linux_signal::THREAD_LIMIT).all(|thread| {
            crate::linux_signal::clear(
                instance,
                crate::linux_signal::Scope::Thread,
                linux_thread_signal_queue_slot(process, thread),
            )
            .is_ok()
        })
}

pub(super) fn clear_current_linux_process_signal_queues() -> bool {
    linux_process::live_process_slot(current_linux_process_pid()).is_some_and(|process| {
        clear_linux_signal_queues_for_process(linux_signal_instance(), process)
    })
}

pub(super) fn linux_dynamic_pending_masks() -> Option<(u64, u64)> {
    let instance = linux_signal_instance();
    let process = linux_process::live_process_slot(current_linux_process_pid())?;
    let thread = current_linux_thread_slot()?;
    Some((
        crate::linux_signal::pending_mask(instance, crate::linux_signal::Scope::Process, process)
            .ok()?,
        crate::linux_signal::pending_mask(
            instance,
            crate::linux_signal::Scope::Thread,
            linux_thread_signal_queue_slot(process, thread),
        )
        .ok()?,
    ))
}

/// Whether a signal is queued that the current thread may have to take: one
/// sent to the thread itself or to its process. A signal queued for another
/// process of the domain is that process's to take, not this thread's (a
/// heartbeat for LTP's parent, held blocked inside its fork, once sent every
/// light-path call of the busy child to the owner for the whole test).
pub(super) fn linux_current_signals_queued() -> bool {
    let instance = linux_signal_instance();
    if !crate::linux_signal::any_pending(instance) {
        return false;
    }
    // Without a process slot or thread to name, assume a signal is there:
    // the owner's path sorts it out.
    let Some(process) = linux_process::live_process_slot(current_linux_process_pid()) else {
        return true;
    };
    let Some(thread) = current_linux_thread_slot() else {
        return true;
    };
    crate::linux_signal::queued(
        instance,
        crate::linux_signal::Scope::Thread,
        linux_thread_signal_queue_slot(process, thread),
    ) || crate::linux_signal::queued(instance, crate::linux_signal::Scope::Process, process)
}

pub(super) fn linux_peek_dynamic_signal(
    requested: u64,
) -> Option<(crate::linux_signal::Scope, crate::linux_signal::Pending)> {
    let instance = linux_signal_instance();
    let process = linux_process::live_process_slot(current_linux_process_pid())?;
    let thread = current_linux_thread_slot()?;
    if let Some(pending) = crate::linux_signal::peek(
        instance,
        crate::linux_signal::Scope::Thread,
        linux_thread_signal_queue_slot(process, thread),
        requested,
    )
    .ok()?
    {
        return Some((crate::linux_signal::Scope::Thread, pending));
    }
    crate::linux_signal::peek(
        instance,
        crate::linux_signal::Scope::Process,
        process,
        requested,
    )
    .ok()?
    .map(|pending| (crate::linux_signal::Scope::Process, pending))
}

pub(super) fn linux_dequeue_dynamic_signal(
    scope: crate::linux_signal::Scope,
    requested: u64,
) -> Option<crate::linux_signal::Pending> {
    let instance = linux_signal_instance();
    let slot = match scope {
        crate::linux_signal::Scope::Process => {
            linux_process::live_process_slot(current_linux_process_pid())?
        }
        crate::linux_signal::Scope::Thread => linux_thread_signal_queue_slot(
            linux_process::live_process_slot(current_linux_process_pid())?,
            current_linux_thread_slot()?,
        ),
    };
    crate::linux_signal::dequeue(instance, scope, slot, requested)
        .ok()
        .flatten()
}

pub(super) fn linux_rt_sigtimedwait(
    set: u64,
    information: u64,
    timeout: u64,
    set_size: u64,
) -> u64 {
    if set_size != LINUX_SIGNAL_SET_SIZE {
        return LINUX_EINVAL;
    }
    let mut set_bytes = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    if !copy_from_linux_user(set, &mut set_bytes) {
        return LINUX_EFAULT;
    }
    let requested = u64::from_ne_bytes(set_bytes) & !LINUX_UNBLOCKABLE_SIGNALS;
    let polls = if timeout == 0 {
        false
    } else {
        let mut timeout_bytes = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut timeout_bytes) {
            return LINUX_EFAULT;
        }
        let seconds = i64::from_ne_bytes(timeout_bytes[..8].try_into().unwrap());
        let nanoseconds = i64::from_ne_bytes(timeout_bytes[8..].try_into().unwrap());
        if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
            return LINUX_EINVAL;
        }
        seconds == 0 && nanoseconds == 0
    };
    linux_take_requested_signal(requested, information).unwrap_or(if polls {
        LINUX_EAGAIN
    } else {
        LINUX_ENOSYS
    })
}

/// Takes a pending signal of `requested` as sigtimedwait does, writing its
/// information to `information` (if nonzero): the signal's number, or an
/// error; None with none pending.
fn linux_take_requested_signal(requested: u64, information: u64) -> Option<u64> {
    let dynamic = linux_dynamic_pending_masks().map_or(0, |(process, thread)| process | thread);
    let matching =
        (X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) | dynamic) & requested;
    if matching == 0 {
        return None;
    }
    if information != 0
        && !linux_writable_user_range_contains(information, size_of::<LinuxSignalInformation>())
    {
        return Some(LINUX_EFAULT);
    }
    let dynamic_candidate = linux_peek_dynamic_signal(requested);
    let legacy_signal = u64::from(matching.trailing_zeros()) + 1;
    let use_dynamic = dynamic_candidate.is_some_and(|(scope, pending)| {
        scope == crate::linux_signal::Scope::Thread || u64::from(pending.signal) <= legacy_signal
    });
    let dynamic_signal = use_dynamic.then_some(dynamic_candidate).flatten();
    let signal =
        dynamic_signal.map_or_else(|| legacy_signal, |(_, pending)| u64::from(pending.signal));
    let index = signal as usize - 1;
    let signal_bit = 1 << (signal - 1);
    let (sender_pid, sender_uid) = dynamic_signal
        .map_or_else(linux_signal_sender, |(_, pending)| {
            (pending.sender_pid, pending.sender_uid)
        });
    let code = dynamic_signal.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].load(Ordering::SeqCst) as i32,
        |(_, pending)| pending.code,
    );
    let value = dynamic_signal.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].load(Ordering::SeqCst),
        |(_, pending)| pending.value,
    );
    let signal_information =
        LinuxSignalInformation::queued_from(signal, code, value, sender_pid, sender_uid);
    if information != 0 {
        // SAFETY: every byte in this repr(C) value is initialized, including
        // padding and the complete signal-specific payload.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(&signal_information).cast::<u8>(),
                size_of::<LinuxSignalInformation>(),
            )
        };
        if !copy_to_linux_user(information, bytes) {
            return Some(LINUX_EFAULT);
        }
    }
    if let Some((scope, _)) = dynamic_signal {
        let _ = linux_dequeue_dynamic_signal(scope, signal_bit);
    } else {
        X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .fetch_and(!signal_bit, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
    }
    linux_note_timer_signal_delivery(signal, code, value);
    Some(signal)
}

/// A POSIX timer's signal taken by the process: its timer's overrun is
/// frozen for timer_getoverrun.
fn linux_note_timer_signal_delivery(signal: u64, code: i32, value: u64) {
    if code == LINUX_SI_TIMER {
        linux_process::note_posix_timer_delivery(current_linux_process_pid(), signal as u8, value);
    }
}

pub(super) fn linux_rt_sigtimedwait_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    set: u64,
    information: u64,
    timeout: u64,
    set_size: u64,
) -> u64 {
    let immediate = linux_rt_sigtimedwait(set, information, timeout, set_size);
    if immediate != LINUX_ENOSYS {
        return immediate;
    }
    let deadline = if timeout == 0 {
        0
    } else {
        let mut timeout_bytes = [0_u8; 16];
        if !copy_from_linux_user(timeout, &mut timeout_bytes) {
            return LINUX_EFAULT;
        }
        let Some(duration) = linux_timespec_nanoseconds(&timeout_bytes).filter(|value| *value != 0)
        else {
            return LINUX_EINVAL;
        };
        let Some(deadline) = linux_elapsed_nanoseconds().and_then(|now| now.checked_add(duration))
        else {
            return LINUX_EINVAL;
        };
        deadline
    };
    let mut set_bytes = [0_u8; LINUX_SIGNAL_SET_SIZE as usize];
    if !copy_from_linux_user(set, &mut set_bytes) {
        return LINUX_EFAULT;
    }
    let requested = u64::from_ne_bytes(set_bytes) & !LINUX_UNBLOCKABLE_SIGNALS;
    if information != 0
        && !linux_writable_user_range_contains(information, size_of::<LinuxSignalInformation>())
    {
        return LINUX_EFAULT;
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    if X86_RUNTIME.ELF_PROBE_SYSTEM_INIT.load(Ordering::SeqCst)
        && current_linux_process_pid() == 1
        && current_linux_tid() == Some(1)
        && requested == 1 << (LINUX_SIGTERM - 1)
        && timeout == 0
        && information != 0
        && X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst) & requested == requested
    {
        if X86_RUNTIME
            .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
            .load(Ordering::SeqCst)
            != 0
            || !refresh_linux_process_registry_for_wait(caller)
            || !save_linux_thread_return_context(current, caller)
            || !block_current_linux_thread(LINUX_THREAD_WAIT_SIGNAL, requested, information, 0)
        {
            return LINUX_EINVAL;
        }
        X86_RUNTIME
            .LINUX_SIGNAL_WAIT_BLOCK_COUNT
            .fetch_add(1, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_SYSTEM_SUPERVISOR_WAIT_COUNT
            .fetch_add(1, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    }
    let target = 'target: {
        if let Some(target) = ready_linux_thread_handle() {
            break 'target target;
        }
        // A lone thread waits in the call as pause does: other processes
        // run until a requested signal is pending (taken here, handler or
        // not, as Linux's sigtimedwait takes it before delivery), another
        // signal interrupts the call (EINTR), or the deadline passes
        // (EAGAIN). A yield that restarts the call keeps its deadline. A
        // sibling thread made ready meanwhile takes over below.
        let deadline =
            take_linux_restart_deadline(caller.rip).or((deadline != 0).then_some(deadline));
        // The requested signals are blocked meanwhile so the wait, not a
        // handler, takes one that arrives; a handler for another signal
        // restores the mask from before.
        let slot = usize::from(current.slot);
        let prior = begin_linux_lone_masked_wait(
            slot,
            LINUX_THREAD_WAIT_SIGNAL,
            current_linux_signal_mask() | requested,
        );
        let ended = loop {
            if let Some(result) = linux_take_requested_signal(requested, information) {
                break Ok(result);
            }
            if deadline.is_some_and(|deadline| {
                linux_elapsed_nanoseconds().is_some_and(|now| now >= deadline)
            }) {
                break Ok(LINUX_EAGAIN);
            }
            let turn = linux_timed_wait_run_others(
                output,
                caller,
                LINUX_RT_SIGTIMEDWAIT_SYSCALL,
                deadline,
            );
            if let LinuxWaitTurn::Done(result) = turn {
                break Ok(result);
            }
            if let Some(target) = ready_linux_thread_handle() {
                break Err(target);
            }
            if let Some((deadline, now)) = deadline.zip(linux_elapsed_nanoseconds()) {
                timer::request_linux_tick_within(deadline.saturating_sub(now));
            }
            if let LinuxWaitTurn::Idle = turn {
                linux_wait_for_interrupt();
            }
        };
        end_linux_lone_masked_wait(slot, prior);
        match ended {
            Ok(result) => return result,
            Err(target) => break 'target target,
        }
    };
    if requested == 0 {
        return LINUX_ENOSYS;
    }
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(LINUX_THREAD_WAIT_SIGNAL, requested, information, deadline)
    {
        return LINUX_EINVAL;
    }
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
        .LINUX_SIGNAL_WAIT_BLOCK_COUNT
        .fetch_add(1, Ordering::SeqCst);
    LINUX_RETURN_FROM_IRET
}

pub(super) fn wake_linux_signal_wait(
    signal: u64,
    signal_code: i32,
    signal_value: Option<u64>,
) -> bool {
    wake_linux_signal_wait_target(None, signal, signal_code, signal_value, None)
}

pub(super) fn wake_linux_signal_wait_target(
    target: Option<LinuxThreadHandle>,
    signal: u64,
    signal_code: i32,
    signal_value: Option<u64>,
    sender: Option<(u32, u32)>,
) -> bool {
    let signal_bit = 1_u64 << (signal - 1);
    for slot in 0..LINUX_THREAD_LIMIT {
        if target.is_some_and(|target| usize::from(target.slot) != slot) {
            continue;
        }
        if X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
            || X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
                != LINUX_THREAD_WAIT_SIGNAL
            || X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst) & signal_bit == 0
        {
            continue;
        }
        let information = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
        if information != 0 {
            let value = sender.map_or_else(
                || LinuxSignalInformation::queued(signal, signal_code, signal_value.unwrap_or(0)),
                |(pid, uid)| {
                    LinuxSignalInformation::queued_from(
                        signal,
                        signal_code,
                        signal_value.unwrap_or(0),
                        pid,
                        uid,
                    )
                },
            );
            // SAFETY: LinuxSignalInformation is repr(C), and every byte of
            // this generated value, including padding, is initialized.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    core::ptr::from_ref(&value).cast::<u8>(),
                    size_of::<LinuxSignalInformation>(),
                )
            };
            if !copy_to_linux_user(information, bytes) {
                return false;
            }
        }
        X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(signal, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_SIGNAL_WAIT_WAKE_COUNT
            .fetch_add(1, Ordering::SeqCst);
        return true;
    }
    false
}

/// How long until the earliest deadline a blocked thread of this process
/// waits for, if any thread has one.
pub(crate) fn linux_nanoseconds_to_next_wait_deadline() -> Option<u64> {
    if !X86_RUNTIME.LINUX_TIMED_WAITS_ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let deadline = (0..LINUX_THREAD_LIMIT)
        .filter(|slot| {
            X86_RUNTIME.LINUX_THREAD_STATES[*slot].load(Ordering::Acquire) == LINUX_THREAD_BLOCKED
        })
        .map(|slot| X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::Acquire))
        .filter(|deadline| *deadline != 0)
        .min()?;
    Some(deadline.saturating_sub(linux_elapsed_nanoseconds()?))
}

pub(super) fn expire_linux_waits() -> u32 {
    if !X86_RUNTIME.LINUX_TIMED_WAITS_ACTIVE.load(Ordering::Acquire) {
        return 0;
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return 0;
    };
    let mut expired = 0;
    // Of `expired`, the timerfd reads the timer made readable: a read that
    // returns the expirations, which the descriptor wakes complete too.
    let mut timerfd_reads = 0;
    for slot in 0..LINUX_THREAD_LIMIT {
        let deadline = X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst);
        if deadline == 0
            || now < deadline
            || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        {
            continue;
        }
        if matches!(
            X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst),
            LINUX_THREAD_WAIT_POLL | LINUX_THREAD_WAIT_PPOLL
        ) {
            if complete_linux_poll_wait(slot, true) {
                expired += 1;
            }
            continue;
        }
        if matches!(
            X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst),
            LINUX_THREAD_WAIT_EPOLL | LINUX_THREAD_WAIT_EPOLL_PWAIT
        ) {
            if complete_linux_epoll_wait(slot, true) {
                expired += 1;
            }
            continue;
        }
        if matches!(
            X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst),
            LINUX_THREAD_WAIT_SELECT | LINUX_THREAD_WAIT_PSELECT
        ) {
            if complete_linux_select_wait(slot, true) {
                expired += 1;
            }
            continue;
        }
        if X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst)
            == LINUX_THREAD_WAIT_TIMERFD_READ
        {
            if complete_linux_timerfd_read_wait(slot) {
                expired += 1;
                timerfd_reads += 1;
            }
            continue;
        }
        let (result, counter) =
            match X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst) {
                LINUX_THREAD_WAIT_FUTEX => {
                    (LINUX_ETIMEDOUT, &X86_RUNTIME.LINUX_FUTEX_WAIT_TIMEOUT_COUNT)
                }
                LINUX_THREAD_WAIT_SIGNAL => {
                    (LINUX_EAGAIN, &X86_RUNTIME.LINUX_SIGNAL_WAIT_TIMEOUT_COUNT)
                }
                LINUX_THREAD_WAIT_SLEEP => (0, &X86_RUNTIME.LINUX_SLEEP_WAKE_COUNT),
                // The rewound call is issued again: rax is its number.
                LINUX_THREAD_WAIT_RETRY => (
                    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst),
                    &X86_RUNTIME.LINUX_SLEEP_WAKE_COUNT,
                ),
                _ => continue,
            };
        X86_RUNTIME.LINUX_THREAD_RAXS[slot].store(result, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
        counter.fetch_add(1, Ordering::SeqCst);
        expired += 1;
    }
    let active = (0..LINUX_THREAD_LIMIT).any(|slot| {
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst) != 0
            && X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) == LINUX_THREAD_BLOCKED
    });
    X86_RUNTIME
        .LINUX_TIMED_WAITS_ACTIVE
        .store(active, Ordering::Release);
    // Waits that timed out count whichever path ended them (the tick, a
    // system call's entry, a parked call waking), and a timerfd read does
    // not: the descriptor wakes, which the tick runs first, complete it as
    // a read, and this only when the clock passed the timer's deadline
    // between their look and this one. A vCPU the host held up there made
    // the boot verification count 9 expiries for 8 (an intermittent `make
    // test` failure).
    X86_RUNTIME
        .LINUX_TIMER_WAIT_EXPIRY_COUNT
        .fetch_add(expired - timerfd_reads, Ordering::SeqCst);
    expired
}

pub(super) fn save_linux_interrupt_context(
    handle: LinuxThreadHandle,
    context: UserFaultContext,
    fs_base: u64,
) -> bool {
    let saved = LinuxUserContext {
        registers: LinuxSyscallFrame {
            r15: context.r15,
            r14: context.r14,
            r13: context.r13,
            r12: context.r12,
            rbp: context.rbp,
            rbx: context.rbx,
            r10: context.r10,
            r9: context.r9,
            r8: context.r8,
            rdx: context.rdx,
            rsi: context.rsi,
            rdi: context.rdi,
        },
        rip: context.rip,
        rsp: context.rsp,
        rflags: context.rflags,
        rax: context.rax,
        fs_base,
    };
    if !save_linux_thread_return_context(handle, saved) {
        return false;
    }
    let slot = usize::from(handle.slot);
    X86_RUNTIME.LINUX_THREAD_RCXS[slot].store(context.rcx, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_R11S[slot].store(context.r11, Ordering::SeqCst);
    true
}

pub(super) fn linux_interrupt_context(handle: LinuxThreadHandle) -> Option<UserFaultContext> {
    let slot = usize::from(handle.slot);
    let saved = linux_thread_return_context(handle)?;
    Some(UserFaultContext {
        r15: saved.registers.r15,
        r14: saved.registers.r14,
        r13: saved.registers.r13,
        r12: saved.registers.r12,
        r11: X86_RUNTIME.LINUX_THREAD_R11S[slot].load(Ordering::SeqCst),
        r10: saved.registers.r10,
        r9: saved.registers.r9,
        r8: saved.registers.r8,
        rbp: saved.registers.rbp,
        rdi: saved.registers.rdi,
        rsi: saved.registers.rsi,
        rdx: saved.registers.rdx,
        rcx: X86_RUNTIME.LINUX_THREAD_RCXS[slot].load(Ordering::SeqCst),
        rbx: saved.registers.rbx,
        rax: saved.rax,
        rip: saved.rip,
        rflags: saved.rflags,
        rsp: saved.rsp,
    })
}

/// Records where the runtime CPU was for a SysRq `l` profile.
pub(crate) fn sample_linux_profile(frame: &UserInterruptFrame) {
    let (instruction, code_selector) = frame.interrupted_at();
    crate::linux_profile::sample(
        current_linux_process_pid(),
        code_selector != u64::from(USER_CODE_SELECTOR),
        instruction,
    );
}

pub(crate) fn expire_linux_waits_from_timer(frame: &mut UserInterruptFrame) {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && !X86_RUNTIME
            .LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN
            .load(Ordering::SeqCst)
        && linux_elapsed_nanoseconds().is_some_and(|elapsed| elapsed >= 60_000_000_000)
        && !X86_RUNTIME
            .LINUX_RUNTIME_STALLED_DIAGNOSTIC_WRITTEN
            .swap(true, Ordering::SeqCst)
    {
        serial_write("ginux: Linux runtime exceeded sixty seconds; execution snapshot:");
        serial_write(" pid=");
        serial_write_u64(u64::from(current_linux_process_pid()));
        serial_write(" tid=");
        serial_write_u64(current_linux_tid().map_or(0, u64::from));
        serial_write(" rip=");
        serial_write_u64(
            frame
                .user_context(USER_CODE_SELECTOR, USER_DATA_SELECTOR)
                .map_or(0, |context| context.rip),
        );
        serial_write(" rsp=");
        serial_write_u64(
            frame
                .user_context(USER_CODE_SELECTOR, USER_DATA_SELECTOR)
                .map_or(0, |context| context.rsp),
        );
        serial_write(" syscalls=");
        serial_write_u64(
            X86_RUNTIME
                .LINUX_RUNTIME_SYSCALL_TRACE_COUNT
                .load(Ordering::SeqCst),
        );
        serial_write(" epoll-fd/events=");
        serial_write_u64(
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_DESCRIPTOR
                .load(Ordering::SeqCst),
        );
        serial_write("/");
        serial_write_u64(
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_EVENTS
                .load(Ordering::SeqCst),
        );
        serial_write(" (");
        serial_write(linux_descriptor_kind_name(
            X86_RUNTIME
                .LINUX_EPOLL_LAST_READY_DESCRIPTOR
                .load(Ordering::SeqCst),
        ));
        serial_write(") name=");
        let mut name = [0_u8; 16];
        name[..8].copy_from_slice(
            &X86_RUNTIME
                .ELF_PROBE_PROCESS_NAME_LOW
                .load(Ordering::SeqCst)
                .to_ne_bytes(),
        );
        name[8..].copy_from_slice(
            &X86_RUNTIME
                .ELF_PROBE_PROCESS_NAME_HIGH
                .load(Ordering::SeqCst)
                .to_ne_bytes(),
        );
        let length = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        crate::serial_write_bytes(&name[..length]);
        serial_write("\r\n");
        for slot in 0..LINUX_THREAD_LIMIT {
            let state = X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::Acquire);
            if state == LINUX_THREAD_FREE {
                continue;
            }
            serial_write("ginux: Linux stalled thread slot/tid/state/wait/remote: ");
            serial_write_u64(slot as u64);
            serial_write("/");
            serial_write_u64(u64::from(
                X86_RUNTIME.LINUX_THREAD_TIDS[slot].load(Ordering::Acquire),
            ));
            serial_write("/");
            serial_write_u64(u64::from(state));
            serial_write("/");
            serial_write_u64(u64::from(
                X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::Acquire),
            ));
            serial_write("/");
            serial_write_u64(u64::from(linux_thread_runs_elsewhere(slot)));
            serial_write("\r\n");
        }
        write_linux_runtime_syscall_trace();
        linux_write_stall_diagnostic();
    }
    let descriptor_wakes = wake_linux_descriptor_waits();
    let expired = expire_linux_waits();
    // Detached domains keep the CPU until the operator has input. Polling at
    // 200 Hz bounds console latency without serializing an idle runtime on
    // every timer interrupt.
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        && active_container_slot().is_some_and(|slot| {
            matches!(
                container_state(slot),
                control_abi::DOMAIN_STATE_BOOTING | control_abi::DOMAIN_STATE_RUNNING
            ) && !X86_RUNTIME.CONTAINER_CONSOLE_ATTACHED[slot].load(Ordering::Acquire)
        })
        && X86_RUNTIME
            .LINUX_RUNTIME_BACKGROUND_TICKS
            .fetch_add(1, Ordering::AcqRel)
            + 1
            >= 5
    {
        X86_RUNTIME
            .LINUX_RUNTIME_BACKGROUND_TICKS
            .store(0, Ordering::Release);
        // Other detached domains get a turn about every 100 ms.
        let turn_over = active_container_slot().is_some_and(other_background_work_waiting)
            && X86_RUNTIME
                .LINUX_RUNTIME_BACKGROUND_QUANTA
                .fetch_add(1, Ordering::AcqRel)
                + 1
                >= 20;
        if turn_over {
            X86_RUNTIME
                .LINUX_RUNTIME_BACKGROUND_QUANTA
                .store(0, Ordering::Release);
        }
        if crate::serial_input_ready() || turn_over {
            X86_RUNTIME
                .LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED
                .store(true, Ordering::Release);
        }
    }
    // A Linux runtime thread can wait in a userspace spin lock without making
    // another syscall. Give a runnable sibling a bounded time slice so such a
    // lock cannot deadlock merely because the current thread never yields.
    let runtime_quantum = if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) {
        let ticks = X86_RUNTIME
            .LINUX_RUNTIME_PREEMPT_TICKS
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if ticks >= 10 {
            X86_RUNTIME
                .LINUX_RUNTIME_PREEMPT_TICKS
                .store(0, Ordering::SeqCst);
            ready_linux_thread_handle().is_some()
        } else {
            false
        }
    } else {
        false
    };
    if descriptor_wakes == 0 && expired == 0 && !runtime_quantum {
        // No thread of this process to switch to: other processes may need
        // the CPU instead.
        linux_preempt_process_from_timer(frame);
        return;
    }
    let Some(interrupted) = frame.user_context(USER_CODE_SELECTOR, USER_DATA_SELECTOR) else {
        return;
    };
    // A thread the timer just sent to the preemption entry (an interrupt
    // was pending as it got there) stays: its real context is the one the
    // entry's call takes on this CPU, and resumed elsewhere at the entry it
    // would find none.
    if crate::linux_elf::vdso_preempt_entry()
        .is_some_and(|entry| (entry..entry + 9).contains(&interrupted.rip))
    {
        return;
    }
    if let (Some(current), Some(target)) =
        (current_linux_thread_handle(), ready_linux_thread_handle())
    {
        let Some(target_context) = linux_interrupt_context(target) else {
            return;
        };
        let mut restored = *frame;
        if !restored.restore_user_context(target_context, USER_CODE_SELECTOR, USER_DATA_SELECTOR)
            || !save_linux_interrupt_context(current, interrupted, active_fs_base())
            || !switch_linux_thread(target)
        {
            return;
        }
        *frame = restored;
        X86_RUNTIME
            .LINUX_LAST_PREEMPTED_THREAD_SLOT
            .store(current.slot, Ordering::Release);
        X86_RUNTIME
            .LINUX_TIMER_WAIT_PREEMPTION_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
}

pub(super) fn linux_executable_user_address(address: u64) -> bool {
    address_space::current_linux_address_executable(address)
}

/// The restorer a handler returns through: its own when that is code the
/// process can run, else the vDSO's rt_sigreturn trampoline. Linux would
/// fail the frame without SA_RESTORER; LTP's raw rt_sigaction under musl
/// passes a restorer read back from libc's sigaction, which musl leaves
/// unset (rt_sigaction01, rt_sigprocmask01, rt_sigsuspend01).
pub(super) fn linux_effective_signal_restorer(restorer: u64) -> u64 {
    if linux_executable_user_address(restorer) {
        restorer
    } else {
        crate::linux_elf::vdso_sigreturn_entry().unwrap_or(restorer)
    }
}

pub(super) fn linux_signal_action_deliverable(handler: u64, flags: u64, restorer: u64) -> bool {
    // A blocking call interrupted for an SA_RESTART handler restarts after
    // it (linux_deliver_pending_signal_restarting). SA_NOCLDSTOP and
    // SA_NOCLDWAIT only concern stopped and exiting children, which need no
    // handler change.
    let supported = LINUX_SA_SIGINFO
        | LINUX_SA_RESTORER
        | LINUX_SA_RESTART
        | LINUX_SA_ONSTACK
        | LINUX_SA_NODEFER
        | LINUX_SA_RESETHAND
        | LINUX_SA_NOCLDSTOP
        | LINUX_SA_NOCLDWAIT;
    handler > 1
        && flags & !supported == 0
        && linux_executable_user_address(handler)
        && linux_executable_user_address(restorer)
}

pub(super) fn linux_signal_stack(stack_top: u64, use_alt_stack: bool) -> Option<u64> {
    let frame_top = if use_alt_stack {
        stack_top
    } else {
        stack_top.checked_sub(LINUX_SIGNAL_RED_ZONE_SIZE)?
    };
    let signal_stack = frame_top
        .checked_sub(LINUX_SIGNAL_FRAME_SIZE as u64)?
        .checked_div(16)?
        .checked_mul(16)?
        .checked_sub(8)?;
    if use_alt_stack
        && signal_stack
            < X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .load(Ordering::SeqCst)
    {
        None
    } else {
        Some(signal_stack)
    }
}

pub(super) fn linux_rt_signal_frame(
    context: LinuxSignalContext,
    flags: u64,
    information: LinuxSignalInformation,
    trap: u64,
    error: u64,
    cr2: u64,
) -> LinuxRtSignalFrame {
    let registers = context.registers;
    let alt_stack_flags = context.alt_stack_flags;
    let alt_stack_disabled = alt_stack_flags == LINUX_SS_DISABLE;
    LinuxRtSignalFrame {
        restorer: context.signal_restorer,
        context: LinuxSignalUserContext {
            flags: LINUX_UC_SIGCONTEXT_SS | LINUX_UC_STRICT_RESTORE_SS,
            link: 0,
            stack: LinuxSignalStack {
                pointer: if alt_stack_disabled {
                    0
                } else {
                    context.alt_stack_pointer
                },
                flags: alt_stack_flags,
                padding: 0,
                size: if alt_stack_disabled {
                    0
                } else {
                    context.alt_stack_size
                },
            },
            machine: LinuxSignalMachineContext {
                r8: registers.r8,
                r9: registers.r9,
                r10: registers.r10,
                r11: context.r11,
                r12: registers.r12,
                r13: registers.r13,
                r14: registers.r14,
                r15: registers.r15,
                rdi: registers.rdi,
                rsi: registers.rsi,
                rbp: registers.rbp,
                rbx: registers.rbx,
                rdx: registers.rdx,
                rax: context.rax,
                rcx: context.rcx,
                rsp: context.rsp,
                rip: context.rip,
                rflags: context.rflags,
                cs: USER_CODE_SELECTOR,
                gs: 0,
                fs: 0,
                ss: USER_DATA_SELECTOR,
                error,
                trap,
                old_mask: context.signal_mask,
                cr2,
                fpstate: 0,
                reserved: [0; 8],
            },
            signal_mask: context.signal_mask,
        },
        information: if flags & LINUX_SA_SIGINFO != 0 {
            information
        } else {
            LinuxSignalInformation::ZERO
        },
    }
}

pub(super) fn copy_linux_signal_frame(address: u64, frame: &LinuxRtSignalFrame) -> bool {
    // SAFETY: every field, including ABI padding and reserved bytes, is
    // initialized above and the resulting byte view is used only for copy-out.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            core::ptr::from_ref(frame).cast::<u8>(),
            size_of::<LinuxRtSignalFrame>(),
        )
    };
    copy_to_linux_user(address, bytes)
}

pub(super) fn copy_linux_signal_frame_from_user(
    address: u64,
    frame: &mut LinuxRtSignalFrame,
) -> bool {
    // SAFETY: the destination is a fully initialized, repr(C) frame and the
    // mutable byte view spans exactly that object for bounded copy-in.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::from_mut(frame).cast::<u8>(),
            size_of::<LinuxRtSignalFrame>(),
        )
    };
    copy_from_linux_user(address, bytes)
}

pub(super) fn linux_restored_signal_context(
    saved: LinuxSignalContext,
    returned: &LinuxRtSignalFrame,
) -> Option<LinuxRestoredSignalContext> {
    let expected = linux_rt_signal_frame(saved, 0, LinuxSignalInformation::ZERO, 0, 0, 0);
    let context = &returned.context;
    let machine = &context.machine;
    if returned.restorer != saved.signal_restorer
        || context.flags != LINUX_UC_SIGCONTEXT_SS | LINUX_UC_STRICT_RESTORE_SS
        || context.link != 0
        || context.stack != expected.context.stack
        || machine.cs != USER_CODE_SELECTOR
        || machine.gs != 0
        || machine.fs != 0
        || machine.ss != USER_DATA_SELECTOR
        || machine.fpstate != 0
        || machine.reserved != [0; 8]
    {
        return None;
    }
    let restored = LinuxUserContext {
        registers: LinuxSyscallFrame {
            r15: machine.r15,
            r14: machine.r14,
            r13: machine.r13,
            r12: machine.r12,
            rbp: machine.rbp,
            rbx: machine.rbx,
            r10: machine.r10,
            r9: machine.r9,
            r8: machine.r8,
            rdx: machine.rdx,
            rsi: machine.rsi,
            rdi: machine.rdi,
        },
        rip: machine.rip,
        rsp: machine.rsp,
        rflags: (saved.rflags & !LINUX_SIGNAL_RESTORABLE_RFLAGS)
            | (machine.rflags & LINUX_SIGNAL_RESTORABLE_RFLAGS),
        rax: machine.rax,
        fs_base: active_fs_base(),
    };
    restored.is_valid().then_some(LinuxRestoredSignalContext {
        user: restored,
        signal_mask: context.signal_mask & !LINUX_UNBLOCKABLE_SIGNALS,
        rcx: machine.rcx,
        r11: machine.r11,
    })
}

pub(super) fn linux_apply_delivered_signal_action(
    index: usize,
    signal_bit: u64,
    old_mask: u64,
    flags: u64,
) {
    let action_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[index].load(Ordering::SeqCst);
    let automatic_mask = if flags & LINUX_SA_NODEFER == 0 {
        signal_bit
    } else {
        0
    };
    store_current_linux_signal_mask(old_mask | action_mask | automatic_mask);
    // SA_RESETHAND puts back the default action only: the flags,
    // restorer and mask stay, as sigaction then reports them (sigaction01).
    if flags & LINUX_SA_RESETHAND != 0 {
        X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].store(0, Ordering::SeqCst);
    }
}

pub(super) fn linux_default_signal_terminates(signal: u64) -> bool {
    matches!(signal, 1..=16 | 24..=27 | 29..=64)
}

pub(super) fn linux_default_signal_ignored(signal: u64) -> bool {
    matches!(signal, LINUX_SIGCHLD | 18 | 23 | 28)
}

/// SIGSTOP, SIGTSTP, SIGTTIN and SIGTTOU stop the process by default.
pub(super) fn linux_default_signal_stops(signal: u64) -> bool {
    matches!(signal, 19..=22)
}

/// Stops the current process with stop signal `signal` (no handler): its
/// parent is told (SIGCHLD, a wait with WUNTRACED) and the process leaves
/// the CPU with `resume` as its context, which the scheduler, dispatching
/// running processes only, resumes once SIGCONT continues it. ENOSYS where
/// it cannot leave the CPU so: init, a thread on the light path, or a call
/// with no frame to return through.
fn linux_stop_current(
    signal: u64,
    output: *mut LinuxSyscallFrame,
    resume: LinuxUserContext,
) -> u64 {
    let pid = current_linux_process_pid();
    if pid == 1 || output.is_null() || linux_light_thread_here().is_some() {
        return LINUX_ENOSYS;
    }
    if linux_process::live_process_status(pid)
        .is_none_or(|status| status.state == linux_process::LiveProcessState::Stopped)
    {
        // Stopped already, or gone: nothing more to do.
        return 0;
    }
    // The context is recorded while the process still counts as running
    // (the registry refresh refuses a stopped one); then it stops.
    if !yield_current_linux_process(resume, resume.rax) {
        return LINUX_ENOSYS;
    }
    if linux_process::stop_live_process(pid, signal as u8, false) {
        if let Some(parent) = linux_process::live_process_parent_pid(pid) {
            let _ =
                linux_queue_process_signal(parent, LINUX_SIGCHLD, LINUX_CLD_STOPPED, Some(signal));
        }
    }
    LINUX_RETURN_TO_KERNEL
}

pub(super) fn verify_linux_default_signal_dispositions() -> bool {
    (1..=LINUX_SIGNAL_COUNT as u64).all(|signal| {
        let terminates = matches!(signal, 1..=16 | 24..=27 | 29..=64);
        let ignored = matches!(signal, 17 | 18 | 23 | 28);
        linux_default_signal_terminates(signal) == terminates
            && linux_default_signal_ignored(signal) == ignored
            && !(linux_default_signal_terminates(signal) && linux_default_signal_ignored(signal))
    })
}

pub(super) fn linux_terminate_by_default_signal(signal: u64) -> u64 {
    linux_terminate_by_signal(signal, true)
}

/// Ends the current process by `signal`, writing a core file for a
/// core-dumping one when `may_dump` (not from a CPU fault's handler, which
/// does not write files).
fn linux_terminate_by_signal(signal: u64, may_dump: bool) -> u64 {
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) && current_linux_process_pid() != 1 {
        let pid = current_linux_process_pid();
        if !clear_current_linux_process_signal_queues() {
            return LINUX_EIO;
        }
        // The signals whose default action dumps core do, when RLIMIT_CORE
        // allows; bit 7 of the recorded signal says one was written.
        let dumps_core = matches!(signal, 3..=8 | 11 | 24 | 25 | 31);
        let dumped = dumps_core && may_dump && linux_write_core_file(signal);
        let _ = linux_process::set_live_process_killed_by_signal(
            pid,
            signal.min(127) as u8 | if dumped { 0x80 } else { 0 },
        );
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_STATUS
            .store((128 + signal.min(127)) as u8, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXIT_PID
            .store(pid, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_PROCESS_CHILD_EXITED
            .store(true, Ordering::SeqCst);
        return LINUX_RETURN_TO_KERNEL;
    }
    if !record_live_linux_process_snapshot() {
        return LINUX_ESRCH;
    }
    if !linux_close_all_descriptors() {
        return LINUX_EIO;
    }
    if !crate::linux_socket::shutdown()
        || !linux_tmpfs::teardown()
        || !crate::linux_overlay::teardown()
    {
        return LINUX_EIO;
    }
    if !clear_current_linux_process_signal_queues() {
        return LINUX_EIO;
    }
    retire_all_linux_threads();
    X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_EXEC_IGNORED_SIGNALS
        .store(0, Ordering::SeqCst);
    for index in 0..LINUX_SIGNAL_COUNT {
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[index].store(0, Ordering::SeqCst);
        X86_RUNTIME.ELF_PROBE_SIGNAL_ACTION_MASKS[index].store(0, Ordering::SeqCst);
    }
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_POINTER
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_SIZE
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_FLAGS
        .store(LINUX_SS_DISABLE, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_TERMINATION_SIGNAL
        .store(signal as u32, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_COMPLETED
        .store(true, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_ACTIVE.store(false, Ordering::SeqCst);
    LINUX_RETURN_TO_KERNEL
}

pub(super) fn linux_signal_targets(selector: i32) -> Result<(Vec<u32>, usize), u64> {
    let current = current_linux_process_pid();
    let group = match selector {
        0 => linux_process::live_process_group(current),
        value if value < -1 => Some(value.unsigned_abs()),
        _ => None,
    };
    let mut targets = Vec::new();
    for slot in 0..linux_process::live_process_slots() {
        let Some(pid) = linux_process::live_process_pid_at(slot) else {
            continue;
        };
        let selected = match selector {
            value if value > 0 => pid == value as u32,
            0 => group.is_some_and(|group| linux_process::live_process_group(pid) == Some(group)),
            -1 => pid != 1,
            _ => group.is_some_and(|group| linux_process::live_process_group(pid) == Some(group)),
        };
        if selected {
            targets.try_reserve(1).map_err(|_| LINUX_ENOMEM)?;
            targets.push(pid);
        }
    }
    // A thread id names its process, as Linux's find_vpid does: here, one
    // of the caller's own threads.
    if targets.is_empty()
        && selector > 0
        && linux_tgkill_target(u64::from(current), selector as u64).is_ok()
    {
        targets.try_reserve(1).map_err(|_| LINUX_ENOMEM)?;
        targets.push(current);
    }
    let count = targets.len();
    (count != 0).then_some((targets, count)).ok_or(LINUX_ESRCH)
}

pub(super) fn linux_signal_permitted(target: u32, signal: u64) -> bool {
    if target == current_linux_process_pid() {
        return true;
    }
    // A Landlock domain that scopes signals reaches only its own and the
    // domains nested in it (LANDLOCK_SCOPE_SIGNAL).
    if !linux_landlock_may_signal(target) {
        return false;
    }
    if signal == LINUX_SIGCONT
        && linux_process::live_process_session(target)
            == linux_process::live_process_session(current_linux_process_pid())
    {
        return true;
    }
    let Some(caller_namespace) = current_linux_user_namespace() else {
        return false;
    };
    let Some(target_namespace) = linux_process::live_process_user_namespace(target) else {
        return false;
    };
    if !linux_user::may_signal(caller_namespace, target_namespace) {
        return false;
    }
    let (Some(caller), Some(target)) = (
        current_linux_credentials(),
        linux_process::live_process_credentials(target),
    ) else {
        return false;
    };
    caller.may_signal(&target)
}

/// Whether `parent` has its exiting children reaped at once, leaving no
/// zombie: SIGCHLD set to SIG_IGN, or SA_NOCLDWAIT, as in Linux (a wait
/// then blocks until no child is left and fails with ECHILD).
pub(super) fn linux_parent_reaps_automatically(parent: u32) -> bool {
    let index = LINUX_SIGCHLD as usize - 1;
    let (handler, flags) = if parent == current_linux_process_pid() {
        (
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].load(Ordering::SeqCst),
        )
    } else {
        linux_process_runtime_state(parent)
            .filter(|state| state.valid)
            .map_or((0, 0), |state| {
                (state.signal_handlers[index], state.signal_flags[index])
            })
    };
    handler == 1 || flags & LINUX_SA_NOCLDWAIT != 0
}

/// Reaps the calling process's exited children when it ignores SIGCHLD
/// (`linux_parent_reaps_automatically`): Linux keeps no zombie for such a
/// parent, so a kill(pid, 0) of the child finds nothing (ESRCH) and a wait
/// sees no child. Done as the parent calls kill or wait, when the child has
/// long been settled, not while it is still being torn down.
pub(super) fn linux_reap_ignored_children() {
    let parent = current_linux_process_pid();
    if !linux_parent_reaps_automatically(parent) {
        return;
    }
    // Only the children that ended while it did; a zombie from before it
    // ignored SIGCHLD is waited for as any other (fanotify03).
    while let Some(pid) = linux_process::live_child_reaped_by_parent(parent) {
        if linux_reap_child(parent, pid).is_none() {
            break;
        }
    }
}

pub(super) fn linux_target_signal_ignored(target: u32, signal: u64) -> bool {
    // A traced process gets every signal: its tracer sees it at the stop.
    if linux_process::live_process_tracer(target).is_some() {
        return false;
    }
    let index = signal as usize - 1;
    let (handler, mask) = if target == current_linux_process_pid() {
        (
            X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst),
            X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst),
        )
    } else {
        linux_process_runtime_state(target)
            .filter(|state| state.valid)
            .map_or((0, 0), |state| {
                let mask = linux_process_thread_runtime_state(target)
                    .and_then(|threads| threads.get(usize::from(state.current_thread_slot)))
                    .map_or(0, |thread| thread.signal_mask);
                (state.signal_handlers[index], mask)
            })
    };
    // A blocked signal is never discarded as ignored (rt_sigtimedwait01).
    mask & (1 << index) == 0
        && (handler == 1
            || handler == 0 && signal != LINUX_SIGCHLD && linux_default_signal_ignored(signal))
}

pub(super) fn linux_queue_process_signal(
    target: u32,
    signal: u64,
    signal_code: i32,
    signal_value: Option<u64>,
) -> u64 {
    linux_queue_process_signal_from(
        target,
        signal,
        signal_code,
        signal_value,
        linux_signal_sender(),
    )
}

/// `linux_queue_process_signal` with the information's sender fields
/// given: the pid and uid of a kill, or the first two words of another
/// layout (a SIGIO's si_band).
pub(super) fn linux_queue_process_signal_from(
    target: u32,
    signal: u64,
    signal_code: i32,
    signal_value: Option<u64>,
    (sender_pid, sender_uid): (u32, u32),
) -> u64 {
    // SIGCONT discards the stop signals still pending for the process, as
    // Linux's prepare_signal does (a tracer's SIGSTOP queued at
    // PTRACE_ATTACH to a process already stopped would stop it again).
    if signal == LINUX_SIGCONT {
        const STOP_SIGNALS: u64 = 0xf << 18;
        if target == current_linux_process_pid() {
            X86_RUNTIME
                .ELF_PROBE_PENDING_SIGNALS
                .fetch_and(!STOP_SIGNALS, Ordering::SeqCst);
        }
        if let Some(process) = linux_process::live_process_slot(target) {
            while let Ok(Some(_)) = crate::linux_signal::dequeue(
                linux_signal_instance(),
                crate::linux_signal::Scope::Process,
                process,
                STOP_SIGNALS,
            ) {}
        }
    }
    // SIGCONT continues a stopped process as it is sent, whatever its
    // disposition (ignored by default); the parent's wait (WCONTINUED) is told.
    if signal == LINUX_SIGCONT && linux_process::continue_live_process(target) {
        if let Some(parent) = linux_process::live_process_parent_pid(target) {
            let _ = linux_queue_process_signal(
                parent,
                LINUX_SIGCHLD,
                LINUX_CLD_CONTINUED,
                Some(LINUX_SIGCONT),
            );
        }
    }
    if linux_target_signal_ignored(target, signal)
        || linux_process::live_process_status(target)
            .is_some_and(|status| status.state == linux_process::LiveProcessState::Zombie)
    {
        return 0;
    }
    let Some(process) = linux_process::live_process_slot(target) else {
        return LINUX_ESRCH;
    };
    match linux_enqueue_signal(
        linux_signal_instance(),
        crate::linux_signal::Scope::Process,
        process,
        crate::linux_signal::Pending {
            signal: signal as u8,
            code: signal_code,
            value: signal_value.unwrap_or(0),
            sender_pid,
            sender_uid,
        },
        signal >= 32,
    ) {
        Ok(_) => {
            // A signal the target does not block wakes it, as Linux's
            // signal_wake_up: /proc shows it running until it sleeps again
            // (shmctl01 waits for its children to sleep after SIGUSR1).
            if target != current_linux_process_pid()
                && linux_target_signal_mask(target) & (1 << (signal - 1)) == 0
            {
                linux_process::set_live_process_waiting(target, false);
            }
            0
        }
        Err(crate::linux_signal::Error::NoMemory) => LINUX_EAGAIN,
        Err(crate::linux_signal::Error::Invalid) => LINUX_EINVAL,
    }
}

/// The signal mask of process `target`'s current thread, as its saved
/// state has it (the caller's own live one for itself).
fn linux_target_signal_mask(target: u32) -> u64 {
    if target == current_linux_process_pid() {
        return X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    }
    linux_process_runtime_state(target)
        .filter(|state| state.valid)
        .and_then(|state| {
            linux_process_thread_runtime_state(target)
                .and_then(|threads| threads.get(usize::from(state.current_thread_slot)))
                .map(|thread| thread.signal_mask)
        })
        .unwrap_or(0)
}

pub(super) fn linux_kill(
    pid: u64,
    generated: (u64, i32, Option<u64>),
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    let (signal, signal_code, signal_value) = generated;
    let signal = u64::from(signal as u32);
    if !(1..=LINUX_SIGNAL_COUNT as u64).contains(&signal) && signal != 0 {
        return LINUX_EINVAL;
    }
    let (targets, count) = match linux_signal_targets(pid as u32 as i32) {
        Ok(targets) => targets,
        Err(error) => return error,
    };
    let mut permitted = false;
    let mut current = false;
    for target in targets[..count].iter().copied() {
        if !linux_signal_permitted(target, signal) {
            continue;
        }
        permitted = true;
        if signal == 0 {
            continue;
        }
        if target == current_linux_process_pid() {
            current = true;
            continue;
        }
        let result = linux_queue_process_signal(target, signal, signal_code, signal_value);
        if result != 0 {
            return result;
        }
    }
    if !permitted {
        return LINUX_EPERM;
    }
    if signal == 0 || !current {
        return 0;
    }
    // A stop signal the caller sends itself with no handler and unblocked
    // stops it in this call (kill(getpid(), SIGSTOP), waitid07).
    if linux_default_signal_stops(signal)
        && X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal as usize - 1].load(Ordering::SeqCst) == 0
        && current_linux_signal_mask() & (1 << (signal - 1)) == 0
        && linux_process::live_process_tracer(current_linux_process_pid()).is_none()
    {
        return linux_stop_in_call(signal, output, interrupted, false);
    }
    linux_kill_current(
        (signal, signal_code, signal_value),
        Some(linux_signal_sender()),
        output,
        interrupted,
        return_registers,
    )
}

/// Stops the current process in its kill call `caller`: its parent is told
/// (SIGCHLD with CLD_STOPPED, a wait with WUNTRACED) and the call waits as
/// pause does, other processes running, until SIGCONT continues it, when
/// it returns 0. Only SIGKILL and SIGCONT reach the process meanwhile; the
/// rest wait for its mask to come back. ENOSYS for a thread on the light
/// path, and for init unless traced (a traced init stops for its tracer as
/// in Linux, the rest of the domain running meanwhile).
fn linux_stop_in_call(
    signal: u64,
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    traced: bool,
) -> u64 {
    /// si_code of a tracee's stop, as its tracer's SIGCHLD reports it.
    const LINUX_CLD_TRAPPED: i32 = 4;
    let pid = current_linux_process_pid();
    if pid == 1 && !traced
        || output.is_null()
        || linux_light_thread_here().is_some()
        || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
    {
        return LINUX_ENOSYS;
    }
    if linux_process::stop_live_process(pid, signal as u8, true) {
        // A tracee's stop is its tracer's to see; a stop signal's, its
        // parent's.
        let (told, code) = if traced {
            (linux_process::live_process_tracer(pid), LINUX_CLD_TRAPPED)
        } else {
            (
                linux_process::live_process_parent_pid(pid),
                LINUX_CLD_STOPPED,
            )
        };
        if let Some(told) = told {
            let _ = linux_queue_process_signal(told, LINUX_SIGCHLD, code, Some(signal));
        }
    } else if !linux_process::live_process_stopped(pid) {
        return 0;
    }
    let slot = current_linux_thread_slot();
    let prior = slot.map(|slot| {
        begin_linux_lone_masked_wait(
            slot,
            LINUX_THREAD_WAIT_STOPPED,
            !(1 << (LINUX_SIGKILL - 1) | 1 << (LINUX_SIGCONT - 1)),
        )
    });
    let result = loop {
        if !linux_process::live_process_stopped(pid) {
            break 0;
        }
        match run_other_linux_processes_deferring(output, caller, LINUX_KILL_SYSCALL, false) {
            Some(LinuxBlockedWait::Return(result)) => break result,
            Some(LinuxBlockedWait::Recheck) => {}
            None => linux_wait_for_interrupt(),
        }
    };
    if let (Some(slot), Some(prior)) = (slot, prior) {
        end_linux_lone_masked_wait(slot, prior);
    }
    result
}

/// ptrace(2), in a domain set `privileged=true`: PTRACE_TRACEME and
/// PTRACE_ATTACH make a tracer, which then sees each signal its tracee
/// gets as a stop (`linux_kill_current`) and resumes it with PTRACE_CONT
/// (delivering the signal it names, or none), PTRACE_DETACH or
/// PTRACE_KILL. PTRACE_PEEKUSER and PTRACE_POKEUSER reach the debug
/// registers in `struct user` (`linux_debug_registers`); the tracee's
/// memory and general registers are not implemented yet (EIO).
pub(super) fn linux_ptrace(request: u64, pid: u64, address: u64, data: u64) -> u64 {
    const TRACEME: u64 = 0;
    const PEEKUSER: u64 = 3;
    const POKEUSER: u64 = 6;
    const CONT: u64 = 7;
    const KILL: u64 = 8;
    const ATTACH: u64 = 16;
    const DETACH: u64 = 17;
    const SEIZE: u64 = 0x4206;
    const GETREGSET: u64 = 0x4204;
    const SETREGSET: u64 = 0x4205;
    let caller = current_linux_process_pid();
    let request = u64::from(request as u32);
    if request == TRACEME {
        if linux_process::live_process_tracer(caller).is_some() {
            return LINUX_EPERM;
        }
        let Some(parent) = linux_process::live_process_parent_pid(caller).filter(|p| *p != 0)
        else {
            return LINUX_EPERM;
        };
        return if linux_process::set_live_process_tracer(caller, parent) {
            0
        } else {
            LINUX_ESRCH
        };
    }
    let pid = pid as u32;
    let Some(status) = linux_process::live_process_status(pid) else {
        return LINUX_ESRCH;
    };
    if matches!(request, ATTACH | SEIZE) {
        // Only another process, not traced yet, that the caller may signal
        // (the same user, or CAP_SYS_PTRACE); init only with the
        // capability.
        if pid == caller || linux_process::live_process_tracer(pid).is_some() {
            return LINUX_EPERM;
        }
        let may_trace = super::current_linux_credentials().is_some_and(|credentials| {
            credentials.has(ginux_credentials::capability::SYS_PTRACE)
                || pid != 1
                    && linux_process::live_process_credentials(pid)
                        .is_some_and(|target| target.user.real == credentials.user.real)
        });
        if !may_trace || status.state == linux_process::LiveProcessState::Zombie {
            return LINUX_EPERM;
        }
        if !linux_process::set_live_process_tracer(pid, caller) {
            return LINUX_ESRCH;
        }
        if request == ATTACH {
            const SIGSTOP: u64 = 19;
            let _ = linux_queue_process_signal(pid, SIGSTOP, LINUX_SI_USER, None);
        }
        return 0;
    }
    // The rest need a tracee of the caller's that is stopped.
    if linux_process::live_process_tracer(pid) != Some(caller)
        || request != KILL && status.state != linux_process::LiveProcessState::Stopped
    {
        return LINUX_ESRCH;
    }
    match request {
        CONT | DETACH => {
            if data > LINUX_SIGNAL_COUNT as u64 {
                return LINUX_EIO;
            }
            if request == DETACH {
                let _ = linux_process::set_live_process_tracer(pid, 0);
            } else {
                let _ = linux_process::set_live_process_ptrace_resume_signal(pid, data as u8);
            }
            let _ = linux_process::continue_live_process(pid);
            linux_process::set_live_process_waiting(pid, false);
            0
        }
        KILL => {
            let _ = linux_queue_process_signal(pid, LINUX_SIGKILL, LINUX_SI_USER, None);
            let _ = linux_process::continue_live_process(pid);
            linux_process::set_live_process_waiting(pid, false);
            0
        }
        GETREGSET | SETREGSET => linux_ptrace_regset(pid, request == SETREGSET, address, data),
        PEEKUSER | POKEUSER => {
            /// `struct user`: the end of its general registers, where
            /// `u_debugreg[8]` starts, and its size.
            const GENERAL_REGISTERS_END: u64 = 216;
            const DEBUG_REGISTERS: u64 = 848;
            const USER_SIZE: u64 = 912;
            // The general registers are not reachable yet.
            if !address.is_multiple_of(8)
                || !(GENERAL_REGISTERS_END..USER_SIZE).contains(&address)
                || request == POKEUSER && address < DEBUG_REGISTERS
            {
                return LINUX_EIO;
            }
            let index = (address.saturating_sub(DEBUG_REGISTERS) / 8) as usize;
            if request == POKEUSER {
                return match linux_process::set_live_process_debug_register(pid, index, data) {
                    Some(Ok(())) => 0,
                    Some(Err(crate::linux_debug_registers::Error::Invalid)) => LINUX_EINVAL,
                    Some(Err(crate::linux_debug_registers::Error::NoRegister)) => LINUX_EIO,
                    None => LINUX_ESRCH,
                };
            }
            // The rest of the user area reads as 0, as in Linux.
            let value = if address >= DEBUG_REGISTERS {
                let Some(value) = linux_process::live_process_debug_register(pid, index) else {
                    return LINUX_ESRCH;
                };
                value
            } else {
                0
            };
            if copy_to_linux_user(data, &value.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        _ => LINUX_EIO,
    }
}

/// PTRACE_GETREGSET and PTRACE_SETREGSET (`set`) of regset `kind` of the
/// stopped tracee `pid`, through the struct iovec at `iovec`: only
/// NT_X86_XSTATE so far, its main thread's x87, SSE and AVX state in
/// XSAVE's standard format with the software-reserved bytes Linux fills
/// in. A write needs the whole area with a header naming only enabled
/// features in the standard format (EINVAL otherwise, as Linux's
/// validate_user_xstate_header has it).
fn linux_ptrace_regset(pid: u32, set: bool, kind: u64, iovec: u64) -> u64 {
    const NT_X86_XSTATE: u64 = 0x202;
    const SOFTWARE_RESERVED: usize = 464;
    const HEADER: usize = 512;
    const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
    const FP_XSTATE_MAGIC2_SIZE: u32 = 4;
    const FEATURES: u64 = 7;
    if kind != NT_X86_XSTATE {
        return LINUX_EINVAL;
    }
    let mut vector = [0_u8; 16];
    if !copy_from_linux_user(iovec, &mut vector) {
        return LINUX_EFAULT;
    }
    let base = u64::from_ne_bytes(vector[..8].try_into().unwrap());
    let length = u64::from_ne_bytes(vector[8..].try_into().unwrap());
    let size = linux_xstate_size();
    let Some(mut state) = linux_thread_xstate(pid, 0) else {
        return LINUX_ENODEV;
    };
    if set {
        if length != size as u64 {
            return LINUX_EFAULT;
        }
        let mut given = [0_u8; EXTENDED_STATE_SIZE];
        if !copy_from_linux_user(base, &mut given[..size]) {
            return LINUX_EFAULT;
        }
        let word = |at: usize| u64::from_le_bytes(given[at..at + 8].try_into().unwrap());
        let mxcsr = u32::from_le_bytes(given[24..28].try_into().unwrap());
        if word(HEADER) & !FEATURES != 0
            || word(HEADER + 8) != 0
            || given[HEADER + 16..HEADER + 64]
                .iter()
                .any(|byte| *byte != 0)
            || mxcsr & !0xffff != 0
        {
            return LINUX_EINVAL;
        }
        return if set_linux_thread_xstate(pid, 0, &given[..size]) {
            0
        } else {
            LINUX_ESRCH
        };
    }
    let bytes = &mut state.0;
    bytes[SOFTWARE_RESERVED..SOFTWARE_RESERVED + 4]
        .copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    bytes[SOFTWARE_RESERVED + 4..SOFTWARE_RESERVED + 8]
        .copy_from_slice(&(size as u32 + FP_XSTATE_MAGIC2_SIZE).to_le_bytes());
    bytes[SOFTWARE_RESERVED + 8..SOFTWARE_RESERVED + 16].copy_from_slice(&FEATURES.to_le_bytes());
    bytes[SOFTWARE_RESERVED + 16..SOFTWARE_RESERVED + 20]
        .copy_from_slice(&(size as u32).to_le_bytes());
    let copied = (length as usize).min(size);
    if !copy_to_linux_user(base, &bytes[..copied])
        || !copy_to_linux_user(iovec + 8, &(copied as u64).to_ne_bytes())
    {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_kill_current(
    generated: (u64, i32, Option<u64>),
    sender: Option<(u32, u32)>,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    let (signal, signal_code, signal_value) = generated;
    let index = signal as usize - 1;
    let signal_bit = 1 << (signal - 1);
    if wake_linux_signal_wait_target(None, signal, signal_code, signal_value, sender) {
        return 0;
    }
    // A traced process stops for each signal it does not block but
    // SIGKILL, for its tracer to see, instead of acting on it.
    let pid = current_linux_process_pid();
    if signal != LINUX_SIGKILL
        && X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst) & signal_bit == 0
        && linux_process::live_process_tracer(pid).is_some()
        && !linux_process::take_live_process_ptrace_bypass(pid)
    {
        let result = linux_stop_in_call(signal, output, interrupted, true);
        let resume = linux_process::take_live_process_ptrace_resume_signal(pid);
        if result != 0 || resume == 0 {
            return result;
        }
        // The signal the tracer let through is delivered now, past the stop.
        linux_process::set_live_process_ptrace_bypass(pid, true);
        return linux_kill_current(
            (u64::from(resume), LINUX_SI_USER, None),
            sender,
            output,
            interrupted,
            return_registers,
        );
    }
    let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst);
    let old_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    // A blocked signal is never discarded as ignored: the disposition may
    // change before it is unblocked, and sigtimedwait takes it.
    if (handler == 1 || handler == 0 && linux_default_signal_ignored(signal))
        && old_mask & signal_bit == 0
    {
        return 0;
    }
    if old_mask & signal_bit != 0 {
        if signal >= 32 {
            let Some(process) = linux_process::live_process_slot(current_linux_process_pid())
            else {
                return LINUX_ESRCH;
            };
            let (sender_pid, sender_uid) = linux_signal_sender();
            return match linux_enqueue_signal(
                linux_signal_instance(),
                crate::linux_signal::Scope::Process,
                process,
                crate::linux_signal::Pending {
                    signal: signal as u8,
                    code: signal_code,
                    value: signal_value.unwrap_or(0),
                    sender_pid,
                    sender_uid,
                },
                true,
            ) {
                Ok(_) => 0,
                Err(crate::linux_signal::Error::NoMemory) => LINUX_EAGAIN,
                Err(crate::linux_signal::Error::Invalid) => LINUX_EINVAL,
            };
        }
        if X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) & signal_bit == 0 {
            X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index]
                .store(signal_code as u32, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index]
                .store(signal_value.unwrap_or(0), Ordering::SeqCst);
        }
        X86_RUNTIME
            .ELF_PROBE_PENDING_SIGNALS
            .fetch_or(signal_bit, Ordering::SeqCst);
        return 0;
    }
    if handler == 0 {
        return if linux_default_signal_terminates(signal)
            && !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
        {
            linux_terminate_by_default_signal(signal)
        } else if linux_default_signal_stops(signal) {
            linux_stop_current(signal, output, interrupted)
        } else {
            LINUX_ENOSYS
        };
    }
    if output.is_null()
        || current_linux_thread_handle().is_none()
        || X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
    {
        return LINUX_ENOSYS;
    }
    let flags = X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].load(Ordering::SeqCst);
    let restorer = linux_effective_signal_restorer(
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[index].load(Ordering::SeqCst),
    );
    if !linux_signal_action_deliverable(handler, flags, restorer) {
        // A handler whose frame cannot be made (no executable restorer: LTP
        // under musl reads one back from a libc sigaction, which musl does
        // not fill in) kills the process with SIGSEGV, as Linux's
        // force_sigsegv does, instead of leaving the signal pending for
        // every tick to retry (rt_sigsuspend01 ended in SIGILL at the
        // preemption entry's ud2 that way).
        return linux_terminate_by_default_signal(LINUX_SIGSEGV);
    }
    let old_alt_stack_flags = X86_RUNTIME.ELF_PROBE_ALT_STACK_FLAGS.load(Ordering::SeqCst);
    let use_alt_stack = flags & LINUX_SA_ONSTACK != 0
        && old_alt_stack_flags & (LINUX_SS_DISABLE | LINUX_SS_ONSTACK) == 0;
    let stack_top = if use_alt_stack {
        let pointer = X86_RUNTIME
            .ELF_PROBE_ALT_STACK_POINTER
            .load(Ordering::SeqCst);
        let size = X86_RUNTIME.ELF_PROBE_ALT_STACK_SIZE.load(Ordering::SeqCst);
        let Some(top) = pointer.checked_add(size) else {
            return LINUX_EFAULT;
        };
        top
    } else {
        interrupted.rsp
    };
    let Some(signal_stack) = linux_signal_stack(stack_top, use_alt_stack) else {
        return LINUX_EFAULT;
    };
    // A lone thread waiting under a temporary mask (sigtimedwait,
    // sigsuspend) has the handler's frame restore the mask from before.
    let context = LinuxSignalContext::from_syscall(
        interrupted,
        return_registers,
        (signal_stack, restorer),
        linux_lone_wait_prior_mask().unwrap_or(old_mask),
        old_alt_stack_flags,
    );
    if !context.user_context().is_valid() {
        return LINUX_EINVAL;
    }
    let information = sender.map_or_else(
        || LinuxSignalInformation::queued(signal, signal_code, signal_value.unwrap_or(0)),
        |(pid, uid)| {
            LinuxSignalInformation::queued_from(
                signal,
                signal_code,
                signal_value.unwrap_or(0),
                pid,
                uid,
            )
        },
    );
    let signal_frame = linux_rt_signal_frame(context, flags, information, 0, 0, 0);
    if !copy_linux_signal_frame(signal_stack, &signal_frame) {
        return LINUX_EFAULT;
    }
    let mut handler_registers = interrupted.registers;
    handler_registers.rdi = signal;
    handler_registers.rsi = signal_stack + LINUX_SIGNAL_FRAME_INFO_OFFSET;
    handler_registers.rdx = signal_stack + LINUX_SIGNAL_FRAME_CONTEXT_OFFSET;
    let handler_context = LinuxUserContext {
        registers: handler_registers,
        rip: handler,
        rsp: signal_stack,
        rflags: interrupted.rflags & !((1 << 8) | (1 << 10) | (1 << 16)),
        rax: 0,
        fs_base: active_fs_base(),
    };
    if !handler_context.is_valid() || !write_linux_live_return(output, handler_context) {
        return LINUX_EINVAL;
    }
    // SAFETY: syscall entry is serialized with interrupts disabled until its
    // return context enters the handler.
    unsafe { linux_signal_context().get().write(context) };
    linux_apply_delivered_signal_action(index, signal_bit, old_mask, flags);
    if use_alt_stack {
        if old_alt_stack_flags & LINUX_SS_AUTODISARM != 0 {
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_SIZE
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .store(LINUX_SS_DISABLE, Ordering::SeqCst);
        } else {
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .store(LINUX_SS_ONSTACK, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(true, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_DELIVERY_COUNT
        .fetch_add(1, Ordering::SeqCst);
    0
}

pub(super) fn linux_interrupt_blocked_wait(
    target: LinuxThreadHandle,
    generated: (u64, i32),
    output: *mut LinuxSyscallFrame,
    sender_return: LinuxUserContext,
) -> u64 {
    linux_deliver_signal_to_blocked_wait(
        target,
        generated,
        output,
        sender_return,
        LINUX_EINTR,
        false,
    )
}

pub(super) fn linux_deliver_signal_to_blocked_wait(
    target: LinuxThreadHandle,
    generated: (u64, i32),
    output: *mut LinuxSyscallFrame,
    sender_return: LinuxUserContext,
    interrupted_result: u64,
    completed: bool,
) -> u64 {
    let (signal, signal_code) = generated;
    if signal == 0 {
        return 0;
    }
    if !(1..=LINUX_SIGNAL_COUNT as u64).contains(&signal) {
        return LINUX_EINVAL;
    }
    let Some(sender) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let Some(sender_tls) = linux_thread_context(sender) else {
        return LINUX_ESRCH;
    };
    let saved_sender = linux_thread_return_context(sender);
    let slot = usize::from(target.slot);
    let wait_kind = X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].load(Ordering::SeqCst);
    if sender == target
        || X86_RUNTIME.LINUX_THREAD_STATES[slot].load(Ordering::SeqCst) != LINUX_THREAD_BLOCKED
        || !matches!(
            wait_kind,
            LINUX_THREAD_WAIT_FUTEX
                | LINUX_THREAD_WAIT_SIGNAL
                | LINUX_THREAD_WAIT_SLEEP
                | LINUX_THREAD_WAIT_POLL
                | LINUX_THREAD_WAIT_EPOLL
                | LINUX_THREAD_WAIT_EVENTFD_READ
                | LINUX_THREAD_WAIT_PIPE_READ
                | LINUX_THREAD_WAIT_TIMERFD_READ
                | LINUX_THREAD_WAIT_PIPE_WRITE
                | LINUX_THREAD_WAIT_EVENTFD_WRITE
                | LINUX_THREAD_WAIT_PAUSE
                | LINUX_THREAD_WAIT_SIGSUSPEND
                | LINUX_THREAD_WAIT_PPOLL
                | LINUX_THREAD_WAIT_EPOLL_PWAIT
                | LINUX_THREAD_WAIT_SELECT
                | LINUX_THREAD_WAIT_PSELECT
        )
        || output.is_null()
        || X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
    {
        return LINUX_ENOSYS;
    }
    let index = signal as usize - 1;
    let signal_bit = 1 << (signal - 1);
    let wait_mask = X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst);
    if wait_mask & signal_bit != 0
        || wait_kind == LINUX_THREAD_WAIT_SIGNAL
            && X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].load(Ordering::SeqCst) & signal_bit != 0
    {
        return LINUX_ENOSYS;
    }
    let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst);
    if handler == 1 {
        return 0;
    }
    let flags = X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].load(Ordering::SeqCst);
    let restorer = linux_effective_signal_restorer(
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[index].load(Ordering::SeqCst),
    );
    if handler == 0 || !linux_signal_action_deliverable(handler, flags, restorer) {
        return LINUX_ENOSYS;
    }
    let Some(mut interrupted) = linux_thread_return_context(target) else {
        return LINUX_ESRCH;
    };
    let saved_interrupted = interrupted;
    interrupted.rax = interrupted_result;
    let masked_wait = matches!(
        wait_kind,
        LINUX_THREAD_WAIT_PPOLL
            | LINUX_THREAD_WAIT_EPOLL_PWAIT
            | LINUX_THREAD_WAIT_SIGSUSPEND
            | LINUX_THREAD_WAIT_PSELECT
    );
    let restored_mask = if masked_wait {
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].load(Ordering::SeqCst)
    } else {
        wait_mask
    };
    let old_alt_stack_flags = X86_RUNTIME.ELF_PROBE_ALT_STACK_FLAGS.load(Ordering::SeqCst);
    let use_alt_stack = flags & LINUX_SA_ONSTACK != 0
        && old_alt_stack_flags & (LINUX_SS_DISABLE | LINUX_SS_ONSTACK) == 0;
    let stack_top = if use_alt_stack {
        let pointer = X86_RUNTIME
            .ELF_PROBE_ALT_STACK_POINTER
            .load(Ordering::SeqCst);
        let size = X86_RUNTIME.ELF_PROBE_ALT_STACK_SIZE.load(Ordering::SeqCst);
        let Some(top) = pointer.checked_add(size) else {
            return LINUX_EFAULT;
        };
        top
    } else {
        interrupted.rsp
    };
    let Some(signal_stack) = linux_signal_stack(stack_top, use_alt_stack) else {
        return LINUX_EFAULT;
    };
    let target_stack_valid = if use_alt_stack {
        linux_writable_user_range_contains(signal_stack, LINUX_SIGNAL_FRAME_SIZE)
    } else {
        linux_range_contains(
            X86_RUNTIME.LINUX_THREAD_STACK_BASES[slot].load(Ordering::SeqCst),
            X86_RUNTIME.LINUX_THREAD_STACK_SIZES[slot].load(Ordering::SeqCst),
            signal_stack,
            LINUX_SIGNAL_FRAME_SIZE,
        )
    };
    if !target_stack_valid {
        return LINUX_EFAULT;
    }
    let context = LinuxSignalContext::from_syscall(
        interrupted,
        (
            X86_RUNTIME.LINUX_THREAD_RCXS[slot].load(Ordering::SeqCst),
            X86_RUNTIME.LINUX_THREAD_R11S[slot].load(Ordering::SeqCst),
        ),
        (signal_stack, restorer),
        restored_mask,
        old_alt_stack_flags,
    );
    let signal_frame = linux_rt_signal_frame(
        context,
        flags,
        LinuxSignalInformation::generated(signal, signal_code),
        0,
        0,
        0,
    );
    let mut handler_registers = interrupted.registers;
    handler_registers.rdi = signal;
    handler_registers.rsi = signal_stack + LINUX_SIGNAL_FRAME_INFO_OFFSET;
    handler_registers.rdx = signal_stack + LINUX_SIGNAL_FRAME_CONTEXT_OFFSET;
    let handler_context = LinuxUserContext {
        registers: handler_registers,
        rip: handler,
        rsp: signal_stack,
        rflags: interrupted.rflags & !((1 << 8) | (1 << 10) | (1 << 16)),
        rax: 0,
        fs_base: interrupted.fs_base,
    };
    if !context.user_context().is_valid() || !handler_context.is_valid() {
        return LINUX_EINVAL;
    }
    let timeout_remaining = if wait_kind == LINUX_THREAD_WAIT_SLEEP {
        let address = X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].load(Ordering::SeqCst);
        if address == 0 {
            None
        } else {
            let Some(now) = linux_elapsed_nanoseconds() else {
                return LINUX_ENOSYS;
            };
            let deadline = X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst);
            let mut replaced = [0_u8; 16];
            if deadline == 0 || !copy_from_linux_user(address, &mut replaced) {
                return LINUX_EFAULT;
            }
            let mut remaining = [0_u8; 16];
            linux_store_timespec(&mut remaining, deadline.saturating_sub(now));
            Some((address, replaced, remaining))
        }
    } else if wait_kind == LINUX_THREAD_WAIT_SELECT {
        let address = linux_select_timeout_address(slot);
        if address == 0 {
            None
        } else {
            let Some(now) = linux_elapsed_nanoseconds() else {
                return LINUX_ENOSYS;
            };
            let deadline = X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].load(Ordering::SeqCst);
            let mut replaced = [0_u8; 16];
            if deadline == 0 || !copy_from_linux_user(address, &mut replaced) {
                return LINUX_EFAULT;
            }
            let remaining_nanoseconds = deadline.saturating_sub(now);
            let mut remaining = [0_u8; 16];
            remaining[..8]
                .copy_from_slice(&(remaining_nanoseconds / NANOSECONDS_PER_SECOND).to_ne_bytes());
            remaining[8..].copy_from_slice(
                &(remaining_nanoseconds % NANOSECONDS_PER_SECOND / 1_000).to_ne_bytes(),
            );
            Some((address, replaced, remaining))
        }
    } else {
        None
    };
    let mut replaced = [0_u8; LINUX_SIGNAL_FRAME_SIZE];
    if !copy_from_linux_user(signal_stack, &mut replaced) {
        return LINUX_EFAULT;
    }
    if let Some((address, _, remaining)) = &timeout_remaining {
        if !copy_to_linux_user(*address, remaining) {
            return LINUX_EFAULT;
        }
    }
    if !copy_linux_signal_frame(signal_stack, &signal_frame) {
        let _ = copy_to_linux_user(signal_stack, &replaced);
        if let Some((address, original, _)) = &timeout_remaining {
            let _ = copy_to_linux_user(*address, original);
        }
        return LINUX_EFAULT;
    }
    if !save_linux_thread_return_context(sender, sender_return) {
        let _ = copy_to_linux_user(signal_stack, &replaced);
        if let Some((address, original, _)) = &timeout_remaining {
            let _ = copy_to_linux_user(*address, original);
        }
        return LINUX_EINVAL;
    }
    if !save_linux_thread_return_context(target, interrupted) {
        restore_linux_thread_return_context(sender, saved_sender);
        let _ = copy_to_linux_user(signal_stack, &replaced);
        if let Some((address, original, _)) = &timeout_remaining {
            let _ = copy_to_linux_user(*address, original);
        }
        return LINUX_EINVAL;
    }
    if !write_linux_live_return(output, handler_context) {
        let _ = save_linux_thread_return_context(target, saved_interrupted);
        restore_linux_thread_return_context(sender, saved_sender);
        let _ = copy_to_linux_user(signal_stack, &replaced);
        if let Some((address, original, _)) = &timeout_remaining {
            let _ = copy_to_linux_user(*address, original);
        }
        return LINUX_EINVAL;
    }
    X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(restored_mask, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_READY, Ordering::SeqCst);
    if !switch_linux_thread(target) {
        let _ = save_linux_thread_return_context(target, saved_interrupted);
        restore_linux_thread_return_context(sender, saved_sender);
        X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].store(wait_mask, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_BLOCKED, Ordering::SeqCst);
        let _ = install_linux_tls_context(sender_tls);
        let _ = write_linux_live_return(output, sender_return);
        let _ = copy_to_linux_user(signal_stack, &replaced);
        if let Some((address, original, _)) = &timeout_remaining {
            let _ = copy_to_linux_user(*address, original);
        }
        return LINUX_EINVAL;
    }
    X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
    X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
    if masked_wait {
        X86_RUNTIME.LINUX_THREAD_WAIT_PRIOR_SIGNAL_MASKS[slot].store(0, Ordering::SeqCst);
    }
    if matches!(wait_kind, LINUX_THREAD_WAIT_POLL | LINUX_THREAD_WAIT_PPOLL) {
        clear_linux_poll_snapshot(slot);
    }
    if matches!(
        wait_kind,
        LINUX_THREAD_WAIT_SELECT | LINUX_THREAD_WAIT_PSELECT
    ) {
        clear_linux_select_snapshot(slot);
    }
    if matches!(
        wait_kind,
        LINUX_THREAD_WAIT_PIPE_READ | LINUX_THREAD_WAIT_PIPE_WRITE
    ) {
        clear_linux_iov_snapshot(slot);
    }
    // SAFETY: the switch above made the target the sole running Linux thread,
    // and the live return already names its validated handler context.
    unsafe { linux_signal_context().get().write(context) };
    linux_apply_delivered_signal_action(index, signal_bit, restored_mask, flags);
    if use_alt_stack {
        if old_alt_stack_flags & LINUX_SS_AUTODISARM != 0 {
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_SIZE
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .store(LINUX_SS_DISABLE, Ordering::SeqCst);
        } else {
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .store(LINUX_SS_ONSTACK, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(true, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_DELIVERY_COUNT
        .fetch_add(1, Ordering::SeqCst);
    if completed && wait_kind == LINUX_THREAD_WAIT_PIPE_WRITE {
        X86_RUNTIME
            .LINUX_PIPE_WRITE_WAKE_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_SIGNAL {
        X86_RUNTIME
            .LINUX_SIGNAL_WAIT_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_SLEEP {
        X86_RUNTIME
            .LINUX_SLEEP_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_POLL {
        X86_RUNTIME
            .LINUX_POLL_WAIT_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_EPOLL {
        X86_RUNTIME
            .LINUX_EPOLL_WAIT_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_EVENTFD_READ {
        X86_RUNTIME
            .LINUX_EVENTFD_READ_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_PIPE_READ {
        X86_RUNTIME
            .LINUX_PIPE_READ_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_PIPE_WRITE {
        X86_RUNTIME
            .LINUX_PIPE_WRITE_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_EVENTFD_WRITE {
        X86_RUNTIME
            .LINUX_EVENTFD_WRITE_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else if wait_kind == LINUX_THREAD_WAIT_TIMERFD_READ {
        X86_RUNTIME
            .LINUX_TIMERFD_READ_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    } else {
        X86_RUNTIME
            .LINUX_MASKED_WAIT_INTERRUPT_COUNT
            .fetch_add(1, Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_tgkill_identity(
    thread_group: u64,
    thread: u64,
) -> Result<LinuxThreadHandle, u64> {
    let thread_group = thread_group as i32;
    let thread = thread as i32;
    if thread_group <= 0 || thread <= 0 {
        return Err(LINUX_EINVAL);
    }
    if thread_group as u32 != current_linux_process_pid() {
        return Err(LINUX_ESRCH);
    }
    linux_thread_handle_by_tid(thread as u64).ok_or(LINUX_ESRCH)
}

pub(super) fn linux_tkill_identity(thread: u64) -> Result<LinuxThreadHandle, u64> {
    let thread = thread as i32;
    if thread <= 0 {
        return Err(LINUX_EINVAL);
    }
    linux_thread_handle_by_tid(thread as u64).ok_or(LINUX_ESRCH)
}

pub(super) fn linux_saved_thread_target(pid: u32, tid: u32) -> Option<LinuxThreadSignalTarget> {
    if pid == current_linux_process_pid()
        || !linux_process::live_process_status(pid)?.state.is_running()
    {
        return None;
    }
    let process_slot = linux_process::live_process_slot(pid)?;
    let state = linux_process_runtime_state(pid)?;
    let thread_slot = state.valid.then(|| {
        linux_process_thread_runtime_state(pid)?
            .iter()
            .position(|thread| thread.tid == tid)
    })??;
    Some(LinuxThreadSignalTarget::Saved {
        pid,
        process_slot,
        thread_slot,
    })
}

pub(super) fn linux_tgkill_target(
    thread_group: u64,
    thread: u64,
) -> Result<LinuxThreadSignalTarget, u64> {
    let thread_group = thread_group as i32;
    let thread = thread as i32;
    if thread_group <= 0 || thread <= 0 {
        return Err(LINUX_EINVAL);
    }
    let pid = thread_group as u32;
    let tid = thread as u32;
    if pid == current_linux_process_pid() {
        return linux_thread_handle_by_tid(u64::from(tid))
            .map(LinuxThreadSignalTarget::Active)
            .ok_or(LINUX_ESRCH);
    }
    linux_saved_thread_target(pid, tid).ok_or(LINUX_ESRCH)
}

pub(super) fn linux_tkill_target(thread: u64) -> Result<LinuxThreadSignalTarget, u64> {
    let thread = thread as i32;
    if thread <= 0 {
        return Err(LINUX_EINVAL);
    }
    let tid = thread as u32;
    if let Some(target) = linux_thread_handle_by_tid(u64::from(tid)) {
        return Ok(LinuxThreadSignalTarget::Active(target));
    }
    (0..linux_process::live_process_slots())
        .filter_map(linux_process::live_process_pid_at)
        .find_map(|pid| linux_saved_thread_target(pid, tid))
        .ok_or(LINUX_ESRCH)
}

pub(super) fn linux_queue_saved_thread_signal(
    pid: u32,
    process_slot: usize,
    thread_slot: usize,
    signal: u64,
    code: i32,
    value: Option<u64>,
) -> u64 {
    if linux_target_signal_ignored(pid, signal) {
        return 0;
    }
    let (sender_pid, sender_uid) = linux_signal_sender();
    match linux_enqueue_signal(
        linux_signal_instance(),
        crate::linux_signal::Scope::Thread,
        linux_thread_signal_queue_slot(process_slot, thread_slot),
        crate::linux_signal::Pending {
            signal: signal as u8,
            code,
            value: value.unwrap_or(0),
            sender_pid,
            sender_uid,
        },
        signal >= 32,
    ) {
        Ok(_) => {
            // As a process-directed signal does (`linux_queue_process_signal`):
            // a process asleep in a futex wait is resumed to take it, not
            // left until the wait's deadline.
            if linux_target_signal_mask(pid) & (1 << (signal - 1)) == 0 {
                linux_process::set_live_process_waiting(pid, false);
            }
            0
        }
        Err(crate::linux_signal::Error::NoMemory) => LINUX_EAGAIN,
        Err(crate::linux_signal::Error::Invalid) => LINUX_EINVAL,
    }
}

pub(super) fn linux_send_resolved_thread_signal(
    target: LinuxThreadSignalTarget,
    signal: u64,
    code: i32,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    let signal = u64::from(signal as u32);
    if !(1..=LINUX_SIGNAL_COUNT as u64).contains(&signal) && signal != 0 {
        return LINUX_EINVAL;
    }
    match target {
        LinuxThreadSignalTarget::Active(target) => {
            linux_send_thread_signal(target, signal, code, output, interrupted, return_registers)
        }
        LinuxThreadSignalTarget::Saved {
            pid,
            process_slot,
            thread_slot,
        } => {
            if !linux_signal_permitted(pid, signal) {
                return LINUX_EPERM;
            }
            if signal == 0 {
                return 0;
            }
            linux_queue_saved_thread_signal(pid, process_slot, thread_slot, signal, code, None)
        }
    }
}

pub(super) fn linux_tgkill(
    thread_group: u64,
    thread: u64,
    signal: u64,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    let result = match linux_tgkill_target(thread_group, thread) {
        Ok(target) => linux_send_resolved_thread_signal(
            target,
            signal,
            LINUX_SI_TKILL,
            output,
            interrupted,
            return_registers,
        ),
        Err(error) => error,
    };
    if X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && thread_group as u32 != current_linux_process_pid()
        && result != 0
    {
        serial_write("ginux: cross-process tgkill rejected pid/tid/signal/error ");
        serial_write_u64(u64::from(thread_group as u32));
        serial_write(" ");
        serial_write_u64(u64::from(thread as u32));
        serial_write(" ");
        serial_write_u64(u64::from(signal as u32));
        serial_write(" ");
        serial_write_u64(result);
        serial_write("\r\n");
    }
    result
}

pub(super) fn linux_tkill(
    thread: u64,
    signal: u64,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    match linux_tkill_target(thread) {
        Ok(target) => linux_send_resolved_thread_signal(
            target,
            signal,
            LINUX_SI_TKILL,
            output,
            interrupted,
            return_registers,
        ),
        Err(error) => error,
    }
}

pub(super) fn linux_send_thread_signal(
    target: LinuxThreadHandle,
    signal: u64,
    code: i32,
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    let signal = u64::from(signal as u32);
    if signal == 0 {
        return 0;
    }
    if !(1..=LINUX_SIGNAL_COUNT as u64).contains(&signal) {
        return LINUX_EINVAL;
    }
    let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[signal as usize - 1].load(Ordering::SeqCst);
    if handler == 1 || handler == 0 && linux_default_signal_ignored(signal) {
        return 0;
    }
    let slot = usize::from(target.slot);
    let target_is_current = current_linux_thread_handle() == Some(target);
    if target_is_current
        && X86_RUNTIME.LINUX_THREAD_SIGNAL_MASKS[slot].load(Ordering::SeqCst) & (1 << (signal - 1))
            == 0
    {
        return linux_kill(
            u64::from(current_linux_process_pid()),
            (signal, code, None),
            output,
            interrupted,
            return_registers,
        );
    }
    if !target_is_current {
        if wake_linux_signal_wait_target(
            Some(target),
            signal,
            code,
            None,
            Some(linux_signal_sender()),
        ) {
            return 0;
        }
        let result = linux_interrupt_blocked_wait(target, (signal, code), output, interrupted);
        if result != LINUX_ENOSYS {
            return result;
        }
    }
    let Some(process) = linux_process::live_process_slot(current_linux_process_pid()) else {
        return LINUX_ESRCH;
    };
    let (sender_pid, sender_uid) = linux_signal_sender();
    match linux_enqueue_signal(
        linux_signal_instance(),
        crate::linux_signal::Scope::Thread,
        linux_thread_signal_queue_slot(process, slot),
        crate::linux_signal::Pending {
            signal: signal as u8,
            code,
            value: 0,
            sender_pid,
            sender_uid,
        },
        signal >= 32,
    ) {
        Ok(_) => 0,
        Err(crate::linux_signal::Error::NoMemory) => LINUX_EAGAIN,
        Err(crate::linux_signal::Error::Invalid) => LINUX_EINVAL,
    }
}

pub(super) fn linux_deliver_pending_signal(
    output: *mut LinuxSyscallFrame,
    interrupted: LinuxUserContext,
    return_registers: (u64, u64),
) -> u64 {
    linux_deliver_pending_signal_restarting(output, interrupted, return_registers, None)
}

/// System calls Linux restarts after a handler installed with SA_RESTART
/// (signal(7)). Others, such as poll, select, epoll_wait, nanosleep, semop
/// and timed futex waits, fail with EINTR whatever the handler's flags.
fn linux_syscall_restartable(number: u64) -> bool {
    matches!(
        number,
        LINUX_READ_SYSCALL
            | LINUX_READV_SYSCALL
            | LINUX_PREAD64_SYSCALL
            | LINUX_PREADV_SYSCALL
            | LINUX_WRITE_SYSCALL
            | LINUX_WRITEV_SYSCALL
            | LINUX_PWRITE64_SYSCALL
            | LINUX_PWRITEV_SYSCALL
            | LINUX_WAIT4_SYSCALL
            | LINUX_WAITID_SYSCALL
            | LINUX_IOCTL_SYSCALL
            | LINUX_OPEN_SYSCALL
            | LINUX_OPENAT_SYSCALL
            | LINUX_CONNECT_SYSCALL
            | LINUX_ACCEPT_SYSCALL
            | LINUX_ACCEPT4_SYSCALL
            | LINUX_RECVFROM_SYSCALL
            | LINUX_RECVMSG_SYSCALL
            | LINUX_SENDTO_SYSCALL
            | LINUX_SENDMSG_SYSCALL
            | LINUX_FLOCK_SYSCALL
            | LINUX_FCNTL_SYSCALL
            | LINUX_GETRANDOM_SYSCALL
    )
}

/// Delivers a pending signal. For system call `restart` interrupted with
/// EINTR, a handler installed with SA_RESTART returns into the call again,
/// as Linux restarts it, instead of making it fail.
pub(super) fn linux_deliver_pending_signal_restarting(
    output: *mut LinuxSyscallFrame,
    mut interrupted: LinuxUserContext,
    return_registers: (u64, u64),
    restart: Option<u64>,
) -> u64 {
    if X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return 0;
    }
    let requested = !X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    let deliverable = X86_RUNTIME.ELF_PROBE_PENDING_SIGNALS.load(Ordering::SeqCst) & requested;
    let dynamic = linux_peek_dynamic_signal(requested);
    if deliverable == 0 && dynamic.is_none() {
        return 0;
    }
    let legacy_signal = (deliverable != 0).then(|| u64::from(deliverable.trailing_zeros()) + 1);
    let use_dynamic = dynamic.is_some_and(|(scope, pending)| {
        scope == crate::linux_signal::Scope::Thread
            || legacy_signal.is_none_or(|legacy| u64::from(pending.signal) <= legacy)
    });
    let dynamic = use_dynamic.then_some(dynamic).flatten();
    let signal = dynamic.map_or_else(
        || legacy_signal.unwrap_or(0),
        |(_, pending)| u64::from(pending.signal),
    );
    let index = signal as usize - 1;
    let signal_bit = 1 << (signal - 1);
    if let Some(number) = restart.filter(|number| {
        interrupted.rax == LINUX_EINTR
            && linux_syscall_restartable(*number)
            && X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst) > 1
            && X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].load(Ordering::SeqCst) & LINUX_SA_RESTART
                != 0
    }) {
        interrupted.rax = number;
        interrupted.rip = interrupted.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    }
    // A stop signal with no handler restarts the interrupted call once the
    // process is continued, as Linux does: no handler ran to see EINTR.
    if let Some(number) = restart.filter(|_| {
        interrupted.rax == LINUX_EINTR
            && X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst) == 0
            && linux_default_signal_stops(signal)
    }) {
        interrupted.rax = number;
        interrupted.rip = interrupted.rip.wrapping_sub(LINUX_SYSCALL_INSTRUCTION_SIZE);
    }
    let code = dynamic.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].load(Ordering::SeqCst) as i32,
        |(_, pending)| pending.code,
    );
    let value = dynamic.map_or_else(
        || X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].load(Ordering::SeqCst),
        |(_, pending)| pending.value,
    );
    let result = linux_kill_current(
        (signal, code, Some(value)),
        dynamic.map(|(_, pending)| (pending.sender_pid, pending.sender_uid)),
        output,
        interrupted,
        return_registers,
    );
    if result == 0 {
        if let Some((scope, _)) = dynamic {
            let _ = linux_dequeue_dynamic_signal(scope, signal_bit);
        } else {
            X86_RUNTIME
                .ELF_PROBE_PENDING_SIGNALS
                .fetch_and(!signal_bit, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index].store(0, Ordering::SeqCst);
            X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
        }
        linux_note_timer_signal_delivery(signal, code, value);
    }
    result
}

/// The signal Linux sends for a user-mode CPU exception, by vector.
pub(super) const fn linux_fault_signal(vector: u64) -> u64 {
    match vector {
        0 | 16 | 19 => LINUX_SIGFPE,
        1 | 3 => LINUX_SIGTRAP,
        6 => LINUX_SIGILL,
        17 => LINUX_SIGBUS,
        _ => LINUX_SIGSEGV,
    }
}

/// The signal for user fault `fault`: SIGBUS for a page of a file
/// mapping past the end of its file (`address_space::current_linux_page_past_eof`),
/// else the one for its vector.
pub(super) fn linux_user_fault_signal(fault: domain::FaultMetadata) -> u64 {
    if fault.vector == 14
        && X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        && (address_space::current_linux_page_past_eof(fault.address & !(PAGE_SIZE as u64 - 1))
            || linux_mkwrite_failed(fault))
    {
        LINUX_SIGBUS
    } else {
        linux_fault_signal(fault.vector)
    }
}

/// Kills the faulting process, not its domain, when a user fault in a
/// process other than init cannot be delivered to a handler: Linux's
/// default action for a forced fault signal.
pub(super) fn terminate_linux_process_for_fault(fault: domain::FaultMetadata) -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) || current_linux_process_pid() == 1 {
        return false;
    }
    abort_linux_signal();
    linux_terminate_by_signal(linux_user_fault_signal(fault), false) == LINUX_RETURN_TO_KERNEL
}

/// Kills the faulting process with SIGKILL when a page it may touch could
/// not be given memory, as Linux's OOM killer does (the parent sees status
/// 137). Init is left to the fault path: killing it would end the domain.
pub(super) fn terminate_linux_process_out_of_memory() -> bool {
    let pid = current_linux_process_pid();
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst) || pid == 1 {
        return false;
    }
    let free_kib = memory::frame_counts().map_or(0, |(_, free)| free * 4);
    serial_write("ginux: out of memory: killed process ");
    serial_write_u64(u64::from(pid));
    serial_write(" (free kB ");
    serial_write_u64(free_kib);
    serial_write(")\r\n");
    abort_linux_signal();
    linux_terminate_by_default_signal(LINUX_SIGKILL) == LINUX_RETURN_TO_KERNEL
}

/// Delivers `signal` (SIGSEGV, or SIGBUS for a page past the end of its
/// file) for a user page fault to the process's handler.
pub(super) fn deliver_linux_fault_signal(
    frame: &mut UserFaultFrame,
    fault: domain::FaultMetadata,
    signal: u64,
) -> bool {
    if !frame.is_page_fault()
        || current_linux_thread_handle().is_none()
        || X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst)
    {
        return false;
    }
    let signal_bit = 1 << (signal - 1);
    let old_mask = X86_RUNTIME.ELF_PROBE_SIGNAL_MASK.load(Ordering::SeqCst);
    if old_mask & signal_bit != 0 {
        return false;
    }
    let index = signal as usize - 1;
    let handler = X86_RUNTIME.ELF_PROBE_SIGNAL_HANDLERS[index].load(Ordering::SeqCst);
    let flags = X86_RUNTIME.ELF_PROBE_SIGNAL_FLAGS[index].load(Ordering::SeqCst);
    let restorer = linux_effective_signal_restorer(
        X86_RUNTIME.ELF_PROBE_SIGNAL_RESTORERS[index].load(Ordering::SeqCst),
    );
    if !linux_signal_action_deliverable(handler, flags, restorer) {
        return false;
    }
    let interrupted = frame.context();
    let old_alt_stack_flags = X86_RUNTIME.ELF_PROBE_ALT_STACK_FLAGS.load(Ordering::SeqCst);
    let use_alt_stack = flags & LINUX_SA_ONSTACK != 0
        && old_alt_stack_flags & (LINUX_SS_DISABLE | LINUX_SS_ONSTACK) == 0;
    let stack_top = if use_alt_stack {
        let pointer = X86_RUNTIME
            .ELF_PROBE_ALT_STACK_POINTER
            .load(Ordering::SeqCst);
        let size = X86_RUNTIME.ELF_PROBE_ALT_STACK_SIZE.load(Ordering::SeqCst);
        let Some(top) = pointer.checked_add(size) else {
            return false;
        };
        top
    } else {
        interrupted.rsp
    };
    let Some(signal_stack) = linux_signal_stack(stack_top, use_alt_stack) else {
        return false;
    };
    let context = LinuxSignalContext::from_fault(
        interrupted,
        signal_stack,
        restorer,
        old_mask,
        old_alt_stack_flags,
    );
    if !context.user_context().is_valid() {
        return false;
    }
    let signal_frame = linux_rt_signal_frame(
        context,
        flags,
        LinuxSignalInformation::fault(
            signal,
            if signal == LINUX_SIGBUS {
                LINUX_BUS_ADRERR
            } else if fault.error & 1 == 0 {
                LINUX_SEGV_MAPERR
            } else {
                LINUX_SEGV_ACCERR
            },
            fault.address,
        ),
        fault.vector,
        fault.error,
        fault.address,
    );
    if !copy_linux_signal_frame(signal_stack, &signal_frame) {
        return false;
    }
    if !frame.enter_signal_handler(
        handler,
        signal_stack,
        signal,
        (
            signal_stack + LINUX_SIGNAL_FRAME_INFO_OFFSET,
            signal_stack + LINUX_SIGNAL_FRAME_CONTEXT_OFFSET,
        ),
        USER_CODE_SELECTOR,
        USER_DATA_SELECTOR,
    ) {
        return false;
    }
    // SAFETY: interrupts are disabled from exception entry through IRETQ, and
    // only one bounded Linux signal frame may be active at a time.
    unsafe { linux_signal_context().get().write(context) };
    linux_apply_delivered_signal_action(index, signal_bit, old_mask, flags);
    if use_alt_stack {
        if old_alt_stack_flags & LINUX_SS_AUTODISARM != 0 {
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_POINTER
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_SIZE
                .store(0, Ordering::SeqCst);
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .store(LINUX_SS_DISABLE, Ordering::SeqCst);
        } else {
            X86_RUNTIME
                .ELF_PROBE_ALT_STACK_FLAGS
                .store(LINUX_SS_ONSTACK, Ordering::SeqCst);
        }
    }
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(true, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_DELIVERY_COUNT
        .fetch_add(1, Ordering::SeqCst);
    true
}

pub(super) fn linux_rt_sigreturn(output: *mut LinuxSyscallFrame, user_stack: u64) -> u64 {
    if output.is_null() || !X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return LINUX_EINVAL;
    }
    // SAFETY: signal delivery serializes this context while interrupts remain
    // disabled; active is cleared before another delivery can publish state.
    let context = unsafe { linux_signal_context().get().cast_const().read() };
    if context.signal_stack.checked_add(8) != Some(user_stack) {
        return LINUX_EINVAL;
    }
    let mut returned = linux_rt_signal_frame(context, 0, LinuxSignalInformation::ZERO, 0, 0, 0);
    if !copy_linux_signal_frame_from_user(context.signal_stack, &mut returned) {
        return LINUX_EINVAL;
    }
    let Some(restored) = linux_restored_signal_context(context, &returned) else {
        return LINUX_EINVAL;
    };
    if !write_linux_live_return(output, restored.user) {
        return LINUX_EINVAL;
    }
    // SAFETY: this serialized return consumes the sole active record before
    // checking whether another unblocked pending signal should replace it.
    unsafe { linux_signal_context().get().write(LinuxSignalContext::ZERO) };
    store_current_linux_signal_mask(restored.signal_mask);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_POINTER
        .store(context.alt_stack_pointer, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_SIZE
        .store(context.alt_stack_size, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_ALT_STACK_FLAGS
        .store(context.alt_stack_flags, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .store(false, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SIGNAL_RETURN_COUNT
        .fetch_add(1, Ordering::SeqCst);
    let pending_result =
        linux_deliver_pending_signal(output, restored.user, (restored.rcx, restored.r11));
    if pending_result == 0 && X86_RUNTIME.LINUX_SIGNAL_ACTIVE.load(Ordering::SeqCst) {
        return 0;
    }
    // SAFETY: the dedicated IRETQ epilogue consumes these values before this
    // serialized syscall entry can be reused.
    unsafe {
        let entry_state = &mut *current_entry_state();
        entry_state.signal_rax = restored.user.rax;
        entry_state.signal_rcx = restored.rcx;
        entry_state.signal_r11 = restored.r11;
    }
    LINUX_RETURN_FROM_IRET
}

pub(super) fn abort_linux_signal() {
    if X86_RUNTIME
        .LINUX_SIGNAL_ACTIVE
        .swap(false, Ordering::SeqCst)
    {
        // SAFETY: the active context is exclusively owned by this serialized
        // Linux execution while interrupts remain disabled.
        let context = unsafe { linux_signal_context().get().cast_const().read() };
        store_current_linux_signal_mask(context.signal_mask);
        X86_RUNTIME
            .ELF_PROBE_ALT_STACK_POINTER
            .store(context.alt_stack_pointer, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_ALT_STACK_SIZE
            .store(context.alt_stack_size, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_ALT_STACK_FLAGS
            .store(context.alt_stack_flags, Ordering::SeqCst);
        unsafe { linux_signal_context().get().write(LinuxSignalContext::ZERO) };
    }
}

/// Queues `pending` as `crate::linux_signal::enqueue` does, but a real-time
/// signal sent by sigqueue, tkill or tgkill (SI_QUEUE, SI_TKILL) past the
/// sender's RLIMIT_SIGPENDING is refused (NoMemory, EAGAIN to the caller),
/// as Linux refuses to allocate its queue entry (tgkill02).
fn linux_enqueue_signal(
    instance: usize,
    scope: crate::linux_signal::Scope,
    slot: usize,
    pending: crate::linux_signal::Pending,
    realtime: bool,
) -> Result<bool, crate::linux_signal::Error> {
    const SI_QUEUE: i32 = -1;
    const SI_TKILL: i32 = -6;
    if realtime && matches!(pending.code, SI_QUEUE | SI_TKILL) {
        let limit = linux_resource_limit_values(
            LINUX_RLIMIT_SIGPENDING,
            X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst),
        )
        .map_or(u64::MAX, |limit| limit[0]);
        if crate::linux_signal::pending_count(instance) >= limit {
            return Err(crate::linux_signal::Error::NoMemory);
        }
    }
    crate::linux_signal::enqueue(instance, scope, slot, pending, realtime)
}
