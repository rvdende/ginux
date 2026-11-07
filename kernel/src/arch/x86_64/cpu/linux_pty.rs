//! System calls on pseudo-terminal descriptors (`crate::linux_pty`): opening
//! /dev/ptmx and /dev/pts/N, reads and writes that wait as other blocking
//! descriptors do, the tty ioctls, poll, fstat and the /proc/self/fd names.

use super::*;

use crate::linux_pty::{self, OpenError};
use ginux_tty::termios::{self, Termios};
use ginux_tty::{End, Error as TtyError};

const LINUX_TCGETA: u32 = 0x5405;
const LINUX_TCSETA: u32 = 0x5406;
const LINUX_TCSETAW: u32 = 0x5407;
const LINUX_TCSETAF: u32 = 0x5408;
const LINUX_TCSBRK: u32 = 0x5409;
const LINUX_TCXONC: u32 = 0x540a;
const LINUX_TCFLSH: u32 = 0x540b;
const LINUX_TIOCEXCL: u32 = 0x540c;
const LINUX_TIOCNXCL: u32 = 0x540d;
const LINUX_TIOCOUTQ: u32 = 0x5411;
const LINUX_TIOCSTI: u32 = 0x5412;
const LINUX_TIOCSWINSZ: u32 = 0x5414;
const LINUX_TIOCCONS: u32 = 0x541d;
const LINUX_TIOCPKT: u32 = 0x5420;
const LINUX_TIOCSETD: u32 = 0x5423;
const LINUX_TIOCGETD: u32 = 0x5424;
const LINUX_TCSBRKP: u32 = 0x5425;
const LINUX_TIOCSBRK: u32 = 0x5427;
const LINUX_TIOCCBRK: u32 = 0x5428;
const LINUX_TIOCGPTN: u32 = 0x8004_5430;
const LINUX_TIOCSPTLCK: u32 = 0x4004_5431;
const LINUX_TIOCGDEV: u32 = 0x8004_5432;
const LINUX_TIOCSIG: u32 = 0x4004_5436;
const LINUX_TIOCGPKT: u32 = 0x8004_5438;
const LINUX_TIOCGPTLCK: u32 = 0x8004_5439;
const LINUX_TIOCGEXCL: u32 = 0x8004_5440;
const LINUX_TIOCGPTPEER: u32 = 0x5441;
const LINUX_SIGHUP: u64 = 1;
const LINUX_SIGWINCH: u64 = 28;
/// The longest read or write one call moves: a canonical line or a full
/// read buffer, and what a pair can queue.
const LINUX_PTY_TRANSFER_LIMIT: usize = ginux_tty::RECEIVE_LIMIT + 4096;

fn linux_pty_owner() -> usize {
    current_container_slot().unwrap_or(crate::control_abi::DOMAIN_LIMIT)
}

/// The end and pair index a pseudo-terminal descriptor is open on.
pub(super) fn linux_pty_descriptor(descriptor: u64) -> Option<(End, u64)> {
    match linux_object_descriptor(descriptor)? {
        (linux_pty::CLASS_MASTER, index) => Some((End::Master, index)),
        (linux_pty::CLASS_SLAVE, index) => Some((End::Slave, index)),
        _ => None,
    }
}

fn linux_pty_with<R>(index: u64, operation: impl FnOnce(&mut linux_pty::Entry) -> R) -> Option<R> {
    linux_pty::with(linux_pty_owner(), index, operation)
}

fn linux_pty_open_error(error: OpenError) -> u64 {
    match error {
        OpenError::Exhausted => LINUX_ENOSPC,
        OpenError::NoMemory => LINUX_ENOMEM,
        OpenError::Unavailable => LINUX_EIO,
        OpenError::Busy => LINUX_EBUSY,
    }
}

fn linux_pty_privileged() -> bool {
    current_linux_credentials()
        .is_some_and(|credentials| credentials.has(ginux_credentials::capability::SYS_ADMIN))
}

/// A descriptor for object `slot` with the access `flags` ask.
fn linux_install_pty_descriptor(slot: crate::linux_socket::SlotId, flags: u64) -> u64 {
    let access = match flags & LINUX_O_ACCMODE {
        0 => LINUX_DESCRIPTOR_INPUT,
        1 => LINUX_DESCRIPTOR_OUTPUT,
        _ => LINUX_DESCRIPTOR_INPUT | LINUX_DESCRIPTOR_OUTPUT,
    };
    linux_install_object_descriptor_with_access(slot, flags, access)
}

/// Opens /dev/ptmx: a new pair, its master and the slave's node.
pub(super) fn linux_open_pty_master(flags: u64) -> u64 {
    let user = current_linux_credentials().map_or(0, |credentials| credentials.user.filesystem);
    match linux_pty::open_master(linux_pty_owner(), user) {
        Ok((slot, _)) => linux_install_pty_descriptor(slot, flags),
        Err(error) => linux_pty_open_error(error),
    }
}

/// Opens slave `index`. A session leader without a controlling terminal
/// that opens it without O_NOCTTY makes it its controlling terminal.
pub(super) fn linux_open_pty_slave(index: u64, flags: u64) -> u64 {
    let slot = match linux_pty::open_slave(linux_pty_owner(), index, linux_pty_privileged()) {
        Ok(slot) => slot,
        Err(error) => return linux_pty_open_error(error),
    };
    let descriptor = linux_install_pty_descriptor(slot, flags);
    if descriptor < LINUX_DESCRIPTOR_TABLE_LIMIT
        && flags & LINUX_O_NOCTTY == 0
        && flags & LINUX_O_ACCMODE != 1
    {
        let pid = current_linux_process_pid();
        if let Some(session) = linux_process::live_process_session(pid)
            .filter(|&session| session == pid && !linux_session_has_terminal(session))
        {
            let group = linux_process::live_process_group(pid).unwrap_or(pid);
            let _ = linux_pty_with(index, |entry| {
                if entry.session == 0 {
                    entry.session = session;
                    entry.group = group;
                }
            });
        }
    }
    descriptor
}

/// Whether `session` has a controlling terminal: the console or a pty.
fn linux_session_has_terminal(session: u32) -> bool {
    X86_RUNTIME.LINUX_TTY_SESSION.load(Ordering::SeqCst) == session
        || linux_pty::controls_session(session)
}

/// Whether a live process belongs to `session`.
fn linux_session_alive(session: u32) -> bool {
    (0..linux_process::live_process_slots()).any(|slot| {
        linux_process::live_process_pid_at(slot)
            .is_some_and(|pid| linux_process::live_process_session(pid) == Some(session))
    })
}

/// Sends `signal` to every process of group `group`, as the kernel does
/// (SI_KERNEL).
fn linux_pty_signal_group(group: u32, signal: u64) {
    if group == 0 {
        return;
    }
    for slot in 0..linux_process::live_process_slots() {
        if let Some(pid) = linux_process::live_process_pid_at(slot)
            .filter(|&pid| linux_process::live_process_group(pid) == Some(group))
        {
            let _ = linux_queue_process_signal(pid, signal, LINUX_SI_KERNEL, None);
        }
    }
}

/// Sends the signals pair `index`'s input raised to its foreground group.
fn linux_pty_deliver_signals(index: u64) {
    let Some((signals, group)) =
        linux_pty_with(index, |entry| (entry.pair.take_signals(), entry.group))
    else {
        return;
    };
    for signal in 1..=32_u64 {
        if signals & 1 << (signal - 1) != 0 {
            linux_pty_signal_group(group, signal);
        }
    }
}

/// SIGHUP and SIGCONT to the leaders of the sessions whose controlling pty
/// hung up (its master closed).
pub(super) fn linux_pty_send_hangups() {
    for session in linux_pty::take_hangups() {
        if linux_process::live_process_session(session) == Some(session) {
            let _ = linux_queue_process_signal(session, LINUX_SIGHUP, LINUX_SI_KERNEL, None);
            let _ = linux_queue_process_signal(session, LINUX_SIGCONT, LINUX_SI_KERNEL, None);
        }
    }
}

/// read, readv, write, writev and ioctl on a pty descriptor. A read with
/// nothing to read and a write with no room wait, unless O_NONBLOCK, as
/// other blocking descriptors do: the rest of the domain runs and the call
/// starts again.
pub(super) fn linux_pty_syscall_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    descriptor: u64,
    buffer: u64,
    count: u64,
) -> u64 {
    let Some((end, index)) = linux_pty_descriptor(descriptor) else {
        return LINUX_EBADF;
    };
    let nonblocking = linux_socket_nonblocking(descriptor);
    let state = linux_device_descriptor(descriptor);
    let result = match number {
        LINUX_IOCTL_SYSCALL => return linux_pty_ioctl(descriptor, end, index, buffer, count),
        LINUX_READ_SYSCALL | LINUX_READV_SYSCALL if state & LINUX_DESCRIPTOR_INPUT == 0 => {
            LINUX_EBADF
        }
        LINUX_WRITE_SYSCALL | LINUX_WRITEV_SYSCALL if state & LINUX_DESCRIPTOR_OUTPUT == 0 => {
            LINUX_EBADF
        }
        LINUX_READ_SYSCALL | LINUX_WRITE_SYSCALL => {
            let mut ranges = [(0_u64, 0_usize); LINUX_IOV_LIMIT];
            ranges[0] = (buffer, usize::try_from(count).unwrap_or(usize::MAX));
            linux_pty_transfer(
                number == LINUX_WRITE_SYSCALL,
                end,
                index,
                &ranges[..1],
                nonblocking,
            )
        }
        _ => match linux_socket_iov_ranges(buffer, count, number == LINUX_READV_SYSCALL) {
            Ok((ranges, vector_count)) => linux_pty_transfer(
                number == LINUX_WRITEV_SYSCALL,
                end,
                index,
                &ranges[..vector_count],
                nonblocking,
            ),
            Err(error) => error,
        },
    };
    if result == LINUX_EAGAIN && !nonblocking {
        return linux_retry_later_live_return(output, caller, number);
    }
    result
}

/// Moves bytes between `ranges` of user memory and pair `index`'s `end`.
fn linux_pty_transfer(
    write: bool,
    end: End,
    index: u64,
    ranges: &[(u64, usize)],
    nonblocking: bool,
) -> u64 {
    let total = ranges
        .iter()
        .fold(0_usize, |total, (_, length)| total.saturating_add(*length))
        .min(LINUX_PTY_TRANSFER_LIMIT);
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(total).is_err() {
        return LINUX_ENOMEM;
    }
    bytes.resize(total, 0);
    let result = if write {
        let mut gathered = 0;
        for &(address, length) in ranges {
            let length = length.min(total - gathered);
            if !copy_from_linux_user(address, &mut bytes[gathered..gathered + length]) {
                if gathered == 0 {
                    return LINUX_EFAULT;
                }
                break;
            }
            gathered += length;
        }
        linux_pty_with(index, |entry| entry.pair.write(end, &bytes[..gathered]))
    } else {
        // Nothing is taken from the pair that cannot be copied out.
        if let Some(&(address, length)) = ranges.iter().find(|(_, length)| *length != 0) {
            if !linux_writable_user_range_contains(address, length.min(total)) {
                return LINUX_EFAULT;
            }
        }
        let now = linux_elapsed_nanoseconds().unwrap_or(0);
        let slot = end as usize;
        linux_pty_with(index, |entry| {
            let deadline = entry.read_deadline[slot];
            let expired = deadline != 0 && now >= deadline;
            let result = entry.pair.read(end, &mut bytes, expired);
            entry.read_deadline[slot] = match (result, entry.pair.read_timer(end)) {
                (Err(TtyError::WouldBlock), Some(time)) if !nonblocking && deadline == 0 => {
                    now.saturating_add(u64::from(time) * 100_000_000)
                }
                (Err(TtyError::WouldBlock), Some(_)) if !nonblocking => deadline,
                _ => 0,
            };
            result
        })
    };
    linux_pty_deliver_signals(index);
    let result = match result {
        None => return LINUX_EBADF,
        Some(Err(TtyError::WouldBlock)) => return LINUX_EAGAIN,
        Some(Err(TtyError::Io)) => return LINUX_EIO,
        Some(Ok(length)) => length,
    };
    wake_linux_descriptor_waits();
    if !write {
        let mut copied = 0;
        for &(address, length) in ranges {
            if copied == result {
                break;
            }
            let length = length.min(result - copied);
            if !copy_to_linux_user(address, &bytes[copied..copied + length]) {
                return if copied == 0 {
                    LINUX_EFAULT
                } else {
                    copied as u64
                };
            }
            copied += length;
        }
    }
    result as u64
}

fn linux_pty_put_int(address: u64, value: u32) -> u64 {
    if copy_to_linux_user(address, &value.to_ne_bytes()) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_pty_get_int(address: u64) -> Result<u32, u64> {
    let mut bytes = [0_u8; 4];
    if copy_from_linux_user(address, &mut bytes) {
        Ok(u32::from_ne_bytes(bytes))
    } else {
        Err(LINUX_EFAULT)
    }
}

/// The caller's session, when it is a process's.
fn linux_caller_session() -> u32 {
    linux_process::live_process_session(current_linux_process_pid()).unwrap_or(0)
}

/// Applies settings read from user memory at `address` in one of the three
/// layouts; `flush` (TCSETSF and kin) discards the slave's input first.
fn linux_pty_set_termios(index: u64, request: u32, address: u64) -> u64 {
    let current = linux_pty_with(index, |entry| entry.pair.termios()).unwrap_or(Termios::slave());
    let new = match request {
        LINUX_TCSETA | LINUX_TCSETAW | LINUX_TCSETAF => {
            let mut bytes = [0; termios::TERMIO_SIZE];
            copy_from_linux_user(address, &mut bytes).then(|| current.with_termio(&bytes))
        }
        _ if request as u64 == LINUX_TCSETS
            || request as u64 == LINUX_TCSETSW
            || request as u64 == LINUX_TCSETSF =>
        {
            let mut bytes = [0; termios::TERMIOS_SIZE];
            copy_from_linux_user(address, &mut bytes).then(|| current.with_termios(&bytes))
        }
        _ => {
            let mut bytes = [0; termios::TERMIOS2_SIZE];
            copy_from_linux_user(address, &mut bytes).then(|| current.with_termios2(&bytes))
        }
    };
    let Some(new) = new else {
        return LINUX_EFAULT;
    };
    let flush = request == LINUX_TCSETAF
        || request as u64 == LINUX_TCSETSF
        || request as u64 == LINUX_TCSETSF2;
    let _ = linux_pty_with(index, |entry| {
        if flush {
            entry.pair.flush_input(End::Slave);
        }
        entry.pair.set_termios(new);
    });
    linux_pty_deliver_signals(index);
    wake_linux_descriptor_waits();
    0
}

/// The tty ioctls on a pty end. Settings, window size and job control
/// reach the slave from either end; the TIOC*PT* calls are the master's.
fn linux_pty_ioctl(descriptor: u64, end: End, index: u64, request: u64, argument: u64) -> u64 {
    if let Some(result) = linux_generic_ioctl(descriptor, request, argument) {
        return result;
    }
    let request = request as u32;
    let Some(hung_up) = linux_pty_with(index, |entry| end == End::Slave && entry.pair.hung_up())
    else {
        return LINUX_EBADF;
    };
    // A hung-up slave answers only EIO (Linux's hung_up_tty_ioctl).
    if hung_up {
        return if u64::from(request) == LINUX_TIOCSPGRP {
            LINUX_ENOTTY
        } else {
            LINUX_EIO
        };
    }
    let master = end == End::Master;
    let termios = linux_pty_with(index, |entry| entry.pair.termios()).unwrap_or(Termios::slave());
    let copy_out = |bytes: &[u8]| {
        if copy_to_linux_user(argument, bytes) {
            0
        } else {
            LINUX_EFAULT
        }
    };
    match request {
        _ if u64::from(request) == LINUX_TCGETS => copy_out(&termios.to_termios()),
        _ if u64::from(request) == LINUX_TCGETS2 => copy_out(&termios.to_termios2()),
        LINUX_TCGETA => copy_out(&termios.to_termio()),
        LINUX_TCSETA | LINUX_TCSETAW | LINUX_TCSETAF => {
            linux_pty_set_termios(index, request, argument)
        }
        _ if [
            LINUX_TCSETS,
            LINUX_TCSETSW,
            LINUX_TCSETSF,
            LINUX_TCSETS2,
            LINUX_TCSETSW2,
            LINUX_TCSETSF2,
        ]
        .contains(&u64::from(request)) =>
        {
            linux_pty_set_termios(index, request, argument)
        }
        _ if u64::from(request) == LINUX_TIOCGWINSZ => {
            copy_out(&linux_pty_with(index, |entry| entry.pair.window()).unwrap_or([0; 8]))
        }
        LINUX_TIOCSWINSZ => {
            let mut window = [0_u8; 8];
            if !copy_from_linux_user(argument, &mut window) {
                return LINUX_EFAULT;
            }
            if let Some((true, group)) =
                linux_pty_with(index, |entry| (entry.pair.set_window(window), entry.group))
            {
                linux_pty_signal_group(group, LINUX_SIGWINCH);
            }
            0
        }
        LINUX_TIOCGPTN if master => linux_pty_put_int(argument, index as u32),
        LINUX_TIOCSPTLCK if master => match linux_pty_get_int(argument) {
            Ok(value) => {
                let _ = linux_pty_with(index, |entry| entry.pair.set_locked(value != 0));
                0
            }
            Err(error) => error,
        },
        LINUX_TIOCGPTLCK if master => linux_pty_put_int(
            argument,
            u32::from(linux_pty_with(index, |entry| entry.pair.locked()).unwrap_or(false)),
        ),
        LINUX_TIOCPKT if master => match linux_pty_get_int(argument) {
            Ok(value) => {
                let _ = linux_pty_with(index, |entry| entry.pair.set_packet(value != 0));
                0
            }
            Err(error) => error,
        },
        LINUX_TIOCGPKT if master => linux_pty_put_int(
            argument,
            u32::from(linux_pty_with(index, |entry| entry.pair.packet()).unwrap_or(false)),
        ),
        LINUX_TIOCSIG if master => {
            let signal = argument as u32 as u64;
            if ![2, 3, 20].contains(&signal) {
                return LINUX_EINVAL;
            }
            linux_pty_signal_group(
                linux_pty_with(index, |entry| entry.group).unwrap_or(0),
                signal,
            );
            0
        }
        LINUX_TIOCGPTPEER if master => {
            let flags = argument & 0xffff_ffff;
            if flags & !(LINUX_O_ACCMODE | LINUX_O_NOCTTY | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC) != 0
            {
                return LINUX_EINVAL;
            }
            linux_open_pty_slave(index, flags)
        }
        _ if u64::from(request) == LINUX_FIONREAD => linux_pty_put_int(
            argument,
            linux_pty_with(index, |entry| entry.pair.readable_bytes(end)).unwrap_or(0) as u32,
        ),
        LINUX_TIOCOUTQ => linux_pty_put_int(argument, 0),
        LINUX_TCFLSH => {
            if argument > 2 {
                return LINUX_EINVAL;
            }
            let _ = linux_pty_with(index, |entry| {
                if argument != 1 {
                    entry.pair.flush_input(end);
                }
                if argument != 0 {
                    entry.pair.flush_output(end);
                }
            });
            wake_linux_descriptor_waits();
            0
        }
        LINUX_TCXONC => {
            let characters = if master {
                Termios::master().cc
            } else {
                termios.cc
            };
            let _ = linux_pty_with(index, |entry| match argument {
                0 => entry.pair.suspend_output(end),
                1 => entry.pair.resume_output(end),
                2 if characters[termios::VSTOP] != termios::DISABLED => {
                    entry.pair.send_char(end, characters[termios::VSTOP])
                }
                3 if characters[termios::VSTART] != termios::DISABLED => {
                    entry.pair.send_char(end, characters[termios::VSTART])
                }
                _ => {}
            });
            linux_pty_deliver_signals(index);
            wake_linux_descriptor_waits();
            if argument > 3 {
                LINUX_EINVAL
            } else {
                0
            }
        }
        // A pty has no line to break or wait for.
        LINUX_TCSBRK | LINUX_TCSBRKP | LINUX_TIOCSBRK | LINUX_TIOCCBRK => 0,
        LINUX_TIOCEXCL | LINUX_TIOCNXCL => {
            if !master {
                let _ = linux_pty_with(index, |entry| entry.exclusive = request == LINUX_TIOCEXCL);
            }
            0
        }
        LINUX_TIOCGEXCL => linux_pty_put_int(
            argument,
            u32::from(!master && linux_pty_with(index, |entry| entry.exclusive).unwrap_or(false)),
        ),
        LINUX_TIOCGETD => linux_pty_put_int(argument, u32::from(termios.line)),
        // Only the terminal discipline (N_TTY) is built in.
        LINUX_TIOCSETD => match linux_pty_get_int(argument) {
            Ok(0) => 0,
            Ok(_) => LINUX_EINVAL,
            Err(error) => error,
        },
        LINUX_TIOCGDEV => linux_pty_put_int(argument, linux_pty::slave_device(index)),
        LINUX_TIOCSTI => {
            let controlling =
                linux_pty_with(index, |entry| entry.session).unwrap_or(0) == linux_caller_session();
            if !linux_pty_privileged() && (master || !controlling) {
                return LINUX_EPERM;
            }
            let mut character = [0_u8];
            if !copy_from_linux_user(argument, &mut character) {
                return LINUX_EFAULT;
            }
            let _ = linux_pty_with(index, |entry| entry.pair.inject(end, character[0]));
            linux_pty_deliver_signals(index);
            wake_linux_descriptor_waits();
            0
        }
        LINUX_TIOCCONS if master => LINUX_EINVAL,
        LINUX_TIOCCONS => {
            if linux_pty_privileged() {
                0
            } else {
                LINUX_EPERM
            }
        }
        _ if u64::from(request) == LINUX_TIOCVHANGUP => {
            if !linux_pty_privileged() {
                return LINUX_EPERM;
            }
            if let Some(session) = linux_pty_with(index, |entry| {
                let session = entry.session;
                entry.session = 0;
                entry.group = 0;
                session
            })
            .filter(|session| *session != 0)
            {
                if linux_process::live_process_session(session) == Some(session) {
                    let _ =
                        linux_queue_process_signal(session, LINUX_SIGHUP, LINUX_SI_KERNEL, None);
                    let _ =
                        linux_queue_process_signal(session, LINUX_SIGCONT, LINUX_SI_KERNEL, None);
                }
            }
            0
        }
        _ => linux_pty_job_control(descriptor, end, index, request, argument),
    }
}

/// TIOCSCTTY, TIOCNOTTY, TIOCGPGRP, TIOCSPGRP and TIOCGSID: the slave as a
/// session's controlling terminal. Through the master they reach the
/// slave, though the master is no process's controlling terminal.
fn linux_pty_job_control(
    descriptor: u64,
    end: End,
    index: u64,
    request: u32,
    argument: u64,
) -> u64 {
    let request = u64::from(request);
    let pid = current_linux_process_pid();
    let session = linux_caller_session();
    let Some((terminal_session, group)) =
        linux_pty_with(index, |entry| (entry.session, entry.group))
    else {
        return LINUX_EBADF;
    };
    let controlling = session != 0 && terminal_session == session;
    match request {
        LINUX_TIOCSCTTY => {
            if session == pid && controlling {
                return 0;
            }
            if session != pid || linux_session_has_terminal(session) {
                return LINUX_EPERM;
            }
            if terminal_session != 0
                && linux_session_alive(terminal_session)
                && !(argument == 1 && linux_pty_privileged())
            {
                return LINUX_EPERM;
            }
            if linux_device_descriptor(descriptor) & LINUX_DESCRIPTOR_INPUT == 0
                && !linux_pty_privileged()
            {
                return LINUX_EPERM;
            }
            let group = linux_process::live_process_group(pid).unwrap_or(pid);
            let _ = linux_pty_with(index, |entry| {
                entry.session = session;
                entry.group = group;
            });
            0
        }
        LINUX_TIOCNOTTY => {
            if end == End::Master || !controlling {
                return LINUX_ENOTTY;
            }
            // The leader gives the terminal up for its whole session, and
            // the foreground group is told.
            if session == pid {
                let _ = linux_pty_with(index, |entry| {
                    entry.session = 0;
                    entry.group = 0;
                });
                linux_pty_signal_group(group, LINUX_SIGHUP);
                linux_pty_signal_group(group, LINUX_SIGCONT);
            }
            0
        }
        LINUX_TIOCGPGRP => {
            if end == End::Slave && !controlling {
                return LINUX_ENOTTY;
            }
            linux_pty_put_int(argument, group)
        }
        LINUX_TIOCGSID => {
            if end == End::Slave && !controlling || terminal_session == 0 {
                return LINUX_ENOTTY;
            }
            linux_pty_put_int(argument, terminal_session)
        }
        LINUX_TIOCSPGRP => {
            let wanted = match linux_pty_get_int(argument) {
                Ok(wanted) => wanted as i32,
                Err(error) => return error,
            };
            if wanted < 0 {
                return LINUX_EINVAL;
            }
            if !controlling {
                return LINUX_ENOTTY;
            }
            let wanted = wanted as u32;
            let members = || {
                (0..linux_process::live_process_slots())
                    .filter_map(linux_process::live_process_pid_at)
                    .filter(move |&pid| linux_process::live_process_group(pid) == Some(wanted))
            };
            if members().next().is_none()
                && !(0..linux_process::live_process_slots())
                    .any(|slot| linux_process::live_process_pid_at(slot) == Some(wanted))
            {
                return LINUX_ESRCH;
            }
            if !members().any(|pid| linux_process::live_process_session(pid) == Some(session)) {
                return LINUX_EPERM;
            }
            let _ = linux_pty_with(index, |entry| entry.group = wanted);
            0
        }
        _ => LINUX_ENOTTY,
    }
}

/// poll's events for a pty end. A hung-up slave is readable, writable and
/// hung up at once, as Linux's hung_up_tty_poll says.
pub(super) fn linux_pty_poll_events(end: End, index: u64, requested: u16) -> u16 {
    const LINUX_POLLWRNORM: u16 = 0x100;
    let Some((hung_up, readiness)) = linux_pty_with(index, |entry| {
        (
            end == End::Slave && entry.pair.hung_up(),
            entry.pair.poll(end),
        )
    }) else {
        return LINUX_POLLNVAL;
    };
    linux_pty_deliver_signals(index);
    if hung_up {
        return requested & (LINUX_POLLIN | LINUX_POLLRDNORM | LINUX_POLLOUT | LINUX_POLLWRNORM)
            | LINUX_POLLERR
            | LINUX_POLLHUP;
    }
    let mut events = 0;
    if readiness.readable {
        events |= requested & (LINUX_POLLIN | LINUX_POLLRDNORM);
    }
    if readiness.priority {
        events |= requested & LINUX_POLLPRI;
    }
    if readiness.writable {
        events |= requested & (LINUX_POLLOUT | LINUX_POLLWRNORM);
    }
    if readiness.hangup {
        events |= LINUX_POLLHUP;
    }
    events
}

/// fstat of a pty end: its device node's, so ttyname finds the node, or the
/// node's identity once the node is gone.
pub(super) fn linux_pty_stat(end: End, index: u64) -> [u8; LINUX_STAT_SIZE] {
    let mut path = [0_u8; 16];
    let (path, device, mode): (&[u8], u32, u32) = match end {
        End::Master => (b"dev/ptmx", linux_pty::MASTER_DEVICE, 0o666),
        End::Slave => (
            linux_pty::node_path(index, &mut path),
            linux_pty::slave_device(index),
            0o620,
        ),
    };
    if let Some(metadata) = crate::linux_overlay::lookup(path).filter(|metadata| {
        metadata.kind == crate::linux_overlay::NodeKind::CharacterDevice
            && metadata.device == device
    }) {
        return linux_overlay_stat(metadata);
    }
    let mut stat = linux_stat(0o020_000 | mode, 0x3000 + index);
    stat[40..48].copy_from_slice(&u64::from(device).to_ne_bytes());
    stat
}

/// The path /proc/self/fd shows for a pty end.
pub(super) fn linux_pty_link_target(
    end: End,
    index: u64,
    output: &mut [u8; crate::linux_overlay::PATH_CAPACITY],
) -> Option<usize> {
    let mut path = [0_u8; 16];
    let path = match end {
        End::Master => b"dev/ptmx",
        End::Slave => linux_pty::node_path(index, &mut path),
    };
    output[0] = b'/';
    output.get_mut(1..1 + path.len())?.copy_from_slice(path);
    Some(1 + path.len())
}
