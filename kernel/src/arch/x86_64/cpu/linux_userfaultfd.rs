//! userfaultfd(2) for Linux processes (`crate::linux_userfaultfd` keeps
//! the contexts): making one (the system call and /dev/userfaultfd), its
//! ioctls, reads and polls, and the user page faults it resolves.
//!
//! A faulting thread waits as a preempted thread does: the fault sends it
//! to the vDSO's preemption entry with the faulting instruction as the
//! place to go on from, so the rest of the process runs (the thread that
//! reads the message and fills the page), and the access is tried again
//! when the thread runs next. Once the page is filled, protected no more or
//! the context gone, the access goes through.

use super::*;

use crate::linux_userfaultfd::{
    self as userfaultfd, Error as ContextError, Fault, Kind, FEATURES, FEATURE_EVENT_FORK,
    MODE_MINOR, MODE_MISSING, MODE_WP,
};

const UFFD_USER_MODE_ONLY: u64 = 1;
const UFFDIO_REGISTER: u32 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u32 = 0x8010_aa01;
const UFFDIO_WAKE: u32 = 0x8010_aa02;
const UFFDIO_COPY: u32 = 0xc028_aa03;
const UFFDIO_ZEROPAGE: u32 = 0xc020_aa04;
const UFFDIO_MOVE: u32 = 0xc028_aa05;
const UFFDIO_WRITEPROTECT: u32 = 0xc018_aa06;
const UFFDIO_CONTINUE: u32 = 0xc020_aa07;
const UFFDIO_POISON: u32 = 0xc020_aa08;
const UFFDIO_API: u32 = 0xc018_aa3f;
const UFFD_API: u64 = 0xaa;
/// The ioctls UFFDIO_API reports: register, unregister and API.
const UFFD_API_IOCTLS: u64 = 1 | 1 << 1 | 1 << 0x3f;
/// The ioctls UFFDIO_REGISTER reports for a range: wake, copy, zeropage,
/// move, writeprotect, continue and poison.
const UFFD_API_RANGE_IOCTLS: u64 = 0x1fc;
const UFFDIO_WRITEPROTECT_BIT: u64 = 1 << 6;
const UFFDIO_CONTINUE_BIT: u64 = 1 << 7;
const MODE_DONTWAKE: u64 = 1;
/// UFFDIO_COPY_MODE_WP and UFFDIO_CONTINUE_MODE_WP.
const MODE_FILL_WP: u64 = 2;
const MOVE_MODE_ALLOW_SRC_HOLES: u64 = 2;
const WRITEPROTECT_MODE_WP: u64 = 1;
const WRITEPROTECT_MODE_DONTWAKE: u64 = 2;
const PAGE: u64 = PAGE_SIZE as u64;

/// The context a userfaultfd descriptor is open on.
fn linux_userfaultfd_context(descriptor: u64) -> Option<u64> {
    match linux_object_descriptor(descriptor)? {
        (userfaultfd::CLASS_CONTEXT, id) => Some(id),
        _ => None,
    }
}

pub(super) fn linux_userfaultfd_descriptor(descriptor: u64) -> bool {
    linux_userfaultfd_context(descriptor).is_some()
}

pub(super) fn linux_userfaultfd(flags: u64) -> u64 {
    linux_userfaultfd_create(flags, false)
}

/// A userfaultfd with `flags` for the calling process. Without
/// UFFD_USER_MODE_ONLY the system call needs CAP_SYS_PTRACE, as Linux's
/// does with vm.unprivileged_userfaultfd 0; /dev/userfaultfd (`device`)
/// needs nothing more than the device's permissions. The kernel's own
/// faults are never reported either way.
pub(super) fn linux_userfaultfd_create(flags: u64, device: bool) -> u64 {
    let flags = u64::from(flags as u32);
    if flags & !(UFFD_USER_MODE_ONLY | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC) != 0 {
        return LINUX_EINVAL;
    }
    if flags & UFFD_USER_MODE_ONLY == 0
        && !device
        && !current_linux_credentials()
            .is_some_and(|credentials| credentials.has(ginux_credentials::capability::SYS_PTRACE))
    {
        return LINUX_EPERM;
    }
    let Some(id) = userfaultfd::create(linux_execution_instance(), current_linux_process_pid())
    else {
        return LINUX_ENOMEM;
    };
    match crate::linux_socket::open_object(userfaultfd::CLASS_CONTEXT, id) {
        Ok(slot) => linux_install_object_descriptor(slot, flags & !UFFD_USER_MODE_ONLY),
        Err(_) => {
            let _ = userfaultfd::release(userfaultfd::CLASS_CONTEXT, id);
            LINUX_ENOMEM
        }
    }
}

/// A context's last descriptor closed: the pages it write-protected are
/// writable again, when they are the current process's.
pub(super) fn linux_userfaultfd_release(class: u8, id: u64) {
    let Some(released) = userfaultfd::release(class, id) else {
        return;
    };
    if released.instance == linux_execution_instance()
        && released.pid == current_linux_process_pid()
    {
        for (page, protection) in released.protected {
            let _ = address_space::protect_current_linux_runtime_page(page, protection);
        }
    }
    wake_linux_descriptor_waits();
}

/// read(2) of a userfaultfd: whole `struct uffd_msg`s, EAGAIN with none
/// (a blocking reader waits and reads again).
pub(super) fn linux_userfaultfd_read(descriptor: u64, address: u64, count: u64) -> u64 {
    let Some(id) = linux_userfaultfd_context(descriptor) else {
        return LINUX_EBADF;
    };
    let size = userfaultfd::MESSAGE_SIZE;
    let limit = usize::try_from(count).unwrap_or(usize::MAX) / size;
    if limit == 0 {
        return LINUX_EINVAL;
    }
    if !linux_writable_user_range_contains(address, size) {
        return LINUX_EFAULT;
    }
    let messages = match userfaultfd::read(id, limit.min(64)) {
        Ok(messages) => messages,
        Err(_) => return LINUX_EINVAL,
    };
    if messages.is_empty() {
        return LINUX_EAGAIN;
    }
    for (index, message) in messages.iter().enumerate() {
        if !copy_to_linux_user(address + (index * size) as u64, &message.to_bytes()) {
            return if index == 0 {
                LINUX_EFAULT
            } else {
                (index * size) as u64
            };
        }
    }
    (messages.len() * size) as u64
}

/// poll's events for a userfaultfd: POLLIN with a fault to read. Before
/// UFFDIO_API, and on a descriptor without O_NONBLOCK, POLLERR, as Linux
/// reports.
pub(super) fn linux_userfaultfd_poll_events(descriptor: u64, id: u64, requested: u16) -> u16 {
    match userfaultfd::readable(id) {
        Some(_) if !linux_socket_nonblocking(descriptor) => LINUX_POLLERR,
        Some(true) => requested & (LINUX_POLLIN | LINUX_POLLRDNORM),
        Some(false) => 0,
        None => LINUX_POLLERR,
    }
}

fn linux_context_error(error: ContextError) -> u64 {
    match error {
        ContextError::Invalid => LINUX_EINVAL,
        ContextError::Busy => LINUX_EBUSY,
        ContextError::NoMemory => LINUX_ENOMEM,
    }
}

/// `count` u64 words of an ioctl's argument.
fn linux_userfaultfd_words<const N: usize>(argument: u64) -> Result<[u64; N], u64> {
    let mut words = [0_u64; N];
    let mut bytes = [0_u8; 64];
    let bytes = &mut bytes[..N * 8];
    if !copy_from_linux_user(argument, bytes) {
        return Err(LINUX_EFAULT);
    }
    for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_ne_bytes(*chunk);
    }
    Ok(words)
}

fn linux_userfaultfd_put(address: u64, value: u64) -> bool {
    copy_to_linux_user(address, &value.to_ne_bytes())
}

/// A range of whole pages in user space: Linux's validate_range.
fn linux_userfaultfd_range(start: u64, length: u64) -> Result<(u64, u64), u64> {
    if !start.is_multiple_of(PAGE) || !length.is_multiple_of(PAGE) || length == 0 {
        return Err(LINUX_EINVAL);
    }
    match start.checked_add(length) {
        Some(end) if end <= 1 << 47 => Ok((start, end)),
        _ => Err(LINUX_EINVAL),
    }
}

/// Whether `page` is an anonymous page with nothing in it yet.
fn linux_page_missing(page: u64) -> bool {
    let state = address_space::current_linux_runtime_page(page);
    state.occupied && state.frame.is_none() && !state.file && state.protection != 0
}

/// Whether `page` is a shared file page with contents in its file but not
/// mapped here: a minor fault's page.
fn linux_page_minor(page: u64) -> bool {
    address_space::current_linux_page_past_eof(page)
        && linux_shared_file_page(page).is_some_and(|(handle, offset)| {
            crate::linux_overlay::metadata(handle)
                .is_some_and(|metadata| offset < metadata.size.next_multiple_of(PAGE_SIZE))
        })
}

/// Whether `page` maps a file (shared or private), as minor-fault
/// registration needs: Linux takes shmem and hugetlbfs files, and the
/// files of a domain's overlay live in memory as shmem's do.
fn linux_file_backed_page(page: u64) -> bool {
    crate::linux_areas::area_at(
        linux_execution_instance(),
        current_linux_process_pid(),
        page,
    )
    .is_some_and(|area| matches!(area.backing, crate::linux_areas::Backing::File { .. }))
}

/// Fills missing page `page` with `contents` (zeros past their end).
fn linux_fill_missing_page(page: u64, contents: &[u8]) -> bool {
    let state = address_space::current_linux_runtime_page(page);
    let Some([frame]) = memory::allocate_user_frames::<1>() else {
        return false;
    };
    if !address_space::prepare_linux_frame(frame.address(), contents)
        || !address_space::materialize_current_linux_runtime_page(
            page,
            frame,
            state.protection,
            false,
        )
    {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return false;
    }
    true
}

/// The user page fault `fault` is a userfaultfd context's to resolve:
/// reports it and sends the faulting thread to wait (true). False when
/// no context registered the page for this kind of fault.
pub(super) fn linux_userfault(frame: &mut UserFaultFrame, fault: domain::FaultMetadata) -> bool {
    if !userfaultfd::active()
        || fault.vector != 14
        || !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::SeqCst)
        || fault.address >= 1 << 47
    {
        return false;
    }
    let page = fault.address & !(PAGE - 1);
    let (instance, pid) = (linux_execution_instance(), current_linux_process_pid());
    let modes = userfaultfd::page_modes(instance, pid, page);
    if modes == 0 {
        return false;
    }
    let present = fault.error & 1 != 0;
    let write = fault.error & 2 != 0;
    let state = address_space::current_linux_runtime_page(page);
    let kind = if present {
        if !write || modes & MODE_WP == 0 {
            return false;
        }
        Kind::WriteProtect
    } else if modes & MODE_MISSING != 0 && linux_page_missing(page) {
        if write && state.protection & LINUX_PROT_WRITE as u8 == 0 {
            return false;
        }
        Kind::Missing
    } else if modes & MODE_MINOR != 0 && linux_page_minor(page) {
        Kind::Minor
    } else {
        return false;
    };
    let thread = current_linux_tid().unwrap_or(pid);
    if userfaultfd::fault(instance, pid, thread, fault.address, kind, write) != Fault::Reported {
        return false;
    }
    wake_linux_descriptor_waits();
    linux_wait_at_fault(frame)
}

/// Sends the faulting thread to the vDSO's preemption entry, which yields
/// it with the faulting instruction as the place to go on from.
fn linux_wait_at_fault(frame: &mut UserFaultFrame) -> bool {
    let Some(entry) = crate::linux_elf::vdso_preempt_entry() else {
        return false;
    };
    let context = frame.context();
    if (entry..entry + 9).contains(&context.rip)
        || !frame.redirect(entry, USER_CODE_SELECTOR, USER_DATA_SELECTOR)
    {
        return false;
    }
    *LINUX_PREEMPTED_CONTEXT[linux_cpu_slot()].lock() = Some(LinuxPreemptedContext {
        pid: current_linux_process_pid(),
        general: [
            context.rax,
            context.rbx,
            context.rcx,
            context.rdx,
            context.rsi,
            context.rdi,
            context.rbp,
            context.r8,
            context.r9,
            context.r10,
            context.r11,
            context.r12,
            context.r13,
            context.r14,
            context.r15,
        ],
        rip: context.rip,
        rsp: context.rsp,
        rflags: context.rflags,
        signal: false,
    });
    true
}

/// The ioctls of a userfaultfd. Every one but UFFDIO_API is EINVAL before
/// it; the range ioctls work on the caller's own memory.
pub(super) fn linux_userfaultfd_ioctl(descriptor: u64, request: u64, argument: u64) -> u64 {
    let Some(id) = linux_userfaultfd_context(descriptor) else {
        return LINUX_EBADF;
    };
    let request = request as u32;
    if request == UFFDIO_API {
        return linux_userfaultfd_api(id, argument);
    }
    if userfaultfd::features(id).is_none() {
        return LINUX_EINVAL;
    }
    if userfaultfd::process(id) != Some((linux_execution_instance(), current_linux_process_pid())) {
        return LINUX_EINVAL;
    }
    let result = match request {
        UFFDIO_REGISTER => linux_userfaultfd_register(id, argument),
        UFFDIO_UNREGISTER => linux_userfaultfd_unregister(id, argument),
        UFFDIO_WAKE => match linux_userfaultfd_words::<2>(argument)
            .and_then(|[start, length]| linux_userfaultfd_range(start, length))
        {
            Ok((start, end)) => {
                userfaultfd::resolve(id, start, end);
                0
            }
            Err(error) => error,
        },
        UFFDIO_COPY | UFFDIO_MOVE => linux_userfaultfd_copy(id, argument, request == UFFDIO_MOVE),
        UFFDIO_ZEROPAGE | UFFDIO_CONTINUE | UFFDIO_POISON => {
            linux_userfaultfd_fill(id, argument, request)
        }
        UFFDIO_WRITEPROTECT => linux_userfaultfd_writeprotect(id, argument),
        _ => LINUX_EINVAL,
    };
    wake_linux_descriptor_waits();
    result
}

/// UFFDIO_API: the handshake. Unknown API or features are EINVAL, and the
/// structure comes back zeroed, as on Linux.
fn linux_userfaultfd_api(id: u64, argument: u64) -> u64 {
    let [api, features, _] = match linux_userfaultfd_words::<3>(argument) {
        Ok(words) => words,
        Err(error) => return error,
    };
    let refuse = |error: u64| {
        if copy_to_linux_user(argument, &[0; 24]) {
            error
        } else {
            LINUX_EFAULT
        }
    };
    if api != UFFD_API {
        return refuse(LINUX_EINVAL);
    }
    if features & FEATURE_EVENT_FORK != 0
        && !current_linux_credentials()
            .is_some_and(|credentials| credentials.has(ginux_credentials::capability::SYS_PTRACE))
    {
        return refuse(LINUX_EPERM);
    }
    if features & !FEATURES != 0 {
        return refuse(LINUX_EINVAL);
    }
    let mut reply = [0_u8; 24];
    reply[..8].copy_from_slice(&UFFD_API.to_ne_bytes());
    reply[8..16].copy_from_slice(&FEATURES.to_ne_bytes());
    reply[16..].copy_from_slice(&UFFD_API_IOCTLS.to_ne_bytes());
    if !copy_to_linux_user(argument, &reply) {
        return LINUX_EFAULT;
    }
    match userfaultfd::negotiate(id, features) {
        Ok(()) => 0,
        Err(_) => refuse(LINUX_EINVAL),
    }
}

/// UFFDIO_REGISTER: every page of the range must be mapped, a MINOR range
/// shared; the reply lists the ioctls the range takes.
fn linux_userfaultfd_register(id: u64, argument: u64) -> u64 {
    let [start, length, mode] = match linux_userfaultfd_words::<3>(argument) {
        Ok(words) => words,
        Err(error) => return error,
    };
    if mode == 0 || mode & !u64::from(MODE_MISSING | MODE_WP | MODE_MINOR) != 0 {
        return LINUX_EINVAL;
    }
    let (start, end) = match linux_userfaultfd_range(start, length) {
        Ok(range) => range,
        Err(error) => return error,
    };
    let fits = (start..end).step_by(PAGE_SIZE).all(|page| {
        address_space::current_linux_runtime_page(page).occupied
            && (mode & u64::from(MODE_MINOR) == 0 || linux_file_backed_page(page))
    });
    if !fits {
        return LINUX_EINVAL;
    }
    if let Err(error) = userfaultfd::register(id, start, end, mode as u8) {
        return linux_context_error(error);
    }
    let mut ioctls = UFFD_API_RANGE_IOCTLS;
    if mode & u64::from(MODE_WP) == 0 {
        ioctls &= !UFFDIO_WRITEPROTECT_BIT;
    }
    if mode & u64::from(MODE_MINOR) == 0 {
        ioctls &= !UFFDIO_CONTINUE_BIT;
    }
    if linux_userfaultfd_put(argument + 24, ioctls) {
        0
    } else {
        LINUX_EFAULT
    }
}

fn linux_userfaultfd_unregister(id: u64, argument: u64) -> u64 {
    let (start, end) = match linux_userfaultfd_words::<2>(argument)
        .and_then(|[start, length]| linux_userfaultfd_range(start, length))
    {
        Ok(range) => range,
        Err(error) => return error,
    };
    match userfaultfd::unregister(id, start, end) {
        Ok(protected) => {
            for (page, protection) in protected {
                let _ = address_space::protect_current_linux_runtime_page(page, protection);
            }
            0
        }
        Err(error) => linux_context_error(error),
    }
}

/// UFFDIO_COPY (and, with `moving`, UFFDIO_MOVE): fills the missing pages
/// of `dst` with the bytes at `src`; a move then leaves `src` empty. The
/// bytes done go to the structure's last field; part of the range done is
/// EAGAIN.
fn linux_userfaultfd_copy(id: u64, argument: u64, moving: bool) -> u64 {
    let [destination, source, length, mode] = match linux_userfaultfd_words::<4>(argument) {
        Ok(words) => words,
        Err(error) => return error,
    };
    let (start, end) = match linux_userfaultfd_range(destination, length) {
        Ok(range) => range,
        Err(error) => return error,
    };
    let source_valid = if moving {
        linux_userfaultfd_range(source, length).is_ok()
    } else {
        source.checked_add(length).is_some_and(|end| end <= 1 << 47)
    };
    if !source_valid {
        return LINUX_EINVAL;
    }
    let allowed = if moving {
        MODE_DONTWAKE | MOVE_MODE_ALLOW_SRC_HOLES
    } else {
        MODE_DONTWAKE | MODE_FILL_WP
    };
    if mode & !allowed != 0 {
        return LINUX_EINVAL;
    }
    let mut done = 0_u64;
    let mut failure = 0;
    let mut contents = [0_u8; PAGE_SIZE];
    for page in (start..end).step_by(PAGE_SIZE) {
        let from = source + (page - start);
        if userfaultfd::modes(id, page, page + PAGE) == 0 {
            failure = LINUX_ENOENT;
            break;
        }
        if !linux_page_missing(page) {
            failure = LINUX_EEXIST;
            break;
        }
        let source_state = address_space::current_linux_runtime_page(from);
        if moving && (source_state.shared || source_state.file || !source_state.occupied) {
            failure = LINUX_EINVAL;
            break;
        }
        let hole = moving && source_state.frame.is_none();
        if hole && mode & MOVE_MODE_ALLOW_SRC_HOLES == 0 {
            failure = LINUX_ENOENT;
            break;
        }
        if hole {
            done += PAGE;
            continue;
        }
        if !copy_from_linux_user(from, &mut contents) {
            failure = LINUX_EFAULT;
            break;
        }
        if !linux_fill_missing_page(page, &contents) {
            failure = LINUX_ENOMEM;
            break;
        }
        if moving {
            let removed = address_space::remove_current_linux_runtime_page(from);
            let reserved = address_space::reserve_current_linux_runtime_page(
                from,
                source_state.protection,
                false,
                false,
            );
            if reserved.is_none() || !release_linux_runtime_page(removed) {
                failure = LINUX_EFAULT;
                break;
            }
        }
        if !moving && mode & MODE_FILL_WP != 0 {
            linux_userfaultfd_protect_page(id, page);
        }
        done += PAGE;
    }
    linux_userfaultfd_finish(id, argument + 24, start, done, length, failure, mode)
}

/// Reports a fill's progress at `field`, wakes the faults on what was done
/// (unless DONTWAKE), and returns the ioctl's result.
fn linux_userfaultfd_finish(
    id: u64,
    field: u64,
    start: u64,
    done: u64,
    length: u64,
    failure: u64,
    mode: u64,
) -> u64 {
    let reported = if done == 0 && failure != 0 {
        failure
    } else {
        done
    };
    if !linux_userfaultfd_put(field, reported) {
        return LINUX_EFAULT;
    }
    if done == 0 {
        return failure;
    }
    if mode & MODE_DONTWAKE == 0 {
        userfaultfd::resolve(id, start, start + done);
    }
    if done == length {
        0
    } else {
        LINUX_EAGAIN
    }
}

/// UFFDIO_ZEROPAGE, UFFDIO_CONTINUE and UFFDIO_POISON: fill a range's
/// missing pages with zeros, map a minor range's file pages, or make
/// missing pages SIGBUS to touch.
fn linux_userfaultfd_fill(id: u64, argument: u64, request: u32) -> u64 {
    let [start, length, mode] = match linux_userfaultfd_words::<3>(argument) {
        Ok(words) => words,
        Err(error) => return error,
    };
    let (start, end) = match linux_userfaultfd_range(start, length) {
        Ok(range) => range,
        Err(error) => return error,
    };
    let allowed = if request == UFFDIO_CONTINUE {
        MODE_DONTWAKE | MODE_FILL_WP
    } else {
        MODE_DONTWAKE
    };
    if mode & !allowed != 0 {
        return LINUX_EINVAL;
    }
    let mut done = 0_u64;
    let mut failure = 0;
    for page in (start..end).step_by(PAGE_SIZE) {
        let modes = userfaultfd::modes(id, page, page + PAGE);
        let result = match request {
            _ if modes == 0 => Err(LINUX_ENOENT),
            UFFDIO_CONTINUE if modes & MODE_MINOR == 0 => Err(LINUX_ENOENT),
            UFFDIO_CONTINUE if linux_page_minor(page) => {
                if linux_refill_shared_file_page(page) {
                    Ok(())
                } else {
                    Err(LINUX_ENOMEM)
                }
            }
            UFFDIO_CONTINUE
                if address_space::current_linux_runtime_page(page)
                    .frame
                    .is_some() =>
            {
                Err(LINUX_EEXIST)
            }
            // No page in the file to map.
            UFFDIO_CONTINUE => Err(LINUX_EFAULT),
            _ if !linux_page_missing(page) => Err(LINUX_EEXIST),
            UFFDIO_ZEROPAGE => {
                if linux_fill_missing_page(page, &[]) {
                    Ok(())
                } else {
                    Err(LINUX_ENOMEM)
                }
            }
            _ => {
                let protection = address_space::current_linux_runtime_page(page).protection;
                let removed = address_space::remove_current_linux_runtime_page(page);
                if release_linux_runtime_page(removed)
                    && address_space::reserve_current_linux_past_eof_page(page, protection, false)
                        .is_some()
                {
                    Ok(())
                } else {
                    Err(LINUX_ENOMEM)
                }
            }
        };
        if let Err(error) = result {
            failure = error;
            break;
        }
        if request == UFFDIO_CONTINUE && mode & MODE_FILL_WP != 0 {
            linux_userfaultfd_protect_page(id, page);
        }
        done += PAGE;
    }
    linux_userfaultfd_finish(id, argument + 24, start, done, length, failure, mode)
}

/// Write-protects present page `page` for context `id`.
fn linux_userfaultfd_protect_page(id: u64, page: u64) {
    let state = address_space::current_linux_runtime_page(page);
    if state.frame.is_none()
        || state.protection & LINUX_PROT_WRITE as u8 == 0
        || userfaultfd::protected(id, page)
    {
        return;
    }
    if userfaultfd::protect(id, page, state.protection).is_ok()
        && !address_space::protect_current_linux_runtime_page(
            page,
            state.protection & !(LINUX_PROT_WRITE as u8),
        )
    {
        let _ = userfaultfd::unprotect(id, page);
    }
}

/// UFFDIO_WRITEPROTECT: protects the range's present pages from writes, or
/// lifts the protection and wakes the faults waiting on it.
fn linux_userfaultfd_writeprotect(id: u64, argument: u64) -> u64 {
    let [start, length, mode] = match linux_userfaultfd_words::<3>(argument) {
        Ok(words) => words,
        Err(error) => return error,
    };
    let (start, end) = match linux_userfaultfd_range(start, length) {
        Ok(range) => range,
        Err(error) => return error,
    };
    if mode & !(WRITEPROTECT_MODE_WP | WRITEPROTECT_MODE_DONTWAKE) != 0
        || mode == WRITEPROTECT_MODE_WP | WRITEPROTECT_MODE_DONTWAKE
    {
        return LINUX_EINVAL;
    }
    if userfaultfd::modes(id, start, end) & MODE_WP == 0 {
        return LINUX_ENOENT;
    }
    for page in (start..end).step_by(PAGE_SIZE) {
        if mode & WRITEPROTECT_MODE_WP != 0 {
            linux_userfaultfd_protect_page(id, page);
        } else if let Some(protection) = userfaultfd::unprotect(id, page) {
            let _ = address_space::protect_current_linux_runtime_page(page, protection);
        }
    }
    if mode == 0 {
        userfaultfd::resolve(id, start, end);
    }
    0
}

/// Whether DONTNEED of shared page `page` should drop its mapping, so its
/// next touch is a minor fault a userfaultfd sees (UFFDIO_REGISTER_MODE_MINOR).
pub(super) fn linux_userfaultfd_minor_page(page: u64) -> bool {
    userfaultfd::active()
        && userfaultfd::page_modes(
            linux_execution_instance(),
            current_linux_process_pid(),
            page,
        ) & MODE_MINOR
            != 0
        && linux_shared_file_page(page).is_some()
}

/// Boot check of the userfaultfd system call and its handshake.
pub(super) fn verify_linux_userfaultfd_syscall() -> bool {
    const UPPER_REGISTER_BITS: u64 = 1_u64 << 32;
    let mapping = linux_runtime_mmap(
        0,
        PAGE_SIZE as u64,
        LINUX_PROT_READ | LINUX_PROT_WRITE,
        LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if !(LINUX_RUNTIME_DYNAMIC_MMAP_BASE..LINUX_RUNTIME_DYNAMIC_MMAP_BASE + (1 << 39))
        .contains(&mapping)
    {
        return false;
    }
    let descriptor = if linux_userfaultfd(2) == LINUX_EINVAL {
        linux_userfaultfd(UPPER_REGISTER_BITS | 1 | LINUX_O_NONBLOCK | LINUX_O_CLOEXEC)
    } else {
        LINUX_EBADF
    };
    let opened = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close_on_exec(descriptor)
        && linux_descriptor_fcntl(descriptor, LINUX_F_GETFL, 0) == (2 | LINUX_O_NONBLOCK);
    let mut api = [0_u8; 24];
    api[..8].copy_from_slice(&UFFD_API.to_ne_bytes());
    let early = opened && linux_userfaultfd_read(descriptor, mapping + 64, 32) == LINUX_EINVAL;
    let negotiated = early
        && copy_to_linux_user(mapping, &api)
        && linux_userfaultfd_ioctl(descriptor, UPPER_REGISTER_BITS | 0xc018_aa3f, mapping) == 0
        && copy_from_linux_user(mapping, &mut api)
        && u64::from_ne_bytes(api[..8].try_into().unwrap()) == UFFD_API
        && u64::from_ne_bytes(api[8..16].try_into().unwrap()) == FEATURES
        && u64::from_ne_bytes(api[16..24].try_into().unwrap()) == UFFD_API_IOCTLS;
    let empty = negotiated
        && linux_userfaultfd_read(descriptor, mapping + 64, 32) == LINUX_EAGAIN
        && linux_userfaultfd_read(descriptor, mapping + 64, 31) == LINUX_EINVAL
        && linux_userfaultfd_ioctl(descriptor, 0, mapping) == LINUX_EINVAL;
    let closed = descriptor < LINUX_AUX_DESCRIPTOR_LIMIT
        && linux_descriptor_close(descriptor) == 0
        && !linux_userfaultfd_descriptor(descriptor);
    let unmapped = linux_runtime_munmap(mapping, PAGE_SIZE as u64) == 0;
    empty && closed && unmapped
}
