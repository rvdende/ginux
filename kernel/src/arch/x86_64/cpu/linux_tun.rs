//! /dev/net/tun (10:200): TUN and TAP devices for Linux programs.
//!
//! Each open of /dev/net/tun is an object descriptor of class
//! `LINUX_TUN_CLASS` naming a file of the network runtime's TUN table
//! (`linux_socket::tun_*`, `ginux_tun`). TUNSETIFF makes a device or
//! attaches to one; the device is then an interface of the domain's
//! network stack: rtnetlink and the SIOCGIF* ioctls list it, `ip link set
//! up` and `ip addr add` change it, what the stack routes to its subnet
//! the file reads, and what the file writes the stack receives. A read
//! with nothing to read waits (EAGAIN when non-blocking).

use super::*;

/// The object class of an open /dev/net/tun.
pub(super) const LINUX_TUN_CLASS: u8 = 15;
/// /dev/net/tun's device number, 10:200.
pub(super) const LINUX_TUN_DEVICE: u32 = (10 << 8) | 200;

const TUNSETNOCSUM: u32 = 0x4004_54c8;
const TUNSETIFF: u32 = 0x4004_54ca;
const TUNSETPERSIST: u32 = 0x4004_54cb;
const TUNSETOWNER: u32 = 0x4004_54cc;
const TUNSETGROUP: u32 = 0x4004_54ce;
const TUNGETFEATURES: u32 = 0x8004_54cf;
const TUNGETIFF: u32 = 0x8004_54d2;
const TUNSETQUEUE: u32 = 0x4004_54d9;
/// struct ifreq's size: the name, then the flags (a short) in the union.
const IFREQ_SIZE: usize = 40;
/// The largest read or write: a packet and its packet information.
const TRANSFER_LIMIT: usize = ginux_tun::PACKET_LIMIT + 4;

fn linux_tun_errno(errno: i32) -> u64 {
    (-i64::from(errno)) as u64
}

/// Opens /dev/net/tun: ENODEV in a domain without a network device.
pub(super) fn linux_open_tun(flags: u64) -> u64 {
    match crate::linux_socket::tun_open() {
        Ok(id) => linux_open_object(LINUX_TUN_CLASS, id, flags),
        Err(errno) => linux_tun_errno(errno),
    }
}

/// The open /dev/net/tun file descriptor `descriptor` names, if it is one.
pub(super) fn linux_tun_file(descriptor: u64) -> Option<u64> {
    match linux_object_descriptor(descriptor) {
        Some((LINUX_TUN_CLASS, id)) => Some(id),
        _ => None,
    }
}

/// Releases a closed /dev/net/tun file (`linux_release_objects`).
pub(super) fn linux_tun_release(class: u8, id: u64) {
    if class == LINUX_TUN_CLASS {
        crate::linux_socket::tun_close(id);
    }
}

/// Runs `call` with the caller as the device permission checks see it:
/// its effective ids and groups, and CAP_NET_ADMIN.
fn with_tun_caller<R>(call: impl FnOnce(&ginux_tun::Caller) -> R) -> R {
    let credentials = current_linux_credentials();
    let (user, group) = credentials.map_or((u32::MAX, u32::MAX), |credentials| {
        (credentials.user.effective, credentials.group.effective)
    });
    let administrator = credentials
        .is_some_and(|credentials| credentials.has(ginux_credentials::capability::NET_ADMIN));
    let groups = linux_process::with_live_process_groups(current_linux_process_pid(), |groups| {
        groups.to_vec()
    })
    .unwrap_or_default();
    call(&ginux_tun::Caller {
        user,
        group,
        groups: &groups,
        administrator,
    })
}

/// An ioctl on /dev/net/tun file `id`: `command` with `argument` (an
/// address, or the value itself for TUNSETPERSIST, TUNSETOWNER and
/// TUNSETGROUP). The commands that need a device are EBADFD without one;
/// others are EINVAL, as Linux's tun_chr_ioctl answers them.
pub(super) fn linux_tun_ioctl(id: u64, command: u32, argument: u64) -> u64 {
    let result = match command {
        TUNGETFEATURES => {
            return if copy_to_linux_user(argument, &ginux_tun::FEATURES.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            };
        }
        TUNSETIFF => {
            let mut ifreq = [0_u8; IFREQ_SIZE];
            if !copy_from_linux_user(argument, &mut ifreq) {
                return LINUX_EFAULT;
            }
            // Linux ends the name at its last byte.
            ifreq[15] = 0;
            let name_length = ifreq[..16].iter().position(|byte| *byte == 0).unwrap_or(15);
            let flags = u16::from_ne_bytes([ifreq[16], ifreq[17]]);
            let set = with_tun_caller(|caller| {
                crate::linux_socket::tun_set_iff(id, &ifreq[..name_length], flags, caller)
            });
            match set {
                Ok((name, flags)) => linux_tun_write_ifreq(argument, &mut ifreq, name, flags),
                Err(errno) => Err(errno),
            }
        }
        TUNSETQUEUE => {
            let mut ifreq = [0_u8; IFREQ_SIZE];
            if !copy_from_linux_user(argument, &mut ifreq) {
                return LINUX_EFAULT;
            }
            let flags = u16::from_ne_bytes([ifreq[16], ifreq[17]]);
            with_tun_caller(|caller| {
                crate::linux_socket::tun_set(
                    id,
                    crate::linux_socket::TunSetting::Queue(flags, caller),
                )
            })
        }
        TUNGETIFF => match crate::linux_socket::tun_get_iff(id) {
            Ok((name, flags)) => {
                let mut ifreq = [0_u8; IFREQ_SIZE];
                linux_tun_write_ifreq(argument, &mut ifreq, name, flags)
            }
            Err(errno) => Err(errno),
        },
        TUNSETPERSIST => crate::linux_socket::tun_set(
            id,
            crate::linux_socket::TunSetting::Persist(argument != 0),
        ),
        TUNSETOWNER => crate::linux_socket::tun_set(
            id,
            crate::linux_socket::TunSetting::Owner(argument as u32),
        ),
        TUNSETGROUP => crate::linux_socket::tun_set(
            id,
            crate::linux_socket::TunSetting::Group(argument as u32),
        ),
        // Checksums are not offloaded: nothing to switch off.
        TUNSETNOCSUM => crate::linux_socket::tun_get_iff(id).map(|_| ()),
        _ => match crate::linux_socket::tun_get_iff(id) {
            Ok(_) => Err(ginux_tun::EINVAL),
            Err(errno) => Err(errno),
        },
    };
    result.map_or_else(linux_tun_errno, |()| 0)
}

/// Writes a device's name and flags into the caller's struct ifreq at
/// `address` (`ifreq` holds what to keep of the rest).
fn linux_tun_write_ifreq(
    address: u64,
    ifreq: &mut [u8; IFREQ_SIZE],
    name: ginux_tun::Name,
    flags: u16,
) -> Result<(), i32> {
    const EFAULT: i32 = 14;
    ifreq[..16].fill(0);
    ifreq[..name.as_bytes().len()].copy_from_slice(name.as_bytes());
    ifreq[16..18].copy_from_slice(&flags.to_ne_bytes());
    if copy_to_linux_user(address, ifreq) {
        Ok(())
    } else {
        Err(EFAULT)
    }
}

/// read(2) of /dev/net/tun file `id`: one packet (EAGAIN with none; the
/// system call layer waits for one on a blocking descriptor).
pub(super) fn linux_tun_read(id: u64, address: u64, count: u64) -> u64 {
    let length = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(TRANSFER_LIMIT);
    let mut buffer = Vec::new();
    if buffer.try_reserve_exact(length).is_err() {
        return LINUX_ENOMEM;
    }
    buffer.resize(length, 0);
    match crate::linux_socket::tun_read(id, &mut buffer) {
        Ok(read) if copy_to_linux_user(address, &buffer[..read]) => read as u64,
        Ok(_) => LINUX_EFAULT,
        Err(errno) => linux_tun_errno(errno),
    }
}

/// write(2) of /dev/net/tun file `id`: one packet for the stack.
pub(super) fn linux_tun_write(id: u64, address: u64, count: u64) -> u64 {
    let Ok(length) = usize::try_from(count) else {
        return LINUX_EINVAL;
    };
    if length > TRANSFER_LIMIT {
        return LINUX_EINVAL;
    }
    let mut buffer = Vec::new();
    if buffer.try_reserve_exact(length).is_err() {
        return LINUX_ENOMEM;
    }
    buffer.resize(length, 0);
    if !copy_from_linux_user(address, &mut buffer) {
        return LINUX_EFAULT;
    }
    crate::linux_socket::tun_write(id, &buffer)
        .map_or_else(linux_tun_errno, |written| written as u64)
}

/// poll's events for /dev/net/tun file `id`: readable with a packet
/// waiting, always writable.
pub(super) fn linux_tun_poll_events(id: u64, requested: u16) -> u16 {
    let readable = if crate::linux_socket::tun_readable(id).unwrap_or(false) {
        LINUX_POLLIN | LINUX_POLLRDNORM
    } else {
        0
    };
    requested & (readable | LINUX_POLLOUT)
}
