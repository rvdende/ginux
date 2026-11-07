//! Kernel TLS's socket options and control messages: setsockopt and
//! getsockopt of TCP_ULP and SOL_TLS, sendmsg's TLS_SET_RECORD_TYPE and
//! recvmsg's TLS_GET_RECORD_TYPE (`linux_socket::tls`, `ginux_ktls`).

use super::*;

/// TCP_ULP: a TCP socket's upper-layer protocol, by name.
pub(super) const LINUX_TCP_ULP: u64 = 31;
/// The longest upper-layer name, its NUL included (TCP_ULP_NAME_MAX).
const ULP_NAME_MAX: usize = 16;
/// CMSG_LEN(1): a one-byte control message.
const RECORD_TYPE_MESSAGE: usize = 17;

fn linux_ktls_errno(errno: i32) -> u64 {
    (-i64::from(errno)) as u64
}

/// setsockopt(SOL_TCP, TCP_ULP): the name, up to TCP_ULP_NAME_MAX - 1
/// bytes or its NUL, as Linux copies it; a socket that is not TCP has no
/// SOL_TCP options (ENOPROTOOPT).
pub(super) fn linux_set_ulp(slot: crate::linux_socket::SlotId, value: u64, length: u64) -> u64 {
    if crate::linux_socket::kind(slot) != Some(crate::linux_socket::Kind::Tcp) {
        return LINUX_ENOPROTOOPT;
    }
    let mut name = [0_u8; ULP_NAME_MAX];
    let length = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(ULP_NAME_MAX - 1);
    if !copy_from_linux_user(value, &mut name[..length]) {
        return LINUX_EFAULT;
    }
    let end = name[..length]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(length);
    crate::linux_socket::set_ulp(slot, &name[..end]).map_or_else(linux_ktls_errno, |()| 0)
}

/// getsockopt(SOL_TCP, TCP_ULP): "tls", cut to the caller's length, or an
/// empty name.
pub(super) fn linux_get_ulp(slot: crate::linux_socket::SlotId, value: u64, length: u64) -> u64 {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let Ok(supplied) = usize::try_from(i32::from_ne_bytes(supplied)) else {
        return LINUX_EINVAL;
    };
    let name: &[u8] = if crate::linux_socket::tls_attached(slot) {
        b"tls"
    } else {
        b""
    };
    let copied = supplied.min(ULP_NAME_MAX).min(name.len());
    if !copy_to_linux_user(length, &(copied as u32).to_ne_bytes())
        || copied != 0 && !copy_to_linux_user(value, &name[..copied])
    {
        return LINUX_EFAULT;
    }
    0
}

/// setsockopt(SOL_TLS, ...): TLS_TX and TLS_RX take a crypto info
/// structure, TLS_TX_ZEROCOPY_RO and TLS_RX_EXPECT_NO_PAD an int.
pub(super) fn linux_tls_setsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    match option {
        ginux_ktls::TLS_TX | ginux_ktls::TLS_RX => {
            if value == 0 || length < ginux_ktls::CRYPTO_INFO_HEADER as u64 {
                return LINUX_EINVAL;
            }
            // Longer than any structure offered is EINVAL anyway; read no
            // more than that.
            let mut bytes = [0_u8; 64];
            let length = usize::try_from(length)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            if !copy_from_linux_user(value, &mut bytes[..length]) {
                return LINUX_EFAULT;
            }
            crate::linux_socket::set_tls_crypto(
                slot,
                option == ginux_ktls::TLS_RX,
                &bytes[..length],
            )
            .map_or_else(linux_ktls_errno, |()| 0)
        }
        ginux_ktls::TLS_TX_ZEROCOPY_RO | ginux_ktls::TLS_RX_EXPECT_NO_PAD => {
            if value == 0 || length != 4 {
                return LINUX_EINVAL;
            }
            let mut supplied = [0_u8; 4];
            if !copy_from_linux_user(value, &mut supplied) {
                return LINUX_EFAULT;
            }
            let flag = if option == ginux_ktls::TLS_TX_ZEROCOPY_RO {
                crate::linux_socket::TlsFlag::ZerocopyReadOnly
            } else {
                crate::linux_socket::TlsFlag::ExpectNoPad
            };
            crate::linux_socket::set_tls_flag(slot, flag, i32::from_ne_bytes(supplied) != 0)
                .map_or_else(linux_ktls_errno, |()| 0)
        }
        _ => LINUX_ENOPROTOOPT,
    }
}

/// getsockopt(SOL_TLS, ...): a direction's crypto info (the four-byte
/// header alone, or the cipher's whole structure; another length is
/// EINVAL), or a flag as an int.
pub(super) fn linux_tls_getsockopt(
    slot: crate::linux_socket::SlotId,
    option: u64,
    value: u64,
    length: u64,
) -> u64 {
    let mut supplied = [0_u8; 4];
    if !copy_from_linux_user(length, &mut supplied) {
        return LINUX_EFAULT;
    }
    let supplied = i32::from_ne_bytes(supplied);
    match option {
        ginux_ktls::TLS_TX | ginux_ktls::TLS_RX => {
            if value == 0 || supplied < ginux_ktls::CRYPTO_INFO_HEADER as i32 {
                return LINUX_EINVAL;
            }
            let info = match crate::linux_socket::tls_crypto(slot, option == ginux_ktls::TLS_RX) {
                Ok(info) => info,
                Err(errno) => return linux_ktls_errno(errno),
            };
            let wanted = supplied as usize;
            if wanted != ginux_ktls::CRYPTO_INFO_HEADER && wanted != info.len() {
                return LINUX_EINVAL;
            }
            if copy_to_linux_user(value, &info[..wanted]) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        ginux_ktls::TLS_TX_ZEROCOPY_RO | ginux_ktls::TLS_RX_EXPECT_NO_PAD => {
            if supplied != 4 {
                return LINUX_EINVAL;
            }
            let flag = if option == ginux_ktls::TLS_TX_ZEROCOPY_RO {
                crate::linux_socket::TlsFlag::ZerocopyReadOnly
            } else {
                crate::linux_socket::TlsFlag::ExpectNoPad
            };
            match crate::linux_socket::tls_flag(slot, flag) {
                Ok(set) if copy_to_linux_user(value, &i32::from(set).to_ne_bytes()) => 0,
                Ok(_) => LINUX_EFAULT,
                Err(errno) => linux_ktls_errno(errno),
            }
        }
        _ => LINUX_ENOPROTOOPT,
    }
}

/// sendmsg's control messages on a TLS sending socket: SOL_TLS
/// TLS_SET_RECORD_TYPE (one byte, not with MSG_MORE) sets the record type
/// of what this send carries; other levels are ignored, as Linux's
/// tls_process_cmsg ignores them. Some(error) when they are refused.
pub(super) fn linux_tls_send_control(
    slot: crate::linux_socket::SlotId,
    control: u64,
    length: u64,
    more: bool,
) -> Option<u64> {
    let mut bytes = [0_u8; 256];
    let length = usize::try_from(length)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    if !copy_from_linux_user(control, &mut bytes[..length]) {
        return Some(LINUX_EFAULT);
    }
    let mut at = 0;
    while at + 16 <= length {
        let message_length =
            usize::try_from(u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap()))
                .unwrap_or(usize::MAX);
        let level = i32::from_ne_bytes(bytes[at + 8..at + 12].try_into().unwrap());
        let kind = i32::from_ne_bytes(bytes[at + 12..at + 16].try_into().unwrap());
        if message_length < 16 || at + message_length > length {
            return Some(LINUX_EINVAL);
        }
        if u64::try_from(level).ok() == Some(ginux_ktls::SOL_TLS) {
            if kind != ginux_ktls::TLS_SET_RECORD_TYPE
                || message_length != RECORD_TYPE_MESSAGE
                || more
            {
                return Some(LINUX_EINVAL);
            }
            crate::linux_socket::set_tls_record_type(slot, bytes[at + 16]);
        }
        at += (message_length + 7) & !7;
    }
    None
}

/// Before a receive on a TLS socket: whether it takes control messages
/// (room for TLS_GET_RECORD_TYPE's).
pub(super) fn linux_tls_receive_control(slot: crate::linux_socket::SlotId, room: u64) {
    if crate::linux_socket::tls_receives(slot) {
        crate::linux_socket::set_tls_control(slot, room >= RECORD_TYPE_MESSAGE as u64);
    }
}

/// After recvmsg on a TLS socket: TLS_GET_RECORD_TYPE with the type of
/// what it returned, at `address` with `room` bytes left; the bytes it
/// took (CMSG_SPACE), or None when there was nothing to say.
pub(super) fn linux_tls_record_type_message(
    slot: crate::linux_socket::SlotId,
    address: u64,
    room: u64,
) -> Option<Result<u64, u64>> {
    if !crate::linux_socket::tls_receives(slot) {
        return None;
    }
    let kind = crate::linux_socket::tls_last_type(slot);
    crate::linux_socket::set_tls_control(slot, false);
    let kind = kind?;
    if room < RECORD_TYPE_MESSAGE as u64 {
        return Some(Err(0));
    }
    let mut message = [0_u8; 24];
    message[..8].copy_from_slice(&(RECORD_TYPE_MESSAGE as u64).to_ne_bytes());
    message[8..12].copy_from_slice(&(ginux_ktls::SOL_TLS as i32).to_ne_bytes());
    message[12..16].copy_from_slice(&ginux_ktls::TLS_GET_RECORD_TYPE.to_ne_bytes());
    message[16] = kind;
    let space = (room as usize).min(message.len());
    Some(if copy_to_linux_user(address, &message[..space]) {
        Ok(space as u64)
    } else {
        Err(LINUX_EFAULT)
    })
}
