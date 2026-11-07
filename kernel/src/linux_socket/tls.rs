//! Kernel TLS on TCP sockets (TCP_ULP "tls", SOL_TLS), as Linux's net/tls
//! software path gives it: the record layer is `ginux_ktls`; this wires it
//! between a socket's callers and its connection (a local loopback pair or
//! smoltcp).
//!
//! With TLS_TX set, what a process sends (send, write, sendmsg, sendfile,
//! splice) is sealed into records, of the type TLS_SET_RECORD_TYPE gave
//! the send or application_data, and the sealed bytes wait in `pending`
//! until the connection takes them. With TLS_RX set, what arrives is
//! opened record by record: reads return plaintext, stopping where the
//! record type changes; a record that is not application data needs a
//! control buffer (recvmsg's TLS_GET_RECORD_TYPE), else the read is EIO. A
//! record that fails to open makes this and every later read EBADMSG.
//! Once the upper layer is set, the socket can no longer be disconnected
//! (EOPNOTSUPP) or listen (EINVAL), as in Linux 6.12.

use super::*;

/// The most sealed bytes a socket holds for its connection; a send past
/// it waits.
const PENDING_LIMIT: usize = 256 * 1024;

const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOPROTOOPT: i32 = 92;
pub(super) const EOPNOTSUPP: i32 = 95;
const ENOTCONN: i32 = 107;

/// A TCP socket's TLS upper layer.
#[derive(Default)]
pub(super) struct Tls {
    tx: Option<ginux_ktls::Sealer>,
    rx: Option<ginux_ktls::Opener>,
    /// Sealed bytes the connection has not taken yet.
    pending: Vec<u8>,
    /// The type of the next record sent (TLS_SET_RECORD_TYPE), once.
    record_type: Option<u8>,
    /// A record opened but not read whole: its type, plaintext, and how
    /// much of it was read.
    plain: Option<(u8, Vec<u8>, usize)>,
    /// A record that failed to open: every read answers this.
    error: Option<i32>,
    /// The connection delivered its end.
    ended: bool,
    /// The current recvmsg takes control messages.
    control: bool,
    /// The type of the records the last read returned.
    last_type: Option<u8>,
    zerocopy_ro: bool,
    expect_no_pad: bool,
}

/// TLS_TX_ZEROCOPY_RO or TLS_RX_EXPECT_NO_PAD.
#[derive(Clone, Copy)]
pub(crate) enum TlsFlag {
    ZerocopyReadOnly,
    ExpectNoPad,
}

impl Sockets {
    fn tls_state(&self, id: SlotId) -> Option<&Tls> {
        self.slot(id)?.tls.as_deref()
    }

    fn tls_state_mut(&mut self, id: SlotId) -> Option<&mut Tls> {
        self.slot_mut(id)?.tls.as_deref_mut()
    }

    /// Whether socket `id` sends through TLS.
    pub(super) fn tls_sends(&self, id: SlotId) -> bool {
        self.tls_state(id).is_some_and(|tls| tls.tx.is_some())
    }

    /// Whether socket `id` receives through TLS.
    pub(super) fn tls_receives(&self, id: SlotId) -> bool {
        self.tls_state(id).is_some_and(|tls| tls.rx.is_some())
    }

    /// Whether socket `id` has the TLS upper layer.
    pub(super) fn tls_attached(&self, id: SlotId) -> bool {
        self.tls_state(id).is_some()
    }

    /// Whether TCP socket `id` is connected (TCP_ESTABLISHED).
    fn tcp_established(&self, id: SlotId) -> bool {
        let Some(state) = self.slot(id).filter(|state| state.kind == Kind::Tcp) else {
            return false;
        };
        if state.listening {
            return false;
        }
        if state.peer.is_some() {
            return !state.peer_closed;
        }
        let (Some(runtime), Some(handle)) = (self.runtime.as_ref(), state.handle) else {
            return false;
        };
        runtime.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Established
    }

    /// setsockopt(SOL_TCP, TCP_ULP, name): "tls" on a connected TCP socket,
    /// once (EEXIST after); another name is ENOENT (no such module), an
    /// unconnected socket ENOTCONN.
    pub(super) fn set_ulp(&mut self, id: SlotId, name: &[u8]) -> Result<(), i32> {
        self.poll();
        if self.slot(id).is_none_or(|state| state.kind != Kind::Tcp) {
            return Err(ENOPROTOOPT);
        }
        if self.tls_attached(id) {
            return Err(EEXIST);
        }
        if name != b"tls" {
            return Err(ENOENT);
        }
        if !self.tcp_established(id) {
            return Err(ENOTCONN);
        }
        self.slot_mut(id).ok_or(EINVAL)?.tls = Some(Box::default());
        Ok(())
    }

    /// setsockopt(SOL_TLS, TLS_TX or TLS_RX): a direction's keys, once
    /// (EBUSY after); ENOPROTOOPT without the upper layer.
    pub(super) fn set_tls_crypto(
        &mut self,
        id: SlotId,
        receive: bool,
        bytes: &[u8],
    ) -> Result<(), i32> {
        let tls = self.tls_state_mut(id).ok_or(ENOPROTOOPT)?;
        if if receive {
            tls.rx.is_some()
        } else {
            tls.tx.is_some()
        } {
            return Err(EBUSY);
        }
        let info = ginux_ktls::CryptoInfo::parse(bytes)?;
        if receive {
            tls.rx = Some(ginux_ktls::Opener::new(info));
        } else {
            tls.tx = Some(ginux_ktls::Sealer::new(info));
        }
        Ok(())
    }

    /// getsockopt(SOL_TLS, TLS_TX or TLS_RX): the direction's structure as
    /// it stands; EBUSY before it is set.
    pub(super) fn tls_crypto(&self, id: SlotId, receive: bool) -> Result<Vec<u8>, i32> {
        let tls = self.tls_state(id).ok_or(ENOPROTOOPT)?;
        let info = if receive {
            tls.rx.as_ref().map(ginux_ktls::Opener::crypto_info)
        } else {
            tls.tx.as_ref().map(ginux_ktls::Sealer::crypto_info)
        };
        info.ok_or(EBUSY)
    }

    pub(super) fn set_tls_flag(
        &mut self,
        id: SlotId,
        flag: TlsFlag,
        value: bool,
    ) -> Result<(), i32> {
        let tls = self.tls_state_mut(id).ok_or(ENOPROTOOPT)?;
        match flag {
            TlsFlag::ZerocopyReadOnly => tls.zerocopy_ro = value,
            TlsFlag::ExpectNoPad => tls.expect_no_pad = value,
        }
        Ok(())
    }

    pub(super) fn tls_flag(&self, id: SlotId, flag: TlsFlag) -> Result<bool, i32> {
        let tls = self.tls_state(id).ok_or(ENOPROTOOPT)?;
        Ok(match flag {
            TlsFlag::ZerocopyReadOnly => tls.zerocopy_ro,
            TlsFlag::ExpectNoPad => tls.expect_no_pad,
        })
    }

    /// The record type of the next send (sendmsg's TLS_SET_RECORD_TYPE); a
    /// socket that does not send through TLS ignores it.
    pub(super) fn set_tls_record_type(&mut self, id: SlotId, kind: u8) {
        if let Some(tls) = self.tls_state_mut(id).filter(|tls| tls.tx.is_some()) {
            tls.record_type = Some(kind);
        }
    }

    /// Whether the current receive takes control messages, and the record
    /// type the last one returned.
    pub(super) fn set_tls_control(&mut self, id: SlotId, control: bool) {
        if let Some(tls) = self.tls_state_mut(id) {
            tls.control = control;
            tls.last_type = None;
        }
    }

    pub(super) fn tls_last_type(&self, id: SlotId) -> Option<u8> {
        self.tls_state(id)?.last_type
    }

    /// Sends `input` as records: Ok once sealed (the connection takes the
    /// records as it can), WouldBlock while too much waits for it.
    pub(super) fn tls_send(
        &mut self,
        id: SlotId,
        input: &[u8],
        local_capacity: Option<usize>,
    ) -> Result<usize, Error> {
        self.tls_flush(id, local_capacity)?;
        let tls = self.tls_state_mut(id).ok_or(Error::Invalid)?;
        if tls.pending.len() >= PENDING_LIMIT {
            return Err(Error::WouldBlock);
        }
        let kind = tls
            .record_type
            .take()
            .unwrap_or(ginux_ktls::APPLICATION_DATA);
        let mut sealed = core::mem::take(&mut tls.pending);
        if sealed.try_reserve(input.len() + 64).is_err() {
            tls.pending = sealed;
            return Err(Error::Exhausted);
        }
        let Some(sealer) = tls.tx.as_mut() else {
            tls.pending = sealed;
            return Err(Error::Invalid);
        };
        sealer.seal(kind, input, &mut sealed);
        tls.pending = sealed;
        match self.tls_flush(id, local_capacity) {
            Ok(()) | Err(Error::WouldBlock) => Ok(input.len()),
            Err(error) => Err(error),
        }
    }

    /// Hands the connection what of the sealed records it takes.
    pub(super) fn tls_flush(&mut self, id: SlotId, capacity: Option<usize>) -> Result<(), Error> {
        loop {
            let Some(tls) = self.tls_state_mut(id) else {
                return Ok(());
            };
            let pending = core::mem::take(&mut tls.pending);
            if pending.is_empty() {
                return Ok(());
            }
            let sent = self.send_raw(id, &pending, None, capacity);
            let tls = self.tls_state_mut(id).ok_or(Error::Invalid)?;
            match sent {
                Ok(sent) if sent > 0 => tls.pending = pending[sent..].to_vec(),
                Ok(_) => {
                    tls.pending = pending;
                    return Ok(());
                }
                Err(error) => {
                    tls.pending = pending;
                    return Err(error);
                }
            }
        }
    }

    /// Moves what the connection delivered into the record opener, until a
    /// whole record waits or nothing more has come.
    fn tls_fill(&mut self, id: SlotId) -> Result<(), Error> {
        let mut scratch = [0_u8; 4096];
        loop {
            let ready = self
                .tls_state(id)
                .and_then(|tls| tls.rx.as_ref())
                .is_none_or(ginux_ktls::Opener::ready);
            if ready {
                return Ok(());
            }
            match self.recv_raw(id, &mut scratch) {
                Ok((0, _)) => {
                    if let Some(tls) = self.tls_state_mut(id) {
                        tls.ended = true;
                    }
                    return Ok(());
                }
                Ok((received, _)) => {
                    if let Some(opener) = self.tls_state_mut(id).and_then(|tls| tls.rx.as_mut()) {
                        opener.push(&scratch[..received]);
                    }
                }
                Err(Error::WouldBlock) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    /// The record the next read starts in, opened if need be: None while
    /// it has not all come.
    fn tls_current(&mut self, id: SlotId) -> Result<Option<u8>, Error> {
        loop {
            let tls = self.tls_state(id).ok_or(Error::Invalid)?;
            if let Some(error) = tls.error {
                return Err(Error::Errno(error));
            }
            if let Some((kind, ..)) = tls.plain {
                return Ok(Some(kind));
            }
            if !tls.rx.as_ref().is_some_and(ginux_ktls::Opener::ready) {
                self.tls_fill(id)?;
            }
            let tls = self.tls_state_mut(id).ok_or(Error::Invalid)?;
            let opened = match tls.rx.as_mut() {
                Some(opener) => opener.open(),
                None => return Err(Error::Invalid),
            };
            match opened {
                Ok(Some((kind, data))) => {
                    // An empty application data record has nothing to read.
                    if !(data.is_empty() && kind == ginux_ktls::APPLICATION_DATA) {
                        tls.plain = Some((kind, data, 0));
                    }
                }
                Ok(None) => return Ok(None),
                Err(error) => {
                    tls.error = Some(error);
                    return Err(Error::Errno(error));
                }
            }
        }
    }

    /// Reads plaintext into `output` (without taking it, for `peek`): the
    /// records of one type, as far as they have come. End of file once the
    /// connection ended between records; WouldBlock until a record is in.
    pub(super) fn tls_recv(
        &mut self,
        id: SlotId,
        output: &mut [u8],
        peek: bool,
    ) -> Result<usize, Error> {
        let control = self.tls_state(id).is_some_and(|tls| tls.control);
        let mut copied = 0;
        let mut returned: Option<u8> = None;
        loop {
            let current = match self.tls_current(id) {
                Ok(current) => current,
                Err(error) if copied == 0 => return Err(error),
                Err(_) => break,
            };
            let Some(kind) = current else {
                break;
            };
            if returned.is_some_and(|returned| returned != kind) {
                break;
            }
            if kind != ginux_ktls::APPLICATION_DATA && !control {
                if copied == 0 {
                    return Err(Error::Errno(EIO));
                }
                break;
            }
            returned = Some(kind);
            let tls = self.tls_state_mut(id).ok_or(Error::Invalid)?;
            let Some((_, data, offset)) = tls.plain.as_mut() else {
                break;
            };
            let length = (output.len() - copied).min(data.len() - *offset);
            output[copied..copied + length].copy_from_slice(&data[*offset..*offset + length]);
            copied += length;
            if peek {
                break;
            }
            *offset += length;
            if *offset == data.len() {
                tls.plain = None;
            }
            if kind != ginux_ktls::APPLICATION_DATA || copied == output.len() {
                break;
            }
        }
        let tls = self.tls_state_mut(id).ok_or(Error::Invalid)?;
        tls.last_type = returned;
        if returned.is_none() {
            let partial = tls.rx.as_ref().is_some_and(|opener| opener.buffered() > 0);
            return if tls.ended && !partial {
                Ok(0)
            } else {
                Err(Error::WouldBlock)
            };
        }
        Ok(copied)
    }

    /// Whether a TLS read would not wait (a record or an error waits, or
    /// the connection ended); None for a socket without TLS_RX.
    pub(super) fn tls_readable(&mut self, id: SlotId) -> Option<bool> {
        if !self.tls_receives(id) {
            return None;
        }
        let current = self.tls_current(id);
        let tls = self.tls_state(id)?;
        Some(current.is_err() || tls.plain.is_some() || tls.ended)
    }

    /// Whether a TLS send would not wait.
    pub(super) fn tls_writable(&self, id: SlotId) -> Option<bool> {
        self.tls_state(id)
            .filter(|tls| tls.tx.is_some())
            .map(|tls| tls.pending.len() < PENDING_LIMIT)
    }
}
