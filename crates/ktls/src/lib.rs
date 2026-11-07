#![forbid(unsafe_code)]
//! Kernel TLS's record layer (Linux's net/tls, the software path): what
//! setsockopt(SOL_TLS, TLS_TX or TLS_RX) gives a TCP socket once
//! TCP_ULP "tls" is set on it.
//!
//! A process does the TLS handshake itself and hands the kernel the keys
//! as a `struct tls12_crypto_info_aes_gcm_128` (or `_256`). From then on
//! what it writes goes out as TLS records ([`Sealer`]) and what arrives is
//! opened record by record ([`Opener`]):
//!
//! - TLS 1.2 (RFC 5246, RFC 5288): the nonce is the salt and an 8-byte
//!   explicit part sent before the ciphertext, which starts as the
//!   structure's `iv` and counts up per record; the additional data is
//!   the sequence number, type, version and length.
//! - TLS 1.3 (RFC 8446): records are application_data outside; the real
//!   type ends the encrypted inner plaintext; the nonce is the salt and
//!   `iv` XORed with the sequence number; the additional data is the
//!   record header.
//!
//! Both count records from the structure's `rec_seq`. AES-GCM is
//! RustCrypto's `aes-gcm`; ChaCha20-Poly1305 and AES-CCM are not offered
//! (EINVAL). This is pure byte and crypto work, tested on the host.

#![no_std]

extern crate alloc;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// SOL_TLS and its options.
pub const SOL_TLS: u64 = 282;
pub const TLS_TX: u64 = 1;
pub const TLS_RX: u64 = 2;
pub const TLS_TX_ZEROCOPY_RO: u64 = 3;
pub const TLS_RX_EXPECT_NO_PAD: u64 = 4;
/// The control messages that carry a record's type.
pub const TLS_SET_RECORD_TYPE: i32 = 1;
pub const TLS_GET_RECORD_TYPE: i32 = 2;

pub const TLS_1_2_VERSION: u16 = 0x0303;
pub const TLS_1_3_VERSION: u16 = 0x0304;
pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;

/// Record content types.
pub const CHANGE_CIPHER_SPEC: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APPLICATION_DATA: u8 = 23;

/// The most plaintext one record carries (TLS_MAX_PAYLOAD_SIZE).
pub const MAX_PLAINTEXT: usize = 16_384;
/// The record header: type, version, length.
pub const HEADER: usize = 5;
const TAG: usize = 16;
const EXPLICIT_NONCE: usize = 8;
/// The padding a TLS 1.3 record may carry past its content.
const MAX_PADDING: usize = 256;

/// The errno values the calls answer with.
pub const EINVAL: i32 = 22;
pub const EBADMSG: i32 = 74;
pub const EMSGSIZE: i32 = 90;

/// struct tls_crypto_info's size: version and cipher type.
pub const CRYPTO_INFO_HEADER: usize = 4;

/// The keys and counters of one direction (struct
/// tls12_crypto_info_aes_gcm_128 or _256).
#[derive(Clone)]
pub struct CryptoInfo {
    pub version: u16,
    pub cipher: u16,
    pub iv: [u8; 8],
    key: [u8; 32],
    pub salt: [u8; 4],
    pub rec_seq: u64,
}

impl CryptoInfo {
    fn key_length(cipher: u16) -> Option<usize> {
        match cipher {
            TLS_CIPHER_AES_GCM_128 => Some(16),
            TLS_CIPHER_AES_GCM_256 => Some(32),
            _ => None,
        }
    }

    /// The size of `cipher`'s structure.
    pub fn size(cipher: u16) -> Option<usize> {
        Self::key_length(cipher).map(|key| CRYPTO_INFO_HEADER + 8 + key + 4 + 8)
    }

    /// The version and cipher type at the start of `bytes`.
    pub fn header(bytes: &[u8]) -> Option<(u16, u16)> {
        let header = bytes.get(..CRYPTO_INFO_HEADER)?;
        Some((
            u16::from_ne_bytes([header[0], header[1]]),
            u16::from_ne_bytes([header[2], header[3]]),
        ))
    }

    /// The structure setsockopt(TLS_TX or TLS_RX) got, as Linux checks it:
    /// shorter than struct tls_crypto_info, a version other than 1.2 or
    /// 1.3, a cipher not offered, or a length other than the cipher's
    /// structure's is EINVAL.
    pub fn parse(bytes: &[u8]) -> Result<Self, i32> {
        let (version, cipher) = Self::header(bytes).ok_or(EINVAL)?;
        if version != TLS_1_2_VERSION && version != TLS_1_3_VERSION {
            return Err(EINVAL);
        }
        let key_length = Self::key_length(cipher).ok_or(EINVAL)?;
        if Self::size(cipher) != Some(bytes.len()) {
            return Err(EINVAL);
        }
        let mut at = CRYPTO_INFO_HEADER;
        let mut take = |length: usize| {
            let part = &bytes[at..at + length];
            at += length;
            part
        };
        let iv: [u8; 8] = take(8).try_into().map_err(|_| EINVAL)?;
        let mut key = [0_u8; 32];
        key[..key_length].copy_from_slice(take(key_length));
        let salt: [u8; 4] = take(4).try_into().map_err(|_| EINVAL)?;
        let rec_seq = u64::from_be_bytes(take(8).try_into().map_err(|_| EINVAL)?);
        Ok(Self {
            version,
            cipher,
            iv,
            key,
            salt,
            rec_seq,
        })
    }

    /// The structure getsockopt returns: with the direction's current
    /// explicit nonce and sequence number.
    pub fn encode(&self, iv: [u8; 8], rec_seq: u64) -> Vec<u8> {
        let key_length = Self::key_length(self.cipher).unwrap_or(16);
        let mut bytes = Vec::with_capacity(Self::size(self.cipher).unwrap_or(40));
        bytes.extend_from_slice(&self.version.to_ne_bytes());
        bytes.extend_from_slice(&self.cipher.to_ne_bytes());
        bytes.extend_from_slice(&iv);
        bytes.extend_from_slice(&self.key[..key_length]);
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&rec_seq.to_be_bytes());
        bytes
    }

    fn cipher(&self) -> Cipher {
        match self.cipher {
            TLS_CIPHER_AES_GCM_256 => Cipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(&self.key)
                    .unwrap_or_else(|_| unreachable!("a 32-byte key")),
            )),
            _ => Cipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&self.key[..16])
                    .unwrap_or_else(|_| unreachable!("a 16-byte key")),
            )),
        }
    }

    fn tls13(&self) -> bool {
        self.version == TLS_1_3_VERSION
    }

    /// The 12-byte nonce of record `sequence` (TLS 1.2: with explicit part
    /// `explicit`).
    fn nonce(&self, sequence: u64, explicit: [u8; 8]) -> [u8; 12] {
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        if self.tls13() {
            nonce[4..].copy_from_slice(&self.iv);
            for (byte, counter) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
                *byte ^= counter;
            }
        } else {
            nonce[4..].copy_from_slice(&explicit);
        }
        nonce
    }
}

/// The keyed cipher, boxed: its key schedules are large.
enum Cipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl Cipher {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8]) -> Tag {
        let nonce = Nonce::from_slice(nonce);
        let sealed = match self {
            Self::Aes128(cipher) => cipher.encrypt_in_place_detached(nonce, aad, data),
            Self::Aes256(cipher) => cipher.encrypt_in_place_detached(nonce, aad, data),
        };
        sealed.unwrap_or_else(|_| unreachable!("a record is within AES-GCM's length limit"))
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &mut [u8], tag: &[u8]) -> bool {
        let (nonce, tag) = (Nonce::from_slice(nonce), Tag::from_slice(tag));
        match self {
            Self::Aes128(cipher) => cipher.decrypt_in_place_detached(nonce, aad, data, tag),
            Self::Aes256(cipher) => cipher.decrypt_in_place_detached(nonce, aad, data, tag),
        }
        .is_ok()
    }
}

/// The additional data a TLS 1.2 record's tag covers.
fn tls12_aad(sequence: u64, kind: u8, length: usize) -> [u8; 13] {
    let mut aad = [0_u8; 13];
    aad[..8].copy_from_slice(&sequence.to_be_bytes());
    aad[8] = kind;
    aad[9..11].copy_from_slice(&TLS_1_2_VERSION.to_be_bytes());
    aad[11..].copy_from_slice(&(length as u16).to_be_bytes());
    aad
}

fn header(kind: u8, length: usize) -> [u8; HEADER] {
    let mut header = [0_u8; HEADER];
    header[0] = kind;
    header[1..3].copy_from_slice(&TLS_1_2_VERSION.to_be_bytes());
    header[3..].copy_from_slice(&(length as u16).to_be_bytes());
    header
}

/// The sending direction (TLS_TX).
pub struct Sealer {
    info: CryptoInfo,
    cipher: Cipher,
    sequence: u64,
    explicit: [u8; 8],
}

impl Sealer {
    pub fn new(info: CryptoInfo) -> Self {
        Self {
            cipher: info.cipher(),
            sequence: info.rec_seq,
            explicit: info.iv,
            info,
        }
    }

    /// The structure getsockopt(TLS_TX) returns.
    pub fn crypto_info(&self) -> Vec<u8> {
        let iv = if self.info.tls13() {
            self.info.iv
        } else {
            self.explicit
        };
        self.info.encode(iv, self.sequence)
    }

    /// Appends `data` to `output` as records of type `kind`, at most
    /// MAX_PLAINTEXT bytes each (one empty record for empty `data`).
    pub fn seal(&mut self, kind: u8, data: &[u8], output: &mut Vec<u8>) {
        let mut chunks = data.chunks(MAX_PLAINTEXT);
        let first = chunks.next().unwrap_or(&[]);
        self.seal_record(kind, first, output);
        for chunk in chunks {
            self.seal_record(kind, chunk, output);
        }
    }

    fn seal_record(&mut self, kind: u8, data: &[u8], output: &mut Vec<u8>) {
        let nonce = self.info.nonce(self.sequence, self.explicit);
        if self.info.tls13() {
            let inner = data.len() + 1;
            let header = header(APPLICATION_DATA, inner + TAG);
            output.extend_from_slice(&header);
            let start = output.len();
            output.extend_from_slice(data);
            output.push(kind);
            let tag = self.cipher.seal(&nonce, &header, &mut output[start..]);
            output.extend_from_slice(&tag);
        } else {
            output.extend_from_slice(&header(kind, EXPLICIT_NONCE + data.len() + TAG));
            output.extend_from_slice(&self.explicit);
            let start = output.len();
            output.extend_from_slice(data);
            let aad = tls12_aad(self.sequence, kind, data.len());
            let tag = self.cipher.seal(&nonce, &aad, &mut output[start..]);
            output.extend_from_slice(&tag);
            self.explicit = (u64::from_be_bytes(self.explicit).wrapping_add(1)).to_be_bytes();
        }
        self.sequence = self.sequence.wrapping_add(1);
    }
}

/// The receiving direction (TLS_RX): bytes from the connection go in,
/// opened records come out.
pub struct Opener {
    info: CryptoInfo,
    cipher: Cipher,
    sequence: u64,
    /// The explicit nonce of the record opened last (TLS 1.2), which
    /// getsockopt(TLS_RX) shows.
    explicit: [u8; 8],
    buffer: Vec<u8>,
}

impl Opener {
    pub fn new(info: CryptoInfo) -> Self {
        Self {
            cipher: info.cipher(),
            sequence: info.rec_seq,
            explicit: info.iv,
            info,
            buffer: Vec::new(),
        }
    }

    /// The structure getsockopt(TLS_RX) returns.
    pub fn crypto_info(&self) -> Vec<u8> {
        self.info.encode(self.explicit, self.sequence)
    }

    /// Takes bytes the connection delivered.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The bytes of incomplete records held.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// The overhead a record of this direction carries past its content:
    /// the tag, the explicit nonce (1.2) or the inner type (1.3).
    fn overhead(&self) -> usize {
        if self.info.tls13() {
            TAG + 1
        } else {
            TAG + EXPLICIT_NONCE
        }
    }

    /// The length of the record at the front, once its header is in, as
    /// Linux's tls_rx_msg_size checks it: a version other than TLS 1.2's
    /// in the header is EINVAL, a length past the largest record EMSGSIZE,
    /// one below the overhead EBADMSG.
    fn record_length(&self) -> Result<Option<usize>, i32> {
        let Some(header) = self.buffer.get(..HEADER) else {
            return Ok(None);
        };
        if header[1..3] != TLS_1_2_VERSION.to_be_bytes() {
            return Err(EINVAL);
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let padding = if self.info.tls13() { MAX_PADDING } else { 0 };
        if length > MAX_PLAINTEXT + self.overhead() + padding {
            return Err(EMSGSIZE);
        }
        if length < self.overhead() {
            return Err(EBADMSG);
        }
        Ok(Some(length))
    }

    /// Whether a whole record waits (or a bad header, which the next
    /// `open` reports).
    pub fn ready(&self) -> bool {
        match self.record_length() {
            Ok(Some(length)) => self.buffer.len() >= HEADER + length,
            Ok(None) => false,
            Err(_) => true,
        }
    }

    /// Opens the record at the front: its type and plaintext; None until
    /// all of it is in. A record that fails its tag, or a TLS 1.3 one with
    /// no content type, is EBADMSG.
    pub fn open(&mut self) -> Result<Option<(u8, Vec<u8>)>, i32> {
        let Some(length) = self.record_length()? else {
            return Ok(None);
        };
        if self.buffer.len() < HEADER + length {
            return Ok(None);
        }
        let record: Vec<u8> = self.buffer.drain(..HEADER + length).collect();
        let (header, body) = record.split_at(HEADER);
        let (kind, plaintext) = if self.info.tls13() {
            let nonce = self.info.nonce(self.sequence, [0; 8]);
            let (data, tag) = body.split_at(body.len() - TAG);
            let mut data = data.to_vec();
            if !self.cipher.open(&nonce, header, &mut data, tag) {
                return Err(EBADMSG);
            }
            // The content type is the last byte that is not padding.
            let end = data.iter().rposition(|byte| *byte != 0).ok_or(EBADMSG)?;
            let kind = data[end];
            data.truncate(end);
            (kind, data)
        } else {
            let explicit: [u8; 8] = body[..EXPLICIT_NONCE].try_into().map_err(|_| EBADMSG)?;
            let nonce = self.info.nonce(self.sequence, explicit);
            let (data, tag) = body[EXPLICIT_NONCE..].split_at(body.len() - EXPLICIT_NONCE - TAG);
            let mut data = data.to_vec();
            let aad = tls12_aad(self.sequence, header[0], data.len());
            if !self.cipher.open(&nonce, &aad, &mut data, tag) {
                return Err(EBADMSG);
            }
            self.explicit = explicit;
            (header[0], data)
        };
        self.sequence = self.sequence.wrapping_add(1);
        Ok(Some((kind, plaintext)))
    }
}

#[cfg(test)]
mod tests;
