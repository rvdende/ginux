//! The cryptography the key types need, in plain safe Rust: SHA-256 and
//! HMAC, AES-256-CBC, modular exponentiation and a DER reader. None of it
//! is constant-time; it serves keyctl(2), not a TLS stack.

pub(crate) mod aes;
pub(crate) mod bignum;
pub(crate) mod der;
pub(crate) mod sha256;

use alloc::vec::Vec;

use crate::{no_memory, Error};

/// Lower-case hex of `bytes`, appended to `text`.
pub(crate) fn push_hex(text: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    text.try_reserve(bytes.len() * 2).map_err(no_memory)?;
    for byte in bytes {
        text.push(DIGITS[usize::from(byte >> 4)]);
        text.push(DIGITS[usize::from(byte & 0xf)]);
    }
    Ok(())
}

/// The bytes that the hex digits in `hex` spell, upper or lower case; an
/// odd length or another character is EINVAL.
pub(crate) fn parse_hex(hex: &[u8]) -> Result<Vec<u8>, Error> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Invalid);
    }
    let digit = |byte: u8| char::from(byte).to_digit(16).ok_or(Error::Invalid);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(hex.len() / 2).map_err(no_memory)?;
    for pair in hex.as_chunks::<2>().0 {
        bytes.push((digit(pair[0])? << 4 | digit(pair[1])?) as u8);
    }
    Ok(bytes)
}
