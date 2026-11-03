//! KEYCTL_DH_COMPUTE: a Diffie-Hellman value g^x mod p from three "user"
//! keys, optionally run through the SP800-56A key derivation (SP800-108's
//! counter mode over a hash) with caller-supplied other information.

use alloc::vec::Vec;

use crate::crypto::{bignum, sha256};
use crate::keys::{copy, Lookup, Need};
use crate::permission::READ;
use crate::{no_memory, Caller, Error, KeyType, Keyrings};

/// The most a derivation may produce (`KEYCTL_KDF_MAX_OUTPUT_LEN`).
pub const KDF_OUTPUT_LIMIT: usize = 1024;
/// The longest other information (`KEYCTL_KDF_MAX_OI_LEN`).
pub const KDF_OTHER_INFO_LIMIT: usize = 64;
/// The longest hash name, counting its NUL (`CRYPTO_MAX_ALG_NAME`).
pub const HASH_NAME_LIMIT: usize = 128;
/// The smallest prime accepted, in bits.
const PRIME_BITS_MINIMUM: usize = 1536;

/// Checks a derivation's hash name: SHA-256 is the only hash here, so any
/// other name is ENOENT, as for a hash the kernel does not have.
pub fn check_hash(name: &[u8]) -> Result<(), Error> {
    match name {
        b"sha256" => Ok(()),
        _ => Err(Error::NotFound),
    }
}

/// `length` bytes derived from `input` (the shared secret followed by the
/// other information) with the hash `name`, which [`check_hash`] accepts.
pub fn derive(name: &[u8], input: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    check_hash(name)?;
    let mut output = Vec::new();
    output.try_reserve_exact(length).map_err(no_memory)?;
    let mut counter = 1_u32;
    while output.len() < length {
        let block = sha256::digest(&[&counter.to_be_bytes(), input]);
        let taken = (length - output.len()).min(block.len());
        output.extend_from_slice(&block[..taken]);
        counter = counter.wrapping_add(1);
    }
    Ok(output)
}

impl Keyrings {
    /// The shared value base^private mod prime, padded to the length of
    /// the prime without its leading zeros rounded up to eight bytes. Each id must name a "user" key
    /// the caller may read: one it cannot find or read is ENOKEY, another
    /// type or a key no longer valid EOPNOTSUPP. A prime under 1536 bits,
    /// zero or even, or a base or exponent longer than the prime, is
    /// EINVAL.
    pub fn dh_compute(
        &mut self,
        caller: &Caller,
        private: i32,
        prime: i32,
        base: i32,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        let prime = self.dh_data(caller, prime, now)?;
        let base = self.dh_data(caller, base, now)?;
        let private = self.dh_data(caller, private, now)?;
        if prime.len() * 8 < PRIME_BITS_MINIMUM
            || private.len() > prime.len()
            || base.len() > prime.len()
            || bignum::significant(&prime).is_empty()
        {
            return Err(Error::Invalid);
        }
        // Linux sizes the result as whole 64-bit limbs of the prime.
        let value = bignum::power_mod(&base, &private, &prime)?;
        let size = value.len().next_multiple_of(8);
        let mut padded = Vec::new();
        padded.try_reserve_exact(size).map_err(no_memory)?;
        padded.resize(size - value.len(), 0);
        padded.extend_from_slice(&value);
        Ok(padded)
    }

    fn dh_data(&mut self, caller: &Caller, id: i32, now: u64) -> Result<Vec<u8>, Error> {
        let handle = self
            .lookup(caller, id, Lookup::PLAIN, Need::Rights(READ), now)
            .map_err(|_| Error::NoKey)?;
        let key = self.get(handle.serial)?;
        if key.kind != KeyType::User || key.validate(now).is_err() {
            return Err(Error::NotSupported);
        }
        copy(key.payload.data())
    }
}
