//! Modular exponentiation of big unsigned integers given as big-endian
//! bytes, for Diffie-Hellman and RSA. Numbers are little-endian vectors of
//! 32-bit limbs; the exponentiation works in Montgomery form, so the
//! modulus must be odd, as Diffie-Hellman primes and RSA moduli are.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::keys::copy;
use crate::{no_memory, Error};

type Limbs = Vec<u32>;

fn zeroed(count: usize) -> Result<Limbs, Error> {
    let mut limbs = Vec::new();
    limbs.try_reserve_exact(count).map_err(no_memory)?;
    limbs.resize(count, 0);
    Ok(limbs)
}

/// The big-endian `bytes` as `count` limbs; `count` must hold them.
fn from_bytes(bytes: &[u8], count: usize) -> Result<Limbs, Error> {
    let mut limbs = zeroed(count)?;
    for (index, byte) in bytes.iter().rev().enumerate() {
        limbs[index / 4] |= u32::from(*byte) << (8 * (index % 4));
    }
    Ok(limbs)
}

/// The big-endian bytes without leading zeros: how Linux's MPI code sizes
/// a number.
pub(crate) fn significant(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn compare(a: &[u32], b: &[u32]) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

/// `a -= b` over equal lengths, returning the borrow.
fn subtract(a: &mut [u32], b: &[u32]) -> bool {
    let mut borrow = false;
    for (limb, other) in a.iter_mut().zip(b) {
        let (value, first) = limb.overflowing_sub(*other);
        let (value, second) = value.overflowing_sub(u32::from(borrow));
        *limb = value;
        borrow = first || second;
    }
    borrow
}

/// `value = 2 * value + bit (mod modulus)` for `value < modulus`.
fn double_add(value: &mut [u32], bit: bool, modulus: &[u32]) {
    let mut carry = u32::from(bit);
    for limb in value.iter_mut() {
        let next = *limb >> 31;
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    if carry != 0 || compare(value, modulus) != Ordering::Less {
        subtract(value, modulus);
    }
}

/// An odd modulus prepared for Montgomery multiplication with R = 2^(32n).
struct Montgomery {
    modulus: Limbs,
    /// -modulus^-1 mod 2^32.
    inverse: u32,
    /// R^2 mod modulus.
    r_squared: Limbs,
}

impl Montgomery {
    fn new(modulus: Limbs) -> Result<Self, Error> {
        let mut inverse = 1_u32;
        for _ in 0..5 {
            inverse = inverse.wrapping_mul(2_u32.wrapping_sub(modulus[0].wrapping_mul(inverse)));
        }
        let mut r_squared = zeroed(modulus.len())?;
        r_squared[0] = 1;
        for _ in 0..64 * modulus.len() {
            double_add(&mut r_squared, false, &modulus);
        }
        Ok(Self {
            modulus,
            inverse: inverse.wrapping_neg(),
            r_squared,
        })
    }

    /// a * b / R mod modulus, for a and b below the modulus.
    fn multiply(&self, a: &[u32], b: &[u32], scratch: &mut [u32]) -> Result<Limbs, Error> {
        let size = self.modulus.len();
        scratch.fill(0);
        for &digit in a {
            let mut carry = 0_u64;
            for (slot, &limb) in scratch.iter_mut().zip(b) {
                let value = u64::from(*slot) + u64::from(digit) * u64::from(limb) + carry;
                *slot = value as u32;
                carry = value >> 32;
            }
            let value = u64::from(scratch[size]) + carry;
            scratch[size] = value as u32;
            scratch[size + 1] = (value >> 32) as u32;
            let factor = scratch[0].wrapping_mul(self.inverse);
            let mut carry =
                (u64::from(scratch[0]) + u64::from(factor) * u64::from(self.modulus[0])) >> 32;
            for index in 1..size {
                let value = u64::from(scratch[index])
                    + u64::from(factor) * u64::from(self.modulus[index])
                    + carry;
                scratch[index - 1] = value as u32;
                carry = value >> 32;
            }
            let value = u64::from(scratch[size]) + carry;
            scratch[size - 1] = value as u32;
            scratch[size] = scratch[size + 1] + (value >> 32) as u32;
        }
        let mut result = zeroed(size)?;
        result.copy_from_slice(&scratch[..size]);
        if scratch[size] != 0 || compare(&result, &self.modulus) != Ordering::Less {
            subtract(&mut result, &self.modulus);
        }
        Ok(result)
    }
}

/// base^exponent mod modulus, as big-endian bytes padded to the
/// modulus's significant length. An even or zero modulus is EINVAL.
pub(crate) fn power_mod(base: &[u8], exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>, Error> {
    let modulus = significant(modulus);
    if modulus.last().is_none_or(|byte| byte & 1 == 0) {
        return Err(Error::Invalid);
    }
    if modulus == [1] {
        return copy(&[0]);
    }
    let size = modulus.len().div_ceil(4);
    let context = Montgomery::new(from_bytes(modulus, size)?)?;
    // Reduce the base bit by bit, so it may be any length.
    let mut reduced = zeroed(size)?;
    for byte in base {
        for bit in (0..8).rev() {
            double_add(&mut reduced, byte >> bit & 1 != 0, &context.modulus);
        }
    }
    let mut scratch = zeroed(size + 2)?;
    let base = context.multiply(&reduced, &context.r_squared, &mut scratch)?;
    let mut one = zeroed(size)?;
    one[0] = 1;
    // R mod modulus: one in Montgomery form.
    let mut result = context.multiply(&one, &context.r_squared, &mut scratch)?;
    for byte in significant(exponent) {
        for bit in (0..8).rev() {
            result = context.multiply(&result, &result, &mut scratch)?;
            if byte >> bit & 1 != 0 {
                result = context.multiply(&result, &base, &mut scratch)?;
            }
        }
    }
    let result = context.multiply(&result, &one, &mut scratch)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(modulus.len()).map_err(no_memory)?;
    for index in (0..modulus.len()).rev() {
        bytes.push((result[index / 4] >> (8 * (index % 4))) as u8);
    }
    Ok(bytes)
}

/// Whether the big-endian `value` is below the big-endian `modulus`.
pub(crate) fn less_than(value: &[u8], modulus: &[u8]) -> bool {
    let (value, modulus) = (significant(value), significant(modulus));
    value
        .len()
        .cmp(&modulus.len())
        .then_with(|| value.cmp(modulus))
        == Ordering::Less
}
