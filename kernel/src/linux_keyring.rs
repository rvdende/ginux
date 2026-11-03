//! The key retention service of each domain (add_key, request_key, keyctl):
//! `ginux_keyrings` keeps the keys and checks every rule; this holds one set
//! of keys per domain instance.

use alloc::vec::Vec;

pub(crate) use ginux_keyrings::{Caller, Error, Keyrings, Output};

use crate::arch::x86_64::cpu;
use crate::linux_process;
use crate::sync::{LockRank, SpinLock};

/// Each domain instance's keys, created by its first key operation and
/// dropped when it stops.
static KEYRINGS: SpinLock<Vec<(usize, Keyrings)>> = SpinLock::new(LockRank::KEYRINGS, Vec::new());

/// Runs `operation` on the current domain's keys.
pub(crate) fn with<R>(
    operation: impl FnOnce(&mut Keyrings) -> Result<R, Error>,
) -> Result<R, Error> {
    let instance = linux_process::current_ipc_instance();
    let mut domains = KEYRINGS.lock();
    let index = match domains.iter().position(|(owner, _)| *owner == instance) {
        Some(index) => index,
        None => {
            domains.try_reserve(1).map_err(|_| Error::NoMemory)?;
            domains.push((instance, Keyrings::with_random(fill_random)));
            domains.len() - 1
        }
    };
    operation(&mut domains[index].1)
}

/// Random bytes for encrypted keys, from the CPU's generator as
/// getrandom(2) takes them; false when it has none.
fn fill_random(buffer: &mut [u8]) -> bool {
    buffer.chunks_mut(16).all(|chunk| {
        cpu::linux_startup_random().is_some_and(|random| {
            chunk.copy_from_slice(&random[..chunk.len()]);
            true
        })
    })
}

/// Drops the keys of the domain that is stopping.
pub(crate) fn teardown() -> bool {
    let instance = linux_process::current_ipc_instance();
    let removed = {
        let mut domains = KEYRINGS.lock();
        domains
            .iter()
            .position(|(owner, _)| *owner == instance)
            .map(|index| domains.swap_remove(index))
    };
    drop(removed);
    true
}
