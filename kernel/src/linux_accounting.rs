//! Process accounting (acct(2)): the file each domain's exiting
//! processes append their records to, named by the file's overlay
//! generation, in a domain set `privileged=true`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::control_abi::DOMAIN_LIMIT;

static FILES: [AtomicU64; DOMAIN_LIMIT] = [const { AtomicU64::new(0) }; DOMAIN_LIMIT];

/// Sets the accounting file of the domain in `instance` (0: off).
pub(crate) fn set_file(instance: usize, generation: u64) {
    if let Some(file) = FILES.get(instance) {
        file.store(generation, Ordering::Release);
    }
}

/// The accounting file of the domain in `instance`, if accounting is on.
pub(crate) fn file(instance: usize) -> Option<u64> {
    FILES
        .get(instance)
        .map(|file| file.load(Ordering::Acquire))
        .filter(|generation| *generation != 0)
}
