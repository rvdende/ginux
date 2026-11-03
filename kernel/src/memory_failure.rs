//! Memory taken out of service, as Linux's memory-failure handling
//! (CONFIG_MEMORY_FAILURE) takes it: a soft-offlined page's contents move
//! to another frame (MADV_SOFT_OFFLINE), and the frame it left is kept
//! here, allocated and unused, so that it is never handed out again.

use alloc::vec::Vec;

use crate::memory::FrameLease;
use crate::sync::{LockRank, SpinLock};

/// The frames taken out of service.
static RETIRED: SpinLock<Vec<FrameLease>> = SpinLock::new(LockRank::MEMORY_FAILURE, Vec::new());

/// Takes `frame`, whose last user let it go, out of service for good.
pub(crate) fn retire(frame: FrameLease) {
    RETIRED.lock().push(frame);
}
