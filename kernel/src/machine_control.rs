//! Machine-wide state that root in a domain set `privileged=true` may
//! change through reboot(2): how the machine resets when the kernel shuts
//! down, and whether Ctrl-Alt-Del reboots at once.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// UEFI ResetSystem kinds.
pub(crate) const RESET_COLD: u32 = 0;
pub(crate) const RESET_SHUTDOWN: u32 = 2;

/// The reset the kernel's clean shutdown ends with.
static RESET_KIND: AtomicU32 = AtomicU32::new(RESET_SHUTDOWN);
/// reboot(LINUX_REBOOT_CMD_CAD_ON): Ctrl-Alt-Del reboots at once.
static CTRL_ALT_DEL: AtomicBool = AtomicBool::new(false);

/// Sets the reset the next clean shutdown performs.
pub(crate) fn set_reset_kind(kind: u32) {
    RESET_KIND.store(kind, Ordering::Release);
}

pub(crate) fn reset_kind() -> u32 {
    RESET_KIND.load(Ordering::Acquire)
}

pub(crate) fn set_ctrl_alt_del(enabled: bool) {
    CTRL_ALT_DEL.store(enabled, Ordering::Release);
}
