//! Kernel stacks for Linux process activations.
//!
//! Entering a Linux process starts an activation: the process runs in ring 3
//! and makes its system calls, until one of them returns to the kernel. Each
//! activation gets a kernel stack of its own instead of continuing below the
//! frames of whoever entered the process. A process that runs others from
//! inside a system call (today's nested scheduling) therefore only holds its
//! own frames on its stack, and the entering CPU's stack only holds the
//! runtime's. This is step 2 of docs/SCHEDULER.md; switching between parked
//! activations follows.
//!
//! The lowest page of each stack is a red zone holding a fixed pattern.
//! Kernel work that overflows its stack overwrites it, and the check when the
//! activation ends stops the kernel before the damage spreads. (Stacks come
//! from the heap's direct-map memory, which has no unmapped guard pages.)

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::arch::global_asm;
use core::ffi::c_void;

use crate::sync::{LockRank, SpinLock};

/// Usable bytes of an activation stack.
const STACK_SIZE: usize = 256 * 1024;
const RED_ZONE_SIZE: usize = 4096;
const RED_ZONE_PATTERN: u64 = 0x454e_4f5a_4445_5221;

#[repr(C, align(4096))]
struct KernelStack([u8; RED_ZONE_SIZE + STACK_SIZE]);

impl KernelStack {
    fn new() -> Option<Box<Self>> {
        let layout = Layout::new::<Self>();
        // SAFETY: the layout has a non-zero size.
        let pointer = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<Self>();
        if pointer.is_null() {
            return None;
        }
        // SAFETY: the global allocator returned this zeroed block for
        // `Self`'s layout, and zero bytes are a valid KernelStack.
        let mut stack = unsafe { Box::from_raw(pointer) };
        stack.paint_red_zone();
        Some(stack)
    }

    fn red_zone(&mut self) -> &mut [u8] {
        &mut self.0[..RED_ZONE_SIZE]
    }

    fn paint_red_zone(&mut self) {
        for word in self.red_zone().as_chunks_mut::<8>().0 {
            *word = RED_ZONE_PATTERN.to_ne_bytes();
        }
    }

    fn red_zone_intact(&mut self) -> bool {
        self.red_zone()
            .as_chunks::<8>()
            .0
            .iter()
            .all(|word| *word == RED_ZONE_PATTERN.to_ne_bytes())
    }

    /// The initial stack pointer: the end of the stack, 16-byte aligned.
    fn top(&mut self) -> usize {
        self.0.as_mut_ptr_range().end as usize
    }
}

/// Stacks of finished activations, kept for reuse because activations start
/// and end on every process switch. The lock ranks below the heap's so the
/// list may grow while held.
static FREE_STACKS: SpinLock<Vec<Box<KernelStack>>> =
    SpinLock::new(LockRank::KERNEL_STACKS, Vec::new());

/// Processes with a live activation, outermost first.
static ACTIVE_PIDS: SpinLock<Vec<u32>> = SpinLock::new(LockRank::KERNEL_STACKS, Vec::new());

struct EntryArguments {
    entry: usize,
    stack: usize,
    general: *const u64,
    rflags: u64,
}

global_asm!(
    r#"
    .text
    .global ginux_call_on_stack
// ginux_call_on_stack(top: rdi, function: rsi, argument: rdx) calls
// function(argument) with rsp = top and returns on the caller's stack.
ginux_call_on_stack:
    push rbp
    mov rbp, rsp
    mov rsp, rdi
    mov rdi, rdx
    call rsi
    mov rsp, rbp
    pop rbp
    ret
"#
);

extern "sysv64" {
    fn ginux_call_on_stack(
        top: usize,
        function: extern "sysv64" fn(*mut c_void),
        argument: *mut c_void,
    );
}

extern "sysv64" fn enter_user_mode(argument: *mut c_void) {
    // SAFETY: `enter_on_own_stack` passes its live EntryArguments.
    let arguments = unsafe { &*argument.cast::<EntryArguments>() };
    // SAFETY: as for `enter_on_own_stack`; the entry stub records this stack
    // as the return stack, so the process's system calls run here too.
    unsafe {
        super::ginux_process_user_enter(
            arguments.entry,
            arguments.stack,
            arguments.general,
            arguments.rflags,
        )
    };
}

/// Enters process `pid`'s user mode on an activation stack of its own and
/// returns when one of its system calls returns to the kernel. Returns false
/// without entering when no stack could be allocated.
///
/// # Safety
///
/// As for `ginux_process_user_enter`: the caller activated the process's
/// address space and validated the complete user context.
pub(super) unsafe fn enter_on_own_stack(
    pid: u32,
    entry: usize,
    stack: usize,
    general: *const u64,
    rflags: u64,
) -> bool {
    let reused = FREE_STACKS.lock().pop();
    let Some(mut kernel_stack) = reused.or_else(KernelStack::new) else {
        return false;
    };
    {
        let mut active = ACTIVE_PIDS.lock();
        if active.contains(&pid) {
            report_reentry(pid, &active);
        }
        active.push(pid);
    }
    let mut arguments = EntryArguments {
        entry,
        stack,
        general,
        rflags,
    };
    // SAFETY: the stack is exclusively this activation's until it is
    // returned to the free list below, and `enter_user_mode` only reads the
    // arguments, which outlive the call.
    unsafe {
        ginux_call_on_stack(
            kernel_stack.top(),
            enter_user_mode,
            (&raw mut arguments).cast::<c_void>(),
        )
    };
    {
        let mut active = ACTIVE_PIDS.lock();
        if let Some(position) = active.iter().rposition(|active| *active == pid) {
            active.remove(position);
        }
    }
    if !kernel_stack.red_zone_intact() {
        crate::serial_write_raw(b"ginux: kernel stack overflow in an activation of pid ");
        crate::serial_write_u64(u64::from(pid));
        crate::serial_write_raw(b"\r\n");
        crate::kernel_fail("ginux: kernel stack red zone overwritten\r\n");
    }
    FREE_STACKS.lock().push(kernel_stack);
    true
}

/// A process entered while an earlier activation of it is still inside a
/// system call: it now runs twice, which the scheduler rework removes.
fn report_reentry(pid: u32, active: &[u32]) {
    crate::serial_write_raw(b"ginux: process re-entered during its own system call; pid ");
    crate::serial_write_u64(u64::from(pid));
    crate::serial_write_raw(b" active");
    for pid in active {
        crate::serial_write_raw(b" ");
        crate::serial_write_u64(u64::from(*pid));
    }
    crate::serial_write_raw(b"\r\n");
}
