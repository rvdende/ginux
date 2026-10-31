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
//! Stacks live in the kernel stack window (`paging::KERNEL_STACK_WINDOW_BASE`),
//! one per 512 KiB slot: the stack's pages at the top of its slot and the
//! rest of the slot unmapped, so kernel work that overflows its stack faults
//! on a guard page (reported as a double fault) instead of overwriting the
//! memory below it. Stacks are reused, never unmapped.

use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;

use crate::arch::x86_64::paging;
use crate::memory::{self, FrameOwner};
use crate::sync::{LockRank, SpinLock};

/// Usable bytes of an activation stack.
const STACK_SIZE: usize = 256 * 1024;
/// Window space per stack; everything below the stack in its slot is guard.
const SLOT_SIZE: usize = 512 * 1024;
const PAGE_SIZE: usize = 4096;

struct KernelStack {
    /// The initial stack pointer: the end of the stack, 16-byte aligned.
    top: usize,
}

impl KernelStack {
    /// Maps a new stack into window slot `slot` from fresh frames.
    fn new(slot: usize) -> Option<Self> {
        let end = slot.checked_add(1)?.checked_mul(SLOT_SIZE)?;
        if end > paging::KERNEL_STACK_WINDOW_SIZE {
            return None;
        }
        let top = paging::KERNEL_STACK_WINDOW_BASE + end;
        for page in 1..=STACK_SIZE / PAGE_SIZE {
            let address = top - page * PAGE_SIZE;
            let [frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
            let mut table = None;
            if !paging::map_kernel_stack_page(address, frame.address(), &mut table) {
                // The first page in a 2 MiB region also needs its page table.
                let [table_frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
                table = Some(table_frame.address());
                if !paging::map_kernel_stack_page(address, frame.address(), &mut table) {
                    return None;
                }
            }
        }
        Some(Self { top })
    }
}

/// Stacks of finished activations, kept for reuse because activations start
/// and end on every process switch, and the next unused window slot. The
/// lock serializes mapping new stacks; it ranks below the heap and the frame
/// allocator, both used while it is held.
struct StackPool {
    free: Vec<KernelStack>,
    next_slot: usize,
}

static STACK_POOL: SpinLock<StackPool> = SpinLock::new(
    LockRank::KERNEL_STACKS,
    StackPool {
        free: Vec::new(),
        next_slot: 0,
    },
);

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
    let kernel_stack = {
        let mut pool = STACK_POOL.lock();
        match pool.free.pop() {
            Some(stack) => stack,
            None => {
                let slot = pool.next_slot;
                let Some(stack) = KernelStack::new(slot) else {
                    return false;
                };
                pool.next_slot = slot + 1;
                stack
            }
        }
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
            kernel_stack.top,
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
    STACK_POOL.lock().free.push(kernel_stack);
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
