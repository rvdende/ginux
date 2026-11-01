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
//!
//! A kernel context parks on its stack by switching to another: the switch
//! saves the callee-saved registers and the stack pointer, loads another
//! context's, and returns into wherever that one switched away (or, for a
//! new context, into its function). This is how a blocked system call will
//! wait on its own stack while others run; `verify_stack_switching` proves
//! the mechanism at boot.

use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;

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

/// Whether the first activation has checked stack switching yet.
static SWITCHING_VERIFIED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

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
    .global ginux_switch_stack
// ginux_switch_stack(save: rdi, load: rsi) saves the callee-saved registers
// on the current stack, stores its stack pointer at [rdi], loads the stack
// pointer in rsi, restores that context's callee-saved registers and
// returns into wherever it switched away.
ginux_switch_stack:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    .global ginux_context_start
// A new context's first switch returns here with its function in r12 and
// the function's argument in r13. The function never returns.
ginux_context_start:
    mov rdi, r13
    call r12
    ud2
"#
);

extern "sysv64" {
    fn ginux_switch_stack(save: *mut usize, load: usize);
    fn ginux_context_start();
}

/// One entry into a process: a kernel context on the activation's own stack
/// that enters user mode, and the context that entered it.
struct Activation {
    arguments: EntryArguments,
    /// The entering context's stack pointer while the activation runs.
    caller: usize,
    /// The activation's stack pointer while it does not run.
    context: usize,
}

/// An activation's context: runs the process until one of its system calls
/// returns to the kernel, then switches back to whoever entered it for
/// good.
extern "sysv64" fn run_activation(argument: *mut c_void) -> ! {
    let activation = argument.cast::<Activation>();
    // SAFETY: `enter_on_own_stack` keeps the activation alive until this
    // context switches back to it, which it does exactly once, last. The
    // entry stub records this stack as the return stack, so the process's
    // system calls run here too.
    unsafe {
        let arguments = &(*activation).arguments;
        super::ginux_process_user_enter(
            arguments.entry,
            arguments.stack,
            arguments.general,
            arguments.rflags,
        );
        ginux_switch_stack(&raw mut (*activation).context, (*activation).caller);
    }
    unreachable!("a finished activation is never resumed")
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
    // The first activation proves stack switching on the stack window it
    // is about to use (the self-test cannot run earlier in boot, before
    // the runtime owns its frames).
    if !SWITCHING_VERIFIED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        if !verify_stack_switching() {
            crate::kernel_fail("ginux: kernel stack switching invalid\r\n");
        }
        crate::serial_write_raw(b"ginux: kernel stack switching validated\r\n");
    }
    let Some(kernel_stack) = take_stack() else {
        return false;
    };
    {
        let mut active = ACTIVE_PIDS.lock();
        if active.contains(&pid) {
            report_reentry(pid, &active);
        }
        active.push(pid);
    }
    let mut activation = Activation {
        arguments: EntryArguments {
            entry,
            stack,
            general,
            rflags,
        },
        caller: 0,
        context: 0,
    };
    let activation_pointer = &raw mut activation;
    // SAFETY: the stack is exclusively this activation's until it is
    // returned to the free list below; the activation record outlives the
    // context, which switches back here when the process returns to the
    // kernel and is never resumed.
    unsafe {
        (*activation_pointer).context = new_context(
            kernel_stack.top,
            run_activation,
            activation_pointer.cast::<c_void>(),
        );
        ginux_switch_stack(
            &raw mut (*activation_pointer).caller,
            (*activation_pointer).context,
        );
    }
    {
        let mut active = ACTIVE_PIDS.lock();
        if let Some(position) = active.iter().rposition(|active| *active == pid) {
            active.remove(position);
        }
    }
    STACK_POOL.lock().free.push(kernel_stack);
    true
}

/// Takes a kernel stack from the pool, or maps a new one.
fn take_stack() -> Option<KernelStack> {
    let mut pool = STACK_POOL.lock();
    if let Some(stack) = pool.free.pop() {
        return Some(stack);
    }
    let slot = pool.next_slot;
    let stack = KernelStack::new(slot)?;
    pool.next_slot = slot + 1;
    Some(stack)
}

/// Lays out a new context on the stack ending at `top` so that switching
/// to the returned stack pointer starts `function(argument)`.
///
/// # Safety
///
/// `top` must be the 16-byte aligned end of a mapped kernel stack that
/// nothing else uses while the context lives.
unsafe fn new_context(
    top: usize,
    function: extern "sysv64" fn(*mut c_void) -> !,
    argument: *mut c_void,
) -> usize {
    // Six callee-saved registers and the return address, placed so that
    // the stack is 16-byte aligned when ginux_context_start calls function.
    let saved = top - 9 * size_of::<usize>();
    let frame = saved as *mut usize;
    let words = [
        0,                                         // r15
        0,                                         // r14
        argument as usize,                         // r13
        function as usize,                         // r12
        0,                                         // rbx
        0,                                         // rbp
        ginux_context_start as *const () as usize, // return address
    ];
    for (index, word) in words.into_iter().enumerate() {
        // SAFETY: the caller hands over the stack below `top`, and these
        // seven words lie within its top page.
        unsafe { frame.add(index).write(word) };
    }
    saved
}

/// The state the switching self-test passes between its two contexts.
struct PingPong {
    boot: usize,
    context: usize,
    rounds: u32,
}

extern "sysv64" fn ping_pong(argument: *mut c_void) -> ! {
    let state = argument.cast::<PingPong>();
    loop {
        // SAFETY: verify_stack_switching keeps the state alive and only
        // touches it while this context is parked.
        unsafe {
            (*state).rounds += 1;
            ginux_switch_stack(&raw mut (*state).context, (*state).boot);
        }
    }
}

/// Starts a context on a stack of its own, switches into it and back three
/// times, and checks each round ran on that stack and came back here.
pub(super) fn verify_stack_switching() -> bool {
    let Some(stack) = take_stack() else {
        return false;
    };
    let mut state = PingPong {
        boot: 0,
        context: 0,
        rounds: 0,
    };
    let state_pointer = &raw mut state;
    // SAFETY: the stack is this test's until it goes back to the pool, and
    // the state outlives every switch into the context.
    unsafe {
        (*state_pointer).context = new_context(stack.top, ping_pong, state_pointer.cast());
        for round in 1..=3 {
            ginux_switch_stack(&raw mut (*state_pointer).boot, (*state_pointer).context);
            let parked = (*state_pointer).context;
            if (*state_pointer).rounds != round
                || !(stack.top - STACK_SIZE..stack.top).contains(&parked)
            {
                return false;
            }
        }
    }
    // The context stays parked; its stack is reused like any other.
    STACK_POOL.lock().free.push(stack);
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
