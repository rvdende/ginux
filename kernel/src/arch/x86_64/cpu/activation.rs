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

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::size_of;

use super::architecture::CpuEntryState;
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

/// Every live activation, running or parked, in the order they were
/// entered. Each is boxed so its address stays fixed while its context and
/// the context that entered it use it through raw pointers, without the
/// lock, across a switch; only the context that entered or resumed an
/// activation removes it, once it has finished.
#[allow(clippy::vec_box)] // the boxes keep each record's address fixed
static ACTIVATIONS: SpinLock<Vec<Box<Activation>>> =
    SpinLock::new(LockRank::KERNEL_STACKS, Vec::new());

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

/// What had become of an activation when control came back to the context
/// that entered or resumed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    /// One of the process's system calls returned to the kernel: the
    /// activation is over.
    Finished,
    /// A system call parked: it waits on the activation's stack until
    /// `resume`.
    Parked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Running,
    Parked,
    Finished,
}

/// One entry into a process: a kernel context on a stack of its own that
/// enters user mode and runs the process's system calls, and the context
/// that entered (or last resumed) it.
struct Activation {
    /// The process: its domain instance in the high half, its pid in the
    /// low half (pids repeat across domains).
    owner: u64,
    stack: KernelStack,
    entry: usize,
    user_stack: usize,
    general: [u64; 15],
    rflags: u64,
    /// The entering or resuming context's stack pointer while this runs.
    caller: usize,
    /// This activation's stack pointer while it does not run.
    context: usize,
    state: State,
    /// A parked system call's CPU entry state (its return stack, kernel
    /// frame and user return context), which other activations overwrite
    /// while it waits.
    entry_state: CpuEntryState,
    /// The kernel-entry depth of the context running this activation, when
    /// it switched here.
    base_depth: u32,
    /// The kernel-entry entries a parked system call holds on its stack,
    /// taken off its CPU while it waits and given to the CPU that resumes
    /// it.
    parked_depth: u32,
}

/// An activation's context: runs the process until one of its system calls
/// returns to the kernel, then switches back for good.
extern "sysv64" fn run_activation(argument: *mut c_void) -> ! {
    let activation = argument.cast::<Activation>();
    // SAFETY: the activation stays in ACTIVATIONS until the context that
    // switched here sees it finished, which this context reports last. The
    // entry stub records this stack as the return stack, so the process's
    // system calls run here too.
    unsafe {
        super::process_user_enter(
            (*activation).entry,
            (*activation).user_stack,
            (*activation).general.as_ptr(),
            (*activation).rflags,
        );
        (*activation).state = State::Finished;
        ginux_switch_stack(&raw mut (*activation).context, (*activation).caller);
    }
    unreachable!("a finished activation is never resumed")
}

/// Switches to `activation` until it parks or finishes, and frees it once
/// finished.
///
/// # Safety
///
/// `activation` is a live, running record in ACTIVATIONS.
unsafe fn run(activation: *mut Activation) -> Outcome {
    // SAFETY: as the caller promises; the record outlives the switch.
    let state = unsafe {
        (*activation).base_depth = crate::sync::kernel_entry_depth();
        crate::sync::kernel_entry_attach(core::mem::take(&mut (*activation).parked_depth));
        ginux_switch_stack(&raw mut (*activation).caller, (*activation).context);
        (*activation).state
    };
    match state {
        State::Parked => Outcome::Parked,
        State::Finished => {
            let finished = {
                let mut activations = ACTIVATIONS.lock();
                activations
                    .iter()
                    .position(|candidate| core::ptr::eq(&raw const **candidate, activation))
                    .map(|index| activations.remove(index))
            };
            if let Some(finished) = finished {
                STACK_POOL.lock().free.push(finished.stack);
            }
            Outcome::Finished
        }
        State::Running => crate::kernel_fail("ginux: activation switched away while running\r\n"),
    }
}

/// Enters process `pid`'s user mode on an activation stack of its own and
/// returns when one of its system calls returns to the kernel or parks.
/// Returns `None` without entering when no stack could be allocated.
///
/// # Safety
///
/// As for `ginux_process_user_enter`: the caller activated the process's
/// address space and validated the complete user context in `general`
/// (fifteen registers).
pub(super) unsafe fn enter_on_own_stack(
    owner: u64,
    entry: usize,
    stack: usize,
    general: *const u64,
    rflags: u64,
) -> Option<Outcome> {
    // The first activation proves stack switching on the stack window it
    // is about to use (the self-test cannot run earlier in boot, before
    // the runtime owns its frames).
    if !SWITCHING_VERIFIED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        if !verify_stack_switching() {
            crate::kernel_fail("ginux: kernel stack switching invalid\r\n");
        }
        crate::serial_write_raw(b"ginux: kernel stack switching validated\r\n");
    }
    let kernel_stack = take_stack()?;
    let mut registers = [0_u64; 15];
    for (index, register) in registers.iter_mut().enumerate() {
        // SAFETY: the caller passes fifteen readable registers.
        *register = unsafe { general.add(index).read() };
    }
    let top = kernel_stack.top;
    let mut record = Box::new(Activation {
        owner,
        stack: kernel_stack,
        entry,
        user_stack: stack,
        general: registers,
        rflags,
        caller: 0,
        context: 0,
        state: State::Running,
        entry_state: CpuEntryState::EMPTY,
        base_depth: 0,
        parked_depth: 0,
    });
    let activation: *mut Activation = &raw mut *record;
    // SAFETY: the stack is this activation's alone until it finishes.
    unsafe { (*activation).context = new_context(top, run_activation, activation.cast()) };
    {
        let mut activations = ACTIVATIONS.lock();
        if activations
            .iter()
            .any(|candidate| candidate.owner == owner && candidate.state == State::Running)
        {
            report_reentry(owner, &activations);
        }
        activations.push(record);
    }
    // SAFETY: the record was just added and is running.
    Some(unsafe { run(activation) })
}

/// Parks the running activation of process `owner`: the system call it is in
/// waits on the activation's stack while the context that entered or
/// resumed it runs, and continues from here when `resume` switches back.
/// Returns false, without parking, when this is not that activation's
/// stack (a process run below another's frames cannot park).
pub(super) fn park(owner: u64) -> bool {
    let here = 0_u8;
    let here = &raw const here as usize;
    let activation = ACTIVATIONS
        .lock()
        .iter_mut()
        .rev()
        .find(|candidate| candidate.owner == owner && candidate.state == State::Running)
        .filter(|candidate| (candidate.stack.top - STACK_SIZE..candidate.stack.top).contains(&here))
        .map(|candidate| &raw mut **candidate);
    let Some(activation) = activation else {
        return false;
    };
    // SAFETY: this is the running activation, on its own stack; its record
    // stays in ACTIVATIONS while it is parked. The CPU's entry state belongs
    // to this system call and is put back before it continues, into the
    // entry state of the CPU that resumed it.
    unsafe {
        (*activation).entry_state = *super::current_entry_state();
        (*activation).state = State::Parked;
        let own = crate::sync::kernel_entry_depth().saturating_sub((*activation).base_depth);
        crate::sync::kernel_entry_detach(own);
        (*activation).parked_depth = own;
        ginux_switch_stack(&raw mut (*activation).context, (*activation).caller);
        *super::current_entry_state() = (*activation).entry_state;
    }
    true
}

/// Resumes the parked activation of process `owner` until it parks again or
/// finishes; `None` when it has none.
///
/// # Safety
///
/// The caller made the process current again (its address space,
/// thread pointer and per-process kernel state), as for entering it.
pub(super) unsafe fn resume(owner: u64) -> Option<Outcome> {
    let activation = ACTIVATIONS
        .lock()
        .iter_mut()
        .find(|candidate| candidate.owner == owner && candidate.state == State::Parked)
        .map(|candidate| &raw mut **candidate)?;
    // SAFETY: a parked record stays in ACTIVATIONS until its context runs
    // again and finishes.
    unsafe {
        (*activation).state = State::Running;
        Some(run(activation))
    }
}

/// Process `owner` has an activation running on some CPU: its system call
/// is in progress there (or it runs user code), so no other CPU may enter
/// or resume it.
pub(super) fn is_running(owner: u64) -> bool {
    ACTIVATIONS
        .lock()
        .iter()
        .any(|candidate| candidate.owner == owner && candidate.state == State::Running)
}

/// Process `owner` has a parked activation.
pub(super) fn is_parked(owner: u64) -> bool {
    ACTIVATIONS
        .lock()
        .iter()
        .any(|candidate| candidate.owner == owner && candidate.state == State::Parked)
}

/// Drops the parked activations of domain instance `instance` when its
/// runtime stops: their system calls never continue, and their stacks are
/// reused.
pub(super) fn discard_parked(instance: u32) {
    let discarded = {
        let mut activations = ACTIVATIONS.lock();
        let mut discarded = Vec::new();
        let mut index = 0;
        while index < activations.len() {
            let candidate = &activations[index];
            if candidate.state == State::Parked && (candidate.owner >> 32) as u32 == instance {
                discarded.push(activations.remove(index));
            } else {
                index += 1;
            }
        }
        discarded
    };
    let mut pool = STACK_POOL.lock();
    for activation in discarded {
        pool.free.push(activation.stack);
    }
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

/// A process entered while an earlier activation of it is still running
/// inside a system call: it now runs twice, which the scheduler rework
/// removes.
fn report_reentry(owner: u64, activations: &[Box<Activation>]) {
    crate::serial_write_raw(b"ginux: process re-entered during its own system call; pid ");
    crate::serial_write_u64(owner & u64::from(u32::MAX));
    crate::serial_write_raw(b" active");
    for activation in activations
        .iter()
        .filter(|activation| activation.state == State::Running)
    {
        crate::serial_write_raw(b" ");
        crate::serial_write_u64(activation.owner & u64::from(u32::MAX));
    }
    crate::serial_write_raw(b"\r\n");
}
