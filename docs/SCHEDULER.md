# Kernel stacks and scheduling: design

Status: design, step 1 of the core rebuild in CLAUDE.md. It replaces the
nested execution model with Linux's: every thread has its own kernel stack,
blocking switches stacks, and a scheduler decides who runs next on each CPU.

## The model being replaced

- `ginux_process_user_enter` pushes the callee-saved registers on the current
  kernel stack, records that stack pointer as the CPU's *return stack* and
  enters ring 3 with `iretq`.
- A Linux `syscall` switches to the return stack and runs the handler below
  that frame. The handler either returns to the same thread (`sysretq`, or the
  `iretq` epilogue when it switched threads) or returns
  `LINUX_RETURN_TO_KERNEL`, which abandons the user frame and returns from
  `ginux_process_user_enter` to whoever entered the process.
- Waiting is done in one of two ways: save the user context so the syscall is
  re-issued later (restart), or call `run_other_linux_processes` /
  `run_scheduled_linux_process`, which enters *another* process from inside
  the current syscall. That process runs on the same stack, below the
  waiting handler's frames (`LINUX_PROCESS_SCHEDULER_NESTING` counts the
  depth), and the waiting process continues only when it returns to kernel.
- Per-process kernel state is swapped in and out of globals around every
  switch (`save/restore_linux_process_runtime_state`, extended state, the
  current thread slot, `LINUX_CURRENT_PROCESS_PID`).

Consequences: execution is strictly last-in first-out, so a process can only
continue after everything it started has returned; stack depth grows with the
process tree (the stack is 2 MiB as a stopgap); and a process that is parked
mid-syscall can be resumed a second time from its saved user context inside a
descendant's syscall (two live activations of one thread: the desktop's
shutdown failure). Upstream's SMP keeps this model per CPU (per-CPU return
stacks in `CpuEntryState`, one dispatched runtime thread per application
processor, all kernel entry serialized by `kernel_entry_lock`).

## Target model

**Task.** Every Linux thread is a task that owns a kernel stack (guard page
below it so an overflow faults instead of corrupting a neighbour) and a saved
kernel stack pointer. A task is in exactly one state: running on a CPU,
runnable, blocked in the kernel (parked inside `switch_to`), or dead.

**Entry.** `CpuEntryState` holds the current task's stack top. The `syscall`
entry and TSS.rsp0 (interrupts and exceptions from ring 3) both land there;
the user registers are saved at the top of the task's own stack (Linux's
`pt_regs`) instead of in per-CPU globals, so nothing is lost when the task
blocks and another runs.

**Switch.** `switch_to(prev, next)` pushes the callee-saved registers, stores
`rsp` in `prev`, loads `next`'s `rsp`, pops and returns, on `next`'s stack.
Around it: CR3 when the address space changes, FS base, XSAVE state,
TSS.rsp0 and the per-CPU current task. A new task's stack is prepared so that
its first switch returns into a trampoline that leaves to ring 3 from its
saved user registers.

**Blocking.** `schedule()` parks the current task and switches to the next
runnable one; a wakeup makes the task runnable and it continues inside its
own handler. The existing restart-style waits keep working unchanged during
the migration: rewind the saved user registers to re-issue the syscall, then
`schedule()` instead of returning to an outer process.

**Exit.** A dying task marks itself dead and switches away for good; the next
task frees its stack (a stack cannot be freed while running on it), as in
Linux's `finish_task_switch`.

**fork/clone/exec.** clone creates a task whose saved user registers are a
copy of the parent's with `rax = 0` and queues it; the parent returns
normally. exec replaces the task's saved user registers in place. Nothing
runs nested, so the deferred-fork machinery goes away.

**Scheduler.** Runnable tasks sit on a run queue; the timer tick sets a
need-resched flag and preemption happens on the way back to ring 3 (and later
inside the kernel at preemption points). Each CPU's boot stack becomes its
idle task, which halts when nothing is runnable.

## Migration steps

Each step keeps `make check`, the Alpine, Rust-workload, all-Rust userland and
desktop suites passing.

1. A kernel heap (`alloc`): a slab allocator for small objects over the frame
   allocator, plus page-granular allocations. Tasks, stacks and the dynamic
   tables in step 3 of the roadmap need it.
2. Tasks with their own stacks and `switch_to`, with the scheduler choice
   still emulating today's order: a task that returns to kernel switches back
   to the task that started it. Behaviour is unchanged, but each stack only
   holds its own frames.
3. User registers saved on the task stack; per-process globals become task or
   process fields, so `switch_to` no longer swaps them.
4. Real scheduling: a task parked in the kernel is resumed only by switching
   to it, never by re-entering its user context; waits block in place;
   `run_other_linux_processes` and the nesting counter disappear; fork/clone
   queue tasks.
5. Preemption from the timer on return to ring 3.
6. Per-CPU run queues with load balancing and wakeups by IPI, then splitting
   `kernel_entry_lock` into per-subsystem locks so CPUs run kernel code in
   parallel (lock ranks from `docs/feedback-hardening/SYNCHRONIZATION.md`).
