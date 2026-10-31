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

Since the upstream merge only init (pid 1) runs other processes from inside
its blocking calls; every other process waits by returning to the kernel
with its call set to restart. So the nesting is shallow, and init's system
calls act as the scheduler.

1. Done: a kernel heap (`kernel/src/heap.rs`): slab size classes over the
   frame allocator plus frame runs for large objects.
2. Done: activation stacks (`cpu/activation.rs`). Every entry into a Linux
   process on the boot CPU runs it, and its system calls, on a kernel stack
   of its own (256 KiB) in today's order. Stacks are mapped page by page in
   a kernel stack window (`paging::map_kernel_stack_page`), one per 512 KiB
   slot with the rest of the slot unmapped, so an overflow faults on a guard
   page (a double fault) instead of corrupting memory. A process entered
   while an earlier activation of it is still inside a system call is
   reported ("re-entered during its own system call").
3. Parent-first fork, Linux's default order (`LINUX_PARENT_FIRST_FORK` in
   cpu.rs, implemented but off): plain forks resume the parent with the
   child's pid and leave the child ready in the run queue; vfork, CLONE_VM,
   child-stack, new-mount-namespace and domain-exec forks stay child-first.
   Turning it on needed edge-triggered epoll (tokio waits on a pidfd) and a
   sched_yield that lets other processes run (the rustup proxy spins on it),
   both now in; `cargo build | grep` inside a domain still hangs with it on.
4. A kernel scheduler loop replaces init's role: the runtime's entry frame
   picks the next runnable process from the run queue and enters it; every
   process, init included, waits by returning to the kernel; exit and fork
   are handled by the loop. Processes can then be preempted by the timer
   (save the user context, return to the loop), which LTP's spinning tests
   need.
5. Real blocking: an activation that must wait parks (switches to the loop)
   instead of returning to the kernel with a restart, and the loop resumes
   parked activations by switching to them; threads get activations of their
   own; per-process globals become task fields so a switch no longer copies
   them in and out.
6. Per-CPU scheduler loops with load balancing and wakeups by IPI, then
   splitting `kernel_entry_lock` into per-subsystem locks so CPUs run kernel
   code in parallel (lock ranks from
   `docs/feedback-hardening/SYNCHRONIZATION.md`).
