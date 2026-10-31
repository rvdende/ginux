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
Done out of order: timer preemption of processes (`linux_preempt_process_from_timer`
in cpu.rs). A process other than init that runs 50 ms is sent through the
vDSO's `__ginux_preempt` entry, whose internal system call yields it with its
exact interrupted registers; it is resumed where the tick interrupted it.
It applies whenever someone can take the yield (init's nested scheduling, or
a fork transaction's exec'd child); the scheduler loop makes that everyone.

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

## Step 4 in detail: the scheduler loop

Measured on 2026-10-31 with parent-first fork switched on under today's
init-driven scheduling: LTP's wait/kill/clone tests regress (children forked
parent-first wait, ready, until init's descendant walk happens to pick them,
and the 64-slot process table fills with them), and `cargo build | grep`
hangs. Parent-first fork therefore lands together with the loop, which picks
every ready process in turn.

Global state a switch moves today (what the loop must save and restore,
lazily: only when switching away from the loaded process, so timer-driven
wakeups between dispatches are not lost):

| State | Saved by | Restored by |
|---|---|---|
| Runtime globals (descriptors, mmap, cwd, rlimits, signal handlers/pending, thread table, current thread slot, mount namespace) | `save_current_linux_process_runtime_state(pid)`; finds the thread table via `current_linux_process_pid()`, so that must still name the process | `restore_saved_linux_process_runtime_state(pid)` (also switches the mount namespace, signal mask, wait hints) |
| XSAVE state | `save_linux_process_extended_state` | `restore_linux_process_extended_state` |
| `LINUX_CURRENT_PROCESS_PID` | | stored explicitly |
| Address-space globals | | `sync_live_linux_process_address_space(pid)` before every entry |
| CR3, FS base | | `address_space::resume_live_linux_process` (skips the CR3 load when the root is already active) |
| Registry context | `refresh_live_linux_process_registry` on every return to kernel | `dispatch_live_process` |
| `LINUX_FORK_*` requests, `LINUX_PROCESS_CHILD_{EXITED,EXECUTED,YIELDED}` with pids/status | single global slots: consume before any other process runs | |

Hazards found in the code:

- Domain exec (`execute_deferred_live_fork`'s domain-exec loop) re-runs only
  the injected process; forks inside it must stay child-first (done:
  `LinuxDomainExecGuard`), or the loop must own it.
- CLONE_NEWNS children retire their namespace only inside the fork
  transaction; a parent-first child that exits would leak it (kept
  child-first).
- `begin_live_fork` writes the child's pid into the parent's registry rax;
  for a domain-exec parent suspended mid-call this clobbers its result.
- Background resume of a process other than init does not restore its
  runtime state today; the loop must.
- `schedule_next` prefers higher priority and honours affinity; in the
  restart model a waiter stays ready, so the loop must pick round-robin and
  ignore priority/affinity until per-CPU scheduling.
- The run queue keeps its own copy of each context; registry writes for a
  process that is not running (`set_live_process_return_value`) make them
  differ, so the loop treats the registry as the source of truth.
- Background suspension is only checked at the end of a syscall returning a
  normal result; the loop must check `LINUX_RUNTIME_BACKGROUND_YIELD_REQUESTED`.
- The APIC timer entry has no `swapgs`; preempting from user mode needs it,
  and `process_general(rax, rip, rflags)` is wrong for a context interrupted
  mid-instruction (rcx/r11 are live there).
- Releasing `kernel_entry_lock` while user code runs lets threads on other
  CPUs enter the kernel concurrently: run the rocky-smp tests.

Order:

1. Refactor without behaviour change: split `run_scheduled_linux_process`
   into switch-in (restore runtime + extended state, current pid, address
   space, pending-SIGKILL check) and settle (fork loop, save, exit block:
   signal queues, SIGCHLD, cgroup, runtime state, extended state, slot
   release, descriptor wakeups); route waitid/recvfrom/recvmsg's direct child
   runs through `run_other_linux_processes`.
2. The loop owns the run queue: claim the workspace and make init current at
   runtime start/resume; stop `complete_live_child_exit` from releasing it in
   runtime mode; release it before `finish_runtime_process_registry`.
3. New `ProcessScheduler` operations: park current (Running→Ready, current =
   None), select a given thread, next round-robin, has-ready; registry
   wrappers replace `switch_live_process`/`yield_live_process`.
4. `run_linux_process_loop` at the runtime entry: pick next, lazily switch
   state, enter (SIGKILL pending → terminate), then settle in this order:
   forks, suspension (restore init's globals before returning), init
   completion, exit, park; halt when every ready process has yielded waiting
   since the last progress. Everyone, init included, waits by returning to
   the kernel; `run_other_linux_processes` keeps only the sibling-thread
   switch, delivers pending signals (EINTR) and yields; the init branch, the
   descendant walk, `run_scheduled_linux_process` and the nesting counter go.
5. Then vfork in the loop (parent blocked, child preferred, unblocked at
   exec/exit via a registry `vfork_parent`), release-on-exec from the
   registry's `shares_parent_vm` instead of the global flag, domain exec run
   from the loop, parent-first fork on.
6. Timer preemption: `swapgs` in the timer entry for user frames, a slice
   counter reset per dispatch, refresh the registry from the interrupted
   frame's exact registers, park without counting a wait.

Progress on step 1: every dispatched process is entered through
`run_dispatched_linux_process` (cpu.rs), the place the loop will own.

### What waits look like until the loop exists (2026-11-01)

A process other than init waits by yielding with its call set to restart,
so anything a wait must remember lives outside the call and goes when the
call completes, fails, is interrupted or the process exits:

- semop, msgsnd/msgrcv: wait records with the SysV IPC instance
  (`linux_sysv_ipc`), so GETNCNT/GETZCNT count waiters and a removed set or
  queue is EIDRM; a semtimedop deadline is kept from the first attempt.
- futex waits of single-threaded processes: records under
  `LINUX_FUTEX_COORDINATION`, keyed by the futex word's physical address,
  marked by FUTEX_WAKE from another process, with their deadline.
- poll and nanosleep keep their deadline by return address
  (`take_linux_restart_deadline`).
- `Process.waiting` is set when a process yields with a restart and cleared
  when it is woken or dispatched; /proc shows it as 'S'.
- A WNOHANG wait that finds nothing while a child can run yields the CPU
  once (a parent polling for its children would otherwise starve them).
- Signals reach a process running user code from the timer tick, through
  the same vDSO entry as preemption (`linux_signal_due_from_timer`), and a
  call interrupted for an SA_RESTART handler restarts.

The loop replaces the restarts with real blocking (step 5), and these
records become the wait queues blocked tasks sit on.
