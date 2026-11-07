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

Progress on kernel stacks (2026-11-01): every activation already runs on a
guarded 256 KiB kernel stack of its own (`cpu/activation.rs`), and the
switch between kernel contexts now exists: `ginux_switch_stack(save, load)`
saves the callee-saved registers and stack pointer, loads another
context's and returns into it, and `new_context` lays out a fresh stack
so its first switch starts a function. `verify_stack_switching` runs at
every boot ("kernel stack switching validated"). The next step uses it: a
system call that must wait parks its activation (switches to the
scheduler's context, keeping its frames on its own stack) instead of
yielding with a restart, and the loop at the runtime entry resumes parked
activations when what they wait for is ready. That removes the restart
model's stale contexts (the checkpoint timeouts above) and lets pause()
sleep without the starvation rename14 showed.

Parking (2026-11-01). Activations are entered by switching kernel
contexts (`activation::enter_on_own_stack` builds a context with
`new_context` and switches to it), and a domain's init has an activation
of its own like every other entry. `activation::park` lets a system call
wait on its activation's stack: it saves the CPU's entry state (return
stack, kernel frame, user return context) and switches to whoever entered
or last resumed the activation; `activation::resume` switches back, and the
call restores its entry state, thread pointer and address space itself
(`park_linux_process` keeps them in locals on its own stack). Init now
parks in its blocking calls (`run_other_linux_processes`) instead of
running other processes nested inside them, and the runtime loop
(`run_linux_runtime_loop`) runs one other process at a time (one with
SIGKILL pending first, then the deepest running descendant, then the run
queue: `run_one_other_linux_process`) and resumes init to check its wait
again, halting when nothing ran. All suites pass with it.

Every other process now parks too: its wait in `run_other_linux_processes`
still records a yield (what whoever entered it expects) but then parks, so
the call keeps its place instead of being re-issued from user mode.
`run_dispatched_linux_process`, the one place processes are entered,
resumes a parked process instead of entering it again (and puts back the
caller's address space after); a parked process with SIGKILL pending is
resumed so its own wait ends it. On waking, a parked call checks what a
system call entry would (expired waits, the real timer raising SIGALRM).
Parked calls leave the kernel in any order, so the kernel-entry lock is
now released when its depth returns to zero, whichever entry leaves last,
as Linux tasks held the big kernel lock across a sleep. Parked
activations are keyed by domain instance and pid, and dropped when the
domain's runtime ends. What is left of step 5: wakeups instead of resuming
every parked call to check again, activations per thread instead of per
process, and timer preemption parking instead of restarting.

First attempt at step 4 (2026-11-01, superseded by parking above; it was
parked behind a `LINUX_SCHEDULER_LOOP = false` switch in cpu.rs): init yields like every other
process (`yield_current_linux_process` no longer refuses pid 1) and
`run_linux_runtime_loop`, at the runtime entry in `finish_linux_runtime`,
runs one other process (deepest running descendant, then the run queue,
halting when none ran) and re-enters init. LTP's syscall tests ran, but two
suites broke, and both point at init-only paths that assume init never
yields:

- brush as init (`make test-rust-userland`) livelocks with its first child:
  the loop keeps running pid 2 (`ran=1 descendant=2`), whose only thread is
  ready but makes no progress, and init is never re-entered with the child's
  result. The descendant walk, not a round-robin pick over the run queue,
  chooses what runs; step 2 (the loop owning the run queue) comes first.
- busybox sh as init (`make test-alpine`) exits after sending the `ESC[6n`
  cursor query: its console read waits, the yield is refused somewhere on
  the console path, and the read's `None` (no data) is reported as end of
  file, so the shell sees EOF on stdin.
- Paths to revisit before the next attempt: console reads that map "nothing
  yet" to EOF for init, init's exit (kill rounds run nested in its call),
  the epoll branch for pid 1, and `take_linux_child_yield(1)` as the only
  signal that init is waiting.

Resolved (2026-11-01): the checkpoint timeouts were not the restart model.
The FUTEX_WAKE fast path in `linux_syscall_handler`, taken before the
kernel-entry lock, woke only the calling process's threads, so a child's
TST_CHECKPOINT_WAKE never reached its parent's futex wait; it now defers
to the full path whenever another process waits (e043be5a). The analysis
below is kept for its account of how the waits then behaved.

What LTP's checkpoint timeouts (about 25 tests: pause01/02, tgkill01-03,
setpgid03, fork04, ...) come down to, traced on 2026-11-01 with pause01: a
child forked child-first calls TST_CHECKPOINT_WAKE before its parent waits,
finds no waiter (correct) and sleeps 1 ms in usleep to retry. The parent
resumes inside its own fork transaction, waits on the futex, and from then
on only the parent is dispatched: each of its restarts finds its wait
record (FUTEX_WAKE from the child would find it too; the futex key is the
same physical address in both), but the child never calls FUTEX_WAKE
again. Its nanosleep keeps being entered at the same return address with
a fresh deadline, as if resumed from the restart point its first yield set
inside the fork transaction rather than where it had got to. Init's pick
does choose the child (the deepest descendant) and dispatches it. So the
fix belongs with the loop: one saved context per process, owned by the run
queue, instead of the fork transaction resuming the parent nested and the
child's registry context going stale. Two causes found on the way are
fixed: restart deadlines leaked (a 32-entry per-domain table whose entries
only a restart removed) and pause() never showed as sleeping.

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

### Wait costs and the runtime loop (2026-11-01, measured with cadrs)

A process that waits records where it waits in the process registry. That
used to be a full snapshot of its address space: every mapped page, checked
against the frame allocator, on every wait. For a GPU application (hundreds
of thousands of pages) that was 50 million frame-lock acquisitions a second
and most of each frame. Waits now record only the execution context, checked
against the live page tables, and mark the registry's mapping list stale;
release frees what the live tables map, `process_vm_readv/writev` look
pages up in them, and fork, exec and exit still take a full snapshot (a
CLONE_VM fork snapshots a stale parent first).

Other costs found the same way (`echo l > /proc/sysrq-trigger` profiles the
runtime CPU; `t` lists every task's threads):

- The runtime loop resumed every parked call to recheck it and halted only
  when nothing ran, so an idle domain spun at 100%. It now waits for an
  interrupt once every process has had a round without a system call.
- sched_yield with no ready sibling went round every other process; it now
  does so at most every 250 us (GPU drivers yield thousands of times a
  second while they poll for the device).
- Console reads and selects on the attached console spun on the serial port
  with interrupts off, freezing the domain while its shell waited for input;
  they now wait like any other blocking call.
- A process switch copies the thread table and descriptor tables through
  banked atomics. Free thread slots are skipped, and the descriptor tables
  are banked as whole arrays (`BankedAtomicArray`: one contiguous table
  per domain instance, copied with relaxed accesses and a fence) instead of
  arrays of banked cells, which interleaved the instances and touched a
  cache line per element. Open-file ids are assigned at fork, where they
  matter, not on every save. A save went from 73 to 15 us and a restore
  from 46 to 10 us (the profile above: 21% of the CPU to 6%).
- Frame ownership checks for the kernel's own frames (page-table walks,
  `live_frame_lease`) read the frame's metadata word without the allocator
  lock: the kernel's owner slot never changes and metadata words are
  written atomically. They took the lock about 3 million times a second.
- A timed wait (nanosleep, poll, pause) that the runtime loop resumed to
  look at its wait again used to halt the CPU until its deadline, holding
  it from every other process: a shell loop's `sleep 0.2` stalled cadrs
  for the whole 200 ms (median frame 136 ms with five spawns a second).
  Resumed, it now parks again, as futex and wait4 waits do, after asking
  for a tick at its deadline; only a wait with nothing else to run halts
  (`LinuxWaitTurn`). With that loop running, cadrs's median is 31 ms:
  processes are still picked down the first running child of each
  process, so a busy branch can hold back another for up to two seconds,
  and picking branches in turn broke `cat | tar` pipelines (a fork
  transaction's order matters); real wakeups (step 5) are the fix. The
  price of re-parking is switches: while cadrs spins on sched_yield for
  the GPU, every rotation resumes each parked waiter to look again, about
  20,000 process switches a second, on CPU time the renderer was not using
  (its steady frame went from 17.3 to 16.9 ms). Wakeups remove that too.
- Timed waits wake at their deadline: the one-shot tick is brought forward
  to the earliest blocked thread's deadline.

Multi-CPU domains still cannot run an application next to its compositor: a
process whose threads run on application processors cannot be switched out
until they block, and the remote futex wait spins without marking its thread
blocked. That needs the per-CPU loop of step 6.

### Several CPUs per domain (2026-11-02)

A domain set `cpu=N` runs on N CPUs. The boot CPU runs init's runtime loop
as before; each application processor runs `run_application_processor_runtime`,
a loop that takes work under the kernel-entry lock and lets the lock go
while its work runs in user mode (every CPU does: the lock is released on
the way to user mode and taken again on the way back). Two kinds of work:

- **A process as the registry dispatched it** (`run_linux_process_on_this_cpu`,
  `claim_live_process`): the process's kernel activation runs on this CPU
  until the process waits, yields, forks or exits. This CPU *owns* the
  process meanwhile: the fork transaction, exec, exit, waits for children,
  signal delivery and the waits that run other processes all happen here.
- **A thread on the light path** (`run_linux_light_thread`): any ready
  thread of a process whose bank is live (below), other than the one whose
  context the registry holds. It runs on the CPU's own kernel stack with
  no activation until it blocks (futex), is preempted by this CPU's timer
  tick (`linux_preempt_light_thread_from_timer`, through the vDSO
  preemption entry), exits, or makes a system call the light path does not
  run (`linux_light_syscall_allowed`). Such a call is put back to be
  restarted and the thread is marked for the owner
  (`LINUX_THREAD_OWNER_ONLY`): the owner switches to it when its own thread
  waits, as it switches between threads on one CPU. A thread that leaves
  the light path saves its context in its thread slot, as a thread switch
  on one CPU does, so any CPU can take it up next.

The owner's timer tick preempts its current thread for a ready sibling
even when nothing can take a yield of the process (the scheduler nesting
of the bank it runs in is 0), and it checks the bank's descriptor and
timed waits as the boot CPU's tick does: with every thread of a process
busy, the thread the registry holds (only the owner runs it) and a thread
blocked in a pipe read were otherwise never run again (dirtyc0w_shmem).

**Process banks.** The per-process kernel state the runtime keeps in
`X86_RUNTIME` (descriptors, threads, signal and address-space bookkeeping)
lives in banks (`linux_cpu_bank`). A process live on any CPU has one bank,
which every CPU running one of its threads uses; the boot CPU has a bank of
its own per execution instance, each application processor one, and there
are spares for a CPU whose own bank still holds a process other CPUs run
threads of. `attach_linux_process_bank` (on restore) joins the bank the
process is live in, or fills a free one from the process's saved record;
`linux_release_current_bank` leaves it, and the last CPU out saves the
record (the owner on its way out, or the last light thread,
`capture_linux_process_runtime_state_for`). Per-CPU state (the current
thread slot, preemption) stays in the CPU's own bank (`ThreadCpuAtomicU8`).
A process's exit waits for its threads on other CPUs to leave
(`LINUX_BANK_DYING`, `wait_for_linux_process_threads_to_leave`) before its
memory goes, on every path that settles an exit: the scheduler's, and a
fork transaction whose child, run first, exited (it once took the exit
before the save that waits, so the threads ran on in freed memory and their
CPU triple-faulted at its next interrupt). SysRq `u` lists the banks and
the light-path counters.

The fork transaction's markers (the child whose exit, exec or yield it
waits for) are one set per bank. A child that forks runs a nested
transaction, which points them at the grandchild; they are put back for
the outer transaction when the child resumes inside the nested one
(`LinuxForkExecFlagGuard`). The timer yields a process only when someone
takes the yield (`linux_preemption_yield_taken`), so a multithreaded child
that had forked once was never preempted back to its parent, which waited
for it in the outer transaction forever (dirtyc0w_shmem). getcpu reports
the CPU a call runs on, the owner's path included, and sched_setaffinity
leaves a CPU the new mask excludes by that CPU's own index: the run queue
already keeps a process to the CPUs its mask allows (getcpu01).

The futex coordinator spinning (`linux_remote_futex_wait_fast`) and the
thread-by-interrupt dispatch (`begin_linux_runtime_thread`) that preceded
this are gone: the owner blocks like any thread, and its process is
resumed by whichever CPU claims it, since the bank follows the process.

TLB shootdowns interrupt only CPUs whose last loaded CR3 is the root being
changed (`smp::note_active_root`), and only for a leaf entry that was
present (`invalidate_changed_runtime_translation`): a page mapped for the
first time was in no TLB. Before the first, every page-table change of a
process on an application processor waited on an NMI to CPU 0 and a 4-CPU
domain ran compute-bound work five times slower than a 1-CPU one; before
the second, four threads of one process touching fresh pages interrupted
each other on every page and spent most of their time in the kernel-entry
lock.

Measured with cadrs_core's 87 reference tests (host: 6.5 s on 12 threads):
1 CPU 19.1 s, 4 CPUs 20.2 s before threads could spread; see the commit
log for after. `make test-multithread` checks four threads of one process
on four CPUs, waits and wakes across CPUs, timed waits, a thread spawning
processes, exit and a fault with threads elsewhere.

Still per domain rather than per process: the mount namespace that is
"current" (`linux_mount`), which CPUs running processes of different
namespaces at once would see wrongly; and the alternate signal stack, kept
per process. Next: a thread's wait in poll/epoll on the light path (today
those calls go to the owner), and lighter rechecks of a parked process
(each park refreshes the registry's mapping list).

### Sleepers and their deadlines (2026-11-07)

A single-threaded process parked in a futex wait, a wait for children
(wait4, waitid) or nanosleep is *marked asleep* (`mark_linux_process_asleep`,
`Process.futex_sleep`) until its wait's deadline or its own real or POSIX
timer, whichever is first (a wait for children has none of its own). While
the mark holds, with `waiting` set and the deadline not passed
(`linux_process_asleep`), the runtime loop and the application processors
pass the process over instead of resuming it to look at its wait again. A
wake clears `waiting` (FUTEX_WAKE from another process, a child's change of
state, a signal it takes), and each dispatch clears the mark, so every
sleep sets it again.

- **The deadlines** are kept in a min-heap (`crates/deadline-heap`, tested
  on the host), so the earliest is found without walking every process
  (`next_live_futex_sleep_deadline`). Entries are checked lazily against
  the mark they were pushed for and dropped when it no longer holds; a heap
  that overflowed is rebuilt from the process table.
- **The tick** is brought forward to the earliest sleeper's deadline, as it
  is for a blocked thread's (`request_linux_tick_within`, rounded up so it
  comes at the deadline, not just before it), and the boot CPU does not
  halt with a sleeper due before its next tick: a halt there slept through
  the deadline whenever nothing else woke the CPU.
- **Who resumes a due sleeper.** The boot CPU's runtime loop at its next
  scheduling point, or an idle application processor: one takes a parked
  (Sleeping) process when its deadline has passed, or when its affinity
  keeps it from the boot CPU (pinned to another CPU, it otherwise slept for
  good). An application processor with a sleeper due within a tick keeps
  looking every few microseconds instead of backing off to a millisecond.
  The boot CPU, finding a sleeper due that it did not run, lets the
  kernel-entry lock go for a moment and looks again, instead of halting or
  looking again at once with the lock held, which kept the CPU a sleeper
  was pinned to from ever taking it (`linux_wait_for_interrupt`).
- **Wakeup preemption.** A tick that finds a sleeper due ends the slice of
  the process it interrupted, on any CPU, once per deadline
  (`linux_sleeper_due_from_timer`), as Linux preempts for a woken task:
  otherwise a process running nested in another's system call, or for a
  whole slice, held the sleeper off for up to 50 ms (24 ms seen). The
  yield goes to the scheduler that entered the process; if that scheduler
  runs another first, the sleeper waits for the next scheduling point
  rather than every tick cutting a slice short. A process nobody can take
  the yield of carries on.
- **The margin.** On one CPU a nanosleep is marked to 2 ms before its
  deadline (`LINUX_SLEEP_WAKE_MARGIN_NS`) and from there looks at the clock
  itself every round, as an unmarked sleep does: a process running nested
  can still hold off the next scheduling point. With more CPUs an idle one
  resumes the sleeper on time and sleeps are marked to their deadline
  (`linux_sleep_wake_margin`). Futex and wait4 waits, which have no look
  of their own, always are.

Still to come: a sleeper is resumed to find its wait over, not handed its
result by the wake (step 5's real wakeups), and the tick preempts only a
process in user mode: one in a long system call holds its CPU until the
call ends.
