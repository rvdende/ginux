use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    mem::{size_of, MaybeUninit},
    sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
};

use crate::linux_debug_registers::{DebugRegisters, Error as DebugRegisterError};
use crate::{
    address_space, arch::x86_64::cpu, control_abi, linux_namespace, linux_user, memory, scheduler,
};

/// Processes a domain's table holds, zombies included. The table, and every
/// table kept per process slot, grows on demand up to this (slots are u16):
/// the bound is what a domain's memory allows, not what was reserved.
pub(crate) const PROCESS_LIMIT: usize = 4096;
/// Processes with an address space at once: a zombie releases its runtime
/// slot when it exits, so many unreaped zombies need table slots only.
/// Processes of one domain that can exist at once (as many as its process
/// table holds): each takes a runtime slot, whose saved state and address-
/// space lists are allocated when the slot is first used.
pub(crate) const PROCESS_RUNTIME_LIMIT: usize = PROCESS_LIMIT;
const PAGE_SIZE: usize = 4096;
const FORK_PRIVATE_PAGE_LIMIT: usize = 2;
/// Process slots up to which a fork checks its new frames against every
/// process's lists (`ProcessTable::resources_available`).
const FORK_CHECK_ALL_LIMIT: usize = 256;
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const NO_EXECUTE: u64 = 1 << 63;
const TEST_USER_ADDRESS: usize = 1usize << 39;
const PROCESS_RAX_INDEX: usize = 0;
const HOST_PROCESS_INSTANCE: usize = control_abi::DOMAIN_LIMIT;
const PROCESS_INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
const PROCESS_INSTANCE_NONE: u8 = u8::MAX;

struct LiveForkScratch {
    child_mappings: Vec<cpu::LinuxActiveImageMapping>,
    parent_pages: Vec<memory::FrameLease>,
}

struct ProcessRuntimeOwner(UnsafeCell<ProcessRuntimeState>);

unsafe impl Sync for ProcessRuntimeOwner {}

/// Each instance's address-space storage by runtime slot, as long as the
/// highest slot used so far.
struct ProcessAddressSpaceStorageOwner(
    UnsafeCell<[Vec<*mut ProcessAddressSpaceStorage>; PROCESS_INSTANCE_LIMIT]>,
);

unsafe impl Sync for ProcessAddressSpaceStorageOwner {}

struct ProcessRuntimeState {
    table_initialized: [AtomicBool; PROCESS_INSTANCE_LIMIT],
    refresh_count: [AtomicU32; PROCESS_INSTANCE_LIMIT],
    active_instance: AtomicU8,
    fork_child_executed: AtomicBool,
    fork_execution_stage: AtomicU32,
    fork_child_diagnostic: AtomicU32,
    tables: UnsafeCell<[ProcessTable; PROCESS_INSTANCE_LIMIT]>,
    test_table: UnsafeCell<MaybeUninit<ProcessTable>>,
}

/// Transient fork and teardown work areas, each as long as the largest
/// address space forked lately: they grow with the process instead of
/// bounding it.
struct ProcessScratchState {
    fork_scratch: UnsafeCell<LiveForkScratch>,
    fork_allocation_scratch: UnsafeCell<Vec<memory::FrameLease>>,
    fork_hierarchy_allocation_scratch: UnsafeCell<Vec<memory::FrameLease>>,
}

struct ProcessScratchOwner(UnsafeCell<ProcessScratchState>);

unsafe impl Sync for ProcessScratchOwner {}

static PROCESS_SCRATCH: ProcessScratchOwner =
    ProcessScratchOwner(UnsafeCell::new(ProcessScratchState {
        fork_scratch: UnsafeCell::new(LiveForkScratch {
            child_mappings: Vec::new(),
            parent_pages: Vec::new(),
        }),
        fork_allocation_scratch: UnsafeCell::new(Vec::new()),
        fork_hierarchy_allocation_scratch: UnsafeCell::new(Vec::new()),
    }));

/// `list` resized to `count` empty leases for a fork to allocate into; empty
/// (so the allocation fails and the fork backs out) without the memory.
fn fork_frame_scratch(
    list: &'static mut Vec<memory::FrameLease>,
    count: usize,
) -> &'static mut [memory::FrameLease] {
    if address_space::fill_list(list, count, memory::FrameLease::EMPTY).is_none() {
        return &mut [];
    }
    list
}

fn process_scratch() -> &'static ProcessScratchState {
    // SAFETY: as for process_runtime; the recursive kernel-entry boundary
    // serializes the fork and teardown paths that use these areas.
    unsafe { &*PROCESS_SCRATCH.0.get() }
}

// Keep the elastic process address-space registry out of the kernel image.
// Each slot's storage is several megabytes, so it is allocated from the frame
// allocator the first time a process occupies the slot. Every reader is
// count-bounded and the live prefixes are written before publication.
static PROCESS_ADDRESS_SPACE_STORAGE: ProcessAddressSpaceStorageOwner =
    ProcessAddressSpaceStorageOwner(UnsafeCell::new(
        [const { Vec::new() }; PROCESS_INSTANCE_LIMIT],
    ));

static PROCESS_RUNTIME: ProcessRuntimeOwner =
    ProcessRuntimeOwner(UnsafeCell::new(ProcessRuntimeState {
        table_initialized: [const { AtomicBool::new(false) }; PROCESS_INSTANCE_LIMIT],
        refresh_count: [const { AtomicU32::new(0) }; PROCESS_INSTANCE_LIMIT],
        active_instance: AtomicU8::new(PROCESS_INSTANCE_NONE),
        fork_child_executed: AtomicBool::new(false),
        fork_execution_stage: AtomicU32::new(0),
        fork_child_diagnostic: AtomicU32::new(0),
        tables: UnsafeCell::new([const { ProcessTable::new() }; PROCESS_INSTANCE_LIMIT]),
        test_table: UnsafeCell::new(MaybeUninit::uninit()),
    }));

fn process_runtime() -> &'static ProcessRuntimeState {
    // SAFETY: The owner has boot lifetime. Mutable fields use atomics or
    // UnsafeCell and are serialized by the recursive kernel-entry boundary.
    // Gate 9 may replace that coarse rule with finer per-owner locks.
    unsafe { &*PROCESS_RUNTIME.0.get() }
}

fn mapping_requires_fork_copy(mapping: &cpu::LinuxActiveImageMapping) -> bool {
    !mapping.dontfork
        && !mapping.shared
        && (mapping.writable || !memory::frame_lease_is_runtime(mapping.frame))
}

const PROCESS_CHILD_PROGRAM: [u8; 42] = [
    0x48, 0x85, 0xc0, // test rax, rax
    0x75, 0x23, // jne failure
    0x48, 0x83, 0xfb, 0x55, // cmp rbx, 0x55
    0x75, 0x1d, // jne failure
    0x49, 0x83, 0xff, 0x55, // cmp r15, 0x55
    0x75, 0x17, // jne failure
    0x64, 0xc6, 0x04, 0x25, 0, 0, 0, 0, 0x5a, // mov byte ptr fs:[0], 0x5a
    0xcd, 0x80, // context-check trap
    0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (__NR_exit)
    0xbf, 0x2a, 0, 0, 0, // mov edi, 42
    0xcd, 0x80, // exit(42)
    0x0f, 0x0b, // failure: ud2
];
const CONCURRENT_PROCESS_PROGRAM: [u8; 36] = [
    0x48, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // mov rax, 0x8000001000
    0xf0, 0xff, 0x00, // lock inc dword ptr [rax]
    0x83, 0x38, 0x02, // wait: cmp dword ptr [rax], 2
    0x75, 0xfb, // jne wait
    0x31, 0xc0, // xor eax, eax
    0xcd, 0x80, // context-check trap
    0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (__NR_exit)
    0xbf, 0x2a, 0, 0, 0, // mov edi, 42
    0xcd, 0x80, // exit(42)
    0x0f, 0x0b, // failure: ud2
];
#[allow(dead_code)]
const LIVE_PROCESS_CHILD_PROGRAM: [u8; 16] = [
    0xcd, 0x80, // validate the complete fork-child context
    0xb8, 0x3c, 0, 0, 0, // mov eax, 60 (__NR_exit)
    0xbf, 0x2a, 0, 0, 0, // mov edi, 42
    0xcd, 0x80, // exit(42)
    0x0f, 0x0b, // failure: ud2
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessHandle {
    slot: u16,
    generation: u32,
    pid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessState {
    Preparing,
    Running,
    Stopped { signal: u8 },
    Exiting,
    Zombie { status: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessExecutionContext {
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
}

impl ProcessExecutionContext {
    fn is_valid(self, address_space: &ProcessAddressSpace) -> bool {
        self.validation_error(address_space).is_none()
    }

    /// Whether the registers alone are a context a process may resume in:
    /// canonical user addresses and no privileged flags.
    fn registers_valid(self) -> bool {
        const REQUIRED_RFLAGS: u64 = (1 << 1) | (1 << 9);
        const FORBIDDEN_RFLAGS: u64 = (3 << 12) | (1 << 14) | (1 << 17);
        !(self.rip == 0
            || self.rip >= 1 << 47
            || self.rsp == 0
            || self.rsp >= 1 << 47
            || self.fs_base >= 1 << 47
            || self.rflags & REQUIRED_RFLAGS != REQUIRED_RFLAGS
            || self.rflags & FORBIDDEN_RFLAGS != 0)
    }

    fn validation_error(self, address_space: &ProcessAddressSpace) -> Option<u8> {
        if !self.registers_valid() {
            return Some(1);
        }
        // A stale list may lack the pages the context runs on; the context
        // was checked against the live page tables when it was recorded
        // (`refresh_live_process_context_for_wait`).
        if address_space.stale {
            return None;
        }
        let contains = |mapping: &cpu::LinuxActiveImageMapping, address: u64| {
            u64::try_from(mapping.address).ok().is_some_and(|start| {
                start
                    .checked_add(PAGE_SIZE as u64)
                    .is_some_and(|end| address >= start && address < end)
            })
        };
        let executable = address_space
            .mappings()
            .iter()
            .any(|mapping| mapping.executable && contains(mapping, self.rip));
        let writable_stack = address_space.mappings().iter().any(|mapping| {
            u64::try_from(mapping.address).ok().is_some_and(|start| {
                mapping.writable
                    && start
                        .checked_add(PAGE_SIZE as u64)
                        .is_some_and(|end| self.rsp >= start && self.rsp <= end)
            })
        });
        if !executable {
            Some(2)
        } else if !writable_stack {
            Some(3)
        } else {
            None
        }
    }

    fn fork_child(self) -> Self {
        let mut child = self;
        child.general[PROCESS_RAX_INDEX] = 0;
        child
    }

    fn scheduler_context(
        self,
        address_space: &ProcessAddressSpace,
    ) -> Option<scheduler::ProcessSchedulerContext> {
        self.is_valid(address_space).then_some(())?;
        scheduler::process_user_context(
            self.general,
            self.rip,
            self.rsp,
            self.rflags,
            address_space.root().address(),
            self.fs_base,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ProcessAddressSpace {
    storage_slot: u16,
    hierarchy_count: u32,
    mapping_count: u32,
    /// The process changed its mappings after this snapshot, so its lists
    /// may name frames it already freed and that now belong to others.
    stale: bool,
}

/// A process's page-table frames and mapped pages as its last snapshot found
/// them, each list as long as the process needs.
#[derive(Default)]
struct ProcessAddressSpaceStorage {
    hierarchy: Vec<memory::FrameLease>,
    mappings: Vec<cpu::LinuxActiveImageMapping>,
}

impl ProcessAddressSpaceStorage {
    fn store(
        &mut self,
        hierarchy: &[memory::FrameLease],
        mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Option<()> {
        replace_list(&mut self.hierarchy, hierarchy)?;
        replace_list(&mut self.mappings, mappings)
    }
}

/// Makes `list` a copy of `items`, reusing its buffer, and gives back memory
/// when the list has shrunk to a fraction of it.
fn replace_list<T: Copy>(list: &mut Vec<T>, items: &[T]) -> Option<()> {
    list.clear();
    list.try_reserve_exact(items.len()).ok()?;
    list.extend_from_slice(items);
    if list.capacity() > items.len().saturating_mul(4).max(64) {
        list.shrink_to(items.len());
    }
    Some(())
}

/// Returns the storage for `storage_slot` of the current process instance,
/// allocating it on first use.
fn address_space_storage(storage_slot: usize) -> Option<&'static mut ProcessAddressSpaceStorage> {
    if storage_slot >= PROCESS_RUNTIME_LIMIT {
        return None;
    }
    // SAFETY: the table is only touched here, and the recursive kernel-entry
    // boundary serializes process lifecycle operations.
    let tables = unsafe { &mut *PROCESS_ADDRESS_SPACE_STORAGE.0.get() };
    let table = tables.get_mut(current_process_instance())?;
    if table.len() <= storage_slot {
        table.try_reserve(storage_slot + 1 - table.len()).ok()?;
        table.resize(storage_slot + 1, core::ptr::null_mut());
    }
    let entry = table.get_mut(storage_slot)?;
    if entry.is_null() {
        *entry = alloc::boxed::Box::into_raw(alloc::boxed::Box::default());
    }
    // SAFETY: the pointer comes from a Box that is never freed, and callers
    // do not hold two references to one slot.
    Some(unsafe { &mut **entry })
}

impl ProcessAddressSpace {
    fn new(
        storage_slot: usize,
        hierarchy: &[memory::FrameLease],
        mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Option<Self> {
        if storage_slot >= PROCESS_RUNTIME_LIMIT
            || hierarchy.len() < 4
            || mappings.is_empty()
            || !memory::frames_owned_by(memory::FrameOwner::KERNEL, hierarchy)
            || hierarchy
                .iter()
                .enumerate()
                .any(|(index, frame)| hierarchy[..index].contains(frame))
            || mappings.iter().enumerate().any(|(index, mapping)| {
                mapping.address == 0
                    || !mapping.address.is_multiple_of(PAGE_SIZE)
                    || mapping.writable && mapping.executable
                    || !(memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
                        || memory::frame_lease_is_runtime(mapping.frame))
                    || hierarchy.contains(&mapping.frame)
                    || mappings[..index].iter().any(|prior| {
                        prior.address == mapping.address
                            || prior.frame == mapping.frame && !(mapping.shared && prior.shared)
                    })
            })
            || !address_space::validate_linux_process_address_space(hierarchy, mappings)
        {
            return None;
        }
        address_space_storage(storage_slot)?.store(hierarchy, mappings)?;
        Some(Self {
            storage_slot: u16::try_from(storage_slot).ok()?,
            hierarchy_count: u32::try_from(hierarchy.len()).ok()?,
            mapping_count: u32::try_from(mappings.len()).ok()?,
            stale: false,
        })
    }

    fn from_validated_snapshot(
        storage_slot: usize,
        hierarchy: &[memory::FrameLease],
        mappings: &[cpu::LinuxActiveImageMapping],
    ) -> Option<Self> {
        if storage_slot >= PROCESS_RUNTIME_LIMIT || hierarchy.len() < 4 || mappings.is_empty() {
            return None;
        }
        address_space_storage(storage_slot)?.store(hierarchy, mappings)?;
        Some(Self {
            storage_slot: u16::try_from(storage_slot).ok()?,
            hierarchy_count: u32::try_from(hierarchy.len()).ok()?,
            mapping_count: u32::try_from(mappings.len()).ok()?,
            stale: false,
        })
    }

    fn storage(&self) -> &'static ProcessAddressSpaceStorage {
        // A ProcessAddressSpace exists only after its storage was allocated.
        address_space_storage(usize::from(self.storage_slot))
            .map(|storage| &*storage)
            .expect("process address-space storage is allocated")
    }

    // A copy of the address space made before its lists were last stored
    // can count more entries than they hold; it then sees none (and fails
    // validation) instead of reading past them.
    fn hierarchy(&self) -> &[memory::FrameLease] {
        self.storage()
            .hierarchy
            .get(..self.hierarchy_count as usize)
            .unwrap_or(&[])
    }

    fn root(&self) -> memory::FrameLease {
        self.hierarchy()
            .first()
            .copied()
            .unwrap_or(memory::FrameLease::EMPTY)
    }

    fn mappings(&self) -> &[cpu::LinuxActiveImageMapping] {
        self.storage()
            .mappings
            .get(..self.mapping_count as usize)
            .unwrap_or(&[])
    }

    fn is_valid(&self) -> bool {
        self.is_owned()
            && address_space::validate_linux_process_address_space(
                self.hierarchy(),
                self.mappings(),
            )
    }

    fn is_owned(&self) -> bool {
        memory::frames_owned_by(memory::FrameOwner::KERNEL, self.hierarchy())
            && self.mappings().iter().all(|mapping| {
                memory::frame_lease_is_runtime(mapping.frame)
                    || memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            })
    }

    fn hierarchy_is_owned(&self) -> bool {
        memory::frames_owned_by(memory::FrameOwner::KERNEL, self.hierarchy())
    }

    fn is_live(&self) -> bool {
        memory::any_frame_lease_live(self.hierarchy())
            || self.mappings().iter().any(|mapping| {
                !mapping.shared
                    && !memory::frame_lease_is_runtime(mapping.frame)
                    && memory::any_frame_lease_live(&[mapping.frame])
            })
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.hierarchy()
            .iter()
            .chain(
                self.mappings()
                    .iter()
                    .filter(|mapping| {
                        !mapping.shared && !memory::frame_lease_is_runtime(mapping.frame)
                    })
                    .map(|mapping| &mapping.frame),
            )
            .any(|left| {
                other
                    .hierarchy()
                    .iter()
                    .chain(
                        other
                            .mappings()
                            .iter()
                            .filter(|mapping| {
                                !mapping.shared && !memory::frame_lease_is_runtime(mapping.frame)
                            })
                            .map(|mapping| &mapping.frame),
                    )
                    .any(|right| left.address() == right.address())
            })
    }

    fn scrub_and_release(&self) -> bool {
        if !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, self.hierarchy())
            || self.mappings().iter().any(|mapping| {
                !mapping.shared
                    && !memory::frame_lease_is_runtime(mapping.frame)
                    && !memory::frame_leases_releasable(
                        memory::FrameOwner::KERNEL,
                        &[mapping.frame],
                    )
            })
        {
            return false;
        }
        let mut released =
            memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, self.hierarchy());
        for mapping in self.mappings() {
            if !mapping.shared && !memory::frame_lease_is_runtime(mapping.frame) {
                released &=
                    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[mapping.frame]);
            }
        }
        released
    }
}

#[derive(Clone, Copy)]
struct Process {
    handle: ProcessHandle,
    parent: Option<ProcessHandle>,
    process_group: u32,
    session: u32,
    executed: bool,
    user_namespace: linux_user::UserNamespaceHandle,
    /// Its UTS, IPC, PID and time namespaces: a child starts in its
    /// parent's (those for children, of PID and time).
    namespaces: linux_namespace::Set,
    /// The namespaces a clone it asked for made for its next child (clone
    /// with CLONE_NEWPID and the like), taken when that child is made.
    child_namespaces: Option<linux_namespace::Set>,
    /// Its user and group ids: inherited across fork, kept across exec.
    credentials: linux_user::Credentials,
    runtime_slot: Option<u16>,
    address_space: Option<ProcessAddressSpace>,
    retiring_address_space: Option<ProcessAddressSpace>,
    context: Option<ProcessExecutionContext>,
    scheduler_thread: Option<scheduler::ProcessThreadHandle>,
    cpu_affinity: u64,
    /// sched_setscheduler's policy and static priority, inherited across
    /// fork and kept across exec (what sched_getscheduler and
    /// sched_getparam report; the scheduler itself does not consult them).
    scheduling: (u8, u8),
    /// prctl's timer slack (current, default), in nanoseconds: a child's
    /// both start as the parent's current one, and setting 0 restores the
    /// default.
    timer_slack: (u64, u64),
    /// Stopped by a stop signal while waiting in its kill call: the call
    /// parks until SIGCONT, so the state stays Running for the wait engine
    /// and this marks the stop (what /proc and the parent's wait see).
    stopped_in_call: bool,
    /// POSIX timers (timer_create) by id - 1: none across fork and exec.
    posix_timers: [Option<PosixTimer>; POSIX_TIMER_LIMIT],
    /// setitimer's ITIMER_VIRTUAL and ITIMER_PROF, as timers on the
    /// process's CPU clock (SIGVTALRM, SIGPROF): none in a new child, kept
    /// across exec.
    /// and RLIMIT_CPU's soft (SIGXCPU, then every second) and hard
    /// (SIGKILL) limits as two more.
    itimers: [Option<PosixTimer>; 4],
    /// getrusage's ru_maxrss in KiB: the most the process was seen to hold
    /// resident (at getrusage and as it exits), and the most any child it
    /// waited for (or that child's own waited children) held. A new child
    /// starts with neither.
    maxrss_kib: u64,
    children_maxrss_kib: u64,
    /// SCHED_DEADLINE's runtime, deadline and period in nanoseconds, as
    /// sched_setattr set them (zero for other policies).
    deadline_parameters: [u64; 3],
    /// `/proc/PID/oom_score_adj`: inherited across fork, kept across exec.
    oom_score_adj: i16,
    /// `/proc/PID/io`'s counts: none in a new child, kept across exec.
    io: IoAccounting,
    /// Marked a child subreaper (PR_SET_CHILD_SUBREAPER): its
    /// descendants' orphans are reparented to it rather than to init. Not
    /// inherited across fork, kept across exec.
    child_subreaper: bool,
    /// Its memory policy (set_mempolicy): inherited across fork, kept
    /// across exec, as Linux's task policy is. Linux keeps one per thread;
    /// here the process's threads share it.
    memory_policy: crate::linux_areas::Policy,
    /// The signal whose default action terminated the process, or 0.
    killed_by_signal: u8,
    /// Chosen by a memory cgroup's OOM killer: dying for its memory, so no
    /// other process is killed for the same shortage meanwhile.
    oom_victim: bool,
    /// Its newest seccomp filter (index + 1 in the table's filters), or 0:
    /// inherited across fork, kept across exec.
    seccomp_filter: u32,
    /// The pid of the process tracing this one (ptrace), or 0: not
    /// inherited across fork, kept across exec.
    tracer: u32,
    /// The signal PTRACE_CONT asked to deliver as the tracee resumes from
    /// its trace stop (0: none), and whether that delivery is past the stop.
    ptrace_resume_signal: u8,
    ptrace_bypass: bool,
    /// The debug registers its tracer set (PTRACE_POKEUSER): none in a new
    /// child or after exec.
    debug_registers: DebugRegisters,
    state: ProcessState,
    wait_event: Option<ProcessWaitEvent>,
    /// A child forked onto its parent's pages (CLONE_VM, or a vfork child
    /// with its own stack) that has not executed yet: every page it maps is
    /// its parent's.
    shares_parent_vm: bool,
    /// The objects clone can share between processes, by id: processes
    /// holding the same id share that object (see `SharedResource`).
    shared: [u32; SHARED_RESOURCE_COUNT],
    /// The signal its parent gets when it ends (clone's exit signal): 0 for
    /// none. A child whose signal is not SIGCHLD is a "clone" child, which
    /// only a wait with __WCLONE or __WALL reports.
    exit_signal: u8,
    /// It ended while its parent ignored SIGCHLD (or set SA_NOCLDWAIT): its
    /// parent reaps it at once, leaving no zombie to wait for. A child that
    /// ended before its parent did so stays a zombie, as in Linux.
    reaped_by_parent: bool,
    /// Its cgroup, by the cgroup directory's generation, or 0 for the
    /// domain's root: its parent's, unless it was cloned into another
    /// (CLONE_INTO_CGROUP) or moved (a write to `cgroup.procs`).
    cgroup_generation: u32,
    /// The memory cgroup its user pages are charged to (`linux_cgroup`),
    /// that cgroup's; 0 until it is known (the domain's root then).
    memcg: u16,
    /// The process that cloned this one when that is not its parent
    /// (CLONE_PARENT): the fork transaction that runs it first resumes that
    /// one, not the parent.
    cloned_by: Option<ProcessHandle>,
    /// The child of a vfork (CLONE_VFORK) this process is suspended for
    /// until that child executes or exits, or 0.
    vfork_child: u32,
    /// Gave up the CPU in a blocking system call and has not been dispatched
    /// since: Linux's interruptible sleep ('S').
    waiting: bool,
    /// Asleep in a wait of its own (a single-threaded process's futex wait
    /// or wait for its children) until woken (which clears `waiting`:
    /// a futex wake, a signal, a child's change of state) or this deadline
    /// (0: none), in nanoseconds since boot: the wait's, or a timer of its
    /// own due sooner. Not worth resuming before then.
    futex_sleep: Option<u64>,
    /// CPU time used, in timestamp-counter cycles, and the part of it in
    /// user mode (the rest is system time).
    cpu_cycles: u64,
    user_cycles: u64,
    /// The user and system time of the children it waited for, theirs
    /// included (times' tms_cutime and tms_cstime). A new child starts
    /// with none.
    children_cycles: (u64, u64),
    /// Its task events (`cpu_time::TaskEvent`), and those of the children
    /// it waited for (theirs included), which perf's software counters
    /// count.
    task_events: [u64; crate::cpu_time::TASK_EVENTS],
    children_task_events: [u64; crate::cpu_time::TASK_EVENTS],
    /// When the process was created, in nanoseconds since boot (process
    /// accounting's start time and elapsed time).
    started_nanoseconds: u64,
}

/// What clone can share between processes rather than copy (CLONE_VM,
/// CLONE_FILES, CLONE_FS, CLONE_SIGHAND, CLONE_IO, CLONE_SYSVSEM). Each
/// process names each of these by an id; processes that share one hold the
/// same id, and an id is never handed out twice in a domain, so kcmp(2)
/// compares them and the runtime keeps the shared state of processes with
/// the same id in step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SharedResource {
    Memory,
    Descriptors,
    Filesystem,
    SignalHandlers,
    Io,
    SemaphoreUndo,
}

const SHARED_RESOURCE_COUNT: usize = 6;

/// The signal a child's end sends its parent unless clone named another.
const DEFAULT_EXIT_SIGNAL: u8 = 17;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessWaitEvent {
    Stopped { signal: u8 },
    Continued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitResult {
    pid: u32,
    status: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildWaitState {
    Running,
    Stopped {
        pid: u32,
        signal: u8,
    },
    Continued {
        pid: u32,
    },
    /// `signal` is the signal that killed the process, or 0 if it exited
    /// with `status`.
    Exited {
        pid: u32,
        status: u8,
        signal: u8,
    },
}

#[derive(Clone, Copy)]
pub(crate) struct LiveProcessDispatch {
    pub(crate) pid: u32,
    pub(crate) root: memory::FrameLease,
    pub(crate) general: [u64; 15],
    pub(crate) rip: u64,
    pub(crate) rsp: u64,
    pub(crate) rflags: u64,
    pub(crate) fs_base: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveProcessState {
    Running,
    /// Waiting in a blocking system call.
    Sleeping,
    Stopped,
    Zombie,
}

impl LiveProcessState {
    /// Running or waiting in a system call: neither stopped nor exited.
    pub(crate) const fn is_running(self) -> bool {
        matches!(self, Self::Running | Self::Sleeping)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveProcessStatus {
    pub(crate) pid: u32,
    pub(crate) parent_pid: u32,
    pub(crate) state: LiveProcessState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessGroupError {
    Access,
    NoSuchProcess,
    Permission,
}

struct ProcessTable {
    owner_domain: u64,
    /// Indexed by a handle's slot; grows on demand up to PROCESS_LIMIT and
    /// never shrinks, so slots stay valid.
    processes: Vec<Option<Process>>,
    /// The slot of every process by pid, sorted by pid: a lookup by pid
    /// would otherwise walk thousands of slots.
    pid_slots: Vec<(u32, u16)>,
    /// The generation each slot last handed out, parallel to `processes`.
    generations: Vec<u32>,
    /// Each slot's supplementary groups, sorted, parallel to `processes`:
    /// inherited across fork, emptied when the slot is freed.
    groups: Vec<Vec<u32>>,
    /// Each slot's root directory (chroot) as a canonical path without a
    /// leading slash, parallel to `processes`; empty for the domain's root.
    /// Inherited across fork, kept across exec, emptied when the slot is
    /// freed.
    roots: Vec<Vec<u8>>,
    /// seccomp filters, each with the one installed before it; a process
    /// names its newest. One no process reaches is reused (`install`).
    seccomp_filters: Vec<Option<SeccompFilter>>,
    next_pid: u32,
    /// The next id of a shared object (`Process::shared`).
    next_shared_id: u32,
    /// Some process was cloned sharing runtime state with another (see
    /// `live_processes_share_state`).
    sharing: bool,
    /// The pid the boot CPU's runtime loop last ran from the run queue: the
    /// next turn goes to the ready process after it (`next_ready_live_process`).
    dispatch_cursor: u32,
    init: Option<ProcessHandle>,
    /// The deadlines processes are marked asleep until (`futex_sleep`), by
    /// pid: one entry per mark, checked against the process when looked at
    /// (`next_live_futex_sleep_deadline`) rather than taken out wherever a
    /// mark ends. Lossy after an allocation failure, until rebuilt.
    sleepers: ginux_deadline_heap::DeadlineHeap<u32>,
    sleepers_lossy: bool,
}

/// One installed seccomp program and the filter before it in its chain.
struct SeccompFilter {
    program: ginux_seccomp::Program,
    /// Index + 1 of the previous filter, or 0.
    previous: u32,
    /// The chain's instructions up to here, each filter counting 4 more,
    /// as Linux limits them (MAX_INSNS_PER_PATH).
    path_instructions: usize,
}

/// The most instructions a chain may hold (Linux's MAX_INSNS_PER_PATH).
const SECCOMP_PATH_LIMIT: usize = 32_768;

impl ProcessTable {
    const fn new() -> Self {
        Self {
            owner_domain: 0,
            processes: Vec::new(),
            pid_slots: Vec::new(),
            generations: Vec::new(),
            groups: Vec::new(),
            roots: Vec::new(),
            seccomp_filters: Vec::new(),
            next_pid: 1,
            next_shared_id: 1,
            sharing: false,
            dispatch_cursor: 0,
            init: None,
            sleepers: ginux_deadline_heap::DeadlineHeap::new(),
            sleepers_lossy: false,
        }
    }

    /// A shared-object id no process holds yet.
    fn new_shared_id(&mut self) -> u32 {
        let id = self.next_shared_id;
        self.next_shared_id = id.wrapping_add(1).max(1);
        id
    }

    fn create_init(
        &mut self,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
    ) -> Option<ProcessHandle> {
        if self.init.is_some()
            || self.next_pid != 1
            || !address_space.is_valid()
            || !context.is_valid(&address_space)
        {
            return None;
        }
        let user_namespace = linux_user::initial()?;
        let handle = self.allocate(
            None,
            user_namespace,
            Some(address_space),
            Some(context),
            ProcessState::Running,
        )?;
        if handle.pid != 1 {
            return None;
        }
        self.init = Some(handle);
        Some(handle)
    }

    fn scheduler_domain(&self) -> u64 {
        if self.owner_domain == 0 {
            1
        } else {
            self.owner_domain
        }
    }

    /// The lowest runtime slot no process holds: one pass marks the slots
    /// in use, as a table of thousands of processes would otherwise be
    /// scanned once per slot tried.
    fn free_runtime_slot(&self) -> Option<usize> {
        let mut used = [0_u64; PROCESS_RUNTIME_LIMIT.div_ceil(64)];
        for slot in self
            .processes
            .iter()
            .flatten()
            .filter_map(|process| process.runtime_slot)
        {
            if let Some(word) = used.get_mut(usize::from(slot) / 64) {
                *word |= 1 << (slot % 64);
            }
        }
        used.iter()
            .enumerate()
            .find(|(_, word)| **word != u64::MAX)
            .map(|(index, word)| index * 64 + word.trailing_ones() as usize)
            .filter(|slot| *slot < PROCESS_RUNTIME_LIMIT)
    }

    fn prepare_fork(&mut self, parent: ProcessHandle) -> Option<ProcessHandle> {
        let parent_process = self.process(parent)?;
        if parent_process.state != ProcessState::Running
            || parent_process.address_space.is_none()
            || parent_process.context.is_none()
        {
            return None;
        }
        let user_namespace = parent_process.user_namespace;
        linux_user::credentials(user_namespace)?;
        self.allocate(
            Some(parent),
            user_namespace,
            None,
            None,
            ProcessState::Preparing,
        )
    }

    fn refresh_process_inner(
        &mut self,
        handle: ProcessHandle,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
        validate_address_space: bool,
    ) -> bool {
        if validate_address_space && !address_space.is_valid() || !context.is_valid(&address_space)
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if linux_user::credentials(process.user_namespace).is_none()
            || process.retiring_address_space.is_some()
            || process.state != ProcessState::Running
        {
            return false;
        }
        process.address_space = Some(address_space);
        process.runtime_slot = Some(address_space.storage_slot);
        process.context = Some(context);
        true
    }

    fn commit_fork(
        &mut self,
        handle: ProcessHandle,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
    ) -> bool {
        self.commit_fork_inner(handle, address_space, context, true)
    }

    fn commit_fork_inner(
        &mut self,
        handle: ProcessHandle,
        address_space: ProcessAddressSpace,
        context: ProcessExecutionContext,
        validate_address_space: bool,
    ) -> bool {
        if !context.is_valid(&address_space)
            || validate_address_space
                && (!address_space.is_valid()
                    || self.processes.iter().flatten().any(|process| {
                        // A stale list may name frames freed since and now
                        // another's; the live page tables are its record.
                        process.address_space.is_some_and(|existing| {
                            !existing.stale && existing.overlaps(&address_space)
                        }) || process
                            .retiring_address_space
                            .is_some_and(|existing| existing.overlaps(&address_space))
                    }))
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Preparing
            || process.address_space.is_some()
            || process.retiring_address_space.is_some()
            || process.context.is_some()
            || process.scheduler_thread.is_some()
        {
            return false;
        }
        process.address_space = Some(address_space);
        process.runtime_slot = Some(address_space.storage_slot);
        process.context = Some(context);
        process.state = ProcessState::Running;
        true
    }

    fn admit_to_scheduler(
        &mut self,
        handle: ProcessHandle,
        run_queue: &mut scheduler::ProcessScheduler,
        domain: u64,
    ) -> bool {
        let Some(process) = self.process(handle).copied() else {
            return false;
        };
        let (Some(address_space), Some(context)) = (process.address_space, process.context) else {
            return false;
        };
        if process.state != ProcessState::Running || process.scheduler_thread.is_some() {
            return false;
        }
        let Some(scheduler_context) = context.scheduler_context(&address_space) else {
            return false;
        };
        let Some(thread) = run_queue.admit(domain, scheduler_context) else {
            return false;
        };
        if !run_queue.set_affinity(thread, process.cpu_affinity) {
            let _ = run_queue.retire(thread);
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            let _ = run_queue.retire(thread);
            return false;
        };
        if process.state != ProcessState::Running || process.scheduler_thread.is_some() {
            let _ = run_queue.retire(thread);
            return false;
        }
        process.scheduler_thread = Some(thread);
        true
    }

    fn withdraw_from_scheduler(
        &mut self,
        handle: ProcessHandle,
        run_queue: &mut scheduler::ProcessScheduler,
    ) -> bool {
        let Some(thread) = self
            .process(handle)
            .and_then(|process| process.scheduler_thread)
        else {
            crate::serial_write(
                "ginux: process withdraw missing scheduler thread pid/slot/generation: ",
            );
            crate::serial_write_u64(u64::from(handle.pid));
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(handle.slot));
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(handle.generation));
            crate::serial_write("\r\n");
            return false;
        };
        if !run_queue.retire(thread) {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.scheduler_thread != Some(thread) {
            return false;
        }
        process.scheduler_thread = None;
        true
    }

    fn commit_cloned_fork(
        &mut self,
        handle: ProcessHandle,
        child_hierarchy: &[memory::FrameLease],
        child_pages: &[memory::FrameLease],
        share_vm: bool,
    ) -> bool {
        process_runtime()
            .fork_execution_stage
            .store(1131, Ordering::Release);
        let Some(preparing) = self.process(handle) else {
            return false;
        };
        if preparing.state != ProcessState::Preparing
            || preparing.address_space.is_some()
            || preparing.retiring_address_space.is_some()
        {
            return false;
        }
        let Some(parent_handle) = preparing.parent else {
            let _ = self.abort_fork(handle);
            return false;
        };
        let Some(parent) = self.process(parent_handle) else {
            let _ = self.abort_fork(handle);
            return false;
        };
        let Some(parent_space) = parent.address_space.as_ref() else {
            let _ = self.abort_fork(handle);
            return false;
        };
        let Some(parent_context) = parent.context else {
            let _ = self.abort_fork(handle);
            return false;
        };
        process_runtime()
            .fork_execution_stage
            .store(1132, Ordering::Release);
        // Each reason the commit can refuse the prepared child has a stage
        // of its own, so a fork that fails with EAGAIN names it in the log.
        let parent_pid = parent.handle.pid;
        let hierarchy_owned = if share_vm {
            parent_space.hierarchy_is_owned()
        } else {
            parent_space.is_owned()
        };
        let copy_count = parent_space
            .mappings()
            .iter()
            .filter(|mapping| !mapping.dontfork && mapping_requires_fork_copy(mapping))
            .count();
        let refused = if parent.state != ProcessState::Running {
            Some(1191)
        } else if !hierarchy_owned {
            Some(1192)
        } else if child_hierarchy.len() != parent_space.hierarchy().len() {
            Some(1193)
        } else if !child_pages.is_empty() && child_pages.len() != copy_count {
            Some(1194)
        } else {
            None
        };
        if let Some(stage) = refused {
            process_runtime()
                .fork_execution_stage
                .store(stage, Ordering::Release);
            let _ = self.abort_fork(handle);
            return false;
        }
        // Sets stages 1195..=1199 itself, one per check that can refuse.
        if !self.resources_available(parent_pid, child_hierarchy, child_pages) {
            let _ = self.abort_fork(handle);
            return false;
        }

        let scratch = unsafe { &mut *process_scratch().fork_scratch.get() };
        process_runtime()
            .fork_execution_stage
            .store(1133, Ordering::Release);
        let parent_page_capacity = if child_pages.is_empty() {
            0
        } else {
            child_pages.len()
        };
        if address_space::fill_list(
            &mut scratch.child_mappings,
            parent_space.mappings().len(),
            cpu::LinuxActiveImageMapping::EMPTY,
        )
        .is_none()
            || address_space::fill_list(
                &mut scratch.parent_pages,
                parent_page_capacity,
                memory::FrameLease::EMPTY,
            )
            .is_none()
        {
            let _ = self.abort_fork(handle);
            return false;
        }
        let child_mappings = &mut scratch.child_mappings;
        let parent_pages = &mut scratch.parent_pages;
        let mut private_index = 0;
        let mut child_mapping_count = 0;
        for parent in parent_space.mappings() {
            if parent.dontfork && !share_vm {
                continue;
            }
            let frame = if child_pages.is_empty() || !mapping_requires_fork_copy(parent) {
                parent.frame
            } else {
                let frame = *child_pages
                    .get(private_index)
                    .unwrap_or(&memory::FrameLease::EMPTY);
                private_index += 1;
                frame
            };
            child_mappings[child_mapping_count] = cpu::LinuxActiveImageMapping {
                address: parent.address,
                frame,
                writable: parent.writable,
                executable: parent.executable,
                shared: share_vm || parent.shared,
                dontfork: false,
            };
            child_mapping_count += 1;
        }
        let mut parent_page_count = 0;
        if !child_pages.is_empty() {
            for mapping in parent_space
                .mappings()
                .iter()
                .filter(|mapping| !mapping.dontfork && mapping_requires_fork_copy(mapping))
            {
                parent_pages[parent_page_count] = mapping.frame;
                parent_page_count += 1;
            }
        }
        process_runtime()
            .fork_execution_stage
            .store(1134, Ordering::Release);
        let published = child_pages.is_empty()
            || private_index == child_pages.len()
                && parent_page_count == child_pages.len()
                && copy_validated_private_pages(
                    parent_space.mappings(),
                    parent_space.root(),
                    &parent_pages[..parent_page_count],
                    child_pages,
                );
        process_runtime()
            .fork_execution_stage
            .store(1135, Ordering::Release);
        let published = published
            && address_space::clone_validated_linux_process_hierarchy(
                parent_space.mappings(),
                parent_space.hierarchy(),
                child_hierarchy,
                child_pages,
                share_vm,
            );
        process_runtime()
            .fork_execution_stage
            .store(1136, Ordering::Release);
        let child_space = if published {
            process_runtime()
                .fork_execution_stage
                .store(11361, Ordering::Release);
            let Some(storage_slot) = self.free_runtime_slot() else {
                if child_pages.is_empty() {
                    let _ = address_space::release_linux_leaf_pages(child_hierarchy[0]);
                }
                let _ = scrub_candidate_resources(child_hierarchy, child_pages);
                let _ = self.abort_fork(handle);
                return false;
            };
            ProcessAddressSpace::from_validated_snapshot(
                storage_slot,
                child_hierarchy,
                &child_mappings[..child_mapping_count],
            )
        } else {
            None
        };
        process_runtime()
            .fork_execution_stage
            .store(1137, Ordering::Release);
        if child_space.is_none() {
            crate::serial_write("ginux: runtime fork clone state published/hierarchy/mappings: ");
            crate::serial_write_u64(u64::from(published));
            crate::serial_write(" ");
            crate::serial_write_u64(child_hierarchy.len() as u64);
            crate::serial_write(" ");
            crate::serial_write_u64(child_mapping_count as u64);
            crate::serial_write("\r\n");
        }
        if let Some(child_space) = child_space {
            process_runtime()
                .fork_execution_stage
                .store(1138, Ordering::Release);
            let attachments_inherited =
                crate::linux_sysv_ipc::inherit_process_attachments(parent_handle.pid, handle.pid)
                    .is_ok();
            process_runtime().fork_execution_stage.store(
                if attachments_inherited { 11381 } else { 11380 },
                Ordering::Release,
            );
            if attachments_inherited
                && self.commit_fork_inner(handle, child_space, parent_context.fork_child(), false)
            {
                if let Some(child) = self.process_mut(handle) {
                    child.shares_parent_vm = share_vm;
                }
                process_runtime()
                    .fork_execution_stage
                    .store(1139, Ordering::Release);
                return true;
            }
            if attachments_inherited {
                process_runtime()
                    .fork_execution_stage
                    .store(11382, Ordering::Release);
                crate::serial_write("ginux: runtime fork child context validation error: ");
                crate::serial_write_u64(u64::from(
                    parent_context
                        .fork_child()
                        .validation_error(&child_space)
                        .unwrap_or(0),
                ));
                crate::serial_write("\r\n");
            }
            if attachments_inherited {
                let _ = crate::linux_sysv_ipc::drop_process_attachments(handle.pid);
            }
        }
        if published && child_pages.is_empty() {
            let _ = address_space::release_linux_leaf_pages(child_hierarchy[0]);
        }
        let _ = scrub_candidate_resources(child_hierarchy, child_pages);
        let _ = self.abort_fork(handle);
        false
    }

    fn resources_available(
        &self,
        parent_pid: u32,
        hierarchy: &[memory::FrameLease],
        pages: &[memory::FrameLease],
    ) -> bool {
        // The candidates, sorted: each is checked against every frame the
        // processes use by binary search, since a large process's lists made
        // a pairwise check take seconds.
        let mut candidates = Vec::new();
        if candidates
            .try_reserve_exact(hierarchy.len() + pages.len())
            .is_err()
        {
            return false;
        }
        candidates.extend(
            hierarchy
                .iter()
                .chain(pages)
                .map(|frame| (frame.address(), frame.generation())),
        );
        candidates.sort_unstable();
        // Distinct, within and between the two lists.
        let unique = candidates.windows(2).all(|pair| pair[0].0 != pair[1].0);
        // A process's registry lists are a snapshot that goes stale while it
        // runs (a thread on another CPU frees page tables without a refresh):
        // a lease behind the frame's current generation names a frame freed
        // and reused since, not one still held. Only a lease of the same
        // generation marks a frame as published.
        let candidate = |frame: &memory::FrameLease| {
            candidates
                .binary_search(&(frame.address(), frame.generation()))
                .is_ok()
        };
        // Every process's lists are checked while the table is small; past
        // that, the parent's, which the child's frames are copies of: every
        // process's at every fork made forking a thousand children take
        // seconds per hundred (futex_cmp_requeue01), and a frame lease of
        // the frame's current generation in another list would be the
        // allocator issuing it twice, not a stale list.
        let checked = |process: &&Process| {
            self.processes.len() <= FORK_CHECK_ALL_LIMIT || process.handle.pid == parent_pid
        };
        let unpublished = self
            .processes
            .iter()
            .flatten()
            .filter(checked)
            .all(|process| {
                process.address_space.into_iter().all(|space| {
                    !space.hierarchy().iter().any(candidate)
                        && !space.mappings().iter().any(|mapping| {
                            !mapping.shared
                                && !memory::frame_lease_is_runtime(mapping.frame)
                                && candidate(&mapping.frame)
                        })
                })
            });
        let refuse = |stage: u32| {
            process_runtime()
                .fork_execution_stage
                .store(stage, Ordering::Release);
            false
        };
        if hierarchy.len() < 4 {
            return refuse(1195);
        }
        if !memory::frames_owned_by(memory::FrameOwner::KERNEL, hierarchy) {
            return refuse(1196);
        }
        if !(pages.is_empty() || memory::frames_owned_by(memory::FrameOwner::KERNEL, pages)) {
            return refuse(1197);
        }
        if !unique {
            return refuse(1198);
        }
        if !unpublished {
            // Which process still lists a candidate frame, for the log: a
            // child that exited on another CPU may not have dropped its list
            // yet when the allocator hands its frames to this fork.
            let listed = self.processes.iter().flatten().find_map(|process| {
                let space = process.address_space.as_ref()?;
                let in_hierarchy = space.hierarchy().iter().find(|frame| candidate(frame));
                let in_mappings = space.mappings().iter().find(|mapping| {
                    !mapping.shared
                        && !memory::frame_lease_is_runtime(mapping.frame)
                        && candidate(&mapping.frame)
                });
                match (in_hierarchy, in_mappings) {
                    (Some(frame), _) => Some((process, frame.address(), 0_u64, 0_u64)),
                    (None, Some(mapping)) => {
                        Some((process, mapping.frame.address(), 1, mapping.address as u64))
                    }
                    (None, None) => None,
                }
            });
            if let Some((process, frame, in_mapping, address)) = listed {
                // The listing process's lease generation against the new
                // allocation's: behind it, the frame was freed under that
                // process and reused; equal, the allocator issued it twice.
                let listed_generation = process
                    .address_space
                    .as_ref()
                    .and_then(|space| {
                        space
                            .hierarchy()
                            .iter()
                            .copied()
                            .chain(space.mappings().iter().map(|mapping| mapping.frame))
                            .find(|lease| lease.address() == frame)
                    })
                    .map_or(0, |lease| u64::from(lease.generation()));
                let new_generation = hierarchy
                    .iter()
                    .chain(pages)
                    .find(|lease| lease.address() == frame)
                    .map_or(0, |lease| u64::from(lease.generation()));
                crate::serial_write(
                    "ginux: fork frames still listed by pid/not-running/frame/in-mapping/address/its-generation/new-generation, forking parent: ",
                );
                for value in [
                    u64::from(process.handle.pid),
                    u64::from(process.state != ProcessState::Running),
                    frame,
                    in_mapping,
                    address,
                    listed_generation,
                    new_generation,
                    u64::from(parent_pid),
                ] {
                    crate::serial_write_u64(value);
                    crate::serial_write(" ");
                }
                crate::serial_write("\r\n");
            }
            return refuse(1199);
        }
        true
    }

    fn abort_fork(&mut self, handle: ProcessHandle) -> bool {
        let Some(process) = self.process(handle) else {
            return false;
        };
        if process.state != ProcessState::Preparing
            || process.address_space.is_some()
            || process.retiring_address_space.is_some()
            || process.context.is_some()
            || process.scheduler_thread.is_some()
        {
            return false;
        }
        self.processes[usize::from(handle.slot)] = None;
        self.forget_pid_slot(handle.pid);
        self.groups[usize::from(handle.slot)] = Vec::new();
        self.roots[usize::from(handle.slot)] = Vec::new();
        linux_namespace::forget_pid(cpu::current_linux_execution_instance(), handle.pid);
        true
    }

    fn begin_exit(
        &mut self,
        handle: ProcessHandle,
        expected_space: ProcessAddressSpace,
    ) -> Option<ProcessAddressSpace> {
        let process = self.process_mut(handle)?;
        if process.state != ProcessState::Running
            || process.address_space != Some(expected_space)
            || process.retiring_address_space.is_some()
            || process.context.is_none()
            || process.scheduler_thread.is_some()
            || !expected_space.is_owned()
        {
            return None;
        }
        process.address_space = None;
        process.retiring_address_space = Some(expected_space);
        process.context = None;
        process.state = ProcessState::Exiting;
        // However it ends, a tracer leaves its tracees running.
        self.detach_tracees(handle.pid);
        Some(expected_space)
    }

    /// Detaches every process `tracer` traces and continues the stopped
    /// ones, as Linux's exit_ptrace does.
    fn detach_tracees(&mut self, tracer: u32) {
        if tracer == 0 {
            return;
        }
        for slot in 0..self.processes.len() {
            let Some(handle) = self.processes[slot]
                .as_ref()
                .filter(|process| process.tracer == tracer)
                .map(|process| process.handle)
            else {
                continue;
            };
            if let Some(process) = self.process_mut(handle) {
                process.tracer = 0;
                process.ptrace_resume_signal = 0;
            }
            let _ = self.continue_process(handle);
        }
    }

    /// Clears `waiting` of whoever waits for `handle` to change state: its
    /// parent and its tracer. A process asleep in a wait for its children
    /// (`Process::is_asleep`) is skipped by the scheduler until then; any
    /// other wait it is in only looks again.
    fn wake_state_waiters(&mut self, handle: ProcessHandle) {
        let Some((parent, tracer)) = self
            .process(handle)
            .map(|process| (process.parent, process.tracer))
        else {
            return;
        };
        let tracer = (tracer != 0).then(|| self.handle_by_pid(tracer)).flatten();
        for waiter in [parent, tracer].into_iter().flatten() {
            if let Some(process) = self.process_mut(waiter) {
                process.waiting = false;
            }
        }
    }

    fn exit(&mut self, handle: ProcessHandle, status: u8) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Exiting
            || process.address_space.is_some()
            || process.context.is_some()
            || process.scheduler_thread.is_some()
        {
            return false;
        }
        let Some(retiring) = process.retiring_address_space else {
            return false;
        };
        if retiring.is_live() {
            return false;
        }
        process.retiring_address_space = None;
        process.wait_event = None;
        process.state = ProcessState::Zombie { status };
        self.wake_state_waiters(handle);
        self.reparent_children_to_init(handle);
        true
    }

    /// Hands the children of an exiting process, running or already zombies,
    /// to its nearest living ancestor marked a child subreaper
    /// (PR_SET_CHILD_SUBREAPER), or else to the domain's init, as Linux's
    /// find_new_reaper does, so that their exit status can still be
    /// collected and their slots reused.
    fn reparent_children_to_init(&mut self, handle: ProcessHandle) {
        let alive = |table: &Self, candidate: ProcessHandle| {
            candidate != handle
                && table.process(candidate).is_some_and(|process| {
                    matches!(
                        process.state,
                        ProcessState::Running | ProcessState::Stopped { .. }
                    )
                })
        };
        let init = self.handle_by_pid(1).filter(|init| alive(self, *init));
        let mut subreaper = None;
        let mut ancestor = self.process(handle).and_then(|process| process.parent);
        for _ in 0..PROCESS_LIMIT {
            let Some(candidate) = ancestor.filter(|candidate| Some(*candidate) != init) else {
                break;
            };
            let Some(process) = self.process(candidate) else {
                break;
            };
            if process.child_subreaper && alive(self, candidate) {
                subreaper = Some(candidate);
                break;
            }
            ancestor = process.parent;
        }
        let Some(init) = subreaper.or(init) else {
            return;
        };
        // An adopted child ends with SIGCHLD to init, whatever its clone
        // asked of its first parent, as in Linux.
        let mut adopted = false;
        for process in self.processes.iter_mut().flatten() {
            if process.parent == Some(handle) {
                process.parent = Some(init);
                process.exit_signal = DEFAULT_EXIT_SIGNAL;
                adopted = true;
            }
        }
        // Init may wait for children already gone.
        if adopted {
            if let Some(init) = self.process_mut(init) {
                init.waiting = false;
            }
        }
    }

    fn exit_after_current_address_space_retired(
        &mut self,
        handle: ProcessHandle,
        status: u8,
    ) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Running || process.scheduler_thread.is_some() {
            return false;
        }
        process.address_space = None;
        process.retiring_address_space = None;
        process.context = None;
        process.wait_event = None;
        process.state = ProcessState::Zombie { status };
        self.wake_state_waiters(handle);
        self.reparent_children_to_init(handle);
        true
    }

    fn exit_after_retiring_address_space_released(
        &mut self,
        handle: ProcessHandle,
        expected_space: ProcessAddressSpace,
        status: u8,
    ) -> bool {
        let Some(process) = self.process(handle) else {
            return false;
        };
        if process.state != ProcessState::Exiting
            || process.address_space.is_some()
            || process.retiring_address_space != Some(expected_space)
            || process.context.is_some()
            || process.scheduler_thread.is_some()
            || expected_space
                .hierarchy()
                .iter()
                .any(|frame| memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame]))
        {
            return false;
        }
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        process.retiring_address_space = None;
        process.wait_event = None;
        process.state = ProcessState::Zombie { status };
        self.wake_state_waiters(handle);
        self.reparent_children_to_init(handle);
        true
    }

    fn wait(&mut self, parent: ProcessHandle, pid: u32) -> Option<WaitResult> {
        if self.process(parent)?.state != ProcessState::Running {
            return None;
        }
        let slot = self.processes.iter().position(|candidate| {
            candidate.is_some_and(|process| {
                process.handle.pid == pid
                    && process.parent == Some(parent)
                    && matches!(process.state, ProcessState::Zombie { .. })
            })
        })?;
        let process = self.processes[slot].take()?;
        self.forget_pid_slot(process.handle.pid);
        self.groups[slot] = Vec::new();
        self.roots[slot] = Vec::new();
        let ProcessState::Zombie { status } = process.state else {
            return None;
        };
        // The child's CPU time, and its own children's, joins the parent's
        // children's, as Linux adds it when a wait reaps the child.
        if let Some(parent) = self.process_mut(parent) {
            let system = process.cpu_cycles.saturating_sub(process.user_cycles);
            parent.children_cycles.0 = parent
                .children_cycles
                .0
                .saturating_add(process.user_cycles)
                .saturating_add(process.children_cycles.0);
            parent.children_cycles.1 = parent
                .children_cycles
                .1
                .saturating_add(system)
                .saturating_add(process.children_cycles.1);
            for event in 0..crate::cpu_time::TASK_EVENTS {
                parent.children_task_events[event] = parent.children_task_events[event]
                    .saturating_add(process.task_events[event])
                    .saturating_add(process.children_task_events[event]);
            }
        }
        if self
            .processes
            .iter()
            .flatten()
            .all(|candidate| candidate.user_namespace != process.user_namespace)
        {
            let _ = linux_user::retire(process.user_namespace);
        }
        linux_namespace::forget_pid(cpu::current_linux_execution_instance(), pid);
        self.collect_namespaces();
        Some(WaitResult { pid, status })
    }

    fn child_wait_state(
        &self,
        parent: ProcessHandle,
        pid: Option<u32>,
        report_stopped: bool,
        report_continued: bool,
    ) -> Option<ChildWaitState> {
        self.child_wait_state_matching(
            parent,
            |process| pid.is_none_or(|pid| process.handle.pid == pid),
            true,
            report_stopped,
            report_continued,
        )
    }

    fn child_group_wait_state(
        &self,
        parent: ProcessHandle,
        process_group: u32,
        report_stopped: bool,
        report_continued: bool,
    ) -> Option<ChildWaitState> {
        self.child_wait_state_matching(
            parent,
            |process| process.process_group == process_group,
            true,
            report_stopped,
            report_continued,
        )
    }

    /// The wait-visible state of the first matching child. Exited children
    /// are reported only with `report_exited`: waitid(2) without WEXITED
    /// must not see, and so must not reap, them.
    fn child_wait_state_matching(
        &self,
        parent: ProcessHandle,
        matches: impl Fn(&Process) -> bool,
        report_exited: bool,
        report_stopped: bool,
        report_continued: bool,
    ) -> Option<ChildWaitState> {
        if self.process(parent)?.state != ProcessState::Running {
            return None;
        }
        // A tracer waits for its tracees as for its children.
        let parent_pid = parent.pid;
        let mut children = self.processes.iter().flatten().filter(|process| {
            (process.parent == Some(parent) || process.tracer == parent_pid && parent_pid != 0)
                && matches(process)
        });
        // A tracer is told of its tracee's stops without WUNTRACED.
        let stops_reported =
            |process: &Process| report_stopped || process.tracer == parent_pid && parent_pid != 0;
        let child = children
            .clone()
            .find(|process| {
                report_exited
                    && process.parent == Some(parent)
                    && matches!(process.state, ProcessState::Zombie { .. })
            })
            .or_else(|| {
                children.clone().find(|process| {
                    stops_reported(process)
                        && matches!(process.wait_event, Some(ProcessWaitEvent::Stopped { .. }))
                        || report_continued
                            && process.parent == Some(parent)
                            && process.wait_event == Some(ProcessWaitEvent::Continued)
                })
            })
            .or_else(|| children.next())?;
        if stops_reported(child) {
            if let Some(ProcessWaitEvent::Stopped { signal }) = child.wait_event {
                return Some(ChildWaitState::Stopped {
                    pid: child.handle.pid,
                    signal,
                });
            }
        }
        // A tracee that is not a child is the tracer's to see stop only:
        // its parent reaps it.
        if child.parent != Some(parent) {
            return Some(ChildWaitState::Running);
        }
        if report_continued && child.wait_event == Some(ProcessWaitEvent::Continued) {
            return Some(ChildWaitState::Continued {
                pid: child.handle.pid,
            });
        }
        match child.state {
            ProcessState::Running
            | ProcessState::Stopped { .. }
            | ProcessState::Preparing
            | ProcessState::Exiting => Some(ChildWaitState::Running),
            ProcessState::Zombie { .. } if !report_exited => Some(ChildWaitState::Running),
            ProcessState::Zombie { status } => Some(ChildWaitState::Exited {
                pid: child.handle.pid,
                status,
                signal: child.killed_by_signal,
            }),
        }
    }

    /// Stops a running process with stop signal `signal`: `in_call` for one
    /// that parks in its kill call (its state stays Running for the wait
    /// engine), else one that left the CPU and is not dispatched again
    /// until continued.
    fn stop(&mut self, handle: ProcessHandle, signal: u8, in_call: bool) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.state != ProcessState::Running || process.stopped_in_call || signal == 0 {
            return false;
        }
        if in_call {
            process.stopped_in_call = true;
        } else {
            process.state = ProcessState::Stopped { signal };
        }
        process.wait_event = Some(ProcessWaitEvent::Stopped { signal });
        self.wake_state_waiters(handle);
        true
    }

    fn continue_process(&mut self, handle: ProcessHandle) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        if process.stopped_in_call {
            process.stopped_in_call = false;
        } else if matches!(process.state, ProcessState::Stopped { .. }) {
            process.state = ProcessState::Running;
        } else {
            return false;
        }
        process.wait_event = Some(ProcessWaitEvent::Continued);
        self.wake_state_waiters(handle);
        true
    }

    fn consume_wait_event(&mut self, parent: ProcessHandle, pid: u32) -> bool {
        let Some(handle) = self.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        let traced = process.tracer == parent.pid && parent.pid != 0;
        if process.parent != Some(parent) && !traced || process.wait_event.is_none() {
            return false;
        }
        process.wait_event = None;
        true
    }

    fn reap_init_zombies(&mut self) -> bool {
        let Some(init) = self.init else {
            return false;
        };
        loop {
            let Some(pid) = self
                .processes
                .iter()
                .flatten()
                .find(|process| {
                    process.parent == Some(init)
                        && matches!(process.state, ProcessState::Zombie { .. })
                })
                .map(|process| process.handle.pid)
            else {
                return true;
            };
            if self.wait(init, pid).is_none() {
                return false;
            }
        }
    }

    fn reap_all_zombies(&mut self) -> bool {
        for slot in 0..self.processes.len() {
            let Some(candidate) = self.processes[slot].as_ref() else {
                continue;
            };
            if matches!(candidate.state, ProcessState::Zombie { .. }) {
                if candidate.address_space.is_some()
                    || candidate.retiring_address_space.is_some()
                    || candidate.scheduler_thread.is_some()
                {
                    return false;
                }
                let pid = candidate.handle.pid;
                self.processes[slot] = None;
                self.forget_pid_slot(pid);
            }
        }
        true
    }

    fn handle_by_pid(&self, pid: u32) -> Option<ProcessHandle> {
        let index = self
            .pid_slots
            .binary_search_by_key(&pid, |(pid, _)| *pid)
            .ok()?;
        let slot = usize::from(self.pid_slots[index].1);
        self.processes
            .get(slot)?
            .as_ref()
            .filter(|process| process.handle.pid == pid)
            .map(|process| process.handle)
    }

    /// Forgets slot `slot`'s process (`pid`) in the pid index.
    fn forget_pid_slot(&mut self, pid: u32) {
        if let Ok(index) = self.pid_slots.binary_search_by_key(&pid, |(pid, _)| *pid) {
            self.pid_slots.remove(index);
        }
    }

    fn set_return_value(&mut self, handle: ProcessHandle, value: u64) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        let Some(mut context) = process.context else {
            return false;
        };
        if process.state != ProcessState::Running {
            return false;
        }
        context.general[PROCESS_RAX_INDEX] = value;
        process.context = Some(context);
        true
    }

    fn set_stack_pointer(&mut self, handle: ProcessHandle, stack: u64) -> bool {
        let Some(process) = self.process_mut(handle) else {
            return false;
        };
        let Some(mut context) = process.context else {
            return false;
        };
        if process.state != ProcessState::Running || stack == 0 {
            return false;
        }
        context.rsp = stack;
        process.context = Some(context);
        true
    }

    fn dispatch(&mut self, handle: ProcessHandle) -> Option<LiveProcessDispatch> {
        let process = self.process_mut(handle)?;
        process.waiting = false;
        process.futex_sleep = None;
        let process = self.process(handle)?;
        let address_space = process.address_space.as_ref()?;
        let context = process.context?;
        if process.state != ProcessState::Running || !context.is_valid(address_space) {
            return None;
        }
        Some(LiveProcessDispatch {
            pid: handle.pid,
            root: address_space.root(),
            general: context.general,
            rip: context.rip,
            rsp: context.rsp,
            rflags: context.rflags,
            fs_base: context.fs_base,
        })
    }

    fn allocate(
        &mut self,
        parent: Option<ProcessHandle>,
        user_namespace: linux_user::UserNamespaceHandle,
        address_space: Option<ProcessAddressSpace>,
        context: Option<ProcessExecutionContext>,
        state: ProcessState,
    ) -> Option<ProcessHandle> {
        let slot = match self.processes.iter().position(Option::is_none) {
            Some(slot) => slot,
            None if self.processes.len() < PROCESS_LIMIT => {
                self.processes.try_reserve(1).ok()?;
                self.generations.try_reserve(1).ok()?;
                self.groups.try_reserve(1).ok()?;
                self.roots.try_reserve(1).ok()?;
                self.processes.push(None);
                self.generations.push(0);
                self.groups.push(Vec::new());
                self.roots.push(Vec::new());
                self.processes.len() - 1
            }
            None => return None,
        };
        self.pid_slots.try_reserve(1).ok()?;
        let generation = self.generations[slot].checked_add(1)?;
        let pid = self.next_pid;
        self.next_pid = self.next_pid.checked_add(1)?;
        let handle = ProcessHandle {
            slot: u16::try_from(slot).ok()?,
            generation,
            pid,
        };
        let (process_group, session, cpu_affinity, scheduling, oom_score_adj, credentials) =
            parent.and_then(|parent| self.process(parent)).map_or(
                (pid, pid, u64::MAX, (0, 0), 0, linux_user::Credentials::ROOT),
                |parent| {
                    (
                        parent.process_group,
                        parent.session,
                        parent.cpu_affinity,
                        if parent.scheduling.0 & SCHED_RESET_ON_FORK == 0 {
                            parent.scheduling
                        } else {
                            (0, 0)
                        },
                        parent.oom_score_adj,
                        parent.credentials,
                    )
                },
            );
        let timer_slack = parent
            .and_then(|parent| self.process(parent))
            .map_or((DEFAULT_TIMER_SLACK, DEFAULT_TIMER_SLACK), |parent| {
                (parent.timer_slack.0, parent.timer_slack.0)
            });
        let seccomp_filter = parent
            .and_then(|parent| self.process(parent))
            .map_or(0, |parent| parent.seccomp_filter);
        // A child starts in its parent's cgroup.
        let (cgroup_generation, memcg) = parent
            .and_then(|parent| self.process(parent))
            .map_or((0, 0), |parent| (parent.cgroup_generation, parent.memcg));
        let memory_policy = parent
            .and_then(|parent| self.process(parent))
            .map_or(crate::linux_areas::Policy::DEFAULT, |parent| {
                parent.memory_policy
            });
        let namespaces = match parent.and_then(|parent| self.process_mut(parent)) {
            Some(parent) => parent
                .child_namespaces
                .take()
                .unwrap_or_else(|| parent.namespaces.for_child()),
            None => linux_namespace::Set::default(),
        };
        // A child born into a PID namespace gets its numbers there, and the
        // time namespace it enters keeps its offsets from now on.
        let instance = cpu::current_linux_execution_instance();
        linux_namespace::enter_pid(instance, namespaces.pid, pid).ok()?;
        if namespaces.time != 0 {
            linux_namespace::freeze_time(instance, namespaces.time);
        }
        // A new process's groups are its parent's; the first is in group 0.
        let inherited: &[u32] = match parent {
            Some(parent) => self.groups.get(usize::from(parent.slot))?,
            None => &[0],
        };
        let mut groups = Vec::new();
        groups.try_reserve_exact(inherited.len()).ok()?;
        groups.extend_from_slice(inherited);
        self.groups[slot] = groups;
        // A child starts in its parent's root directory.
        let mut root = Vec::new();
        if let Some(parent_root) =
            parent.and_then(|parent| self.roots.get(usize::from(parent.slot)))
        {
            root.try_reserve_exact(parent_root.len()).ok()?;
            root.extend_from_slice(parent_root);
        }
        self.roots[slot] = root;
        self.generations[slot] = generation;
        let shared = core::array::from_fn(|_| self.new_shared_id());
        self.processes[slot] = Some(Process {
            handle,
            parent,
            process_group,
            session,
            executed: false,
            user_namespace,
            namespaces,
            child_namespaces: None,
            credentials,
            runtime_slot: address_space.map(|space| space.storage_slot),
            address_space,
            retiring_address_space: None,
            context,
            scheduler_thread: None,
            cpu_affinity,
            scheduling,
            timer_slack,
            stopped_in_call: false,
            oom_score_adj,
            io: IoAccounting::default(),
            child_subreaper: false,
            memory_policy,
            killed_by_signal: 0,
            oom_victim: false,
            seccomp_filter,
            tracer: 0,
            ptrace_resume_signal: 0,
            ptrace_bypass: false,
            debug_registers: DebugRegisters::RESET,
            state,
            wait_event: None,
            shares_parent_vm: false,
            shared,
            exit_signal: DEFAULT_EXIT_SIGNAL,
            reaped_by_parent: false,
            cgroup_generation,
            memcg,
            cloned_by: None,
            vfork_child: 0,
            waiting: false,
            futex_sleep: None,
            cpu_cycles: 0,
            user_cycles: 0,
            children_cycles: (0, 0),
            task_events: [0; crate::cpu_time::TASK_EVENTS],
            children_task_events: [0; crate::cpu_time::TASK_EVENTS],
            started_nanoseconds: crate::arch::x86_64::cpu::linux_uptime_nanoseconds(),
            posix_timers: [None; POSIX_TIMER_LIMIT],
            itimers: [None; 4],
            maxrss_kib: 0,
            children_maxrss_kib: 0,
            deadline_parameters: [0; 3],
        });
        let index = self.pid_slots.partition_point(|(other, _)| *other < pid);
        self.pid_slots.insert(index, (pid, handle.slot));
        Some(handle)
    }

    /// Drops the namespaces no process of the table uses any more.
    fn collect_namespaces(&self) {
        let mut sets = Vec::new();
        if sets.try_reserve(self.processes.len()).is_err() {
            return;
        }
        sets.extend(
            self.processes
                .iter()
                .flatten()
                .map(|process| process.namespaces),
        );
        linux_namespace::collect(
            cpu::current_linux_execution_instance(),
            &sets,
            crate::linux_sysv_ipc::release_instance,
        );
    }

    fn process_group(&self, pid: u32) -> Option<(u32, u32)> {
        let process = self.process(self.handle_by_pid(pid)?)?;
        matches!(
            process.state,
            ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
        )
        .then_some((process.process_group, process.session))
    }

    fn set_process_group(
        &mut self,
        caller_pid: u32,
        target_pid: u32,
        process_group: u32,
    ) -> Result<(), ProcessGroupError> {
        let caller = self
            .handle_by_pid(caller_pid)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        let target = self
            .handle_by_pid(target_pid)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        let caller_process = self
            .process(caller)
            .filter(|process| process.state == ProcessState::Running)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        let target_process = self
            .process(target)
            .filter(|process| process.state == ProcessState::Running)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        if target != caller && target_process.parent != Some(caller) {
            return Err(ProcessGroupError::NoSuchProcess);
        }
        if target != caller && target_process.executed {
            return Err(ProcessGroupError::Access);
        }
        if target_process.session != caller_process.session
            || target_process.session == target_process.handle.pid
        {
            return Err(ProcessGroupError::Permission);
        }
        let requested = if process_group == 0 {
            target_process.handle.pid
        } else {
            process_group
        };
        if requested != target_process.handle.pid
            && !self.processes.iter().flatten().any(|process| {
                process.process_group == requested && process.session == caller_process.session
            })
        {
            return Err(ProcessGroupError::Permission);
        }
        self.process_mut(target)
            .ok_or(ProcessGroupError::NoSuchProcess)?
            .process_group = requested;
        Ok(())
    }

    fn create_session(&mut self, pid: u32) -> Result<u32, ProcessGroupError> {
        let handle = self
            .handle_by_pid(pid)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        if self
            .processes
            .iter()
            .flatten()
            .any(|process| process.process_group == pid)
        {
            return Err(ProcessGroupError::Permission);
        }
        let process = self
            .process_mut(handle)
            .filter(|process| process.state == ProcessState::Running)
            .ok_or(ProcessGroupError::NoSuchProcess)?;
        process.process_group = pid;
        process.session = pid;
        Ok(pid)
    }

    fn mark_executed(&mut self, pid: u32) -> bool {
        let Some(handle) = self.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = self
            .process_mut(handle)
            .filter(|process| process.state == ProcessState::Running)
        else {
            return false;
        };
        process.executed = true;
        process.posix_timers = [None; POSIX_TIMER_LIMIT];
        process.debug_registers = DebugRegisters::RESET;
        true
    }

    fn set_exec_context(&mut self, pid: u32, rip: u64, rsp: u64) -> bool {
        let Some(handle) = self.handle_by_pid(pid) else {
            return false;
        };
        let Some(process) = self
            .process_mut(handle)
            .filter(|process| process.state == ProcessState::Running)
        else {
            return false;
        };
        let context = ProcessExecutionContext {
            general: [0; 15],
            rip,
            rsp,
            rflags: (1 << 1) | (1 << 9),
            fs_base: 0,
        };
        if process
            .address_space
            .as_ref()
            .is_none_or(|space| !context.is_valid(space))
        {
            return false;
        }
        process.context = Some(context);
        process.executed = true;
        process.posix_timers = [None; POSIX_TIMER_LIMIT];
        process.debug_registers = DebugRegisters::RESET;
        process.shares_parent_vm = false;
        let memory = self.new_shared_id();
        if let Some(process) = self.process_mut(handle) {
            process.shared[SharedResource::Memory as usize] = memory;
        }
        true
    }

    fn process(&self, handle: ProcessHandle) -> Option<&Process> {
        self.processes
            .get(usize::from(handle.slot))?
            .as_ref()
            .filter(|process| process.handle == handle)
    }

    fn process_mut(&mut self, handle: ProcessHandle) -> Option<&mut Process> {
        self.processes
            .get_mut(usize::from(handle.slot))?
            .as_mut()
            .filter(|process| process.handle == handle)
    }
}

fn test_mapping(
    address: usize,
    frame: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> cpu::LinuxActiveImageMapping {
    cpu::LinuxActiveImageMapping {
        address,
        frame,
        writable,
        executable,
        shared: false,
        dontfork: false,
    }
}

fn write_test_hierarchy(
    hierarchy: &[memory::FrameLease],
    mappings: &[cpu::LinuxActiveImageMapping],
) -> bool {
    if hierarchy.len() != 4 || mappings.is_empty() {
        return false;
    }
    let mut tables = [core::ptr::null_mut::<u64>(); 4];
    for (table, frame) in tables.iter_mut().zip(hierarchy) {
        let Some(address) = frame.direct_map_address() else {
            return false;
        };
        *table = address as *mut u64;
        unsafe { core::ptr::write_bytes(*table, 0, PAGE_SIZE / size_of::<u64>()) };
    }
    let branch_flags = PRESENT | WRITABLE | USER;
    for mapping in mappings {
        let indexes = [
            (mapping.address >> 39) & 0x1ff,
            (mapping.address >> 30) & 0x1ff,
            (mapping.address >> 21) & 0x1ff,
            (mapping.address >> 12) & 0x1ff,
        ];
        unsafe {
            tables[0]
                .add(indexes[0])
                .write(hierarchy[1].address() | branch_flags);
            tables[1]
                .add(indexes[1])
                .write(hierarchy[2].address() | branch_flags);
            tables[2]
                .add(indexes[2])
                .write(hierarchy[3].address() | branch_flags);
            tables[3].add(indexes[3]).write(
                mapping.frame.address()
                    | PRESENT
                    | USER
                    | if mapping.writable { WRITABLE } else { 0 }
                    | if mapping.executable { 0 } else { NO_EXECUTE },
            );
        }
    }
    true
}

fn test_context() -> ProcessExecutionContext {
    ProcessExecutionContext {
        general: [0x55; 15],
        rip: TEST_USER_ADDRESS as u64,
        rsp: (TEST_USER_ADDRESS + 2 * PAGE_SIZE) as u64,
        rflags: (1 << 1) | (1 << 9),
        fs_base: (TEST_USER_ADDRESS + PAGE_SIZE) as u64,
    }
}

fn verify_user_kernel_mapping_rejected(root: memory::FrameLease) -> bool {
    let Some(address) = root.direct_map_address() else {
        return false;
    };
    let entry = unsafe { (address as *mut u64).add(256) };
    let original = unsafe { entry.read() };
    unsafe { entry.write(original | USER) };
    let rejected = !address_space::verify_linux_process_root_activation(root);
    unsafe { entry.write(original) };
    rejected && unsafe { entry.read() } == original
}

pub(crate) fn verify_lifecycle_contract() -> bool {
    // Address-space storage is allocated on first use and kept. Allocate the
    // slots this check uses (0 to 5) first, so the frame count it compares
    // at the end covers only the frames the lifecycle takes and returns.
    if (0..6).any(|slot| address_space_storage(slot).is_none()) {
        return false;
    }
    // The heap keeps the frames it grows by (the test table's slots live
    // there): count the frames outside it.
    let Some(before) = crate::heap::kernel_frames_outside_heap() else {
        return false;
    };
    let Some(frames) = memory::allocate_frames::<18>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let init_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[4], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[5], true, false),
    ];
    if !write_test_hierarchy(&frames[0..4], &init_mappings) {
        crate::serial_write("ginux: lifecycle stage hierarchy failed\r\n");
        return false;
    }
    if !address_space::set_linux_mapping_wipe_on_fork(
        frames[0],
        TEST_USER_ADDRESS + PAGE_SIZE,
        true,
    ) {
        crate::serial_write("ginux: lifecycle stage wipe policy failed\r\n");
        return false;
    }
    if address_space::verify_linux_process_root_activation(frames[0])
        || !address_space::inherit_linux_process_kernel_mappings(frames[0])
    {
        crate::serial_write("ginux: lifecycle stage kernel inheritance failed\r\n");
        return false;
    }
    let Some(init_space) = ProcessAddressSpace::new(0, &frames[0..4], &init_mappings) else {
        return false;
    };
    let init_context = test_context();
    let table = process_runtime().test_table.get().cast::<ProcessTable>();
    unsafe { table.write(ProcessTable::new()) };
    let table = unsafe { &mut *table };
    let mut invalid_context = init_context;
    invalid_context.rip = (TEST_USER_ADDRESS + PAGE_SIZE) as u64;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    invalid_context = init_context;
    invalid_context.rsp = TEST_USER_ADDRESS as u64;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    invalid_context = init_context;
    invalid_context.rflags |= 3 << 12;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    invalid_context = init_context;
    invalid_context.fs_base = 1 << 47;
    if table.create_init(init_space, invalid_context).is_some() {
        return false;
    }
    let Some(init) = table.create_init(init_space, init_context) else {
        return false;
    };
    let Some(init_scheduler_context) = init_context.scheduler_context(&init_space) else {
        return false;
    };
    let mut run_queue = scheduler::ProcessScheduler::new();
    if table.admit_to_scheduler(init, &mut run_queue, 0)
        || !table.admit_to_scheduler(init, &mut run_queue, 1)
        || table.admit_to_scheduler(init, &mut run_queue, 1)
    {
        return false;
    }
    let Some(rejected_child) = table.prepare_fork(init) else {
        return false;
    };
    let shared_page_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[4], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[11], true, false),
    ];
    if !write_test_hierarchy(&frames[6..10], &shared_page_mappings)
        || !address_space::inherit_linux_process_kernel_mappings(frames[6])
    {
        return false;
    }
    let Some(shared_page_space) =
        ProcessAddressSpace::new(1, &frames[6..10], &shared_page_mappings)
    else {
        return false;
    };
    if table.commit_fork(rejected_child, shared_page_space, init_context.fork_child()) {
        return false;
    }
    let first_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[10], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[11], true, false),
    ];
    let second_mappings = [
        test_mapping(TEST_USER_ADDRESS, frames[16], false, true),
        test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[17], true, false),
    ];
    if !write_test_hierarchy(&frames[6..10], &first_mappings)
        || !address_space::inherit_linux_process_kernel_mappings(frames[6])
        || !verify_user_kernel_mapping_rejected(frames[6])
        || !write_test_hierarchy(&frames[12..16], &second_mappings)
        || !address_space::inherit_linux_process_kernel_mappings(frames[12])
    {
        return false;
    }
    let mut wrong_permission = first_mappings;
    wrong_permission[0].writable = true;
    wrong_permission[0].executable = false;
    let mut wrong_address = first_mappings;
    wrong_address[0].address += 2 * PAGE_SIZE;
    if ProcessAddressSpace::new(4, &frames[6..10], &wrong_permission)
        .is_some_and(|space| space.is_valid())
        || ProcessAddressSpace::new(5, &frames[6..10], &wrong_address)
            .is_some_and(|space| space.is_valid())
    {
        return false;
    }
    let (Some(first_space), Some(mut second_space)) = (
        ProcessAddressSpace::new(1, &frames[6..10], &first_mappings),
        ProcessAddressSpace::new(2, &frames[12..16], &second_mappings),
    ) else {
        return false;
    };
    let Some(stale_generation) = frames[6].generation().checked_add(1) else {
        return false;
    };
    let Some(stale_root) = memory::FrameLease::from_parts(frames[6].address(), stale_generation)
    else {
        return false;
    };
    let mut stale_hierarchy: [memory::FrameLease; 4] =
        core::array::from_fn(|index| frames[6 + index]);
    stale_hierarchy[0] = stale_root;
    let stale_space = ProcessAddressSpace::new(3, &stale_hierarchy, &first_mappings);
    let stale_expected = ProcessAddressSpace {
        storage_slot: 3,
        hierarchy_count: first_space.hierarchy_count,
        mapping_count: first_space.mapping_count,
        stale: false,
    };
    if init.pid != 1
        || rejected_child.pid != 2
        || table.process_group(init.pid) != Some((1, 1))
        || table.create_session(init.pid) != Err(ProcessGroupError::Permission)
        || table.create_init(first_space, init_context).is_some()
        || table.commit_fork(rejected_child, init_space, init_context.fork_child())
        || stale_space.is_some_and(|space| space.is_valid())
        || address_space::verify_linux_process_root_activation(stale_root)
        || table.wait(init, rejected_child.pid).is_some()
        || table.exit(rejected_child, 1)
        || table.commit_cloned_fork(rejected_child, &frames[0..4], &frames[4..6], false)
        || !init_space.is_valid()
        || table.commit_fork(rejected_child, first_space, init_context.fork_child())
        || table.abort_fork(rejected_child)
    {
        return false;
    }
    let Some(first_child) = table.prepare_fork(init) else {
        return false;
    };
    let (Some(parent_page), Some(parent_stack), Some(child_page), Some(child_stack)) = (
        frames[4].direct_map_address(),
        frames[5].direct_map_address(),
        frames[10].direct_map_address(),
        frames[11].direct_map_address(),
    ) else {
        return false;
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            PROCESS_CHILD_PROGRAM.as_ptr(),
            parent_page as *mut u8,
            PROCESS_CHILD_PROGRAM.len(),
        );
        (parent_page as *mut u8).add(PAGE_SIZE - 1).write(0x32);
        (parent_stack as *mut u8).write(0x44);
    }
    if first_child.pid != 3 {
        crate::serial_write("ginux: lifecycle stage child identity failed\r\n");
        return false;
    }
    if !table.commit_cloned_fork(first_child, &frames[6..10], &frames[10..12], false) {
        crate::serial_write("ginux: lifecycle stage cloned fork failed\r\n");
        return false;
    }
    if unsafe { core::slice::from_raw_parts(child_page as *const u8, PROCESS_CHILD_PROGRAM.len()) }
        != PROCESS_CHILD_PROGRAM
        || unsafe { (child_page as *const u8).add(PAGE_SIZE - 1).read() } != 0x32
        || table.commit_fork(first_child, second_space, init_context.fork_child())
        || table.wait(init, first_child.pid).is_some()
        || table.exit(first_child, 42)
        || table.begin_exit(first_child, second_space).is_some()
        || table.begin_exit(first_child, stale_expected).is_some()
    {
        crate::serial_write("ginux: lifecycle stage cloned fork state failed\r\n");
        return false;
    }
    if unsafe { (child_stack as *const u8).read() } != 0 {
        crate::serial_write("ginux: lifecycle stage wipe contents failed\r\n");
        return false;
    }
    if table.process_group(first_child.pid) != Some((1, 1))
        || table.child_wait_state(init, Some(first_child.pid), false, false)
            != Some(ChildWaitState::Running)
        || table.set_process_group(init.pid, first_child.pid, first_child.pid) != Ok(())
        || table.process_group(first_child.pid) != Some((3, 1))
        || table.child_group_wait_state(init, first_child.pid, false, false)
            != Some(ChildWaitState::Running)
        || table
            .child_group_wait_state(init, init.pid, false, false)
            .is_some()
        || table.set_process_group(init.pid, first_child.pid, init.pid) != Ok(())
        || !table.mark_executed(first_child.pid)
        || table.set_process_group(init.pid, first_child.pid, first_child.pid)
            != Err(ProcessGroupError::Access)
        || table.create_session(first_child.pid) != Ok(first_child.pid)
        || table.process_group(first_child.pid) != Some((3, 3))
        || table.set_process_group(init.pid, first_child.pid, init.pid)
            != Err(ProcessGroupError::Access)
        || table.set_process_group(first_child.pid, init.pid, init.pid)
            != Err(ProcessGroupError::NoSuchProcess)
    {
        return false;
    }
    if !table.stop(first_child, 19, false)
        || table.child_wait_state(init, Some(first_child.pid), false, false)
            != Some(ChildWaitState::Running)
        || table.child_wait_state(init, Some(first_child.pid), true, false)
            != Some(ChildWaitState::Stopped {
                pid: first_child.pid,
                signal: 19,
            })
        || !table.consume_wait_event(init, first_child.pid)
        || !table.continue_process(first_child)
        || table.child_wait_state(init, Some(first_child.pid), false, true)
            != Some(ChildWaitState::Continued {
                pid: first_child.pid,
            })
        || !table.consume_wait_event(init, first_child.pid)
        || table.child_wait_state(init, Some(first_child.pid), true, true)
            != Some(ChildWaitState::Running)
    {
        return false;
    }
    let Some(child_context) = table
        .process(first_child)
        .and_then(|process| process.context)
    else {
        return false;
    };
    if child_context != init_context.fork_child()
        || child_context.general[PROCESS_RAX_INDEX] != 0
        || table.process(init).and_then(|process| process.context) != Some(init_context)
    {
        return false;
    }
    let Some(child_scheduler_context) = child_context.scheduler_context(&first_space) else {
        return false;
    };
    if !table.admit_to_scheduler(first_child, &mut run_queue, 1)
        || table.admit_to_scheduler(first_child, &mut run_queue, 1)
    {
        return false;
    }
    let (Some(init_thread), Some(child_thread)) = (
        table
            .process(init)
            .and_then(|process| process.scheduler_thread),
        table
            .process(first_child)
            .and_then(|process| process.scheduler_thread),
    ) else {
        return false;
    };
    let Some(initial) = run_queue.schedule_next() else {
        return false;
    };
    let Some(selected_child) = run_queue.yield_current(init_thread, init_scheduler_context) else {
        return false;
    };
    if selected_child.handle() != child_thread
        || selected_child.context() != child_scheduler_context
    {
        return false;
    }
    let child_exit_status = if crate::arch::x86_64::smp::online_count() > 1 {
        crate::arch::x86_64::smp::execute_linux_process(
            1,
            first_space.root(),
            child_context.rip,
            child_context.rsp,
            child_context.fs_base,
            child_context.general,
        )
    } else {
        address_space::execute_linux_process_child(
            first_space.root(),
            child_context.rip,
            child_context.rsp,
            child_context.fs_base,
            child_context.general,
        )
    };
    let Some(child_exit_status) = child_exit_status else {
        return false;
    };
    if crate::arch::x86_64::smp::online_count() > 1 {
        crate::serial_write("ginux: scheduled Linux child executed on application processor\r\n");
    }
    if child_exit_status != 42
        || unsafe { (child_stack as *const u8).read() } != 0x5a
        || unsafe { (parent_stack as *const u8).read() } != 0x44
    {
        crate::serial_write("ginux: lifecycle stage wipe execution failed\r\n");
        return false;
    }
    if crate::arch::x86_64::smp::online_count() > 1 {
        let (Some(second_page), Some(shared_page)) = (
            frames[16].direct_map_address(),
            frames[11].direct_map_address(),
        ) else {
            return false;
        };
        let concurrent_second_mappings = [
            test_mapping(TEST_USER_ADDRESS, frames[16], false, true),
            // Alias the first process's writable page only for this bounded
            // rendezvous. Neither test program uses its user stack while the
            // alias exists, and the original second mapping is restored before
            // lifecycle teardown resumes.
            test_mapping(TEST_USER_ADDRESS + PAGE_SIZE, frames[11], true, false),
        ];
        if !write_test_hierarchy(&frames[12..16], &concurrent_second_mappings)
            || !address_space::inherit_linux_process_kernel_mappings(frames[12])
        {
            return false;
        }
        let Some(concurrent_second_space) =
            ProcessAddressSpace::new(2, &frames[12..16], &concurrent_second_mappings)
        else {
            return false;
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                CONCURRENT_PROCESS_PROGRAM.as_ptr(),
                child_page as *mut u8,
                CONCURRENT_PROCESS_PROGRAM.len(),
            );
            core::ptr::copy_nonoverlapping(
                CONCURRENT_PROCESS_PROGRAM.as_ptr(),
                second_page as *mut u8,
                CONCURRENT_PROCESS_PROGRAM.len(),
            );
            (shared_page as *mut u32).write(0);
        }
        let concurrent_context = init_context.fork_child();
        let ticket = crate::arch::x86_64::smp::begin_linux_process(
            1,
            first_space.root(),
            concurrent_context.rip,
            concurrent_context.rsp,
            concurrent_context.fs_base,
            concurrent_context.general,
        );
        let Some(ticket) = ticket else {
            crate::serial_write("ginux: concurrent Linux process dispatch failed\r\n");
            return false;
        };
        let mut remote_entered = false;
        for _ in 0..20_000_000 {
            if unsafe { (shared_page as *const u32).read_volatile() } == 1 {
                remote_entered = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !remote_entered {
            let _ = crate::arch::x86_64::smp::finish_linux_process(ticket);
            crate::serial_write("ginux: concurrent Linux process rendezvous failed\r\n");
            return false;
        }
        let local_status = address_space::execute_linux_process_child(
            concurrent_second_space.root(),
            concurrent_context.rip,
            concurrent_context.rsp,
            concurrent_context.fs_base,
            concurrent_context.general,
        );
        let remote_status = crate::arch::x86_64::smp::finish_linux_process(ticket);
        if local_status != Some(42)
            || remote_status != Some(42)
            || unsafe { (shared_page as *const u32).read() } != 2
        {
            return false;
        }
        crate::serial_write("ginux: concurrent Linux processes executed across processors\r\n");
        if !write_test_hierarchy(&frames[12..16], &second_mappings)
            || !address_space::inherit_linux_process_kernel_mappings(frames[12])
        {
            return false;
        }
        let Some(restored_second_space) =
            ProcessAddressSpace::new(2, &frames[12..16], &second_mappings)
        else {
            return false;
        };
        second_space = restored_second_space;
    }
    let Some(resumed_parent) = run_queue.yield_current(child_thread, child_scheduler_context)
    else {
        return false;
    };
    if initial.handle() != init_thread
        || initial.context() != init_scheduler_context
        || resumed_parent.handle() != init_thread
        || resumed_parent.context() != init_scheduler_context
        || table.begin_exit(first_child, first_space).is_some()
        || !table.withdraw_from_scheduler(first_child, &mut run_queue)
        || !table.withdraw_from_scheduler(init, &mut run_queue)
        || run_queue.retire(child_thread)
        || table.withdraw_from_scheduler(first_child, &mut run_queue)
    {
        return false;
    }
    if unsafe { (parent_page as *const u8).read() } != PROCESS_CHILD_PROGRAM[0] {
        return false;
    }
    let Some(first_resources) = table.begin_exit(first_child, first_space) else {
        return false;
    };
    let first_root = first_resources.hierarchy()[0];
    if table.exit(first_child, child_exit_status)
        || !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[first_root])
        || table.exit(first_child, child_exit_status)
        || !memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &first_resources.hierarchy()[1..],
        )
        || first_resources.mappings().iter().any(|mapping| {
            !mapping.shared
                && !memory::frame_lease_is_runtime(mapping.frame)
                && !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[mapping.frame])
        })
        || !table.exit(first_child, child_exit_status)
        || table.child_wait_state(init, Some(first_child.pid), false, false)
            != Some(ChildWaitState::Exited {
                pid: first_child.pid,
                status: child_exit_status,
                signal: 0,
            })
        || table.child_group_wait_state(init, first_child.pid, false, false)
            != Some(ChildWaitState::Exited {
                pid: first_child.pid,
                status: child_exit_status,
                signal: 0,
            })
        || table.wait(first_child, first_child.pid).is_some()
        || table.wait(init, first_child.pid)
            != Some(WaitResult {
                pid: 3,
                status: child_exit_status,
            })
        || table.exit(first_child, child_exit_status)
    {
        return false;
    }
    let Some(second_child) = table.prepare_fork(init) else {
        return false;
    };
    if second_child.slot != first_child.slot
        || second_child.generation <= first_child.generation
        || second_child.pid != 4
        || table.begin_exit(first_child, second_space).is_some()
        || table.commit_fork(second_child, first_space, init_context.fork_child())
        || table.commit_fork(second_child, second_space, invalid_context)
        || !table.commit_fork(second_child, second_space, init_context.fork_child())
    {
        return false;
    }
    let Some(second_resources) = table.begin_exit(second_child, second_space) else {
        return false;
    };
    if !second_resources.scrub_and_release()
        || !table.exit(second_child, 7)
        || table.wait(init, second_child.pid) != Some(WaitResult { pid: 4, status: 7 })
    {
        return false;
    }
    let Some(init_resources) = table.begin_exit(init, init_space) else {
        return false;
    };
    init_resources.scrub_and_release()
        && table.exit(init, 0)
        && crate::heap::kernel_frames_outside_heap() == Some(before)
}

pub(crate) fn install_live_process_registry(
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let instance = current_process_instance();
    if process_runtime().table_initialized[instance].load(Ordering::Acquire)
        || process_runtime().active_instance.load(Ordering::Acquire) != PROCESS_INSTANCE_NONE
    {
        return false;
    }
    let Some(address_space) =
        ProcessAddressSpace::new(0, snapshot.hierarchy(), snapshot.mappings())
    else {
        return false;
    };
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    let mut invalid = context;
    invalid.rip = 0;
    if invalid.is_valid(&address_space) || !context.is_valid(&address_space) {
        return false;
    }
    let table = unsafe {
        process_runtime()
            .tables
            .get()
            .cast::<ProcessTable>()
            .add(instance)
    };
    unsafe {
        core::ptr::addr_of_mut!((*table).owner_domain).write(
            cpu::current_container_slot()
                .and_then(cpu::container_domain_id)
                .unwrap_or(0),
        );
        // The tables start const-initialized, so the vectors are valid here;
        // emptying them keeps their memory for the next domain.
        (*table).processes.clear();
        (*table).pid_slots.clear();
        (*table).generations.clear();
        (*table).groups.clear();
        (*table).roots.clear();
        (*table).seccomp_filters.clear();
        core::ptr::addr_of_mut!((*table).next_pid).write(1);
        core::ptr::addr_of_mut!((*table).init).write(None);
    }
    let table = unsafe { &mut *table };
    if table.create_init(address_space, context).is_none() {
        return false;
    }
    process_runtime().refresh_count[instance].store(0, Ordering::Release);
    process_runtime().table_initialized[instance].store(true, Ordering::Release);
    process_runtime()
        .active_instance
        .store(instance as u8, Ordering::Release);
    true
}

pub(crate) fn refresh_live_process_registry(
    pid: u32,
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    refresh_live_process_registry_inner(pid, snapshot, general, rip, rsp, rflags, fs_base, true)
}

pub(crate) fn refresh_validated_runtime_process_registry(
    pid: u32,
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    refresh_live_process_registry_inner(pid, snapshot, general, rip, rsp, rflags, fs_base, false)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn refresh_live_process_context_from_syscall_entry(
    pid: u32,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let Some(instruction_mapping) = address_space::current_linux_active_mapping(rip) else {
        return false;
    };
    let Some(stack_address) = rsp.checked_sub(1) else {
        return false;
    };
    let Some(stack_mapping) = address_space::current_linux_active_mapping(stack_address) else {
        return false;
    };
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    if process.state != ProcessState::Running {
        return false;
    }
    let Some(space) = process.address_space.as_mut() else {
        return false;
    };
    let Some(storage) = address_space_storage(usize::from(space.storage_slot)) else {
        return false;
    };
    let mut count = space.mapping_count as usize;
    if count != storage.mappings.len() {
        return false;
    }
    let context_mappings = [instruction_mapping, stack_mapping];
    let missing = context_mappings
        .iter()
        .enumerate()
        .filter(|(index, mapping)| {
            context_mappings[..*index]
                .iter()
                .all(|prior| prior.address != mapping.address)
                && storage.mappings[..count]
                    .iter()
                    .all(|existing| existing.address != mapping.address)
        })
        .count();
    if storage.mappings.try_reserve(missing).is_err() {
        return false;
    }
    for mapping in context_mappings {
        if let Some(existing) = storage.mappings[..count]
            .iter_mut()
            .find(|existing| existing.address == mapping.address)
        {
            let shared = existing.shared;
            let dontfork = existing.dontfork;
            *existing = mapping;
            existing.shared = shared;
            existing.dontfork = dontfork;
        } else {
            storage.mappings.push(mapping);
            count += 1;
        }
    }
    space.mapping_count = count as u32;
    if !context.is_valid(space) {
        return false;
    }
    process.context = Some(context);
    true
}

/// Records the context the current process `pid` waits in, checked against
/// its live page tables (the instruction executable, the stack writable)
/// rather than its registered mapping list, which this marks stale: a wait
/// costs a few lookups instead of a pass over every mapped page. Its
/// release then frees what the live page tables map, and fork and exec
/// take a full snapshot again.
pub(crate) fn refresh_live_process_context_for_wait(
    pid: u32,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
) -> bool {
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    let mapped = context.registers_valid()
        && address_space::current_linux_active_mapping(rip).is_some_and(|page| page.executable)
        && rsp
            .checked_sub(1)
            .and_then(address_space::current_linux_active_mapping)
            .is_some_and(|page| page.writable);
    if !mapped {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    if process.state != ProcessState::Running {
        return false;
    }
    let Some(space) = process.address_space.as_mut() else {
        return false;
    };
    space.stale = true;
    process.context = Some(context);
    true
}

pub(crate) fn refresh_live_process_hierarchy(pid: u32, hierarchy: &[memory::FrameLease]) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(space) = table
        .process(handle)
        .and_then(|process| process.address_space)
    else {
        return false;
    };
    if hierarchy.len() < 4 || !memory::frames_owned_by(memory::FrameOwner::KERNEL, hierarchy) {
        return false;
    }
    let Some(storage) = address_space_storage(usize::from(space.storage_slot)) else {
        return false;
    };
    if replace_list(&mut storage.hierarchy, hierarchy).is_none() {
        return false;
    }
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    let Some(mut updated) = process.address_space else {
        return false;
    };
    updated.hierarchy_count = hierarchy.len() as u32;
    process.address_space = Some(updated);
    true
}

#[allow(clippy::too_many_arguments)]
fn refresh_live_process_registry_inner(
    pid: u32,
    snapshot: &cpu::LinuxProcessAddressSpaceSnapshot,
    general: [u64; 15],
    rip: u64,
    rsp: u64,
    rflags: u64,
    fs_base: u64,
    validate_address_space: bool,
) -> bool {
    let Some(table) = live_process_table_mut() else {
        crate::serial_write("ginux: live registry refresh has no table\r\n");
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        crate::serial_write("ginux: live registry refresh has no process\r\n");
        return false;
    };
    let Some(storage_slot) = table
        .process(handle)
        .and_then(|process| process.address_space)
        .map(|space| usize::from(space.storage_slot))
    else {
        crate::serial_write("ginux: live registry refresh has no address space\r\n");
        return false;
    };
    let address_space = if validate_address_space {
        ProcessAddressSpace::new(storage_slot, snapshot.hierarchy(), snapshot.mappings())
    } else {
        ProcessAddressSpace::from_validated_snapshot(
            storage_slot,
            snapshot.hierarchy(),
            snapshot.mappings(),
        )
    };
    let Some(address_space) = address_space else {
        crate::serial_write("ginux: live registry refresh rejected address space\r\n");
        return false;
    };
    let context = ProcessExecutionContext {
        general,
        rip,
        rsp,
        rflags,
        fs_base,
    };
    let context_error = context.validation_error(&address_space);
    let refreshed =
        table.refresh_process_inner(handle, address_space, context, validate_address_space);
    if refreshed {
        let instance = active_process_instance().unwrap_or(HOST_PROCESS_INSTANCE);
        process_runtime().refresh_count[instance].fetch_add(1, Ordering::SeqCst);
    } else if REFRESH_REJECTIONS.fetch_add(1, Ordering::Relaxed) < 8 {
        // Reported for the first few only: a call that retries after a
        // rejection would otherwise flood the serial console.
        crate::serial_write(
            "ginux: live registry refresh rejected process context pid/state/error/rip/rsp/rflags: ",
        );
        let (state, retiring) = table
            .process(handle)
            .map(|process| {
                (
                    match process.state {
                        ProcessState::Preparing => 1,
                        ProcessState::Running => 2,
                        ProcessState::Stopped { .. } => 3,
                        ProcessState::Exiting => 4,
                        ProcessState::Zombie { .. } => 5,
                    },
                    u64::from(process.retiring_address_space.is_some()),
                )
            })
            .unwrap_or((0, 0));
        let error =
            u64::from(context_error.unwrap_or(0))
                | u64::from(table.process(handle).is_some_and(|process| {
                    linux_user::credentials(process.user_namespace).is_none()
                })) << 4
                | (address_space.mapping_count as u64) << 16;
        for value in [
            u64::from(pid),
            state,
            error | retiring << 8,
            rip,
            rsp,
            rflags,
        ] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        let (root, leaf) = address_space::current_linux_leaf_report(rsp.wrapping_sub(1));
        let snapshot_root = snapshot
            .hierarchy()
            .first()
            .map_or(0, |frame| frame.address());
        crate::serial_write("cr3/snapshot-root/stack-leaf: ");
        for value in [root, snapshot_root, leaf] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        crate::serial_write("\r\n");
    }
    refreshed
}

/// Registry refreshes rejected, for the report above.
static REFRESH_REJECTIONS: AtomicU32 = AtomicU32::new(0);

pub(crate) fn finish_live_process_registry(refresh_floor: u32) -> bool {
    finish_live_process_registry_with_refresh_floor(refresh_floor)
}

pub(crate) fn finish_runtime_process_registry() -> bool {
    finish_live_process_registry_with_refresh_floor(0)
}

pub(crate) fn force_stop_runtime_process_registry() -> bool {
    let Some(instance) = active_process_instance() else {
        return true;
    };
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire) {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(init) = table.init else {
        return false;
    };
    let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
        return false;
    };
    run_queue.retire_all();
    for process in table.processes.iter_mut().flatten() {
        process.scheduler_thread = None;
    }
    if !scheduler::release_process_scheduler_workspace() {
        return false;
    }

    for slot in 0..table.processes.len() {
        let Some(process) = table.processes[slot] else {
            continue;
        };
        if process.handle == init {
            continue;
        }
        if let Some(space) = process.address_space {
            if !release_live_process_address_space(space) {
                return false;
            }
        }
        if let Some(space) = process.retiring_address_space {
            if !release_live_process_address_space(space) {
                return false;
            }
        }
        if crate::linux_sysv_ipc::drop_process_attachments(process.handle.pid).is_err() {
            return false;
        }
        table.processes[slot] = None;
        table.forget_pid_slot(process.handle.pid);
        table.groups[slot] = Vec::new();
        table.roots[slot] = Vec::new();
        if table
            .processes
            .iter()
            .flatten()
            .all(|candidate| candidate.user_namespace != process.user_namespace)
        {
            let _ = linux_user::retire(process.user_namespace);
        }
    }
    let Some(process) = table.process_mut(init) else {
        return false;
    };
    process.parent = None;
    process.retiring_address_space = None;
    process.scheduler_thread = None;
    process.state = ProcessState::Running;
    process.wait_event = None;
    true
}

pub(crate) fn suspend_runtime_process_registry() -> bool {
    let Some(instance) = active_process_instance() else {
        return false;
    };
    if instance != current_process_instance()
        || !process_runtime().table_initialized[instance].load(Ordering::Acquire)
    {
        return false;
    }
    process_runtime()
        .active_instance
        .store(PROCESS_INSTANCE_NONE, Ordering::Release);
    true
}

pub(crate) fn resume_runtime_process_registry() -> bool {
    let instance = current_process_instance();
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire)
        || process_runtime()
            .active_instance
            .compare_exchange(
                PROCESS_INSTANCE_NONE,
                instance as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
    {
        return false;
    }
    let valid = live_process_table_mut().is_some_and(|table| {
        table.owner_domain
            == cpu::current_container_slot()
                .and_then(cpu::container_domain_id)
                .unwrap_or(0)
            && table.init.is_some()
    });
    if !valid {
        process_runtime()
            .active_instance
            .store(PROCESS_INSTANCE_NONE, Ordering::Release);
    }
    valid
}

pub(crate) fn reset_runtime_scheduler_bindings() -> bool {
    if let Some(run_queue) = scheduler::active_process_scheduler_workspace() {
        run_queue.retire_all();
        if !scheduler::release_process_scheduler_workspace() {
            return false;
        }
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    for process in table.processes.iter_mut().flatten() {
        process.scheduler_thread = None;
    }
    true
}

fn finish_live_process_registry_with_refresh_floor(refresh_floor: u32) -> bool {
    let Some(instance) = active_process_instance() else {
        return true;
    };
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire) {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let valid = table.reap_init_zombies()
        && table.reap_all_zombies()
        && table.init.is_some()
        && process_runtime().refresh_count[instance].load(Ordering::Acquire) >= refresh_floor
        && table.processes.iter().flatten().count() == 1
        && table.processes.iter().flatten().all(|process| {
            process.parent.is_none()
                && linux_user::credentials(process.user_namespace).is_some()
                && process.state == ProcessState::Running
                && process.retiring_address_space.is_none()
                && process.scheduler_thread.is_none()
        });
    if !valid {
        crate::serial_write("ginux: live process registry finish state: ");
        crate::serial_write_u64(u64::from(table.init.is_some()));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(
            process_runtime().refresh_count[instance].load(Ordering::Acquire),
        ));
        crate::serial_write(" ");
        crate::serial_write_u64(table.processes.iter().flatten().count() as u64);
        crate::serial_write("\r\n");
        write_process_table(table);
        return false;
    }
    process_runtime().table_initialized[instance].store(false, Ordering::Release);
    process_runtime().refresh_count[instance].store(0, Ordering::Release);
    process_runtime()
        .active_instance
        .store(PROCESS_INSTANCE_NONE, Ordering::Release);
    true
}

pub(crate) fn live_process_user_namespace(pid: u32) -> Option<linux_user::UserNamespaceHandle> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let namespace = table.process(handle)?.user_namespace;
    linux_user::credentials(namespace).map(|_| namespace)
}

pub(crate) fn live_process_credentials(pid: u32) -> Option<linux_user::Credentials> {
    let table = live_process_table_mut()?;
    Some(table.process(table.handle_by_pid(pid)?)?.credentials)
}

pub(crate) fn set_live_process_credentials(pid: u32, credentials: linux_user::Credentials) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.credentials = credentials;
    true
}

/// Runs `inspect` on the supplementary groups of `pid`, sorted.
pub(crate) fn with_live_process_groups<R>(
    pid: u32,
    inspect: impl FnOnce(&[u32]) -> R,
) -> Option<R> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    table.process(handle)?;
    Some(inspect(table.groups.get(usize::from(handle.slot))?))
}

/// Runs `inspect` on the root directory of `pid` (its chroot, a canonical
/// path without a leading slash; empty for the domain's root).
pub(crate) fn with_live_process_root<R>(pid: u32, inspect: impl FnOnce(&[u8]) -> R) -> Option<R> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    table.process(handle)?;
    Some(inspect(table.roots.get(usize::from(handle.slot))?))
}

/// Makes `root` the root directory of `pid` (chroot).
pub(crate) fn set_live_process_root(pid: u32, root: Vec<u8>) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    if table.process(handle).is_none() {
        return false;
    }
    let Some(slot) = table.roots.get_mut(usize::from(handle.slot)) else {
        return false;
    };
    *slot = root;
    true
}

/// Replaces the supplementary groups of `pid` with `groups`, sorted.
pub(crate) fn set_live_process_groups(pid: u32, groups: Vec<u32>) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    if table.process(handle).is_none() {
        return false;
    }
    let Some(slot) = table.groups.get_mut(usize::from(handle.slot)) else {
        return false;
    };
    *slot = groups;
    true
}

/// Sets the namespaces process `pid`'s next child is made in (`None`:
/// its own, as a fork's child has).
pub(crate) fn set_live_process_child_namespaces(
    pid: u32,
    namespaces: Option<linux_namespace::Set>,
) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.child_namespaces = namespaces;
    true
}

/// Process `pid`'s UTS, IPC, PID and time namespaces.
pub(crate) fn live_process_namespaces(pid: u32) -> Option<linux_namespace::Set> {
    let table = live_process_table_mut()?;
    Some(table.process(table.handle_by_pid(pid)?)?.namespaces)
}

/// Moves running process `pid` to `namespaces`, then drops the ones it
/// left that nothing else uses.
pub(crate) fn set_live_process_namespaces(pid: u32, namespaces: linux_namespace::Set) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    if process.state != ProcessState::Running {
        return false;
    }
    process.namespaces = namespaces;
    table.collect_namespaces();
    true
}

pub(crate) fn set_live_process_user_namespace(
    pid: u32,
    namespace: linux_user::UserNamespaceHandle,
) -> bool {
    if linux_user::credentials(namespace).is_none() {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    if process.state != ProcessState::Running {
        return false;
    }
    process.user_namespace = namespace;
    true
}

pub(crate) fn live_process_status(pid: u32) -> Option<LiveProcessStatus> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process(handle)?;
    let state = match process.state {
        ProcessState::Running if process.stopped_in_call => LiveProcessState::Stopped,
        ProcessState::Running if process.waiting => LiveProcessState::Sleeping,
        ProcessState::Running => LiveProcessState::Running,
        ProcessState::Stopped { .. } => LiveProcessState::Stopped,
        ProcessState::Zombie { .. } => LiveProcessState::Zombie,
        ProcessState::Preparing | ProcessState::Exiting => return None,
    };
    Some(LiveProcessStatus {
        pid: process.handle.pid,
        parent_pid: process.parent.map_or(0, |parent| parent.pid),
        state,
    })
}

/// Charges the CPU time since the last charge to the process that ran
/// meanwhile, at timestamp `now`. Saving a process's state charges it;
/// switching another one in starts its interval. Each CPU keeps its own
/// interval (`cpu_time::process_interval`), so the threads of one process
/// on several CPUs each add theirs, and an interval goes to the process it
/// was opened for.
pub(crate) fn charge_live_process_cpu(now: u64) {
    if let Some(interval) = crate::cpu_time::process_interval(now, true) {
        charge_process_interval(interval);
    }
}

fn charge_process_interval(interval: crate::cpu_time::ProcessInterval) {
    if let Some(process) = live_process_table_mut().and_then(|table| {
        let handle = table.handle_by_pid(interval.pid)?;
        table.process_mut(handle)
    }) {
        process.cpu_cycles = process.cpu_cycles.saturating_add(interval.total);
        process.user_cycles = process.user_cycles.saturating_add(interval.user);
        for (total, added) in process.task_events.iter_mut().zip(interval.events) {
            *total = total.saturating_add(added);
        }
    }
}

/// The task events of the live processes of the domain `pid` is in, the
/// open interval on this CPU included (a CPU-wide perf event's counts).
pub(crate) fn live_domain_task_events(pid: u32, now: u64) -> [u64; crate::cpu_time::TASK_EVENTS] {
    let mut events = [0; crate::cpu_time::TASK_EVENTS];
    let Some(table) = live_process_table_mut() else {
        return events;
    };
    if table.handle_by_pid(pid).is_none() {
        return events;
    }
    for process in table.processes.iter().flatten() {
        for (total, added) in events.iter_mut().zip(process.task_events) {
            *total = total.saturating_add(added);
        }
    }
    if let Some(interval) = crate::cpu_time::process_interval(now, false) {
        for (total, added) in events.iter_mut().zip(interval.events) {
            *total = total.saturating_add(added);
        }
    }
    events
}

/// The task events of `pid` (`cpu_time::TaskEvent`), its open interval on
/// this CPU included when `running`, and with `children` those of the
/// children it waited for.
pub(crate) fn live_process_task_events(
    pid: u32,
    running: bool,
    children: bool,
    now: u64,
) -> Option<[u64; crate::cpu_time::TASK_EVENTS]> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    let mut events = process.task_events;
    if children {
        for (total, added) in events.iter_mut().zip(process.children_task_events) {
            *total = total.saturating_add(added);
        }
    }
    if running {
        if let Some(interval) =
            crate::cpu_time::process_interval(now, false).filter(|interval| interval.pid == pid)
        {
            for (total, added) in events.iter_mut().zip(interval.events) {
                *total = total.saturating_add(added);
            }
        }
    }
    Some(events)
}

/// Starts the CPU interval of process `pid`, switched in at timestamp
/// `now`; the interval open until then goes to its process.
pub(crate) fn start_live_process_cpu(pid: u32, now: u64) {
    if let Some(open) = crate::cpu_time::start_process_interval(pid, now) {
        charge_process_interval(open);
    }
}

/// When `pid` was created, in nanoseconds since boot.
pub(crate) fn live_process_started_nanoseconds(pid: u32) -> Option<u64> {
    let table = live_process_table_mut()?;
    Some(
        table
            .process(table.handle_by_pid(pid)?)?
            .started_nanoseconds,
    )
}

/// The CPU time `pid` has used, in timestamp-counter cycles, at `now`; for
/// the running process this includes its current interval.
pub(crate) fn live_process_cpu_cycles(pid: u32, running: bool, now: u64) -> Option<u64> {
    live_process_cpu_times(pid, running, now).map(|(user, system)| user + system)
}

/// The user and system time `pid` has used, in timestamp-counter cycles,
/// at `now`, as `live_process_cpu_cycles` counts it.
pub(crate) fn live_process_cpu_times(pid: u32, running: bool, now: u64) -> Option<(u64, u64)> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    let (mut total, mut user) = (process.cpu_cycles, process.user_cycles);
    if running {
        if let Some(interval) =
            crate::cpu_time::process_interval(now, false).filter(|interval| interval.pid == pid)
        {
            total = total.saturating_add(interval.total);
            user = user.saturating_add(interval.user);
        }
    }
    let user = user.min(total);
    Some((user, total - user))
}

/// The user and system time of the children `pid` waited for, theirs
/// included, in timestamp-counter cycles.
pub(crate) fn live_process_children_cpu_times(pid: u32) -> Option<(u64, u64)> {
    let table = live_process_table_mut()?;
    Some(table.process(table.handle_by_pid(pid)?)?.children_cycles)
}

/// Records whether a process waits in a blocking system call: set when it
/// gives up the CPU there, cleared when it is woken or next dispatched.
pub(crate) fn set_live_process_waiting(pid: u32, waiting: bool) {
    if let Some(table) = live_process_table_mut() {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.waiting = waiting;
        } else {
            return;
        }
        if waiting {
            table.note_sleeper(pid);
        }
    }
}

/// Records that process `pid` sleeps in a futex wait until `deadline` (0:
/// none), or no longer (None).
pub(crate) fn set_live_process_futex_sleep(pid: u32, deadline: Option<u64>) {
    if let Some(table) = live_process_table_mut() {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.futex_sleep = deadline;
        } else {
            return;
        }
        table.note_sleeper(pid);
    }
}

/// Whether process `pid` is parked asleep with its mark's deadline passed
/// by `now`: due to run, to find its wait over.
pub(crate) fn live_process_sleep_due(pid: u32, now: u64) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .and_then(Process::marked_asleep_until)
            .is_some_and(|deadline| deadline <= now)
    })
}

/// Whether process `pid` sleeps in a futex wait nothing has ended by `now`
/// (`Process::is_asleep`): resuming it would only find it waiting again.
pub(crate) fn live_process_futex_asleep(pid: u32, now: u64) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .is_some_and(|process| process.is_asleep(now))
    })
}

/// The earliest deadline a process marked asleep in a wait of its own
/// (`Process::is_asleep`) is due at, passed already or not: a CPU that
/// halts until its next tick would resume it late, and one that halts with
/// it due (its deadline came between the look for work and the halt) a
/// whole tick late.
pub(crate) fn next_live_futex_sleep_deadline() -> Option<u64> {
    let table = live_process_table_mut()?;
    if table.sleepers_lossy {
        table.rebuild_sleepers();
    }
    if table.sleepers_lossy {
        return table
            .processes
            .iter()
            .flatten()
            .filter_map(|process| process.marked_asleep_until())
            .min();
    }
    let mut sleepers = core::mem::take(&mut table.sleepers);
    let earliest = sleepers.earliest(|pid, deadline| table.sleeper_holds(pid, deadline));
    table.sleepers = sleepers;
    earliest.map(|(deadline, _)| deadline)
}

impl ProcessTable {
    /// Records `pid`'s deadline if it is now marked asleep (both its mark
    /// and its `waiting`, which are set apart, hold), dropping the entries
    /// no longer marked once they outnumber the processes.
    fn note_sleeper(&mut self, pid: u32) {
        let Some(deadline) = self
            .handle_by_pid(pid)
            .and_then(|handle| self.process(handle))
            .and_then(Process::marked_asleep_until)
        else {
            return;
        };
        if self.sleepers_lossy {
            return;
        }
        if self.sleepers.len() >= 2 * self.pid_slots.len() + 64 {
            let mut sleepers = core::mem::take(&mut self.sleepers);
            sleepers.retain(|pid, deadline| self.sleeper_holds(pid, deadline));
            self.sleepers = sleepers;
        }
        if self.sleepers.push(deadline, pid).is_err() {
            self.sleepers.clear();
            self.sleepers_lossy = true;
        }
    }

    /// Whether `pid` is still marked asleep until `deadline`.
    fn sleeper_holds(&self, pid: u32, deadline: u64) -> bool {
        self.handle_by_pid(pid)
            .and_then(|handle| self.process(handle))
            .and_then(Process::marked_asleep_until)
            == Some(deadline)
    }

    /// Puts every current mark back after an allocation failure lost some.
    fn rebuild_sleepers(&mut self) {
        let mut sleepers = ginux_deadline_heap::DeadlineHeap::new();
        for process in self.processes.iter().flatten() {
            if let Some(deadline) = process.marked_asleep_until() {
                if sleepers.push(deadline, process.handle.pid).is_err() {
                    return;
                }
            }
        }
        self.sleepers = sleepers;
        self.sleepers_lossy = false;
    }
}

impl Process {
    /// The deadline the process is marked asleep until, if it is: running,
    /// waiting, with a deadline to its mark.
    fn marked_asleep_until(&self) -> Option<u64> {
        (self.state == ProcessState::Running && self.waiting)
            .then_some(self.futex_sleep)
            .flatten()
            .filter(|deadline| *deadline != 0)
    }

    /// Asleep in a futex wait that no wake (which clears `waiting`), signal
    /// it takes (likewise) or deadline has ended by `now`.
    fn is_asleep(&self, now: u64) -> bool {
        self.waiting
            && self
                .futex_sleep
                .is_some_and(|deadline| deadline == 0 || now < deadline)
    }
}

/// POSIX timers per process (timer_create); Linux allows far more, this
/// table is fixed like the rest of the process record.
pub(crate) const POSIX_TIMER_LIMIT: usize = 16;

/// A POSIX interval timer of a process. Deadlines are the monotonic
/// nanoseconds `linux_elapsed_nanoseconds` counts (wall-clock values are
/// converted at timer_settime), 0 while disarmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PosixTimer {
    pub(crate) clock: u32,
    /// SIGEV_SIGNAL (0), SIGEV_NONE (1) or SIGEV_THREAD_ID (4).
    pub(crate) notify: u32,
    pub(crate) signal: u8,
    /// The thread a SIGEV_THREAD_ID timer signals, else 0.
    pub(crate) tid: u32,
    /// sigev_value, delivered as si_value.
    pub(crate) value: u64,
    pub(crate) deadline: u64,
    pub(crate) interval: u64,
    /// Expirations the queued signal stands for beyond its own, counted on
    /// while the signal stays pending (DELAYTIMER_MAX saturates it).
    pub(crate) overrun: u32,
    /// The overrun of the last signal delivered (timer_getoverrun).
    pub(crate) delivered_overrun: u32,
}

/// Notes the delivery of `signal` with `value` to `pid`: the overrun the
/// timer that queued it counted is what timer_getoverrun reports from now
/// on, as Linux freezes it at delivery (timer_settime03 reads it in the
/// handler).
pub(crate) fn note_posix_timer_delivery(pid: u32, signal: u8, value: u64) {
    let Some(table) = live_process_table_mut() else {
        return;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return;
    };
    for timer in process.posix_timers.iter_mut().flatten() {
        if timer.signal == signal && timer.value == value {
            timer.delivered_overrun = timer.overrun;
        }
    }
}

/// What an expired timer delivers.
#[derive(Clone, Copy)]
pub(crate) struct PosixTimerExpiry {
    pub(crate) notify: u32,
    pub(crate) signal: u8,
    pub(crate) tid: u32,
    pub(crate) value: u64,
    /// An interval timer's (setitimer): its signal comes from the kernel
    /// (SI_KERNEL), not a POSIX timer (SI_TIMER).
    pub(crate) interval_timer: bool,
}

/// The most expiries one check reports: every POSIX timer, both CPU
/// interval timers and the two RLIMIT_CPU limits.
pub(crate) const TIMER_EXPIRY_LIMIT: usize = POSIX_TIMER_LIMIT + 4;

impl PosixTimerExpiry {
    pub(crate) const NONE: Self = Self {
        notify: 0,
        signal: 0,
        tid: 0,
        value: 0,
        interval_timer: false,
    };
}

/// Creates a POSIX timer for `pid`: its id, from 1, the first free one.
pub(crate) fn create_posix_timer(pid: u32, timer: PosixTimer) -> Option<u32> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process_mut(handle)?;
    let index = process.posix_timers.iter().position(Option::is_none)?;
    process.posix_timers[index] = Some(timer);
    Some(index as u32 + 1)
}

/// Timer `id` of `pid`.
pub(crate) fn posix_timer(pid: u32, id: u32) -> Option<PosixTimer> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process(handle)?;
    let index = usize::try_from(id.checked_sub(1)?).ok()?;
    process.posix_timers.get(index).copied().flatten()
}

/// Changes timer `id` of `pid` with `change`; None without such a timer.
pub(crate) fn update_posix_timer(
    pid: u32,
    id: u32,
    change: impl FnOnce(&mut PosixTimer),
) -> Option<PosixTimer> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process_mut(handle)?;
    let index = usize::try_from(id.checked_sub(1)?).ok()?;
    let timer = process.posix_timers.get_mut(index)?.as_mut()?;
    change(timer);
    Some(*timer)
}

/// Deletes timer `id` of `pid`.
pub(crate) fn delete_posix_timer(pid: u32, id: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    let Some(index) = id
        .checked_sub(1)
        .and_then(|index| usize::try_from(index).ok())
    else {
        return false;
    };
    match process.posix_timers.get_mut(index) {
        Some(slot @ Some(_)) => {
            *slot = None;
            true
        }
        _ => false,
    }
}

/// The earliest armed deadline among `pid`'s timers, 0 with none armed.
pub(crate) fn earliest_posix_timer_deadline(pid: u32) -> u64 {
    let Some(table) = live_process_table_mut() else {
        return 0;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process(handle))
    else {
        return 0;
    };
    process
        .posix_timers
        .iter()
        .chain(process.itimers.iter())
        .flatten()
        .map(|timer| timer.deadline)
        .filter(|deadline| *deadline != 0)
        .min()
        .unwrap_or(0)
}

/// Expires `pid`'s timers whose deadline passed by `now`: a periodic one
/// moves on past `now` (the expirations in between are its overrun), a
/// one-shot one disarms. Lists what each delivers. `pending` is the mask
/// of signals the process has pending: a timer whose signal is still
/// queued counts these expirations on its overrun instead of queueing
/// again, as Linux does until the signal is delivered.
/// Whether a POSIX timer's clock counts CPU time: CLOCK_PROCESS_CPUTIME_ID,
/// CLOCK_THREAD_CPUTIME_ID, or a clock id clock_getcpuclockid or
/// pthread_getcpuclockid made (negative). Its deadlines are CPU nanoseconds.
pub(crate) fn posix_clock_is_cpu(clock: u32) -> bool {
    matches!(clock, 2 | 3) || (clock as i32) < 0
}

/// Whether a CPU clock counts one thread's time (CLOCK_THREAD_CPUTIME_ID,
/// or a pthread_getcpuclockid id: bit 2 set).
pub(crate) fn posix_clock_is_thread_cpu(clock: u32) -> bool {
    clock == 3 || (clock as i32) < 0 && clock & 4 != 0
}

/// setitimer's ITIMER_VIRTUAL (`which` 1) or ITIMER_PROF (2) of `pid`:
/// its interval and its deadline on the process CPU clock (0: disarmed).
pub(crate) fn live_process_interval_timer(pid: u32, which: usize) -> Option<(u64, u64)> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    let timer = process.itimers.get(which.checked_sub(1)?)?;
    Some(timer.map_or((0, 0), |timer| (timer.interval, timer.deadline)))
}

/// Arms (`deadline` nonzero, on the process CPU clock) or disarms
/// `pid`'s ITIMER_VIRTUAL or ITIMER_PROF, which sends `signal`.
pub(crate) fn set_live_process_interval_timer(
    pid: u32,
    which: usize,
    signal: u8,
    (interval, deadline): (u64, u64),
) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    let Some(timer) = which
        .checked_sub(1)
        .and_then(|index| process.itimers.get_mut(index))
    else {
        return false;
    };
    // CLOCK_PROCESS_CPUTIME_ID, signalled as SIGEV_SIGNAL.
    *timer = (deadline != 0).then_some(PosixTimer {
        clock: 2,
        notify: 0,
        signal,
        tid: 0,
        value: 0,
        deadline,
        interval,
        overrun: 0,
        delivered_overrun: 0,
    });
    true
}

/// Fires process `pid`'s timers whose deadline passed: `now` on the
/// monotonic clock, `cpu_now` the process's CPU time, for timers on a CPU
/// clock (timer_settime01).
pub(crate) fn expire_posix_timers(
    pid: u32,
    (monotonic_now, cpu_now, thread_now): (u64, u64, u64),
    pending: u64,
    expiries: &mut [PosixTimerExpiry; TIMER_EXPIRY_LIMIT],
) -> usize {
    let Some(table) = live_process_table_mut() else {
        return 0;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return 0;
    };
    let mut count = 0;
    let posix_count = process.posix_timers.len();
    for (index, timer) in process
        .posix_timers
        .iter_mut()
        .chain(process.itimers.iter_mut())
        .enumerate()
        .filter_map(|(index, timer)| Some((index, timer.as_mut()?)))
    {
        let now = if posix_clock_is_thread_cpu(timer.clock) {
            thread_now
        } else if posix_clock_is_cpu(timer.clock) {
            cpu_now
        } else {
            monotonic_now
        };
        if timer.deadline == 0 || now < timer.deadline {
            continue;
        }
        let expirations = match (now - timer.deadline).checked_div(timer.interval) {
            // A one-shot timer (no interval) disarms.
            None => {
                timer.deadline = 0;
                1
            }
            Some(missed) => {
                timer.deadline = timer
                    .deadline
                    .saturating_add((missed + 1).saturating_mul(timer.interval));
                missed + 1
            }
        };
        let overrun = u32::try_from(expirations - 1).unwrap_or(u32::MAX);
        if timer.signal != 0 && pending & (1_u64 << (timer.signal - 1)) != 0 {
            timer.overrun = timer.overrun.saturating_add(overrun).saturating_add(1);
            continue;
        }
        timer.overrun = overrun;
        expiries[count] = PosixTimerExpiry {
            notify: timer.notify,
            signal: timer.signal,
            tid: timer.tid,
            value: timer.value,
            interval_timer: index >= posix_count,
        };
        count += 1;
    }
    count
}

pub(crate) fn live_process_cpu_affinity(pid: u32) -> Option<u64> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process(handle)?;
    matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
    )
    .then_some(process.cpu_affinity)
}

/// Stops process `pid` with stop signal `signal` (SIGSTOP, SIGTSTP, SIGTTIN
/// or SIGTTOU): its parent's wait (WUNTRACED) reports it. `in_call` for a
/// process parking in its kill call until SIGCONT; otherwise the scheduler
/// no longer dispatches it. False unless it was running.
pub(crate) fn stop_live_process(pid: u32, signal: u8, in_call: bool) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    table.stop(handle, signal, in_call)
}

/// Whether process `pid` is stopped (by a stop signal, until SIGCONT).
pub(crate) fn live_process_stopped(pid: u32) -> bool {
    live_process_status(pid).is_some_and(|status| status.state == LiveProcessState::Stopped)
}

/// Continues stopped process `pid` (SIGCONT): it runs again, and its
/// parent's wait (WCONTINUED) reports it. False unless it was stopped.
pub(crate) fn continue_live_process(pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    table.continue_process(handle)
}

/// Set in a process's policy byte by SCHED_RESET_ON_FORK: its children
/// start with SCHED_OTHER and priority 0.
pub(crate) const SCHED_RESET_ON_FORK: u8 = 0x80;

/// sched_getscheduler and sched_getparam: `pid`'s policy and priority.
pub(crate) fn live_process_scheduling(pid: u32) -> Option<(u8, u8)> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
    )
    .then_some(process.scheduling)
}

/// sched_setscheduler: gives `pid` `policy` and `priority`.
pub(crate) fn set_live_process_scheduling(pid: u32, policy: u8, priority: u8) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    if !matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. }
    ) {
        return false;
    }
    process.scheduling = (policy, priority);
    true
}

/// Linux's timer slack for a new process, in nanoseconds.
pub(crate) const DEFAULT_TIMER_SLACK: u64 = 50_000;

/// prctl(PR_GET_TIMERSLACK): `pid`'s current timer slack.
/// Why a seccomp filter was not installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SeccompError {
    /// No such live process.
    NoProcess,
    /// The chain would pass MAX_INSNS_PER_PATH, or no memory (ENOMEM).
    NoMemory,
}

impl ProcessTable {
    /// Adds `program` in front of `pid`'s filters. Filters no process
    /// reaches any more (their processes exited) are freed first.
    fn install_seccomp_filter(
        &mut self,
        pid: u32,
        program: ginux_seccomp::Program,
    ) -> Result<(), SeccompError> {
        let handle = self.handle_by_pid(pid).ok_or(SeccompError::NoProcess)?;
        let previous = self
            .process(handle)
            .ok_or(SeccompError::NoProcess)?
            .seccomp_filter;
        let path_instructions = self
            .seccomp_filter(previous)
            .map_or(0, |filter| filter.path_instructions)
            .saturating_add(program.len() + 4);
        if path_instructions > SECCOMP_PATH_LIMIT {
            return Err(SeccompError::NoMemory);
        }
        self.free_unreached_seccomp_filters();
        let filter = SeccompFilter {
            program,
            previous,
            path_instructions,
        };
        let index = match self.seccomp_filters.iter().position(Option::is_none) {
            Some(index) => {
                self.seccomp_filters[index] = Some(filter);
                index
            }
            None => {
                self.seccomp_filters
                    .try_reserve(1)
                    .map_err(|_| SeccompError::NoMemory)?;
                self.seccomp_filters.push(Some(filter));
                self.seccomp_filters.len() - 1
            }
        };
        let id = u32::try_from(index + 1).map_err(|_| SeccompError::NoMemory)?;
        self.process_mut(handle)
            .ok_or(SeccompError::NoProcess)?
            .seccomp_filter = id;
        Ok(())
    }

    fn seccomp_filter(&self, id: u32) -> Option<&SeccompFilter> {
        self.seccomp_filters
            .get(usize::try_from(id).ok()?.checked_sub(1)?)?
            .as_ref()
    }

    /// Frees the filters no process's chain reaches.
    fn free_unreached_seccomp_filters(&mut self) {
        let mut reached = Vec::new();
        if reached
            .try_reserve_exact(self.seccomp_filters.len())
            .is_err()
        {
            return;
        }
        reached.resize(self.seccomp_filters.len(), false);
        for process in self.processes.iter().flatten() {
            let mut id = process.seccomp_filter;
            while let Some(filter) = self.seccomp_filter(id) {
                let index = id as usize - 1;
                if reached[index] {
                    break;
                }
                reached[index] = true;
                id = filter.previous;
            }
        }
        for (slot, reached) in self.seccomp_filters.iter_mut().zip(reached) {
            if !reached {
                *slot = None;
            }
        }
    }

    /// The strictest return value of `pid`'s filters for `data`, or None
    /// when it has none.
    fn seccomp_return(&self, pid: u32, data: &ginux_seccomp::Data) -> Option<u32> {
        let mut id = self.process(self.handle_by_pid(pid)?)?.seccomp_filter;
        let mut result = None;
        while let Some(filter) = self.seccomp_filter(id) {
            let value = filter.program.run(data);
            result = Some(result.map_or(value, |old| ginux_seccomp::strictest(old, value)));
            id = filter.previous;
        }
        result
    }
}

/// seccomp(SECCOMP_SET_MODE_FILTER) for `pid`.
pub(crate) fn install_live_process_seccomp_filter(
    pid: u32,
    program: ginux_seccomp::Program,
) -> Result<(), SeccompError> {
    live_process_table_mut()
        .ok_or(SeccompError::NoProcess)?
        .install_seccomp_filter(pid, program)
}

/// What `pid`'s seccomp filters return for a system call, or None without
/// filters.
pub(crate) fn live_process_seccomp_return(pid: u32, data: &ginux_seccomp::Data) -> Option<u32> {
    live_process_table_mut()?.seccomp_return(pid, data)
}

pub(crate) fn live_process_timer_slack(pid: u32) -> Option<u64> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. }
    )
    .then_some(process.timer_slack.0)
}

/// prctl(PR_SET_TIMERSLACK): 0 restores the process's default.
pub(crate) fn set_live_process_timer_slack(pid: u32, slack: u64) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    if !matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. }
    ) {
        return false;
    }
    process.timer_slack.0 = if slack == 0 {
        process.timer_slack.1
    } else {
        slack
    };
    true
}

/// A process's I/O as `/proc/PID/io` counts it (Linux's task_io_accounting):
/// bytes passed by read and write calls and how many such calls it made,
/// and the bytes its file I/O read from and wrote to storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IoAccounting {
    pub(crate) rchar: u64,
    pub(crate) wchar: u64,
    pub(crate) syscr: u64,
    pub(crate) syscw: u64,
    pub(crate) read_bytes: u64,
    pub(crate) write_bytes: u64,
    pub(crate) cancelled_write_bytes: u64,
}

/// The I/O process `pid` did (`/proc/PID/io`).
pub(crate) fn live_process_io(pid: u32) -> Option<IoAccounting> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.io)
}

/// Adds to the I/O counts of process `pid`.
pub(crate) fn account_live_process_io(pid: u32, account: impl FnOnce(&mut IoAccounting)) {
    if let Some(process) = live_process_table_mut().and_then(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
    }) {
        account(&mut process.io);
    }
}

pub(crate) fn live_process_oom_score_adj(pid: u32) -> Option<i16> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Zombie { .. }
    )
    .then_some(process.oom_score_adj)
}

/// Whether `pid` is marked a child subreaper (PR_GET_CHILD_SUBREAPER).
pub(crate) fn live_process_child_subreaper(pid: u32) -> Option<bool> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.child_subreaper)
}

/// Marks `pid` a child subreaper or not (PR_SET_CHILD_SUBREAPER).
pub(crate) fn set_live_process_child_subreaper(pid: u32, marked: bool) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.child_subreaper = marked;
    true
}

/// The memory policy of `pid` (set_mempolicy).
pub(crate) fn live_process_memory_policy(pid: u32) -> Option<crate::linux_areas::Policy> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.memory_policy)
}

/// Sets the memory policy of `pid` (set_mempolicy).
pub(crate) fn set_live_process_memory_policy(pid: u32, policy: crate::linux_areas::Policy) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.memory_policy = policy;
    true
}

/// Records that a signal's default action is terminating `pid`, so its
/// parent's wait reports it as killed by that signal rather than as an exit.
pub(crate) fn set_live_process_killed_by_signal(pid: u32, signal: u8) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.killed_by_signal = signal;
    true
}

/// Sets `/proc/PID/oom_score_adj`; the caller has checked the Linux range
/// -1000..=1000.
pub(crate) fn set_live_process_oom_score_adj(pid: u32, value: i16) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    if !matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. }
    ) {
        return false;
    }
    process.oom_score_adj = value;
    true
}

pub(crate) fn set_live_process_cpu_affinity(pid: u32, mask: u64) -> bool {
    if mask == 0 {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    if !matches!(
        process.state,
        ProcessState::Running | ProcessState::Stopped { .. }
    ) {
        return false;
    }
    process.cpu_affinity = mask;
    process.scheduler_thread.is_none_or(|thread| {
        scheduler::active_process_scheduler_workspace()
            .is_some_and(|run_queue| run_queue.set_affinity(thread, mask))
    })
}

/// Lets only CPU `cpu` run process `pid` (`Some`), or again the CPUs its
/// affinity names (`None`): for a CPU that made the process ready but will
/// switch back to it, such as the parent of the fork it runs, so that no
/// other CPU takes it meanwhile. Its affinity as the process sees it does
/// not change.
pub(crate) fn pin_live_process(pid: u32, cpu: Option<usize>) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process(handle))
    else {
        return false;
    };
    let mask = cpu.map_or(process.cpu_affinity, |cpu| 1_u64 << cpu);
    process.scheduler_thread.is_none_or(|thread| {
        scheduler::active_process_scheduler_workspace()
            .is_some_and(|run_queue| run_queue.set_affinity(thread, mask))
    })
}

pub(crate) fn set_live_process_scheduler_nice(pid: u32, nice: u8) -> bool {
    if nice > 39 {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(thread) = table
        .process(handle)
        .and_then(|process| process.scheduler_thread)
    else {
        return true;
    };
    let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
        return false;
    };
    run_queue.set_priority(thread, 39_i8 - nice as i8)
}

/// The pid of the process tracing `pid` (ptrace), if one is.
pub(crate) fn live_process_tracer(pid: u32) -> Option<u32> {
    let table = live_process_table_mut()?;
    let tracer = table.process(table.handle_by_pid(pid)?)?.tracer;
    (tracer != 0).then_some(tracer)
}

/// Makes `tracer` (0: none) trace `pid`, clearing any resume signal.
pub(crate) fn set_live_process_tracer(pid: u32, tracer: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    process.tracer = tracer;
    process.ptrace_resume_signal = 0;
    true
}

/// Records the signal a tracee delivers as it resumes (PTRACE_CONT).
pub(crate) fn set_live_process_ptrace_resume_signal(pid: u32, signal: u8) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.ptrace_resume_signal = signal;
    true
}

/// Takes the signal a tracee resuming from its trace stop delivers.
pub(crate) fn take_live_process_ptrace_resume_signal(pid: u32) -> u8 {
    live_process_table_mut()
        .and_then(|table| {
            let handle = table.handle_by_pid(pid)?;
            let process = table.process_mut(handle)?;
            Some(core::mem::take(&mut process.ptrace_resume_signal))
        })
        .unwrap_or(0)
}

/// Marks (or, taking it, reads and clears) that the tracee's next signal
/// delivery is the one its tracer let through, which does not stop again.
pub(crate) fn set_live_process_ptrace_bypass(pid: u32, bypass: bool) {
    if let Some(process) = live_process_table_mut().and_then(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process_mut(handle)
    }) {
        process.ptrace_bypass = bypass;
    }
}

/// Tracee `pid`'s debug register `index` (PTRACE_PEEKUSER).
pub(crate) fn live_process_debug_register(pid: u32, index: usize) -> Option<u64> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.debug_registers.read(index))
}

/// Writes tracee `pid`'s debug register `index` (PTRACE_POKEUSER); None
/// for no such process.
pub(crate) fn set_live_process_debug_register(
    pid: u32,
    index: usize,
    value: u64,
) -> Option<Result<(), DebugRegisterError>> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process_mut(handle)?;
    Some(process.debug_registers.write(index, value))
}

pub(crate) fn take_live_process_ptrace_bypass(pid: u32) -> bool {
    live_process_table_mut()
        .and_then(|table| {
            let handle = table.handle_by_pid(pid)?;
            let process = table.process_mut(handle)?;
            Some(core::mem::take(&mut process.ptrace_bypass))
        })
        .unwrap_or(false)
}

pub(crate) fn live_process_parent_pid(pid: u32) -> Option<u32> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process(handle)?;
    Some(
        process
            .parent
            .and_then(|parent| table.process(parent).map(|parent| parent.handle.pid))
            .unwrap_or(0),
    )
}

pub(crate) fn live_running_child_pid(parent_pid: u32) -> Option<u32> {
    let table = live_process_table_mut()?;
    let parent = table.handle_by_pid(parent_pid)?;
    table
        .processes
        .iter()
        .flatten()
        .find(|process| process.parent == Some(parent) && process.state == ProcessState::Running)
        .map(|process| process.handle.pid)
}

/// Whether a child of `parent_pid` can run: running and not waiting in a
/// system call.
pub(crate) fn live_runnable_child_exists(parent_pid: u32) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table.handle_by_pid(parent_pid).is_some_and(|parent| {
            table.processes.iter().flatten().any(|process| {
                process.parent == Some(parent)
                    && process.state == ProcessState::Running
                    && !process.waiting
            })
        })
    })
}

pub(crate) fn live_process_group(pid: u32) -> Option<u32> {
    live_process_table_mut()?
        .process_group(pid)
        .map(|group| group.0)
}

pub(crate) fn live_process_session(pid: u32) -> Option<u32> {
    live_process_table_mut()?
        .process_group(pid)
        .map(|group| group.1)
}

pub(crate) fn set_live_process_group(
    caller_pid: u32,
    target_pid: u32,
    process_group: u32,
) -> Result<(), ProcessGroupError> {
    live_process_table_mut()
        .ok_or(ProcessGroupError::NoSuchProcess)?
        .set_process_group(caller_pid, target_pid, process_group)
}

pub(crate) fn create_live_process_session(pid: u32) -> Result<u32, ProcessGroupError> {
    live_process_table_mut()
        .ok_or(ProcessGroupError::NoSuchProcess)?
        .create_session(pid)
}

pub(crate) fn mark_live_process_executed(pid: u32) -> bool {
    live_process_table_mut().is_some_and(|table| table.mark_executed(pid))
}

pub(crate) fn set_live_process_exec_context(pid: u32, rip: u64, rsp: u64) -> bool {
    live_process_table_mut().is_some_and(|table| table.set_exec_context(pid, rip, rsp))
}

pub(crate) fn live_process_slot(pid: u32) -> Option<usize> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    Some(usize::from(handle.slot))
}

pub(crate) fn live_process_runtime_slot(pid: u32) -> Option<usize> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    table.process(handle)?.runtime_slot.map(usize::from)
}

pub(crate) fn release_live_process_runtime_slot(pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    if !matches!(process.state, ProcessState::Zombie { .. }) || process.runtime_slot.is_none() {
        return false;
    }
    let slot = process.runtime_slot.take();
    // Give back the slot's lists: a large process's are many megabytes and
    // would otherwise stay until another process takes the slot.
    let referenced = table.processes.iter().flatten().any(|process| {
        process.runtime_slot == slot
            || [process.address_space, process.retiring_address_space]
                .into_iter()
                .flatten()
                .any(|space| Some(space.storage_slot) == slot)
    });
    if let (false, Some(slot)) = (referenced, slot) {
        if let Some(storage) = address_space_storage(usize::from(slot)) {
            *storage = ProcessAddressSpaceStorage::default();
        }
    }
    true
}

pub(crate) fn live_process_generation(pid: u32) -> Option<u32> {
    let table = live_process_table_mut()?;
    Some(table.handle_by_pid(pid)?.generation)
}

/// How many slots the process table has now (`live_process_pid_at` is
/// None at and past them).
pub(crate) fn live_process_slots() -> usize {
    live_process_table_mut().map_or(0, |table| table.processes.len())
}

pub(crate) fn live_process_pid_at(slot: usize) -> Option<u32> {
    let table = live_process_table_mut()?;
    table
        .processes
        .get(slot)?
        .as_ref()
        .map(|process| process.handle.pid)
}

/// The smallest pid at least `from` of a process in the table, as /proc
/// lists them (zombies included, processes still being made or ended not).
pub(crate) fn next_live_pid(from: u32) -> Option<u32> {
    let table = live_process_table_mut()?;
    let start = table.pid_slots.partition_point(|(pid, _)| *pid < from);
    table.pid_slots[start..].iter().find_map(|(pid, slot)| {
        table
            .processes
            .get(usize::from(*slot))?
            .as_ref()
            .filter(|process| {
                process.handle.pid == *pid
                    && !matches!(
                        process.state,
                        ProcessState::Preparing | ProcessState::Exiting
                    )
            })
            .map(|_| *pid)
    })
}

pub(crate) fn live_process_count() -> Option<u16> {
    let table = live_process_table_mut()?;
    table
        .processes
        .iter()
        .filter(|process| process.is_some())
        .count()
        .try_into()
        .ok()
}

pub(crate) fn host_live_process_count() -> Option<u16> {
    let mut count = 0_usize;
    for (instance, initialized) in process_runtime().table_initialized.iter().enumerate() {
        if initialized.load(Ordering::Acquire) {
            // Linux process-table mutation and host inspection are serialized
            // by the recursive kernel-entry boundary.
            let table = unsafe {
                &*process_runtime()
                    .tables
                    .get()
                    .cast::<ProcessTable>()
                    .add(instance)
            };
            count = count.checked_add(
                table
                    .processes
                    .iter()
                    .filter(|process| process.is_some())
                    .count(),
            )?;
        }
    }
    count.try_into().ok()
}

pub(crate) fn live_process_mapping(
    pid: u32,
    address: usize,
) -> Option<cpu::LinuxActiveImageMapping> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let space = table.process(handle)?.address_space?;
    // A stale list lacks pages mapped since its snapshot; the live page
    // tables have them.
    if space.stale {
        return address_space::linux_active_mapping_in_root(space.root(), address as u64);
    }
    space
        .mappings()
        .iter()
        .copied()
        .find(|mapping| mapping.address == address)
}

/// Takes the next process ID for a new thread, so thread and process IDs
/// never repeat each other, as in Linux's shared PID space.
pub(crate) fn allocate_live_thread_id() -> Option<u32> {
    let table = live_process_table_mut()?;
    let tid = table.next_pid;
    table.next_pid = tid.checked_add(1)?;
    Some(tid)
}

/// Marks `pid`'s registered address space as older than its mappings, when
/// a final snapshot could not be taken, so its release frees only what the
/// live page tables show.
pub(crate) fn mark_live_process_address_space_stale(pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(space) = table
        .process_mut(handle)
        .and_then(|process| process.address_space.as_mut())
    else {
        return false;
    };
    space.stale = true;
    true
}

/// Whether `pid`'s registered mapping list is stale (see
/// `refresh_live_process_context_for_wait`), so a fork must snapshot its
/// address space before copying the list.
pub(crate) fn live_process_address_space_stale(pid: u32) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .and_then(|process| process.address_space)
            .is_some_and(|space| space.stale)
    })
}

/// Whether `pid` is a child forked onto its parent's pages that has not
/// executed yet, whose pages all belong to its parent.
pub(crate) fn live_process_shares_parent_vm(pid: u32) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .is_some_and(|process| process.shares_parent_vm)
    })
}

/// The id of the `resource` process `pid` uses (`SharedResource`).
pub(crate) fn live_process_shared_id(pid: u32, resource: SharedResource) -> Option<u32> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.shared[resource as usize])
}

/// Makes process `pid` use `resource` of process `owner` (a clone that
/// shares it), or one of its own when `owner` is None (unshare, exec).
pub(crate) fn share_live_process_resource(
    pid: u32,
    resource: SharedResource,
    owner: Option<u32>,
) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let id = match owner {
        Some(owner) => {
            let Some(owner) = table
                .handle_by_pid(owner)
                .and_then(|handle| table.process(handle))
            else {
                return false;
            };
            owner.shared[resource as usize]
        }
        None => table.new_shared_id(),
    };
    table.sharing |= owner.is_some()
        && matches!(
            resource,
            SharedResource::Descriptors
                | SharedResource::Filesystem
                | SharedResource::SignalHandlers
        );
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.shared[resource as usize] = id;
    true
}

/// The other processes that share `resource` with process `pid` and have
/// not ended (a zombie holds nothing any more), by pid; empty when memory
/// for the list runs out.
pub(crate) fn live_processes_sharing(pid: u32, resource: SharedResource) -> Vec<u32> {
    let mut sharing = Vec::new();
    let Some(table) = live_process_table_mut() else {
        return sharing;
    };
    let Some(id) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process(handle))
        .map(|process| process.shared[resource as usize])
    else {
        return sharing;
    };
    for process in table.processes.iter().flatten() {
        if process.handle.pid != pid
            && process.shared[resource as usize] == id
            && matches!(
                process.state,
                ProcessState::Running | ProcessState::Stopped { .. }
            )
        {
            if sharing.try_reserve(1).is_err() {
                return Vec::new();
            }
            sharing.push(process.handle.pid);
        }
    }
    sharing
}

/// Whether process `pid` shares `resource` with another that has not ended.
pub(crate) fn live_process_resource_shared(pid: u32, resource: SharedResource) -> bool {
    let tracked = matches!(
        resource,
        SharedResource::Memory | SharedResource::Io | SharedResource::SemaphoreUndo
    ) || live_processes_share_state();
    let Some(table) = live_process_table_mut().filter(|_| tracked) else {
        return false;
    };
    let Some(id) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process(handle))
        .map(|process| process.shared[resource as usize])
    else {
        return false;
    };
    table.processes.iter().flatten().any(|process| {
        process.handle.pid != pid
            && process.shared[resource as usize] == id
            && matches!(
                process.state,
                ProcessState::Running | ProcessState::Stopped { .. }
            )
    })
}

/// Whether any process of the domain was ever cloned to share runtime
/// state (descriptors, filesystem context, signal handlers) with another:
/// until then no system call needs to keep any in step.
pub(crate) fn live_processes_share_state() -> bool {
    live_process_table_mut().is_some_and(|table| table.sharing)
}

/// Places process `pid` in the cgroup of generation `generation` (0: the
/// root), whose memory cgroup is `memcg`, and gives back the one it was in.
pub(crate) fn replace_live_process_cgroup(pid: u32, generation: u32, memcg: u16) -> Option<u32> {
    let table = live_process_table_mut()?;
    let process = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))?;
    process.memcg = memcg;
    Some(core::mem::replace(
        &mut process.cgroup_generation,
        generation,
    ))
}

/// Marks process `pid` as an OOM victim (`oom_victim`).
pub(crate) fn note_live_process_killed(pid: u32) {
    if let Some(table) = live_process_table_mut() {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.oom_victim = true;
        }
    }
}

/// Whether process `pid` is an OOM victim not yet gone.
pub(crate) fn live_process_killed(pid: u32) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table
            .handle_by_pid(pid)
            .and_then(|handle| table.process(handle))
            .is_some_and(|process| {
                process.oom_victim
                    && matches!(
                        process.state,
                        ProcessState::Running | ProcessState::Stopped { .. }
                    )
            })
    })
}

/// The memory cgroup process `pid`'s pages are charged to (0: not known).
pub(crate) fn live_process_memcg(pid: u32) -> Option<u16> {
    let table = live_process_table_mut()?;
    Some(table.process(table.handle_by_pid(pid)?)?.memcg)
}

/// The running or stopped processes charged to memory cgroups for which
/// `within` holds, with their `oom_score_adj`.
pub(crate) fn live_memcg_members(within: impl Fn(u16) -> bool) -> impl Iterator<Item = (u32, i32)> {
    live_process_table_mut()
        .into_iter()
        .flat_map(|table| table.processes.iter().flatten())
        .filter(move |process| {
            within(process.memcg)
                && matches!(
                    process.state,
                    ProcessState::Running | ProcessState::Stopped { .. }
                )
        })
        .map(|process| (process.handle.pid, i32::from(process.oom_score_adj)))
}

/// The signal process `pid`'s end sends its parent (clone's exit signal).
pub(crate) fn live_process_exit_signal(pid: u32) -> Option<u8> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.exit_signal)
}

/// Process `pid` ended while its parent reaped its children automatically.
pub(crate) fn set_live_process_reaped_by_parent(pid: u32) {
    if let Some(table) = live_process_table_mut() {
        if let Some(process) = table
            .handle_by_pid(pid)
            .and_then(|handle| table.process_mut(handle))
        {
            process.reaped_by_parent = true;
        }
    }
}

pub(crate) fn set_live_process_exit_signal(pid: u32, signal: u8) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.exit_signal = signal;
    true
}

/// Makes process `pid`, a child just cloned, the child of its parent's
/// parent instead (CLONE_PARENT): that process waits for it and gets its
/// exit signal.
pub(crate) fn adopt_live_process_by_grandparent(pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(grandparent) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process(handle))
        .and_then(|process| process.parent)
        .and_then(|parent| table.process(parent))
        .and_then(|parent| parent.parent)
    else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.cloned_by = process.parent;
    process.parent = Some(grandparent);
    true
}

/// Records that process `parent` is suspended in a vfork until `child`
/// executes or exits (0: no longer).
pub(crate) fn set_live_process_vfork_child(parent: u32, child: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(parent)
        .and_then(|handle| table.process_mut(handle))
    else {
        return false;
    };
    process.vfork_child = child;
    true
}

/// The vfork child process `parent` is suspended for, and whether it still
/// is: true until the child has executed or ended.
pub(crate) fn live_process_vfork_child(parent: u32) -> Option<(u32, bool)> {
    let table = live_process_table_mut()?;
    let child = table.process(table.handle_by_pid(parent)?)?.vfork_child;
    if child == 0 {
        return None;
    }
    let pending = table
        .handle_by_pid(child)
        .and_then(|handle| table.process(handle))
        .is_some_and(|process| {
            !process.executed
                && matches!(
                    process.state,
                    ProcessState::Running | ProcessState::Stopped { .. } | ProcessState::Preparing
                )
        });
    Some((child, pending))
}

pub(crate) fn replace_live_process_mapping(
    pid: u32,
    address: usize,
    expected: memory::FrameLease,
    replacement: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> bool {
    replace_live_process_mapping_inner(
        pid,
        address,
        expected,
        replacement,
        writable,
        executable,
        false,
    )
}

pub(crate) fn replace_live_process_mapping_for_exec(
    pid: u32,
    address: usize,
    expected: memory::FrameLease,
    replacement: memory::FrameLease,
    writable: bool,
    executable: bool,
) -> bool {
    replace_live_process_mapping_inner(
        pid,
        address,
        expected,
        replacement,
        writable,
        executable,
        true,
    )
}

fn replace_live_process_mapping_inner(
    pid: u32,
    address: usize,
    expected: memory::FrameLease,
    replacement: memory::FrameLease,
    writable: bool,
    executable: bool,
    private_exec_mapping: bool,
) -> bool {
    if writable && executable
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[replacement])
    {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    let Some(space) = process.address_space.as_mut() else {
        return false;
    };
    let Some(storage) = address_space_storage(usize::from(space.storage_slot)) else {
        return false;
    };
    let Some(mapping) = storage
        .mappings
        .get_mut(..space.mapping_count as usize)
        .into_iter()
        .flatten()
        .find(|mapping| mapping.address == address && mapping.frame == expected)
    else {
        return false;
    };
    mapping.frame = replacement;
    mapping.writable = writable;
    mapping.executable = executable;
    if private_exec_mapping {
        mapping.shared = false;
        mapping.dontfork = false;
    }
    true
}

/// Drops `pid`'s registered mapping at `address`, whose page its page
/// tables no longer hold; false if there was none.
pub(crate) fn remove_live_process_mapping(pid: u32, address: usize) -> bool {
    with_live_process_mappings(pid, |mappings| {
        let index = mappings
            .iter()
            .position(|mapping| mapping.address == address)?;
        mappings.remove(index);
        Some(())
    })
    .is_some()
}

/// Moves `pid`'s registered mapping at `from` to `to`, as its page-table
/// entry moved (exec moving the stack); false if there was none at `from`
/// or there is one at `to`.
pub(crate) fn move_live_process_mapping(pid: u32, from: usize, to: usize) -> bool {
    with_live_process_mappings(pid, |mappings| {
        if mappings.iter().any(|mapping| mapping.address == to) {
            return None;
        }
        mappings
            .iter_mut()
            .find(|mapping| mapping.address == from)?
            .address = to;
        Some(())
    })
    .is_some()
}

/// Runs `change` on `pid`'s registered mapping list, keeping its count in
/// step with the list.
fn with_live_process_mappings<T>(
    pid: u32,
    change: impl FnOnce(&mut Vec<cpu::LinuxActiveImageMapping>) -> Option<T>,
) -> Option<T> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let space = table.process_mut(handle)?.address_space.as_mut()?;
    let storage = address_space_storage(usize::from(space.storage_slot))?;
    if space.mapping_count as usize != storage.mappings.len() {
        return None;
    }
    let result = change(&mut storage.mappings)?;
    space.mapping_count = storage.mappings.len().try_into().ok()?;
    Some(result)
}

pub(crate) fn add_live_process_mapping(pid: u32, mapping: cpu::LinuxActiveImageMapping) -> bool {
    if mapping.address == 0
        || !mapping.address.is_multiple_of(PAGE_SIZE)
        || mapping.writable && mapping.executable
        || !(memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            || memory::frame_lease_is_runtime(mapping.frame))
    {
        return false;
    }
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process_mut(handle) else {
        return false;
    };
    let Some(space) = process.address_space.as_mut() else {
        return false;
    };
    let Some(storage) = address_space_storage(usize::from(space.storage_slot)) else {
        return false;
    };
    let count = space.mapping_count as usize;
    if count != storage.mappings.len()
        || storage
            .mappings
            .iter()
            .any(|existing| existing.address == mapping.address)
        || storage.mappings.try_reserve(1).is_err()
    {
        return false;
    }
    storage.mappings.push(mapping);
    space.mapping_count += 1;
    true
}

pub(crate) fn import_live_process_mapping_from_hardware(pid: u32, address: u64) -> bool {
    let Some(current) = address_space::current_linux_active_mapping(address) else {
        return false;
    };
    if let Some(existing) = live_process_mapping(pid, current.address) {
        return existing.frame == current.frame
            && existing.writable == current.writable
            && existing.executable == current.executable;
    }
    add_live_process_mapping(pid, current)
}

pub(crate) fn live_process_hierarchy_frame(pid: u32, index: usize) -> Option<memory::FrameLease> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    table
        .process(handle)?
        .address_space?
        .hierarchy()
        .get(index)
        .copied()
}

pub(crate) fn write_live_process_u32(pid: u32, address: u64, value: u32) -> bool {
    let Ok(address) = usize::try_from(address) else {
        return false;
    };
    let page = address & !(PAGE_SIZE - 1);
    let offset = address & (PAGE_SIZE - 1);
    if offset + size_of::<u32>() > PAGE_SIZE {
        return false;
    }
    let Some(mapping) = live_process_mapping(pid, page).filter(|mapping| mapping.writable) else {
        return false;
    };
    let Some(frame) = mapping.frame.direct_map_address() else {
        return false;
    };
    unsafe {
        (frame as *mut u8)
            .add(offset)
            .cast::<u32>()
            .write_unaligned(value)
    };
    true
}

pub(crate) fn copy_from_live_process(pid: u32, address: u64, output: &mut [u8]) -> bool {
    copy_live_process_bytes(pid, address, output.as_mut_ptr(), output.len(), false)
}

pub(crate) fn copy_to_live_process(pid: u32, address: u64, input: &[u8]) -> bool {
    copy_live_process_bytes(pid, address, input.as_ptr().cast_mut(), input.len(), true)
}

pub(crate) fn live_process_range_mapped(
    pid: u32,
    address: u64,
    length: usize,
    writable: bool,
) -> bool {
    let Ok(address) = usize::try_from(address) else {
        return false;
    };
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    if length == 0 {
        return true;
    }
    let mut page = address & !(PAGE_SIZE - 1);
    while page < end {
        if live_process_mapping(pid, page).is_none_or(|mapping| writable && !mapping.writable) {
            return false;
        }
        let Some(next) = page.checked_add(PAGE_SIZE) else {
            return false;
        };
        page = next;
    }
    true
}

fn copy_live_process_bytes(
    pid: u32,
    address: u64,
    buffer: *mut u8,
    buffer_length: usize,
    write: bool,
) -> bool {
    let Ok(mut address) = usize::try_from(address) else {
        return false;
    };
    let mut copied = 0;
    while copied < buffer_length {
        let page = address & !(PAGE_SIZE - 1);
        let offset = address & (PAGE_SIZE - 1);
        let length = (buffer_length - copied).min(PAGE_SIZE - offset);
        if write && !prepare_live_process_write(pid, page) {
            return false;
        }
        let Some(mapping) =
            live_process_mapping(pid, page).filter(|mapping| !write || mapping.writable)
        else {
            return false;
        };
        let Some(frame) = mapping.frame.direct_map_address() else {
            return false;
        };
        // SAFETY: the generation-bound process mapping owns a live page. The
        // bounds above keep each copy within that page, and syscall execution
        // serializes live-process table access on the current CPU.
        unsafe {
            let process = (frame as *mut u8).add(offset);
            if write {
                core::ptr::copy_nonoverlapping(buffer.add(copied), process, length);
            } else {
                core::ptr::copy_nonoverlapping(process, buffer.add(copied), length);
            }
        }
        copied += length;
        address += length;
    }
    true
}

pub(crate) fn prepare_live_process_write(pid: u32, address: usize) -> bool {
    let Some(mapping) =
        live_process_mapping(pid, address).filter(|mapping| mapping.writable && !mapping.shared)
    else {
        return live_process_mapping(pid, address).is_some_and(|mapping| mapping.writable);
    };
    let Some(root) = live_process_root(pid) else {
        return false;
    };
    if address_space::linux_cow_page_in_root(root, address as u64) != Some(mapping.frame) {
        return true;
    }
    let Some([replacement]) = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL) else {
        return false;
    };
    if !address_space::copy_linux_frame(mapping.frame, replacement)
        || !replace_live_process_mapping(
            pid,
            address,
            mapping.frame,
            replacement,
            true,
            mapping.executable,
        )
        || !address_space::replace_linux_cow_page_in_root(
            root,
            address as u64,
            mapping.frame,
            replacement,
            mapping.executable,
        )
    {
        let _ = replace_live_process_mapping(
            pid,
            address,
            replacement,
            mapping.frame,
            true,
            mapping.executable,
        );
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[replacement]);
        return false;
    }
    address_space::release_linux_private_page(mapping.frame)
}

pub(crate) fn live_process_root(pid: u32) -> Option<memory::FrameLease> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    Some(table.process(handle)?.address_space?.root())
}

/// Whether `visit` holds for the page-table root of some process of the
/// domain (zombies whose memory has not gone yet included).
pub(crate) fn any_live_process_root(mut visit: impl FnMut(u64) -> bool) -> bool {
    live_process_table_mut().is_some_and(|table| {
        table.processes.iter().flatten().any(|process| {
            [&process.address_space, &process.retiring_address_space]
                .into_iter()
                .flatten()
                .any(|space| visit(space.root().address()))
        })
    })
}

pub(crate) fn dispatch_live_init_with_return(value: u64) -> Option<LiveProcessDispatch> {
    let table = live_process_table_mut()?;
    let init = table.init?;
    if !table.set_return_value(init, value) {
        return None;
    }
    table.dispatch(init)
}

/// Sets the value a running process's interrupted system call returns.
pub(crate) fn set_live_process_return_value(pid: u32, value: u64) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    table
        .handle_by_pid(pid)
        .is_some_and(|handle| table.set_return_value(handle, value))
}

pub(crate) fn dispatch_live_process(pid: u32) -> Option<LiveProcessDispatch> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    table.dispatch(handle)
}

pub(crate) fn yield_live_process(pid: u32) -> Option<LiveProcessDispatch> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process(handle)?;
    let address_space = process.address_space.as_ref()?;
    let context = process.context?;
    let thread = process.scheduler_thread?;
    let scheduler_context = context.scheduler_context(address_space)?;
    let run_queue = scheduler::active_process_scheduler_workspace()?;
    let selected = run_queue.yield_current(thread, scheduler_context)?;
    let selected_handle = table
        .processes
        .iter()
        .flatten()
        .find(|process| process.scheduler_thread == Some(selected.handle()))?
        .handle;
    (table
        .process(selected_handle)?
        .context?
        .scheduler_context(table.process(selected_handle)?.address_space.as_ref()?)?
        == selected.context())
    .then(|| table.dispatch(selected_handle))
    .flatten()
}

#[inline(never)]
/// Says why `prepare_fork` refused: the parent's registry state, or a full
/// process table.
fn report_fork_preparation_failure(table: &ProcessTable, parent: ProcessHandle) {
    let used = table.processes.iter().flatten().count();
    let zombies = table
        .processes
        .iter()
        .flatten()
        .filter(|process| matches!(process.state, ProcessState::Zombie { .. }))
        .count();
    crate::serial_write("ginux: fork refused; parent pid/state/space/context/credentials: ");
    crate::serial_write_u64(u64::from(parent.pid));
    if let Some(process) = table.process(parent) {
        let state = match process.state {
            ProcessState::Preparing => 1,
            ProcessState::Running => 2,
            ProcessState::Stopped { .. } => 3,
            ProcessState::Exiting => 4,
            ProcessState::Zombie { .. } => 5,
        };
        for value in [
            state,
            u64::from(process.address_space.is_some()),
            u64::from(process.context.is_some()),
            u64::from(linux_user::credentials(process.user_namespace).is_some()),
        ] {
            crate::serial_write(" ");
            crate::serial_write_u64(value);
        }
    }
    crate::serial_write("; processes used/zombie/limit: ");
    for value in [used, zombies, PROCESS_LIMIT] {
        crate::serial_write_u64(value as u64);
        crate::serial_write(" ");
    }
    crate::serial_write("\r\n");
}

/// One line per process: pid, state (0 preparing, 1 running, 2 stopped,
/// 3 exiting, 4 zombie), parent, and whether it has an address space, a
/// retiring one and a run-queue thread.
fn write_process_table(table: &ProcessTable) {
    for process in table.processes.iter().flatten() {
        let state = match process.state {
            ProcessState::Preparing => 0,
            ProcessState::Running => 1,
            ProcessState::Stopped { .. } => 2,
            ProcessState::Exiting => 3,
            ProcessState::Zombie { .. } => 4,
        };
        crate::serial_write("ginux: process pid/state/parent/space/retiring/thread: ");
        for value in [
            u64::from(process.handle.pid),
            state,
            process.parent.map_or(0, |parent| u64::from(parent.pid)),
            u64::from(process.address_space.is_some()),
            u64::from(process.retiring_address_space.is_some()),
            u64::from(process.scheduler_thread.is_some()),
        ] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        crate::serial_write("\r\n");
    }
}

/// Creates a forked child of `parent_pid`. With `child_first` the run queue
/// switches to the child, which the caller runs before resuming the parent;
/// otherwise the parent stays current and the child waits, ready, for its
/// turn.
pub(crate) fn begin_live_fork(
    parent_pid: u32,
    eager_private_copy: bool,
    share_vm: bool,
    child_stack: Option<u64>,
    child_first: bool,
) -> Option<LiveProcessDispatch> {
    process_runtime()
        .fork_execution_stage
        .store(10, Ordering::Release);
    let Some(table) = live_process_table_mut() else {
        process_runtime()
            .fork_execution_stage
            .store(101, Ordering::Release);
        return None;
    };
    let Some(parent_handle) = table.handle_by_pid(parent_pid) else {
        process_runtime()
            .fork_execution_stage
            .store(102, Ordering::Release);
        return None;
    };
    let Some(parent) = table.process(parent_handle) else {
        process_runtime()
            .fork_execution_stage
            .store(103, Ordering::Release);
        return None;
    };
    let Some(parent_space) = parent.address_space.as_ref() else {
        process_runtime()
            .fork_execution_stage
            .store(104, Ordering::Release);
        return None;
    };
    let parent_space_owned = if share_vm {
        parent_space.hierarchy_is_owned()
    } else {
        parent_space.is_owned()
    };
    if parent.state != ProcessState::Running || !parent_space_owned {
        crate::serial_write("ginux: fork parent ownership pid/state/hierarchy/mappings: ");
        crate::serial_write_u64(u64::from(parent_pid));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(parent.state == ProcessState::Running));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(parent_space.hierarchy_is_owned()));
        crate::serial_write(" ");
        crate::serial_write_u64(parent_space.mappings().len() as u64);
        crate::serial_write("\r\n");
        for mapping in parent_space
            .mappings()
            .iter()
            .filter(|mapping| {
                !memory::frame_lease_is_runtime(mapping.frame)
                    && !memory::frames_owned_by(memory::FrameOwner::KERNEL, &[mapping.frame])
            })
            .take(4)
        {
            crate::serial_write("ginux: fork parent unowned mapping address/frame/generation: ");
            crate::serial_write_u64(mapping.address as u64);
            crate::serial_write(" ");
            crate::serial_write_u64(mapping.frame.address());
            crate::serial_write(" ");
            crate::serial_write_u64(u64::from(mapping.frame.generation()));
            crate::serial_write("\r\n");
        }
        process_runtime().fork_execution_stage.store(
            if parent.state != ProcessState::Running {
                105
            } else {
                106
            },
            Ordering::Release,
        );
        return None;
    }
    let hierarchy_count = parent_space.hierarchy().len();
    let private_count = (eager_private_copy && !share_vm).then(|| {
        parent_space
            .mappings()
            .iter()
            .filter(|mapping| !mapping.dontfork && mapping_requires_fork_copy(mapping))
            .count()
    });
    process_runtime()
        .fork_execution_stage
        .store(11, Ordering::Release);
    let Some(child_handle) = table.prepare_fork(parent_handle) else {
        report_fork_preparation_failure(table, parent_handle);
        return None;
    };
    process_runtime()
        .fork_execution_stage
        .store(111, Ordering::Release);
    let child_hierarchy = fork_frame_scratch(
        unsafe { &mut *process_scratch().fork_hierarchy_allocation_scratch.get() },
        hierarchy_count,
    );
    if !memory::allocate_frame_prefix_into(
        memory::FrameOwner::KERNEL,
        child_hierarchy,
        hierarchy_count,
    ) {
        let _ = table.abort_fork(child_handle);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(112, Ordering::Release);
    let private_count = private_count.unwrap_or(0);
    let child_pages = fork_frame_scratch(
        unsafe { &mut *process_scratch().fork_allocation_scratch.get() },
        private_count,
    );
    if private_count != 0
        && !memory::allocate_frame_prefix_into(
            memory::FrameOwner::KERNEL,
            child_pages,
            private_count,
        )
    {
        let _ = memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &child_hierarchy[..hierarchy_count],
        );
        let _ = table.abort_fork(child_handle);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(113, Ordering::Release);
    let published = table.commit_cloned_fork(
        child_handle,
        &child_hierarchy[..hierarchy_count],
        &child_pages[..private_count],
        share_vm,
    );
    if !published {
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(12, Ordering::Release);
    // fork returns the child's number in the parent's PID namespace.
    let parent_namespace = table
        .process(parent_handle)
        .map_or(0, |parent| parent.namespaces.pid);
    let child_seen = linux_namespace::pid_seen_from(
        cpu::current_linux_execution_instance(),
        parent_namespace,
        child_handle.pid,
    )
    .unwrap_or(child_handle.pid);
    if !table.set_return_value(parent_handle, u64::from(child_seen)) {
        process_runtime()
            .fork_execution_stage
            .store(121, Ordering::Release);
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    }
    if child_stack.is_some_and(|stack| !table.set_stack_pointer(child_handle, stack)) {
        process_runtime()
            .fork_execution_stage
            .store(122, Ordering::Release);
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    }
    let Some(parent_context) = table
        .process(parent_handle)
        .and_then(|process| process.context)
    else {
        process_runtime()
            .fork_execution_stage
            .store(123, Ordering::Release);
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    };
    let Some(parent_space) = table
        .process(parent_handle)
        .and_then(|process| process.address_space.as_ref())
    else {
        process_runtime()
            .fork_execution_stage
            .store(124, Ordering::Release);
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    };
    let Some(parent_scheduler_context) = parent_context.scheduler_context(parent_space) else {
        process_runtime()
            .fork_execution_stage
            .store(125, Ordering::Release);
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    };
    let Some(child) = table.process(child_handle) else {
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    };
    let (Some(child_space), Some(child_context)) = (child.address_space.as_ref(), child.context)
    else {
        process_runtime()
            .fork_execution_stage
            .store(126, Ordering::Release);
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    };
    let Some(child_scheduler_context) = child_context.scheduler_context(child_space) else {
        process_runtime()
            .fork_execution_stage
            .store(127, Ordering::Release);
        crate::serial_write("ginux: fork child context validation error/rip/rsp/fs/mappings: ");
        crate::serial_write_u64(u64::from(
            child_context.validation_error(child_space).unwrap_or(0),
        ));
        crate::serial_write(" ");
        crate::serial_write_u64(child_context.rip);
        crate::serial_write(" ");
        crate::serial_write_u64(child_context.rsp);
        crate::serial_write(" ");
        crate::serial_write_u64(child_context.fs_base);
        crate::serial_write(" ");
        crate::serial_write_u64(child_space.mappings().len() as u64);
        crate::serial_write("\r\n");
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    };
    process_runtime()
        .fork_execution_stage
        .store(13, Ordering::Release);
    let scheduler_domain = table.scheduler_domain();
    let nested = table
        .process(parent_handle)
        .is_some_and(|process| process.scheduler_thread.is_some());
    let run_queue = if nested {
        scheduler::active_process_scheduler_workspace()
    } else {
        scheduler::acquire_process_scheduler_workspace()
    }?;
    if !nested && !table.admit_to_scheduler(parent_handle, run_queue, scheduler_domain) {
        let _ = scheduler::release_process_scheduler_workspace();
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    }
    if !table.admit_to_scheduler(child_handle, run_queue, scheduler_domain) {
        if !nested {
            let _ = table.withdraw_from_scheduler(parent_handle, run_queue);
            let _ = scheduler::release_process_scheduler_workspace();
        }
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    }
    let scheduled = (|| {
        let parent_thread = table.process(parent_handle)?.scheduler_thread?;
        let child_thread = table.process(child_handle)?.scheduler_thread?;
        if !nested {
            let initial = run_queue.schedule_next()?;
            if initial.handle() != parent_thread || initial.context() != parent_scheduler_context {
                return None;
            }
        }
        if !child_first {
            return Some(());
        }
        let selected =
            run_queue.switch_current(parent_thread, parent_scheduler_context, child_thread)?;
        (selected.handle() == child_thread && selected.context() == child_scheduler_context)
            .then_some(())
    })()
    .is_some();
    if !scheduled {
        let _ = table.withdraw_from_scheduler(child_handle, run_queue);
        if !nested {
            let _ = table.withdraw_from_scheduler(parent_handle, run_queue);
            let _ = scheduler::release_process_scheduler_workspace();
        }
        let _ = discard_live_fork(table, parent_handle, child_handle);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(14, Ordering::Release);
    table.dispatch(child_handle)
}

fn discard_live_fork(
    table: &mut ProcessTable,
    parent_handle: ProcessHandle,
    child_handle: ProcessHandle,
) -> bool {
    let Some(child_space) = table
        .process(child_handle)
        .and_then(|process| process.address_space)
    else {
        return false;
    };
    let return_restored = table.set_return_value(parent_handle, 0);
    let Some(retiring) = table.begin_exit(child_handle, child_space) else {
        return false;
    };
    return_restored
        && release_live_process_address_space(retiring)
        && crate::linux_sysv_ipc::drop_process_attachments(child_handle.pid).is_ok()
        && table.exit_after_retiring_address_space_released(child_handle, retiring, 0)
        && table.wait(parent_handle, child_handle.pid)
            == Some(WaitResult {
                pid: child_handle.pid,
                status: 0,
            })
}

fn release_live_process_address_space(space: ProcessAddressSpace) -> bool {
    const RELEASE_BATCH_SIZE: usize = 64;
    let page_table_started = crate::arch::x86_64::timer::timestamp_counter();
    // Retiring the page tables releases each private page they map: pages no
    // other address space maps are freed, shared ones lose this mapping. The
    // tables are the record of what the process maps; its registry may be a
    // stale snapshot (a process killed by a signal has no final refresh).
    if !address_space::retire_linux_child_address_space(space.root()) {
        return false;
    }
    // A stale snapshot's hierarchy list may name tables already freed and
    // handed out again; the live tree's tables are freed already.
    if space.stale {
        return true;
    }
    if cfg!(feature = "linux-boot-profile") {
        crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(7, page_table_started);
    }
    let frame_release_started = crate::arch::x86_64::timer::timestamp_counter();
    let mut release_batch = [memory::FrameLease::EMPTY; RELEASE_BATCH_SIZE];
    let mut release_count = 0;
    for frame in space.hierarchy() {
        let ownership_started = crate::arch::x86_64::timer::timestamp_counter();
        let owned = memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame]);
        if cfg!(feature = "linux-boot-profile") {
            crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(
                10,
                ownership_started,
            );
        }
        if owned && !release_batch[..release_count].contains(frame) {
            release_batch[release_count] = *frame;
            release_count += 1;
            if release_count == release_batch.len() {
                let scrub_started = crate::arch::x86_64::timer::timestamp_counter();
                if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &release_batch) {
                    return false;
                }
                if cfg!(feature = "linux-boot-profile") {
                    crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(
                        11,
                        scrub_started,
                    );
                }
                release_count = 0;
            }
        }
    }
    let scrub_started = crate::arch::x86_64::timer::timestamp_counter();
    let released = release_count == 0
        || memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &release_batch[..release_count],
        );
    if cfg!(feature = "linux-boot-profile") && release_count != 0 {
        crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(11, scrub_started);
    }
    if cfg!(feature = "linux-boot-profile") {
        crate::arch::x86_64::cpu::linux_boot_profile_record_lifecycle_phase(
            8,
            frame_release_started,
        );
    }
    released
}

#[inline(never)]
/// Ends a process from another process's context: withdraws it from the
/// run queue, frees its address space and leaves it a zombie for its
/// parent. A domain's init uses this on exit for killed processes the
/// scheduler can no longer switch to, so they cannot run their own exit.
pub(crate) fn force_exit_live_process(pid: u32, status: u8) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(process) = table.process(handle) else {
        return false;
    };
    if process.state != ProcessState::Running {
        return false;
    }
    let Some(space) = process.address_space else {
        return false;
    };
    if process.scheduler_thread.is_some() {
        let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
            return false;
        };
        if !table.withdraw_from_scheduler(handle, run_queue) {
            return false;
        }
    }
    release_live_process_address_space(space)
        && crate::linux_sysv_ipc::drop_process_attachments(pid).is_ok()
        && table.exit_after_current_address_space_retired(handle, status)
}

pub(crate) fn complete_live_child_exit(pid: u32, status: u8) -> Option<LiveProcessDispatch> {
    process_runtime()
        .fork_execution_stage
        .store(15, Ordering::Release);
    let table = live_process_table_mut()?;
    process_runtime()
        .fork_execution_stage
        .store(151, Ordering::Release);
    let child_handle = table.handle_by_pid(pid)?;
    let child = table.process(child_handle)?;
    let parent_handle = child.cloned_by.or(child.parent)?;
    let parent = table.process(parent_handle)?;
    if child.state != ProcessState::Running {
        return None;
    }
    let parent_space = parent.address_space.as_ref()?;
    let parent_context = parent.context?;
    let child_space = child.address_space?;
    let child_context = child.context?;
    process_runtime()
        .fork_execution_stage
        .store(152, Ordering::Release);
    let parent_scheduler_context = parent_context.scheduler_context(parent_space)?;
    let child_scheduler_context = child_context.scheduler_context(&child_space)?;
    let parent_thread = parent.scheduler_thread?;
    let child_thread = child.scheduler_thread?;
    let run_queue = scheduler::active_process_scheduler_workspace()?;
    process_runtime()
        .fork_execution_stage
        .store(153, Ordering::Release);
    let resumed = run_queue.switch_current(child_thread, child_scheduler_context, parent_thread)?;
    process_runtime()
        .fork_execution_stage
        .store(154, Ordering::Release);
    if resumed.handle() != parent_thread || resumed.context() != parent_scheduler_context {
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(16, Ordering::Release);
    let nested = parent.parent.is_some();
    let standalone_transaction = table
        .processes
        .iter()
        .flatten()
        .filter(|process| process.scheduler_thread.is_some())
        .count()
        == 2;
    if !table.withdraw_from_scheduler(child_handle, run_queue) {
        return None;
    }
    if !nested
        && standalone_transaction
        && (!table.withdraw_from_scheduler(parent_handle, run_queue)
            || !scheduler::release_process_scheduler_workspace())
    {
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(161, Ordering::Release);
    if !release_live_process_address_space(child_space) {
        process_runtime()
            .fork_execution_stage
            .store(162, Ordering::Release);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(163, Ordering::Release);
    if crate::linux_sysv_ipc::drop_process_attachments(pid).is_err()
        || !table.exit_after_current_address_space_retired(child_handle, status)
    {
        process_runtime()
            .fork_execution_stage
            .store(164, Ordering::Release);
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(17, Ordering::Release);
    table.dispatch(parent_handle)
}

pub(crate) fn resume_live_parent_after_child_exec(pid: u32) -> Option<LiveProcessDispatch> {
    let table = live_process_table_mut()?;
    let child_handle = table.handle_by_pid(pid)?;
    let child = table.process(child_handle)?;
    let parent_handle = child.cloned_by.or(child.parent)?;
    let parent = table.process(parent_handle)?;
    let child_space = child.address_space.as_ref()?;
    let parent_space = parent.address_space.as_ref()?;
    let child_context = child.context?;
    let parent_context = parent.context?;
    let child_thread = child.scheduler_thread?;
    let parent_thread = parent.scheduler_thread?;
    let child_scheduler_context = child_context.scheduler_context(child_space)?;
    let parent_scheduler_context = parent_context.scheduler_context(parent_space)?;
    let run_queue = scheduler::active_process_scheduler_workspace()?;
    let resumed = run_queue.switch_current(child_thread, child_scheduler_context, parent_thread)?;
    if resumed.handle() != parent_thread || resumed.context() != parent_scheduler_context {
        return None;
    }
    table.dispatch(parent_handle)
}

/// Makes process `pid`, ready in the run queue, current on this CPU, which
/// runs no process: another CPU of the domain taking it to run.
pub(crate) fn claim_live_process(pid: u32) -> Option<LiveProcessDispatch> {
    let table = live_process_table_mut()?;
    let handle = table.handle_by_pid(pid)?;
    let process = table.process(handle)?;
    if process.state != ProcessState::Running {
        return None;
    }
    let space = process.address_space.as_ref()?;
    let context = process.context?.scheduler_context(space)?;
    let thread = process.scheduler_thread?;
    let run_queue = scheduler::active_process_scheduler_workspace()?;
    let claimed = run_queue.claim(thread)?;
    if claimed.context() != context {
        // Put it back as it was.
        let _ = run_queue.release(thread, claimed.context());
        return None;
    }
    table.dispatch(handle)
}

/// After the last other scheduled process of the domain ended: process
/// `pid`, current on this CPU and at the top of the tree, leaves the run queue
/// and the queue is released, as when no fork had been scheduled. True too
/// when other processes still run.
pub(crate) fn retire_lone_live_process(pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let lone = table
        .process(handle)
        .is_some_and(|process| process.parent.is_none() && process.scheduler_thread.is_some())
        && table
            .processes
            .iter()
            .flatten()
            .filter(|process| process.scheduler_thread.is_some())
            .count()
            == 1;
    if !lone {
        return true;
    }
    let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
        return false;
    };
    table.withdraw_from_scheduler(handle, run_queue)
        && scheduler::release_process_scheduler_workspace()
}

/// Puts process `pid`, current on this CPU, back among the ready ones with
/// the context its registry records, leaving the CPU with no process.
pub(crate) fn release_live_process(pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(process) = table
        .handle_by_pid(pid)
        .and_then(|handle| table.process(handle))
    else {
        return false;
    };
    let (Some(space), Some(context), Some(thread)) = (
        process.address_space.as_ref(),
        process.context,
        process.scheduler_thread,
    ) else {
        return false;
    };
    let (Some(context), Some(run_queue)) = (
        context.scheduler_context(space),
        scheduler::active_process_scheduler_workspace(),
    ) else {
        return false;
    };
    run_queue.release(thread, context)
}

/// The first live process after `after` (in pid order, wrapping) that is
/// ready in the run queue, may run on this CPU and `accept` takes, for a CPU
/// looking for one to run.
pub(crate) fn ready_live_process_after(
    after: u32,
    now: u64,
    mut accept: impl FnMut(u32) -> bool,
) -> Option<u32> {
    let table = live_process_table_mut()?;
    let run_queue = scheduler::active_process_scheduler_workspace()?;
    // A process asleep in a futex wait (`Process::is_asleep`) is passed
    // over here, before `accept`'s costlier tests and without a place in
    // the list: a thousand of them would otherwise be sorted and tested on
    // every pass.
    let mut ready: Vec<u32> = Vec::new();
    for process in table.processes.iter().flatten() {
        if process.state == ProcessState::Running
            && !process.is_asleep(now)
            && process
                .scheduler_thread
                .is_some_and(|thread| run_queue.is_ready_here(thread))
            && ready.try_reserve(1).is_ok()
        {
            ready.push(process.handle.pid);
        }
    }
    ready.sort_unstable();
    let start = ready.iter().position(|pid| *pid > after).unwrap_or(0);
    (0..ready.len())
        .map(|offset| ready[(start + offset) % ready.len()])
        .find(|pid| accept(*pid))
}

/// The ready process to run next in turn, after the one the last call
/// chose, that `accept` takes; it becomes the turn's.
pub(crate) fn next_ready_live_process(now: u64, accept: impl FnMut(u32) -> bool) -> Option<u32> {
    let after = live_process_table_mut()?.dispatch_cursor;
    let next = ready_live_process_after(after, now, accept)?;
    live_process_table_mut()?.dispatch_cursor = next;
    Some(next)
}

/// Ends process `pid`, current on this CPU, with `status`: it leaves the
/// run queue, its memory goes and it becomes a zombie for its parent to
/// reap, which runs elsewhere or waits. The CPU is left with no process.
pub(crate) fn complete_live_process_exit_detached(pid: u32, status: u8) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(handle) = table.handle_by_pid(pid) else {
        return false;
    };
    let Some(space) = table
        .process(handle)
        .filter(|process| process.state == ProcessState::Running)
        .and_then(|process| process.address_space)
    else {
        return false;
    };
    let Some(run_queue) = scheduler::active_process_scheduler_workspace() else {
        return false;
    };
    table.withdraw_from_scheduler(handle, run_queue)
        && release_live_process_address_space(space)
        && crate::linux_sysv_ipc::drop_process_attachments(pid).is_ok()
        && table.exit_after_current_address_space_retired(handle, status)
}

pub(crate) fn switch_live_process(from_pid: u32, to_pid: u32) -> Option<LiveProcessDispatch> {
    let table = live_process_table_mut()?;
    let from_handle = table.handle_by_pid(from_pid)?;
    let to_handle = table.handle_by_pid(to_pid)?;
    let from = table.process(from_handle)?;
    let to = table.process(to_handle)?;
    let from_space = from.address_space.as_ref()?;
    let to_space = to.address_space.as_ref()?;
    let from_context = from.context?;
    let to_context = to.context?;
    let from_thread = from.scheduler_thread?;
    let to_thread = to.scheduler_thread?;
    let from_scheduler_context = from_context.scheduler_context(from_space)?;
    let to_scheduler_context = to_context.scheduler_context(to_space)?;
    let run_queue = scheduler::active_process_scheduler_workspace()?;
    let resumed = run_queue.switch_current(from_thread, from_scheduler_context, to_thread)?;
    if resumed.handle() != to_thread || resumed.context() != to_scheduler_context {
        return None;
    }
    table.dispatch(to_handle)
}

/// `pid`'s SCHED_DEADLINE runtime, deadline and period.
pub(crate) fn live_process_deadline_parameters(pid: u32) -> Option<[u64; 3]> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some(process.deadline_parameters)
}

/// Sets `pid`'s SCHED_DEADLINE runtime, deadline and period.
pub(crate) fn set_live_process_deadline_parameters(pid: u32, parameters: [u64; 3]) -> bool {
    let Some(process) = live_process_table_mut().and_then(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process_mut(handle)
    }) else {
        return false;
    };
    process.deadline_parameters = parameters;
    true
}

/// Notes that `pid` holds `kib` KiB resident now (its ru_maxrss peak).
pub(crate) fn note_live_process_rss(pid: u32, kib: u64) {
    if let Some(process) = live_process_table_mut().and_then(|table| {
        let handle = table.handle_by_pid(pid)?;
        table.process_mut(handle)
    }) {
        process.maxrss_kib = process.maxrss_kib.max(kib);
    }
}

/// `pid`'s ru_maxrss peaks: its own and its waited children's, in KiB.
pub(crate) fn live_process_maxrss(pid: u32) -> Option<(u64, u64)> {
    let table = live_process_table_mut()?;
    let process = table.process(table.handle_by_pid(pid)?)?;
    Some((process.maxrss_kib, process.children_maxrss_kib))
}

/// A wait reaped `child` of `parent`: the child's peaks join the
/// parent's children's (RUSAGE_CHILDREN's ru_maxrss).
pub(crate) fn add_waited_child_maxrss(parent: u32, (own, children): (u64, u64)) {
    if let Some(process) = live_process_table_mut().and_then(|table| {
        let handle = table.handle_by_pid(parent)?;
        table.process_mut(handle)
    }) {
        process.children_maxrss_kib = process.children_maxrss_kib.max(own).max(children);
    }
}

pub(crate) fn wait_live_child(parent_pid: u32, child_pid: u32) -> Option<(u32, u8)> {
    let table = live_process_table_mut()?;
    let parent = table.handle_by_pid(parent_pid)?;
    table
        .wait(parent, child_pid)
        .map(|result| (result.pid, result.status))
}

pub(crate) fn live_child_wait_state(
    parent_pid: u32,
    child_pid: Option<u32>,
    events: ChildWaitEvents,
) -> Option<ChildWaitState> {
    let table = live_process_table_mut()?;
    let parent = table.handle_by_pid(parent_pid)?;
    table.child_wait_state_matching(
        parent,
        |process| {
            child_pid.is_none_or(|pid| process.handle.pid == pid) && events.scope.includes(process)
        },
        events.exited,
        events.stopped,
        events.continued,
    )
}

/// An exited child of `parent_pid` that ended while it reaped its
/// children automatically.
pub(crate) fn live_child_reaped_by_parent(parent_pid: u32) -> Option<u32> {
    let table = live_process_table_mut()?;
    let parent = table.handle_by_pid(parent_pid)?;
    match table.child_wait_state_matching(
        parent,
        |process| process.reaped_by_parent,
        true,
        false,
        false,
    )? {
        ChildWaitState::Exited { pid, .. } => Some(pid),
        _ => None,
    }
}

pub(crate) fn live_child_group_wait_state(
    parent_pid: u32,
    process_group: u32,
    events: ChildWaitEvents,
) -> Option<ChildWaitState> {
    let table = live_process_table_mut()?;
    let parent = table.handle_by_pid(parent_pid)?;
    table.child_wait_state_matching(
        parent,
        |process| process.process_group == process_group && events.scope.includes(process),
        events.exited,
        events.stopped,
        events.continued,
    )
}

/// Which child state changes a wait reports (WEXITED, WUNTRACED/WSTOPPED,
/// WCONTINUED).
#[derive(Clone, Copy)]
pub(crate) struct ChildWaitEvents {
    pub(crate) exited: bool,
    pub(crate) stopped: bool,
    pub(crate) continued: bool,
    pub(crate) scope: ChildScope,
}

/// Which children a wait looks at, by the signal they end with: those
/// ending with SIGCHLD (the default), the others ("clone" children,
/// __WCLONE) or all of them (__WALL).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildScope {
    Plain,
    Clone,
    All,
}

impl ChildScope {
    fn includes(self, process: &Process) -> bool {
        match self {
            Self::Plain => process.exit_signal == DEFAULT_EXIT_SIGNAL,
            Self::Clone => process.exit_signal != DEFAULT_EXIT_SIGNAL,
            Self::All => true,
        }
    }
}

pub(crate) fn consume_live_child_wait_event(parent_pid: u32, child_pid: u32) -> bool {
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(parent) = table.handle_by_pid(parent_pid) else {
        return false;
    };
    table.consume_wait_event(parent, child_pid)
}

#[inline(never)]
#[allow(dead_code)]
pub(crate) fn verify_live_fork_clone_transaction() -> bool {
    process_runtime()
        .fork_execution_stage
        .store(0, Ordering::Release);
    process_runtime()
        .fork_child_diagnostic
        .store(0, Ordering::Release);
    cpu::reset_process_child_execution_diagnostic();
    if process_runtime()
        .fork_child_executed
        .load(Ordering::Acquire)
    {
        verify_live_fork_clone_only_transaction()
    } else {
        verify_live_fork_clone_and_execution_transaction()
    }
}

#[inline(never)]
#[allow(dead_code)]
fn verify_live_fork_clone_and_execution_transaction() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Some(table) = live_process_table_mut() else {
        return false;
    };
    let Some(parent_handle) = table.init else {
        return false;
    };
    let Some(parent) = table.process(parent_handle) else {
        return false;
    };
    let (Some(parent_space), Some(parent_context)) = (parent.address_space, parent.context) else {
        return false;
    };
    let parent_user_namespace = parent.user_namespace;
    if parent.state != ProcessState::Running || !parent_space.is_valid() {
        return false;
    }
    let Some(child_handle) = table.prepare_fork(parent_handle) else {
        return false;
    };
    let hierarchy_count = parent_space.hierarchy().len();
    let mapping_count = parent_space.mappings().len();
    let private_count = parent_space
        .mappings()
        .iter()
        .filter(|mapping| mapping_requires_fork_copy(mapping))
        .count();
    let child_hierarchy = fork_frame_scratch(
        unsafe { &mut *process_scratch().fork_hierarchy_allocation_scratch.get() },
        hierarchy_count,
    );
    if !memory::allocate_frame_prefix_into(
        memory::FrameOwner::KERNEL,
        child_hierarchy,
        hierarchy_count,
    ) {
        let _ = table.abort_fork(child_handle);
        return false;
    }
    let child_pages = fork_frame_scratch(
        unsafe { &mut *process_scratch().fork_allocation_scratch.get() },
        private_count,
    );
    if !memory::allocate_frame_prefix_into(memory::FrameOwner::KERNEL, child_pages, private_count) {
        let _released = memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &child_hierarchy[..hierarchy_count],
        );
        let _aborted = table.abort_fork(child_handle);
        return false;
    }
    let published = table.commit_cloned_fork(
        child_handle,
        &child_hierarchy[..hierarchy_count],
        &child_pages[..private_count],
        false,
    );
    let hierarchy_extras_released = true;
    let page_extras_released = true;
    if !published {
        return false;
    }
    let Some(child) = table.process(child_handle) else {
        return false;
    };
    let Some(child_space) = child.address_space else {
        return false;
    };
    let child_valid = child.parent == Some(parent_handle)
        && child.user_namespace == parent_user_namespace
        && linux_user::credentials(child.user_namespace).is_some()
        && child.state == ProcessState::Running
        && child.context == Some(parent_context.fork_child())
        && child_space.is_valid()
        && !child_space.overlaps(&parent_space)
        && child_space.hierarchy().len() == hierarchy_count
        && child_space.mappings().len() == mapping_count
        && child_space
            .mappings()
            .iter()
            .zip(parent_space.mappings())
            .all(|(child, parent)| {
                child.address == parent.address
                    && child.writable == parent.writable
                    && child.executable == parent.executable
                    && child.shared == parent.shared
                    && (child.frame != parent.frame) == mapping_requires_fork_copy(parent)
                    && (!mapping_requires_fork_copy(parent)
                        || child
                            .frame
                            .direct_map_address()
                            .zip(parent.frame.direct_map_address())
                            .is_some_and(|(child_address, parent_address)| {
                                // SAFETY: Both leases remain owned by the process table for
                                // the duration of this comparison, and a direct-map lookup
                                // validates the complete physical page range.
                                unsafe {
                                    core::slice::from_raw_parts(
                                        child_address as *const u8,
                                        PAGE_SIZE,
                                    ) == core::slice::from_raw_parts(
                                        parent_address as *const u8,
                                        PAGE_SIZE,
                                    )
                                }
                            }))
            });
    let execute_child = child_valid
        && !process_runtime()
            .fork_child_executed
            .load(Ordering::Acquire);
    let exit_status = if execute_child {
        execute_cloned_live_child(table, parent_handle, child_handle)
    } else {
        child_valid.then_some(42)
    };
    let Some(retiring) = table.begin_exit(child_handle, child_space) else {
        return false;
    };
    let resources_released = retiring.scrub_and_release();
    let exited = resources_released && table.exit(child_handle, exit_status.unwrap_or(0));
    let waited = exited
        && table.wait(parent_handle, child_handle.pid)
            == Some(WaitResult {
                pid: child_handle.pid,
                status: 42,
            });
    let valid = child_valid
        && hierarchy_extras_released
        && page_extras_released
        && exit_status == Some(42)
        && waited
        && table.processes.iter().flatten().count() == 1
        && table.process(parent_handle).is_some_and(|process| {
            process.address_space == Some(parent_space)
                && process.context == Some(parent_context)
                && process.state == ProcessState::Running
                && process.scheduler_thread.is_none()
        })
        && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before);
    if valid && execute_child {
        process_runtime()
            .fork_child_executed
            .store(true, Ordering::Release);
    }
    valid
}

#[inline(never)]
#[allow(dead_code)]
fn verify_live_fork_clone_only_transaction() -> bool {
    macro_rules! reject {
        ($stage:expr) => {{
            process_runtime()
                .fork_execution_stage
                .store($stage, Ordering::Release);
            return false;
        }};
    }
    process_runtime()
        .fork_execution_stage
        .store(200, Ordering::Release);
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        reject!(201);
    };
    let Some(table) = live_process_table_mut() else {
        reject!(202);
    };
    let Some(parent_handle) = table.init else {
        reject!(203);
    };
    let Some(parent) = table.process(parent_handle) else {
        reject!(204);
    };
    let (Some(parent_space), Some(parent_context)) = (parent.address_space, parent.context) else {
        reject!(205);
    };
    let parent_user_namespace = parent.user_namespace;
    if parent.state != ProcessState::Running || !parent_space.is_valid() {
        crate::serial_write("ginux: clone-only parent state/owned/validated: ");
        crate::serial_write_u64(u64::from(parent.state == ProcessState::Running));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(parent_space.is_owned()));
        crate::serial_write(" ");
        crate::serial_write_u64(u64::from(
            address_space::validate_linux_process_address_space(
                parent_space.hierarchy(),
                parent_space.mappings(),
            ),
        ));
        crate::serial_write("\r\n");
        reject!(206);
    }
    let Some(child_handle) = table.prepare_fork(parent_handle) else {
        reject!(207);
    };
    let hierarchy_count = parent_space.hierarchy().len();
    let mapping_count = parent_space.mappings().len();
    let private_count = parent_space
        .mappings()
        .iter()
        .filter(|mapping| mapping_requires_fork_copy(mapping))
        .count();
    let child_hierarchy = fork_frame_scratch(
        unsafe { &mut *process_scratch().fork_hierarchy_allocation_scratch.get() },
        hierarchy_count,
    );
    if !memory::allocate_frame_prefix_into(
        memory::FrameOwner::KERNEL,
        child_hierarchy,
        hierarchy_count,
    ) {
        let _ = table.abort_fork(child_handle);
        reject!(208);
    }
    let child_pages = fork_frame_scratch(
        unsafe { &mut *process_scratch().fork_allocation_scratch.get() },
        private_count,
    );
    if !memory::allocate_frame_prefix_into(memory::FrameOwner::KERNEL, child_pages, private_count) {
        let _ = memory::scrub_and_release_frames(
            memory::FrameOwner::KERNEL,
            &child_hierarchy[..hierarchy_count],
        );
        let _ = table.abort_fork(child_handle);
        reject!(209);
    }
    let published = table.commit_cloned_fork(
        child_handle,
        &child_hierarchy[..hierarchy_count],
        &child_pages[..private_count],
        false,
    );
    let hierarchy_extras_released = true;
    let page_extras_released = true;
    if !published {
        reject!(210);
    }
    let Some(child) = table.process(child_handle) else {
        reject!(211);
    };
    let Some(child_space) = child.address_space else {
        reject!(212);
    };
    let child_valid = child.parent == Some(parent_handle)
        && child.user_namespace == parent_user_namespace
        && linux_user::credentials(child.user_namespace).is_some()
        && child.state == ProcessState::Running
        && child.context == Some(parent_context.fork_child())
        && child_space.is_valid()
        && !child_space.overlaps(&parent_space)
        && child_space.hierarchy().len() == hierarchy_count
        && child_space.mappings().len() == mapping_count
        && child_space
            .mappings()
            .iter()
            .zip(parent_space.mappings())
            .all(|(child, parent)| {
                child.address == parent.address
                    && child.writable == parent.writable
                    && child.executable == parent.executable
                    && child.shared == parent.shared
                    && (child.frame != parent.frame) == mapping_requires_fork_copy(parent)
                    && (!mapping_requires_fork_copy(parent)
                        || child
                            .frame
                            .direct_map_address()
                            .zip(parent.frame.direct_map_address())
                            .is_some_and(|(child_address, parent_address)| {
                                // SAFETY: Both live, generation-checked leases map
                                // complete pages for this serialized comparison.
                                unsafe {
                                    core::slice::from_raw_parts(
                                        child_address as *const u8,
                                        PAGE_SIZE,
                                    ) == core::slice::from_raw_parts(
                                        parent_address as *const u8,
                                        PAGE_SIZE,
                                    )
                                }
                            }))
            });
    let Some(retiring) = table.begin_exit(child_handle, child_space) else {
        reject!(213);
    };
    let resources_released = retiring.scrub_and_release();
    let exited = resources_released && table.exit(child_handle, 42);
    let waited = exited
        && table.wait(parent_handle, child_handle.pid)
            == Some(WaitResult {
                pid: child_handle.pid,
                status: 42,
            });
    let parent_restored = table.process(parent_handle).is_some_and(|process| {
        process.address_space == Some(parent_space)
            && process.context == Some(parent_context)
            && process.state == ProcessState::Running
            && process.scheduler_thread.is_none()
    });
    let frame_count_restored =
        memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before);
    let valid = child_valid
        && hierarchy_extras_released
        && page_extras_released
        && waited
        && table.processes.iter().flatten().count() == 1
        && parent_restored
        && frame_count_restored;
    if !valid {
        crate::serial_write("ginux: clone-only verification state: ");
        for state in [
            child_valid,
            resources_released,
            exited,
            waited,
            table.processes.iter().flatten().count() == 1,
            parent_restored,
            frame_count_restored,
        ] {
            crate::serial_write_u64(u64::from(state));
            crate::serial_write(" ");
        }
        crate::serial_write_u64(before as u64);
        crate::serial_write(" ");
        crate::serial_write_u64(
            memory::owner_live_frame_count(memory::FrameOwner::KERNEL).unwrap_or(usize::MAX) as u64,
        );
        crate::serial_write("\r\n");
    }
    valid
}

#[inline(never)]
#[allow(dead_code)]
fn execute_cloned_live_child(
    table: &mut ProcessTable,
    parent_handle: ProcessHandle,
    child_handle: ProcessHandle,
) -> Option<u8> {
    process_runtime()
        .fork_execution_stage
        .store(1, Ordering::Release);
    let parent = table.process(parent_handle)?;
    let parent_space = parent.address_space.as_ref()?;
    let parent_context = parent.context?;
    let parent_scheduler_context = parent_context.scheduler_context(parent_space)?;
    let child = table.process(child_handle)?;
    let child_space = child.address_space.as_ref()?;
    let child_context = child.context?;
    let child_scheduler_context = child_context.scheduler_context(child_space)?;
    let child_root = child_space.root();
    let child_code = child_space.mappings().iter().find(|mapping| {
        mapping.executable
            && child_context.rip >= mapping.address as u64
            && child_context.rip < mapping.address as u64 + PAGE_SIZE as u64
    })?;
    let parent_code = parent_space
        .mappings()
        .iter()
        .find(|mapping| mapping.address == child_code.address)?;
    let child_code_frame = child_code.frame;
    let parent_code_frame = parent_code.frame;
    let offset = usize::try_from(child_context.rip - child_code.address as u64).ok()?;
    if offset.checked_add(LIVE_PROCESS_CHILD_PROGRAM.len())? > PAGE_SIZE {
        return None;
    }
    let child_address = child_code_frame.direct_map_address()?.checked_add(offset)?;
    let parent_address = parent_code_frame
        .direct_map_address()?
        .checked_add(offset)?;
    let mut original_parent = [0_u8; LIVE_PROCESS_CHILD_PROGRAM.len()];
    // SAFETY: Both generation-checked pages remain exclusively owned by their
    // process records. The validated offset covers the complete bounded probe.
    unsafe {
        core::ptr::copy_nonoverlapping(
            parent_address as *const u8,
            original_parent.as_mut_ptr(),
            original_parent.len(),
        );
        core::ptr::copy_nonoverlapping(
            LIVE_PROCESS_CHILD_PROGRAM.as_ptr(),
            child_address as *mut u8,
            LIVE_PROCESS_CHILD_PROGRAM.len(),
        );
    }
    process_runtime()
        .fork_execution_stage
        .store(2, Ordering::Release);
    let run_queue = scheduler::acquire_process_scheduler_workspace()?;
    let scheduler_domain = table.scheduler_domain();
    if !table.admit_to_scheduler(parent_handle, run_queue, scheduler_domain) {
        let _ = scheduler::release_process_scheduler_workspace();
        return None;
    }
    if !table.admit_to_scheduler(child_handle, run_queue, scheduler_domain) {
        let _ = table.withdraw_from_scheduler(parent_handle, run_queue);
        let _ = scheduler::release_process_scheduler_workspace();
        return None;
    }
    process_runtime()
        .fork_execution_stage
        .store(3, Ordering::Release);
    let parent_thread = table.process(parent_handle)?.scheduler_thread?;
    let child_thread = table.process(child_handle)?.scheduler_thread?;
    let initial = run_queue.schedule_next();
    let selected_child = initial
        .and_then(|selected| {
            (selected.handle() == parent_thread && selected.context() == parent_scheduler_context)
                .then_some(())
        })
        .and_then(|()| run_queue.yield_current(parent_thread, parent_scheduler_context));
    let selected = selected_child.is_some_and(|selected| {
        selected.handle() == child_thread && selected.context() == child_scheduler_context
    });
    if selected {
        process_runtime()
            .fork_execution_stage
            .store(4, Ordering::Release);
    }
    cpu::reset_process_child_execution_diagnostic();
    let exit_status = selected
        .then(|| {
            address_space::execute_linux_process_child(
                child_root,
                child_context.rip,
                child_context.rsp,
                child_context.fs_base,
                child_context.general,
            )
        })
        .flatten();
    if exit_status == Some(42) {
        process_runtime()
            .fork_execution_stage
            .store(5, Ordering::Release);
    }
    let resumed_parent =
        exit_status.and_then(|_| run_queue.yield_current(child_thread, child_scheduler_context));
    let resumed = resumed_parent.is_some_and(|selected| {
        selected.handle() == parent_thread && selected.context() == parent_scheduler_context
    });
    if resumed {
        process_runtime()
            .fork_execution_stage
            .store(6, Ordering::Release);
    }
    let child_withdrawn = table.withdraw_from_scheduler(child_handle, run_queue);
    let parent_withdrawn = table.withdraw_from_scheduler(parent_handle, run_queue);
    let scheduler_released = scheduler::release_process_scheduler_workspace();
    let parent_unchanged = parent_code_frame
        .direct_map_address()
        .and_then(|address| address.checked_add(offset))
        .is_some_and(|address| {
            // SAFETY: The parent lease remains live and the bounded range was
            // validated above; the child executed under a disjoint root.
            unsafe {
                core::slice::from_raw_parts(address as *const u8, original_parent.len())
                    == original_parent
            }
        });
    if child_withdrawn && parent_withdrawn && parent_unchanged {
        process_runtime()
            .fork_execution_stage
            .store(7, Ordering::Release);
    }
    let valid = selected
        && resumed
        && child_withdrawn
        && parent_withdrawn
        && scheduler_released
        && parent_unchanged
        && exit_status == Some(42);
    let diagnostic = u32::from(selected)
        | (u32::from(exit_status.is_some()) << 1)
        | (u32::from(exit_status == Some(42)) << 2)
        | (u32::from(resumed) << 3)
        | (u32::from(child_withdrawn) << 4)
        | (u32::from(parent_withdrawn) << 5)
        | (u32::from(parent_unchanged) << 6)
        | (u32::from(scheduler_released) << 7);
    process_runtime()
        .fork_child_diagnostic
        .store(diagnostic, Ordering::Release);
    valid.then_some(42)
}

pub(crate) fn live_fork_execution_stage() -> u32 {
    process_runtime()
        .fork_execution_stage
        .load(Ordering::Acquire)
}

pub(crate) fn live_fork_child_diagnostic() -> u32 {
    process_runtime()
        .fork_child_diagnostic
        .load(Ordering::Acquire)
}

fn live_process_table_mut() -> Option<&'static mut ProcessTable> {
    let instance = active_process_instance()?;
    if !process_runtime().table_initialized[instance].load(Ordering::Acquire) {
        return None;
    }
    let table = unsafe {
        process_runtime()
            .tables
            .get()
            .cast::<ProcessTable>()
            .add(instance)
    };
    Some(unsafe { &mut *table })
}

fn current_process_instance() -> usize {
    cpu::current_container_slot().unwrap_or(HOST_PROCESS_INSTANCE)
}

/// The System V instance the current process's IPC namespace keeps its
/// objects in: the domain's own unless it made one.
pub(crate) fn current_ipc_instance() -> usize {
    let instance = current_process_instance();
    if !linux_namespace::any(linux_namespace::Kind::Ipc) {
        return instance;
    }
    live_process_namespaces(cpu::current_linux_process_id())
        .filter(|set| set.ipc != 0)
        .and_then(|set| {
            linux_namespace::ipc_instance(cpu::current_linux_execution_instance(), set.ipc)
        })
        .unwrap_or(instance)
}

fn active_process_instance() -> Option<usize> {
    let instance = usize::from(process_runtime().active_instance.load(Ordering::Acquire));
    (instance < PROCESS_INSTANCE_LIMIT).then_some(instance)
}

fn scrub_candidate_resources(
    hierarchy: &[memory::FrameLease],
    pages: &[memory::FrameLease],
) -> bool {
    if !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, hierarchy)
        || !memory::frame_leases_releasable(memory::FrameOwner::KERNEL, pages)
    {
        return false;
    }
    memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, hierarchy)
        && memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, pages)
}

pub(crate) fn copy_private_pages(
    source: &[memory::FrameLease],
    destination: &[memory::FrameLease],
) -> bool {
    if source.is_empty()
        || source.len() != destination.len()
        || !source.iter().all(|frame| {
            memory::frames_owned_by(memory::FrameOwner::KERNEL, &[*frame])
                || memory::frame_lease_is_runtime(*frame)
        })
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, destination)
        || source
            .iter()
            .enumerate()
            .any(|(index, frame)| source[..index].contains(frame) || destination.contains(frame))
        || destination
            .iter()
            .enumerate()
            .any(|(index, frame)| destination[..index].contains(frame))
    {
        return false;
    }
    if source.iter().zip(destination).any(|(source, destination)| {
        source.direct_map_address().is_none() || destination.direct_map_address().is_none()
    }) {
        return false;
    }
    for (source_frame, destination_frame) in source.iter().zip(destination) {
        let (Some(source_address), Some(destination_address)) = (
            source_frame.direct_map_address(),
            destination_frame.direct_map_address(),
        ) else {
            return false;
        };
        // SAFETY: all leases and direct-map extents were validated before the
        // first write, and source/destination frames are live and disjoint.
        unsafe {
            core::ptr::copy_nonoverlapping(
                source_address as *const u8,
                destination_address as *mut u8,
                PAGE_SIZE,
            );
        }
    }
    true
}

fn copy_validated_private_pages(
    mappings: &[cpu::LinuxActiveImageMapping],
    root: memory::FrameLease,
    source: &[memory::FrameLease],
    destination: &[memory::FrameLease],
) -> bool {
    if source.is_empty()
        || source.len() != destination.len()
        || mappings
            .iter()
            .filter(|mapping| mapping_requires_fork_copy(mapping))
            .count()
            != source.len()
        || !memory::frames_owned_by(memory::FrameOwner::KERNEL, destination)
    {
        return false;
    }
    for ((mapping, source_frame), destination_frame) in mappings
        .iter()
        .filter(|mapping| mapping_requires_fork_copy(mapping))
        .zip(source)
        .zip(destination)
    {
        let (Some(source_address), Some(destination_address)) = (
            source_frame.direct_map_address(),
            destination_frame.direct_map_address(),
        ) else {
            return false;
        };
        let Some(wipeonfork) = address_space::linux_mapping_wipe_on_fork(root, mapping.address)
        else {
            return false;
        };
        unsafe {
            if wipeonfork {
                core::ptr::write_bytes(destination_address as *mut u8, 0, PAGE_SIZE);
            } else {
                core::ptr::copy_nonoverlapping(
                    source_address as *const u8,
                    destination_address as *mut u8,
                    PAGE_SIZE,
                );
            }
        }
    }
    true
}

pub(crate) fn verify_private_page_copy_contract() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Some(source) =
        memory::allocate_frames::<FORK_PRIVATE_PAGE_LIMIT>(memory::FrameOwner::KERNEL)
    else {
        return false;
    };
    let Some(destination) =
        memory::allocate_frames::<FORK_PRIVATE_PAGE_LIMIT>(memory::FrameOwner::KERNEL)
    else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &source);
        return false;
    };

    let result = (|| {
        let source_addresses = source.map(memory::FrameLease::direct_map_address);
        let destination_addresses = destination.map(memory::FrameLease::direct_map_address);
        if source_addresses.iter().any(Option::is_none)
            || destination_addresses.iter().any(Option::is_none)
        {
            return None;
        }
        for (index, source_address) in source_addresses.iter().copied().enumerate() {
            let source_address = source_address?;
            // SAFETY: allocation returned a private zeroed frame with a valid
            // complete direct-map extent.
            unsafe {
                (source_address as *mut u8).write(0x41 + index as u8);
                (source_address as *mut u8)
                    .add(PAGE_SIZE - 1)
                    .write(0x61 + index as u8);
            }
        }

        let stale_generation = destination[0].generation().checked_add(1)?;
        let stale = memory::FrameLease::from_parts(destination[0].address(), stale_generation)?;
        let mut stale_destination = destination;
        stale_destination[0] = stale;
        if copy_private_pages(&source, &stale_destination)
            || copy_private_pages(&source, &source)
            || destination_addresses.into_iter().any(|address| {
                address.is_none_or(|address| unsafe {
                    core::slice::from_raw_parts(address as *const u8, PAGE_SIZE)
                        .iter()
                        .any(|byte| *byte != 0)
                })
            })
            || !copy_private_pages(&source, &destination)
        {
            return None;
        }

        for (source_address, destination_address) in source_addresses
            .iter()
            .copied()
            .zip(destination_addresses.iter().copied())
        {
            let source_address = source_address?;
            let destination_address = destination_address?;
            // SAFETY: both complete direct-map extents remain live.
            let (source_page, destination_page) = unsafe {
                (
                    core::slice::from_raw_parts(source_address as *const u8, PAGE_SIZE),
                    core::slice::from_raw_parts(destination_address as *const u8, PAGE_SIZE),
                )
            };
            if source_page != destination_page {
                return None;
            }
        }

        let first_source = source_addresses[0]?;
        let first_destination = destination_addresses[0]?;
        // SAFETY: the destination is a distinct, live, private frame.
        unsafe { (first_destination as *mut u8).write(0xff) };
        Some(unsafe { (first_source as *const u8).read() == 0x41 })
    })()
    .unwrap_or(false);

    let destination_released =
        memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &destination);
    let source_released = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &source);
    result
        && destination_released
        && source_released
        && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before)
}
