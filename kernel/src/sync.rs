use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

const INTERRUPT_FLAG: u64 = 1 << 9;
const CPU_SLOT_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct LockRank(u16);

impl LockRank {
    pub(crate) const PRIMITIVE_TEST_LOW: Self = Self(1);
    pub(crate) const PRIMITIVE_TEST_HIGH: Self = Self(2);
    pub(crate) const ARCHITECTURE: Self = Self(100);
    /// The mounts domains made; ranks below the heap so the table may grow
    /// while held, and above ARCHITECTURE, which system calls run under.
    pub(crate) const MOUNTS: Self = Self(105);
    /// The UTS, IPC, PID and time namespaces domains made; ranks below the
    /// heap so the table may grow while held.
    pub(crate) const NAMESPACES: Self = Self(107);
    /// Processes' memory areas; ranks just below the heap so the sets may
    /// grow while held, and above the socket, inotify and futex locks, under
    /// which a copy to user memory may look up a lazily reserved page.
    pub(crate) const MEMORY_AREAS: Self = Self(185);
    /// The executables behind /proc/PID/exe; ranks below the heap so the
    /// list may grow while held.
    pub(crate) const EXECUTABLES: Self = Self(110);
    /// Each domain's keys; ranks below the heap so the keys may grow while
    /// held.
    pub(crate) const KEYRINGS: Self = Self(115);
    /// Deadlines of timed waits set to restart; ranks below the heap so the
    /// list may grow while held.
    pub(crate) const RESTART_DEADLINES: Self = Self(120);
    /// The socket table with smoltcp and the network device under it; ranks
    /// below the heap so the table and socket buffers may grow while held.
    pub(crate) const SOCKETS: Self = Self(140);
    /// Open DRM render node files and dma-bufs; ranks below the heap so
    /// the tables may grow while held.
    pub(crate) const DRM: Self = Self(145);
    /// Each domain's loop devices and their opens; ranks below the heap so
    /// the tables may grow while held.
    pub(crate) const LOOP: Self = Self(150);
    /// Open /dev/kmsg readers; ranks below the heap so the table may grow
    /// while held.
    pub(crate) const KMSG: Self = Self(155);
    /// Pseudo-terminal pairs; ranks below the heap so their queues may grow
    /// while held, and below inotify, which removing a slave's node under it
    /// may reach.
    pub(crate) const PTYS: Self = Self(158);
    /// The record (fcntl) lock table; ranks below the heap so the table may
    /// grow while held.
    pub(crate) const RECORD_LOCKS: Self = Self(160);
    /// inotify instances, watches and queues; ranks below the heap so the
    /// queues may grow while held.
    pub(crate) const INOTIFY: Self = Self(165);
    /// fanotify groups, marks, queues and permission requests; ranks below
    /// the heap so the queues may grow while held.
    pub(crate) const FANOTIFY: Self = Self(166);
    /// io_uring rings and their registered buffers; ranks below the heap
    /// so the tables may grow while held.
    pub(crate) const IO_URING: Self = Self(167);
    /// The pool of Linux activation stacks; ranks below the heap so the
    /// pool may grow while held.
    pub(crate) const KERNEL_STACKS: Self = Self(170);
    /// Frames taken out of service (`memory_failure`); ranks below the
    /// heap so the list may grow while held.
    pub(crate) const MEMORY_FAILURE: Self = Self(175);
    pub(crate) const FUTEX_COORDINATION: Self = Self(180);
    /// The kernel heap refills from the frame allocator while holding its
    /// lock, so it ranks just below it.
    pub(crate) const KERNEL_HEAP: Self = Self(190);
    pub(crate) const PHYSICAL_MEMORY: Self = Self(200);
    pub(crate) const ADDRESS_SPACE: Self = Self(300);
    pub(crate) const SCHEDULER: Self = Self(400);
    pub(crate) const DOMAIN_PROCESS: Self = Self(500);
    pub(crate) const FILESYSTEM: Self = Self(600);
    pub(crate) const IPC_SIGNAL: Self = Self(700);
    pub(crate) const DEVICE_NETWORK: Self = Self(800);
    pub(crate) const DIAGNOSTICS: Self = Self(900);
}

static HELD_RANKS: [AtomicU16; CPU_SLOT_LIMIT] = [const { AtomicU16::new(0) }; CPU_SLOT_LIMIT];
static KERNEL_ENTRY_LOCK: KernelEntryLock = KernelEntryLock::new();

pub(crate) struct SpinLock<T> {
    next: AtomicU32,
    owner: AtomicU32,
    rank: LockRank,
    value: UnsafeCell<T>,
}

// SAFETY: the ticket lock grants one guard at a time and a guard exists only
// while the protected value is exclusively borrowed.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub(crate) const fn new(rank: LockRank, value: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            rank,
            value: UnsafeCell::new(value),
        }
    }

    pub(crate) fn lock(&self) -> SpinLockGuard<'_, T> {
        let previous_rank = enter_rank(self.rank);
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.owner.load(Ordering::Acquire) != ticket {
            spin_loop();
        }
        SpinLockGuard {
            lock: self,
            previous_rank,
            _not_send: PhantomData,
        }
    }

    pub(crate) fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let owner = self.owner.load(Ordering::Acquire);
        if self
            .next
            .compare_exchange(
                owner,
                owner.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        let previous_rank = enter_rank(self.rank);
        Some(SpinLockGuard {
            lock: self,
            previous_rank,
            _not_send: PhantomData,
        })
    }
}

pub(crate) struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
    previous_rank: u16,
    _not_send: PhantomData<*mut ()>,
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard owns the current ticket.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the guard owns the current ticket exclusively.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        leave_rank(self.lock.rank, self.previous_rank);
        self.lock.owner.fetch_add(1, Ordering::Release);
    }
}

pub(crate) struct IrqSpinLock<T>(SpinLock<T>);

unsafe impl<T: Send> Sync for IrqSpinLock<T> {}

impl<T> IrqSpinLock<T> {
    pub(crate) const fn new(rank: LockRank, value: T) -> Self {
        Self(SpinLock::new(rank, value))
    }

    pub(crate) fn lock(&self) -> IrqSpinLockGuard<'_, T> {
        let interrupt_state = disable_interrupts();
        let guard = self.0.lock();
        IrqSpinLockGuard {
            guard: ManuallyDrop::new(guard),
            interrupt_state,
        }
    }

    pub(crate) fn try_lock(&self) -> Option<IrqSpinLockGuard<'_, T>> {
        let interrupt_state = disable_interrupts();
        match self.0.try_lock() {
            Some(guard) => Some(IrqSpinLockGuard {
                guard: ManuallyDrop::new(guard),
                interrupt_state,
            }),
            None => {
                restore_interrupts(interrupt_state);
                None
            }
        }
    }
}

pub(crate) struct IrqSpinLockGuard<'a, T> {
    guard: ManuallyDrop<SpinLockGuard<'a, T>>,
    interrupt_state: InterruptState,
}

impl<T> Deref for IrqSpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for IrqSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for IrqSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        // Release the shared lock before reenabling local interrupts.
        unsafe { ManuallyDrop::drop(&mut self.guard) };
        restore_interrupts(self.interrupt_state);
    }
}

pub(crate) fn kernel_entry_lock() -> KernelEntryGuard {
    KERNEL_ENTRY_LOCK.lock()
}

/// The kernel-entry lock if no CPU holds or waits for it (`try_lock`).
pub(crate) fn kernel_entry_try_lock() -> Option<KernelEntryGuard> {
    KERNEL_ENTRY_LOCK.try_lock()
}

/// Called just before this CPU returns to a Linux process's user mode:
/// releases the kernel-entry lock, keeping its depth (the entries of the
/// calls this CPU is nested in) for `kernel_entry_return_from_user`. User
/// code never holds the lock, so other CPUs enter the kernel while it runs.
/// Interrupts must be off.
pub(crate) fn kernel_entry_leave_to_user() {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1 {
        return;
    }
    let depth = lock.depths[cpu].swap(0, Ordering::AcqRel);
    lock.user_depths[cpu].store(depth, Ordering::Release);
    lock.release(cpu);
}

/// Called when this CPU enters the kernel from a Linux process's user mode
/// by a system call or fault, which may return to the kernel instead of the
/// process: takes the lock back with the depth `kernel_entry_leave_to_user`
/// kept. Interrupts must be off.
pub(crate) fn kernel_entry_return_from_user() {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
        return;
    }
    let depth = lock.user_depths[cpu].swap(0, Ordering::AcqRel);
    if depth != 0 {
        lock.acquire(cpu, depth);
    }
}

/// Lets the CPUs waiting for the kernel-entry lock have it before this one
/// goes on: a scheduling loop that holds it round after round (resuming
/// parked calls that only check their waits again) never reaches user mode
/// or a halt, where it would let go, and starved the other CPUs' system
/// calls.
pub(crate) fn kernel_entry_yield() {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1
        || lock.next.load(Ordering::Acquire) == lock.owner.load(Ordering::Acquire).wrapping_add(1)
    {
        return;
    }
    kernel_entry_leave_to_user();
    spin_loop();
    kernel_entry_return_from_user();
}

/// This CPU's depth in the kernel-entry lock: 0 unless it holds it.
pub(crate) fn kernel_entry_depth() -> u32 {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if lock.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
        lock.depths[cpu].load(Ordering::Acquire)
    } else {
        0
    }
}

/// Takes `count` entries off this CPU's depth: those of a system call that
/// parks (see `cpu::activation`), whose frames wait on its own stack while
/// this CPU goes on with others. The CPU keeps at least its own entry.
pub(crate) fn kernel_entry_detach(count: u32) {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if count == 0 {
        return;
    }
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1
        || lock.depths[cpu].load(Ordering::Acquire) <= count
    {
        crate::serial_write("ginux: kernel-entry detach cpu/owner/depth/count: ");
        for value in [
            cpu as u64,
            u64::from(lock.cpu_owner.load(Ordering::Acquire)),
            u64::from(lock.depths[cpu].load(Ordering::Acquire)),
            u64::from(count),
        ] {
            crate::serial_write_u64(value);
            crate::serial_write(" ");
        }
        crate::serial_write("\r\n");
        crate::kernel_fail("ginux: invalid kernel-entry detach\r\n");
    }
    lock.depths[cpu].fetch_sub(count, Ordering::AcqRel);
}

/// Adds the `count` entries a parked system call took off its CPU's depth
/// (`kernel_entry_detach`) to this CPU's, which resumes the call, on
/// whichever CPU that is.
pub(crate) fn kernel_entry_attach(count: u32) {
    let lock = &KERNEL_ENTRY_LOCK;
    let cpu = cpu_slot();
    if count == 0 {
        return;
    }
    if lock.cpu_owner.load(Ordering::Acquire) != cpu as u16 + 1 {
        crate::kernel_fail("ginux: invalid kernel-entry attach\r\n");
    }
    lock.depths[cpu].fetch_add(count, Ordering::AcqRel);
}

/// The kernel-entry lock serializes kernel work across CPUs. It is
/// recursive per CPU: each entry on the owning CPU adds to its depth, and
/// the lock is released when the depth returns to zero, whichever entry
/// leaves last. Entries need not leave in the order they came: a system
/// call parked on its own stack (see `cpu::activation`) takes its entries
/// with it and gives them to the CPU that resumes it. A CPU running user
/// code holds no lock: it releases it on the way out to user mode and takes
/// it back, at the same depth, when a system call or fault comes in.
struct KernelEntryLock {
    next: AtomicU32,
    owner: AtomicU32,
    cpu_owner: AtomicU16,
    depths: [AtomicU32; CPU_SLOT_LIMIT],
    /// Each CPU's depth while it runs user code.
    user_depths: [AtomicU32; CPU_SLOT_LIMIT],
    /// The lock rank each CPU held before it took the lock, put back when
    /// it releases it.
    previous_ranks: [AtomicU16; CPU_SLOT_LIMIT],
}

impl KernelEntryLock {
    const fn new() -> Self {
        Self {
            next: AtomicU32::new(0),
            owner: AtomicU32::new(0),
            cpu_owner: AtomicU16::new(0),
            depths: [const { AtomicU32::new(0) }; CPU_SLOT_LIMIT],
            user_depths: [const { AtomicU32::new(0) }; CPU_SLOT_LIMIT],
            previous_ranks: [const { AtomicU16::new(0) }; CPU_SLOT_LIMIT],
        }
    }

    fn lock(&'static self) -> KernelEntryGuard {
        let interrupt_state = disable_interrupts();
        let cpu = cpu_slot();
        if self.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
            let previous = self.depths[cpu].fetch_add(1, Ordering::AcqRel);
            if previous == 0 {
                crate::kernel_fail("ginux: invalid recursive kernel-entry depth\r\n");
            }
            return KernelEntryGuard {
                lock: self,
                interrupt_state,
            };
        }
        self.acquire(cpu, 1);
        KernelEntryGuard {
            lock: self,
            interrupt_state,
        }
    }

    /// Takes the lock only when no CPU holds or waits for it, else None with
    /// this CPU's interrupts as they were. The ticket serves waiters in
    /// order, so an idle CPU that merely looks for work must not queue: three
    /// idle application processors re-queuing after every look would take
    /// three turns in four from the owner CPU's system calls.
    fn try_lock(&'static self) -> Option<KernelEntryGuard> {
        let interrupt_state = disable_interrupts();
        let cpu = cpu_slot();
        if self.cpu_owner.load(Ordering::Acquire) == cpu as u16 + 1 {
            let previous = self.depths[cpu].fetch_add(1, Ordering::AcqRel);
            if previous == 0 {
                crate::kernel_fail("ginux: invalid recursive kernel-entry depth\r\n");
            }
            return Some(KernelEntryGuard {
                lock: self,
                interrupt_state,
            });
        }
        // Free when the next ticket to hand out is the owner's: take exactly
        // that ticket, or nothing.
        let ticket = self.owner.load(Ordering::Acquire);
        if self
            .next
            .compare_exchange(
                ticket,
                ticket.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            restore_interrupts(interrupt_state);
            return None;
        }
        let previous_rank = enter_rank(LockRank::ARCHITECTURE);
        self.previous_ranks[cpu].store(previous_rank, Ordering::Release);
        self.depths[cpu].store(1, Ordering::Release);
        self.cpu_owner.store(cpu as u16 + 1, Ordering::Release);
        Some(KernelEntryGuard {
            lock: self,
            interrupt_state,
        })
    }

    /// Takes the lock for `cpu` (this CPU) at `depth`.
    fn acquire(&'static self, cpu: usize, depth: u32) {
        let previous_rank = enter_rank(LockRank::ARCHITECTURE);
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        if self.owner.load(Ordering::Acquire) != ticket {
            let started = crate::arch::x86_64::timer::timestamp_counter();
            while self.owner.load(Ordering::Acquire) != ticket {
                spin_loop();
            }
            crate::cpu_time::add_lock_wait(
                crate::arch::x86_64::timer::timestamp_counter().saturating_sub(started),
            );
        }
        self.previous_ranks[cpu].store(previous_rank, Ordering::Release);
        self.depths[cpu].store(depth, Ordering::Release);
        self.cpu_owner.store(cpu as u16 + 1, Ordering::Release);
    }

    /// Lets the next CPU in; `cpu` (this CPU) held the lock.
    fn release(&'static self, cpu: usize) {
        self.cpu_owner.store(0, Ordering::Release);
        leave_rank(
            LockRank::ARCHITECTURE,
            self.previous_ranks[cpu].load(Ordering::Acquire),
        );
        self.owner.fetch_add(1, Ordering::Release);
    }
}

/// An entry into the kernel-entry lock. It counts against the CPU that drops
/// it, which for a parked system call resumed elsewhere is not the one that
/// took it.
pub(crate) struct KernelEntryGuard {
    lock: &'static KernelEntryLock,
    interrupt_state: InterruptState,
}

impl Drop for KernelEntryGuard {
    fn drop(&mut self) {
        let cpu = cpu_slot();
        let previous = self.lock.depths[cpu].fetch_sub(1, Ordering::AcqRel);
        if previous == 0 {
            crate::kernel_fail("ginux: invalid kernel-entry release depth\r\n");
        }
        // The last entry on this CPU to leave releases the lock.
        if previous == 1 {
            self.lock.release(cpu);
        }
        restore_interrupts(self.interrupt_state);
    }
}

#[derive(Clone, Copy)]
struct InterruptState {
    enabled: bool,
}

fn disable_interrupts() -> InterruptState {
    let flags: u64;
    // SAFETY: reading RFLAGS and clearing IF are privileged, local-CPU
    // operations. The matching guard restores the prior IF state.
    unsafe {
        asm!("pushfq", "pop {}", out(reg) flags, options(preserves_flags));
        asm!("cli", options(nomem, nostack));
    }
    InterruptState {
        enabled: flags & INTERRUPT_FLAG != 0,
    }
}

fn restore_interrupts(state: InterruptState) {
    if state.enabled {
        // SAFETY: this restores the IF state captured by disable_interrupts
        // after the shared lock has been released.
        unsafe { asm!("sti", options(nomem, nostack)) };
    }
}

/// The slot of the executing CPU in the per-CPU lock tables: its index from
/// the per-CPU entry state once that is installed, and its initial APIC ID
/// before. The entry state is found through the GS base, which hypervisors
/// let the guest read directly, whereas CPUID always exits to the hypervisor;
/// every lock acquisition and release asks for the slot, so CPUID here made
/// allocator-heavy system calls tens of times slower under KVM.
fn cpu_slot() -> usize {
    crate::arch::x86_64::cpu::current_cpu_index_checked()
        .unwrap_or_else(|| usize::from((__cpuid(1).ebx >> 24) as u8))
}

/// Whether this CPU may take a lock of `rank` now: it holds none ranked
/// at or above it.
pub(crate) fn rank_available(rank: LockRank) -> bool {
    HELD_RANKS[cpu_slot()].load(Ordering::Acquire) < rank.0
}

fn enter_rank(rank: LockRank) -> u16 {
    crate::linux_profile::count_lock(rank.0);
    let held = &HELD_RANKS[cpu_slot()];
    let previous = held.load(Ordering::Acquire);
    if previous >= rank.0 {
        crate::kernel_fail("ginux: synchronization lock-order violation\r\n");
    }
    held.store(rank.0, Ordering::Release);
    previous
}

fn leave_rank(rank: LockRank, previous: u16) {
    let held = &HELD_RANKS[cpu_slot()];
    if held.load(Ordering::Acquire) != rank.0 {
        crate::kernel_fail("ginux: synchronization unlock-order violation\r\n");
    }
    held.store(previous, Ordering::Release);
}

pub(crate) fn verify_primitives() -> bool {
    static LOW: IrqSpinLock<u64> = IrqSpinLock::new(LockRank::PRIMITIVE_TEST_LOW, 0);
    static HIGH: IrqSpinLock<u64> = IrqSpinLock::new(LockRank::PRIMITIVE_TEST_HIGH, 0);
    static PLAIN: SpinLock<u64> = SpinLock::new(LockRank::ARCHITECTURE, 0);

    let ranks = [
        LockRank::ARCHITECTURE,
        LockRank::PHYSICAL_MEMORY,
        LockRank::ADDRESS_SPACE,
        LockRank::SCHEDULER,
        LockRank::DOMAIN_PROCESS,
        LockRank::FILESYSTEM,
        LockRank::IPC_SIGNAL,
        LockRank::DEVICE_NETWORK,
        LockRank::DIAGNOSTICS,
    ];
    if !ranks.windows(2).all(|pair| pair[0] < pair[1]) {
        return false;
    }

    {
        let mut low = LOW.lock();
        *low = 1;
        let mut high = HIGH.lock();
        *high = *low + 1;
    }
    {
        let Some(mut plain) = PLAIN.try_lock() else {
            return false;
        };
        *plain = 3;
    }
    let Some(low) = LOW.try_lock() else {
        return false;
    };
    *low == 1 && *HIGH.lock() == 2 && *PLAIN.lock() == 3
}
