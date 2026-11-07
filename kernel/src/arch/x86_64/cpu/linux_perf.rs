//! perf_event_open(2) for a machine without a PMU, as Linux runs in a VM
//! that has none: the software events count (the clocks PERF_COUNT_SW_CPU_
//! CLOCK and TASK_CLOCK in nanoseconds of a task's CPU time, or of wall
//! time for a CPU-wide event; page faults, minor and major ones, context
//! switches and CPU migrations from `cpu_time`'s task events; alignment
//! and emulation faults, which x86 has none of, and the dummy event stay
//! 0), and every hardware, cache, raw, tracepoint or breakpoint event is
//! ENOENT (no PMU for it). The attribute checks, the perf_event_paranoid
//! levels and the errors come in Linux's order (kernel/events/core.c).
//!
//! An event counts processes of its own domain only: a task the caller
//! may look into (ptrace_may_access), or, for a CPU-wide event (paranoid 0
//! or CAP_PERFMON), the domain's processes, whatever the CPU named.
//!
//! An event is an object descriptor ([`LINUX_PERF_CLASS`]): read gives
//! its value in its read format (one event or its group), ioctl enables,
//! disables and resets it (or its group), and prctl's
//! PR_TASK_PERF_EVENTS_ENABLE/DISABLE do so for every event the caller
//! made. Not here: sampling (no PMU interrupt here: EOPNOTSUPP) and the
//! mmap ring buffer (ENODEV). Counts are per process (Linux counts the
//! thread pid names), and an inherited event adds the target's children
//! that it waited for, where Linux adds every child as it exits.

use super::*;
use crate::sync::{LockRank, SpinLock};

/// The object class of perf event descriptors in the socket table.
pub(super) const LINUX_PERF_CLASS: u8 = 20;

const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
const PERF_COUNT_SW_PAGE_FAULTS: u64 = 2;
const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;
const PERF_COUNT_SW_PAGE_FAULTS_MIN: u64 = 5;
const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u64 = 6;
/// PERF_COUNT_SW_MAX: the software events Linux 6.12 knows.
const PERF_COUNT_SW_MAX: u64 = 12;

/// perf_event_attr: the first published size, and the size Linux 6.12 has.
const PERF_ATTR_SIZE_VER0: u32 = 64;
const PERF_ATTR_SIZE: usize = 136;

const PERF_FLAG_FD_NO_GROUP: u64 = 1;
const PERF_FLAG_FD_OUTPUT: u64 = 2;
const PERF_FLAG_PID_CGROUP: u64 = 4;
const PERF_FLAG_FD_CLOEXEC: u64 = 8;

const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 2;
const PERF_FORMAT_ID: u64 = 4;
const PERF_FORMAT_GROUP: u64 = 8;
const PERF_FORMAT_LOST: u64 = 16;
const PERF_FORMAT_MAX: u64 = 1 << 5;

const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;
const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;
const PERF_SAMPLE_WEIGHT: u64 = 1 << 14;
const PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
const PERF_SAMPLE_CGROUP: u64 = 1 << 21;
const PERF_SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;
const PERF_SAMPLE_MAX: u64 = 1 << 25;

/// The attribute's flag bits that matter here.
const ATTR_DISABLED: u64 = 1 << 0;
const ATTR_INHERIT: u64 = 1 << 1;
const ATTR_EXCLUDE_USER: u64 = 1 << 4;
const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const ATTR_FREQ: u64 = 1 << 10;
const ATTR_ENABLE_ON_EXEC: u64 = 1 << 12;
const ATTR_USE_CLOCKID: u64 = 1 << 25;
const ATTR_NAMESPACES: u64 = 1 << 28;
const ATTR_INHERIT_THREAD: u64 = 1 << 35;
const ATTR_REMOVE_ON_EXEC: u64 = 1 << 36;
const ATTR_SIGTRAP: u64 = 1 << 37;
/// __reserved_1: bits past sigtrap.
const ATTR_RESERVED: u64 = !((1 << 38) - 1);

const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;
const PERF_EVENT_IOC_REFRESH: u32 = 0x2402;
const PERF_EVENT_IOC_RESET: u32 = 0x2403;
const PERF_EVENT_IOC_PERIOD: u32 = 0x4008_2404;
const PERF_EVENT_IOC_SET_OUTPUT: u32 = 0x2405;
const PERF_EVENT_IOC_SET_FILTER: u32 = 0x4008_2406;
const PERF_EVENT_IOC_ID: u32 = 0x8008_2407;
const PERF_EVENT_IOC_SET_BPF: u32 = 0x4004_2408;
const PERF_EVENT_IOC_PAUSE_OUTPUT: u32 = 0x4004_2409;
const PERF_EVENT_IOC_QUERY_BPF: u32 = 0xc008_240a;
const PERF_EVENT_IOC_MODIFY_ATTRIBUTES: u32 = 0x4008_240b;
/// PERF_IOC_FLAG_GROUP: the ioctl acts on the event's whole group.
const PERF_IOC_FLAG_GROUP: u64 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Counter {
    /// Nanoseconds of the target's CPU time, or of wall time for a
    /// CPU-wide event (cpu-clock and task-clock alike here).
    Clock,
    /// A `cpu_time::TaskEvent` of the target, or of the domain's
    /// processes for a CPU-wide event.
    Task(crate::cpu_time::TaskEvent),
    /// What never happens here: alignment and emulation faults (none on
    /// x86), the dummy event, BPF output and cgroup switches.
    Zero,
}

#[derive(Clone, Copy)]
struct Event {
    instance: usize,
    /// The process that made it (prctl's PR_TASK_PERF_EVENTS_*).
    owner: u32,
    /// The process it counts, or None for a CPU-wide event.
    target: Option<u32>,
    counter: Counter,
    read_format: u64,
    inherit: bool,
    /// exclude_user and exclude_kernel: a task event counts only where it
    /// happens, as Linux's perf_exclude_event does (page faults come from
    /// user mode, context switches and migrations happen in the kernel).
    exclude_user: bool,
    exclude_kernel: bool,
    /// Its group leader's slot (its own for a leader).
    leader: usize,
    /// The id PERF_EVENT_IOC_ID and PERF_FORMAT_ID report.
    id: u64,
    enabled: bool,
    /// What it counted while enabled before, and the counter's source
    /// value when it was last enabled or reset.
    counted: u64,
    base: u64,
    /// Nanoseconds enabled before, and the clock when last enabled.
    enabled_time: u64,
    enabled_at: u64,
    /// The largest value read, so a count never goes back (a target that
    /// exited keeps what it counted).
    last: u64,
}

struct Events {
    slots: Vec<Option<Event>>,
    next_id: u64,
}

static PERF_EVENTS: SpinLock<Events> = SpinLock::new(
    LockRank::PERF_EVENTS,
    Events {
        slots: Vec::new(),
        next_id: 1,
    },
);

/// The monotonic clock, in nanoseconds.
fn linux_perf_now() -> u64 {
    linux_elapsed_nanoseconds().unwrap_or(0)
}

/// What `event`'s counter reads now (its source, before the enabled
/// intervals are taken).
fn linux_perf_source(event: &Event) -> u64 {
    let now = timer::timestamp_counter();
    match (event.counter, event.target) {
        (Counter::Zero, _) => return 0,
        (Counter::Task(kind), _)
            if match kind {
                crate::cpu_time::TaskEvent::ContextSwitch
                | crate::cpu_time::TaskEvent::Migration => event.exclude_kernel,
                _ => event.exclude_user,
            } =>
        {
            return 0
        }
        (Counter::Task(kind), Some(pid)) => {
            return linux_process::live_process_task_events(
                pid,
                pid == current_linux_process_pid(),
                event.inherit,
                now,
            )
            .map_or(0, |events| events[kind as usize]);
        }
        (Counter::Task(kind), None) => {
            return linux_process::live_domain_task_events(current_linux_process_pid(), now)
                [kind as usize];
        }
        (Counter::Clock, None) => return linux_perf_now(),
        (Counter::Clock, Some(_)) => {}
    }
    let Some(pid) = event.target else {
        return linux_perf_now();
    };
    let own = if pid == current_linux_process_pid() {
        linux_current_process_cpu_cycles()
    } else {
        linux_process_cpu_cycles(pid)
    };
    let children = if event.inherit {
        linux_process::live_process_children_cpu_times(pid)
            .map_or(0, |(user, system)| user.saturating_add(system))
    } else {
        0
    };
    linux_cycles_nanoseconds(own.saturating_add(children))
}

/// `event`'s value, time enabled and time running now.
fn linux_perf_value(event: &Event, source: u64, now: u64) -> (u64, u64) {
    let mut value = event.counted;
    let mut time = event.enabled_time;
    if event.enabled {
        value = value.saturating_add(source.saturating_sub(event.base));
        time = time.saturating_add(now.saturating_sub(event.enabled_at));
    }
    (value.max(event.last), time)
}

fn linux_perf_enable(event: &mut Event, source: u64, now: u64) {
    if !event.enabled {
        event.enabled = true;
        event.base = source;
        event.enabled_at = now;
    }
}

fn linux_perf_disable(event: &mut Event, source: u64, now: u64) {
    if event.enabled {
        let (value, time) = linux_perf_value(event, source, now);
        event.counted = value;
        event.enabled_time = time;
        event.enabled = false;
    }
}

/// The event slot descriptor `descriptor` names.
fn linux_perf_slot(descriptor: u64) -> Option<usize> {
    match linux_object_descriptor(descriptor)? {
        (LINUX_PERF_CLASS, id) => usize::try_from(id).ok(),
        _ => None,
    }
}

/// Whether the caller holds CAP_PERFMON (or CAP_SYS_ADMIN, which implies
/// it): Linux's perfmon_capable.
fn linux_perfmon_capable() -> bool {
    linux_has_capability(ginux_credentials::capability::PERFMON)
        || linux_has_capability(ginux_credentials::capability::SYS_ADMIN)
}

fn linux_perf_paranoid() -> i64 {
    linux_proc_sysctl_value(b"sys/kernel/perf_event_paranoid").unwrap_or(2)
}

/// perf_allow_kernel: counting kernel work takes perf_event_paranoid of
/// at most 1, or CAP_PERFMON.
fn linux_perf_allow_kernel() -> Result<(), u64> {
    if linux_perf_paranoid() > 1 && !linux_perfmon_capable() {
        Err(LINUX_EACCES)
    } else {
        Ok(())
    }
}

/// The attribute at `address` (perf_copy_attr): its size 0 is the first
/// version's; a size below that or above a page, or a longer struct whose
/// tail is not zero, is E2BIG, with the size this kernel takes written back.
fn linux_perf_copy_attr(address: u64) -> Result<[u8; PERF_ATTR_SIZE], u64> {
    let mut size = [0_u8; 4];
    if !copy_from_linux_user(address.wrapping_add(4), &mut size) {
        return Err(LINUX_EFAULT);
    }
    let mut size = u32::from_ne_bytes(size);
    if size == 0 {
        size = PERF_ATTR_SIZE_VER0;
    }
    let too_big = || {
        let _ = copy_to_linux_user(
            address.wrapping_add(4),
            &(PERF_ATTR_SIZE as u32).to_ne_bytes(),
        );
        LINUX_E2BIG
    };
    if size < PERF_ATTR_SIZE_VER0 || size as usize > PAGE_SIZE {
        return Err(too_big());
    }
    let size = size as usize;
    let mut attr = [0_u8; PERF_ATTR_SIZE];
    if !copy_from_linux_user(address, &mut attr[..size.min(PERF_ATTR_SIZE)]) {
        return Err(LINUX_EFAULT);
    }
    if size > PERF_ATTR_SIZE {
        let mut rest = [0_u8; PAGE_SIZE];
        let rest = &mut rest[..size - PERF_ATTR_SIZE];
        if !copy_from_linux_user(address + PERF_ATTR_SIZE as u64, rest) {
            return Err(LINUX_EFAULT);
        }
        if rest.iter().any(|byte| *byte != 0) {
            return Err(too_big());
        }
    }
    attr[4..8].copy_from_slice(&(size as u32).to_ne_bytes());
    Ok(attr)
}

fn attr_u64(attr: &[u8; PERF_ATTR_SIZE], offset: usize) -> u64 {
    u64::from_ne_bytes(attr[offset..offset + 8].try_into().unwrap())
}

fn attr_u32(attr: &[u8; PERF_ATTR_SIZE], offset: usize) -> u32 {
    u32::from_ne_bytes(attr[offset..offset + 4].try_into().unwrap())
}

pub(super) fn linux_perf_event_open(
    attr_address: u64,
    pid: u64,
    cpu: u64,
    group: u64,
    flags: u64,
) -> u64 {
    match linux_perf_open(attr_address, pid as i32, cpu as i32, group as i32, flags) {
        Ok(descriptor) => descriptor,
        Err(error) => error,
    }
}

fn linux_perf_open(
    attr_address: u64,
    pid: i32,
    cpu: i32,
    group: i32,
    flags: u64,
) -> Result<u64, u64> {
    if flags
        & !(PERF_FLAG_FD_NO_GROUP
            | PERF_FLAG_FD_OUTPUT
            | PERF_FLAG_PID_CGROUP
            | PERF_FLAG_FD_CLOEXEC)
        != 0
    {
        return Err(LINUX_EINVAL);
    }
    let attr = linux_perf_copy_attr(attr_address)?;
    let kind = attr_u32(&attr, 0);
    let config = attr_u64(&attr, 8);
    let sample_period = attr_u64(&attr, 16);
    let sample_type = attr_u64(&attr, 24);
    let read_format = attr_u64(&attr, 32);
    let bits = attr_u64(&attr, 40);
    let sample_stack_user = attr_u32(&attr, 88);
    let clockid = attr_u32(&attr, 92) as i32;
    let reserved_2 = u16::from_ne_bytes([attr[110], attr[111]]);
    let reserved_3 = attr_u32(&attr, 116);
    if bits & ATTR_RESERVED != 0 || reserved_2 != 0 || reserved_3 != 0 {
        return Err(LINUX_EINVAL);
    }
    if sample_type & !(PERF_SAMPLE_MAX - 1) != 0 || read_format & !(PERF_FORMAT_MAX - 1) != 0 {
        return Err(LINUX_EINVAL);
    }
    if sample_type & PERF_SAMPLE_STACK_USER != 0
        && (sample_stack_user >= u32::from(u16::MAX) || !sample_stack_user.is_multiple_of(8))
    {
        return Err(LINUX_EINVAL);
    }
    if sample_type & PERF_SAMPLE_CGROUP != 0
        || sample_type & PERF_SAMPLE_WEIGHT != 0 && sample_type & PERF_SAMPLE_WEIGHT_STRUCT != 0
    {
        return Err(LINUX_EINVAL);
    }
    if bits & ATTR_INHERIT == 0 && bits & ATTR_INHERIT_THREAD != 0
        || bits & ATTR_REMOVE_ON_EXEC != 0 && bits & ATTR_ENABLE_ON_EXEC != 0
        || bits & ATTR_SIGTRAP != 0 && bits & ATTR_REMOVE_ON_EXEC == 0
    {
        return Err(LINUX_EINVAL);
    }
    if bits & ATTR_EXCLUDE_KERNEL == 0 {
        linux_perf_allow_kernel()?;
    }
    if bits & ATTR_NAMESPACES != 0 && !linux_perfmon_capable() {
        return Err(LINUX_EACCES);
    }
    let freq = bits & ATTR_FREQ != 0;
    if freq {
        let rate = linux_proc_sysctl_value(b"sys/kernel/perf_event_max_sample_rate")
            .and_then(|rate| u64::try_from(rate).ok())
            .unwrap_or(100_000);
        if sample_period > rate {
            return Err(LINUX_EINVAL);
        }
    } else if sample_period & 1 << 63 != 0 {
        return Err(LINUX_EINVAL);
    }
    if sample_type & PERF_SAMPLE_PHYS_ADDR != 0 {
        linux_perf_allow_kernel()?;
    }
    if flags & PERF_FLAG_PID_CGROUP != 0 && (pid == -1 || cpu == -1) {
        return Err(LINUX_EINVAL);
    }
    // The group leader descriptor; cgroups are not perf targets here, so a
    // cgroup descriptor in pid is not a perf one either (EBADF).
    let leader = if group != -1 {
        Some(linux_perf_slot(group as u32 as u64).ok_or(LINUX_EBADF)?)
    } else {
        None
    };
    if flags & PERF_FLAG_PID_CGROUP != 0 {
        return Err(LINUX_EBADF);
    }
    let caller = current_linux_process_pid();
    let target = linux_perf_target(pid)?;
    let instance = linux_execution_instance();
    let leader_event = leader.and_then(|slot| {
        PERF_EVENTS
            .lock()
            .slots
            .get(slot)
            .copied()
            .flatten()
            .filter(|event| event.instance == instance)
    });
    if leader.is_some() && leader_event.is_none() {
        return Err(LINUX_EBADF);
    }
    let inherit = bits & ATTR_INHERIT != 0;
    if target.is_some() && leader_event.is_some_and(|leader| leader.inherit != inherit) {
        return Err(LINUX_EINVAL);
    }
    // perf_event_alloc: a CPU past the last one, or none for an event on
    // no task.
    let cpus = linux_available_cpu_count() as u32;
    if cpu as u32 >= cpus && (target.is_none() || cpu != -1) {
        return Err(LINUX_EINVAL);
    }
    // perf_init_event: only the software clocks and the dummy event have a
    // PMU here.
    let counter = linux_perf_counter(kind, config)?;
    if sample_type & PERF_SAMPLE_BRANCH_STACK != 0 {
        return Err(LINUX_EOPNOTSUPP);
    }
    // A sampling event needs an overflow interrupt, which nothing here
    // raises (PERF_PMU_CAP_NO_INTERRUPT).
    if sample_period != 0 || freq {
        return Err(LINUX_EOPNOTSUPP);
    }
    if bits & ATTR_USE_CLOCKID != 0 && !matches!(clockid, 0 | 1 | 4 | 7 | 11) {
        return Err(LINUX_EINVAL);
    }
    match target {
        Some(pid) if pid != caller && !linux_ptrace_access_permitted(pid) => {
            return Err(LINUX_EACCES)
        }
        // perf_allow_cpu: a CPU-wide event takes perf_event_paranoid of at
        // most 0, or CAP_PERFMON.
        None if linux_perf_paranoid() > 0 && !linux_perfmon_capable() => return Err(LINUX_EACCES),
        _ => {}
    }
    // The group descriptor must be a group leader's, on the same task.
    if let (Some(slot), Some(leader)) = (leader, leader_event) {
        if leader.leader != slot || leader.target != target {
            return Err(LINUX_EINVAL);
        }
    }
    let mut event = Event {
        instance,
        owner: caller,
        target,
        counter,
        read_format,
        inherit,
        exclude_user: bits & ATTR_EXCLUDE_USER != 0,
        exclude_kernel: bits & ATTR_EXCLUDE_KERNEL != 0,
        leader: 0,
        id: 0,
        enabled: false,
        counted: 0,
        base: 0,
        enabled_time: 0,
        enabled_at: 0,
        last: 0,
    };
    // enable_on_exec waits for an exec, which is not counted here: such an
    // event starts disabled, as Linux's does until then.
    if bits & (ATTR_DISABLED | ATTR_ENABLE_ON_EXEC) == 0 {
        let source = linux_perf_source(&event);
        linux_perf_enable(&mut event, source, linux_perf_now());
    }
    let slot = {
        let mut events = PERF_EVENTS.lock();
        event.id = events.next_id;
        events.next_id += 1;
        let slot = match events.slots.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                events.slots.try_reserve(1).map_err(|_| LINUX_ENOMEM)?;
                events.slots.push(None);
                events.slots.len() - 1
            }
        };
        event.leader = leader.unwrap_or(slot);
        events.slots[slot] = Some(event);
        slot
    };
    let descriptor_flags = if flags & PERF_FLAG_FD_CLOEXEC != 0 {
        LINUX_O_CLOEXEC
    } else {
        0
    };
    let descriptor = linux_open_object(LINUX_PERF_CLASS, slot as u64, descriptor_flags);
    if descriptor >= LINUX_RETURN_TO_KERNEL {
        PERF_EVENTS.lock().slots[slot] = None;
        return Err(descriptor);
    }
    Ok(descriptor)
}

/// The process `pid` names for an event (perf_event_open's
/// find_lively_task_by_vpid): none for -1 (a CPU-wide event), the caller
/// for 0, else a living process of the caller's domain: ESRCH for any
/// other pid, which includes every process of another domain (each
/// domain's process table holds its own processes only).
fn linux_perf_target(pid: i32) -> Result<Option<u32>, u64> {
    match pid {
        -1 => Ok(None),
        0 => Ok(Some(current_linux_process_pid())),
        pid => {
            let pid = u32::try_from(pid).map_err(|_| LINUX_ESRCH)?;
            linux_process::live_process_status(pid)
                .filter(|status| status.state.is_running())
                .ok_or(LINUX_ESRCH)?;
            Ok(Some(pid))
        }
    }
}

/// What an event of `kind` and `config` counts (perf_init_event): the
/// software events only. Every other kind, hardware, cache, raw,
/// tracepoint, breakpoint or a dynamic PMU's, has no PMU here (ENOENT).
fn linux_perf_counter(kind: u32, config: u64) -> Result<Counter, u64> {
    use crate::cpu_time::TaskEvent;
    Ok(match (kind, config) {
        (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK | PERF_COUNT_SW_TASK_CLOCK) => Counter::Clock,
        (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS) => Counter::Task(TaskEvent::PageFault),
        (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES) => {
            Counter::Task(TaskEvent::ContextSwitch)
        }
        (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS) => Counter::Task(TaskEvent::Migration),
        (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN) => Counter::Task(TaskEvent::MinorFault),
        (PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ) => Counter::Task(TaskEvent::MajorFault),
        (PERF_TYPE_SOFTWARE, config) if config < PERF_COUNT_SW_MAX => Counter::Zero,
        _ => return Err(LINUX_ENOENT),
    })
}

/// The boot check of what perf_event_open refuses: every event that is
/// not a software one (hardware, cache, raw, tracepoint, breakpoint, a
/// dynamic PMU's) whatever its config, a software config past the last,
/// any pid that is not a living process of the caller's domain (another
/// domain's processes included), bad flags and an unreadable attribute.
pub(super) fn verify_linux_perf_event_open() -> bool {
    const PERF_TYPE_HARDWARE: u32 = 0;
    const PERF_TYPE_TRACEPOINT: u32 = 2;
    const PERF_TYPE_HW_CACHE: u32 = 3;
    const PERF_TYPE_RAW: u32 = 4;
    const PERF_TYPE_BREAKPOINT: u32 = 5;
    let refused_kinds = [
        PERF_TYPE_HARDWARE,
        PERF_TYPE_TRACEPOINT,
        PERF_TYPE_HW_CACHE,
        PERF_TYPE_RAW,
        PERF_TYPE_BREAKPOINT,
        6,
        u32::MAX,
    ];
    let configs = [0, 1, PERF_COUNT_SW_CPU_MIGRATIONS, u64::MAX];
    let hardware_refused = refused_kinds.iter().all(|kind| {
        configs
            .iter()
            .all(|config| linux_perf_counter(*kind, *config) == Err(LINUX_ENOENT))
    });
    let software_bounded = linux_perf_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_MAX)
        == Err(LINUX_ENOENT)
        && linux_perf_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK) == Ok(Counter::Clock);
    let foreign_refused = [i32::MAX, -2, i32::MIN]
        .into_iter()
        .all(|pid| linux_perf_target(pid) == Err(LINUX_ESRCH));
    hardware_refused
        && software_bounded
        && foreign_refused
        && linux_perf_event_open(0, 0, u64::MAX, u64::MAX, 0x10) == LINUX_EINVAL
        && linux_perf_event_open(0, 0, u64::MAX, u64::MAX, 0) == LINUX_EFAULT
}

/// Drops event `id` after its last descriptor closed; its group's
/// members then lead themselves.
pub(super) fn linux_perf_release(class: u8, id: u64) {
    if class != LINUX_PERF_CLASS {
        return;
    }
    let Ok(slot) = usize::try_from(id) else {
        return;
    };
    let mut events = PERF_EVENTS.lock();
    if let Some(entry) = events.slots.get_mut(slot) {
        *entry = None;
    }
    for (index, event) in events.slots.iter_mut().enumerate() {
        if let Some(event) = event.as_mut().filter(|event| event.leader == slot) {
            event.leader = index;
        }
    }
}

/// The slots of `slot`'s group, leader first, when `group` (or just
/// `slot`).
fn linux_perf_members(events: &Events, slot: usize, group: bool) -> Vec<usize> {
    let mut members = Vec::new();
    let Some(event) = events.slots.get(slot).copied().flatten() else {
        return members;
    };
    if !group {
        members.push(slot);
        return members;
    }
    let leader = event.leader;
    members.push(leader);
    members.extend(
        events
            .slots
            .iter()
            .enumerate()
            .filter(|(index, member)| {
                *index != leader && member.is_some_and(|member| member.leader == leader)
            })
            .map(|(index, _)| index),
    );
    members
}

/// read(2) of an event descriptor: the value (and the times, id and lost
/// count its read format asks for), or its group's with PERF_FORMAT_GROUP;
/// a buffer too small is ENOSPC.
pub(super) fn linux_perf_read(descriptor: u64, address: u64, count: u64) -> u64 {
    let Some(slot) = linux_perf_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let (event, members) = {
        let events = PERF_EVENTS.lock();
        let Some(event) = events.slots.get(slot).copied().flatten() else {
            return LINUX_EBADF;
        };
        let group = event.read_format & PERF_FORMAT_GROUP != 0;
        let members: Vec<(usize, Event)> = linux_perf_members(&events, slot, group)
            .into_iter()
            .filter_map(|member| events.slots[member].map(|event| (member, event)))
            .collect();
        (event, members)
    };
    let format = event.read_format;
    let now = linux_perf_now();
    let values: Vec<(usize, u64, u64, u64)> = members
        .iter()
        .map(|(member, event)| {
            let (value, time) = linux_perf_value(event, linux_perf_source(event), now);
            (*member, value, time, event.id)
        })
        .collect();
    {
        let mut events = PERF_EVENTS.lock();
        for (member, value, _, _) in &values {
            if let Some(event) = events.slots.get_mut(*member).and_then(Option::as_mut) {
                event.last = event.last.max(*value);
            }
        }
    }
    let mut words: Vec<u64> = Vec::new();
    let times = |words: &mut Vec<u64>, time: u64| {
        if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
            words.push(time);
        }
        if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
            words.push(time);
        }
    };
    let entry = |words: &mut Vec<u64>, value: u64, id: u64| {
        words.push(value);
        if format & PERF_FORMAT_ID != 0 {
            words.push(id);
        }
        if format & PERF_FORMAT_LOST != 0 {
            words.push(0);
        }
    };
    if format & PERF_FORMAT_GROUP != 0 {
        words.push(values.len() as u64);
        times(&mut words, values.first().map_or(0, |value| value.2));
        for (_, value, _, id) in &values {
            entry(&mut words, *value, *id);
        }
    } else {
        let (_, value, time, id) = values.first().copied().unwrap_or((slot, 0, 0, event.id));
        words.push(value);
        times(&mut words, time);
        if format & PERF_FORMAT_ID != 0 {
            words.push(id);
        }
        if format & PERF_FORMAT_LOST != 0 {
            words.push(0);
        }
    }
    let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_ne_bytes()).collect();
    if count < bytes.len() as u64 {
        return LINUX_ENOSPC;
    }
    if copy_to_linux_user(address, &bytes) {
        bytes.len() as u64
    } else {
        LINUX_EFAULT
    }
}

/// Enables, disables or resets the events of `slots`.
fn linux_perf_apply(slots: &[usize], action: u32) {
    let now = linux_perf_now();
    let sources: Vec<(usize, u64)> = {
        let events = PERF_EVENTS.lock();
        slots
            .iter()
            .filter_map(|slot| {
                events
                    .slots
                    .get(*slot)
                    .copied()
                    .flatten()
                    .map(|event| (*slot, event))
            })
            .map(|(slot, event)| (slot, linux_perf_source(&event)))
            .collect()
    };
    let mut events = PERF_EVENTS.lock();
    for (slot, source) in sources {
        let Some(event) = events.slots.get_mut(slot).and_then(Option::as_mut) else {
            continue;
        };
        match action {
            PERF_EVENT_IOC_ENABLE => linux_perf_enable(event, source, now),
            PERF_EVENT_IOC_DISABLE => linux_perf_disable(event, source, now),
            _ => {
                event.counted = 0;
                event.last = 0;
                event.base = source;
            }
        }
    }
}

/// ioctl(2) on an event descriptor.
pub(super) fn linux_perf_ioctl(descriptor: u64, command: u64, argument: u64) -> u64 {
    let Some(slot) = linux_perf_slot(descriptor) else {
        return LINUX_EBADF;
    };
    let command = command as u32;
    match command {
        PERF_EVENT_IOC_ENABLE | PERF_EVENT_IOC_DISABLE | PERF_EVENT_IOC_RESET => {
            let members = linux_perf_members(
                &PERF_EVENTS.lock(),
                slot,
                argument & PERF_IOC_FLAG_GROUP != 0,
            );
            linux_perf_apply(&members, command);
            0
        }
        PERF_EVENT_IOC_ID => {
            let Some(id) = PERF_EVENTS
                .lock()
                .slots
                .get(slot)
                .copied()
                .flatten()
                .map(|event| event.id)
            else {
                return LINUX_EBADF;
            };
            if copy_to_linux_user(argument, &id.to_ne_bytes()) {
                0
            } else {
                LINUX_EFAULT
            }
        }
        // Not a sampling event, no ring buffer, no filters, BPF or
        // breakpoint attributes: what Linux refuses for such an event.
        PERF_EVENT_IOC_REFRESH
        | PERF_EVENT_IOC_PERIOD
        | PERF_EVENT_IOC_SET_OUTPUT
        | PERF_EVENT_IOC_SET_FILTER
        | PERF_EVENT_IOC_SET_BPF
        | PERF_EVENT_IOC_PAUSE_OUTPUT
        | PERF_EVENT_IOC_QUERY_BPF
        | PERF_EVENT_IOC_MODIFY_ATTRIBUTES => LINUX_EINVAL,
        _ => LINUX_ENOTTY,
    }
}

/// prctl's PR_TASK_PERF_EVENTS_ENABLE (`enable`) and
/// PR_TASK_PERF_EVENTS_DISABLE: every event the caller made.
pub(super) fn linux_perf_task_events(enable: bool) -> u64 {
    let (instance, pid) = (linux_execution_instance(), current_linux_process_pid());
    let slots: Vec<usize> = PERF_EVENTS
        .lock()
        .slots
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            event.is_some_and(|event| event.instance == instance && event.owner == pid)
        })
        .map(|(slot, _)| slot)
        .collect();
    linux_perf_apply(
        &slots,
        if enable {
            PERF_EVENT_IOC_ENABLE
        } else {
            PERF_EVENT_IOC_DISABLE
        },
    );
    0
}

/// Whether `descriptor` is a perf event's.
pub(super) fn linux_perf_descriptor(descriptor: u64) -> bool {
    linux_perf_slot(descriptor).is_some()
}

/// Drops the events of `instance`, when its domain stops.
pub(super) fn linux_perf_forget_instance(instance: usize) {
    for event in PERF_EVENTS.lock().slots.iter_mut() {
        if event.is_some_and(|event| event.instance == instance) {
            *event = None;
        }
    }
}
