use super::*;

/// The CPU time a clock id names, in cycles: CLOCK_PROCESS_CPUTIME_ID and
/// CLOCK_THREAD_CPUTIME_ID for the caller, and the ids clock_getcpuclockid
/// and pthread_getcpuclockid make (negative: the pid or tid in the upper
/// bits, inverted, the kind in the low three, bit 2 for a thread). None for
/// a clock that is not a CPU clock; an error for a process or thread that
/// is not there (EINVAL, as Linux answers an invalid clock id).
fn linux_cpu_clock_cycles(clock: u64) -> Option<Result<u64, u64>> {
    let id = clock as u32 as i32;
    let pid = current_linux_process_pid();
    if id == LINUX_CLOCK_PROCESS_CPUTIME_ID as i32 {
        return Some(Ok(linux_current_process_cpu_cycles()));
    }
    if id == LINUX_CLOCK_THREAD_CPUTIME_ID as i32 {
        return Some(Ok(
            current_linux_thread_slot().map_or(0, linux_thread_cpu_cycles)
        ));
    }
    if id >= 0 {
        return None;
    }
    let target = !(id >> 3) as u32;
    let per_thread = id & 4 != 0;
    if id & 3 == 3 {
        return Some(Err(LINUX_EINVAL));
    }
    Some(if per_thread {
        let own = target == 0 || Some(target) == current_linux_tid();
        match (own, linux_thread_handle_by_tid(u64::from(target))) {
            (true, _) => Ok(current_linux_thread_slot().map_or(0, linux_thread_cpu_cycles)),
            (false, Some(handle)) => Ok(linux_thread_cpu_cycles(usize::from(handle.slot))),
            (false, None) => Err(LINUX_EINVAL),
        }
    } else {
        let target = if target == 0 { pid } else { target };
        if linux_process::live_process_status(target).is_none() {
            Err(LINUX_EINVAL)
        } else if target == pid {
            Ok(linux_current_process_cpu_cycles())
        } else {
            Ok(linux_process_cpu_cycles(target))
        }
    })
}

/// Timestamp-counter cycles as a (seconds, nanoseconds) pair.
fn linux_cycles_time(cycles: u64) -> (u64, u64) {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    if frequency == 0 {
        return (0, 0);
    }
    (
        cycles / frequency,
        cycles % frequency * NANOSECONDS_PER_SECOND / frequency,
    )
}

/// The current process's time namespace offset of `clock`, in nanoseconds:
/// CLOCK_MONOTONIC's for the monotonic clocks, CLOCK_BOOTTIME's for the
/// boot-time ones, none for the others.
pub(super) fn linux_time_namespace_offset(clock: u64) -> i64 {
    if !linux_namespace::any(linux_namespace::Kind::Time) {
        return 0;
    }
    let [monotonic, boottime] =
        linux_namespace::time_offsets(linux_execution_instance(), current_linux_namespaces().time);
    match clock {
        LINUX_CLOCK_MONOTONIC | LINUX_CLOCK_MONOTONIC_RAW | LINUX_CLOCK_MONOTONIC_COARSE => {
            monotonic
        }
        LINUX_CLOCK_BOOTTIME | LINUX_CLOCK_BOOTTIME_ALARM => boottime,
        _ => 0,
    }
}

/// An absolute `clock` time the current process gave (as its time
/// namespace shows the clock) as the kernel's clock counts it.
pub(super) fn linux_time_namespace_host(clock: u64, nanoseconds: u64) -> u64 {
    nanoseconds.saturating_add_signed(linux_time_namespace_offset(clock).saturating_neg())
}

/// (seconds, nanoseconds) moved by `offset` nanoseconds, no earlier than 0.
fn linux_shift_time((seconds, nanoseconds): (u64, u64), offset: i64) -> (u64, u64) {
    if offset == 0 {
        return (seconds, nanoseconds);
    }
    let total = (i128::from(seconds) * i128::from(NANOSECONDS_PER_SECOND)
        + i128::from(nanoseconds)
        + i128::from(offset))
    .max(0);
    let second = i128::from(NANOSECONDS_PER_SECOND);
    ((total / second) as u64, (total % second) as u64)
}

pub(super) fn linux_clock_gettime(clock: u64, output_address: u64) -> u64 {
    let clock = u64::from(clock as u32);
    let cpu_clock = match linux_cpu_clock_cycles(clock) {
        Some(Ok(cycles)) => Some(linux_cycles_time(cycles)),
        Some(Err(error)) => return error,
        None => None,
    };
    if cpu_clock.is_none() && !linux_clock_supported(clock) {
        return LINUX_EINVAL;
    }
    let realtime = matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_TAI
    );
    let Some((seconds, mut nanoseconds)) = cpu_clock.or_else(|| {
        if realtime {
            linux_realtime_time()
        } else {
            linux_elapsed_time()
                .map(|time| linux_shift_time(time, linux_time_namespace_offset(clock)))
        }
    }) else {
        return LINUX_ENOSYS;
    };
    if matches!(
        clock,
        LINUX_CLOCK_REALTIME_COARSE | LINUX_CLOCK_MONOTONIC_COARSE
    ) {
        let resolution = NANOSECONDS_PER_SECOND / LINUX_CLOCK_TICKS_PER_SECOND;
        nanoseconds -= nanoseconds % resolution;
    }
    let mut timespec = [0_u8; 16];
    timespec[..8].copy_from_slice(&seconds.to_ne_bytes());
    timespec[8..].copy_from_slice(&nanoseconds.to_ne_bytes());
    // The fast copy takes only pages already present and writable; one not
    // yet touched or shared copy-on-write is made writable by the full copy
    // (on the boot CPU, which may change page tables).
    if !address_space::copy_to_current_linux_user_fast(output_address, &timespec)
        && !copy_to_linux_user(output_address, &timespec)
    {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_gettimeofday(timeval_address: u64, timezone_address: u64) -> u64 {
    if timeval_address == 0 && timezone_address == 0 {
        return 0;
    }
    let Some((seconds, nanoseconds)) = linux_realtime_time() else {
        return LINUX_ENOSYS;
    };
    if timeval_address != 0
        && (!copy_to_linux_user(timeval_address, &seconds.to_ne_bytes())
            || !copy_to_linux_user(
                timeval_address.saturating_add(8),
                &(nanoseconds / 1_000).to_ne_bytes(),
            ))
    {
        return LINUX_EFAULT;
    }
    if timezone_address != 0 && !copy_to_linux_user(timezone_address, &[0; 8]) {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_time(output_address: u64) -> u64 {
    if output_address != 0 && !linux_writable_user_range_contains(output_address, 8) {
        return LINUX_EFAULT;
    }
    let Some((seconds, _)) = linux_realtime_time() else {
        return LINUX_ENOSYS;
    };
    if output_address != 0 && !copy_to_linux_user(output_address, &seconds.to_ne_bytes()) {
        return LINUX_EFAULT;
    }
    seconds
}

/// Whether the caller may set the clock: root, standing in for CAP_SYS_TIME.
/// Setting the clock needs CAP_SYS_TIME (settimeofday02 drops it as root).
fn linux_may_set_clock() -> bool {
    current_linux_credentials()
        .is_some_and(|credentials| credentials.has(ginux_credentials::capability::SYS_TIME))
}

/// Sets the domain's wall clock to `seconds` and `nanoseconds`: the
/// difference from the clock as it reads now becomes part of the offset.
fn linux_set_realtime(seconds: u64, nanoseconds: u64) -> u64 {
    let Some((now_seconds, now_nanoseconds)) = linux_realtime_time() else {
        return LINUX_ENOSYS;
    };
    let wanted = i128::from(seconds) * i128::from(NANOSECONDS_PER_SECOND) + i128::from(nanoseconds);
    let now =
        i128::from(now_seconds) * i128::from(NANOSECONDS_PER_SECOND) + i128::from(now_nanoseconds);
    let Ok(delta) = i64::try_from(wanted - now) else {
        return LINUX_EINVAL;
    };
    if linux_adjust_realtime_offset(delta) {
        0
    } else {
        LINUX_EINVAL
    }
}

/// clock_settime(2): CLOCK_REALTIME alone can be set, by root; the setting
/// moves this domain's clock, not the host's.
pub(super) fn linux_clock_settime(clock: u64, address: u64) -> u64 {
    if u64::from(clock as u32) != LINUX_CLOCK_REALTIME {
        return LINUX_EINVAL;
    }
    let mut specification = [0_u8; 16];
    if !copy_from_linux_user(address, &mut specification) {
        return LINUX_EFAULT;
    }
    let seconds = i64::from_ne_bytes(specification[..8].try_into().unwrap());
    let nanoseconds = i64::from_ne_bytes(specification[8..].try_into().unwrap());
    if seconds < 0 || !(0..NANOSECONDS_PER_SECOND as i64).contains(&nanoseconds) {
        return LINUX_EINVAL;
    }
    if !linux_may_set_clock() {
        return LINUX_EPERM;
    }
    linux_set_realtime(seconds as u64, nanoseconds as u64)
}

/// settimeofday(2): a timeval, by root; a timezone is accepted and ignored.
pub(super) fn linux_settimeofday(timeval_address: u64, _timezone_address: u64) -> u64 {
    if timeval_address == 0 {
        return 0;
    }
    let mut timeval = [0_u8; 16];
    if !copy_from_linux_user(timeval_address, &mut timeval) {
        return LINUX_EFAULT;
    }
    let seconds = i64::from_ne_bytes(timeval[..8].try_into().unwrap());
    let microseconds = i64::from_ne_bytes(timeval[8..].try_into().unwrap());
    if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
        return LINUX_EINVAL;
    }
    if !linux_may_set_clock() {
        return LINUX_EPERM;
    }
    linux_set_realtime(seconds as u64, microseconds as u64 * 1000)
}

/// adjtimex(2): mode 0 reads the clock's state; ADJ_OFFSET and
/// ADJ_OFFSET_SINGLESHOT move the clock by the offset and ADJ_SETOFFSET by
/// the time field (at once, there is no slewing); the other parameters are
/// checked as Linux does (the tick within 900000..=1100000) and not kept.
/// ADJ_STATUS keeps the NTP status word (a leap second asked for with
/// STA_INS is reported, TIME_INS then TIME_WAIT, though the clock is not
/// stepped), and the call returns the clock state (leapsec01).
pub(super) fn linux_adjtimex(address: u64) -> u64 {
    const ADJ_OFFSET: i32 = 0x0001;
    const ADJ_STATUS: i32 = 0x0010;
    const ADJ_SETOFFSET: i32 = 0x0100;
    const ADJ_NANO: i32 = 0x2000;
    const ADJ_TICK: i32 = 0x4000;
    const ADJ_ADJTIME: i32 = 0x8000;
    const ADJ_OFFSET_SINGLESHOT: i32 = 0x8001;
    const ADJ_OFFSET_SS_READ: i32 = 0xa001;
    const TIMEX_SIZE: usize = 208;
    let mut timex = [0_u8; TIMEX_SIZE];
    if !copy_from_linux_user(address, &mut timex) {
        return LINUX_EFAULT;
    }
    let modes = i32::from_ne_bytes(timex[..4].try_into().unwrap());
    let field = |offset: usize| i64::from_ne_bytes(timex[offset..offset + 8].try_into().unwrap());
    let singleshot = modes == ADJ_OFFSET_SINGLESHOT || modes == ADJ_OFFSET_SS_READ;
    if modes & ADJ_ADJTIME != 0 && !singleshot {
        return LINUX_EINVAL;
    }
    if modes != 0 && modes != ADJ_OFFSET_SS_READ && !linux_may_set_clock() {
        return LINUX_EPERM;
    }
    // The tick is in microseconds per clock tick: Linux allows a tenth
    // either side of the nominal 1 s / HZ.
    let tick_bounds = 900_000 / LINUX_CLOCK_TICKS_PER_SECOND as i64
        ..=1_100_000 / LINUX_CLOCK_TICKS_PER_SECOND as i64;
    if !singleshot && modes & ADJ_TICK != 0 && !tick_bounds.contains(&field(88)) {
        return LINUX_EINVAL;
    }
    if modes == ADJ_OFFSET_SINGLESHOT || (!singleshot && modes & ADJ_OFFSET != 0) {
        let offset = field(8);
        let delta = if modes & ADJ_NANO != 0 {
            offset
        } else {
            offset.saturating_mul(1000)
        };
        if !linux_adjust_realtime_offset(delta) {
            return LINUX_EINVAL;
        }
    }
    if !singleshot && modes & ADJ_SETOFFSET != 0 {
        let fraction = if modes & ADJ_NANO != 0 {
            field(80)
        } else {
            field(80).saturating_mul(1000)
        };
        let delta = field(72)
            .saturating_mul(NANOSECONDS_PER_SECOND as i64)
            .saturating_add(fraction);
        if !linux_adjust_realtime_offset(delta) {
            return LINUX_EINVAL;
        }
    }
    let Some((seconds, nanoseconds)) = linux_realtime_time() else {
        return LINUX_ENOSYS;
    };
    if !singleshot && modes & ADJ_STATUS != 0 {
        linux_set_ntp_status(
            u32::from_ne_bytes(timex[40..44].try_into().unwrap()),
            seconds,
        );
    }
    let (status, state) = linux_ntp_state(seconds);
    let mut output = [0_u8; TIMEX_SIZE];
    output[..4].copy_from_slice(&modes.to_ne_bytes());
    output[40..44].copy_from_slice(&status.to_ne_bytes());
    output[56..64].copy_from_slice(&1_i64.to_ne_bytes());
    output[64..72].copy_from_slice(&32_768_000_i64.to_ne_bytes());
    output[72..80].copy_from_slice(&(seconds as i64).to_ne_bytes());
    output[80..88].copy_from_slice(&((nanoseconds / 1000) as i64).to_ne_bytes());
    output[88..96]
        .copy_from_slice(&(1_000_000 / LINUX_CLOCK_TICKS_PER_SECOND as i64).to_ne_bytes());
    if !copy_to_linux_user(address, &output) {
        return LINUX_EFAULT;
    }
    state
}

/// clock_adjtime(2): adjtimex for CLOCK_REALTIME; no other clock here can
/// be adjusted.
pub(super) fn linux_clock_adjtime(clock: u64, address: u64) -> u64 {
    if u64::from(clock as u32) != LINUX_CLOCK_REALTIME {
        return LINUX_EINVAL;
    }
    linux_adjtimex(address)
}

pub(super) fn linux_uname_with_copy(address: u64, copy: impl FnOnce(u64, &[u8]) -> bool) -> u64 {
    let mut name = [0_u8; LINUX_UTSNAME_SIZE];
    // The Linux personality is "Linux", which rustup's installer, cmake,
    // autoconf's config.guess and Node check before anything runs; the
    // release ("...-ginux...") and node name still say Ginux.
    name[..6].copy_from_slice(b"Linux\0");
    let mut host = [0_u8; LINUX_UTS_NAME_CAPACITY];
    let host_length = linux_uts_name(LINUX_UTS_HOST, &mut host);
    name[65..65 + host_length].copy_from_slice(&host[..host_length]);
    let release = if X86_RUNTIME.ELF_PROBE_PERSONALITY.load(Ordering::SeqCst)
        & LINUX_PERSONALITY_UNAME26
        != 0
    {
        b"2.6.52.0-ginux.0.1\0".as_slice()
    } else {
        b"6.12.0-ginux.0.1\0".as_slice()
    };
    name[130..130 + release.len()].copy_from_slice(release);
    name[195..198].copy_from_slice(b"#1\0");
    name[260..267].copy_from_slice(b"x86_64\0");
    let mut domain = [0_u8; LINUX_UTS_NAME_CAPACITY];
    let domain_length = linux_uts_name(LINUX_UTS_DOMAIN, &mut domain);
    name[325..325 + domain_length].copy_from_slice(&domain[..domain_length]);
    if copy(address, &name) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_elapsed_time() -> Option<(u64, u64)> {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    let epoch = X86_RUNTIME.ELF_PROBE_CLOCK_EPOCH.load(Ordering::SeqCst);
    if frequency == 0 || epoch == 0 {
        return None;
    }
    let ticks = timer::timestamp_counter().saturating_sub(epoch);
    linux_ticks_to_time(ticks, frequency)
}

pub(crate) fn refresh_linux_vvar() -> bool {
    if !X86_RUNTIME.LINUX_RUNTIME_MODE.load(Ordering::Acquire)
        || !X86_RUNTIME.ELF_PROBE_ACTIVE.load(Ordering::Acquire)
    {
        return true;
    }
    let frequency = X86_RUNTIME
        .ELF_PROBE_CLOCK_FREQUENCY
        .load(Ordering::Relaxed);
    let monotonic_epoch = X86_RUNTIME.ELF_PROBE_CLOCK_EPOCH.load(Ordering::Relaxed);
    let now = timer::timestamp_counter();
    let multiplier = (NANOSECONDS_PER_SECOND << 32).checked_div(frequency);
    let monotonic = now
        .checked_sub(monotonic_epoch)
        .and_then(|ticks| linux_ticks_to_time(ticks, frequency));
    // The wall time the vDSO hands out carries the domain's clock_settime
    // offset, as the system call does.
    let realtime = crate::linux_realtime_epoch().and_then(|(seconds, epoch)| {
        now.checked_sub(epoch)
            .and_then(|ticks| linux_ticks_to_time(ticks, frequency))
            .and_then(|(elapsed, nanoseconds)| {
                seconds
                    .checked_add(elapsed)
                    .map(|seconds| (seconds, nanoseconds))
            })
            .and_then(|(seconds, nanoseconds)| linux_offset_realtime(seconds, nanoseconds))
    });
    let frame = (0..usize::from(
        X86_RUNTIME
            .ELF_PROBE_ACTIVE_IMAGE_COUNT
            .load(Ordering::Acquire),
    ))
        .find(|index| {
            X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_ADDRESSES[*index].load(Ordering::Acquire)
                == crate::linux_elf::VVAR_ADDRESS
        })
        .and_then(|index| {
            memory::FrameLease::from_parts(
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_FRAMES[index].load(Ordering::Acquire),
                X86_RUNTIME.ELF_PROBE_ACTIVE_IMAGE_GENERATIONS[index].load(Ordering::Acquire),
            )
        });
    multiplier
        .zip(monotonic)
        .zip(realtime)
        .zip(frame)
        .is_some_and(
            |(
                (
                    (multiplier, (monotonic_seconds, monotonic_nanoseconds)),
                    (realtime_seconds, realtime_nanoseconds),
                ),
                frame,
            )| {
                // A process in a time namespace reads its clocks through the
                // system call, which adds the namespace's offsets: an empty
                // page tells the vDSO to fall back to it.
                let in_time_namespace = linux_namespace::any(linux_namespace::Kind::Time)
                    && current_linux_namespaces().time != 0;
                address_space::update_linux_vvar(
                    frame,
                    if in_time_namespace {
                        [0; 6]
                    } else {
                        [
                            multiplier,
                            now,
                            monotonic_seconds,
                            monotonic_nanoseconds,
                            realtime_seconds,
                            realtime_nanoseconds,
                        ]
                    },
                )
            },
        )
}

pub(super) fn linux_ticks_to_time(ticks: u64, frequency: u64) -> Option<(u64, u64)> {
    if frequency == 0 {
        return None;
    }
    let seconds = ticks / frequency;
    let remainder = ticks % frequency;
    let nanoseconds = if frequency == NANOSECONDS_PER_SECOND {
        remainder
    } else {
        remainder
            .checked_mul(NANOSECONDS_PER_SECOND)?
            .checked_div(frequency)?
    };
    Some((seconds, nanoseconds))
}

pub(super) fn linux_realtime_time() -> Option<(u64, u64)> {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    let (epoch_seconds, epoch_counter) = crate::linux_realtime_epoch()?;
    let ticks = timer::timestamp_counter().checked_sub(epoch_counter)?;
    let (elapsed_seconds, nanoseconds) = linux_ticks_to_time(ticks, frequency)?;
    linux_offset_realtime(epoch_seconds.checked_add(elapsed_seconds)?, nanoseconds)
}

/// Applies the current domain's clock_settime/adjtimex offset to a wall
/// time read from the host clock.
fn linux_offset_realtime(seconds: u64, nanoseconds: u64) -> Option<(u64, u64)> {
    let offset = linux_realtime_offset_nanoseconds();
    if offset == 0 {
        return Some((seconds, nanoseconds));
    }
    let total = i128::from(seconds) * i128::from(NANOSECONDS_PER_SECOND)
        + i128::from(nanoseconds)
        + i128::from(offset);
    if total < 0 {
        return Some((0, 0));
    }
    Some((
        u64::try_from(total / i128::from(NANOSECONDS_PER_SECOND)).ok()?,
        (total % i128::from(NANOSECONDS_PER_SECOND)) as u64,
    ))
}

pub(super) fn linux_host_realtime_time() -> Option<(u64, u64)> {
    let frequency = timer::monotonic_frequency()?;
    let (epoch_seconds, epoch_counter) = crate::linux_realtime_epoch()?;
    let ticks = timer::timestamp_counter().checked_sub(epoch_counter)?;
    let elapsed_seconds = ticks.checked_div(frequency)?;
    let remainder = ticks.checked_rem(frequency)?;
    let nanoseconds = remainder
        .checked_mul(NANOSECONDS_PER_SECOND)?
        .checked_div(frequency)?;
    Some((epoch_seconds.checked_add(elapsed_seconds)?, nanoseconds))
}

pub(super) fn linux_elapsed_nanoseconds() -> Option<u64> {
    let (seconds, nanoseconds) = linux_elapsed_time()?;
    seconds
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|value| value.checked_add(nanoseconds))
}

pub(super) fn linux_system_elapsed_time() -> Option<(u64, u64)> {
    let frequency = timer::monotonic_frequency()?;
    let (_, epoch) = crate::linux_realtime_epoch()?;
    let elapsed = timer::timestamp_counter().saturating_sub(epoch);
    Some((
        elapsed / frequency,
        elapsed % frequency * NANOSECONDS_PER_SECOND / frequency,
    ))
}

pub(super) fn linux_clock_supported(clock: u64) -> bool {
    let clock = u64::from(clock as u32);
    matches!(
        clock,
        LINUX_CLOCK_REALTIME
            | LINUX_CLOCK_MONOTONIC
            | LINUX_CLOCK_PROCESS_CPUTIME_ID
            | LINUX_CLOCK_THREAD_CPUTIME_ID
            | LINUX_CLOCK_MONOTONIC_RAW
            | LINUX_CLOCK_REALTIME_COARSE
            | LINUX_CLOCK_MONOTONIC_COARSE
            | LINUX_CLOCK_BOOTTIME
            | LINUX_CLOCK_REALTIME_ALARM
            | LINUX_CLOCK_BOOTTIME_ALARM
            | LINUX_CLOCK_TAI
    )
}

/// The CPU time process `pid` has used, in timestamp-counter cycles.
pub(super) fn linux_process_cpu_cycles(pid: u32) -> u64 {
    linux_process::live_process_cpu_cycles(
        pid,
        pid == current_linux_process_pid(),
        timer::timestamp_counter(),
    )
    .unwrap_or(0)
}

/// The CPU time process `pid` has used, in clock ticks (USER_HZ).
pub(super) fn linux_process_cpu_ticks(pid: u32) -> u64 {
    linux_cycles_to_clock_ticks(linux_process_cpu_cycles(pid))
}

/// The user and system time process `pid` has used, in timestamp-counter
/// cycles.
pub(super) fn linux_process_cpu_times(pid: u32) -> (u64, u64) {
    linux_process::live_process_cpu_times(
        pid,
        pid == current_linux_process_pid(),
        timer::timestamp_counter(),
    )
    .unwrap_or((0, 0))
}

/// `cycles` of the timestamp counter in clock ticks (USER_HZ).
fn linux_cycles_to_clock_ticks(cycles: u64) -> u64 {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    if frequency == 0 {
        return 0;
    }
    cycles / frequency * LINUX_CLOCK_TICKS_PER_SECOND
        + cycles % frequency * LINUX_CLOCK_TICKS_PER_SECOND / frequency
}

/// `cycles` of the timestamp counter as a timeval: seconds and
/// microseconds.
fn linux_cycles_to_timeval(cycles: u64, frequency: u64) -> [u8; 16] {
    let mut timeval = [0_u8; 16];
    timeval[..8].copy_from_slice(&(cycles / frequency).to_ne_bytes());
    timeval[8..].copy_from_slice(&(cycles % frequency * 1_000_000 / frequency).to_ne_bytes());
    timeval
}

pub(super) fn linux_times(output_address: u64) -> u64 {
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    let epoch = X86_RUNTIME.ELF_PROBE_CLOCK_EPOCH.load(Ordering::SeqCst);
    if frequency == 0 || epoch == 0 {
        return LINUX_ENOSYS;
    }
    let elapsed = timer::timestamp_counter().saturating_sub(epoch);
    let ticks = elapsed / frequency * LINUX_CLOCK_TICKS_PER_SECOND
        + elapsed % frequency * LINUX_CLOCK_TICKS_PER_SECOND / frequency;
    if output_address != 0 {
        // tms_utime, tms_stime, tms_cutime and tms_cstime.
        let pid = current_linux_process_pid();
        let (user, system) = linux_process_cpu_times(pid);
        let (children_user, children_system) =
            linux_process::live_process_children_cpu_times(pid).unwrap_or((0, 0));
        let mut accounting = [0_u8; 32];
        for (field, cycles) in accounting.as_chunks_mut::<8>().0.iter_mut().zip([
            user,
            system,
            children_user,
            children_system,
        ]) {
            field.copy_from_slice(&linux_cycles_to_clock_ticks(cycles).to_ne_bytes());
        }
        if !copy_to_linux_user(output_address, &accounting) {
            return LINUX_EFAULT;
        }
    }
    ticks
}

pub(super) fn linux_sysinfo(output_address: u64) -> u64 {
    let Some(processes) = linux_process::live_process_count() else {
        return LINUX_ESRCH;
    };
    // The uptime is CLOCK_BOOTTIME's, as the caller's time namespace shows
    // it, in whole seconds rounded up (as Linux's sysinfo rounds).
    let Some(uptime) = linux_elapsed_time()
        .map(|time| linux_shift_time(time, linux_time_namespace_offset(LINUX_CLOCK_BOOTTIME)))
        .map(|(seconds, nanoseconds)| (seconds + u64::from(nanoseconds != 0), 0))
    else {
        return LINUX_ENOSYS;
    };
    let information = match linux_sysinfo_information(processes, uptime) {
        Ok(information) => information,
        Err(error) => return error,
    };
    if copy_to_linux_user(output_address, &information) {
        0
    } else {
        LINUX_EFAULT
    }
}

pub(super) fn linux_sysinfo_information(
    processes: u16,
    (uptime, _): (u64, u64),
) -> Result<[u8; 112], u64> {
    // The domain's memory, as /proc/meminfo reports it (sysinfo01 compares
    // the two): the machine's, bounded by the domain's budget.
    if memory::frame_counts().is_none() {
        return Err(LINUX_ENOSYS);
    }
    let (total_frames, free_frames) = linux_domain_frame_counts();
    let Some(total_memory) = total_frames.checked_mul(PAGE_SIZE as u64) else {
        return Err(LINUX_EOVERFLOW);
    };
    let Some(free_memory) = free_frames.checked_mul(PAGE_SIZE as u64) else {
        return Err(LINUX_EOVERFLOW);
    };
    let mut information = [0_u8; 112];
    information[..8].copy_from_slice(&uptime.to_ne_bytes());
    information[32..40].copy_from_slice(&total_memory.to_ne_bytes());
    information[40..48].copy_from_slice(&free_memory.to_ne_bytes());
    // The domain's swap, as /proc/meminfo's SwapTotal and SwapFree.
    let (swap_total, swap_free) = crate::linux_swap::totals(linux_execution_instance());
    information[64..72].copy_from_slice(&(swap_total * 1024).to_ne_bytes());
    information[72..80].copy_from_slice(&(swap_free * 1024).to_ne_bytes());
    information[80..82].copy_from_slice(&processes.to_ne_bytes());
    information[104..108].copy_from_slice(&1_u32.to_ne_bytes());
    Ok(information)
}

/// The calling process's resident memory in KiB, as its page tables map it.
pub(super) fn linux_current_resident_kib() -> u64 {
    address_space::current_linux_user_page_count()
        .and_then(|pages| pages.checked_mul(PAGE_SIZE / 1024))
        .and_then(|kib| u64::try_from(kib).ok())
        .unwrap_or(0)
}

pub(super) fn linux_getrusage(who: u64, output_address: u64) -> u64 {
    let who = who as i32;
    let children = who == -1;
    if !matches!(who, -1..=1) {
        return LINUX_EINVAL;
    }
    let mut usage = [0_u8; 144];
    let frequency = X86_RUNTIME.ELF_PROBE_CLOCK_FREQUENCY.load(Ordering::SeqCst);
    if frequency == 0 {
        return LINUX_ENOSYS;
    }
    // ru_utime and ru_stime: the process's own, or its waited children's.
    let (user, system) = if children {
        linux_process::live_process_children_cpu_times(current_linux_process_pid())
            .unwrap_or((0, 0))
    } else {
        linux_process_cpu_times(current_linux_process_pid())
    };
    usage[..16].copy_from_slice(&linux_cycles_to_timeval(user, frequency));
    usage[16..32].copy_from_slice(&linux_cycles_to_timeval(system, frequency));
    if !children {
        let pid = current_linux_process_pid();
        linux_process::note_live_process_rss(pid, linux_current_resident_kib());
        let peak = linux_process::live_process_maxrss(pid).map_or(0, |(own, _)| own);
        usage[32..40].copy_from_slice(&peak.to_ne_bytes());
    } else {
        // The most any waited-for child (or its own waited children) held.
        let peak = linux_process::live_process_maxrss(current_linux_process_pid())
            .map_or(0, |(_, children)| children);
        usage[32..40].copy_from_slice(&peak.to_ne_bytes());
    }
    if !copy_to_linux_user(output_address, &usage) {
        return LINUX_EFAULT;
    }
    0
}

/// ITIMER_VIRTUAL (1, SIGVTALRM) and ITIMER_PROF (2, SIGPROF): timers on
/// the process's CPU time (user and system alike here, so both count the
/// same time), kept in the process table and fired with its POSIX timers.
fn linux_set_cpu_interval_timer(
    which: u64,
    (interval, value): (u64, u64),
    old_output_address: u64,
) -> u64 {
    const SIGVTALRM: u8 = 26;
    const SIGPROF: u8 = 27;
    let pid = current_linux_process_pid();
    let which = which as usize;
    let cpu_now = linux_current_process_cpu_nanoseconds();
    let Some((old_interval, old_deadline)) = linux_process::live_process_interval_timer(pid, which)
    else {
        return LINUX_ESRCH;
    };
    let old = linux_interval_timer_specification(old_interval, old_deadline, cpu_now);
    if old_output_address != 0 && !copy_to_linux_user(old_output_address, &old) {
        return LINUX_EFAULT;
    }
    let deadline = if value == 0 {
        0
    } else {
        cpu_now.saturating_add(value).max(1)
    };
    let signal = if which == 1 { SIGVTALRM } else { SIGPROF };
    if !linux_process::set_live_process_interval_timer(pid, which, signal, (interval, deadline)) {
        return LINUX_ESRCH;
    }
    linux_refresh_posix_timer_cache(pid);
    0
}

pub(super) fn linux_getitimer(which: u64, output_address: u64) -> u64 {
    let which = u64::from(which as u32);
    if which > 2 {
        return LINUX_EINVAL;
    }
    if which != 0 {
        let cpu_now = linux_current_process_cpu_nanoseconds();
        let Some((interval, deadline)) =
            linux_process::live_process_interval_timer(current_linux_process_pid(), which as usize)
        else {
            return LINUX_ESRCH;
        };
        let specification = if deadline == 0 {
            linux_interval_timer_specification(interval, 0, 0)
        } else {
            linux_interval_timer_specification(interval, deadline, cpu_now)
        };
        return if copy_to_linux_user(output_address, &specification) {
            0
        } else {
            LINUX_EFAULT
        };
    }
    let specification = if which == 0 {
        let Some(now) = linux_elapsed_nanoseconds() else {
            return LINUX_ENOSYS;
        };
        linux_interval_timer_specification(
            X86_RUNTIME
                .ELF_PROBE_REAL_TIMER_INTERVAL
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_REAL_TIMER_DEADLINE
                .load(Ordering::SeqCst),
            now,
        )
    } else {
        [0_u8; 32]
    };
    if !copy_to_linux_user(output_address, &specification) {
        return LINUX_EFAULT;
    }
    0
}

pub(super) fn linux_alarm(seconds: u64) -> u64 {
    let seconds = u64::from(seconds as u32);
    let Some(now) = linux_elapsed_nanoseconds() else {
        return 0;
    };
    let old_deadline = X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .load(Ordering::SeqCst);
    let remaining = old_deadline
        .saturating_sub(now)
        .div_ceil(NANOSECONDS_PER_SECOND);
    let deadline = if seconds == 0 {
        0
    } else {
        now.saturating_add(seconds.saturating_mul(NANOSECONDS_PER_SECOND))
    };
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_INTERVAL
        .store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .store(deadline, Ordering::SeqCst);
    remaining.min(u64::from(u32::MAX))
}

pub(super) fn refresh_linux_real_timer() -> bool {
    let deadline = X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .load(Ordering::SeqCst);
    if deadline == 0 {
        return false;
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return false;
    };
    if now < deadline {
        return false;
    }
    let interval = X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_INTERVAL
        .load(Ordering::SeqCst);
    let next = now
        .saturating_sub(deadline)
        .checked_div(interval)
        .map_or(0, |elapsed| {
            deadline.saturating_add((elapsed + 1).saturating_mul(interval))
        });
    X86_RUNTIME
        .ELF_PROBE_REAL_TIMER_DEADLINE
        .store(next, Ordering::SeqCst);
    let index = LINUX_SIGALRM as usize - 1;
    X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_CODES[index]
        .store(LINUX_SI_KERNEL as u32, Ordering::SeqCst);
    X86_RUNTIME.ELF_PROBE_PENDING_SIGNAL_VALUES[index].store(0, Ordering::SeqCst);
    X86_RUNTIME
        .ELF_PROBE_PENDING_SIGNALS
        .fetch_or(1 << index, Ordering::SeqCst);
    true
}

/// The deadline of a timed wait that yielded with its call set to
/// restart, kept for when the call starts again: by domain instance,
/// process, thread and the call's return address.
#[derive(Clone, Copy)]
pub(super) struct LinuxRestartDeadline {
    instance: usize,
    pid: u32,
    tid: u32,
    rip: u64,
    deadline: u64,
}

/// Records the deadline of a timed wait about to yield with a restart.
pub(super) fn save_linux_restart_deadline(rip: u64, deadline: u64) {
    let instance = linux_execution_instance();
    let (pid, tid) = (
        current_linux_process_pid(),
        current_linux_tid().unwrap_or(0),
    );
    let mut deadlines = LINUX_RESTART_DEADLINES.lock();
    // A thread waits in one call at a time, so one it left in an earlier
    // call (a signal handler ended that wait) is stale, and so are those of
    // a process that has ended.
    // (A child still running inside its parent's fork is not published
    // yet, but it is not gone.)
    deadlines.retain(|entry| {
        entry.instance != instance
            || (entry.pid, entry.tid) != (pid, tid)
                && linux_process::live_process_slot(entry.pid).is_some()
                && !linux_process::live_process_status(entry.pid)
                    .is_some_and(|status| status.state == linux_process::LiveProcessState::Zombie)
    });
    if deadlines.try_reserve(1).is_ok() {
        deadlines.push(LinuxRestartDeadline {
            instance,
            pid,
            tid,
            rip,
            deadline,
        });
    }
}

/// Returns and forgets the deadline saved when this thread's call at `rip`
/// last yielded.
pub(super) fn take_linux_restart_deadline(rip: u64) -> Option<u64> {
    let instance = linux_execution_instance();
    let (pid, tid) = (
        current_linux_process_pid(),
        current_linux_tid().unwrap_or(0),
    );
    let mut deadlines = LINUX_RESTART_DEADLINES.lock();
    let index = deadlines.iter().position(|entry| {
        entry.instance == instance && entry.pid == pid && entry.tid == tid && entry.rip == rip
    })?;
    Some(deadlines.swap_remove(index).deadline)
}

/// What a wait's turn at letting other processes run came to.
pub(super) enum LinuxWaitTurn {
    /// The call ends with this result.
    Done(u64),
    /// The call waited parked while others ran and was resumed to look at
    /// its wait again. If it goes on waiting it parks again: halting here
    /// would hold the only CPU from a parked process with work to do (a
    /// shell's `sleep 0.2` stalled a renderer for the whole 200 ms).
    Resumed,
    /// Nothing else could run: wait for an interrupt.
    Idle,
}

/// Lets other processes run while a timed wait has nothing to wait for in
/// its own process.
pub(super) fn linux_timed_wait_run_others(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    number: u64,
    deadline: Option<u64>,
) -> LinuxWaitTurn {
    if let Some(deadline) = deadline {
        save_linux_restart_deadline(caller.rip, deadline);
    }
    let turn = match run_other_linux_processes(output, caller, number) {
        // Yielded, or set to start again from user mode: the call comes
        // back and takes its deadline.
        Some(LinuxBlockedWait::Return(result))
            if result == LINUX_RETURN_TO_KERNEL || result == number =>
        {
            return LinuxWaitTurn::Done(result);
        }
        Some(LinuxBlockedWait::Return(result)) => LinuxWaitTurn::Done(result),
        Some(LinuxBlockedWait::Recheck) => LinuxWaitTurn::Resumed,
        None => LinuxWaitTurn::Idle,
    };
    // The wait ended here (a signal, or other processes ran and it goes on
    // waiting in this call): the saved deadline goes with it.
    let _ = take_linux_restart_deadline(caller.rip);
    turn
}

pub(super) fn linux_nanosleep_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    request: u64,
    remaining: u64,
) -> u64 {
    let sleep = LinuxSleep {
        number: LINUX_NANOSLEEP_SYSCALL,
        clock: LINUX_CLOCK_MONOTONIC,
        flags: 0,
    };
    linux_sleep_live_return(output, caller, sleep, request, remaining)
}

pub(super) fn linux_clock_nanosleep_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    clock: u64,
    flags: u64,
    request: u64,
    remaining: u64,
) -> u64 {
    let sleep = LinuxSleep {
        number: LINUX_CLOCK_NANOSLEEP_SYSCALL,
        clock,
        flags,
    };
    linux_sleep_live_return(output, caller, sleep, request, remaining)
}

/// A sleep call: its syscall number, which a yield restarts it with, and
/// its clock and flags.
struct LinuxSleep {
    number: u64,
    clock: u64,
    flags: u64,
}

fn linux_sleep_live_return(
    output: *mut LinuxSyscallFrame,
    caller: LinuxUserContext,
    LinuxSleep {
        number,
        clock,
        flags,
    }: LinuxSleep,
    request: u64,
    remaining: u64,
) -> u64 {
    const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
    const CLOCK_BOOTTIME: u64 = 7;
    let clock = u64::from(clock as u32);
    let flags = u64::from(flags as u32);
    let namespace_clock = clock;
    // A thread's CPU clock cannot be slept on (Linux has no nsleep for it:
    // EOPNOTSUPP); CLOCK_BOOTTIME runs as CLOCK_MONOTONIC, with no suspend.
    if clock == CLOCK_THREAD_CPUTIME_ID && flags & !LINUX_TIMER_ABSTIME == 0 {
        return LINUX_EOPNOTSUPP;
    }
    let clock = if clock == CLOCK_BOOTTIME {
        LINUX_CLOCK_MONOTONIC
    } else {
        clock
    };
    if !matches!(clock, LINUX_CLOCK_REALTIME | LINUX_CLOCK_MONOTONIC)
        || flags & !LINUX_TIMER_ABSTIME != 0
    {
        return LINUX_EINVAL;
    }
    let mut request_bytes = [0_u8; 16];
    if !copy_from_linux_user(request, &mut request_bytes) {
        return LINUX_EFAULT;
    }
    let Some(requested) = linux_timespec_nanoseconds(&request_bytes) else {
        return LINUX_EINVAL;
    };
    let Some(monotonic_now) = linux_elapsed_nanoseconds() else {
        return LINUX_ENOSYS;
    };
    let realtime_now = if clock == LINUX_CLOCK_REALTIME {
        let Some((seconds, nanoseconds)) = linux_realtime_time() else {
            return LINUX_ENOSYS;
        };
        let Some(now) = seconds
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(nanoseconds))
        else {
            return LINUX_EINVAL;
        };
        now
    } else {
        monotonic_now
    };
    let absolute = flags & LINUX_TIMER_ABSTIME != 0;
    let restarted = take_linux_restart_deadline(caller.rip);
    let deadline = if let Some(deadline) = restarted {
        deadline
    } else if absolute && clock == LINUX_CLOCK_REALTIME {
        monotonic_now.saturating_add(requested.saturating_sub(realtime_now))
    } else if absolute {
        // An absolute time of the caller's time namespace's clock.
        linux_time_namespace_host(namespace_clock, requested)
    } else {
        let Some(deadline) = monotonic_now.checked_add(requested) else {
            return LINUX_EINVAL;
        };
        deadline
    };
    if deadline <= monotonic_now {
        return 0;
    }
    let remaining = if absolute { 0 } else { remaining };
    if remaining != 0 && !linux_writable_user_range_contains(remaining, 16) {
        return LINUX_EFAULT;
    }
    let Some(current) = current_linux_thread_handle() else {
        return LINUX_ESRCH;
    };
    let target = 'target: {
        if let Some(target) = ready_linux_thread_handle() {
            break 'target target;
        }
        // With no runnable thread here, other processes (such as a child this
        // one waits for) get the CPU; failing that, sleep in the kernel until
        // the deadline. Device/timer interrupts still wake the CPU and are
        // handled normally between checks. Once a sibling thread is ready,
        // this thread sleeps as a thread wait while it runs.
        while let Some(now) = linux_elapsed_nanoseconds().filter(|now| *now < deadline) {
            // The time left is written before each turn: a signal the turn
            // delivers ends the sleep with EINTR straight into its handler,
            // and a relative sleep reports what was left then.
            if remaining != 0 {
                let left = deadline - now;
                let mut timespec = [0_u8; 16];
                timespec[..8].copy_from_slice(&(left / 1_000_000_000).to_ne_bytes());
                timespec[8..].copy_from_slice(&(left % 1_000_000_000).to_ne_bytes());
                if !copy_to_linux_user(remaining, &timespec) {
                    return LINUX_EFAULT;
                }
            }
            // Passed over until shortly before its deadline, then resumed
            // each round to look at the clock itself (see
            // mark_linux_process_asleep): a thousand children sleeping in
            // usleep (futex_cmp_requeue01) took the CPU from the one with
            // work when every round resumed each of them.
            let pid = current_linux_process_pid();
            mark_linux_process_asleep(pid, deadline, linux_sleep_wake_margin());
            let turn = linux_timed_wait_run_others(output, caller, number, Some(deadline));
            if let LinuxWaitTurn::Done(result) = turn {
                // Yielded to start again: still asleep until then.
                if result != LINUX_RETURN_TO_KERNEL && result != number {
                    linux_process::set_live_process_futex_sleep(pid, None);
                }
                return result;
            }
            if let Some(target) = ready_linux_thread_handle() {
                linux_process::set_live_process_futex_sleep(pid, None);
                break 'target target;
            }
            // Wake at the deadline, not on the next tick after it, whether
            // this CPU halts here or in the runtime loop.
            if let Some(now) = linux_elapsed_nanoseconds() {
                timer::request_linux_tick_within(deadline.saturating_sub(now));
            }
            if let LinuxWaitTurn::Idle = turn {
                linux_wait_for_interrupt();
            }
        }
        // Its deadline has passed: a mark left would count as a sleeper
        // due for its next wait of another kind.
        linux_process::set_live_process_futex_sleep(current_linux_process_pid(), None);
        return 0;
    };
    let Some(tls) = linux_thread_context(current) else {
        return LINUX_ESRCH;
    };
    if !save_linux_thread_return_context(current, caller)
        || !block_current_linux_thread(LINUX_THREAD_WAIT_SLEEP, 1, remaining, deadline)
    {
        return LINUX_EINVAL;
    }
    let mut target_registers = LinuxSyscallFrame::ZERO;
    let mut target_rip = 0;
    let mut target_rsp = 0;
    let mut target_rflags = 0;
    let mut target_rax = 0;
    if !install_linux_thread_return(
        target,
        &mut target_registers,
        &mut target_rip,
        &mut target_rsp,
        &mut target_rflags,
        &mut target_rax,
    ) {
        let slot = usize::from(current.slot);
        X86_RUNTIME.LINUX_THREAD_WAIT_KINDS[slot].store(LINUX_THREAD_WAIT_NONE, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_KEYS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_OUTPUTS[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_WAIT_DEADLINES[slot].store(0, Ordering::SeqCst);
        X86_RUNTIME.LINUX_THREAD_STATES[slot].store(LINUX_THREAD_RUNNING, Ordering::SeqCst);
        X86_RUNTIME
            .LINUX_CURRENT_THREAD_SLOT
            .store(current.slot, Ordering::SeqCst);
        let _ = install_linux_tls_context(tls);
        return LINUX_EINVAL;
    }
    let selected = LinuxUserContext {
        registers: target_registers,
        rip: target_rip,
        rsp: target_rsp,
        rflags: target_rflags,
        rax: target_rax,
        fs_base: active_fs_base(),
    };
    if !write_linux_thread_live_return(output, target, selected) {
        return LINUX_EINVAL;
    }
    X86_RUNTIME
        .LINUX_LIVE_RETURN_VALIDATED
        .store(true, Ordering::SeqCst);
    X86_RUNTIME
        .LINUX_SLEEP_BLOCK_COUNT
        .fetch_add(1, Ordering::SeqCst);
    LINUX_RETURN_FROM_IRET
}

pub(super) fn linux_setitimer(which: u64, input_address: u64, old_output_address: u64) -> u64 {
    let which = u64::from(which as u32);
    if which > 2 {
        return LINUX_EINVAL;
    }
    if old_output_address != 0 && !linux_writable_user_range_contains(old_output_address, 32) {
        return LINUX_EFAULT;
    }
    let mut requested = [0_u8; 32];
    if input_address != 0 && !copy_from_linux_user(input_address, &mut requested) {
        return LINUX_EFAULT;
    }
    let Some(interval) = linux_timeval_nanoseconds(&requested[..16]) else {
        return LINUX_EINVAL;
    };
    let Some(value) = linux_timeval_nanoseconds(&requested[16..]) else {
        return LINUX_EINVAL;
    };
    if which != 0 {
        return linux_set_cpu_interval_timer(which, (interval, value), old_output_address);
    }
    let Some(now) = linux_elapsed_nanoseconds() else {
        return LINUX_ENOSYS;
    };
    let old = if which == 0 {
        linux_interval_timer_specification(
            X86_RUNTIME
                .ELF_PROBE_REAL_TIMER_INTERVAL
                .load(Ordering::SeqCst),
            X86_RUNTIME
                .ELF_PROBE_REAL_TIMER_DEADLINE
                .load(Ordering::SeqCst),
            now,
        )
    } else {
        [0_u8; 32]
    };
    let deadline = if value == 0 {
        0
    } else {
        let Some(deadline) = now.checked_add(value) else {
            return LINUX_EINVAL;
        };
        deadline
    };
    if old_output_address != 0 && !copy_to_linux_user(old_output_address, &old) {
        return LINUX_EFAULT;
    }
    if which == 0 {
        X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_INTERVAL
            .store(interval, Ordering::SeqCst);
        X86_RUNTIME
            .ELF_PROBE_REAL_TIMER_DEADLINE
            .store(deadline, Ordering::SeqCst);
    }
    0
}

pub(super) fn linux_timeval_nanoseconds(value: &[u8]) -> Option<u64> {
    let seconds = i64::from_ne_bytes(value.get(..8)?.try_into().ok()?);
    let microseconds = i64::from_ne_bytes(value.get(8..16)?.try_into().ok()?);
    if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
        return None;
    }
    (seconds as u64)
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add((microseconds as u64) * 1_000))
}

pub(super) fn linux_interval_timer_specification(
    interval: u64,
    deadline: u64,
    now: u64,
) -> [u8; 32] {
    let remaining = deadline.saturating_sub(now);
    let mut specification = [0_u8; 32];
    for (offset, value) in [(0, interval), (16, remaining)] {
        specification[offset..offset + 8]
            .copy_from_slice(&(value / NANOSECONDS_PER_SECOND).to_ne_bytes());
        specification[offset + 8..offset + 16]
            .copy_from_slice(&((value % NANOSECONDS_PER_SECOND) / 1_000).to_ne_bytes());
    }
    specification
}
