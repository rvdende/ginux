//! ginux-memtest: memory checks for Ginux tests.
//!
//! - `ginux-memtest touch MIB [THEN]` maps MIB MiB of private anonymous
//!   memory, writes one byte to every page, reads them back, and prints
//!   `MEMTEST OK MIB`. Then, still holding the memory, it exits (no THEN),
//!   or THEN is `segv` (fault: the kernel frees a killed process's memory),
//!   `fork` (fork a child that writes a page of it, copy-on-write, and
//!   exits; prints `FORK OK`) or `spawn` (run `true` through
//!   `std::process::Command`, a vfork-and-exec; prints `SPAWN OK`).
//! - `ginux-memtest segv` writes through a null pointer, so the process dies
//!   from SIGSEGV (a parent shell sees status 139).
//! - `ginux-memtest returns` checks that memory comes back: rounds of a
//!   burst of processes alive at once, fork-and-exec children, and shared
//!   mappings of files removed while mapped. Once a burst is over its
//!   kernel stacks (/proc/meminfo's KernelStack) must have gone back but
//!   for the spare ones, and the rounds after the first must give back
//!   all but a little of MemFree. Prints `RETURNS OK`.
//! - `ginux-memtest slab` makes and removes thousands of files with long
//!   paths, whose names the kernel keeps on its heap: /proc/meminfo's Slab
//!   must grow with them and come back once they are gone. Prints
//!   `SLAB OK`.

use rustix::mm::{mmap, mmap_anonymous, munmap, MapFlags, ProtFlags};
use rustix::process::{wait, WaitOptions};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};
use std::time::Instant;

const PAGE: usize = 4096;

extern "C" {
    fn fork() -> i32;
    fn _exit(status: i32) -> !;
}

fn touch(mib: usize, then: Option<&str>) -> ExitCode {
    let Some(length) = mib.checked_mul(1 << 20) else {
        eprintln!("memtest: {mib} MiB is too large");
        return ExitCode::FAILURE;
    };
    // SAFETY: a fresh private anonymous mapping aliases nothing.
    let base = match unsafe {
        mmap_anonymous(
            core::ptr::null_mut(),
            length,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::PRIVATE | MapFlags::NORESERVE,
        )
    } {
        Ok(base) => base.cast::<u8>(),
        Err(error) => {
            eprintln!("memtest: mmap {mib} MiB: {error}");
            return ExitCode::FAILURE;
        }
    };
    let pages = length / PAGE;
    let stamp = |page: usize| (page as u8) | 1;
    for page in 0..pages {
        // SAFETY: page * PAGE < length, inside the mapping.
        unsafe { base.add(page * PAGE).write_volatile(stamp(page)) };
        if (page + 1) % (1 << 18) == 0 {
            println!("memtest: touched {} MiB", ((page + 1) * PAGE) >> 20);
        }
    }
    for page in 0..pages {
        // SAFETY: as above.
        let value = unsafe { base.add(page * PAGE).read_volatile() };
        if value != stamp(page) {
            eprintln!("memtest: page {page} reads {value}");
            return ExitCode::FAILURE;
        }
    }
    println!("MEMTEST OK {mib}");
    match then {
        None => ExitCode::SUCCESS,
        Some("segv") => {
            segv();
            ExitCode::FAILURE
        }
        Some("fork") => fork_child(base),
        Some("spawn") => match std::process::Command::new("true").status() {
            Ok(status) if status.success() => {
                println!("SPAWN OK");
                ExitCode::SUCCESS
            }
            result => {
                eprintln!("memtest: spawn: {result:?}");
                ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!("memtest: unknown action {other}");
            ExitCode::FAILURE
        }
    }
}

fn fork_child(base: *mut u8) -> ExitCode {
    // SAFETY: the process is single-threaded, so the child may run any code.
    match unsafe { fork() } {
        0 => {
            // SAFETY: the first page is mapped and private to this child.
            unsafe { base.write_volatile(0x5a) };
            // SAFETY: ends the child without running the parent's exit code.
            unsafe { _exit(0) }
        }
        pid if pid < 0 => {
            eprintln!("memtest: fork failed");
            ExitCode::FAILURE
        }
        _ => match wait(WaitOptions::empty()) {
            // SAFETY: the parent's copy of the page is its own.
            Ok(Some((_, status)))
                if status.exit_status() == Some(0) && unsafe { base.read_volatile() } == 1 =>
            {
                println!("FORK OK");
                ExitCode::SUCCESS
            }
            result => {
                eprintln!("memtest: fork child: {result:?}");
                ExitCode::FAILURE
            }
        },
    }
}

fn segv() {
    // SAFETY: none; this faults on purpose so the kernel delivers SIGSEGV.
    unsafe { core::ptr::null_mut::<u8>().write_volatile(1) };
}

/// A /proc/meminfo figure (`MemFree`, `KernelStack`), in KiB.
fn meminfo_kib(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()
}

/// Processes alive at once in each round of `returns`: more than the
/// kernel keeps spare stacks for (64).
const BURST: usize = 150;

/// A kernel stack, in KiB.
const KERNEL_STACK_KIB: u64 = 256;

/// The kernel stacks that may stay once a burst is over: the 64 spare ones
/// and those of the processes still running (this one, the shell, init).
const KERNEL_STACKS_KEPT_KIB: u64 = 80 * KERNEL_STACK_KIB;

/// What the rounds after the first may keep between them. The first may
/// keep memory for good: the kernel keeps the records of the first 256
/// process slots for the next processes.
const LATER_ROUNDS_LIMIT_KIB: u64 = 1024;

/// Shared mappings of removed files in each round: one page each, so
/// keeping them would keep 800 KiB a round.
const SHARED_FILES: usize = 200;

/// Fork-and-execs in each round: an exec that left the old program's
/// heap and stack pages behind kept about 9 KiB each.
const FORK_EXECS: usize = 100;

/// Maps a page of a tmpfs file shared, removes the file, writes through
/// the mapping and unmaps it: the file's page must go with the mapping.
fn shared_unlinked_file(index: usize) -> std::io::Result<()> {
    let path = format!("/tmp/memtest-returns-{index}");
    let file = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    file.set_len(PAGE as u64)?;
    // SAFETY: a fresh shared mapping of a file only this process has.
    let base = unsafe {
        mmap(
            core::ptr::null_mut(),
            PAGE,
            ProtFlags::READ | ProtFlags::WRITE,
            MapFlags::SHARED,
            &file,
            0,
        )
    }?;
    drop(file);
    std::fs::remove_file(&path)?;
    // SAFETY: the page was just mapped readable and writable.
    unsafe { base.cast::<u64>().write_volatile(index as u64) };
    // SAFETY: nothing refers to the mapping any more.
    unsafe { munmap(base, PAGE) }?;
    Ok(())
}

/// Forks a child that execs this program (`exit`), and waits for it.
fn fork_exec(program: &std::path::Path) -> std::io::Result<()> {
    // SAFETY: the process is single-threaded, so the child may run any code.
    match unsafe { fork() } {
        0 => {
            let error = Command::new(program).arg("exit").exec();
            eprintln!("memtest: exec: {error}");
            // SAFETY: ends the child without running the parent's exit code.
            unsafe { _exit(1) }
        }
        pid if pid < 0 => Err(std::io::Error::other("fork failed")),
        _ => match wait(WaitOptions::empty()) {
            Ok(Some((_, status))) if status.exit_status() == Some(0) => Ok(()),
            result => Err(std::io::Error::other(format!("child: {result:?}"))),
        },
    }
}

/// One round of `returns`; returns the kernel stacks' KiB while the burst
/// runs and once it is over.
fn returns_round(program: &std::path::Path) -> std::io::Result<(u64, u64)> {
    let mut children = Vec::with_capacity(BURST);
    for _ in 0..BURST {
        children.push(
            Command::new(program)
                .arg("idle")
                .stdin(std::process::Stdio::piped())
                .spawn()?,
        );
    }
    let during = meminfo_kib("KernelStack").unwrap_or(0);
    // Each child waits for its stdin to close, so all are alive when the
    // stacks are counted however long the burst took to start (with a
    // fixed sleep, the first children's ended before the last had started
    // once sleeps woke on time).
    for child in &mut children {
        drop(child.stdin.take());
    }
    for mut child in children {
        let status = child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("idle child: {status}")));
        }
    }
    let after = meminfo_kib("KernelStack").unwrap_or(u64::MAX);
    for _ in 0..FORK_EXECS {
        fork_exec(program)?;
    }
    (0..SHARED_FILES).try_for_each(shared_unlinked_file)?;
    Ok((during, after))
}

/// Files `slab` makes at once.
const SLAB_FILES: usize = 4000;

/// What `slab` needs the files to have taken from the heap's slabs.
const SLAB_GROWTH_KIB: u64 = 2048;

/// What `slab` lets the heap keep of it once the files are gone: the
/// spare slabs and the kernel's path hints.
const SLAB_KEPT_KIB: u64 = 1024;

/// Makes `SLAB_FILES` files below `directory` and removes them; returns
/// the Slab KiB while they existed.
fn slab_burst(directory: &std::path::Path) -> std::io::Result<u64> {
    std::fs::create_dir_all(directory)?;
    for index in 0..SLAB_FILES {
        std::fs::File::create(directory.join(format!("{index:0>200}")))?;
    }
    let during = meminfo_kib("Slab").unwrap_or(0);
    for index in 0..SLAB_FILES {
        std::fs::remove_file(directory.join(format!("{index:0>200}")))?;
    }
    Ok(during)
}

fn slab() -> ExitCode {
    // Paths of about a kilobyte: three directories of 200-character names.
    let root = std::path::Path::new("/tmp/memtest-slab");
    let directory = root
        .join("d".repeat(200))
        .join("e".repeat(200))
        .join("f".repeat(200));
    let Some(before) = meminfo_kib("Slab") else {
        eprintln!("memtest: no Slab in /proc/meminfo");
        return ExitCode::FAILURE;
    };
    let during = match slab_burst(&directory) {
        Ok(during) => during,
        Err(error) => {
            eprintln!("memtest: slab: {error}");
            return ExitCode::FAILURE;
        }
    };
    let _ = std::fs::remove_dir_all(root);
    let after = meminfo_kib("Slab").unwrap_or(u64::MAX);
    println!("SLAB kib before={before} during={during} after={after}");
    if during < before + SLAB_GROWTH_KIB {
        eprintln!(
            "memtest: {SLAB_FILES} files took {} KiB of slabs",
            during.saturating_sub(before)
        );
        return ExitCode::FAILURE;
    }
    if after > before + SLAB_KEPT_KIB {
        eprintln!(
            "memtest: slabs kept {} KiB once the files went (limit {SLAB_KEPT_KIB})",
            after - before
        );
        return ExitCode::FAILURE;
    }
    println!("SLAB OK");
    ExitCode::SUCCESS
}

fn returns() -> ExitCode {
    const ROUNDS: usize = 4;
    let program = match std::env::current_exe() {
        Ok(program) => program,
        Err(error) => {
            eprintln!("memtest: current_exe: {error}");
            return ExitCode::FAILURE;
        }
    };
    let started = Instant::now();
    let mut free = vec![meminfo_kib("MemFree")];
    for round in 0..ROUNDS {
        let (during, after) = match returns_round(&program) {
            Ok(stacks) => stacks,
            Err(error) => {
                eprintln!("memtest: round {round}: {error}");
                return ExitCode::FAILURE;
            }
        };
        free.push(meminfo_kib("MemFree"));
        println!("RETURNS round={round} kernel_stack_kib during={during} after={after}");
        // While the burst runs its stacks show; once it is over they must
        // have gone back, but for the spare ones.
        if during < BURST as u64 * KERNEL_STACK_KIB || after > KERNEL_STACKS_KEPT_KIB {
            eprintln!(
                "memtest: kernel stacks {during} KiB with {BURST} processes, \
                 {after} KiB after them (limit {KERNEL_STACKS_KEPT_KIB})"
            );
            return ExitCode::FAILURE;
        }
    }
    let Some(free) = free.into_iter().collect::<Option<Vec<u64>>>() else {
        eprintln!("memtest: no MemFree in /proc/meminfo");
        return ExitCode::FAILURE;
    };
    let first = free[0].saturating_sub(free[1]);
    let later = free[1].saturating_sub(free[ROUNDS]);
    println!(
        "RETURNS free_kib={free:?} first_round_kib={first} later_rounds_kib={later} ms={}",
        started.elapsed().as_millis()
    );
    if later > LATER_ROUNDS_LIMIT_KIB {
        eprintln!(
            "memtest: {later} KiB not given back over rounds 2 to {ROUNDS} \
             (limit {LATER_ROUNDS_LIMIT_KIB})"
        );
        return ExitCode::FAILURE;
    }
    println!("RETURNS OK");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("touch") => match args.get(2).and_then(|mib| mib.parse().ok()) {
            Some(mib) => touch(mib, args.get(3).map(String::as_str)),
            None => {
                eprintln!("usage: ginux-memtest touch MIB [segv|fork|spawn]");
                ExitCode::FAILURE
            }
        },
        Some("segv") => {
            segv();
            ExitCode::FAILURE
        }
        Some("returns") => returns(),
        Some("slab") => slab(),
        Some("idle") => {
            // Until the parent closes stdin.
            let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
            ExitCode::SUCCESS
        }
        Some("exit") => ExitCode::SUCCESS,
        _ => {
            eprintln!("usage: ginux-memtest touch MIB [segv|fork|spawn] | segv | returns");
            ExitCode::FAILURE
        }
    }
}
