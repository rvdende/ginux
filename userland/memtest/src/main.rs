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

use rustix::mm::{mmap_anonymous, MapFlags, ProtFlags};
use rustix::process::{wait, WaitOptions};
use std::process::ExitCode;

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
        _ => {
            eprintln!("usage: ginux-memtest touch MIB [segv|fork|spawn] | segv");
            ExitCode::FAILURE
        }
    }
}
