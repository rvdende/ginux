//! A domain with most of a large machine's memory runs one big process; a
//! child that faults, or that runs the machine out of memory, dies alone and
//! gives its memory back.
//!
//! Boots the ESP in `GINUX_ESP_DIR` (default `build/esp`) under QEMU with
//! `GINUX_BIGMEM_QEMU` of RAM (default 26G), starts a domain on the built-in
//! Rust image with `memory-mib=GINUX_BIGMEM_DOMAIN_MIB` (default 24000), and
//! in its shell runs `ginux-memtest` (userland/memtest):
//!
//! 1. `segv`: a write through a null pointer; the shell sees status 139
//!    (SIGSEGV) and keeps running;
//! 2. `touch MIB` (`GINUX_BIGMEM_MIB`, default 16384): one process maps that
//!    much anonymous memory and writes every page;
//! 3. `touch MIB segv`: the same, then a fault while holding it (139);
//! 4. `touch MIB fork` and `touch MIB spawn`: the big process forks a child
//!    (copy-on-write) and spawns `true` (vfork and exec);
//! 5. `touch` of more than is free: the process is killed (status 137, the
//!    SIGKILL of Linux's OOM killer), not the domain.
//!
//! After each step the free memory must come back to where it was. Every
//! wait fails at once on a kernel failure line, on a wrong status, or when
//! the next GiB is not touched within its budget.
//!
//!   make rust-rootfs build && cargo test --manifest-path tests/smp/Cargo.toml bigmem
//!
//! QEMU touches up to the guest's whole memory: run one at a time.

mod guest;

use guest::Guest;
use std::path::Path;
use std::time::Duration;

/// Free memory may differ this much between steps (MiB): the shell and
/// kernel caches grow a little.
const FREE_SLACK_MIB: u64 = 64;
/// How many times free memory is read before it must be back: the kernel's
/// fork and snapshot work lists, sized for the last big process, shrink
/// over the next few smaller ones.
const FREE_READS: usize = 4;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

struct Shell {
    guest: Guest,
    at: usize,
}

impl Shell {
    /// Runs `command` and returns its output and exit status. `gib` is how
    /// many GiB it touches, so the wait can follow its progress lines.
    fn run(&mut self, tag: &str, command: &str, gib: u64) -> (String, u32) {
        let marker = format!("{tag}STATUS=");
        self.guest.send(&format!("{command}; echo {tag}''STATUS=$?"));
        let start = self.at;
        for step in 1..=gib {
            self.at = self.guest.wait_for_either(
                &format!("touched {} MiB", step * 1024),
                &marker,
                self.at,
                Duration::from_secs(120),
            );
        }
        let end = self.guest.wait_for(&marker, self.at, Duration::from_secs(120));
        let line_end = self.guest.wait_for_line_end(end, Duration::from_secs(10));
        self.at = line_end;
        let status = self.guest.text(end, line_end).trim().parse().unwrap_or_else(|_| {
            panic!("{tag}: no status; see {}", self.guest.log().display())
        });
        (self.guest.text(start, end), status)
    }

    fn free_mib(&mut self, tag: &str) -> u64 {
        let (text, _) = self.run(tag, "head -3 /proc/meminfo", 0);
        let kib: u64 = text
            .lines()
            .find_map(|line| line.strip_prefix("MemFree:"))
            .and_then(|value| value.split_whitespace().next()?.parse().ok())
            .unwrap_or_else(|| panic!("no MemFree in {text:?}"));
        let mib = kib / 1024;
        eprintln!("bigmem: {tag}: {mib} MiB free");
        mib
    }

    fn expect(&mut self, tag: &str, command: &str, gib: u64, status: u32, ok: Option<&str>) {
        let (text, actual) = self.run(tag, command, gib);
        let log = self.guest.log().display().to_string();
        assert_eq!(actual, status, "{tag}: `{command}` status; output {text:?}; see {log}");
        if let Some(ok) = ok {
            assert!(text.contains(ok), "{tag}: no {ok:?} in {text:?}; see {log}");
        }
        eprintln!("bigmem: {tag}: `{command}` exited {actual}");
    }

    fn expect_free(&mut self, tag: &str, before: u64) {
        let mut after = self.free_mib(tag);
        for _ in 1..FREE_READS {
            if after + FREE_SLACK_MIB >= before {
                break;
            }
            after = self.free_mib(tag);
        }
        assert!(
            after + FREE_SLACK_MIB >= before,
            "{tag}: {after} MiB free, {before} MiB before: memory leaked; see {}",
            self.guest.log().display()
        );
    }
}

#[test]
fn bigmem() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo = repo.canonicalize().unwrap();
    let qemu_memory = env_or("GINUX_BIGMEM_QEMU", "26G");
    let domain_mib = env_or("GINUX_BIGMEM_DOMAIN_MIB", "24000");
    let touch_mib: u64 = env_or("GINUX_BIGMEM_MIB", "16384").parse().unwrap();
    let mut guest = Guest::boot(&repo, &repo.join("target/bigmem-test"), 2, &qemu_memory);
    let mut at = guest.wait_for("ginux> ", 0, Duration::from_secs(90));
    guest.send("domain new big");
    at = guest.wait_for("ginux> ", at, Duration::from_secs(20));
    guest.send(&format!(
        "domain set big image=builtin://rust init=/sbin/init memory-mib={domain_mib} cpu=1"
    ));
    at = guest.wait_for("settings accepted", at, Duration::from_secs(20));
    guest.send("domain start big --attach");
    at = guest.wait_for("all written in Rust", at, Duration::from_secs(60));
    guest.send("echo READY''MARK");
    at = guest.wait_for("READYMARK", at, Duration::from_secs(30));
    let mut shell = Shell { guest, at };

    let free = shell.free_mib("START");
    shell.expect("SEGV", "ginux-memtest segv", 0, 139, None);
    shell.expect_free("AFTERSEGV", free);

    let gib = touch_mib / 1024;
    let ok = format!("MEMTEST OK {touch_mib}");
    shell.expect("TOUCH", &format!("ginux-memtest touch {touch_mib}"), gib, 0, Some(&ok));
    shell.expect_free("AFTERTOUCH", free);
    shell.expect(
        "BIGSEGV",
        &format!("ginux-memtest touch {touch_mib} segv"),
        gib,
        139,
        Some(&ok),
    );
    shell.expect_free("AFTERBIGSEGV", free);
    // A big process starts others: fork (its pages shared copy-on-write)
    // and a vfork-and-exec spawn.
    for (tag, then, ok) in [("FORK", "fork", "FORK OK"), ("SPAWN", "spawn", "SPAWN OK")] {
        let command = format!("ginux-memtest touch {touch_mib} {then}");
        shell.expect(tag, &command, gib, 0, Some(ok));
        shell.expect_free(&format!("AFTER{tag}"), free);
    }

    // More than is free: Linux's OOM killer would SIGKILL the process.
    let free = shell.free_mib("BEFOREOOM");
    let too_much = free + 1024;
    let (text, status) = shell.run("OOM", &format!("ginux-memtest touch {too_much}"), 0);
    assert_eq!(
        status,
        128 + 9,
        "running out of memory: status; output {text:?}; see {}",
        shell.guest.log().display()
    );
    eprintln!("bigmem: OOM: `ginux-memtest touch {too_much}` exited {status}");
    shell.expect_free("AFTEROOM", free);
}
