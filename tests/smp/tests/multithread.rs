//! One process's threads run on all the CPUs of a domain given four.
//!
//! Boots the ESP in `GINUX_ESP_DIR` (default `build/esp`) under QEMU with
//! four CPUs, starts a domain on the built-in Rust image with `cpu=4`, and
//! in its shell runs `ginux-threadtest` (userland/threadtest):
//!
//! 1. `spin 1` and `spin 4`: the same fixed work per thread; four threads
//!    on four CPUs must finish in less than 2.5 times the one thread's
//!    time (on one CPU they take four times as long);
//! 2. `pingpong`: two threads hand a counter back and forth through a
//!    condition variable, waking each other across CPUs;
//! 3. `sleep`: timed waits end on time while other threads run elsewhere;
//! 4. `queue`: a channel feeds a pool of threads;
//! 5. `spawn`: a thread other than the main one starts child processes;
//! 6. `exit`: the main thread exits (status 7) while others spin on other
//!    CPUs, which must end them;
//! 7. `segv`: a thread faults while others spin; the process dies (139).
//!    Steps 6 and 7 run `EXIT_ROUNDS` times.
//! 8. `ginux-memtest returns` (userland/memtest): memory comes back after
//!    bursts of processes, fork-and-exec children and shared mappings of
//!    removed files.
//!
//! Every wait fails at once on a kernel failure line, a wrong status, or a
//! step that does not finish within its budget.
//!
//!   make rust-rootfs build && cargo test --manifest-path tests/smp/Cargo.toml multithread

mod guest;

use guest::Guest;
use std::path::Path;
use std::time::Duration;

struct Shell {
    guest: Guest,
    at: usize,
}

impl Shell {
    /// Runs `command` and returns its output and exit status.
    fn run(&mut self, tag: &str, command: &str, budget: Duration) -> (String, u32) {
        let marker = format!("{tag}STATUS=");
        self.guest.send(&format!("{command}; echo {tag}''STATUS=$?"));
        let start = self.at;
        let end = self.guest.wait_for(&marker, self.at, budget);
        let line_end = self.guest.wait_for_line_end(end, Duration::from_secs(10));
        self.at = line_end;
        let status = self.guest.text(end, line_end).trim().parse().unwrap_or_else(|_| {
            panic!("{tag}: no status; see {}", self.guest.log().display())
        });
        (self.guest.text(start, end), status)
    }

    fn expect(&mut self, tag: &str, command: &str, status: u32, ok: Option<&str>) -> String {
        let (text, actual) = self.run(tag, command, Duration::from_secs(60));
        let log = self.guest.log().display().to_string();
        assert_eq!(actual, status, "{tag}: `{command}` status; output {text:?}; see {log}");
        if let Some(ok) = ok {
            assert!(text.contains(ok), "{tag}: no {ok:?} in {text:?}; see {log}");
        }
        eprintln!("multithread: {tag}: `{command}` exited {actual}");
        text
    }

    /// The `ms=` figure a `ginux-threadtest` run printed.
    fn milliseconds(text: &str) -> u64 {
        text.lines()
            .find_map(|line| {
                line.split_whitespace()
                    .find_map(|word| word.strip_prefix("ms=")?.parse().ok())
            })
            .unwrap_or_else(|| panic!("no ms= in {text:?}"))
    }
}

/// Rounds of the `exit` and `segv` steps.
const EXIT_ROUNDS: u32 = 5;

#[test]
fn multithread() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo = repo.canonicalize().unwrap();
    let cpus: u32 = std::env::var("GINUX_SMP_TEST_CPUS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4);
    let mut guest = Guest::boot(&repo, &repo.join("target/multithread-test"), cpus, "2G");
    let mut at = guest.wait_for("ginux> ", 0, Duration::from_secs(90));
    guest.send("domain new threads");
    at = guest.wait_for("ginux> ", at, Duration::from_secs(20));
    guest.send(&format!(
        "domain set threads image=builtin://rust init=/sbin/init memory-mib=1024 cpu={cpus}"
    ));
    at = guest.wait_for("settings accepted", at, Duration::from_secs(20));
    guest.send("domain start threads --attach");
    at = guest.wait_for("all written in Rust", at, Duration::from_secs(60));
    guest.send("echo READY''MARK");
    at = guest.wait_for("READYMARK", at, Duration::from_secs(30));
    let mut shell = Shell { guest, at };

    let one = Shell::milliseconds(&shell.expect(
        "SPIN1",
        "ginux-threadtest spin 1",
        0,
        Some("THREADTEST OK spin"),
    ));
    let four = Shell::milliseconds(&shell.expect(
        "SPIN4",
        "ginux-threadtest spin 4",
        0,
        Some("THREADTEST OK spin"),
    ));
    eprintln!("multithread: one thread {one} ms, four threads {four} ms on {cpus} CPUs");
    assert!(
        cpus < 4 || four * 10 < one * 25,
        "four threads took {four} ms, one {one} ms: not running on several CPUs; see {}",
        shell.guest.log().display()
    );
    shell.expect("PINGPONG", "ginux-threadtest pingpong 20000", 0, Some("THREADTEST OK pingpong"));
    shell.expect("SLEEP", "ginux-threadtest sleep", 0, Some("THREADTEST OK sleep"));
    shell.expect("QUEUE", "ginux-threadtest queue", 0, Some("THREADTEST OK queue"));
    shell.expect("SPAWN", "ginux-threadtest spawn 10", 0, Some("THREADTEST OK spawn"));
    // A process pinned to a CPU moves there at once, and its sleeps end
    // there: pinned to another CPU, one ran on in place and, asleep, was
    // never resumed.
    shell.expect("PIN", "ginux-threadtest pin", 0, Some("THREADTEST OK pin"));
    // A few rounds: the process ends while its threads run elsewhere, and
    // the race that lets one of them outlive its memory takes a few tries
    // to show on a quiet host.
    for round in 0..EXIT_ROUNDS {
        shell.expect(&format!("EXIT{round}"), "ginux-threadtest exit", 7, Some("THREADTEST OK exit"));
        shell.expect(&format!("SEGV{round}"), "ginux-threadtest segv", 139, None);
    }
    let returns = shell.expect("RETURNS", "ginux-memtest returns", 0, Some("RETURNS OK"));
    for line in returns.lines().filter(|line| line.starts_with("RETURNS ")) {
        eprintln!("multithread: {line}");
    }
    // The shell still works after all that.
    shell.expect("AFTER", "echo still''alive", 0, Some("stillalive"));
}
