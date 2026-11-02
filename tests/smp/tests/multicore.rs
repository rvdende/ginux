//! A domain given four CPUs runs four CPU-bound processes at once.
//!
//! Boots the ESP in `GINUX_ESP_DIR` (default `build/esp`) under QEMU with
//! four CPUs and a fresh volume, starts a domain on the built-in Rust image
//! with `cpu=4`, and times one CPU-bound job (`seq` into /dev/null) against
//! four at once. Four processes on four CPUs take about as long as one; on one CPU
//! they take four times as long. Any kernel failure line, or a step that
//! does not finish within its budget, fails the test at once rather than
//! waiting.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Console lines that mean the kernel or the domain has failed.
const FAILURES: &[&str] = &[
    "GINUX_KERNEL_PANIC",
    "application processor run failed",
    "Linux runtime exceeded",
    "domain marked failed",
    "invalid kernel-entry",
    "scheduled process return failed",
];

struct Guest {
    qemu: Child,
    input: ChildStdin,
    output: Arc<Mutex<Vec<u8>>>,
    pid_file: PathBuf,
    log: PathBuf,
}

impl Guest {
    fn boot(repo: &Path, work: &Path, cpus: u32) -> Guest {
        fs::create_dir_all(work).unwrap();
        let volume = work.join("volume.raw");
        let _ = fs::remove_file(&volume);
        File::create(&volume).unwrap().set_len(8 << 30).unwrap();
        let pid_file = work.join("qemu.pid");
        let log = work.join("serial.log");
        let esp = std::env::var_os("GINUX_ESP_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo.join("build/esp"));
        let mut qemu = Command::new(repo.join("tools/qemu/run.sh"))
            .env("GINUX_ESP_DIR", &esp)
            .env("GINUX_CPUS", cpus.to_string())
            .env("GINUX_MEMORY", "8G")
            .env("GINUX_VOLUME_IMAGE", &volume)
            .env("GINUX_QEMU_PID_FILE", &pid_file)
            .env(
                "OVMF_CODE",
                std::env::var("OVMF_CODE")
                    .unwrap_or_else(|_| "/usr/share/OVMF/OVMF_CODE_4M.fd".into()),
            )
            .env(
                "OVMF_VARS",
                std::env::var("OVMF_VARS")
                    .unwrap_or_else(|_| "/usr/share/OVMF/OVMF_VARS_4M.fd".into()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("tools/qemu/run.sh starts");
        let input = qemu.stdin.take().unwrap();
        let mut stdout = qemu.stdout.take().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let collected = output.clone();
        let mut log_file = File::create(&log).unwrap();
        thread::spawn(move || {
            let mut buffer = [0_u8; 65536];
            while let Ok(read) = stdout.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let _ = log_file.write_all(&buffer[..read]);
                collected.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
        Guest {
            qemu,
            input,
            output,
            pid_file,
            log,
        }
    }

    fn send(&mut self, line: &str) {
        self.input.write_all(line.as_bytes()).unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
    }

    /// Waits for `needle` after byte `from` of the console output; returns
    /// where it ends. Fails at once on a failure line or when QEMU exits.
    fn wait_for(&mut self, needle: &str, from: usize, budget: Duration) -> usize {
        let deadline = Instant::now() + budget;
        loop {
            let (failure, found) = {
                let output = self.output.lock().unwrap();
                let text = String::from_utf8_lossy(&output[from.min(output.len())..]);
                (
                    FAILURES.iter().find(|failure| text.contains(*failure)),
                    text.find(needle),
                )
            };
            if let Some(failure) = failure {
                panic!("guest reported {failure:?}; see {}", self.log.display());
            }
            if let Some(position) = found {
                return from + position + needle.len();
            }
            if let Ok(Some(status)) = self.qemu.try_wait() {
                panic!("QEMU exited ({status}); see {}", self.log.display());
            }
            if Instant::now() > deadline {
                panic!(
                    "no {needle:?} within {budget:?}; see {}",
                    self.log.display()
                );
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn text(&self, from: usize, to: usize) -> String {
        let output = self.output.lock().unwrap();
        String::from_utf8_lossy(&output[from..to.min(output.len())]).into_owned()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        // run.sh execs QEMU, so its pid file names QEMU itself.
        if let Ok(pid) = fs::read_to_string(&self.pid_file) {
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
        let _ = self.qemu.kill();
        let _ = self.qemu.wait();
    }
}

/// Milliseconds between the `start` and `end` timestamps (`date +%s%N`)
/// the guest printed after `label`.
fn elapsed_ms(text: &str, label: &str) -> u64 {
    let line = text
        .lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} line in {text:?}"));
    let numbers: Vec<u64> = line[label.len()..]
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    (numbers[1] - numbers[0]) / 1_000_000
}

#[test]
fn multicore() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo = repo.canonicalize().unwrap();
    // GINUX_SMP_TEST_CPUS=1 runs the same steps on one CPU, for comparison.
    let cpus: u32 = std::env::var("GINUX_SMP_TEST_CPUS")
        .ok()
        .and_then(|cpus| cpus.parse().ok())
        .unwrap_or(4);
    let mut guest = Guest::boot(&repo, &repo.join("target/smp-test"), cpus);
    let mut at = guest.wait_for("ginux> ", 0, Duration::from_secs(90));
    guest.send("domain new smp");
    at = guest.wait_for("ginux> ", at, Duration::from_secs(20));
    guest.send(&format!(
        "domain set smp image=builtin://rust init=/sbin/init cpu={cpus}"
    ));
    at = guest.wait_for("settings accepted", at, Duration::from_secs(20));
    guest.send("domain start smp --attach");
    at = guest.wait_for("all written in Rust", at, Duration::from_secs(60));
    // The shell's prompt is not stable to match; a marker is.
    guest.send("echo READY''MARK");
    at = guest.wait_for("READYMARK", at, Duration::from_secs(30));
    let start = at;
    // The workload runs in a shell of its own, so that if that shell
    // fails, this one reports it. The job is user-mode work (formatting
    // numbers) written to /dev/null, so it measures the CPUs, not kernel
    // work, which still runs one CPU at a time. Each CPU's time
    // (/proc/stat, and SysRq `u` for kernel-entry lock waits) is shown
    // after.
    guest.send(
        "echo 'job() { seq 1 20000000 > /dev/null; }; \
         s=$(date +%s%N); job; echo ONE $s $(date +%s%N); \
         echo STAT''BEFORE; head -5 /proc/stat; \
         s=$(date +%s%N); for i in 1 2 3 4; do job & done; wait; \
         echo FOUR $s $(date +%s%N); echo STAT''AFTER; head -5 /proc/stat; \
         echo u > /proc/sysrq-trigger' > /tmp/work.sh; brush /tmp/work.sh; \
         cat /tmp/report-*.toml 2>/dev/null | head -60; echo DONE''MARK",
    );
    let end = guest.wait_for("DONEMARK", at, Duration::from_secs(120));
    // GINUX_SMP_TEST_PROBE: a command whose output (and kernel log) to show.
    if let Ok(probe) = std::env::var("GINUX_SMP_TEST_PROBE") {
        guest.send(&format!("{probe}; echo PROBE''MARK"));
        let probe_end = guest.wait_for("PROBEMARK", end, Duration::from_secs(120));
        eprintln!("{}", guest.text(end, probe_end));
    }
    let text = guest.text(start, end);
    let one = elapsed_ms(&text, "ONE ");
    let four = elapsed_ms(&text, "FOUR ");
    eprintln!("multicore: one job {one} ms, four at once {four} ms");
    // Per CPU, the user, kernel and idle time (1/100 s) the four took.
    let section = |marker: &str| -> String {
        let at = text.find(marker).map_or(text.len(), |at| at + marker.len());
        text[at..].to_owned()
    };
    let (before_text, after_text) = (section("STATBEFORE"), section("STATAFTER"));
    let row = |prefix: &str, cpu: usize| -> Vec<u64> {
        let source = if prefix == "BEFORE" { &before_text } else { &after_text };
        source
            .lines()
            .find(|line| line.starts_with(&format!("cpu{cpu} ")))
            .map(|line| {
                line.split_whitespace()
                    .skip(1)
                    .map(|value| value.parse().unwrap_or(0))
                    .collect()
            })
            .unwrap_or_default()
    };
    for cpu in 0..cpus as usize {
        let (before, after) = (row("BEFORE", cpu), row("AFTER", cpu));
        if before.len() >= 4 && after.len() >= 4 {
            eprintln!(
                "multicore: cpu{cpu} user {} kernel {} idle {} (1/100 s)",
                after[0] - before[0],
                after[2] - before[2],
                after[3] - before[3]
            );
        }
    }
    for line in text.lines().filter(|line| line.starts_with("ginux: cpu ")) {
        eprintln!("multicore: {line} (ms user/kernel/idle/lock-wait since boot, processes run)");
    }
    // On one CPU four take four times as long as one; on four CPUs about as
    // long. Allow for the kernel work they still do one CPU at a time.
    assert!(
        cpus < 4 || four * 10 < one * 25,
        "four processes took {four} ms against {one} ms for one: they did not run in parallel"
    );
}
