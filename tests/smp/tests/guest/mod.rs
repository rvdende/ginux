//! A Ginux guest under QEMU driven over its serial console, for tests that
//! type commands at a domain's shell.

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
    "domain marked failed",
    "invalid kernel-entry",
    "scheduled process return failed",
    "runtime child completion failed",
    "thread run failed",
    "light thread",
    "no free process bank",
    "no free idle bank",
    "owned by two CPUs",
    "did not leave",
];

pub struct Guest {
    qemu: Child,
    input: ChildStdin,
    output: Arc<Mutex<Vec<u8>>>,
    pid_file: PathBuf,
    log: PathBuf,
}

impl Guest {
    pub fn boot(repo: &Path, work: &Path, cpus: u32, memory: &str) -> Guest {
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
            .env("GINUX_MEMORY", memory)
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

    pub fn log(&self) -> &Path {
        &self.log
    }

    pub fn send(&mut self, line: &str) {
        self.input.write_all(line.as_bytes()).unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
    }

    /// Waits for `needle` after byte `from` of the console output; returns
    /// where it ends. Fails at once on a failure line or when QEMU exits.
    pub fn wait_for(&mut self, needle: &str, from: usize, budget: Duration) -> usize {
        self.wait_until(from, budget, needle, |text| {
            text.find(needle).map(|at| at + needle.len())
        })
    }

    /// Waits for `needle` or `other`, whichever comes first, and returns
    /// where it ends.
    pub fn wait_for_either(
        &mut self,
        needle: &str,
        other: &str,
        from: usize,
        budget: Duration,
    ) -> usize {
        self.wait_until(from, budget, needle, |text| {
            [needle, other]
                .iter()
                .filter_map(|word| text.find(word).map(|at| at + word.len()))
                .min()
        })
    }

    /// Waits for the end of the line `from` is on and returns where it is.
    pub fn wait_for_line_end(&mut self, from: usize, budget: Duration) -> usize {
        self.wait_until(from, budget, "end of line", |text| {
            text.find(['\r', '\n'])
        })
    }

    fn wait_until(
        &mut self,
        from: usize,
        budget: Duration,
        what: &str,
        find: impl Fn(&str) -> Option<usize>,
    ) -> usize {
        let deadline = Instant::now() + budget;
        loop {
            let (failure, found) = {
                let output = self.output.lock().unwrap();
                let text = String::from_utf8_lossy(&output[from.min(output.len())..]);
                (
                    FAILURES.iter().find(|failure| text.contains(*failure)),
                    find(&text),
                )
            };
            if let Some(failure) = failure {
                panic!("guest reported {failure:?}; see {}", self.log.display());
            }
            if let Some(position) = found {
                return from + position;
            }
            if let Ok(Some(status)) = self.qemu.try_wait() {
                panic!("QEMU exited ({status}); see {}", self.log.display());
            }
            if Instant::now() > deadline {
                panic!("no {what:?} within {budget:?}; see {}", self.log.display());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn text(&self, from: usize, to: usize) -> String {
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
