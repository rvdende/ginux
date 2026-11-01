//! One QEMU boot: its serial console, the events the session watches for,
//! and the serial log.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use regex::bytes::Regex;

use crate::config::Config;

static MARKER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)@@LTP (BEGIN|END|READY|DONE|SETUP_FAILED|RUNNER_EXITED)(?: ([^\r\n]*))?")
        .expect("valid marker pattern")
});
/// A kernel or boot panic.
pub static PANIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"GINUX_(?:BOOT|KERNEL)_PANIC").expect("valid panic pattern"));
static DOMAIN_DOWN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"ginux: Linux init (?:exited|execution failed)|domain marked failed")
        .expect("valid domain-down pattern")
});

/// What a console line (or the end of the console) reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// `@@LTP BEGIN INDEX TAG`: a test started.
    Begin,
    /// `@@LTP END INDEX TAG STATUS MILLISECONDS LEFTOVER`: a test ended.
    End,
    /// `@@LTP READY COUNT FIRST`: the runner read its list.
    Ready,
    /// `@@LTP DONE`: the runner ran its whole list.
    Done,
    /// `@@LTP SETUP_FAILED WHAT`: setup.sh could not start the runner.
    SetupFailed,
    /// `@@LTP RUNNER_EXITED STATUS`: the runner (or setup) exited.
    RunnerExited,
    /// The kernel panicked.
    Panic,
    /// The domain's init exited or failed.
    DomainDown,
    /// QEMU's output ended.
    Eof,
}

/// A console event.
#[derive(Clone, Debug)]
pub struct Event {
    /// What happened.
    pub kind: EventKind,
    /// The marker's arguments, or the whole line for a panic or a domain
    /// going down.
    pub text: String,
    /// When the line was read.
    pub when: Instant,
    /// The console offset where the line starts.
    pub start: usize,
    /// The console offset just past the line.
    pub end: usize,
}

/// Recognizes an event in one console line (without its line ending).
pub fn scan_line(line: &[u8]) -> Option<(EventKind, String)> {
    if let Some(found) = MARKER.captures(line) {
        let kind = match &found[1] {
            b"BEGIN" => EventKind::Begin,
            b"END" => EventKind::End,
            b"READY" => EventKind::Ready,
            b"DONE" => EventKind::Done,
            b"SETUP_FAILED" => EventKind::SetupFailed,
            _ => EventKind::RunnerExited,
        };
        let text = found.get(2).map_or(&b""[..], |m| m.as_bytes());
        return Some((kind, String::from_utf8_lossy(text).into_owned()));
    }
    let whole = || String::from_utf8_lossy(line).into_owned();
    if PANIC.is_match(line) {
        Some((EventKind::Panic, whole()))
    } else if DOMAIN_DOWN.is_match(line) {
        Some((EventKind::DomainDown, whole()))
    } else {
        None
    }
}

/// Why waiting on the console stopped early.
#[derive(Debug)]
pub enum WaitError {
    /// The boot failed: a panic, QEMU exiting, or a timeout.
    Boot(String),
    /// The run was interrupted (SIGINT or SIGTERM).
    Interrupted,
}

#[derive(Default)]
struct Console {
    data: Mutex<Vec<u8>>,
    changed: Condvar,
}

impl Console {
    fn data(&self) -> MutexGuard<'_, Vec<u8>> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A running QEMU (through `tools/qemu/run.sh`) and its console.
pub struct Qemu {
    child: Child,
    stdin: Option<ChildStdin>,
    console: Arc<Console>,
    events: Receiver<Event>,
    reader: Option<JoinHandle<()>>,
}

impl Qemu {
    /// Boots Ginux. Console output is appended to `log`.
    pub fn start(config: &Config, boot: u32, log: &Arc<File>) -> io::Result<Qemu> {
        let header = format!(
            "\n===== ltp driver: boot {boot} at {} =====\n",
            chrono::Local::now().format("%H:%M:%S")
        );
        (&**log).write_all(header.as_bytes())?;
        let (output, writer) = io::pipe()?;
        let mut command = Command::new(config.repo.join("tools/qemu/run.sh"));
        command
            .env("GINUX_ESP_DIR", &config.esp_dir)
            .env("GINUX_MEMORY", &config.memory)
            .env("GINUX_VOLUME_IMAGE", config.volume())
            .env("GINUX_QEMU_PID_FILE", config.pid_file())
            .stdin(Stdio::piped())
            .stdout(writer.try_clone()?)
            .stderr(writer)
            // Its own process group: a Ctrl-C on the terminal reaches the
            // harness, which stops QEMU itself.
            .process_group(0);
        if std::env::var_os("TMPDIR").is_none() {
            let tmp: PathBuf = config.repo.join("target/tmp");
            std::fs::create_dir_all(&tmp)?;
            command.env("TMPDIR", tmp);
        }
        let mut child = command.spawn()?;
        // The command holds the pipe's write ends; the reader sees the end
        // of the output only once they are closed.
        drop(command);
        let stdin = child.stdin.take();
        let console = Arc::new(Console::default());
        let (sender, events) = mpsc::channel();
        let reader = {
            let console = Arc::clone(&console);
            let log = Arc::clone(log);
            thread::spawn(move || read_console(output, &console, &log, &sender))
        };
        Ok(Qemu {
            child,
            stdin,
            console,
            events,
            reader: Some(reader),
        })
    }

    /// Types a line on the console.
    pub fn send(&mut self, line: &str) {
        if let Some(stdin) = &mut self.stdin {
            let _ = stdin
                .write_all(format!("{line}\n").as_bytes())
                .and_then(|()| stdin.flush());
        }
    }

    /// Whether QEMU is still running.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// The next console event, waiting up to `timeout`.
    pub fn next_event(&self, timeout: Duration) -> Option<Event> {
        match self.events.recv_timeout(timeout) {
            Ok(event) => Some(event),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                // The reader is gone; let the caller notice QEMU exiting
                // without spinning.
                thread::sleep(timeout);
                None
            }
        }
    }

    /// The console's length so far.
    pub fn len(&self) -> usize {
        self.console.data().len()
    }

    /// Whether the console is still empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Waits until `needle` appears on the console after offset `start`;
    /// returns the offset just past it. Stops early if the kernel panics,
    /// QEMU exits, `seconds` pass or the run is interrupted.
    pub fn wait_for(
        &mut self,
        needle: &[u8],
        seconds: u64,
        start: usize,
        interrupted: &AtomicBool,
    ) -> Result<usize, WaitError> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            {
                let data = self.console.data();
                let after = data.get(start..).unwrap_or_default();
                if let Some(position) = memchr::memmem::find(after, needle) {
                    return Ok(start + position + needle.len());
                }
                if PANIC.is_match(after) {
                    return Err(WaitError::Boot("kernel panic".to_string()));
                }
            }
            if !self.alive() {
                return Err(WaitError::Boot("QEMU exited".to_string()));
            }
            if interrupted.load(Ordering::Relaxed) {
                return Err(WaitError::Interrupted);
            }
            if Instant::now() > deadline {
                return Err(WaitError::Boot(format!(
                    "no '{}' within {seconds}s",
                    String::from_utf8_lossy(needle)
                )));
            }
            let data = self.console.data();
            let _ = self
                .console
                .changed
                .wait_timeout(data, Duration::from_millis(100));
        }
    }

    /// Waits until the console has been quiet for half a second (so a
    /// crash report is complete), or five seconds pass.
    pub fn settle(&self, interrupted: &AtomicBool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut size = None;
        while Instant::now() < deadline && !interrupted.load(Ordering::Relaxed) {
            let current = self.len();
            if size == Some(current) {
                return;
            }
            size = Some(current);
            thread::sleep(Duration::from_millis(500));
        }
    }

    /// The console from `start` to `end` (or to now).
    pub fn output(&self, start: usize, end: Option<usize>) -> Vec<u8> {
        let data = self.console.data();
        let end = end.unwrap_or(data.len()).min(data.len());
        data.get(start.min(end)..end).unwrap_or_default().to_vec()
    }

    /// Stops QEMU: SIGTERM, then SIGKILL if it has not exited after five
    /// seconds. Nothing in the guest needs saving: the console is attached
    /// to the domain (or the guest is wedged), and the volume's metadata is
    /// transactional and survives this like a crash.
    pub fn stop(&mut self) {
        if self.alive() {
            let pid = rustix::process::Pid::from_child(&self.child);
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.alive() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(50));
            }
            if self.alive() {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        self.stdin = None;
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Qemu {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Copies QEMU's output into the console buffer and the serial log, and
/// sends an event for each marker, panic or domain failure line.
fn read_console(mut output: impl Read, console: &Console, log: &File, events: &Sender<Event>) {
    let mut chunk = vec![0; 65536];
    let mut pending = Vec::new();
    let mut pending_offset = 0;
    loop {
        let count = match output.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        let now = Instant::now();
        let bytes = &chunk[..count];
        console.data().extend_from_slice(bytes);
        console.changed.notify_all();
        let mut log = log;
        let _ = log.write_all(bytes);
        pending.extend_from_slice(bytes);
        let mut consumed = 0;
        while let Some(newline) = memchr::memchr(b'\n', &pending[consumed..]) {
            let mut line = &pending[consumed..consumed + newline];
            while let [rest @ .., b'\r'] = line {
                line = rest;
            }
            let start = pending_offset + consumed;
            if let Some((kind, text)) = scan_line(line) {
                let _ = events.send(Event {
                    kind,
                    text,
                    when: now,
                    start,
                    end: start + newline + 1,
                });
            }
            consumed += newline + 1;
        }
        pending.drain(..consumed);
        pending_offset += consumed;
    }
    let length = console.data().len();
    console.changed.notify_all();
    let _ = events.send(Event {
        kind: EventKind::Eof,
        text: String::new(),
        when: Instant::now(),
        start: length,
        end: length,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers() {
        let begin = scan_line(b"@@LTP BEGIN 3 accept01").unwrap();
        assert_eq!(begin, (EventKind::Begin, "3 accept01".to_string()));
        let end = scan_line(b"junk@@LTP END 3 accept01 exit=0 120 0").unwrap();
        assert_eq!(end, (EventKind::End, "3 accept01 exit=0 120 0".to_string()));
        assert_eq!(
            scan_line(b"@@LTP DONE").unwrap(),
            (EventKind::Done, String::new())
        );
        assert_eq!(scan_line(b"@@LTP READY 25 0").unwrap().0, EventKind::Ready);
        assert_eq!(
            scan_line(b"@@LTP SETUP_FAILED runner download").unwrap(),
            (EventKind::SetupFailed, "runner download".to_string())
        );
        assert_eq!(
            scan_line(b"@@LTP RUNNER_EXITED 0").unwrap(),
            (EventKind::RunnerExited, "0".to_string())
        );
        assert_eq!(scan_line(b"@@LTP BEGIN 1 \xff").unwrap().1, "1 \u{fffd}");
    }

    #[test]
    fn the_shells_echo_of_the_start_command_is_not_a_marker() {
        let echo = br#"/ # wget -q -O /tmp/ltp-setup.sh http://10.0.2.2:4321/setup.sh && /bin/sh /tmp/ltp-setup.sh http://10.0.2.2:4321 0; echo "@@LTP" RUNNER"_"EXITED $?"#;
        assert_eq!(scan_line(echo), None);
    }

    #[test]
    fn kernel_failures() {
        let panic = b"ginux: fatal exception GINUX_KERNEL_PANIC";
        assert_eq!(scan_line(panic).unwrap().0, EventKind::Panic);
        assert_eq!(
            scan_line(b"GINUX_BOOT_PANIC: no volume").unwrap().0,
            EventKind::Panic
        );
        let down = b"ginux: Linux init execution failed; domain marked failed";
        assert_eq!(
            scan_line(down).unwrap(),
            (
                EventKind::DomainDown,
                String::from_utf8_lossy(down).into_owned()
            )
        );
        assert_eq!(
            scan_line(b"ginux: Linux init exited with 0").unwrap().0,
            EventKind::DomainDown
        );
        assert_eq!(scan_line(b"ginux: Linux init started"), None);
    }

    #[test]
    fn reader_offsets_events_by_console_position() {
        let console = Console::default();
        let directory =
            std::env::temp_dir().join(format!("ginux-ltp-console-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let log_path = directory.join("serial.log");
        let log = File::create(&log_path).unwrap();
        let (sender, receiver) = mpsc::channel();
        let input: &[u8] = b"boot\r\n@@LTP BEGIN 0 a\r\nout\r\n@@LTP END 0 a exit=0 5 0\r\npartial";
        read_console(input, &console, &log, &sender);
        let events: Vec<_> = receiver
            .try_iter()
            .map(|e| (e.kind, e.text, e.start, e.end))
            .collect();
        assert_eq!(
            events,
            [
                (EventKind::Begin, "0 a".to_string(), 6, 23),
                (EventKind::End, "0 a exit=0 5 0".to_string(), 28, 54),
                (EventKind::Eof, String::new(), 61, 61),
            ]
        );
        assert_eq!(&console.data()[23..28], b"out\r\n");
        assert_eq!(std::fs::read(&log_path).unwrap(), input);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
