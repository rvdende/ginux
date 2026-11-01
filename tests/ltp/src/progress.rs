//! What the run is doing, on the terminal.
//!
//! On a terminal a status line shows the current boot step or test, how
//! long it has run, the results so far and the elapsed time, redrawn every
//! second. When libtest's output shares the terminal, the status follows
//! its open `test NAME ... ` line and is erased before libtest prints the
//! outcome; messages print above that line. Without a terminal (a log),
//! boot steps print as plain `ltp:` lines.

use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use crate::Verdict;

/// libtest's output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// One `test NAME ... ok` line per test.
    Pretty,
    /// One character per test.
    Terse,
    /// JSON lines.
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Display {
    /// A terminal shared with libtest's pretty output: the status follows
    /// the open `test NAME ... ` line.
    Inline,
    /// A terminal of our own: the status is a line by itself.
    Line,
    /// No status line; boot steps print as lines.
    Plain,
}

const SHORT: [(Verdict, &str); 7] = [
    (Verdict::Tpass, "pass"),
    (Verdict::Tfail, "fail"),
    (Verdict::Tbrok, "broken"),
    (Verdict::Tconf, "conf"),
    (Verdict::Twarn, "warn"),
    (Verdict::Crash, "crash"),
    (Verdict::Hang, "hang"),
];

struct State {
    done: usize,
    counts: [usize; Verdict::ALL.len()],
    activity: String,
    since: Instant,
    /// The trial whose `test NAME ... ` line libtest has left open.
    open: Option<String>,
    closed: bool,
}

/// The run's progress display.
pub struct Progress {
    display: Display,
    /// libtest writes to the same file as we do (the terminal, or one log).
    shared: bool,
    format: Format,
    /// libtest's padding of test names.
    name_width: usize,
    total: usize,
    started: Instant,
    state: Mutex<State>,
}

/// The status line's text.
pub fn status_text(
    done: usize,
    total: usize,
    activity: &str,
    for_seconds: u64,
    counts: &[usize; Verdict::ALL.len()],
    elapsed: u64,
) -> String {
    let counts: Vec<String> = SHORT
        .iter()
        .filter(|(verdict, _)| counts[verdict.index()] > 0)
        .map(|(verdict, short)| format!("{short} {}", counts[verdict.index()]))
        .collect();
    let mut line = format!("[{done}/{total}] {activity} {for_seconds}s");
    if !counts.is_empty() {
        line.push_str(" | ");
        line.push_str(&counts.join(" "));
    }
    line.push_str(&format!(" | {}m{:02}s", elapsed / 60, elapsed % 60));
    line
}

fn same_file(a: BorrowedFd<'_>, b: BorrowedFd<'_>) -> bool {
    match (rustix::fs::fstat(a), rustix::fs::fstat(b)) {
        (Ok(a), Ok(b)) => a.st_dev == b.st_dev && a.st_ino == b.st_ino,
        _ => false,
    }
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|columns| columns.parse().ok())
        .filter(|&columns| columns > 0)
        .or_else(|| {
            rustix::termios::tcgetwinsize(io::stderr())
                .ok()
                .map(|size| usize::from(size.ws_col))
                .filter(|&columns| columns > 0)
        })
        .unwrap_or(100)
}

fn truncate(text: &str, width: usize) -> &str {
    match text.char_indices().nth(width) {
        Some((cut, _)) => &text[..cut],
        None => text,
    }
}

impl Progress {
    /// A display for `total` tests. `name_width` is the longest test name
    /// libtest pads to; `logfile` is set when libtest writes to a file of
    /// its own.
    pub fn new(total: usize, format: Format, name_width: usize, logfile: bool) -> Arc<Progress> {
        let shared = !logfile && same_file(io::stdout().as_fd(), io::stderr().as_fd());
        let display = if !io::stderr().is_terminal() {
            Display::Plain
        } else if !shared {
            Display::Line
        } else if format == Format::Pretty {
            Display::Inline
        } else {
            Display::Plain
        };
        let now = Instant::now();
        let progress = Arc::new(Progress {
            display,
            shared,
            format,
            name_width,
            total,
            started: now,
            state: Mutex::new(State {
                done: 0,
                counts: [0; Verdict::ALL.len()],
                activity: "starting".to_string(),
                since: now,
                open: None,
                closed: false,
            }),
        });
        if display != Display::Plain {
            let ticker = Arc::clone(&progress);
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(1));
                let state = ticker.lock();
                if state.closed {
                    return;
                }
                ticker.draw(&state);
            });
        }
        progress
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A boot or setup step began.
    pub fn step(&self, text: &str) {
        let mut state = self.lock();
        state.activity = text.to_string();
        state.since = Instant::now();
        if self.display == Display::Plain {
            self.print_above(&state, &format!("ltp: {text}"));
        } else {
            self.draw(&state);
        }
    }

    /// A test began in the guest.
    pub fn test(&self, name: &str) {
        let mut state = self.lock();
        state.activity = format!("running {name}");
        state.since = Instant::now();
        self.draw(&state);
    }

    /// A test finished.
    pub fn result(&self, verdict: Verdict) {
        let mut state = self.lock();
        state.done += 1;
        state.counts[verdict.index()] += 1;
        state.activity = "waiting for the next test".to_string();
        state.since = Instant::now();
        self.draw(&state);
    }

    /// Prints a message line above the status.
    pub fn message(&self, text: &str) {
        let state = self.lock();
        self.print_above(&state, text);
    }

    /// libtest has printed `test NAME ... ` and waits for the trial.
    pub fn trial_waits(&self, name: &str) {
        let mut state = self.lock();
        state.open = Some(name.to_string());
        self.draw(&state);
    }

    /// The trial is about to return: erase the status from libtest's line.
    pub fn trial_returns(&self) {
        let mut state = self.lock();
        if self.display == Display::Inline && state.open.is_some() {
            emit("\x1b[K");
        }
        state.open = None;
    }

    /// Erases the status line for good. A trial still waiting (the run was
    /// interrupted) gets its libtest line ended with "interrupted".
    pub fn close(&self) {
        let mut state = self.lock();
        self.clear(&state);
        let open_line = self.display == Display::Inline
            || (self.shared && matches!(self.format, Format::Pretty | Format::Terse));
        if state.open.is_some() && open_line {
            emit(if self.format == Format::Pretty {
                "interrupted\n"
            } else {
                "\n"
            });
        }
        state.open = None;
        state.closed = true;
    }

    fn prefix(&self, name: &str) -> String {
        format!("test {name:<0$} ... ", self.name_width)
    }

    fn status(&self, state: &State) -> String {
        let now = Instant::now();
        status_text(
            state.done,
            self.total,
            &state.activity,
            now.duration_since(state.since).as_secs(),
            &state.counts,
            now.duration_since(self.started).as_secs(),
        )
    }

    fn draw(&self, state: &State) {
        if state.closed {
            return;
        }
        let width = terminal_width();
        match self.display {
            Display::Inline => {
                if state.open.is_none() {
                    return;
                }
                // The status goes after libtest's `test NAME ... `, and the
                // cursor back to where libtest left it.
                let room = width.saturating_sub(self.name_width + 11);
                let status = self.status(state);
                let status = truncate(&status, room);
                if status.chars().count() < 10 {
                    return;
                }
                emit(&format!("\x1b[K{status}\x1b[{}D", status.chars().count()));
            }
            Display::Line => {
                let status = self.status(state);
                emit(&format!(
                    "\r\x1b[K{}",
                    truncate(&status, width.saturating_sub(1).max(20))
                ));
            }
            Display::Plain => {}
        }
    }

    fn clear(&self, state: &State) {
        match self.display {
            Display::Inline if state.open.is_some() => emit("\x1b[K"),
            Display::Line => emit("\r\x1b[K"),
            _ => {}
        }
    }

    fn print_above(&self, state: &State, text: &str) {
        let open = state.open.as_deref().filter(|_| !state.closed);
        match (self.display, open) {
            (Display::Inline, Some(name)) => {
                // Over libtest's open line, then that line again.
                emit(&format!("\r\x1b[K{text}\n{}", self.prefix(name)));
                self.draw(state);
            }
            (Display::Line, _) => {
                emit(&format!("\r\x1b[K{text}\n"));
                self.draw(state);
            }
            (_, Some(name)) if self.shared && self.format == Format::Pretty => {
                emit(&format!("\n{text}\n{}", self.prefix(name)));
            }
            (_, Some(_)) if self.shared && self.format == Format::Terse => {
                emit(&format!("\n{text}\n"));
            }
            _ => emit(&format!("{text}\n")),
        }
    }
}

fn emit(text: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn status_line() {
        let mut counts = [0; Verdict::ALL.len()];
        assert_eq!(
            status_text(0, 25, "boot 1: booting Ginux", 3, &counts, 3),
            "[0/25] boot 1: booting Ginux 3s | 0m03s"
        );
        counts[Verdict::Tpass.index()] = 380;
        counts[Verdict::Tfail.index()] = 20;
        counts[Verdict::Tbrok.index()] = 9;
        counts[Verdict::Tconf.index()] = 3;
        counts[Verdict::Skip.index()] = 7;
        assert_eq!(
            status_text(412, 1362, "running fork14", 12, &counts, 401),
            "[412/1362] running fork14 12s | pass 380 fail 20 broken 9 conf 3 | 6m41s"
        );
    }

    #[test]
    fn truncates_by_characters() {
        assert_eq!(truncate("abcdef", 4), "abcd");
        assert_eq!(truncate("ab", 4), "ab");
        assert_eq!(truncate("äöü", 2), "äö");
    }

    #[test]
    fn same_file_compares_inodes() {
        let path = std::env::temp_dir().join(format!("ginux-ltp-same-{}", std::process::id()));
        let a = File::create(&path).unwrap();
        let b = File::open(&path).unwrap();
        assert!(same_file(a.as_fd(), b.as_fd()));
        let other = File::open("/dev/null").unwrap();
        assert!(!same_file(a.as_fd(), other.as_fd()));
        std::fs::remove_file(&path).unwrap();
    }
}
