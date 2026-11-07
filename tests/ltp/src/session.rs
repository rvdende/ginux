//! The QEMU session: boots Ginux, starts the domain and the runner, turns
//! the runner's events into results, and recovers from crashes and hangs by
//! rebooting. It runs on a background thread and hands each trial its
//! result over a channel.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, LazyLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use regex::Regex;

use crate::baseline::{tail_lines, Baseline, Report};
use crate::classify::{classify, first_message};
use crate::config::Config;
use crate::console::{EventKind, Qemu, WaitError};
use crate::list::Test;
use crate::progress::Progress;
use crate::Verdict;

/// Lines of a test's log a failing trial shows.
const TAIL_LINES: usize = 40;

static ANSI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").expect("valid escape pattern"));

/// One test's line in the results file.
#[derive(Clone, Debug, PartialEq)]
pub struct TestResult {
    /// The result.
    pub verdict: Verdict,
    /// How long it ran.
    pub seconds: f64,
    /// Why: the exit status, the hang or crash, the skip reason.
    pub detail: String,
}

/// The run was interrupted (SIGINT or SIGTERM).
#[derive(Debug)]
pub struct Interrupted;

/// Counts of each result; tests without one count as NOTRUN.
pub fn count(tests: &[Test], results: &HashMap<String, TestResult>) -> [usize; Verdict::ALL.len()] {
    let mut counts = [0; Verdict::ALL.len()];
    for result in results.values() {
        counts[result.verdict.index()] += 1;
    }
    counts[Verdict::Notrun.index()] = tests.len().saturating_sub(results.len());
    counts
}

/// `TPASS=n TFAIL=n ...` for every result.
pub fn count_line(counts: &[usize; Verdict::ALL.len()]) -> String {
    Verdict::ALL
        .iter()
        .map(|verdict| format!("{verdict}={}", counts[verdict.index()]))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The results file: four comment lines (state and time, the run, the
/// counts, the column names), then `NAME RESULT SECONDS DETAIL` per test in
/// list order.
pub fn render_results(
    complete: bool,
    timestamp: &str,
    run_line: &str,
    tests: &[Test],
    results: &HashMap<String, TestResult>,
) -> String {
    let state = if complete { "complete" } else { "in progress" };
    let counts = count(tests, results);
    let mut text = format!(
        "# Ginux LTP results ({state}), {timestamp}\n# {run_line}\n# total={} {}\n# name result seconds detail\n",
        tests.len(),
        count_line(&counts)
    );
    for test in tests {
        match results.get(&test.tag) {
            Some(result) => writeln!(
                text,
                "{} {} {:.2} {}",
                test.tag, result.verdict, result.seconds, result.detail
            ),
            None => writeln!(text, "{} NOTRUN 0.00 not reached", test.tag),
        }
        .expect("writing to a String");
    }
    text
}

/// The console's CRLF line endings as LF, for a log file.
pub fn unix_lines(output: &[u8]) -> Vec<u8> {
    let mut log = Vec::with_capacity(output.len());
    let mut rest = output;
    while let Some(at) = memchr::memmem::find(rest, b"\r\n") {
        log.extend_from_slice(&rest[..at]);
        log.push(b'\n');
        rest = &rest[at + 2..];
    }
    log.extend_from_slice(rest);
    log
}

/// A fresh sparse volume; reboots within a run reuse it, so the domain
/// image comes from the OCI cache after the first boot.
pub fn new_volume(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    File::create(path)?.set_len(8 << 30)
}

/// The commit Ginux was built from, `-dirty` with uncommitted changes.
pub fn git_rev(repo: &Path) -> String {
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    };
    let Some(rev) = git(&["rev-parse", "--short", "HEAD"]) else {
        return "unknown".to_string();
    };
    match git(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(dirty) if dirty.is_empty() => rev,
        Some(_) => format!("{rev}-dirty"),
        None => "unknown".to_string(),
    }
}

/// Sets up the files the guest downloads (in `work/serve`: the LTP tree,
/// the runner, e2fsprogs, setup.sh and the run list of `runnable`) and
/// serves them.
/// Returns the base URL the guest uses.
pub fn serve_guest_files(config: &Config, runnable: &[&Test]) -> io::Result<String> {
    let serve = config.work().join("serve");
    let _ = fs::remove_dir_all(&serve);
    fs::create_dir_all(&serve)?;
    let ltp_dir = config.ltp_dir();
    symlink(ltp_dir.join("ltp.tar.xz"), serve.join("ltp.tar.xz"))?;
    symlink(ltp_dir.join("ltp-runner"), serve.join("ltp-runner"))?;
    // mkfs.ext2 and friends (tools/ltp/fetch-e2fsprogs.sh), if fetched.
    let e2fsprogs = config.repo.join("build/e2fsprogs/e2fsprogs.tar.gz");
    if e2fsprogs.exists() {
        symlink(e2fsprogs, serve.join("e2fsprogs.tar.gz"))?;
    }
    symlink(
        config.repo.join("tests/ltp/setup.sh"),
        serve.join("setup.sh"),
    )?;
    let runlist: String = runnable
        .iter()
        .enumerate()
        .map(|(index, test)| format!("{index}\t{}\t{}\t{}\n", test.tag, test.budget, test.command))
        .collect();
    fs::write(serve.join("runlist.txt"), runlist)?;
    let port = crate::http::serve(serve)?;
    Ok(format!("http://10.0.2.2:{port}"))
}

/// The run: the selected tests, their results, and the session state.
pub struct Run {
    config: Arc<Config>,
    /// The selected tests in list order: what the results file lists.
    tests: Vec<Test>,
    /// Every tag of the run list, in order (for the baseline).
    list_order: Vec<String>,
    /// The tests the guest runs, as indices into `tests`; the runner's
    /// indices are positions in this list.
    runnable: Vec<usize>,
    results: HashMap<String, TestResult>,
    /// Each runnable test's trial, until it has its result.
    trials: Vec<Option<Sender<Report>>>,
    progress: Arc<Progress>,
    serial_log: Arc<File>,
    interrupted: Arc<AtomicBool>,
    boots: u32,
    started: Instant,
    ltp_version: String,
    kernel_rev: String,
    /// Why the session stopped before running everything.
    stopped: Option<String>,
}

impl Run {
    /// A run of `tests` (the selection, in list order) of which those at
    /// `runnable` run in the guest; the others are recorded as skipped.
    /// Returns the run and, for each runnable test, the receiver its trial
    /// waits on.
    pub fn new(
        config: Arc<Config>,
        tests: Vec<Test>,
        list_order: Vec<String>,
        runnable: Vec<usize>,
        progress: Arc<Progress>,
        interrupted: Arc<AtomicBool>,
    ) -> io::Result<(Run, Vec<Receiver<Report>>)> {
        let mut results = HashMap::new();
        for (index, test) in tests.iter().enumerate() {
            if !runnable.contains(&index) {
                let reason = test.skip.clone().unwrap_or_else(|| "skipped".to_string());
                results.insert(
                    test.tag.clone(),
                    TestResult {
                        verdict: Verdict::Skip,
                        seconds: 0.0,
                        detail: reason,
                    },
                );
            }
        }
        let logs = config.logs();
        let _ = fs::remove_dir_all(&logs);
        fs::create_dir_all(&logs)?;
        let ltp_version = fs::read_to_string(config.ltp_dir().join("ltp/VERSION"))?
            .trim()
            .to_string();
        let kernel_rev = git_rev(&config.repo);
        let serial_log = Arc::new(File::create(config.serial_log())?);
        let (trials, receivers) = runnable
            .iter()
            .map(|_| {
                let (sender, receiver) = mpsc::channel();
                (Some(sender), receiver)
            })
            .unzip();
        let run = Run {
            config,
            tests,
            list_order,
            runnable,
            results,
            trials,
            progress,
            serial_log,
            interrupted,
            boots: 0,
            started: Instant::now(),
            ltp_version,
            kernel_rev,
            stopped: None,
        };
        Ok((run, receivers))
    }

    /// Runs the session on a background thread. If the run is interrupted,
    /// the final results are written and `on_interrupt` runs (it is
    /// expected to end the process). The thread returns the run once every
    /// trial has its result.
    pub fn spawn(
        mut self,
        base_url: String,
        on_interrupt: impl FnOnce(&Run) + Send + 'static,
    ) -> JoinHandle<Run> {
        thread::spawn(move || {
            if self.run(&base_url).is_err() {
                self.progress.message("ltp: interrupted");
                self.write_results(true);
                self.stopped = Some("interrupted".to_string());
                on_interrupt(&self);
            }
            self.release_trials();
            self
        })
    }

    /// The selected tests.
    pub fn tests(&self) -> &[Test] {
        &self.tests
    }

    /// The results so far, by tag.
    pub fn results(&self) -> &HashMap<String, TestResult> {
        &self.results
    }

    /// How many times Ginux was booted.
    pub fn boots(&self) -> u32 {
        self.boots
    }

    /// Counts of each result.
    pub fn counts(&self) -> [usize; Verdict::ALL.len()] {
        count(&self.tests, &self.results)
    }

    fn interrupted(&self) -> bool {
        self.interrupted.load(Ordering::Relaxed)
    }

    /// Ends every trial still waiting, as not reached.
    fn release_trials(&mut self) {
        let why = self.stopped.as_deref().unwrap_or("the run stopped");
        for trial in self.trials.iter_mut().filter_map(Option::take) {
            let _ = trial.send(Report::not_reached(why));
        }
    }

    // Results -----------------------------------------------------------

    fn record(
        &mut self,
        position: usize,
        verdict: Verdict,
        seconds: f64,
        detail: String,
        output: &[u8],
    ) {
        let test = &self.tests[self.runnable[position]];
        let tag = test.tag.clone();
        let log = unix_lines(output);
        let log_path = self.config.logs().join(format!("{tag}.log"));
        if let Err(error) = fs::write(&log_path, &log) {
            self.progress.message(&format!(
                "ltp: cannot write {}: {error}",
                log_path.display()
            ));
        }
        let conf_reason = (verdict == Verdict::Tconf)
            .then(|| first_message(output, "TCONF"))
            .flatten();
        self.results.insert(
            tag,
            TestResult {
                verdict,
                seconds,
                detail: detail.clone(),
            },
        );
        self.progress.result(verdict);
        self.write_results(false);
        if let Some(trial) = self.trials[position].take() {
            let _ = trial.send(Report {
                verdict,
                seconds,
                detail,
                conf_reason,
                log_tail: tail_lines(&log, TAIL_LINES),
            });
        }
    }

    /// Rewrites the results file (through a temporary file).
    pub fn write_results(&self, complete: bool) {
        let run_line = format!(
            "list={} ltp={} kernel={} boots={} elapsed={}s",
            self.config.relative(&self.config.list),
            self.ltp_version,
            self.kernel_rev,
            self.boots,
            self.started.elapsed().as_secs()
        );
        let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        let text = render_results(complete, &timestamp, &run_line, &self.tests, &self.results);
        let target = self.config.results();
        let temporary = target.with_extension("tmp");
        if let Err(error) =
            fs::write(&temporary, text).and_then(|()| fs::rename(&temporary, &target))
        {
            self.progress
                .message(&format!("ltp: cannot write {}: {error}", target.display()));
        }
    }

    // Sessions ----------------------------------------------------------

    /// Boots until every runnable test has a result, rebooting after a
    /// crash or hang and resuming at the next test.
    pub fn run(&mut self, base_url: &str) -> Result<(), Interrupted> {
        let mut position = 0;
        let mut failed_boots = 0;
        while position < self.runnable.len() {
            if self.interrupted() {
                return Err(Interrupted);
            }
            if self.boots >= self.config.max_boots {
                let why = format!("stopping after {} boots", self.boots);
                self.progress.message(&format!("ltp: {why}"));
                self.stopped = Some(why);
                break;
            }
            self.boots += 1;
            self.progress
                .step(&format!("boot {}: booting Ginux", self.boots));
            let (outcome, next, progressed) = self.boot(base_url, position)?;
            position = next;
            if outcome == "done" {
                break;
            }
            failed_boots = if progressed { 0 } else { failed_boots + 1 };
            if failed_boots >= 3 {
                let why = "three boots in a row made no progress; stopping";
                self.progress.message(&format!("ltp: {why}"));
                self.stopped = Some(why.to_string());
                break;
            }
        }
        self.write_results(true);
        Ok(())
    }

    /// One boot: starts QEMU and the domain, then runs tests until the
    /// list is done or the guest fails. Returns (outcome, next position,
    /// whether any test finished). QEMU is stopped on return.
    fn boot(
        &mut self,
        base_url: &str,
        position: usize,
    ) -> Result<(String, usize, bool), Interrupted> {
        let mut qemu = match Qemu::start(&self.config, self.boots, &self.serial_log) {
            Ok(qemu) => qemu,
            Err(error) => {
                let what = format!("boot failed: cannot start QEMU: {error}");
                self.progress
                    .message(&format!("ltp: boot {}: {what}", self.boots));
                return Ok((what, position, false));
            }
        };
        let phase_start = match self.start_domain(&mut qemu, base_url, position) {
            Ok(offset) => offset,
            Err(WaitError::Interrupted) => return Err(Interrupted),
            Err(WaitError::Boot(error)) => {
                let console = qemu.output(qemu.len().saturating_sub(600), None);
                let tail = String::from_utf8_lossy(&console);
                let tail = ANSI.replace_all(&tail, "");
                self.progress.message(&format!(
                    "ltp: boot {}: {error}; console ends:\n{tail}",
                    self.boots
                ));
                // Start the next boot from a fresh volume in case this one
                // was left unusable.
                qemu.stop();
                if let Err(error) = new_volume(&self.config.volume()) {
                    self.progress
                        .message(&format!("ltp: cannot make a new volume: {error}"));
                }
                return Ok((format!("boot failed: {error}"), position, false));
            }
        };
        self.run_session(&mut qemu, phase_start, position)
    }

    fn start_domain(
        &mut self,
        qemu: &mut Qemu,
        base_url: &str,
        position: usize,
    ) -> Result<usize, WaitError> {
        let config = Arc::clone(&self.config);
        let interrupted = Arc::clone(&self.interrupted);
        let boot = self.boots;
        let mut offset = qemu.wait_for(b"ginux> ", 120, 0, &interrupted)?;
        self.progress
            .step(&format!("boot {boot}: configuring the ltp domain"));
        // The volume keeps domain configurations across reboots, so after the
        // first boot the domain already exists and creating it is rejected.
        qemu.send("domain new ltp");
        offset = qemu.wait_for(b"ginux> ", 30, offset, &interrupted)?;
        // LTP's credential tests switch between root and other users (nobody,
        // bin), which a domain allows only with user-switching=true.
        qemu.send(&format!(
            "domain set ltp image={} init=/bin/sh memory-mib={} cpu={} user-switching=true write-execute=true privileged=true",
            config.image, config.domain_memory_mib, config.domain_cpus
        ));
        offset = qemu.wait_for(b"settings accepted", 30, offset, &interrupted)?;
        self.progress.step(&format!(
            "boot {boot}: starting the ltp domain ({}; the first start pulls it)",
            config.image
        ));
        qemu.send("domain start ltp --attach");
        offset = qemu.wait_for(
            b"ginux: entering configured Linux init",
            900,
            offset,
            &interrupted,
        )?;
        offset = qemu.wait_for(b"/ # ", 60, offset, &interrupted)?;
        self.progress.step(&format!(
            "boot {boot}: unpacking LTP and starting the runner"
        ));
        // The runner cannot replace the init shell: Ginux fails execve in a
        // domain's init process (ENOENT). The quotes keep the shell's echo of
        // this line from looking like a marker.
        qemu.send(&format!(
            "wget -q -O /tmp/ltp-setup.sh {base_url}/setup.sh && \
             /bin/sh /tmp/ltp-setup.sh {base_url} {position}; \
             echo \"@@LTP\" RUNNER\"_\"EXITED $?"
        ));
        Ok(offset)
    }

    /// Consumes runner events until the list is done or the guest fails.
    /// Returns (outcome, next position, whether any test finished).
    fn run_session(
        &mut self,
        qemu: &mut Qemu,
        phase_start: usize,
        mut position: usize,
    ) -> Result<(String, usize, bool), Interrupted> {
        let config = Arc::clone(&self.config);
        let between_tests = Duration::from_secs(config.between_tests);
        let mut progressed = false;
        // The running test: its position, when it began, its output offset.
        let mut current: Option<(usize, Instant, usize)> = None;
        let mut deadline = Instant::now() + Duration::from_secs(config.setup_timeout);
        loop {
            if self.interrupted() {
                return Err(Interrupted);
            }
            let event = qemu.next_event(Duration::from_millis(250));
            let now = Instant::now();
            if event
                .as_ref()
                .is_some_and(|event| event.start < phase_start)
            {
                continue;
            }
            let failure = match &event {
                Some(event) => match event.kind {
                    EventKind::Ready => {
                        deadline = now + between_tests;
                        None
                    }
                    EventKind::Begin => {
                        let index = event
                            .text
                            .split_whitespace()
                            .next()
                            .and_then(|index| index.parse().ok());
                        if let Some(index) =
                            index.filter(|&index: &usize| index < self.runnable.len())
                        {
                            let test = &self.tests[self.runnable[index]];
                            current = Some((index, event.when, event.end));
                            self.progress.test(&test.tag);
                            deadline =
                                now + Duration::from_secs(u64::from(test.budget) + config.grace);
                        }
                        None
                    }
                    EventKind::End => {
                        let fields: Vec<&str> = event.text.split_whitespace().collect();
                        let index = fields.first().and_then(|index| index.parse::<usize>().ok());
                        let millis = fields.get(3).and_then(|millis| millis.parse::<i64>().ok());
                        if let (Some(index), Some(status), Some(millis)) =
                            (index, fields.get(2), millis)
                        {
                            if index < self.runnable.len() {
                                let leftover = fields
                                    .get(4)
                                    .and_then(|n| n.parse::<i64>().ok())
                                    .unwrap_or(0);
                                let budget = self.tests[self.runnable[index]].budget;
                                let begin = current.map_or(event.start, |(_, _, offset)| offset);
                                let output = qemu.output(begin, Some(event.start));
                                let (verdict, mut detail) = classify(status, &output, budget);
                                if leftover > 0 {
                                    detail.push_str(&format!(" leftover={leftover}"));
                                }
                                self.record(
                                    index,
                                    verdict,
                                    millis as f64 / 1000.0,
                                    detail,
                                    &output,
                                );
                                current = None;
                                position = index + 1;
                                progressed = true;
                                deadline = now + between_tests;
                            }
                        }
                        None
                    }
                    EventKind::Done => {
                        return Ok(("done".to_string(), self.runnable.len(), progressed))
                    }
                    EventKind::SetupFailed => Some(format!("setup failed: {}", event.text)),
                    EventKind::RunnerExited => {
                        Some(format!("runner exited: status {}", event.text.trim()))
                    }
                    EventKind::Panic => Some("kernel panic".to_string()),
                    EventKind::DomainDown => Some(format!("domain down: {}", event.text.trim())),
                    EventKind::Eof => Some("QEMU exited".to_string()),
                },
                None if !qemu.alive() => Some("QEMU exited".to_string()),
                None => None,
            };
            if let Some(what) = failure {
                qemu.settle(&self.interrupted);
                if let Some((index, began, offset)) = current {
                    let output = qemu.output(offset, None);
                    self.record(
                        index,
                        Verdict::Crash,
                        (now - began).as_secs_f64(),
                        what.clone(),
                        &output,
                    );
                    return Ok((what, index + 1, true));
                }
                self.progress
                    .message(&format!("ltp: boot {}: {what} between tests", self.boots));
                return Ok((what, position, progressed));
            }
            if now > deadline {
                if let Some((index, began, offset)) = current {
                    let budget = self.tests[self.runnable[index]].budget;
                    let output = qemu.output(offset, None);
                    let detail = format!("host-watchdog {budget}+{}s (guest wedged)", config.grace);
                    self.record(
                        index,
                        Verdict::Hang,
                        (now - began).as_secs_f64(),
                        detail,
                        &output,
                    );
                    return Ok(("wedged".to_string(), index + 1, true));
                }
                self.progress
                    .message(&format!("ltp: boot {}: no runner progress", self.boots));
                return Ok(("stalled".to_string(), position, progressed));
            }
        }
    }

    // The end of the run --------------------------------------------------

    /// Prints the counts and what changed against the baseline, rewrites
    /// the baseline if asked to, and writes the failure report. `baseline`
    /// is the file as it was before the run.
    pub fn summarize(&self, baseline: &Baseline) {
        self.progress.close();
        let config = &self.config;
        println!("ltp: {} boots={}", count_line(&self.counts()), self.boots);
        let verdicts: HashMap<String, Verdict> = self
            .results
            .iter()
            .map(|(tag, result)| (tag.clone(), result.verdict))
            .collect();
        if !config.strict {
            let now = |wanted: Verdict| -> Vec<&str> {
                baseline
                    .entries()
                    .iter()
                    .filter(|(tag, _)| verdicts.get(tag) == Some(&wanted))
                    .map(|(tag, _)| tag.as_str())
                    .collect()
            };
            let passing = now(Verdict::Tpass);
            let conf = now(Verdict::Tconf);
            if !passing.is_empty() {
                println!("newly passing: {}", passing.join(" "));
            }
            if !conf.is_empty() {
                println!("no longer failing (now TCONF): {}", conf.join(" "));
            }
            if !(passing.is_empty() && conf.is_empty()) && !config.update_baseline {
                println!(
                    "ltp: remove them from {} (or rerun with LTP_UPDATE_BASELINE=1)",
                    config.display(&config.baseline)
                );
            }
        }
        if config.update_baseline {
            let updated = baseline.updated(self.list_order.iter().map(String::as_str), &verdicts);
            let origin = format!(
                "From {} ({}), list={} ltp={} kernel={}.",
                config.display(&config.results()),
                chrono::Local::now().format("%Y-%m-%d"),
                config.relative(&config.list),
                self.ltp_version,
                self.kernel_rev
            );
            match fs::write(&config.baseline, updated.render(&origin)) {
                Ok(()) => println!(
                    "ltp: baseline {} rewritten: {} known failures (was {})",
                    config.display(&config.baseline),
                    updated.len(),
                    baseline.len()
                ),
                Err(error) => eprintln!("ltp: cannot write {}: {error}", config.baseline.display()),
            }
        }
        let mut report = Command::new("python3");
        report
            .arg("-I")
            .arg(config.repo.join("tests/ltp/report.py"));
        if !config.variant.is_empty() {
            report.args(["--variant", &config.variant]);
        }
        if let Err(error) = report.status() {
            eprintln!("ltp: cannot run report.py: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(tag: &str) -> Test {
        Test {
            tag: tag.to_string(),
            command: tag.to_string(),
            budget: 60,
            skip: None,
        }
    }

    #[test]
    fn results_file_lists_every_selected_test_in_order() {
        let tests = vec![
            test("abort01"),
            test("accept01"),
            test("acct02"),
            test("fork14"),
        ];
        let results: HashMap<String, TestResult> = [
            (
                "fork14",
                Verdict::Hang,
                90.04,
                "host-watchdog 60+30s (guest wedged)",
            ),
            ("abort01", Verdict::Tfail, 0.03, "exit=1"),
            ("acct02", Verdict::Skip, 0.0, "needs a loop device"),
        ]
        .into_iter()
        .map(|(tag, verdict, seconds, detail)| {
            (
                tag.to_string(),
                TestResult {
                    verdict,
                    seconds,
                    detail: detail.to_string(),
                },
            )
        })
        .collect();
        let text = render_results(
            false,
            "2026-11-01T13:04:25",
            "list=l ltp=v kernel=k boots=1 elapsed=5s",
            &tests,
            &results,
        );
        assert_eq!(
            text,
            "# Ginux LTP results (in progress), 2026-11-01T13:04:25\n\
             # list=l ltp=v kernel=k boots=1 elapsed=5s\n\
             # total=4 TPASS=0 TFAIL=1 TBROK=0 TCONF=0 TWARN=0 CRASH=0 HANG=1 SKIP=1 NOTRUN=1\n\
             # name result seconds detail\n\
             abort01 TFAIL 0.03 exit=1\n\
             accept01 NOTRUN 0.00 not reached\n\
             acct02 SKIP 0.00 needs a loop device\n\
             fork14 HANG 90.04 host-watchdog 60+30s (guest wedged)\n"
        );
        assert!(render_results(true, "t", "r", &tests, &results)
            .starts_with("# Ginux LTP results (complete), t\n"));
    }

    #[test]
    fn logs_get_unix_line_endings() {
        assert_eq!(unix_lines(b"a\r\nb\r\r\nc\rd\n\r\n"), b"a\nb\r\nc\rd\n\n");
        assert_eq!(unix_lines(b""), b"");
    }

    #[test]
    fn a_new_volume_is_sparse_and_replaces_the_old() {
        let path = std::env::temp_dir().join(format!("ginux-ltp-volume-{}", std::process::id()));
        fs::write(&path, b"old").unwrap();
        new_volume(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), 8 << 30);
        fs::remove_file(&path).unwrap();
    }
}
